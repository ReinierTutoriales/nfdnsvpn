#!/usr/bin/env bash
# End-to-end test of the tunnel on a real Linux TUN. As on Android, every packet of "the apps"
# goes into the TUN (kernel-generated ones too, such as ACKs of closed sockets), while the
# tunnel's own sockets go out directly:
#
#   ns "tv":  tun0 10.111.0.2, default route via tun0           <- the apps (curl, python)
#   ns "gw":  linux_tun example holding tun0's fd, veth 192.0.2.2 <- the tunnel
#   ns "srv": veth 192.0.2.1: HTTP :8080, UDP echo :9999, fake DNS :53, nothing on :853
#
# Needs root, iproute2, python3 and curl. Usage: sudo scripts/e2e-linux.sh
# (or TUNNEL_BIN=<prebuilt linux_tun> sudo -E scripts/e2e-linux.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

TV=nfe2e-tv
GW=nfe2e-gw
SRV=nfe2e-srv
WORK=$(mktemp -d)
PIDS=()
cleanup() {
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    ip netns del "$TV" 2>/dev/null || true
    ip netns del "$GW" 2>/dev/null || true
    ip netns del "$SRV" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
trap "exit 130" INT TERM
tv() { ip netns exec "$TV" "$@"; }
gw() { ip netns exec "$GW" "$@"; }
srv() { ip netns exec "$SRV" "$@"; }
app() { ip netns exec "$TV" runuser -u nobody -- "$@"; }

# CI builds the example as its normal user and passes TUNNEL_BIN, so root never runs cargo.
if [[ -z "${TUNNEL_BIN:-}" ]]; then
    (cd native/nfdns-core && cargo build -q --release --example linux_tun)
    TUNNEL_BIN=native/nfdns-core/target/release/examples/linux_tun
fi

for ns in "$TV" "$GW" "$SRV"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add veth-gw netns "$GW" type veth peer name veth-srv netns "$SRV"
gw ip addr add 192.0.2.2/24 dev veth-gw
srv ip addr add 192.0.2.1/24 dev veth-srv
gw ip link set veth-gw up
srv ip link set veth-srv up
gw ip tuntap add dev tun0 mode tun

# Servers.
head -c 200000000 /dev/zero > "$WORK/big"
echo "hello through the tunnel" > "$WORK/small"
cat > "$WORK/servers.py" <<'EOF'
import socket, struct, sys, threading
def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.1", 9999))
    while True:
        data, peer = s.recvfrom(2048); s.sendto(data, peer)
def fake_dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.1", 53))
    while True:
        q, peer = s.recvfrom(2048)
        end = 12
        while q[end] != 0: end += q[end] + 1
        question = q[12:end + 5]
        answer = q[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + question
        answer += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("192.0.2.1")
        s.sendto(answer, peer)
threading.Thread(target=udp_echo, daemon=True).start()
fake_dns()
EOF
srv python3 "$WORK/servers.py" & PIDS+=($!)
srv python3 -m http.server 8080 --bind 192.0.2.1 --directory "$WORK" >/dev/null 2>&1 & PIDS+=($!)
printf '||doubleclick.net^\n' > "$WORK/list.txt"
ip netns exec "$GW" "$TUNNEL_BIN" tun0 192.0.2.1 "$WORK/list.txt" 10.111.0.1,8.8.8.8 > "$WORK/tunnel.log" 2>&1 &
TUNNEL_PID=$!   # ip netns exec execs the binary, so this is the tunnel itself
PIDS+=($TUNNEL_PID)
sleep 1
# The tunnel keeps its fd while the device moves to the apps' namespace.
ip -n "$GW" link set tun0 netns "$TV"
tv ip addr add 10.111.0.2/32 dev tun0
tv ip link set tun0 up
tv ip route add default dev tun0
[[ "$(cat /proc/$TUNNEL_PID/comm)" == linux_tun ]] || { echo "FAIL PID del túnel incorrecto"; exit 1; }

cat > "$WORK/client.py" <<'EOF'
import socket, struct, sys, time
def query(server, name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(q, (server, 53)); r, _ = s.recvfrom(2048)
    return socket.inet_ntoa(r[-4:])
cmd = sys.argv[1]
if cmd == "dns":
    print(query(sys.argv[2], sys.argv[3]))
elif cmd == "udp":
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(b"udp-ok", ("192.0.2.1", 9999)); print(s.recvfrom(2048)[0].decode())
elif cmd == "refused":
    start = time.monotonic()
    try:
        socket.create_connection(("192.0.2.1", int(sys.argv[2])), timeout=5); print("connected")
    except ConnectionRefusedError:
        print("refused %.0fms" % ((time.monotonic() - start) * 1000))
    except OSError as e:
        print("error", e)
EOF
chmod 755 "$WORK" && chmod 644 "$WORK"/*

FAILURES=0
check() { # name expected actual
    if [[ "$3" == $2 ]]; then echo "PASS $1: $3"; else echo "FAIL $1: expected '$2', got '$3'"; FAILURES=$((FAILURES + 1)); fi
}
check "DNS bloqueado (resolvedor virtual)" "0.0.0.0" "$(app python3 "$WORK/client.py" dns 10.111.0.1 pubads.g.doubleclick.net)"
check "DNS permitido (forzado aunque vaya a 8.8.8.8)" "192.0.2.1" "$(app python3 "$WORK/client.py" dns 8.8.8.8 example.org)"
check "TCP (HTTP por la pila smoltcp)" "hello through the tunnel" "$(app curl -s --max-time 5 http://192.0.2.1:8080/small)"
check "UDP (NAT)" "udp-ok" "$(app python3 "$WORK/client.py" udp)"
check "DoT (puerto 853) cortado con RST" "refused*" "$(app python3 "$WORK/client.py" refused 853)"

# Five bursts of 50 parallel connections: all must succeed, and memory must not keep growing
# (a stuck connection would hold its stack and relay buffers). Measured after TIME-WAIT.
burst() {
    local ok=0 clients=()
    for i in $(seq 1 50); do app curl -s --max-time 10 http://192.0.2.1:8080/small > "$WORK/p$i" & clients+=($!); done
    wait "${clients[@]}"
    for i in $(seq 1 50); do grep -q hello "$WORK/p$i" && ok=$((ok + 1)); done
    echo "$ok"
}
RSS_AFTER=()
for round in 1 2 3 4 5; do
    check "Ráfaga $round: 50 conexiones en paralelo" "50" "$(burst)"
    sleep 15   # closed connections stay in smoltcp's TIME-WAIT for about 10 s
    RSS_AFTER+=("$(awk '/VmRSS/ {print $2}' /proc/$TUNNEL_PID/status)")
done
echo "INFO RSS tras cada ráfaga (KB): ${RSS_AFTER[*]}"
check "RAM estable entre la ráfaga 2 y la 5 (< 1 MB)" "1" "$(( ${RSS_AFTER[4]} - ${RSS_AFTER[1]} < 1024 ? 1 : 0 ))"

# Throughput and cost of a 200 MB download.
cpu_before=$(awk '{print $14 + $15}' /proc/$TUNNEL_PID/stat)
speed=$(app curl -s -o /dev/null --max-time 120 -w '%{speed_download}' http://192.0.2.1:8080/big)
cpu_after=$(awk '{print $14 + $15}' /proc/$TUNNEL_PID/stat)
mbits=$(python3 -c "print(round($speed * 8 / 1e6))")
cpu_seconds=$(python3 -c "print(round(($cpu_after - $cpu_before) / $(getconf CLK_TCK), 2))")
rss=$(awk '/VmRSS/ {print $2}' /proc/$TUNNEL_PID/status)
hwm=$(awk '/VmHWM/ {print $2}' /proc/$TUNNEL_PID/status)
echo "INFO descarga 200 MB: ${mbits} Mbit/s, CPU del túnel ${cpu_seconds} s, RSS ${rss} KB (pico ${hwm} KB)"
check "Velocidad mayor que 25 Mbit/s (4K)" "1" "$(python3 -c "print(int($mbits > 25))")"

# Closed connections leave the stack after smoltcp's TIME-WAIT (about 10 s).
for _ in $(seq 1 30); do
    sleep 1
    active=$(tail -n 1 "$WORK/tunnel.log" | cut -d, -f3)
    [[ "$active" == 0 ]] && break
done
echo "INFO $(tail -n 1 "$WORK/tunnel.log") (consultas,bloqueadas,tcp,udp)"
check "Conexiones TCP liberadas tras cerrarse" "0" "$active"
kill -0 "$TUNNEL_PID" && echo "PASS túnel sigue vivo" || { echo "FAIL túnel caído"; cat "$WORK/tunnel.log"; FAILURES=$((FAILURES + 1)); }
echo "Fallos: $FAILURES"
exit "$FAILURES"
