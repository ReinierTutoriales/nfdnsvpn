#!/usr/bin/env bash
# End-to-end test of the tunnel on a real Linux TUN. As on Android, every packet of "the apps"
# goes into the TUN (kernel-generated ones too, such as ACKs of closed sockets), while the
# tunnel's own sockets go out directly:
#
#   ns "tv":  tun0 10.111.0.2 / fd00:6e66::2, default routes via tun0   <- the apps (curl, python)
#   ns "gw":  linux_tun example holding tun0's fd, veth 192.0.2.2 / 2001:db8:1::2 <- the tunnel
#   ns "srv": veth 192.0.2.1 / 2001:db8:1::1: HTTP :8080, HTTPS :8443, QUIC :443, UDP echo :9999,
#             fake DNS :53, nothing on :853
#
# Needs root, iproute2, python3 (with aioquic for the QUIC checks) and curl.
# Usage: sudo scripts/e2e-linux.sh [--bench]
# --bench adds latency, connection-cut and efficiency measurements (several minutes).
# (or TUNNEL_BIN=<prebuilt linux_tun> sudo -E scripts/e2e-linux.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
BENCH=0
[[ "${1:-}" == "--bench" ]] && BENCH=1

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
# Python for the test servers and clients; CI points this at a venv that has aioquic.
PY=${E2E_PYTHON:-python3}
tv() { ip netns exec "$TV" "$@"; }
gw() { ip netns exec "$GW" "$@"; }
srv() { ip netns exec "$SRV" "$@"; }
# Proxy variables (set in some CI and sandbox environments) would send curl around the TUN.
app() { ip netns exec "$TV" runuser -u nobody -- env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY -u all_proxy -u ALL_PROXY "$@"; }

# CI builds the example as its normal user and passes TUNNEL_BIN, so root never runs cargo.
if [[ -z "${TUNNEL_BIN:-}" ]]; then
    (cd native/nfdns-core && cargo build -q --release --example linux_tun)
    TUNNEL_BIN=native/nfdns-core/target/release/examples/linux_tun
fi

# Some sandboxes run kernels without IPv6; the IPv6 checks are skipped there (CI has it).
[[ -d /proc/sys/net/ipv6 ]] && HAS_IPV6=1 || HAS_IPV6=0
for ns in "$TV" "$GW" "$SRV"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add veth-gw netns "$GW" type veth peer name veth-srv netns "$SRV"
gw ip addr add 192.0.2.2/24 dev veth-gw
srv ip addr add 192.0.2.1/24 dev veth-srv
# A second address listed as an encrypted DNS server: non-DNS traffic to it must be refused.
srv ip addr add 192.0.2.9/24 dev veth-srv
if (( HAS_IPV6 )); then
    gw ip addr add 2001:db8:1::2/64 dev veth-gw nodad
    srv ip addr add 2001:db8:1::1/64 dev veth-srv nodad
fi
gw ip link set veth-gw up
srv ip link set veth-srv up
gw ip tuntap add dev tun0 mode tun

# Servers.
head -c 200000000 /dev/zero > "$WORK/big"
echo "hello through the tunnel" > "$WORK/small"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=e2e" -keyout "$WORK/key.pem" -out "$WORK/cert.pem" 2>/dev/null
cat > "$WORK/servers.py" <<'EOF'
import functools, http.server, os, socket, ssl, struct, sys, threading
def udp_echo(family, address):
    s = socket.socket(family, socket.SOCK_DGRAM); s.bind((address, 9999))
    while True:
        data, peer = s.recvfrom(2048); s.sendto(data, peer)
def tcp_echo():
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("192.0.2.1", 7000)); s.listen(1024)
    def serve(c):
        with c:
            while True:
                data = c.recv(4096)
                if not data: return
                c.sendall(data)
    while True:
        c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
def banner():
    # Server speaks first (SMTP/FTP/SSH style), then echoes.
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("192.0.2.1", 2222)); s.listen(256)
    def serve(c):
        with c:
            c.sendall(b"SSH-2.0-e2e\r\n")
            while c.recv(4096): pass
    while True:
        c, _ = s.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
def encode(name):
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
def fake_dns():
    # Every name resolves to 192.0.2.1; cloaked.example hides behind a tracker CNAME.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("192.0.2.1", 53))
    while True:
        q, peer = s.recvfrom(2048)
        end, labels = 12, []
        while q[end] != 0:
            labels.append(q[end + 1:end + 1 + q[end]].decode()); end += q[end] + 1
        question = q[12:end + 5]
        if ".".join(labels) == "cloaked.example":
            target = encode("pixel.doubleclick.net")
            records = b"\xc0\x0c\x00\x05\x00\x01\x00\x00\x00\x3c" + struct.pack(">H", len(target)) + target
            records += struct.pack(">H", 0xC000 | (12 + len(question) + 12)) + b"\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("192.0.2.1")
            count = 2
        else:
            records = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton("192.0.2.1")
            count = 1
        s.sendto(q[:2] + b"\x81\x80\x00\x01" + struct.pack(">H", count) + b"\x00\x00\x00\x00" + question + records, peer)
def https(port):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[1])
    server = http.server.ThreadingHTTPServer(("", port), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(os.path.join(sys.argv[1], "cert.pem"), os.path.join(sys.argv[1], "key.pem"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
def quic():
    import asyncio
    from aioquic.asyncio import serve
    from aioquic.quic.configuration import QuicConfiguration
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["e2e"])
    configuration.load_cert_chain(os.path.join(sys.argv[1], "cert.pem"), os.path.join(sys.argv[1], "key.pem"))
    async def main():
        await serve("192.0.2.1", 443, configuration=configuration)
        await serve("192.0.2.1", 4433, configuration=configuration)
        await asyncio.Future()
    asyncio.run(main())
class HTTPServerV6(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6
def http_v6():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=sys.argv[1])
    HTTPServerV6(("2001:db8:1::1", 8080), handler).serve_forever()
threading.Thread(target=udp_echo, args=(socket.AF_INET, "192.0.2.1"), daemon=True).start()
threading.Thread(target=https, args=(8443,), daemon=True).start()
threading.Thread(target=tcp_echo, daemon=True).start()
threading.Thread(target=banner, daemon=True).start()
threading.Thread(target=https, args=(9443,), daemon=True).start()
if socket.has_ipv6 and os.path.isdir("/proc/sys/net/ipv6"):
    threading.Thread(target=udp_echo, args=(socket.AF_INET6, "2001:db8:1::1"), daemon=True).start()
    threading.Thread(target=http_v6, daemon=True).start()
try:
    import aioquic  # optional: the QUIC checks are skipped without it
    threading.Thread(target=quic, daemon=True).start()
except ImportError:
    pass
fake_dns()
EOF
srv "$PY" "$WORK/servers.py" "$WORK" > /dev/null 2>&1 & PIDS+=($!)
srv python3 -m http.server 8080 --bind 192.0.2.1 --directory "$WORK" >/dev/null 2>&1 & PIDS+=($!)
printf '||doubleclick.net^\n192.0.2.9\n' > "$WORK/list.txt"
ip netns exec "$GW" "$TUNNEL_BIN" tun0 192.0.2.1 "$WORK/list.txt" 10.111.0.1,8.8.8.8 > "$WORK/tunnel.log" 2>&1 &
TUNNEL_PID=$!   # ip netns exec execs the binary, so this is the tunnel itself
PIDS+=($TUNNEL_PID)
sleep 1
# The tunnel keeps its fd while the device moves to the apps' namespace.
ip -n "$GW" link set tun0 netns "$TV"
tv ip addr add 10.111.0.2/32 dev tun0
tv ip link set tun0 up
tv ip route add default dev tun0
if (( HAS_IPV6 )); then
    tv ip addr add fd00:6e66::2/128 dev tun0 nodad
    tv ip -6 route add default dev tun0
fi
[[ "$(cat /proc/$TUNNEL_PID/comm)" == linux_tun ]] || { echo "FAIL PID del túnel incorrecto"; exit 1; }

cat > "$WORK/client.py" <<'EOF'
import socket, struct, sys, time
def query(server, name):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00\x00\x01\x00\x01"
    s = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(q, (server, 53)); r, _ = s.recvfrom(2048)
    return socket.inet_ntoa(r[-4:])
cmd = sys.argv[1]
if cmd == "dns":
    print(query(sys.argv[2], sys.argv[3]))
elif cmd == "udp":
    server = sys.argv[2] if len(sys.argv) > 2 else "192.0.2.1"
    s = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
    s.sendto(b"udp-ok", (server, 9999)); print(s.recvfrom(2048)[0].decode())
elif cmd == "quic":
    import asyncio, ssl
    from aioquic.asyncio.protocol import QuicConnectionProtocol
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    async def main():
        configuration = QuicConfiguration(is_client=True, alpn_protocols=["e2e"], server_name=sys.argv[2])
        configuration.verify_mode = ssl.CERT_NONE
        # Plain IPv4 socket: aioquic's connect() always opens an IPv6 one.
        transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: QuicConnectionProtocol(QuicConnection(configuration=configuration)), local_addr=("0.0.0.0", 0))
        try:
            protocol.connect(("192.0.2.1", int(sys.argv[3]) if len(sys.argv) > 3 else 443))
            await protocol.wait_connected()
            await protocol.ping()
        finally:
            protocol.close()
            transport.close()
        print("quic-ok")
    try:
        asyncio.run(asyncio.wait_for(main(), 4))
    except Exception as e:
        print("quic-failed", type(e).__name__)
elif cmd in ("dnsbench", "tcpbench", "tlsbench", "banner"):
    import ssl
    def pct(values):
        values = sorted(values)
        pick = lambda q: values[min(len(values) - 1, int(q * len(values)))]
        return "p50 %.2f ms  p95 %.2f ms  p99 %.2f ms" % (pick(0.5) * 1e3, pick(0.95) * 1e3, pick(0.99) * 1e3)
    n = int(sys.argv[2]); samples = []
    for i in range(n):
        start = time.perf_counter()
        if cmd == "dnsbench":
            query(sys.argv[3], "bench%d.example.org" % i if sys.argv[4] == "allowed" else "x%d.doubleclick.net" % i)
        elif cmd == "tcpbench":
            c = socket.create_connection(("192.0.2.1", 8080), timeout=5)
            c.sendall(b"GET /small HTTP/1.0\r\nHost: allowed.example\r\n\r\n"); c.recv(1); c.close()
        elif cmd == "tlsbench":
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection(("192.0.2.1", 8443), timeout=5)
            t = ctx.wrap_socket(raw, server_hostname="allowed.example"); t.close()
        else:
            c = socket.create_connection(("192.0.2.1", 2222), timeout=5); c.recv(1); c.close()
        samples.append(time.perf_counter() - start)
    print(pct(samples))
elif cmd == "hold":
    # Opens n connections to the echo server, checks each echoes, keeps them open for a while.
    n, keep = int(sys.argv[2]), float(sys.argv[3]); conns = []; ok = 0
    for i in range(n):
        try:
            c = socket.create_connection(("192.0.2.1", 7000), timeout=5); conns.append(c)
        except OSError:
            pass
    for c in conns:
        try:
            c.sendall(b"x"); ok += c.recv(1) == b"x"
        except OSError:
            pass
    print(ok, flush=True); time.sleep(keep)
    for c in conns: c.close()
elif cmd == "idle":
    # One TCP connection and one UDP flow, used, left idle, then used again.
    idle = float(sys.argv[2])
    t = socket.create_connection(("192.0.2.1", 7000), timeout=5); u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    t.sendall(b"a"); t.recv(1); u.sendto(b"a", ("192.0.2.1", 9999)); u.recvfrom(16)
    time.sleep(idle)
    try:
        t.sendall(b"b"); tcp = "tcp-ok" if t.recv(1) == b"b" else "tcp-bad"
    except OSError as e:
        tcp = "tcp-cut(%s)" % type(e).__name__
    try:
        u.sendto(b"b", ("192.0.2.1", 9999)); udp = "udp-ok" if u.recvfrom(16)[0] == b"b" else "udp-bad"
    except OSError as e:
        udp = "udp-cut(%s)" % type(e).__name__
    print(tcp, udp)
elif cmd == "refused":
    start = time.monotonic()
    try:
        host = sys.argv[3] if len(sys.argv) > 3 else "192.0.2.1"
        socket.create_connection((host, int(sys.argv[2])), timeout=5); print("connected")
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
check "DNS bloqueado (resolvedor virtual)" "0.0.0.0" "$(app "$PY" "$WORK/client.py" dns 10.111.0.1 pubads.g.doubleclick.net)"
check "DNS permitido (forzado aunque vaya a 8.8.8.8)" "192.0.2.1" "$(app "$PY" "$WORK/client.py" dns 8.8.8.8 example.org)"
check "TCP (HTTP por la pila smoltcp)" "hello through the tunnel" "$(app curl -s --max-time 5 http://192.0.2.1:8080/small)"
check "UDP (NAT)" "udp-ok" "$(app "$PY" "$WORK/client.py" udp)"
check "DoT (puerto 853) cortado con RST" "refused*" "$(app "$PY" "$WORK/client.py" refused 853)"
check "CNAME de rastreador desenmascarado" "0.0.0.0" "$(app "$PY" "$WORK/client.py" dns 10.111.0.1 cloaked.example)"
# --resolve skips DNS, so only the SNI / Host inspection can stop these.
check "HTTPS permitido (SNI)" "hello through the tunnel" "$(app curl -sk --max-time 5 --resolve allowed.example:8443:192.0.2.1 https://allowed.example:8443/small)"
# 35/56: the TLS handshake was cut after the ClientHello; 7 (no connection) would not prove it.
check "HTTPS bloqueado por SNI" "blocked (curl [35][56])" "$(app curl -sk --max-time 5 --resolve ads.doubleclick.net:8443:192.0.2.1 https://ads.doubleclick.net:8443/small >/dev/null 2>&1 && echo served || echo "blocked (curl $?)")"
if (( HAS_IPV6 )); then
    check "DNS por IPv6 (resolvedor virtual fd00:6e66::1)" "0.0.0.0" "$(app "$PY" "$WORK/client.py" dns fd00:6e66::1 pubads.g.doubleclick.net)"
    check "TCP por IPv6" "hello through the tunnel" "$(app curl -sg --max-time 5 'http://[2001:db8:1::1]:8080/small')"
    check "UDP por IPv6" "udp-ok" "$(app "$PY" "$WORK/client.py" udp 2001:db8:1::1)"
else
    echo "SKIP IPv6: el kernel no tiene IPv6"
fi
if "$PY" -c "import aioquic" 2>/dev/null; then
    check "QUIC permitido (SNI del Initial)" "quic-ok" "$(app "$PY" "$WORK/client.py" quic allowed.example)"
    # Dropped by the tunnel: the handshake times out (any other error would prove nothing).
    check "QUIC bloqueado por SNI del Initial" "quic-failed TimeoutError" "$(app "$PY" "$WORK/client.py" quic ads.doubleclick.net)"
else
    echo "SKIP QUIC: falta aioquic (pip install aioquic)"
fi
# Anti-bypass: an app with its own resolver, DoH by IP, TLS and QUIC on unusual ports.
check "DNS forzado aunque vaya a un resolvedor cualquiera" "192.0.2.1" "$(app "$PY" "$WORK/client.py" dns 203.0.113.53 example.org)"
check "DoH a una IP de la lista cortado" "refused*" "$(app "$PY" "$WORK/client.py" refused 8443 192.0.2.9)"
check "HTTPS en puerto no estándar permitido" "hello through the tunnel" "$(app curl -sk --max-time 5 --resolve allowed.example:9443:192.0.2.1 https://allowed.example:9443/small)"
check "HTTPS en puerto no estándar bloqueado por SNI" "blocked (curl [35][56])" "$(app curl -sk --max-time 5 --resolve ads.doubleclick.net:9443:192.0.2.1 https://ads.doubleclick.net:9443/small >/dev/null 2>&1 && echo served || echo "blocked (curl $?)")"
if "$PY" -c "import aioquic" 2>/dev/null; then
    check "QUIC en puerto no estándar permitido" "quic-ok" "$(app "$PY" "$WORK/client.py" quic allowed.example 4433)"
    check "QUIC en puerto no estándar bloqueado" "quic-failed TimeoutError" "$(app "$PY" "$WORK/client.py" quic ads.doubleclick.net 4433)"
fi
check "HTTP bloqueado por Host" "blocked*" "$(out=$(app curl -s --max-time 5 -H 'Host: ads.doubleclick.net' http://192.0.2.1:8080/small); [[ -z "$out" ]] && echo blocked || echo "served: $out")"

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
    active=$(grep '^stats' "$WORK/tunnel.log" | tail -n 1 | cut -d, -f3)
    [[ "$active" == 0 ]] && break
done
echo "INFO $(grep '^stats' "$WORK/tunnel.log" | tail -n 1) (consultas,bloqueadas,tcp,udp,quic rechazados)"
check "Conexiones TCP liberadas tras cerrarse" "0" "$active"
if (( BENCH )); then
    echo "BENCH --- latencia (con túnel / directo, sin túnel) ---"
    echo "BENCH DNS permitido (reenviado)  túnel:   $(app "$PY" "$WORK/client.py" dnsbench 500 10.111.0.1 allowed)"
    echo "BENCH DNS permitido              directo: $(gw "$PY" "$WORK/client.py" dnsbench 500 192.0.2.1 allowed)"
    echo "BENCH DNS bloqueado (local)      túnel:   $(app "$PY" "$WORK/client.py" dnsbench 500 10.111.0.1 blocked)"
    echo "BENCH HTTP conexión + 1er byte   túnel:   $(app "$PY" "$WORK/client.py" tcpbench 200)"
    echo "BENCH HTTP conexión + 1er byte   directo: $(gw "$PY" "$WORK/client.py" tcpbench 200)"
    echo "BENCH TLS handshake (SNI)        túnel:   $(app "$PY" "$WORK/client.py" tlsbench 200)"
    echo "BENCH TLS handshake (SNI)        directo: $(gw "$PY" "$WORK/client.py" tlsbench 200)"
    echo "BENCH Banner (habla el servidor) túnel:   $(app "$PY" "$WORK/client.py" banner 20)"
    echo "BENCH Banner (habla el servidor) directo: $(gw "$PY" "$WORK/client.py" banner 20)"

    echo "BENCH --- cortes de conexión ---"
    rss0=$(awk '/VmRSS/ {print $2}' /proc/$TUNNEL_PID/status)
    app "$PY" "$WORK/client.py" hold 500 6 > "$WORK/hold.txt" & HOLD=$!
    for _ in $(seq 1 40); do [[ -s "$WORK/hold.txt" ]] && break; sleep 0.25; done
    sleep 1
    rss1=$(awk '/VmRSS/ {print $2}' /proc/$TUNNEL_PID/status)
    echo "BENCH 500 conexiones abiertas a la vez: $(cat "$WORK/hold.txt") responden; RSS +$(( rss1 - rss0 )) KB ($(( (rss1 - rss0) / 500 )) KB por conexión)"
    wait $HOLD
    echo "BENCH Inactividad de 130 s (TCP y UDP): $(app "$PY" "$WORK/client.py" idle 130)"
    printf '||doubleclick.net^\n192.0.2.9\n||reload.example^\n' > "$WORK/list.next"
    ( sleep 2; mv "$WORK/list.next" "$WORK/list.txt" ) &
    size=$(app curl -s -o /dev/null --max-time 60 --limit-rate 25M -w '%{size_download}' http://192.0.2.1:8080/big)
    echo "BENCH Descarga de 200 MB a 25 MB/s con cambio de lista a mitad: ${size} bytes recibidos; $(grep -c '^reloaded' "$WORK/tunnel.log") recarga(s)"

    echo "BENCH --- eficiencia ---"
    idle_before=$(awk '{print $14 + $15}' /proc/$TUNNEL_PID/stat)
    sleep 20
    idle_after=$(awk '{print $14 + $15}' /proc/$TUNNEL_PID/stat)
    echo "BENCH CPU en reposo: $(( idle_after - idle_before )) ticks en 20 s ($(getconf CLK_TCK) ticks = 1 s)"
    for task in /proc/$TUNNEL_PID/task/*; do echo "$(cat $task/comm) $(awk '/^voluntary_ctxt_switches/ {print $2}' $task/status)"; done > "$WORK/wake0"
    sleep 10
    for task in /proc/$TUNNEL_PID/task/*; do echo "$(cat $task/comm) $(awk '/^voluntary_ctxt_switches/ {print $2}' $task/status)"; done > "$WORK/wake1"
    echo "BENCH Despertares en reposo por hilo (10 s): $(paste -d' ' "$WORK/wake0" "$WORK/wake1" | awk '{printf "%s=%d ", $1, $4-$2}')"
fi

kill -0 "$TUNNEL_PID" && echo "PASS túnel sigue vivo" || { echo "FAIL túnel caído"; cat "$WORK/tunnel.log"; FAILURES=$((FAILURES + 1)); }
echo "Fallos: $FAILURES"
exit "$FAILURES"
