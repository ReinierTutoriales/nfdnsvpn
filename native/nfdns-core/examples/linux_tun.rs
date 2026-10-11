//! Runs the tunnel on a Linux TUN device, for the end-to-end test in scripts/e2e-linux.sh.
//! Usage: linux_tun <tun name> <upstream ip[:port]> <list file> <intercepted ip,...>
//! Prints the stats line (`queries,blocked,tcp,udp,quic_refused`) every second, and reloads the
//! list (as the app's daily update does) when the file changes, printing `reloaded <rules>`.
//! With `NFDNS_BLOCK_UID=<uid>` and `NFDNS_APPS_NETNS=<netns path>`, that user's connections are
//! cut as a blocked app's are on Android: owners are looked up in the apps' `/proc/net` tables,
//! the Linux counterpart of `getConnectionOwnerUid`.
use nfdns::apps::{OwnerLookup, Protocol};
use nfdns::filter::FilterBuilder;
use nfdns::parse_servers;
use nfdns::tunnel::Tunnel;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

fn open_tun(name: &str) -> i32 {
    // SAFETY: plain open/ioctl with a correctly sized ifreq.
    unsafe {
        let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR);
        assert!(fd >= 0, "open /dev/net/tun: {}", std::io::Error::last_os_error());
        let mut request = IfReq { name: [0; libc::IFNAMSIZ], flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short, _pad: [0; 22] };
        request.name[..name.len()].copy_from_slice(name.as_bytes());
        assert!(libc::ioctl(fd, TUNSETIFF, &mut request) >= 0, "TUNSETIFF: {}", std::io::Error::last_os_error());
        fd
    }
}

/// Reads the apps' socket tables from a thread that joined their network namespace.
struct ProcLookup {
    netns: String,
    joined: bool,
}

impl ProcLookup {
    /// `/proc/net` address: each 32-bit word in host (little-endian) order.
    fn encode(ip: IpAddr) -> String {
        let bytes = match ip {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        bytes.chunks(4).map(|w| format!("{:08X}", u32::from_le_bytes([w[0], w[1], w[2], w[3]]))).collect()
    }

    /// The addresses an IPv4 or IPv6 socket may show for `ip`: itself, unbound, and for IPv4 its
    /// mapped form in a dual-stack socket.
    fn forms(ip: IpAddr, v6_table: bool) -> Vec<String> {
        match (ip, v6_table) {
            (IpAddr::V4(_), false) => vec![Self::encode(ip), Self::encode(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))],
            (IpAddr::V4(v4), true) => {
                vec![Self::encode(IpAddr::V6(v4.to_ipv6_mapped())), Self::encode(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))]
            }
            (IpAddr::V6(_), true) => vec![Self::encode(ip), Self::encode(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED))],
            (IpAddr::V6(_), false) => Vec::new(),
        }
    }
}

impl OwnerLookup for ProcLookup {
    /// Like the kernel lookup behind `getConnectionOwnerUid`: the exact connection first, then
    /// (UDP) a socket bound to any address on that port and not connected elsewhere.
    fn owner(&mut self, protocol: Protocol, local: SocketAddr, remote: SocketAddr) -> Option<u32> {
        if !self.joined {
            let file = std::fs::File::open(&self.netns).ok()?;
            // SAFETY: setns on a valid namespace fd; only this lookup thread changes namespace.
            if unsafe { libc::setns(std::os::fd::AsRawFd::as_raw_fd(&file), libc::CLONE_NEWNET) } != 0 {
                return None;
            }
            self.joined = true;
        }
        let name = if protocol == Protocol::Tcp { "tcp" } else { "udp" };
        for v6_table in [false, true] {
            let Ok(text) = std::fs::read_to_string(format!("/proc/thread-self/net/{name}{}", if v6_table { "6" } else { "" })) else {
                continue;
            };
            let (locals, remotes) = (Self::forms(local.ip(), v6_table), Self::forms(remote.ip(), v6_table));
            let Some((exact_remote, any_remote)) = remotes.first().zip(remotes.get(1)) else { continue };
            let local_port = format!("{:04X}", local.port());
            let remote_port = format!("{:04X}", remote.port());
            for line in text.lines().skip(1) {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let (Some(l), Some(r), Some(uid)) = (fields.get(1), fields.get(2), fields.get(7)) else { continue };
                let (Some((l_ip, l_port)), Some((r_ip, r_port))) = (l.split_once(':'), r.split_once(':')) else { continue };
                let local_ok =
                    l_port == local_port && (if protocol == Protocol::Tcp { l_ip == locals[0] } else { locals.iter().any(|f| f == l_ip) });
                let remote_ok = (r_ip == exact_remote && r_port == remote_port)
                    || (protocol == Protocol::Udp && r_ip == any_remote && r_port == "0000");
                if local_ok && remote_ok {
                    return uid.parse().ok();
                }
            }
        }
        None
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, tun, upstream, list, intercepted] = args.as_slice() else {
        panic!("usage: linux_tun <tun name> <upstream> <list file> <intercepted ips>");
    };
    let load = |path: &str| {
        let mut builder = FilterBuilder::default();
        builder.add_list(&std::fs::read_to_string(path).expect("list file"));
        builder.build()
    };
    let intercepted = intercepted.split(',').filter_map(|s| s.parse().ok()).collect();
    let tunnel = Arc::new(Tunnel::new(open_tun(tun), load(list), intercepted));
    tunnel.set_upstream(parse_servers(upstream));
    if let (Ok(uid), Ok(netns)) = (std::env::var("NFDNS_BLOCK_UID"), std::env::var("NFDNS_APPS_NETNS")) {
        tunnel.set_owner_lookup(ProcLookup { netns, joined: false }).expect("lookup thread");
        tunnel.set_blocked_apps([uid.parse().expect("NFDNS_BLOCK_UID")]);
    }
    let reporter = tunnel.clone();
    let list = list.clone();
    std::thread::spawn(move || {
        let modified = |path: &str| std::fs::metadata(path).and_then(|m| m.modified()).ok();
        let mut seen = modified(&list);
        loop {
            std::thread::sleep(Duration::from_secs(1));
            println!("stats {}", reporter.stats().encode().lines().next().unwrap_or_default());
            let now = modified(&list);
            if now != seen {
                seen = now;
                reporter.set_filter(load(&list));
                println!("reloaded {}", reporter.rule_count());
            }
        }
    });
    tunnel.run().expect("tunnel");
}
