//! Runs the tunnel on a Linux TUN device, for the end-to-end test in scripts/e2e-linux.sh.
//! Usage: linux_tun <tun name> <upstream ip[:port]> <list file> <intercepted ip,...>
//! Prints the stats line (`queries,blocked,tcp,udp,quic_refused`) every second.
use nfdns::filter::FilterBuilder;
use nfdns::parse_servers;
use nfdns::tunnel::Tunnel;
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

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, tun, upstream, list, intercepted] = args.as_slice() else {
        panic!("usage: linux_tun <tun name> <upstream> <list file> <intercepted ips>");
    };
    let mut builder = FilterBuilder::default();
    builder.add_list(&std::fs::read_to_string(list).expect("list file"));
    let intercepted = intercepted.split(',').filter_map(|s| s.parse().ok()).collect();
    let tunnel = Arc::new(Tunnel::new(open_tun(tun), builder.build(), intercepted));
    tunnel.set_upstream(parse_servers(upstream));
    let reporter = tunnel.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_secs(1));
        println!("stats {}", reporter.stats().encode().lines().next().unwrap_or_default());
    });
    tunnel.run().expect("tunnel");
}
