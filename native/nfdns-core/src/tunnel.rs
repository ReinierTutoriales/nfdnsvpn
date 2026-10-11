//! Event loop of the VPN: one thread running a tokio current-thread runtime.
//!
//! Packets read from the TUN are classified first ([`classify`]): DNS is answered or forwarded
//! here, bypass attempts are refused, and everything else (full mode) goes to a userspace TCP/IP
//! stack (smoltcp via `netstack-smoltcp`). Each TCP connection and UDP flow it terminates is then
//! relayed through an ordinary socket. Those sockets do not loop back into the tunnel because the
//! app excludes itself from the VPN (`addDisallowedApplication`).

use crate::apps::{AppGate, OwnerLookup, Protocol};
use crate::dns;
use crate::filter::Filter;
use crate::route::{classify, wrap_reply, Verdict};
use crate::quic::{self, InitialReader, QuicPeek};
use crate::sni::{self, Peek};
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::udp::UdpMsg;
use netstack_smoltcp::StackBuilder;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::{timeout, timeout_at, Instant};

const MAX_PACKET: usize = 65535;
const MTU: usize = 1500;
const UPSTREAM_TIMEOUT: Duration = Duration::from_millis(2500);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Long enough for QUIC and game sessions between keepalives.
const UDP_IDLE: Duration = Duration::from_secs(120);
/// Per-direction buffers, allocated up front for every connection: netstack-smoltcp keeps two of
/// this size in smoltcp and two more of its own, and the relay two of [`RELAY_BUFFER`]: about
/// 76 KiB per TCP connection (142 KiB with 32 KiB buffers). Measured with scripts/e2e-linux.sh,
/// a single flow still reaches 184 Mbit/s with the tunnel limited to 15 % of a core (204 Mbit/s
/// with 32 KiB): the CPU is the limit, not the window, and 4K video needs about 25 Mbit/s.
const STACK_TCP_BUFFER: u32 = 16 * 1024;
const RELAY_BUFFER: usize = 8 * 1024;
const RECENT_LIMIT: usize = 30;
/// Receive buffer of each UDP flow. Real datagrams stay within the path MTU (~1500 bytes), so
/// 16 KiB is ample, and 50 QUIC flows cost 0.8 MB instead of 3.2 MB with 64 KiB buffers.
const UDP_FLOW_BUFFER: usize = 16 * 1024;
/// Once one direction of a TCP relay has ended, how long the other may still run. Bounds every
/// relay task: netstack-smoltcp sometimes never reports a finished close (seen with bursts of
/// short connections), which would otherwise keep the task and its buffers forever.
const HALF_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// Usual TLS/HTTP ports: clients always speak first, so the server name is waited for.
const WEB_PORTS: [u16; 4] = [80, 443, 8080, 8443];
/// How long a client on a web port may stay silent before it is relayed uninspected.
const PEEK_TIMEOUT: Duration = Duration::from_secs(3);
/// Any other port is inspected too (DoH or DoQ on an unusual port must not slip through), but
/// a client that stays silent this long (a server-speaks-first protocol) is relayed at once.
const OTHER_PORT_PEEK_TIMEOUT: Duration = Duration::from_millis(300);
/// QUIC (HTTP/3). Its first datagrams are held while the server name is read from them.
const QUIC_PORT: u16 = 443;
const QUIC_PEEK_TIMEOUT: Duration = Duration::from_secs(1);
const QUIC_PEEK_DATAGRAMS: usize = 8;
const REFUSED_FLOW_IDLE: Duration = Duration::from_secs(30);

/// Quad9, only when the network announces no resolver.
const FALLBACK_UPSTREAM: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 53),
];

#[derive(Default)]
pub struct Stats {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub tcp_active: AtomicU64,
    pub udp_active: AtomicU64,
    /// QUIC flows refused because no server name could be read (the app falls back to TCP).
    pub quic_refused: AtomicU64,
    recent: Mutex<VecDeque<String>>,
}

impl Stats {
    /// A DNS query answered as blocked.
    fn record_blocked(&self, name: String) {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.blocked.fetch_add(1, Ordering::Relaxed);
        self.remember(name);
    }

    fn remember(&self, name: String) {
        let mut recent = self.recent.lock().unwrap();
        recent.retain(|n| *n != name);
        recent.push_front(name);
        recent.truncate(RECENT_LIMIT);
    }

    /// `queries,blocked,tcp,udp,quic_refused` then one recently blocked name per line, newest first.
    pub fn encode(&self) -> String {
        let mut out = format!(
            "{},{},{},{},{}",
            self.queries.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
            self.tcp_active.load(Ordering::Relaxed),
            self.udp_active.load(Ordering::Relaxed),
            self.quic_refused.load(Ordering::Relaxed),
        );
        for name in self.recent.lock().unwrap().iter() {
            out.push('\n');
            out.push_str(name);
        }
        out
    }
}

/// Decrements an active-flow counter however the task ends, cancellation included.
struct Active<'a>(&'a AtomicU64);

impl<'a> Active<'a> {
    fn new(counter: &'a AtomicU64) -> Self {
        counter.fetch_add(1, Ordering::Relaxed);
        Active(counter)
    }
}

impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The TUN descriptor. Owned by Kotlin (`ParcelFileDescriptor`), so it is never closed here.
struct TunFd(RawFd);

impl AsRawFd for TunFd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// The filter in use, replaceable while the tunnel runs (daily list updates keep connections).
#[derive(Clone)]
struct SharedFilter(Arc<RwLock<Arc<Filter>>>);

impl SharedFilter {
    fn current(&self) -> Arc<Filter> {
        self.0.read().unwrap().clone()
    }
}

pub struct Tunnel {
    fd: RawFd,
    filter: SharedFilter,
    intercepted: Arc<Vec<IpAddr>>,
    upstream: Arc<Mutex<Vec<SocketAddr>>>,
    stats: Arc<Stats>,
    apps: Arc<AppGate>,
    stop: Notify,
}

impl Tunnel {
    /// `intercepted`: resolver addresses (the virtual one and the public ones) whose non-DNS
    /// traffic is refused, so DoH and QUIC to them fall back to plain DNS.
    pub fn new(fd: RawFd, filter: Filter, intercepted: Vec<IpAddr>) -> Self {
        Tunnel {
            fd,
            filter: SharedFilter(Arc::new(RwLock::new(Arc::new(filter)))),
            intercepted: Arc::new(intercepted),
            upstream: Arc::new(Mutex::new(Vec::new())),
            stats: Arc::new(Stats::default()),
            apps: Arc::new(AppGate::default()),
            stop: Notify::new(),
        }
    }

    /// Replaces the filter; new queries and connections use it at once, flows already relayed
    /// keep going. May be called at any time from any thread.
    pub fn set_filter(&self, filter: Filter) {
        *self.filter.0.write().unwrap() = Arc::new(filter);
    }

    /// Rules of the filter in use.
    pub fn rule_count(&self) -> usize {
        self.filter.current().rule_count()
    }

    /// Resolvers of the real network; may be called at any time from any thread.
    pub fn set_upstream(&self, servers: Vec<SocketAddr>) {
        *self.upstream.lock().unwrap() = servers;
    }

    /// Apps (Linux uids) cut off the network entirely: their new TCP connections and UDP flows
    /// are dropped, whatever the destination. Takes effect only once a lookup is installed.
    pub fn set_blocked_apps(&self, uids: impl IntoIterator<Item = u32>) {
        self.apps.set_blocked(uids);
    }

    pub fn has_owner_lookup(&self) -> bool {
        self.apps.has_lookup()
    }

    /// How to find the app behind a connection; consulted only while some app is blocked.
    pub fn set_owner_lookup(&self, lookup: impl OwnerLookup) -> io::Result<()> {
        self.apps.set_lookup(lookup)
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Makes [`Tunnel::run`] return; safe before, during or after it.
    pub fn stop(&self) {
        self.stop.notify_one();
    }

    /// Blocks until [`Tunnel::stop`] or a fatal TUN error. Every flow is closed on return.
    pub fn run(&self) -> io::Result<()> {
        set_nonblocking(self.fd)?;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_io().enable_time().build()?;
        let result = runtime.block_on(async {
            tokio::select! {
                _ = self.stop.notified() => Ok(()),
                result = self.serve() => result,
            }
        });
        runtime.shutdown_timeout(Duration::from_millis(500));
        result
    }

    async fn serve(&self) -> io::Result<()> {
        let tun = Arc::new(AsyncFd::new(TunFd(self.fd))?);
        let (stack, runner, udp, tcp) = StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .mtu(MTU)
            .tcp_recv_buffer_size(STACK_TCP_BUFFER)
            .tcp_send_buffer_size(STACK_TCP_BUFFER)
            .build()?;
        if let Some(runner) = runner {
            tokio::spawn(runner);
        }
        let (mut stack_sink, mut stack_stream) = stack.split();

        // Single writer: packets from the stack and local DNS answers.
        let (to_tun, mut local_packets) = mpsc::channel::<Vec<u8>>(1024);
        let writer_tun = tun.clone();
        tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    Some(packet) = local_packets.recv() => packet,
                    Some(Ok(packet)) = stack_stream.next() => packet,
                    else => break,
                };
                if write_packet(&writer_tun, &packet).await.is_err() {
                    break;
                }
            }
        });

        if let Some(tcp) = tcp {
            tokio::spawn(relay_tcp(tcp, self.filter.clone(), self.stats.clone(), self.apps.clone()));
        }
        if let Some(udp) = udp {
            tokio::spawn(relay_udp(udp, self.filter.clone(), self.stats.clone(), self.apps.clone()));
        }

        let mut buffer = vec![0u8; MAX_PACKET];
        loop {
            let length = read_packet(&tun, &mut buffer).await?;
            let data = &buffer[..length];
            match classify(&self.filter.current(), &self.intercepted, data) {
                Verdict::Drop => {}
                Verdict::Reply { packet, blocked } => {
                    if let Some(name) = blocked {
                        self.stats.record_blocked(name);
                    }
                    let _ = to_tun.try_send(packet);
                }
                Verdict::Forward { query, .. } => {
                    self.stats.queries.fetch_add(1, Ordering::Relaxed);
                    let servers = self.upstream.lock().unwrap().clone();
                    let forward = forward_dns(data.to_vec(), query, servers, to_tun.clone(), self.filter.current(), self.stats.clone());
                    let (apps, stats) = (self.apps.clone(), self.stats.clone());
                    let flow = crate::packet::parse(data).map(|p| (SocketAddr::new(p.src, p.src_port), SocketAddr::new(p.dst, p.dst_port)));
                    tokio::spawn(async move {
                        // An app with its own resolver: a blocked one gets no answer either.
                        if let Some((local, remote)) = flow {
                            if apps.blocks(Protocol::Udp, local, remote).await {
                                stats.blocked.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        }
                        forward.await;
                    });
                }
                Verdict::Stack => {
                    if let Err(e) = stack_sink.send(data.to_vec()).await {
                        // Only a closed channel is fatal; a packet smoltcp rejects is not.
                        if e.kind() == io::ErrorKind::BrokenPipe {
                            return Err(e);
                        }
                    }
                }
            }
        }
    }
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: plain fcntl calls on a descriptor the caller keeps open for the tunnel's lifetime.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

async fn read_packet(tun: &AsyncFd<TunFd>, buffer: &mut [u8]) -> io::Result<usize> {
    loop {
        let mut guard = tun.readable().await?;
        let result = guard.try_io(|fd| {
            // SAFETY: `buffer` is valid for `buffer.len()` bytes.
            let n = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
            if n < 0 { Err(io::Error::last_os_error()) } else { Ok(n as usize) }
        });
        match result {
            Ok(Ok(0)) => continue,
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

async fn write_packet(tun: &AsyncFd<TunFd>, packet: &[u8]) -> io::Result<()> {
    loop {
        let mut guard = tun.writable().await?;
        let result = guard.try_io(|fd| {
            // SAFETY: `packet` is valid for `packet.len()` bytes.
            let n = unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) };
            if n < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
        });
        match result {
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            // A packet the kernel refuses (e.g. larger than the MTU) must not stop the writer.
            Ok(Err(e)) if e.raw_os_error() == Some(libc::EINVAL) || e.raw_os_error() == Some(libc::EMSGSIZE) => return Ok(()),
            Ok(result) => return result,
            Err(_would_block) => continue,
        }
    }
}

fn unspecified_for(address: &SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

async fn forward_dns(
    request: Vec<u8>,
    query: Vec<u8>,
    servers: Vec<SocketAddr>,
    to_tun: mpsc::Sender<Vec<u8>>,
    filter: Arc<Filter>,
    stats: Arc<Stats>,
) {
    let servers = if servers.is_empty() { FALLBACK_UPSTREAM.to_vec() } else { servers };
    let mut answer = vec![0u8; MAX_PACKET];
    for server in servers.iter().take(2) {
        let Ok(socket) = UdpSocket::bind(unspecified_for(server)).await else { continue };
        if socket.connect(server).await.is_err() || socket.send(&query).await.is_err() {
            continue;
        }
        let deadline = Instant::now() + UPSTREAM_TIMEOUT;
        loop {
            match timeout_at(deadline, socket.recv(&mut answer)).await {
                // Same transaction ID as the query, or it is not our answer.
                Ok(Ok(n)) if n >= 2 && answer[..2] == query[..2] => {
                    let cloaked = dns::cname_targets(&answer[..n]).into_iter().find(|name| filter.is_blocked(name));
                    let reply = match (cloaked, dns::parse_query(&query)) {
                        (Some(target), Some(question)) => {
                            stats.blocked.fetch_add(1, Ordering::Relaxed);
                            stats.remember(target);
                            dns::blocked_response(&query, &question)
                        }
                        _ => answer[..n].to_vec(),
                    };
                    if let Some(packet) = wrap_reply(&request, &reply) {
                        let _ = to_tun.send(packet).await;
                    }
                    return;
                }
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
    }
}

async fn relay_tcp(mut listener: netstack_smoltcp::TcpListener, filter: SharedFilter, stats: Arc<Stats>, apps: Arc<AppGate>) {
    while let Some((inbound, local, remote)) = listener.next().await {
        let (filter, stats, apps) = (filter.current(), stats.clone(), apps.clone());
        tokio::spawn(async move {
            let _active = Active::new(&stats.tcp_active);
            // Before connecting: a blocked app's server never even sees a SYN.
            if apps.blocks(Protocol::Tcp, local, remote).await {
                stats.blocked.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let (mut app_read, app_write) = tokio::io::split(inbound);
            // The real connection opens while the app's first bytes are inspected, and whatever
            // the server sends goes to the app at once: protocols where the server speaks first
            // (banners) get no delay. Only the app's bytes wait for the verdict, which is all a
            // block needs (a TLS or HTTP server sends nothing before the client does).
            let (server_tx, server_rx) = oneshot::channel();
            let mut download = tokio::spawn(async move {
                let Ok(Ok(outbound)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(remote)).await else { return };
                let _ = outbound.set_nodelay(true);
                let (server_read, server_write) = outbound.into_split();
                if server_tx.send(server_write).is_ok() {
                    pipe(server_read, app_write).await;
                }
            });
            let peek_timeout = if WEB_PORTS.contains(&remote.port()) { PEEK_TIMEOUT } else { OTHER_PORT_PEEK_TIMEOUT };
            let first = match first_flight(&mut app_read, peek_timeout).await {
                Some((_, Some(name))) if filter.is_blocked(&name) => {
                    // Dropping both halves closes the app's connection at once.
                    download.abort();
                    stats.blocked.fetch_add(1, Ordering::Relaxed);
                    stats.remember(name);
                    return;
                }
                Some((first, _)) => first,
                None => {
                    download.abort();
                    return;
                }
            };
            // An unreachable server drops the sender: closing `inbound` then resets the app.
            let Ok(mut server_write) = server_rx.await else { return };
            if !first.is_empty() && server_write.write_all(&first).await.is_err() {
                download.abort();
                return;
            }
            let upload = pipe(app_read, server_write);
            tokio::pin!(upload);
            tokio::select! {
                _ = &mut upload => {
                    let _ = timeout(HALF_CLOSE_TIMEOUT, &mut download).await;
                    download.abort();
                }
                _ = &mut download => { let _ = timeout(HALF_CLOSE_TIMEOUT, upload).await; }
            }
        });
    }
}

/// Reads what the app sends first until its server name is known (or cannot be), at most
/// [`sni::MAX_PEEK`] bytes or `wait`. `None` if the app closed before sending anything.
async fn first_flight<R: AsyncRead + Unpin>(inbound: &mut R, wait: Duration) -> Option<(Vec<u8>, Option<String>)> {
    let mut first = Vec::new();
    let mut chunk = vec![0u8; RELAY_BUFFER];
    let deadline = Instant::now() + wait;
    loop {
        match sni::server_name(&first) {
            Peek::Name(name) => return Some((first, Some(name))),
            Peek::NoName => return Some((first, None)),
            Peek::NeedMore if first.len() >= sni::MAX_PEEK => return Some((first, None)),
            Peek::NeedMore => {}
        }
        match timeout_at(deadline, inbound.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return if first.is_empty() { None } else { Some((first, None)) },
            Ok(Ok(n)) => first.extend_from_slice(&chunk[..n]),
            // Silent client (server-speaks-first protocol on this port): relay uninspected.
            Err(_) => return Some((first, None)),
        }
    }
}

/// Copies until EOF or error, then half-closes the writer (bounded: see [`SHUTDOWN_TIMEOUT`]).
async fn pipe<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(mut reader: R, mut writer: W) {
    let mut buffer = vec![0u8; RELAY_BUFFER];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if writer.write_all(&buffer[..n]).await.is_err() {
                    break;
                }
            }
        }
    }
    let _ = timeout(SHUTDOWN_TIMEOUT, writer.shutdown()).await;
}

/// UDP "NAT": one connected socket per (app address, destination) flow, closed after
/// [`UDP_IDLE`] without traffic in either direction.
async fn relay_udp(udp: netstack_smoltcp::UdpSocket, filter: SharedFilter, stats: Arc<Stats>, apps: Arc<AppGate>) {
    let (mut inbound, mut outbound) = udp.split();
    let (replies, mut pending) = mpsc::channel::<UdpMsg>(512);
    tokio::spawn(async move {
        while let Some(message) = pending.recv().await {
            if outbound.send(message).await.is_err() {
                break;
            }
        }
    });

    let context = Arc::new(UdpContext { replies, filter, stats, apps });
    let mut flows: HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>> = HashMap::new();
    while let Some((data, local, remote)) = inbound.next().await {
        let key = (local, remote);
        if let Some(flow) = flows.get(&key) {
            match flow.try_send(data) {
                Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => continue,
                Err(mpsc::error::TrySendError::Closed(data)) => {
                    flows.remove(&key);
                    start_udp_flow(&mut flows, key, data, &context);
                }
            }
        } else {
            flows.retain(|_, flow| !flow.is_closed());
            start_udp_flow(&mut flows, key, data, &context);
        }
    }
}

/// What every UDP flow needs: the way back to the stack, the filter, the counters and the
/// blocked apps.
struct UdpContext {
    replies: mpsc::Sender<UdpMsg>,
    filter: SharedFilter,
    stats: Arc<Stats>,
    apps: Arc<AppGate>,
}

fn start_udp_flow(
    flows: &mut HashMap<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>,
    key: (SocketAddr, SocketAddr),
    first: Vec<u8>,
    context: &Arc<UdpContext>,
) {
    let (sender, receiver) = mpsc::channel(64);
    let _ = sender.try_send(first);
    flows.insert(key, sender);
    tokio::spawn(udp_flow(key.0, key.1, receiver, context.clone()));
}

enum QuicDecision {
    /// Allowed name: these datagrams were held back and go out first.
    Allow(Vec<Vec<u8>>),
    Block(String),
    /// No readable name (another QUIC version, another protocol, or nothing in time): refused,
    /// so the app falls back to TCP, where the SNI is inspected.
    Refuse,
}

/// Holds the first datagrams of a QUIC flow until its server name is known.
async fn inspect_quic(first: Vec<u8>, from_app: &mut mpsc::Receiver<Vec<u8>>, filter: &Filter) -> QuicDecision {
    let mut reader = InitialReader::default();
    let mut held = Vec::new();
    let deadline = Instant::now() + QUIC_PEEK_TIMEOUT;
    let mut next = Some(first);
    while held.len() < QUIC_PEEK_DATAGRAMS {
        let datagram = match next.take() {
            Some(datagram) => datagram,
            None => match timeout_at(deadline, from_app.recv()).await {
                Ok(Some(datagram)) => datagram,
                _ => return QuicDecision::Refuse,
            },
        };
        let peek = reader.feed(&datagram);
        held.push(datagram);
        match peek {
            QuicPeek::Name(name) if filter.is_blocked(&name) => return QuicDecision::Block(name),
            QuicPeek::Name(_) => return QuicDecision::Allow(held),
            QuicPeek::Unknown => return QuicDecision::Refuse,
            QuicPeek::NeedMore => {}
        }
    }
    QuicDecision::Refuse
}

/// Keeps a refused flow's key taken, discarding what the app sends, so retries do not each
/// start a new inspection. Ends after [`REFUSED_FLOW_IDLE`] of silence.
async fn swallow(from_app: &mut mpsc::Receiver<Vec<u8>>) {
    while let Ok(Some(_)) = timeout(REFUSED_FLOW_IDLE, from_app.recv()).await {}
}

async fn udp_flow(local: SocketAddr, remote: SocketAddr, mut from_app: mpsc::Receiver<Vec<u8>>, context: Arc<UdpContext>) {
    let stats = &context.stats;
    let _active = Active::new(&stats.udp_active);
    let Some(first) = from_app.recv().await else { return };
    if context.apps.blocks(Protocol::Udp, local, remote).await {
        stats.blocked.fetch_add(1, Ordering::Relaxed);
        swallow(&mut from_app).await;
        return;
    }
    // QUIC on its usual port, or a QUIC Initial on any other (DoQ, apps on custom ports).
    let held = if remote.port() == QUIC_PORT || quic::looks_like_initial(&first) {
        match inspect_quic(first, &mut from_app, &context.filter.current()).await {
            QuicDecision::Allow(held) => held,
            QuicDecision::Block(name) => {
                stats.blocked.fetch_add(1, Ordering::Relaxed);
                stats.remember(name);
                swallow(&mut from_app).await;
                return;
            }
            QuicDecision::Refuse => {
                stats.quic_refused.fetch_add(1, Ordering::Relaxed);
                swallow(&mut from_app).await;
                return;
            }
        }
    } else {
        vec![first]
    };
    let replies = &context.replies;
    let Ok(socket) = UdpSocket::bind(unspecified_for(&remote)).await else { return };
    if socket.connect(remote).await.is_err() {
        return;
    }
    for datagram in held {
        let _ = socket.send(&datagram).await;
    }
    let mut buffer = vec![0u8; UDP_FLOW_BUFFER];
    loop {
        tokio::select! {
            message = from_app.recv() => match message {
                Some(data) => { let _ = socket.send(&data).await; }
                None => return,
            },
            received = socket.recv(&mut buffer) => match received {
                // The reply appears to come from the destination the app wrote to.
                Ok(n) => { let _ = replies.send((buffer[..n].to_vec(), remote, local)).await; }
                Err(_) => return,
            },
            _ = tokio::time::sleep(UDP_IDLE) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{build_query, TYPE_A};
    use crate::filter::FilterBuilder;
    use crate::packet;
    use crate::packet::tests::udp_packet;
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::thread;

    /// A datagram socket pair behaves like a TUN: one packet per read and write.
    fn fake_tun() -> (OwnedFd, OwnedFd) {
        let mut fds = [0; 2];
        // SAFETY: `fds` has room for the two descriptors socketpair writes.
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) }, 0);
        // SAFETY: both descriptors were just created and are owned here.
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }

    fn send(fd: &OwnedFd, packet: &[u8]) {
        // SAFETY: valid descriptor and buffer.
        assert!(unsafe { libc::write(fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) } > 0);
    }

    fn receive(fd: &OwnedFd) -> Vec<u8> {
        let timeout = libc::timeval { tv_sec: 5, tv_usec: 0 };
        let mut buffer = vec![0u8; MAX_PACKET];
        // SAFETY: valid descriptor, option value and buffer.
        unsafe {
            libc::setsockopt(fd.as_raw_fd(), libc::SOL_SOCKET, libc::SO_RCVTIMEO, (&timeout as *const libc::timeval).cast(), std::mem::size_of::<libc::timeval>() as u32);
            let n = libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len());
            assert!(n > 0, "no packet came back from the tunnel");
            buffer.truncate(n as usize);
        }
        buffer
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn start(tun: &OwnedFd) -> Arc<Tunnel> {
        let mut builder = FilterBuilder::default();
        builder.add_list("||doubleclick.net^\n");
        let tunnel = Arc::new(Tunnel::new(tun.as_raw_fd(), builder.build(), vec![ip("10.111.0.1")]));
        let runner = tunnel.clone();
        thread::spawn(move || runner.run().unwrap());
        tunnel
    }

    #[test]
    fn answers_blocked_and_forwards_allowed_queries() {
        let (app, tun) = fake_tun();
        let tunnel = start(&tun);

        // A fake upstream resolver that answers with the query ID and a marker.
        let upstream = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        tunnel.set_upstream(vec![upstream.local_addr().unwrap()]);
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            let (n, from) = upstream.recv_from(&mut buffer).unwrap();
            let mut answer = buffer[..2].to_vec();
            answer.extend_from_slice(b"upstream");
            assert!(n > 12);
            upstream.send_to(&answer, from).unwrap();
        });

        let client = ip("10.111.0.2");
        send(&app, &udp_packet(client, ip("10.111.0.1"), 40000, 53, &build_query(1, "ads.doubleclick.net", TYPE_A)));
        let blocked = receive(&app);
        let reply = packet::parse(&blocked).unwrap();
        assert_eq!((reply.src, reply.dst, reply.dst_port), (ip("10.111.0.1"), client, 40000));
        assert_eq!(&reply.payload[reply.payload.len() - 4..], &[0, 0, 0, 0]);

        send(&app, &udp_packet(client, ip("10.111.0.1"), 40001, 53, &build_query(0x4242, "example.org", TYPE_A)));
        let forwarded = receive(&app);
        let reply = packet::parse(&forwarded).unwrap();
        assert_eq!(reply.dst_port, 40001);
        assert_eq!(reply.payload, b"\x42\x42upstream");

        let stats = tunnel.stats().encode();
        assert!(stats.starts_with("2,1,"), "{stats}");
        assert!(stats.ends_with("\nads.doubleclick.net"), "{stats}");
        tunnel.stop();
    }

    #[test]
    fn relays_udp_flows_through_the_stack() {
        let (app, tun) = fake_tun();
        let tunnel = start(&tun);
        let echo = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            let (n, from) = echo.recv_from(&mut buffer).unwrap();
            echo.send_to(&buffer[..n], from).unwrap();
        });

        let client = ip("10.111.0.2");
        send(&app, &udp_packet(client, ip("127.0.0.1"), 41000, echo_port, b"ping over the tunnel"));
        let echoed = receive(&app);
        let reply = packet::parse(&echoed).unwrap();
        assert_eq!((reply.src, reply.src_port, reply.dst, reply.dst_port), (ip("127.0.0.1"), echo_port, client, 41000));
        assert_eq!(reply.payload, b"ping over the tunnel");
        tunnel.stop();
    }

    struct BlockedPort(u16);

    impl OwnerLookup for BlockedPort {
        fn owner(&mut self, _: Protocol, local: SocketAddr, _: SocketAddr) -> Option<u32> {
            Some(if local.port() == self.0 { 10123 } else { 10200 })
        }
    }

    #[test]
    fn a_blocked_app_gets_nothing_through() {
        let (app, tun) = fake_tun();
        let tunnel = start(&tun);
        tunnel.set_owner_lookup(BlockedPort(41001)).unwrap();
        tunnel.set_blocked_apps([10123]);
        let echo = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let echo_port = echo.local_addr().unwrap().port();
        thread::spawn(move || {
            let mut buffer = [0u8; 512];
            loop {
                let (n, from) = echo.recv_from(&mut buffer).unwrap();
                echo.send_to(&buffer[..n], from).unwrap();
            }
        });

        let client = ip("10.111.0.2");
        send(&app, &udp_packet(client, ip("127.0.0.1"), 41001, echo_port, b"from the blocked app"));
        send(&app, &udp_packet(client, ip("127.0.0.1"), 41002, echo_port, b"from another app"));
        let echoed = receive(&app);
        let reply = packet::parse(&echoed).unwrap();
        assert_eq!((reply.dst_port, reply.payload), (41002, &b"from another app"[..]));
        assert!(tunnel.stats().encode().starts_with("0,1,"), "{}", tunnel.stats().encode());
        tunnel.stop();
    }

    #[test]
    fn a_new_filter_applies_without_restarting() {
        let (app, tun) = fake_tun();
        let tunnel = start(&tun);
        let client = ip("10.111.0.2");
        let blocked = |app: &OwnedFd, id: u16, name: &str| {
            send(app, &udp_packet(client, ip("10.111.0.1"), 40000 + id, 53, &build_query(id, name, TYPE_A)));
            let reply = receive(app);
            let reply = packet::parse(&reply).unwrap();
            reply.payload[reply.payload.len() - 4..] == [0, 0, 0, 0]
        };
        assert!(blocked(&app, 1, "ads.doubleclick.net"));
        let mut builder = FilterBuilder::default();
        builder.add_list("||newtracker.example^\n");
        tunnel.set_filter(builder.build());
        assert_eq!(tunnel.rule_count(), 1);
        assert!(blocked(&app, 2, "pixel.newtracker.example"));
        tunnel.stop();
    }

    #[test]
    fn stop_before_run_returns_immediately() {
        let (_app, tun) = fake_tun();
        let tunnel = Tunnel::new(tun.as_raw_fd(), FilterBuilder::default().build(), Vec::new());
        tunnel.stop();
        tunnel.run().unwrap();
    }
}
