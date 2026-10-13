//! Where allowed DNS queries go: on Android always a chosen resolver over TLS (DNS over TLS,
//! RFC 7858), never the network's; plain UDP remains for the Linux test bench.
//!
//! Over TLS the network (router, ISP) can neither read nor rewrite the answers, which plain DNS
//! to a public resolver does not prevent: many ISPs silently redirect port 53. There is no
//! fallback to plain DNS when TLS fails, or anyone able to block port 853 could force it.
//!
//! One TLS connection carries every query (pipelined, RFC 7766), opened on the first query and
//! closed after [`IDLE`] without any: a TV at rest keeps no socket and wakes nothing.

use futures::StreamExt;
use futures::stream::FuturesUnordered;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, WriteHalf};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// Per query, the plain or the TLS exchange.
const QUERY_TIMEOUT: Duration = Duration::from_millis(2500);
/// A query unanswered this long on an open connection means the connection is dead. Resolvers
/// answer in tens of milliseconds and a slow recursive lookup in about a second; shorter than
/// [`QUERY_TIMEOUT`], so the queries still waiting can be retried on a new connection in time.
const STALE_AFTER: Duration = Duration::from_millis(1800);
/// TCP connect plus TLS handshake to one resolver.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Head start of each resolver over the next one when connecting (RFC 8305's 250 ms): a resolver
/// that drops packets delays the next by this much, not by a whole [`CONNECT_TIMEOUT`], so the
/// alternative answers within the query's [`QUERY_TIMEOUT`].
const CONNECT_STAGGER: Duration = Duration::from_millis(250);
/// A TLS connection without queries for this long is closed.
const IDLE: Duration = Duration::from_secs(30);
/// Largest UDP answer read back: the biggest EDNS size clients ask for (resolvers keep to 1232
/// since DNS Flag Day 2020).
const ANSWER_MAX: usize = 4096;
const DNS_PORT: u16 = 53;
const DOT_PORT: u16 = 853;
pub enum Upstream {
    /// Plain UDP resolvers (test bench). Empty: no resolver, every allowed query fails.
    Plain(Vec<SocketAddr>),
    /// A chosen resolver over TLS; its addresses are tried in order.
    Tls(DotClient),
}

impl Upstream {
    /// Comma-separated resolvers. `tls://IP[:port]#name` entries make it DNS over TLS (the name
    /// is checked against the certificate); otherwise `IP` or `IP:port`, plain. Bad entries are
    /// skipped.
    pub fn parse(list: &str) -> Upstream {
        let entries: Vec<&str> = list.split(',').map(str::trim).filter(|e| !e.is_empty()).collect();
        let tls: Vec<DotServer> = entries.iter().filter_map(|e| e.strip_prefix("tls://")).filter_map(DotServer::parse).collect();
        if !tls.is_empty() {
            return Upstream::Tls(DotClient::new(tls, Vec::new()));
        }
        Upstream::Plain(entries.iter().filter_map(|e| plain_address(e)).collect())
    }

    /// The answer to `query`, or `None` if no resolver gave one in time.
    pub async fn exchange(&self, query: &[u8]) -> Option<Vec<u8>> {
        match self {
            Upstream::Plain(servers) => {
                for server in servers.iter().take(2) {
                    if let Some(answer) = exchange_udp(*server, query).await {
                        return Some(answer);
                    }
                }
                None
            }
            Upstream::Tls(client) => client.exchange(query).await,
        }
    }
}

fn plain_address(entry: &str) -> Option<SocketAddr> {
    entry.parse::<SocketAddr>().ok().or_else(|| entry.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, DNS_PORT)))
}

fn unspecified_for(address: &SocketAddr) -> SocketAddr {
    match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

async fn exchange_udp(server: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(unspecified_for(&server)).await.ok()?;
    socket.connect(server).await.ok()?;
    socket.send(query).await.ok()?;
    let deadline = Instant::now() + QUERY_TIMEOUT;
    let mut answer = vec![0u8; ANSWER_MAX];
    loop {
        let n = timeout_at(deadline, socket.recv(&mut answer)).await.ok()?.ok()?;
        // Same transaction ID as the query, or it is not our answer.
        if n >= 2 && answer[..2] == query[..2] {
            answer.truncate(n);
            return Some(answer);
        }
    }
}

pub struct DotServer {
    pub address: SocketAddr,
    pub name: ServerName<'static>,
}

impl DotServer {
    /// `IP[:port]#name`.
    fn parse(entry: &str) -> Option<DotServer> {
        let (address, name) = entry.split_once('#')?;
        let address =
            address.parse::<SocketAddr>().ok().or_else(|| address.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, DOT_PORT)))?;
        Some(DotServer { address, name: ServerName::try_from(name.to_string()).ok()? })
    }
}

type Request = (Vec<u8>, oneshot::Sender<Vec<u8>>);

/// A query on the wire: as the app sent it (its own ID), where the answer goes, and when.
struct Waiting {
    query: Vec<u8>,
    reply: oneshot::Sender<Vec<u8>>,
    sent: Instant,
}

/// Queries on one connection, by their wire ID.
type Pending = HashMap<u16, Waiting>;

pub struct DotClient {
    servers: Arc<[DotServer]>,
    connector: TlsConnector,
    /// The session task, started by the first query.
    session: Mutex<Option<mpsc::Sender<Request>>>,
}

impl DotClient {
    /// `extra_roots` are trusted besides Mozilla's (tests use a private CA).
    pub fn new(servers: Vec<DotServer>, extra_roots: Vec<CertificateDer<'static>>) -> DotClient {
        let mut roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        for root in extra_roots {
            let _ = roots.add(root);
        }
        let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("ring supports TLS 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        DotClient { servers: servers.into(), connector: TlsConnector::from(Arc::new(config)), session: Mutex::new(None) }
    }

    /// The same resolvers, also trusting `roots` (a private CA, for tests).
    pub fn trusting(self, roots: Vec<CertificateDer<'static>>) -> DotClient {
        let servers = self.servers.iter().map(|s| DotServer { address: s.address, name: s.name.clone() }).collect();
        DotClient::new(servers, roots)
    }

    async fn exchange(&self, query: &[u8]) -> Option<Vec<u8>> {
        if query.len() < 2 {
            return None;
        }
        let session = {
            let mut session = self.session.lock().unwrap();
            match session.as_ref() {
                Some(sender) if !sender.is_closed() => sender.clone(),
                _ => {
                    let (sender, requests) = mpsc::channel(256);
                    tokio::spawn(run_session(self.servers.clone(), self.connector.clone(), requests));
                    session.insert(sender).clone()
                }
            }
        };
        let (reply, answer) = oneshot::channel();
        session.send((query.to_vec(), reply)).await.ok()?;
        timeout(QUERY_TIMEOUT, answer).await.ok()?.ok()
    }
}

/// Keeps at most one TLS connection, opened when a query arrives. Ends when the client is
/// dropped (a new upstream was chosen).
async fn run_session(servers: Arc<[DotServer]>, connector: TlsConnector, mut requests: mpsc::Receiver<Request>) {
    let mut preferred = 0;
    while let Some(first) = requests.recv().await {
        let mut batch = vec![first];
        // Without a connection the batch fails at once (replies dropped): no plain fallback.
        while let Some((stream, index)) = connect(&servers, &connector, preferred).await {
            // Start from the resolver that worked, so a dead one costs a timeout only once.
            preferred = index;
            match serve(stream, batch, &mut requests).await {
                Ok(()) => break,
                // Dead connection: the next resolver, carrying the queries still waited for.
                Err(waiting) => {
                    preferred = (index + 1) % servers.len();
                    if waiting.is_empty() {
                        break;
                    }
                    batch = waiting;
                }
            }
        }
    }
}

/// Connects to the resolvers in order of preference, each started [`CONNECT_STAGGER`] after the
/// previous one while those are still trying; the first TLS session established wins and the
/// other attempts are dropped.
async fn connect(servers: &[DotServer], connector: &TlsConnector, start: usize) -> Option<(TlsStream<TcpStream>, usize)> {
    let mut attempts: FuturesUnordered<_> = (0..servers.len())
        .map(|offset| {
            let index = (start + offset) % servers.len();
            let server = &servers[index];
            async move {
                tokio::time::sleep(CONNECT_STAGGER * offset as u32).await;
                let attempt = async {
                    let tcp = TcpStream::connect(server.address).await.ok()?;
                    let _ = tcp.set_nodelay(true);
                    connector.connect(server.name.clone(), tcp).await.ok()
                };
                timeout(CONNECT_TIMEOUT, attempt).await.ok().flatten().map(|stream| (stream, index))
            }
        })
        .collect();
    while let Some(result) = attempts.next().await {
        if result.is_some() {
            return result;
        }
    }
    None
}

/// Relays queries over one connection until it fails (false) or stays idle (true). Queries get
/// their own IDs on the wire, so answers in any order find their way back. A query left
/// unanswered past [`STALE_AFTER`] means the connection is dead even if TCP has not noticed yet
/// (network change, a router dropping the state): it is dropped and the queries still waited
/// for go to the next resolver, instead of every query timing out until TCP gives up minutes
/// later. Returns the still-waiting queries if the connection failed.
async fn serve(stream: TlsStream<TcpStream>, batch: Vec<Request>, requests: &mut mpsc::Receiver<Request>) -> Result<(), Vec<Request>> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut pending = Pending::new();
    let mut next_id: u16 = 0;
    let mut inbound = Vec::with_capacity(ANSWER_MAX);
    // Queries whose caller is still waiting, to retry on the next connection.
    let still_waiting =
        |pending: Pending| -> Vec<Request> { pending.into_values().filter(|w| !w.reply.is_closed()).map(|w| (w.query, w.reply)).collect() };
    for request in batch {
        if !send(&mut writer, request, &mut pending, &mut next_id).await {
            return Err(still_waiting(pending));
        }
    }
    loop {
        let oldest = pending.values().map(|waiting| waiting.sent).min();
        tokio::select! {
            request = requests.recv() => match request {
                Some(request) => if !send(&mut writer, request, &mut pending, &mut next_id).await { return Err(still_waiting(pending)) },
                None => return Ok(()),
            },
            read = reader.read_buf(&mut inbound) => match read {
                Ok(n) if n > 0 => deliver(&mut inbound, &mut pending),
                _ => return Err(still_waiting(pending)),
            },
            _ = tokio::time::sleep(IDLE), if pending.is_empty() => {
                let _ = writer.shutdown().await;
                return Ok(());
            }
            _ = tokio::time::sleep_until(oldest.unwrap_or_else(Instant::now) + STALE_AFTER), if oldest.is_some() => return Err(still_waiting(pending)),
        }
    }
}

async fn send(writer: &mut WriteHalf<TlsStream<TcpStream>>, (query, reply): Request, pending: &mut Pending, next_id: &mut u16) -> bool {
    let Ok(length) = u16::try_from(query.len()) else { return true };
    // Skip IDs still waiting (a slow answer) so two queries never share one.
    while pending.contains_key(next_id) {
        *next_id = next_id.wrapping_add(1);
    }
    let id = *next_id;
    *next_id = next_id.wrapping_add(1);
    let mut frame = Vec::with_capacity(query.len() + 2);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(&id.to_be_bytes());
    frame.extend_from_slice(&query[2..]);
    pending.insert(id, Waiting { query, reply, sent: Instant::now() });
    writer.write_all(&frame).await.is_ok() && writer.flush().await.is_ok()
}

/// Hands every complete answer in `inbound` to its query, with the app's ID back in place.
fn deliver(inbound: &mut Vec<u8>, pending: &mut Pending) {
    let mut at = 0;
    while inbound.len() - at >= 2 {
        let length = u16::from_be_bytes([inbound[at], inbound[at + 1]]) as usize;
        let Some(message) = inbound.get(at + 2..at + 2 + length) else { break };
        if length >= 2
            && let Some(waiting) = pending.remove(&u16::from_be_bytes([message[0], message[1]]))
        {
            let mut answer = message.to_vec();
            answer[..2].copy_from_slice(&waiting.query[..2]);
            let _ = waiting.reply.send(answer);
        }
        at += 2 + length;
    }
    inbound.drain(..at);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_tls_lists() {
        let Upstream::Plain(plain) = Upstream::parse("192.168.1.1, [2001:db8::2]:5353,garbage") else { panic!() };
        assert_eq!(plain, vec!["192.168.1.1:53".parse().unwrap(), "[2001:db8::2]:5353".parse().unwrap()]);
        let Upstream::Tls(client) =
            Upstream::parse("tls://1.1.1.1#cloudflare-dns.com, tls://[2606:4700:4700::1111]:853#cloudflare-dns.com, tls://bad, 9.9.9.9")
        else {
            panic!()
        };
        let addresses: Vec<String> = client.servers.iter().map(|s| s.address.to_string()).collect();
        assert_eq!(addresses, ["1.1.1.1:853", "[2606:4700:4700::1111]:853"]);
        assert!(matches!(Upstream::parse(""), Upstream::Plain(p) if p.is_empty()));
    }

    #[test]
    fn delivers_pipelined_answers_in_any_order() {
        let mut pending = Pending::new();
        let (first, mut first_answer) = oneshot::channel();
        let (second, mut second_answer) = oneshot::channel();
        pending.insert(7, Waiting { query: vec![0xAA, 0x01, b'?'], reply: first, sent: Instant::now() });
        pending.insert(8, Waiting { query: vec![0xBB, 0x02, b'?'], reply: second, sent: Instant::now() });
        // The answer to 8, then half of the answer to 7.
        let mut inbound = vec![0, 3, 0, 8, b'x', 0, 3, 0, 7];
        deliver(&mut inbound, &mut pending);
        assert_eq!(second_answer.try_recv().unwrap(), vec![0xBB, 0x02, b'x']);
        assert!(first_answer.try_recv().is_err());
        assert_eq!(inbound, vec![0, 3, 0, 7]);
        inbound.push(b'y');
        deliver(&mut inbound, &mut pending);
        assert_eq!(first_answer.try_recv().unwrap(), vec![0xAA, 0x01, b'y']);
        assert!(inbound.is_empty() && pending.is_empty());
    }
}
