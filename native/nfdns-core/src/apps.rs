//! Rules for chosen apps: cut off the network entirely ("blocked"), or only allowed to reach
//! what they can name ("watched").
//!
//! Every packet reaching the tunnel comes from some app, but a packet does not say which one.
//! Android tells the VPN app who owns a connection (`ConnectivityManager.getConnectionOwnerUid`,
//! Android 10+); the platform side implements [`OwnerLookup`] with it. A lookup is a binder call,
//! so it runs on a thread of its own, and only while some app has a rule: with none, a new flow
//! costs two read locks and nothing else.
//!
//! When the owner cannot be found (lookup slow or saturated, socket already gone) the flow is
//! dropped, so a blocked app cannot slip through by flooding the lookup with connections. The one
//! exception: a device whose lookup has never answered (broken or unsupported), where dropping
//! would cut every app off; there flows pass.
//!
//! A watched app may connect only to a readable, allowed server name (TLS SNI, HTTP `Host`, QUIC
//! Initial) or to an address that the tunnel's own DNS gave out. Hardcoded IPs, its own resolver
//! and nameless protocols are cut. What it reaches is kept per app ([`AppGate::activity`]), so its
//! telemetry domains can be picked out and blocked one by one.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::time::timeout;

/// A lookup takes well under a millisecond; one slower than this means the queue is flooded.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);
/// Lookups waiting at most; more new flows than this at once are refused, not queued.
const LOOKUP_QUEUE: usize = 256;
/// Resolved addresses kept for watched apps: ~70 bytes each, about 1 MB at most.
const RESOLVED_LIMIT: usize = 16 * 1024;
/// An address stays valid at least this long, whatever its TTL: apps keep answers a while.
const RESOLVED_MIN_TTL: Duration = Duration::from_secs(5 * 60);
const RESOLVED_MAX_TTL: Duration = Duration::from_secs(6 * 60 * 60);
const RESOLVED_GRACE: Duration = Duration::from_secs(10 * 60);
/// Distinct destinations remembered per watched app, most recent first.
const ACTIVITY_LIMIT: usize = 50;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// What applies to a new flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppRule {
    Normal,
    Blocked,
    /// Watched app (its uid): only names it can show, or addresses from our DNS.
    Watched(u32),
    /// Rules are active but the owner could not be found: treated as blocked, except for DNS,
    /// which the system resolver sends on behalf of every app and is filtered anyway.
    Unknown(Unknown),
    /// The owner could not be found and the lookup has never found one on this device (broken or
    /// unsupported): let through as [`AppRule::Normal`], but counted like [`AppRule::Unknown`].
    Unverified(Unknown),
}

/// Why an owner could not be found (counted separately, to tell them apart when flows drop).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unknown {
    /// The lookup answered: no socket matched.
    NoOwner,
    /// No answer within [`LOOKUP_TIMEOUT`].
    Timeout,
    /// More new flows at once than the lookup queue holds.
    QueueFull,
    /// The lookup thread is gone (its queue or the reply channel closed).
    Disconnected,
}

/// Finds the Linux uid of the app that owns a connection; `None` if unknown.
pub trait OwnerLookup: Send + 'static {
    /// `local` is the app's end of the connection, `remote` the destination it wrote to.
    fn owner(&mut self, protocol: Protocol, local: SocketAddr, remote: SocketAddr) -> Option<u32>;
}

type Request = (Protocol, SocketAddr, SocketAddr, oneshot::Sender<Option<u32>>);
/// Destinations of one watched app, most recent first: (name or address, refused).
type Activity = VecDeque<(Arc<str>, bool)>;

#[derive(Default)]
pub struct AppGate {
    blocked: RwLock<Arc<HashSet<u32>>>,
    watched: RwLock<Arc<HashSet<u32>>>,
    lookups: Mutex<Option<mpsc::SyncSender<Request>>>,
    /// The lookup has found an owner at least once, so an unknown owner is not a broken device.
    proven: Arc<AtomicBool>,
    /// Address -> (valid until, name asked for). Filled only while some app is watched.
    resolved: Mutex<HashMap<IpAddr, (Instant, Arc<str>)>>,
    activity: Mutex<HashMap<u32, Activity>>,
}

impl AppGate {
    /// Replaces the blocked uids; new flows use them at once. Flows already open keep going.
    pub fn set_blocked(&self, uids: impl IntoIterator<Item = u32>) {
        *self.blocked.write().unwrap() = Arc::new(uids.into_iter().collect());
    }

    /// Replaces the watched uids (a blocked uid stays blocked). Activity of the others is dropped.
    pub fn set_watched(&self, uids: impl IntoIterator<Item = u32>) {
        let uids: HashSet<u32> = uids.into_iter().collect();
        self.activity.lock().unwrap().retain(|uid, _| uids.contains(uid));
        if uids.is_empty() {
            self.resolved.lock().unwrap().clear();
        }
        *self.watched.write().unwrap() = Arc::new(uids);
    }

    pub fn has_lookup(&self) -> bool {
        self.lookups.lock().unwrap().is_some()
    }

    /// Starts the thread that answers lookups; it ends when the gate is dropped.
    pub fn set_lookup(&self, mut lookup: impl OwnerLookup) -> std::io::Result<()> {
        let (sender, requests) = mpsc::sync_channel::<Request>(LOOKUP_QUEUE);
        let proven = self.proven.clone();
        thread::Builder::new().name("nfdns-owner".into()).spawn(move || {
            for (protocol, local, remote, reply) in requests {
                // A flow whose caller already gave up needs no binder call.
                if reply.is_closed() {
                    continue;
                }
                let owner = lookup.owner(protocol, local, remote);
                if owner.is_some() {
                    proven.store(true, Ordering::Relaxed);
                }
                let _ = reply.send(owner);
            }
        })?;
        *self.lookups.lock().unwrap() = Some(sender);
        Ok(())
    }

    fn watching(&self) -> bool {
        !self.watched.read().unwrap().is_empty()
    }

    /// The rule for a new flow.
    pub async fn rule(&self, protocol: Protocol, local: SocketAddr, remote: SocketAddr) -> AppRule {
        let blocked = self.blocked.read().unwrap().clone();
        let watched = self.watched.read().unwrap().clone();
        if blocked.is_empty() && watched.is_empty() {
            return AppRule::Normal;
        }
        let Some(lookups) = self.lookups.lock().unwrap().clone() else { return AppRule::Normal };
        let (reply, answer) = oneshot::channel();
        let owner = match lookups.try_send((protocol, local, remote, reply)) {
            Ok(()) => match timeout(LOOKUP_TIMEOUT, answer).await {
                Ok(Ok(Some(uid))) => Ok(uid),
                Ok(Ok(None)) => Err(Unknown::NoOwner),
                // The reply was dropped unanswered: the lookup thread ended.
                Ok(Err(_)) => Err(Unknown::Disconnected),
                Err(_) => Err(Unknown::Timeout),
            },
            // More new flows at once than lookups can keep up with.
            Err(mpsc::TrySendError::Full(_)) => Err(Unknown::QueueFull),
            Err(mpsc::TrySendError::Disconnected(_)) => Err(Unknown::Disconnected),
        };
        match owner {
            Ok(uid) if blocked.contains(&uid) => AppRule::Blocked,
            Ok(uid) if watched.contains(&uid) => AppRule::Watched(uid),
            Ok(_) => AppRule::Normal,
            Err(why) if self.proven.load(Ordering::Relaxed) => AppRule::Unknown(why),
            // Never answered: a broken lookup must not cut every app off (counted all the same).
            Err(why) => AppRule::Unverified(why),
        }
    }

    /// Remembers the addresses our DNS gave out for `name` (only while some app is watched).
    pub fn remember_answer(&self, name: &str, addresses: &[(IpAddr, u32)]) {
        if addresses.is_empty() || !self.watching() {
            return;
        }
        let now = Instant::now();
        let name: Arc<str> = Arc::from(name);
        let mut resolved = self.resolved.lock().unwrap();
        if resolved.len() + addresses.len() > RESOLVED_LIMIT {
            resolved.retain(|_, (until, _)| *until > now);
            if resolved.len() + addresses.len() > RESOLVED_LIMIT {
                // Still full of live answers: start over rather than grow (apps resolve again).
                resolved.clear();
            }
        }
        for &(ip, ttl) in addresses {
            let ttl = Duration::from_secs(ttl.into()).clamp(RESOLVED_MIN_TTL, RESOLVED_MAX_TTL);
            resolved.insert(ip, (now + ttl + RESOLVED_GRACE, name.clone()));
        }
    }

    /// The name an address was resolved from, if our DNS gave it out and it has not expired.
    pub fn resolved_name(&self, ip: IpAddr) -> Option<Arc<str>> {
        let resolved = self.resolved.lock().unwrap();
        resolved.get(&ip).filter(|(until, _)| *until > Instant::now()).map(|(_, name)| name.clone())
    }

    /// Notes where a watched app went (or tried to go).
    pub fn record(&self, uid: u32, destination: &str, refused: bool) {
        let mut activity = self.activity.lock().unwrap();
        let entries = activity.entry(uid).or_default();
        entries.retain(|(seen, _)| &**seen != destination);
        entries.push_front((Arc::from(destination), refused));
        entries.truncate(ACTIVITY_LIMIT);
    }

    /// One line per destination of a watched app, most recent first: `1<TAB>name` if refused,
    /// `0<TAB>name` if allowed.
    pub fn activity(&self, uid: u32) -> String {
        let activity = self.activity.lock().unwrap();
        let Some(entries) = activity.get(&uid) else { return String::new() };
        entries.iter().map(|(name, refused)| format!("{}\t{name}\n", u8::from(*refused))).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ByPort;

    impl OwnerLookup for ByPort {
        fn owner(&mut self, _: Protocol, local: SocketAddr, _: SocketAddr) -> Option<u32> {
            (local.port() != 1).then(|| u32::from(local.port()))
        }
    }

    fn flow(gate: &AppGate, port: u16) -> AppRule {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let local = SocketAddr::from(([10, 111, 0, 2], port));
        runtime.block_on(gate.rule(Protocol::Tcp, local, "192.0.2.1:443".parse().unwrap()))
    }

    #[test]
    fn applies_the_rule_of_the_owner() {
        let gate = AppGate::default();
        gate.set_blocked([10123]);
        assert_eq!(flow(&gate, 10123), AppRule::Normal, "no lookup yet: let through");
        gate.set_lookup(ByPort).unwrap();
        gate.set_watched([10123, 10125]);
        assert_eq!(flow(&gate, 10123), AppRule::Blocked, "blocked wins over watched");
        assert_eq!(flow(&gate, 10124), AppRule::Normal);
        assert_eq!(flow(&gate, 10125), AppRule::Watched(10125));
        assert_eq!(flow(&gate, 1), AppRule::Unknown(Unknown::NoOwner), "unknown owner on a working lookup");
        gate.set_blocked([]);
        gate.set_watched([]);
        assert_eq!(flow(&gate, 10123), AppRule::Normal);
    }

    struct Never;

    impl OwnerLookup for Never {
        fn owner(&mut self, _: Protocol, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            None
        }
    }

    #[test]
    fn a_lookup_that_never_answers_lets_flows_through() {
        let gate = AppGate::default();
        gate.set_blocked([10123]);
        gate.set_lookup(Never).unwrap();
        // Let through, but reported with its reason (counted by the tunnel), not hidden.
        assert_eq!(flow(&gate, 10123), AppRule::Unverified(Unknown::NoOwner));
    }

    /// Holds the lookup thread on its first request until `release` is dropped or sent to.
    struct Held(std::sync::Mutex<mpsc::Receiver<()>>);

    impl OwnerLookup for Held {
        fn owner(&mut self, _: Protocol, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            let _ = self.0.lock().unwrap().recv();
            Some(10200)
        }
    }

    #[test]
    fn a_full_queue_is_told_apart() {
        let gate = AppGate::default();
        gate.set_blocked([10123]);
        let (release, held) = mpsc::channel();
        gate.set_lookup(Held(std::sync::Mutex::new(held))).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let local = |port| SocketAddr::from(([10, 111, 0, 2], port));
        let remote: SocketAddr = "192.0.2.1:443".parse().unwrap();
        // The thread takes at most one request and blocks on it: of 300 at once, the queue holds
        // 256, so at least 43 find it full, whatever the scheduling.
        let rules = runtime.block_on(async {
            let flows = (0..300).map(|i| gate.rule(Protocol::Tcp, local(20000 + i), remote));
            let all = futures::future::join_all(flows);
            let unblock = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                drop(release);
            };
            futures::join!(all, unblock).0
        });
        let full = rules.iter().filter(|r| **r == AppRule::Unverified(Unknown::QueueFull)).count();
        assert!(full >= 300 - LOOKUP_QUEUE - 1, "{full} reported a full queue");
        assert!(!rules.contains(&AppRule::Unverified(Unknown::NoOwner)), "a full queue is not a missing owner");
    }

    struct Crashes;

    impl OwnerLookup for Crashes {
        fn owner(&mut self, _: Protocol, _: SocketAddr, _: SocketAddr) -> Option<u32> {
            panic!("lookup thread ends");
        }
    }

    #[test]
    fn a_lookup_thread_that_ended_is_told_apart() {
        let gate = AppGate::default();
        gate.set_blocked([10123]);
        gate.set_lookup(Crashes).unwrap();
        // The reply is dropped unanswered, then the queue itself is closed: both are reported as
        // disconnected, never as "no owner" or a timeout.
        for port in [1000, 1001, 1002] {
            assert_eq!(flow(&gate, port), AppRule::Unverified(Unknown::Disconnected), "port {port}");
        }
    }

    struct Slow;

    impl OwnerLookup for Slow {
        fn owner(&mut self, _: Protocol, local: SocketAddr, _: SocketAddr) -> Option<u32> {
            if local.port() == 2 {
                thread::sleep(LOOKUP_TIMEOUT * 2);
            }
            Some(u32::from(local.port()))
        }
    }

    #[test]
    fn a_flooded_lookup_drops_instead_of_letting_through() {
        let gate = AppGate::default();
        gate.set_blocked([10123]);
        gate.set_lookup(Slow).unwrap();
        assert_eq!(flow(&gate, 10124), AppRule::Normal);
        // Port 2 stalls the lookup thread past the timeout: the blocked app's flow is not let go.
        assert_eq!(flow(&gate, 2), AppRule::Unknown(Unknown::Timeout));
    }

    #[test]
    fn remembers_answers_only_while_watching() {
        let gate = AppGate::default();
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        gate.remember_answer("cdn.example", &[(ip, 30)]);
        assert!(gate.resolved_name(ip).is_none(), "nothing watched: nothing kept");
        gate.set_watched([10125]);
        gate.remember_answer("cdn.example", &[(ip, 30)]);
        assert_eq!(gate.resolved_name(ip).as_deref(), Some("cdn.example"));
        gate.set_watched([]);
        assert!(gate.resolved_name(ip).is_none());
    }

    #[test]
    fn keeps_distinct_recent_activity() {
        let gate = AppGate::default();
        gate.set_watched([7]);
        gate.record(7, "a.example", false);
        gate.record(7, "203.0.113.5", true);
        gate.record(7, "a.example", false);
        assert_eq!(gate.activity(7), "0\ta.example\n1\t203.0.113.5\n");
        for i in 0..ACTIVITY_LIMIT + 5 {
            gate.record(7, &format!("n{i}.example"), false);
        }
        assert_eq!(gate.activity(7).lines().count(), ACTIVITY_LIMIT);
        gate.set_watched([]);
        assert_eq!(gate.activity(7), "");
    }
}
