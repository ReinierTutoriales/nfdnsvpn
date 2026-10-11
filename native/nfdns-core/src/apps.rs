//! Rules for chosen apps: cut off the network entirely ("blocked"), or only allowed to reach
//! what they can name ("watched").
//!
//! Every packet reaching the tunnel comes from some app, but a packet does not say which one.
//! Android tells the VPN app who owns a connection (`ConnectivityManager.getConnectionOwnerUid`,
//! Android 10+); the platform side implements [`OwnerLookup`] with it. A lookup is a binder call,
//! so it runs on a thread of its own, and only while some app has a rule: with none, a new flow
//! costs two read locks and nothing else.
//!
//! A watched app may connect only to a readable, allowed server name (TLS SNI, HTTP `Host`, QUIC
//! Initial) or to an address that the tunnel's own DNS gave out. Hardcoded IPs, its own resolver
//! and nameless protocols are cut. What it reaches is kept per app ([`AppGate::activity`]), so its
//! telemetry domains can be picked out and blocked one by one.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio::time::timeout;

/// A lookup slower than this lets the flow through: an owner that cannot be found (a socket
/// already closed, an unsupported device) must not cut every app off.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);
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
    lookups: Mutex<Option<mpsc::Sender<Request>>>,
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
        let (sender, requests) = mpsc::channel::<Request>();
        thread::Builder::new().name("nfdns-owner".into()).spawn(move || {
            for (protocol, local, remote, reply) in requests {
                let _ = reply.send(lookup.owner(protocol, local, remote));
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
        if lookups.send((protocol, local, remote, reply)).is_err() {
            return AppRule::Normal;
        }
        match timeout(LOOKUP_TIMEOUT, answer).await {
            Ok(Ok(Some(uid))) if blocked.contains(&uid) => AppRule::Blocked,
            Ok(Ok(Some(uid))) if watched.contains(&uid) => AppRule::Watched(uid),
            _ => AppRule::Normal,
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
        assert_eq!(flow(&gate, 1), AppRule::Normal, "unknown owner: let through");
        gate.set_blocked([]);
        gate.set_watched([]);
        assert_eq!(flow(&gate, 10123), AppRule::Normal);
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
