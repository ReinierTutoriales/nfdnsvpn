//! Cutting chosen apps off the network entirely, whatever they connect to.
//!
//! Every packet reaching the tunnel comes from some app, but a packet does not say which one.
//! Android tells the VPN app who owns a connection (`ConnectivityManager.getConnectionOwnerUid`,
//! Android 10+); the platform side implements [`OwnerLookup`] with it. A lookup is a binder call,
//! so it runs on a thread of its own, and only while at least one app is blocked: with none, a
//! new flow costs one read lock and nothing else.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::timeout;

/// A lookup slower than this lets the flow through: an owner that cannot be found (a socket
/// already closed, an unsupported device) must not cut every app off.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Finds the Linux uid of the app that owns a connection; `None` if unknown.
pub trait OwnerLookup: Send + 'static {
    /// `local` is the app's end of the connection, `remote` the destination it wrote to.
    fn owner(&mut self, protocol: Protocol, local: SocketAddr, remote: SocketAddr) -> Option<u32>;
}

type Request = (Protocol, SocketAddr, SocketAddr, oneshot::Sender<Option<u32>>);

#[derive(Default)]
pub struct AppGate {
    blocked: RwLock<Arc<HashSet<u32>>>,
    lookups: Mutex<Option<mpsc::Sender<Request>>>,
}

impl AppGate {
    /// Replaces the blocked uids; new flows use them at once. Flows already open keep going.
    pub fn set_blocked(&self, uids: impl IntoIterator<Item = u32>) {
        *self.blocked.write().unwrap() = Arc::new(uids.into_iter().collect());
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

    /// Whether the flow belongs to a blocked app.
    pub async fn blocks(&self, protocol: Protocol, local: SocketAddr, remote: SocketAddr) -> bool {
        let blocked = self.blocked.read().unwrap().clone();
        if blocked.is_empty() {
            return false;
        }
        let Some(lookups) = self.lookups.lock().unwrap().clone() else { return false };
        let (reply, answer) = oneshot::channel();
        if lookups.send((protocol, local, remote, reply)).is_err() {
            return false;
        }
        matches!(timeout(LOOKUP_TIMEOUT, answer).await, Ok(Ok(Some(uid))) if blocked.contains(&uid))
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

    fn flow(gate: &AppGate, port: u16) -> bool {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let local = SocketAddr::from(([10, 111, 0, 2], port));
        runtime.block_on(gate.blocks(Protocol::Tcp, local, "192.0.2.1:443".parse().unwrap()))
    }

    #[test]
    fn blocks_only_the_chosen_uids() {
        let gate = AppGate::default();
        gate.set_blocked([10123]);
        assert!(!flow(&gate, 10123), "no lookup yet: let through");
        gate.set_lookup(ByPort).unwrap();
        assert!(flow(&gate, 10123));
        assert!(!flow(&gate, 10124));
        assert!(!flow(&gate, 1), "unknown owner: let through");
        gate.set_blocked([]);
        assert!(!flow(&gate, 10123));
    }
}
