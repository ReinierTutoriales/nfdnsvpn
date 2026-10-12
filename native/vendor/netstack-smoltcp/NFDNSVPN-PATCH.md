# netstack-smoltcp 0.2.4, vendored for nfdnsvpn

Copied from crates.io (MIT OR Apache-2.0, licences unchanged in this folder), without its
examples and tests. Two changes, in `src/tcp.rs`:

- With no smoltcp timer pending the TCP runner parked for 5 ms and polled again, 200 times a
  second for as long as the stack exists, even with no connection at all. It now parks until
  notified (every ingress packet and stream operation notifies it; a `Notify` permit is never
  lost), with a 30 s safety net. Measured on the idle tunnel: about 176 wake-ups/s before.
- The per-socket timeout (abort when the peer stops acknowledging, keep-alive probes included)
  was Linux's 7200 s, marked FIXME upstream: a peer that stopped answering kept the socket and its
  buffers (~64 KiB) for two hours. It is now 120 s; with the 28 s keep-alive a live app always
  answers well within it.

Wired in through `[patch.crates-io]` in `native/nfdns-core/Cargo.toml`.
