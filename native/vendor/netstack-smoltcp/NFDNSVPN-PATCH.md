# netstack-smoltcp 0.2.4, vendored for nfdnsvpn

Copied from crates.io (MIT OR Apache-2.0, licences unchanged in this folder), without its
examples and tests. One change, in `src/tcp.rs`:

- With no smoltcp timer pending the TCP runner parked for 5 ms and polled again, 200 times a
  second for as long as the stack exists, even with no connection at all. It now parks until
  notified (every ingress packet and stream operation notifies it; a `Notify` permit is never
  lost), with a 30 s safety net. Measured on the idle tunnel: about 176 wake-ups/s before.

Wired in through `[patch.crates-io]` in `native/nfdns-core/Cargo.toml`.
