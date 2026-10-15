---
name: performance-hotpath
description: Use when considering or implementing performance changes on the packet, DNS, or tunnel path. Enforces measurement and hard limits.
---

# Performance Hot Path

- No avoidable allocations, locks, or syscalls on the per-packet or per-connection path.
- Optional features must cost nothing while disabled.
- Every queue, cache, or buffer has a hard limit.
- Measure before claiming improvement (`cargo run --release --example measure`, `--bench`, or e2e).
- Do not trade correctness of DNS forcing, SNI/QUIC blocking, or fail-safe behavior for speed.
- Prefer changes justified by real measurements on TV hardware or representative benches.
