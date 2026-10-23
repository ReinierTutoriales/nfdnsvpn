---
name: testing-discipline
description: Use when adding features or changing logic. Enforces required tests and no relaxation of coverage.
---

# Testing Discipline

- Prefer running or reasoning about:
  ```bash
  (cd native/nfdns-core && cargo test)
  ./gradlew testDebugUnitTest lintDebug
  ```
- Every new behavior needs a unit test (Rust or JVM). Tunnel changes also need coverage in scripts/e2e-linux.sh.
- Do not relax or weaken existing tests.
- A change is incomplete until consistent with the test baseline and CI expectations.
- Explicitly call out gaps that need real Android TV device validation.
- Follow agent-governance rules on branches and authorship.
