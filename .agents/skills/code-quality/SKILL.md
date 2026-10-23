---
name: code-quality
description: Use when optimizing, cleaning, or reviewing code. Prioritizes simplicity, low-resource behavior, readability, and production readiness.
---

# Code Quality

- Analyze for real improvements in clarity, performance, memory, and maintainability.
- Prefer the simplest correct solution that matches existing style.
- No avoidable allocations, locks, or syscalls on the packet/connection hot path.
- Every queue, cache, or buffer must have a hard limit.
- If a superior alternative exists, choose the most production-solid one; state what improved and why.
- Do not break mode correctness, DNS forcing, or fail-safe behavior.
- Keep changes focused and measurable. Do not write for the sake of writing.
- Verify against existing tests and contracts before considering the change complete.
- Update documentation only when it reflects verified current behavior.
- Note any remaining need for real Android TV validation.
- Follow agent-governance rules on branches and authorship.
