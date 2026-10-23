---
name: precise-coding
description: Use when writing or modifying any code. Forces grounded output by verifying against the existing codebase. Reduces hallucinations and token waste.
---

# Precise Coding (Anti-Hallucination)

1. Read the relevant existing Rust/Kotlin/JNI files, tests, and docs/PLAN.md before writing anything.
2. Never invent VPN Service behaviors, DNS/SNI/QUIC handling, filter rules, or APIs not already present or clearly documented.
3. If unclear, state the assumption explicitly instead of inventing.
4. Prefer the smallest change that matches existing patterns and preserves on-device, no-decryption design.
5. Do not claim correctness, compilation, or test passage unless reasoned from the actual project files.
6. Write only the precise code needed. Do not write for the sake of writing. Avoid speculative refactors or unused code.
7. Update documentation only when it reflects verified current behavior. Prefer editing existing docs over creating new ones.
8. Follow agent-governance rules: no AI-named branches, no authorship other than the repository owner.

Every line must be traceable to existing code or a clearly labeled minimal assumption.
