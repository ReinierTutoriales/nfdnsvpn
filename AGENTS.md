# nfdnsvpn — Agent Instructions

## Project
Local VPN-based ad and tracker blocker for Android TV / Google TV. Everything runs on-device: no server, no accounts, no root, no HTTPS decryption. Appears as **NF DNS VPN**.

## Stack
- Kotlin / Android (VPN Service + TUN)
- Native Rust core (`native/nfdns-core`): smoltcp stack, DNS (with CNAME), SNI/Host, QUIC Initial, domain filter, JNI
- Gradle Kotlin DSL
- Modes: Completo (full tunnel + SNI) and Ligero (DNS only)

## Commands
```bash
(cd native/nfdns-core && cargo test)
./gradlew testDebugUnitTest lintDebug
./gradlew assembleDebug
./gradlew assembleRelease
scripts/validate-lists.sh
# e2e (Linux root): sudo scripts/e2e-linux.sh
```
See README for full list and physical TV measurement notes.

## Priorities
- Preserve on-device, no-root, no-HTTPS-decryption design.
- Keep both modes correct: Completo (force DNS, cut DoT/DoQ, SNI/QUIC blocking) and Ligero.
- Low memory and CPU on TV hardware; every buffer/queue has a limit.
- Do not invent VPN, DNS, SNI, or filter behaviors not present in the code or docs/PLAN.md.
- Prefer latest stable dependencies; evaluate regression risk.
- Follow existing code policies (no warnings, tests required, measurable performance, readable, fail-safe).

## Working style
1. Brief analysis + risks (especially tunnel, DNS bypass, memory).
2. Propose the smallest grounded solution.
3. Implement cleanly, matching existing style.
4. Verify against existing tests and contracts.
5. State what is measured vs. what needs real Android TV validation.

## Hard Rules for All Agents (mandatory)
- **Branches**: Never create or push branches whose name contains an AI name, model name, tool name, or any non-owner identifier (examples forbidden: `claude-*`, `gpt-*`, `grok-*`, `ai-*`, `agent-*`, `copilot-*`). Use only descriptive, owner-neutral names.
- **Authorship / signing**: Never commit, sign, or set author/committer to any name, email, or identity that is not the repository owner (`ReinierTutoriales`). Do not use AI names, tool names, or third-party identities in commit messages, trailers, or metadata.
- **Write only what is verified**: Read the relevant files, tests, contracts, and documentation before proposing or writing any change. Do not write code, comments, or docs for the sake of writing. Every addition must be the minimal change that solves a demonstrated need and is traceable to existing code or a clearly labeled assumption.
- **Documentation**: Update or create documentation only when it reflects verified current behavior. Do not invent APIs, policies, or guarantees. Prefer updating existing docs over creating new ones. Keep docs short, precise, and consistent with the code.
- **Optimal code**: Prefer the simplest correct solution that matches existing style and patterns. Avoid speculative refactors, unused helpers, extra abstractions, or "improvements" without measured benefit. Verify against tests and contracts before considering the change complete.

## Rules
- Match existing Rust/Kotlin style and patterns.
- Keep changes focused; do not touch unrelated files.
- Prefer the simplest correct fix that preserves security and low-resource behavior.
- Update README or docs/PLAN.md when behavior changes.
- Respect authorship rules in CLAUDE.md (commits as ReinierTutoriales only).

## Skills
Use skills from `.agents/skills/` when relevant, especially `precise-coding` and `agent-governance` for any code or documentation change.
