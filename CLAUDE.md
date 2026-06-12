# CLAUDE.md — Sembazuru working agreement

This file is read on every session. It encodes how we work, not just what we build.
Keep it short. When a plan exposes a wrong assumption, fix it *here* so the next session inherits the correction.

## Language

Converse with me in **Japanese** — explanations, plans, questions, and proposals all in Japanese, even when I prompt you in English.

- **Japanese:** anything the project lead must read to decide or confirm — decision documents (`docs/decisions/`), plans, review requests — and **commit messages**. A decision document the decider can't read is not evidence.
- **English:** code, comments, branch names, and outward-facing docs (README, protocol specs) for the OSS audience.

(Corrected 2026-06-12: the original "all repo artifacts in English" rule made the VFS decision doc unreadable to the decision owner.)

## What this project is

Sembazuru distributes **arbitrary Windows processes** with zero configuration by virtualizing process I/O (hook locally → run remotely → stream files on demand → return outputs). The technical core is process virtualization, not distributed compilation. Full rationale: `docs/DESIGN.md`. Read it before proposing architecture.

## Stack

- **Hooking layer:** C++, built on a vendored fork of Detours (MIT). Keep this layer thin.
- **Agent / Worker / CAS:** Rust. Everything that isn't a raw Win32 hook lives here.
- **Protocol:** bespoke. Control plane on gRPC; the file-supply data plane is measured and kept on a low-overhead transport (latency is the whole game).

## Non-negotiables

1. **Correctness > speed.** A build that breaks "sometimes" loses all trust instantly. The determinism harness (M2) is a quality gate, not a feature.
2. **Local fallback always works.** If the network or a worker dies, the build must still complete locally.
3. **No UBA code, ever.** Unreal Build Accelerator is EULA-licensed. Study its design; never copy its code. Maintain clean-room separation.
4. **clang-cl stays a first-class target.** MSVC remote execution is a licensing grey area; never let the design depend on MSVC alone.

## Model policy (who thinks, who types)

- **Main session runs on Fable (`claude-fable-5`).** Orchestration, Plan Mode, architectural decisions, and integration judgment concentrate here — keep the strongest model where being wrong is most expensive.
- **Quality stays on Fable:** `verifier`, `security-reviewer`, and `determinism-checker` run on Fable. Review and QA are where capability pays for itself.
- **Volume stays cheap:** `researcher` and `implementer` run on Sonnet (`claude-sonnet-4-6`). Reading source, summarizing, and routine implementation don't need the top model — the Fable-tier verifier catches what they miss.
- **Exception:** load-bearing code — the hook layer, the protocol, the VFS core — is implemented directly in the Fable main thread, not delegated.
- Model availability drifts; check with `/model` and update the strings here if they change.

## Workflow (how every change happens)

1. **Plan before writing.** For any non-trivial change, use Plan Mode first. Solving the wrong problem is the most expensive token sink there is. Read-only/trivial edits skip this.
2. **Push exploration into subagents.** Reading BuildXL/Detours source, mapping a dependency, surveying competitors — delegate to a subagent so the exploration does **not** pollute the main context. Only the summary returns.
3. **Verify with a different agent than the one who wrote the code.** The author should not grade their own work. A verification subagent (fresh context, allowed to *refute*) checks the result.
4. **Show evidence, not assertions.** "Tests pass" is not acceptable; paste the command run and its output, the byte-diff, the trace. Reviewing evidence is cheaper than re-running it.

## Token discipline (context is a budget)

- **Never read large files whole** when a targeted `grep`/range read answers the question. Delegate broad reads to a subagent.
- **Keep the main thread for decisions and integration.** Investigation belongs in side windows.
- **`/compact` policy:** compact at natural milestone boundaries, preserving the current plan, the active "Done when" condition, and open decisions. Discard resolved exploration.
- **Plan Mode is a token saver, not overhead** on anything where being wrong costs a rewrite (the hooking layer, the protocol, the VFS). Rewrites cost far more than plans.

## Quality gates (must pass before a milestone is "Done")

- Code is formatted and linted (Rust: `cargo fmt` + `cargo clippy -D warnings`; C++: keep the surface minimal and reviewed).
- The relevant "Done when" from `docs/DESIGN.md` is met *with evidence*.
- For anything touching build output: the **determinism harness passes** (byte-identical outputs for identical inputs).
- The hooking/worker layers got a security-minded review pass (memory safety, and "does this look like malware to an EDR").

## Commits

Small, single-purpose, evidence-backed. A commit message says *why*, not just *what*. Reference the milestone (e.g. `M1:`).

## Things that will bite us (keep in view)

- Detours upstream is effectively frozen — our fork is our responsibility; pin and track Windows-update breakage in CI.
- API hooks look like malware to AV/EDR. Signing and allowlist work is M7, but don't design something un-signable.
- The VFS small-file latency problem is the make-or-break of M3. Batch, prefetch, and cut round-trips from the start.
