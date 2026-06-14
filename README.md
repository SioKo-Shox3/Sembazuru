<div align="center">

# 千羽 Sembazuru

**Run any Windows process distributed, with zero configuration.**

*A thousand workers fold a single build, like a thousand cranes fold into one.*

[![status](https://img.shields.io/badge/status-pre--alpha%20(M1)-orange)]()
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)]()
[![platform](https://img.shields.io/badge/platform-Windows-lightgrey)]()

</div>

---

## What is this?

Sembazuru is an open-source build acceleration platform that distributes **arbitrary Windows processes** across many machines — without forcing you to rewrite your build scripts or adopt a new build description language.

It targets the one thing that makes proprietary distributed-build tools expensive: **process virtualization.** A process launched locally is intercepted, shipped to a remote worker, and made to believe it is still running on your machine — file system and all. Files stream on demand; outputs come back; the caller never knows the difference.

If it works for a compiler, it works for a shader compiler, a test runner, or an asset baker. That generality is the goal.

## Why it exists

Distributed builds shouldn't be gated behind per-core licensing that scales with your pain. The hard part — transparent process virtualization — is buildable in the open. This project is a long-horizon effort to make that capability free.

We are clear-eyed about the moat: the incumbent's real advantage is a decade-plus of compatibility edge cases, not the core idea. So the realistic win is **driving the price floor down and becoming a credible alternative in the non-UE, general-Windows segment** — not a fantasy of overnight displacement.

## How it works

```
Local machine                                    Remote
┌─────────────────────────────┐
│ Build system (MSBuild/Ninja) │
│        │ launch intercepted  │
│        ▼                     │
│  Interceptor (C++/Detours)   │  hooks file I/O + child procs
│        │                     │
│  Local Agent (Rust)          │
│   • Virtual FS (on-demand)   │ ───── custom protocol ─────▶  Worker (Rust)
│   • Scheduler                │                                • sandboxed exec
│   • Prefetch (latency hide)  │ ◀──── outputs returned ─────   • local cache
│   • Local fallback           │
└─────────────────────────────┘                               CAS (dedup + cache)
```

The technical core is **not** distributed compilation — it is making any process's I/O transparently remote. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full architecture and rationale.

## The tracer (M1) — usable today

The first milestone ships as a standalone **build-dependency tracer**. It
injects an observe-only DLL into a compiler process (and its children),
records every file, child-process, registry, and environment access at the
Win32 layer, and reconstructs the complete input/output dependency graph.
Nothing is modified — it only watches.

Build it (needs Visual Studio with the C++ toolset, CMake, and Rust):

```powershell
cmake -S hooks -B hooks/build -A x64
cmake --build hooks/build --config Release
cargo build -p sembazuru-tracer --release
```

Trace a compile and read back the dependency graph (run from a VS developer
shell so `cl.exe` is on PATH):

```powershell
$env:SEMBAZURU_TRACE_DIR = "$PWD\trace"
hooks\build\Release\launcher.exe hooks\build\Release\sbz_interceptor64.dll `
    cl /nologo main.c

target\release\sembazuru-trace.exe export --trace-dir "$PWD\trace" --json
```

The JSON contains the process tree, the `inputs` set (sources, headers,
libraries — including failed include-path probes, which are real
dependencies), the `outputs` set (surviving artifacts), separated
`deletions` (transients), and registry/environment reads. `sembazuru-trace
diff --trace-dir A --trace-dir B` compares two runs and exits non-zero if
their input/output sets differ — the reproducibility check at the heart of
the milestone.

The on-disk trace format is specified in
[`docs/trace-format.md`](docs/trace-format.md). Known limitation: only the
Win32 API layer is hooked, so toolchains that issue `Nt*` syscalls directly
(msys2/Cygwin) are out of scope for M1; the bundled smoke harness
cross-checks completeness against `cl /showIncludes` to prove the Win32
surface is sufficient for MSVC and clang-cl.

## Distributed builds (M6) — try it

The remote-execution path is wired end to end and exercised in CI: point an
existing **CMake/Ninja** or **MSBuild** project at the launcher and its compiles
run on a worker, with the action cache and local fallback working. A distributed
`clang-cl` object is byte-identical to a local build, an incremental header edit
recompiles only its dependents, and stopping the daemon falls back to a normal
local compile. This is the **single-machine** path today (real two-machine LAN is
a separate, deferred milestone). Step-by-step: [`docs/quickstart.md`](docs/quickstart.md).

## Roadmap

Milestones advance by a **"Done when"** condition, not by date. This is a spare-time, long-horizon project; each milestone is designed to be independently useful if published on its own.

| | Milestone | Done when |
|---|---|---|
| **M0** | Recon & foundations | Minimal DLL hooks one `cl.exe` call; VFS approach & protocol skeleton decided |
| **M1** | Process tracer | Full, reproducible input/output dependency graph for any compiler invocation |
| **M2** | Determinism harness | Same input hash → same output hash, stably, across representative TUs |
| **M3** | 1:1 remote exec | Byte-identical `.obj` from a remote worker, *without* latency collapse |
| **M4** | CAS & cache | Second build transfers ~nothing and recompiles ~nothing |
| **M5** | Scheduler & fanout | Compile phase scales at usable parallel efficiency across N workers |
| **M6** | Build-system integrations | Existing projects build distributed with minimal setup |
| **M7** | Hardening | Reliable enough for daily use (signing, AV allowlist, OS-update CI) |
| **M8** | Beyond compilation | Non-compile workloads distribute with no special support |

**First deliverable:** M1, the process tracer, shipped as a standalone "build dependency tracer." It exercises the hardest primitive (hooking) in a safe, observe-only mode and is useful by itself.

## A note on licensing & scope

This project stands on the shoulders of permissively-licensed work, and is careful about what it does **not** borrow:

- **Detours (MIT)** — used as the hooking foundation. Note its stable release predates active maintenance, so we vendor and maintain our own fork.
- **BuildXL (MIT core)** — studied for its sandbox design; MIT portions may be reused.
- **Unreal Build Accelerator** — **studied for design only.** It is under the Unreal Engine EULA, not a permissive license; no code is copied into this repository. Clean-room discipline applies.
- **Remote Execution API (Apache-2.0)** — we borrow CAS/action-cache *design ideas*, not the execution protocol (ours is bespoke).

Running MSVC's `cl.exe` on remote machines sits in a licensing grey area under the Visual Studio license; **clang-cl support runs in parallel as an escape hatch** and is a first-class target, not an afterthought.

> This is not legal advice. Verify every upstream LICENSE before reuse.

## Status & contributing

Pre-alpha. The architecture is being scaffolded (M0). If the mission resonates, the most useful early contributions are around the tracer (M1) and the determinism harness (M2) — the parts that need many eyes to be trustworthy.

## License

Apache-2.0. The patent grant matters here; it lowers the barrier for adoption.

---

<div align="center">
<em>Fold one crane at a time. With a thousand, the flock takes flight.</em>
</div>
