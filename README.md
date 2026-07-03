<div align="center">

# 千羽 Sembazuru

**Run any Windows process distributed, with zero configuration.**

*A thousand workers fold a single build, like a thousand cranes fold into one.*

[![status](https://img.shields.io/badge/status-pre--alpha%20(single--box%20M1--M8)-orange)]()
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)]()
[![platform](https://img.shields.io/badge/platform-Windows-lightgrey)]()

</div>

---

## What is this?

Sembazuru is an open-source build acceleration platform that distributes **arbitrary Windows processes** across many machines — without forcing you to rewrite your build scripts or adopt a new build description language.

It targets the one thing that makes proprietary distributed-build tools expensive: **process virtualization.** A process launched locally is intercepted, shipped to a remote worker, and made to believe it is still running on your machine — file system and all. Files stream on demand; outputs come back; the caller never knows the difference.

If it works for a compiler, it works for a shader compiler, a test runner, or an asset baker. That generality is the goal.

## Why it exists

Distributed builds shouldn't require expensive per-core licensing. The hard part — transparent process virtualization — is buildable in the open. This project is a long-horizon effort to make that capability free.

We are clear-eyed about the challenge: matching the maturity of established tools means covering a decade-plus of compatibility edge cases, not just the core idea. So the realistic goal is **being a dependable free/open-source option for the non-UE, general-Windows segment** — a focused, long-horizon effort.

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

## Distributed builds — try it

The full pipeline is wired end to end and exercised in CI on every push: point an
existing **CMake/Ninja** or **MSBuild** project at the launcher and its compiles
run on a worker — content-addressed, cached, with local fallback throughout. Today
this is the **single-machine** path (daemon, worker, and build on one box, which is
how the gates in `hooks/test/` drive it). Real two-machine LAN is a separate,
deliberately deferred milestone — see [`docs/deferred.md`](docs/deferred.md).

What works today, each backed by a CI gate (`.github/workflows/ci.yml`):

- **Remote execution (M3).** A hooked compiler runs under an on-demand VFS; the
  agent streams inputs as the process opens them. A distributed `clang-cl` `.obj`
  is **byte-identical** to a local build, and injected round-trip latency does not
  collapse the compile.
- **CAS & cache (M4).** Content-addressed storage (BLAKE3) dedups transfers and a
  worker-local cache sends a header once. The action cache makes a 2nd identical
  build skip the compile entirely and republish every output byte-for-byte; a
  changed input misses. Incremental header edits recompile only the dependents.
- **Scheduler & fanout (M5).** Tasks distribute across workers with health checks,
  reassignment on disconnect, and dependency prefetch to hide first-touch latency.
  (Multi-worker efficiency is measured on a single box for now; true N-machine
  numbers wait on real LAN.)
- **Integrations (M6).** CMake/Ninja via `CMAKE_<LANG>_COMPILER_LAUNCHER`, and
  MSBuild/Visual Studio via a `CLToolExe` shim — no source or build-logic edits.
- **Hardening (M7).** Authenticode sign→verify pipeline (placeholder cert in CI; an
  OV cert at release), shared-token auth on both the control and data planes,
  32/64-bit cross-bitness injection, a Job-Object
  sandbox with process-tree kill, and a Windows-version CI matrix
  (windows-2022/2025) to catch OS-update and Detours-fork regressions.
- **Beyond compilation (M8).** An arbitrary non-compiler process distributes with
  **no dedicated support**: `dxc` (the HLSL shader compiler) runs through the same
  launcher→daemon→worker path, byte-identical to local and cached via trace-based
  output discovery — proof that the core is general process virtualization, not
  compilation.

> **clang-cl is the byte-identity target.** Native MSVC `cl` works too (the
> interception mechanism and cache), but its bytes are best-effort — it embeds
> build paths/timestamps (`docs/deferred.md`). clang-cl stays first-class because
> remote `cl.exe` is a Visual Studio licensing grey area.

> **Cluster admission (M9.6).** A worker joins with a participation mode —
> `adaptive` (default; scales its contribution to idle CPU so a shared machine stays
> responsive), `always`, or `off` — and the daemon schedules only to workers whose
> build version matches its own, keeping the cluster on one release so distributed
> output stays byte-identical (ADR 0010/0011/0012). Updates are a manual reinstall —
> no in-app self-update. Details in the quickstart.

Step-by-step: [`docs/quickstart.md`](docs/quickstart.md). Reference env vars and
both interception points: [`docs/integrations/README.md`](docs/integrations/README.md).

## Roadmap

Milestones advance by a **"Done when"** condition, not by date. This is a spare-time, long-horizon project; each milestone is designed to be independently useful if published on its own.

| | Milestone | Done when | Status |
|---|---|---|---|
| **M0** | Recon & foundations | Minimal DLL hooks one `cl.exe` call; VFS approach & protocol skeleton decided | ✅ |
| **M1** | Process tracer | Full, reproducible input/output dependency graph for any compiler invocation | ✅ |
| **M2** | Determinism harness | Same input hash → same output hash, stably, across representative TUs | ✅ |
| **M3** | 1:1 remote exec | Byte-identical `.obj` from a remote worker, *without* latency collapse | ✅ single-box |
| **M4** | CAS & cache | Second build transfers ~nothing and recompiles ~nothing | ✅ |
| **M5** | Scheduler & fanout | Compile phase scales at usable parallel efficiency across N workers | ✅ mechanism · LAN-deferred |
| **M6** | Build-system integrations | Existing projects build distributed with minimal setup | ✅ |
| **M7** | Hardening | Reliable enough for daily use (signing, AV allowlist, OS-update CI) | ✅ |
| **M8** | Beyond compilation | Non-compile workloads distribute with no special support | ✅ |
| **M9** | Productization & UX | A non-developer installs from a signed wizard and drives the resident GUI to distribute a build | ⬜ planned |
| **M10** | Real two-machine LAN | Byte-identical output across physically separate machines, no latency collapse, fallback on disconnect | ⬜ planned |

M0–M8 each meet their "Done when" on the **single-machine** path, gated in CI
(`.github/workflows/ci.yml`): M1–M4 and M6–M8 by end-to-end `hooks/test/*.ps1`
gates, M5 by the scheduler tests under `cargo test --workspace`, and M0's hooking
deliverable transitively via the build + M1 smoke. M9–M10 — shipping installable
software, then going truly multi-machine — are the remaining work (see **What's not
done yet**). The process tracer (M1) still ships standalone as a "build dependency
tracer": it exercises the hardest primitive (hooking) in a safe, observe-only mode
and is useful by itself.

## What's not done yet

The mechanism is proven end to end on one box; the gap to *daily, real-world use by
others* is two things, in order — becoming installable software, then going truly
multi-machine. Packaging comes first so that a second machine is "install, configure,
done" before any real-LAN measurement begins.

- **Windows install wizard (M9).** Today you build from source in a VS developer
  shell (`cmake` + `cargo`) and wire env vars by hand. A signed installer
  (MSI/winget/WiX) that drops the daemon, worker, launcher, and hook DLLs in place,
  registers the service, and configures firewall/auth — wired to the M7.2 signing
  pipeline and EDR allowlist — is **not built yet**.
- **Resident GUI application (M9).** The daemon and worker are headless CLI
  processes you start in terminals. A Windows tray/GUI app that runs the daemon
  resident, shows cluster/worker/cache status, and exposes start/stop and config is
  **not built yet**.
- **Real two-machine LAN (M10).** Everything above runs daemon + worker + build on a
  single host (speed numbers use RTT emulation). The cross-machine specifics —
  `cwd`=input-root drift, returning the trace over the data plane, write-back scope,
  authoritative root binding — are deliberately deferred behind decision-owner
  approval (`docs/deferred.md`, ADR 0007 §M8.x).
- **Smaller open items** (all tracked in `docs/deferred.md`): MSVC cross-dir
  byte-identity (best-effort today), Unreal Engine / UnrealBuildTool integration
  (design-only — EULA/clean-room), disk eviction for long-lived daemons, and
  zero-trust hardening (TLS/mTLS, authoritative worker-root binding).

## A note on licensing & scope

This project stands on the shoulders of permissively-licensed work, and is careful about what it does **not** borrow:

- **Detours (MIT)** — used as the hooking foundation. Note its stable release predates active maintenance, so we vendor and maintain our own fork.
- **BuildXL (MIT core)** — studied for its sandbox design; MIT portions may be reused.
- **Unreal Build Accelerator** — **studied for design only.** It is under the Unreal Engine EULA, not a permissive license; no code is copied into this repository. Clean-room discipline applies.
- **Remote Execution API (Apache-2.0)** — we borrow CAS/action-cache *design ideas*, not the execution protocol (ours is bespoke).

Running MSVC's `cl.exe` on remote machines sits in a licensing grey area under the Visual Studio license; **clang-cl support runs in parallel as an escape hatch** and is a first-class target, not an afterthought.

> This is not legal advice. Verify every upstream LICENSE before reuse.

## Status & contributing

Pre-alpha, but the full compile-distribution pipeline (M1–M8) works and is gated in
CI on the single-machine path. The two things standing between this and other people
using it daily are **end-user packaging** (an install wizard and a resident GUI app)
and then **real two-machine LAN** — see [What's not done yet](#whats-not-done-yet). If
the mission resonates, those, plus widening compiler/build-system coverage and
hammering on determinism, are where help matters most.

## License

Apache-2.0. The patent grant matters here; it lowers the barrier for adoption.

---

<div align="center">
<em>Fold one crane at a time. With a thousand, the flock takes flight.</em>
</div>
