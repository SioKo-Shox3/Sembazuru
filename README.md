<div align="center">

# 千羽 Sembazuru

**Run any Windows process distributed, with zero configuration.**

*A thousand workers fold a single build, like a thousand cranes fold into one.*

[![status](https://img.shields.io/badge/status-pre--alpha%20(single--box%20%C2%B7%20v0.0.3%20MSI%20published)-orange)]()
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

**Install it, or build it.** `Sembazuru-0.0.3-x64.msi` is attached to the
[Releases](https://github.com/SioKo-Shox3/Sembazuru/releases) page: it installs the daemon,
worker, launcher, hook DLLs, and the tray GUI, registers both services, adds the firewall
rules, and seeds `%ProgramData%\Sembazuru\{daemon,worker}.toml`. The MSI is **unsigned**, so
SmartScreen shows an unknown-publisher prompt — **More info → Run anyway**. Updates are a
manual reinstall, and every node in a cluster must run the same version (see the admission
note below). **v0.0.3 was cut on 2026-07-09 and `main` has moved since** — the live monitor,
the privilege-isolation work, and the cache-correctness fixes listed below are *not* in that
MSI. To get them today, build from source:
[`docs/quickstart.md`](docs/quickstart.md).

What works today, each backed by a CI gate (`.github/workflows/ci.yml`). Everything in this
first group is in the published v0.0.3 MSI:

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
- **Hardening (M7).** Authenticode sign→verify pipeline (placeholder cert in CI; real
  signing is optional and the published MSIs are unsigned), shared-token auth on both the
  control and data planes, 32/64-bit cross-bitness injection, a Job-Object sandbox with
  process-tree kill, and a Windows-version CI matrix (windows-2022/2025) to catch OS-update
  and Detours-fork regressions.
- **Beyond compilation (M8).** An arbitrary non-compiler process distributes with
  **no dedicated support**: `dxc` (the HLSL shader compiler) runs through the same
  launcher→daemon→worker path, byte-identical to local and cached via trace-based
  output discovery — proof that the core is general process virtualization, not
  compilation.
- **Packaging & residency (M9).** An MSI installs both services and a tray-resident GUI
  that shows connected workers, cache hit rate / size / cap, in-flight actions, and the
  remote/local/fallback split, and starts/stops the services. Shipped unsigned (v0.0.1,
  then v0.0.3).

**Landed on `main` after v0.0.3 — source builds only, not in the MSI:**

- **Live build monitor (M15).** A Monitor tab draws each worker's execution slots on a
  rolling 60-second timeline — active / done / failed by colour *and* text, local fallback
  on its own band, a recent-activity table underneath — so "is it actually distributing
  right now?" is answerable without reading logs. Only file basenames and outcomes cross
  to the GUI; full paths, arguments, environment values, and tokens never do.
- **Process & privilege isolation.** The daemon's local intake became a protected named pipe
  (`\\.\pipe\Sembazuru.LocalIntake.v1`) with an explicit DACL, mutual SID verification, and
  daemon-side fallback that runs under the *calling* user's restricted token — production no
  longer opens an intake TCP port, as v0.0.3 still did. Each remote action now runs under its
  own restricted primary token in a private scratch directory, bound to a kill-on-close Job
  before its first instruction. `%ProgramData%\Sembazuru` blocks inheritance, and the cluster
  token is stored DPAPI-protected rather than in plaintext TOML.
- **Fail-closed correctness.** Non-deterministic actions never resolve, prefetch, or record
  cache entries. Absent probes inside the build root (`__has_include` and friends) stay in
  the cache key, so a later-generated header misses instead of silently hitting. A VFS child
  process that cannot be injected fails the remote action into local fallback rather than
  running un-virtualized against worker-local files. These are correctness fixes to behaviour
  v0.0.3 shipped with — another reason to prefer a source build until the next release.

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
| **M9** | Productization & UX | A non-developer installs from a wizard and drives the resident GUI to distribute a build | 🔧 released (v0.0.3, unsigned) · clean-machine acceptance open |
| **M11** | GUI cluster-join | A 2nd machine joins as a worker from the GUI alone — no TOML editing | 🔧 wizard built · privileged write open |
| **M12** | Onboarding polish | Docs, tooltips, worker-count badge, unit picker, runtime prerequisites | ✅ |
| **M15** | Live build monitor | Per-worker activity is visible live while a build runs | 🔧 on `main`, post-v0.0.3 · speed-up meter pending |
| **M10** | Real two-machine LAN | Byte-identical output across physically separate machines, no latency collapse, fallback on disconnect | ⬜ next ⭐ |

M0–M8 each meet their "Done when" on the **single-machine** path, gated in CI
(`.github/workflows/ci.yml`): M1–M4 and M6–M8 by end-to-end `hooks/test/*.ps1`
gates, M5 by the scheduler tests under `cargo test --workspace`, and M0's hooking
deliverable transitively via the build + M1 smoke. M11/M12/M15 were deliberately pulled
ahead of M10: a second machine is only worth borrowing once joining one is a GUI step
rather than a TOML edit. **M10 is the next milestone and the project's single go/kill
gate** — until a cold-cache build on real hardware over a real NIC beats a local
`-j all-cores` build, every speed number here is RTT emulation on one box. Remaining work
is in **What's not done yet**. The process tracer (M1) still ships standalone as a "build
dependency tracer": it exercises the hardest primitive (hooking) in a safe, observe-only
mode and is useful by itself.

## What's not done yet

The mechanism is proven end to end on one box and there is now something to download. The
gap to *daily, real-world use by others* is, in order — making the second machine joinable
without a text editor, then proving the whole thing on real hardware over a real network.

- **Releases (M9) — published, unsigned, single-box only.** The tag-triggered pipeline
  (`.github/workflows/release.yml`) has run: v0.0.1 (2026-07-04) and v0.0.3 (2026-07-09)
  are on the Releases page with an `Sembazuru-<version>-x64.msi` attached. Two things are
  still missing. The MSI is **unsigned** — signing is an optional path (`installer/sign_release.ps1`
  drives it when a cert is configured), not a blocker, so every install goes through a
  SmartScreen prompt. And the **clean-machine acceptance run** — install → both services on
  AutoStart → the GUI drives a distributed build → uninstall leaves no residue — has not been
  recorded on any machine other than this project's development box. A consequence of both:
  the newest MSI is now well behind `main`, so **the next tag is the one that matters** —
  the privilege isolation and the cache-correctness fixes above reach installed users only
  when it is cut.
- **GUI cluster-join (M11) — wizard built, the privileged write is not.** The GUI's Join
  tab collects the coordinator address, cluster token, `listen_addr`/`advertise`, and
  participation mode, validates them, auto-fills `advertise` from the machine's LAN IPv4,
  and orchestrates the service Stop→Start; the daemon side has an "allow LAN workers"
  toggle that pins `coord_addr`/`fileserver_addr` to a concrete LAN IP (never `0.0.0.0`,
  or the worker cannot dial the file server back). But the config write itself is still a
  stub that refuses with `MechanismUnconfigured`: `SetConfig` is admin-gated off by default
  and `%ProgramData%\Sembazuru` is ACL-locked, so *how* an unelevated GUI is allowed to
  persist privileged config — enable the admin RPC, grant ACLs, or add an elevated helper —
  is an open decision. **Until it lands, a second PC still needs `worker.toml` edited by
  hand.**
- **Real two-machine LAN (M10).** Everything above runs daemon + worker + build on a
  single host (speed numbers use RTT emulation). The cross-machine specifics —
  `cwd`=input-root drift, returning the trace over the data plane, write-back scope,
  authoritative root binding — are deliberately deferred behind decision-owner
  approval (`docs/deferred.md`, ADR 0007 §M8.x).
- **Smaller open items** (all tracked in `docs/deferred.md`): the loopback **Status**
  endpoint is still plain TCP with no caller authentication — its mutating RPCs are
  admin-gated off by default, but until Status moves behind an authenticated pipe any local
  process can read the short-lived monitor metadata (basenames and outcomes); updates are a
  manual reinstall with no in-app self-update (deliberate — ADR 0009 was superseded so a
  cluster stays on one version); MSVC cross-dir byte-identity is best-effort; Unreal Engine /
  UnrealBuildTool integration stays design-only (EULA / clean-room); disk eviction for
  long-lived daemons; and zero-trust hardening (TLS/mTLS, authoritative worker-root binding).

## A note on licensing & scope

This project stands on the shoulders of permissively-licensed work, and is careful about what it does **not** borrow:

- **Detours (MIT)** — used as the hooking foundation. Note its stable release predates active maintenance, so we vendor and maintain our own fork.
- **BuildXL (MIT core)** — studied for its sandbox design; MIT portions may be reused.
- **Unreal Build Accelerator** — **studied for design only.** It is under the Unreal Engine EULA, not a permissive license; no code is copied into this repository. Clean-room discipline applies.
- **Remote Execution API (Apache-2.0)** — we borrow CAS/action-cache *design ideas*, not the execution protocol (ours is bespoke).

Running MSVC's `cl.exe` on remote machines sits in a licensing grey area under the Visual Studio license; **clang-cl support runs in parallel as an escape hatch** and is a first-class target, not an afterthought.

> This is not legal advice. Verify every upstream LICENSE before reuse.

## Status & contributing

Pre-alpha, but the full compile-distribution pipeline (M1–M8) works and is gated in CI on
the single-machine path, and there is an unsigned MSI to download. The two things standing
between this and other people using it daily are the **GUI-only second-machine join** and
then **real two-machine LAN** — see [What's not done yet](#whats-not-done-yet). If the
mission resonates, those, plus widening compiler/build-system coverage and hammering on
determinism, are where help matters most. Installing the MSI on a machine that is not this
project's development box and reporting what breaks is, today, the single most useful thing
an outsider can do.

## License

Apache-2.0. The patent grant matters here; it lowers the barrier for adoption.

---

<div align="center">
<em>Fold one crane at a time. With a thousand, the flock takes flight.</em>
</div>
