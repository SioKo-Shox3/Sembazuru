# 0001 — Worker-side VFS approach: user-mode hooking vs minifilter driver vs ProjFS

- Status: **PENDING — decision owner: project lead.** This document frames the
  trade-offs; it deliberately does not decide.
- Date framed: 2026-06-12 (evidence gathered via primary sources; confidence
  levels noted inline)
- Decides: the single most load-bearing M0 choice (DESIGN.md §7 M0). Everything
  in M3+ (on-demand file supply) sits on top of this.

## Question

When a hooked process (e.g. `cl.exe`) runs on a remote worker, how do we make
it see the local machine's filesystem? Three candidate mechanisms:

- **A. Pure user-mode VFS** — the same Detours hooks we already inject
  intercept `CreateFileW`/`GetFileAttributes`/`NtQueryDirectoryFile`-level
  calls and redirect them to the agent's file-supply session.
- **B. Filesystem minifilter driver** — a kernel component materializes a
  virtual volume/directory; every process sees it, hooked or not.
- **C. ProjFS (Windows Projected File System)** — a user-mode provider API
  backed by the Microsoft-shipped `prjflt.sys` minifilter; files hydrate on
  first access into a real NTFS directory.

## Comparison

| Axis | A. User-mode hooks | B. Own minifilter | C. ProjFS |
|---|---|---|---|
| Signing burden | Authenticode only; no EV requirement; SmartScreen reputation accrues over time | **EV cert required even for attestation signing; EV is issued to registered legal entities only — not obtainable as an individual** (~$250–500/yr, org vetting). Server SKUs additionally need HLK/WHQL for filter drivers | None beyond normal binaries (driver is Microsoft's, ships in Windows) |
| Distribution | xcopy; no admin rights needed for the mechanism itself | Driver install: admin, reboot risk, cross-signing path closed as of Win11 24H2 (WHCP-only); HVCI/Memory-Integrity compliance required | Optional Windows feature, **disabled by default; enabling requires admin once** (Win10 1809+) |
| Completeness | Known gaps: direct Nt/Zw syscalls (BuildXL issue #680 — msys2/Cygwin bypass entirely), statically-linked code calling ntdll directly, breakaway child processes (BuildXL PR #1175 compensates manually), memory-mapped access after open (inference, medium confidence), CFG/anti-tamper/PPL targets resist injection | Complete: sits under all user-mode I/O paths regardless of how the syscall is made | Complete for file *content* access under the virtualization root (kernel-enforced); semantics limited to hydrate-on-read of a projected tree — not a general I/O redirection layer |
| Performance | Hook overhead ~tens–hundreds of ns per call; network round-trip dominates. BuildXL reports 1–5% sandbox overhead overall | All I/O on the volume pays the filter path; AV-research folklore says OPEN ops hurt most; no public quantitative data (workload-dependent) | ≥2 kernel↔user transitions per first-touch hydration, per file; fine after hydration. Microsoft explicitly says ProjFS targets *fast* backing stores, recommends Cloud Files API for slow/remote ones. Dev Drive excludes `prjflt` by default for perf — telling |
| EDR/AV optics | Injection + inline patching = classic malware TTPs; mitigated by documented Detours path, signing, allowlisting (M7) | Kernel driver = highest scrutiny but also the "legitimate product" path; EV+WHQL is itself the trust signal | Cleanest: documented OS feature, MS-signed driver; provider is an ordinary process |
| Who uses it (design level) | **UBA (confirmed: Epic engineer, "virtualizing using detours"), IncrediBuild (docs describe DLL injection + API interception; no kernel driver documented — medium confidence), BuildXL sandbox, and XiaoBuild by inheritance from UBA** | No direct competitor found using one for build distribution | VFS for Git (now maintenance mode; superseded by Scalar/sparse-checkout — partly a perf-at-scale story) |
| Fit with our architecture | We must inject hooks **anyway** (child-process capture, output interception). VFS reuses the layer we already own | Second mechanism beside the hooks; doubles the surface we maintain and sign | Hybrid: hooks still needed for process/output capture; ProjFS would replace only the read-path |

Key citations (full set in the research log):
- Signing: learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs; …/driver-signing-offerings
- BuildXL gaps: github.com/microsoft/BuildXL/issues/680; …/pull/1175; …/blob/main/Documentation/Specs/Sandboxing.md
- ProjFS mechanics/positioning: learn.microsoft.com/en-us/windows/win32/projfs/projected-file-system; …/enabling-windows-projected-file-system; huntress.com/blog/windows-projected-file-system-mechanics
- UBA approach: x.com/honk_dice/status/1730353497877680376 (Epic engineer)
- IncrediBuild: docs.incredibuild.com/win/latest/windows/process_virtualization_flow.html

## When each option wins

**A wins if** we accept the same completeness envelope as every shipping
competitor (UBA, IncrediBuild, BuildXL all live with it), value xcopy
distribution and individual-developer-compatible signing, and treat the known
gaps (direct syscalls, msys2-style toolchains) as detectable-and-fallback
cases rather than correctness holes. Strong prior: the entire competitive
field converged here.

**B wins if** correctness-by-construction outweighs everything: no process can
bypass it, no toolchain quirk matters. The price is incorporated-entity EV
signing (currently **unavailable to a solo individual developer**), WHQL for
server SKUs, admin+reboot installs, and a kernel codebase to keep safe. B is
effectively foreclosed until the project has a legal entity behind it.

**C wins if** first-build hydration latency proves acceptable in measurement
and we want kernel-enforced read-path completeness without owning a driver.
Risks: admin-once feature enablement contradicts "zero configuration", the
≥2-transition-per-file hydration cost lands exactly on our critical path
(M3's many-small-files problem), and we still need the hook layer for
everything that isn't file reads.

## What this interacts with

- **Local fallback (non-negotiable #2):** A's completeness gaps need a
  detect-and-fallback story (e.g. unknown-syscall processes run locally).
- **EDR/M7:** A concentrates all scrutiny on the injection path we already
  carry; B adds the heaviest-but-most-legitimate trust artifact; C adds none.
- **Protocol v0 §4.1:** the op set is mechanism-agnostic, but A may need
  extra ops for child-handle sync; C would push us toward whole-file
  hydration rather than ranged reads (see v0.md §7.5).

## Measurements recommended before/alongside the decision

1. 10k-file open/stat microbenchmark against an unhydrated ProjFS root vs the
   same workload through a Detours redirect shim (no public data exists; this
   is the deciding number for C).
2. Census of real-world build tools that issue direct Nt* syscalls (how big is
   A's gap in practice for *our* target workloads — MSVC/clang-cl, not msys2?).
3. (Only if B stays on the table) attestation-signed minifilter load test on
   an HVCI-enabled Win11 box.

## Decision

**PENDING.** Recorded here once made, with rationale and the dissenting
considerations preserved.
