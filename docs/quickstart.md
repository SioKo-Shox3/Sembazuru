# Quickstart — distributed builds (M6)

Point an existing CMake/Ninja or MSBuild project at Sembazuru and have its
compiles run on a worker, with the cache and local fallback working — no changes
to your source or build logic beyond a one-line launcher hookup.

This is the **single-machine** path (daemon, worker, and build all on one box,
which is how the gates in `hooks/test/` exercise it). It is the right way to try
the mechanism end to end today; real two-machine LAN is a separate, deferred
milestone (`docs/deferred.md`).

> **clang-cl is the first-class target.** A distributed `clang-cl` object is
> byte-identical to a local one and incremental header tracking works through the
> launcher. Native MSVC `cl` works too (mechanism + cache), but its bytes are
> best-effort — it embeds build paths/timestamps (`docs/deferred.md`).

## 1. Prerequisites

- Windows, Visual Studio with the C++ toolset (for `cl`/`clang-cl`), CMake, and a
  Rust toolchain. Run the commands below from a **VS developer shell** so the
  compiler is on `PATH`.
- For the CMake/Ninja path you also need **Ninja** on `PATH`.

## 2. Build the binaries

The C++ injector + hook DLL:

```powershell
cmake -S hooks -B hooks/build -A x64
cmake --build hooks/build --config Release
```

The Rust agent daemon, the compiler launcher, and the worker:

```powershell
cargo build --release -p sembazuru-agent --bin sembazuru-daemon --bin sembazuru `
    -p sembazuru-worker --bin sembazuru-worker
```

You now have:

| Binary | Role |
|---|---|
| `target\release\sembazuru-daemon.exe` | the local agent (coordination + file supply + scheduler + intake) |
| `target\release\sembazuru.exe` | the compiler launcher the build system calls |
| `target\release\sembazuru-worker.exe` | a remote worker |
| `hooks\build\Release\launcher.exe` + `sbz_interceptor64.dll` | the worker's hook injector + DLL |

## 3. Start the cluster

Start the **daemon** (one terminal). It listens on loopback by default:
Coordination `127.0.0.1:50070`, LocalIntake `127.0.0.1:50071`, file server
`127.0.0.1:50072`. Set `SEMBAZURU_CACHE_ROOT` to enable the action cache (a 2nd
identical build skips the compile):

```powershell
$env:SEMBAZURU_CACHE_ROOT = "$PWD\.sbz-cache"
target\release\sembazuru-daemon.exe
```

Start one or more **workers** (another terminal, from a VS dev shell so the
compiler resolves). A worker enables distributed (VFS) execution when pointed at
the injector + DLL and given scratch/cache roots:

```powershell
$env:SEMBAZURU_AGENT        = "http://127.0.0.1:50070"          # daemon Coordination
$env:SEMBAZURU_LAUNCHER     = "$PWD\hooks\build\Release\launcher.exe"
$env:SEMBAZURU_DLL          = "$PWD\hooks\build\Release\sbz_interceptor64.dll"
$env:SEMBAZURU_SCRATCH_ROOT = "$PWD\.sbz-scratch"               # per-action hydrated inputs
$env:SEMBAZURU_CAS_ROOT     = "$PWD\.sbz-wcas"                  # worker-local content cache
target\release\sembazuru-worker.exe 127.0.0.1:50061
```

> **Trust model.** Out of the box the cluster is LAN-trusted and unauthenticated;
> the daemon warns if a LAN-reachable listener has auth off. To require a shared
> token, set `SEMBAZURU_CLUSTER_TOKEN` on the daemon **and** every worker (ADR
> 0006). Intake is loopback-only and refuses non-loopback binds.

> **Persistent config & participation modes (ADR 0012).** The env vars above are the
> dev/CLI path; an installed worker *service* reads `%ProgramData%\Sembazuru\worker.toml`
> (env vars still override the file). Beyond the paths above, a worker has a
> **participation mode**: `adaptive` (default — scales its contribution to idle CPU,
> so it stays a good neighbour on a developer's machine), `always` (full capacity
> regardless of load), or `off` (registered but never scheduled — park a machine
> without uninstalling).
>
> ```toml
> # %ProgramData%\Sembazuru\worker.toml
> agent                = "http://127.0.0.1:50070"
> participation_mode   = "adaptive"   # always | adaptive | off
> idle_cpu_reserve_pct = 10           # adaptive: idle % kept for the local user
> idle_cpu_floor_pct   = 0            # adaptive: minimum % offered while participating
> ```
>
> *Migration:* the pre-M9.6 `idle_cpu_enabled` key was replaced by `participation_mode`
> and is now ignored — a `worker.toml` that still has it silently falls back to
> `adaptive`. Replace `idle_cpu_enabled = true` with `participation_mode = "adaptive"`
> and `idle_cpu_enabled = false` with `participation_mode = "always"`.

> **One cluster, one version (ADR 0011).** The daemon admits a worker only when its
> build version exactly matches the daemon's, so the cluster stays on one build and
> distributed output stays byte-identical to local. A mismatched worker registers but
> shows as `version-mismatch` on the dashboard and is excluded from scheduling (the
> build still completes — locally if needed). Update every node from the same
> installer/release when you upgrade (updates are a manual reinstall; there is no
> in-app self-update).

## 4. Wire your build

### CMake / Ninja (compiler launcher) — the cleanest hook

CMake prepends the launcher to each compile; no project edits.

```powershell
cmake -G Ninja `
  -DCMAKE_C_COMPILER=clang-cl -DCMAKE_CXX_COMPILER=clang-cl `
  -DCMAKE_C_COMPILER_LAUNCHER="$PWD\target\release\sembazuru.exe" `
  -DCMAKE_CXX_COMPILER_LAUNCHER="$PWD\target\release\sembazuru.exe" `
  -S . -B build
ninja -C build
```

`CMAKE_<LANG>_COMPILER_LAUNCHER` is honored by the Ninja and Makefile generators
(not the Visual Studio generator — use the MSBuild path for that).

### MSBuild / Visual Studio (CLToolExe shim)

The Visual Studio generator and `.vcxproj`/`.sln` builds have no
compiler-launcher variable, so Sembazuru substitutes the CL task's executable.

1. Copy [`integrations/msbuild/Directory.Build.targets`](integrations/msbuild/Directory.Build.targets)
   to your solution/repo root.
2. Set, before building:
   ```powershell
   $env:SEMBAZURU_LAUNCHER_DIR = "$PWD\target\release"   # dir holding sembazuru.exe
   $env:SEMBAZURU_SHIM_CC      = "cl"                     # or clang-cl
   $env:SEMBAZURU_INPUT_ROOT   = "$PWD"                   # solution/repo root (for caching)
   ```
3. `msbuild your.sln /p:Configuration=Release /p:Platform=x64`

Set `SEMBAZURU_DISABLE=true` to bypass the shim entirely.

**Why `SEMBAZURU_INPUT_ROOT` for MSBuild.** MSBuild compiles all sources in one
batched `cl @<response-file>` call, and a `/Zi` build splits its outputs across
`obj\` (objects) and `bin\` (the shared PDB). Pointing `SEMBAZURU_INPUT_ROOT` at
the one root that contains them all lets the action cache key on the real sources
and republish *every* output on a hit. Leave it unset and a compile is still
correct and distributed, but a `/Zi` build whose outputs fall outside its working
directory is simply left uncached (never miscached). The launcher writes
content-addressed response files under `<root>\.sembazuru\` — add that to
`.gitignore`.

If the daemon's intake is not at the default `http://127.0.0.1:50071`, point the
launcher at it with `SEMBAZURU_DAEMON`.

## 5. What you should see

- **Distributed:** each compile prints `sembazuru: remote` (the launcher routed it
  through the daemon to the worker). The build output lands where the build system
  expects it.
- **Cache:** build a second time without changing inputs — `sembazuru: cache hit`,
  no recompile. (Delete the build dir's objects first if the build system thinks
  they are up to date; the *action* cache is what skips the compile.)
- **Fallback:** stop the daemon and rebuild — `sembazuru: ... running locally`. The
  build still completes. **Local fallback always completes the build** is a
  non-negotiable: if the network, the daemon, or a worker dies, you get a normal
  local compile (`docs/DESIGN.md` §2).

## 6. Notes & limits

- **Per-file vs batched.** With a single worker and a parallel build, the scheduler
  may run some compiles locally when no worker slot is free (by design — fallback,
  not failure). Multi-worker scaling is M5.
- **Incremental + native `cl` on a non-English locale.** Ninja's `deps = msvc`
  matches a localized `/showIncludes` prefix; a worker running `cl` under a
  cleared environment can emit a different codepage than CMake sampled, so a header
  edit may not retrigger a distributed recompile. `clang-cl` emits ASCII and is
  unaffected (`docs/deferred.md`). Clean builds and the cached/distributed byte
  path are unaffected either way.
- **Unreal Engine / UnrealBuildTool** integration is design-only for now (UE is
  EULA; clean-room — ADR 0005).

See [`integrations/README.md`](integrations/README.md) for the reference env-var
list and [`DESIGN.md`](DESIGN.md) for the architecture.
