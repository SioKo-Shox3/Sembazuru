# Sembazuru build-system integrations (M6)

Sembazuru distributes existing builds with minimal configuration by routing each
compiler invocation through the agent daemon. There are two interception points,
chosen per build system; both end at the same daemon → worker → VFS compile path.

Run, on the build machine:

```
sembazuru-daemon            # Coordination + file server + scheduler + LocalIntake
sembazuru-worker <addr>     # one or more workers, with VFS execution enabled
```

A worker enables distributed (VFS) execution when these are set:

```
SEMBAZURU_AGENT        = http://<daemon-host>:50070   # Coordination, to register
SEMBAZURU_LAUNCHER     = <path>\launcher.exe          # the hook injector
SEMBAZURU_DLL          = <path>\sbz_interceptor64.dll # the hook DLL
SEMBAZURU_SCRATCH_ROOT = <dir>                        # per-action hydrated inputs
SEMBAZURU_CAS_ROOT     = <dir>                        # worker-local content cache
```

The daemon enables the action cache (a 2nd identical build skips the compile)
when `SEMBAZURU_CACHE_ROOT` is set.

## CMake / Ninja (compiler launcher)

The cleanest, edit-free hook. CMake prepends the launcher to each compile.

```
cmake -G Ninja -DCMAKE_CXX_COMPILER_LAUNCHER=<path>\sembazuru.exe -DCMAKE_C_COMPILER_LAUNCHER=<path>\sembazuru.exe ...
ninja
```

`CMAKE_<LANG>_COMPILER_LAUNCHER` is supported by the Ninja and Makefile
generators (not the Visual Studio generator — use the MSBuild path below for
that). Set `SEMBAZURU_DAEMON` if the daemon is not at the default
`http://127.0.0.1:50071`.

## MSBuild / Visual Studio (CLToolExe shim)

The Visual Studio generator and `.vcxproj`/`.sln` builds do not support a
compiler-launcher variable, so Sembazuru substitutes the CL task's executable.

1. Copy [`msbuild/Directory.Build.targets`](msbuild/Directory.Build.targets) to
   your solution/repo root.
2. Set, before building:
   ```
   SEMBAZURU_LAUNCHER_DIR = <dir containing sembazuru.exe>
   SEMBAZURU_SHIM_CC      = cl.exe        (or clang-cl.exe)
   SEMBAZURU_DAEMON       = http://127.0.0.1:50071
   ```
3. `msbuild your.sln /p:Configuration=Release /p:Platform=x64`

The launcher (named via `CLToolExe`) receives the CL args, prepends
`SEMBAZURU_SHIM_CC` as the real compiler, and hands the action to the daemon.

## Correctness notes

- **clang-cl is the byte-identity target.** A distributed clang-cl `.obj` is
  byte-identical to a local build, and the action cache republishes byte-for-byte.
  Native MSVC `cl` is byte-best-effort (it embeds build-path/timestamp data, see
  `docs/deferred.md`); its distributed output is functionally equivalent.
- **Local fallback always completes the build** (DESIGN.md §2): if the daemon is
  down or no worker is live, the compile runs locally.
- **Unreal Engine / UnrealBuildTool** integration (an `ActionExecutor`) is design
  observation only for now (UE is EULA; clean-room) — see ADR 0005.
