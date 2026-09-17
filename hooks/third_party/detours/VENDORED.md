# Vendored: Microsoft Detours

- Upstream: https://github.com/microsoft/Detours
- Tag: `v4.0.1`
- Commit: `e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`
- License: MIT (see `LICENSE.md` in this directory)
- Imported: 2026-06-12, files from `src/` plus `LICENSE.md` and `CREDITS.TXT`,
  unmodified at import. Later patches are listed under "Local modifications".

## Why vendored (not a submodule)

Upstream's last stable release is from 2018 and the project is effectively in
maintenance freeze. We expect to carry our own patches (Windows-update breakage,
new API surface), so this copy *is* our fork. Keeping it in-tree avoids running
a second repository for a dependency we fully own the maintenance of.

## Rules for this directory

- Record every local modification in this file (date, file, why) so the diff
  against upstream `v4.0.1` stays auditable.
- Build notes: `uimports.cpp` is `#include`d by `creatwth.cpp` and the
  `disol*.cpp` files are `#include`d by `disasm.cpp` — they must NOT be
  compiled as standalone translation units. See `hooks/CMakeLists.txt`.

## Local modifications

### 2026-09-17 — `creatwth.cpp`: the cross-bitness helper must fail, not hang

`DetourProcessViaHelperDllsA`/`W` spawn `rundll32.exe` of the target's bitness
to inject the sibling DLL (`AllocExeHelper` rewrites `...64.dll` to `...32.dll`
and back), then wait for it with `WaitForSingleObject(..., INFINITE)`.

When the sibling DLL is absent, `rundll32` cannot load it and puts up a modal
error box instead of exiting. Nothing dismisses that box on a build machine, so
the caller waits forever: a 64-bit parent spawning a 32-bit child never returns
from `CreateProcess`. Three changes make that case terminate, and terminate
without leaving a helper behind:

- `WaitForHelperProcess` bounds the wait at `DETOUR_HELPER_TIMEOUT_MS` (30 s).
  This is a policy bound, not a claim that a slower helper is necessarily
  wedged. It distinguishes the helper exiting on its own (`ERROR_TIMEOUT` is
  not reported, the exit code is) from the caller giving up (`ERROR_TIMEOUT`)
  from the wait itself failing (`ERROR_PROCESS_ABORTED`), because only the
  first yields a meaningful exit code.
- `CreateHelperJob` puts the helper in a job with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` before it is resumed, so cleanup does
  not depend on `TerminateProcess` succeeding or on the helper responding to
  it. The job handle is closed on every exit path. If no such job can be set
  up, no helper is spawned: an injection that cannot be cleaned up after is
  reported as a failure rather than started.
- `AnyHelperDllIsProvablyMissing` skips the helper entirely when a rewritten
  DLL name cannot possibly load, which keeps the common failure fast rather
  than paying the timeout. "Provably" is narrow on purpose, because absence
  for this process is not absence for the helper: relative names (resolved by
  the helper's own loader search order) and anything under `%WINDIR%` (subject
  to WOW64 redirection, so `System32\x32.dll` may resolve to `SysWOW64` in the
  helper) are never judged, and only `ERROR_FILE_NOT_FOUND`-class results
  count. Everything else falls through to the bounded wait.

All three turn an unbounded wait into a `FALSE` return, which is what the
callers already treat as an injection failure. The duplicated `ResumeThread`
call in the wide variant is upstream's and is left as-is.
