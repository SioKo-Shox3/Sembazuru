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
from `CreateProcess`. Setting the process error mode does not suppress that box
(measured), so the wait itself has to end:

- `WaitForHelperProcess` bounds the wait at `DETOUR_HELPER_TIMEOUT_MS` (15 s),
  then asks the helper to terminate and confirms it is gone. The bound is a
  policy, not a claim that a slower helper is necessarily wedged; a helper that
  would have succeeded later is reported as an injection failure, which every
  caller already handles. It distinguishes the helper exiting on its own (the
  exit code is reported) from the caller giving up (`ERROR_TIMEOUT`) from the
  wait itself failing (`ERROR_PROCESS_ABORTED`), because only the first yields
  a meaningful exit code.
- `CreateHelperJob` / `TryAssignHelperToJob` put the helper in a job with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` before it is resumed, so cleanup does
  not depend on `TerminateProcess` succeeding or on the helper responding to
  it. The job handle is closed on every exit path. This is best effort: the
  caller may already be inside a job that does not permit what this one needs
  (the Sembazuru worker sandboxes actions in a UI-restricted job with no
  breakaway), and losing a cleanup backstop is not a reason to refuse an
  injection that would otherwise succeed.

Both turn an unbounded wait into a `FALSE` return, which is what the callers
already treat as an injection failure. The duplicated `ResumeThread` call in
the wide variant is upstream's and is left as-is.

An earlier revision also skipped the helper when the rewritten DLL name looked
absent, to avoid paying the timeout for a failure that is certain. It was
removed: absence for this process is not absence for the helper (WOW64
redirection under `%WINDIR%`, the helper's own loader search order for relative
names, substituted or linked paths), so the check could only be made safe by
reproducing rules this process cannot observe. Getting it wrong rejects a valid
injection, and all it ever bought was latency.
