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
from `CreateProcess`. Two changes make that case terminate:

- `HelperDllsArePresent` checks the rewritten DLL names before any helper is
  spawned and fails with `ERROR_MOD_NOT_FOUND`. Names without a path separator
  are not checked, because the helper's loader search order cannot be
  reproduced from a process of the other bitness.
- `WaitForHelperProcess` bounds the wait at `DETOUR_HELPER_TIMEOUT_MS`
  (30 s) and terminates a helper that overruns it, reporting `ERROR_TIMEOUT`.
  Injecting into an already-suspended process is sub-second work, so this only
  fires on a wedged helper.

Both turn an unbounded wait into a `FALSE` return, which is what the callers
already treat as an injection failure. The duplicated `ResumeThread` call in
the wide variant is upstream's and is left as-is.
