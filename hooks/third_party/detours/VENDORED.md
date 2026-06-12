# Vendored: Microsoft Detours

- Upstream: https://github.com/microsoft/Detours
- Tag: `v4.0.1`
- Commit: `e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`
- License: MIT (see `LICENSE.md` in this directory)
- Imported: 2026-06-12, files from `src/` plus `LICENSE.md` and `CREDITS.TXT`, unmodified.

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

None yet.
