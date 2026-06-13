# Build-output determinism (M2)

Sembazuru distributes a build by running each process on a remote worker and
returning its outputs. That only works if **the same input produces the same
output bytes** — otherwise a remotely produced `.obj` can't be substituted for
a local one, and the cache (M4) silently corrupts. M2 builds the harness that
proves this and documents what it takes to get there.

This document is the single place the determinism rules and the recommended
compiler/linker flags are defined. The trace/normalization counterpart lives in
`docs/trace-format.md` §6 and `crates/tracer/src/determinism.rs`.

## Strategy: hybrid (flags first, normalization as a guard)

Two complementary halves:

1. **Deterministic flags.** Configure the compiler/linker to not emit
   non-deterministic bytes in the first place (fixed timestamps, no embedded
   build paths). This is the real fix and the only one that yields *byte*
   identity across machines.
2. **Normalization guard.** The `verify-determinism` harness still compares raw
   bytes first, and on a difference masks the documented non-deterministic
   regions (timestamps, the PE Rich header) before comparing again. A residual
   difference is *unexplained* and fails the gate. This catches regressions and
   compilers invoked without the flags.

The harness (`hooks/test/determinism.ps1`) builds a representative corpus twice
and runs `sembazuru-trace verify-determinism`.

## Scope (M2)

- **Primary: `.obj` (COFF) byte determinism.** M3's "Done when" is a
  byte-identical `.obj` from remote execution, so this is the foundation.
- **Secondary: PE images (`.exe`/`.dll`).** Timestamp and Rich-header
  normalization implemented; full link-stage determinism is not gated.
- **Out of scope: PDB and the PE debug directory / CodeView record.** These
  carry a per-link GUID and absolute source paths and need RVA→file-offset
  mapping to normalize; MSVC-native PDBs are not reproducible without a
  post-processing tool. M2 documents this rather than masking it.

## Non-determinism sources and countermeasures

Each row: what varies, what flag fixes it, and the primary source. "Mask"
means the harness normalizes the region when flags are absent.

| Source | What varies | Countermeasure | Primary source |
|---|---|---|---|
| `__DATE__` / `__TIME__` / `__TIMESTAMP__` | string data in `.obj` | cl: `/Brepro` (implies `/d1nodatetime`). clang: `SOURCE_DATE_EPOCH=0` (clang ≥16) or `-D__DATE__= -D__TIME__= -D__TIMESTAMP__= -Wno-builtin-macro-redefined` | [LLVM deterministic builds](https://blog.llvm.org/2019/11/deterministic-builds-with-clang-and-lld.html), [SOURCE_DATE_EPOCH spec](https://reproducible-builds.org/specs/source-date-epoch/) |
| COFF `IMAGE_FILE_HEADER.TimeDateStamp` (`.obj`) | 4 bytes at file offset +4 | cl `/Brepro`; else **mask** | PE/COFF spec; `/Brepro` |
| PE `IMAGE_FILE_HEADER.TimeDateStamp` | 4 bytes at `e_lfanew+8` | link `/Brepro`; else **mask** | [AMOSSYS, /Brepro and PE timestamps](https://blog.amossys.fr/pe-timestamps-and-bepro-flag.html), [The Old New Thing 2024-08-15](https://devblogs.microsoft.com/oldnewthing/20240815-00/?p=110131) |
| PE Rich header (linker tool-version array) | per-tool use counts | toolchain pinning; harness also **masks** the `DanS…Rich` span | [VB2019, Rich Headers](https://www.virusbulletin.com/virusbulletin/2020/01/vb2019-paper-rich-headers-leveraging-mysterious-artifact-pe-format/) |
| `__FILE__` / debug source paths | embedded build path | cl `/d1trimfile:<prefix>` (source paths only — see limitation below). clang: `-ffile-compilation-dir=.`, `-fmacro-prefix-map`, `-fdebug-prefix-map`, `-no-canonical-prefixes` | [Clang CLI ref](https://clang.llvm.org/docs/ClangCommandLineReference.html), LLVM blog |
| Incremental linking (`/INCREMENTAL`) | padding, thunks, timestamp | link `/INCREMENTAL:NO` (lld-link never incremental) | [MSVC /INCREMENTAL](https://learn.microsoft.com/en-us/cpp/build/reference/incremental-link-incrementally) |
| `/GL` LTCG | IR + parallel-opt order | **excluded from the M2 corpus** | [MSVC /GL](https://learn.microsoft.com/en-us/cpp/build/reference/gl-whole-program-optimization), [/LTCG](https://learn.microsoft.com/en-us/cpp/build/reference/ltcg-link-time-code-generation) |
| COMDAT folding (`/OPT:ICF`) order | function placement | feed inputs in a fixed (lexical) order | [MSVC /OPT](https://learn.microsoft.com/en-us/cpp/build/reference/opt-optimizations) |
| PDB GUID/Age, mspdbsrv | whole PDB | clang+lld: `/pdbsourcepath:` + `/pdbaltpath:%_PDB%`; MSVC-native: post-process. **Out of M2 scope.** | [microsoft-pdb#9](https://github.com/microsoft/microsoft-pdb/issues/9), [ducible](https://github.com/jasonwhite/ducible) |

> `/Brepro` is **not in Microsoft's documented option list.** Its behavior also
> varies by toolset (older versions write `0xFFFFFFFF`; VS2017+ writes a
> content-hash "Build ID"). That is exactly why the harness masks the timestamp
> fields rather than trusting a fixed value. Pin the MSVC toolset version in CI
> so the Rich header stays stable.

## Recommended flag sets

**clang-cl + lld-link — the guaranteed-deterministic, path-independent path.**
This is the target Sembazuru leans on (it is also the licensing-safe path per
`docs/DESIGN.md` §8, and clang-cl is first-class per `CLAUDE.md`). Compile:

```
clang-cl /nologo /c /Brepro \
  -ffile-compilation-dir=. -fmacro-prefix-map=<root>=. -fdebug-prefix-map=<root>=. \
  -no-canonical-prefixes -Wdate-time a.cpp
```
with `SOURCE_DATE_EPOCH=0` in the environment. Link with lld-link
`/Brepro /INCREMENTAL:NO /pdbsourcepath:<virtual> /pdbaltpath:%_PDB%`.

**cl.exe (MSVC native) — next best, content-deterministic but not
path-independent.**

```
cl /nologo /c /Brepro a.cpp        # + /d1trimfile:<prefix> for __FILE__
```

## Known limitation: MSVC-native `.obj` is not byte-identical across directories

Empirically (verified by `verify-determinism` on cl 14.50): a `.obj` built by
`cl` in two **different** directories differs even with `/Brepro` and
`/d1trimfile`, because the object's `.debug$S` section embeds the **absolute
object path** in an `S_OBJNAME` record, and a content hash derived from it. No
documented `cl` flag removes `S_OBJNAME`; `/d1trimfile` only trims `__FILE__`
and debug *source* paths, not the object name. This matches the upstream
position that MSVC-native reproducibility needs a post-processing tool
([microsoft-pdb#9](https://github.com/microsoft/microsoft-pdb/issues/9),
[ducible](https://github.com/jasonwhite/ducible)).

Consequences for the gate:

- **MSVC** is checked for *content* determinism: the corpus is built **twice in
  the same build root** (run A's outputs snapshotted before run B overwrites
  them), and must be byte-identical (modulo masked timestamps). This proves the
  M2 "Done when" (same input → same output bytes).
- **clang-cl** is checked for *path independence*: the corpus is built in two
  **different** roots and must still be byte-identical. CI makes this a hard
  requirement (`-RequireClangCl`).

Path-independent MSVC determinism (needed to relocate a remote MSVC build to a
local path) is therefore a distribution-time concern for M3/M4 — solved either
by normalizing the remote path to match the local one, or by an `S_OBJNAME`
post-processing step. It is deliberately out of M2 scope.

## Resolved in M3.1.5: clang/lld write outputs via a temp + NT rename

clang-cl and lld write each output to a **run-varying temporary** (e.g.
`a-915f50da.obj.tmp`) and then atomically rename it onto the final name. On a
recent LLVM that rename is an NT-level operation
(`NtSetInformationFile(FileRenameInformation)`, reached either directly or via
`SetFileInformationByHandle`), which the M2 Win32-layer hooks did not observe —
the documented user-mode gap (`docs/trace-format.md` §8). The trace then
recorded only the transient temp write, never the surviving artifact, so
trace-derived output discovery could not match the two runs' outputs and the
harness had to name them explicitly with `verify-determinism … --output a.obj
--output b.obj`.

**M3.1.5 closes this.** The interceptor now hooks `NtSetInformationFile` and
records the rename as a move (source resolved from the handle with
`GetFinalPathNameByHandleW`, destination from the information buffer). The reader
drops the renamed-away temp from the output set and treats it as a deletion, so
the surviving final artifact is discovered from the trace alone. The harness no
longer passes `--output`; trace-derived discovery finds `a.obj`/`b.obj`
directly. The mechanism is gated independently by `hooks/test/nt_rename.ps1`.
MSVC `cl` was never affected (it writes the object directly, importing no
`ntdll`).

## Input-hash → output-hash mapping

`verify-determinism` records, per run, a hash over the sorted logical input set
(`(build-root-relative path, content hash)` pairs, plus the relativized command
lines), excluding generated outputs. The two runs must produce the **same**
input hash, and each output's normalized bytes hash to a stable **output hash**.
`--json` emits the mapping for the action cache to build on in M4.
