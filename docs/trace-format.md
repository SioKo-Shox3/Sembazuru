# Sembazuru trace format (version 0)

This document specifies the on-disk format produced by the Sembazuru
interceptor DLL (`hooks/`) and consumed by the `sembazuru-trace` CLI
(`crates/tracer`). It is the contract between the C++ hook layer and the
Rust analysis layer; both sides must follow it exactly.

Status: **v0 — unstable.** No compatibility promises before M3. The
`version` field exists so readers can refuse files they don't understand.

## 1. Design constraints

- **The writer runs inside a hooked process.** It must be simple enough to
  be obviously re-entrancy-safe and must never allocate unbounded memory.
  Anything that requires lookahead, indexing, or compression belongs in the
  reader.
- **One file per process.** Each injected process appends to its own file;
  no cross-process synchronization exists. The reader merges files and
  reconstructs the process tree from header metadata.
- **Paths are unbounded.** All strings are length-prefixed UTF-16 with no
  `MAX_PATH` assumption. Truncation is a correctness bug: a dependency
  graph with a truncated path is wrong, not just ugly.
- **Append-only, crash-tolerant.** A process may die mid-write (killed,
  crashed). Readers must treat a truncated final record as end-of-file,
  not as corruption of the whole file.

## 2. File naming and location

The interceptor reads the environment variable `SEMBAZURU_TRACE_DIR` at
first use. If it is unset or unusable, tracing is disabled and the process
runs untouched (observe-only also means fail-open).

Each process writes to:

```
%SEMBAZURU_TRACE_DIR%\<pid>-<start_qpc>.sbzt
```

where `<pid>` is the decimal process ID and `<start_qpc>` is the decimal
`QueryPerformanceCounter` value sampled at DLL attach. The QPC suffix
disambiguates PID reuse within one trace session.

## 3. Encoding conventions

- All integers are **little-endian**, unaligned (the file is a byte
  stream; readers must not assume alignment).
- `string` denotes: `u32 char_count` followed by `char_count` UTF-16LE
  code units (2 bytes each), **no** NUL terminator. An empty string is
  encoded as `char_count = 0`.
- Paths are recorded **as the application passed them** (relative, with
  `..`, `\\?\` prefixes, mixed separators, etc.). Normalization is the
  reader's job; the writer must not call path-resolution APIs (re-entrancy
  and fidelity both forbid it). The exception is the header's
  `exe_path`, which is the module path from `GetModuleFileNameW`.

## 4. File header

| Field | Type | Meaning |
|---|---|---|
| `magic` | 4 bytes | `53 42 5A 54` (`"SBZT"`) |
| `version` | u32 | format version, `0` |
| `pid` | u32 | process ID of the writer |
| `parent_pid` | u32 | parent process ID (from `NtQueryInformationProcess`/PEB at attach; `0` if unavailable) |
| `qpc_frequency` | u64 | `QueryPerformanceFrequency` |
| `start_qpc` | u64 | `QueryPerformanceCounter` at DLL attach |
| `start_filetime` | u64 | `GetSystemTimePreciseAsFileTime` at DLL attach (wall-clock anchor for the QPC timeline) |
| `exe_path` | string | `GetModuleFileNameW(NULL)` |
| `command_line` | string | `GetCommandLineW()` |

Records follow immediately after the header, back to back, until EOF.

## 5. Record layout

Every record has the same shape:

| Field | Type | Meaning |
|---|---|---|
| `record_type` | u8 | see §5.1 |
| `op` | u8 | operation within the type, see §5.2–§5.5 |
| `reserved` | u16 | must be written as `0`, ignored by readers |
| `status` | u32 | `0` = success; otherwise the Win32 error code observed (`GetLastError` after the true API returned failure) |
| `tid` | u32 | thread ID of the caller |
| `qpc` | u64 | `QueryPerformanceCounter` at record time |
| `extra` | u64 | op-defined payload, see below; `0` when unused |
| `path` | string | primary subject (path, key, or variable name) |
| `aux` | string | op-defined secondary string; empty when unused |

All bytes of a record are written while holding the writer lock, so
records from different threads never interleave.

### 5.1 Record types

| Value | Type |
|---|---|
| 1 | `FILE` |
| 2 | `PROCESS` |
| 3 | `REGISTRY` |
| 4 | `ENV` |

### 5.2 `FILE` ops

| `op` | Meaning | `path` | `aux` | `extra` |
|---|---|---|---|---|
| 1 | open for read | as passed | — | low u32 = `dwDesiredAccess`, high u32 = `dwCreationDisposition` |
| 2 | open for write | as passed | — | same as op 1 |
| 3 | open for read+write | as passed | — | same as op 1 |
| 4 | probe (attribute/existence query) | as passed | — | low u32 = attributes returned, or `INVALID_FILE_ATTRIBUTES` |
| 5 | enumerate (`FindFirstFile*` pattern) | pattern as passed | — | — |
| 6 | delete | as passed | — | — |
| 7 | move/rename | source | destination | low u32 = `dwFlags` (0 for non-Ex) |
| 8 | create directory | as passed | — | — |
| 9 | remove directory | as passed | — | — |

The read/write/read-write classification of `CreateFile*` is derived from
`dwDesiredAccess` and `dwCreationDisposition`: any of `GENERIC_WRITE |
GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE`, **or** a
disposition that can create or truncate the file (`CREATE_NEW`,
`CREATE_ALWAYS`, `OPEN_ALWAYS`, `TRUNCATE_EXISTING`) ⇒ write intent; any
of `GENERIC_READ | GENERIC_ALL | FILE_READ_DATA | GENERIC_EXECUTE |
FILE_EXECUTE` ⇒ read intent; both ⇒ op 3; neither (a metadata-only open)
⇒ recorded as op 4 with the op-1-style `extra`. The raw access mask and
disposition are preserved in `extra` so the reader can re-derive its own
classification if these rules turn out to be wrong.

### 5.3 `PROCESS` ops

| `op` | Meaning | `path` | `aux` | `extra` |
|---|---|---|---|---|
| 1 | child created | `lpApplicationName` as passed (may be empty) | `lpCommandLine` as passed (may be empty) | child PID (0 on failure) |

The reader links the child's own trace file (matched by header `pid` =
`extra` and header `parent_pid` = this writer's pid) to build the tree.
A `PROCESS` record whose child PID has no corresponding trace file means
injection into the child failed or the child never ran — readers must
surface this as a **trace completeness warning**, not silently ignore it.

### 5.4 `REGISTRY` ops

| `op` | Meaning | `path` | `aux` | `extra` |
|---|---|---|---|---|
| 1 | open key | full key path if resolvable (see below) | — | — |
| 2 | query value | key path | value name | value type (`REG_*`) on success |

Key-path resolution: the writer keeps a map of `HKEY` → path for keys it
saw opened. Predefined roots are rendered `HKLM`, `HKCU`, `HKCR`, `HKU`,
`HKCC`. A query against a key handle the writer never saw opened records
`path` as `"<unresolved>"` — again a visible gap, not a silent one.

### 5.5 `ENV` ops

| `op` | Meaning | `path` | `aux` | `extra` |
|---|---|---|---|---|
| 1 | variable read | variable name | value (empty if not found) | — |
| 2 | environment block read (`GetEnvironmentStringsW`) | — | — | — |

`status` is `0` if the variable existed, `ERROR_ENVVAR_NOT_FOUND`
otherwise. Reads of `SEMBAZURU_TRACE_DIR` itself by the interceptor are
not recorded.

Op 2 exists because CRT runtimes snapshot the whole environment block at
startup and serve `getenv()` from the copy; a process that did this
depends on the *entire* environment, and the reader must treat it that
way. The reader surfaces a block read as a single synthetic env entry
named `<environment-block>` (a name no real variable can have, since `=`
is forbidden in variable names) so the signal is not lost among the
individual variable reads.

## 6. Reader obligations (dependency-graph semantics)

The `sembazuru-trace` reader derives, per process tree:

- **inputs** — paths from successful read/read-write opens (`FILE` op 1, 3),
  **all** probes including failed ones (op 4; a failed include-path probe
  is real dependency information — the build's behavior depends on that
  file *not* existing), enumeration patterns (op 5), move sources, registry
  reads, and env reads.
- **outputs** — files the build produced and **left behind**: write opens
  (op 2, 3), move destinations, created directories.
- **deletions** — files the build deleted or directories it removed
  (op 6, 9) without otherwise producing them. These are dependency
  information but **not** surviving outputs, so they are reported in a
  separate set. A deleted file does not exist after the build, so a
  transient with a run-varying name (e.g. a compiler temp file) must not
  break output-set comparison — separating deletions is what prevents that.

Failed *read opens* (op 1 with nonzero `status`) count as probe-misses.

Exclusions applied by the reader before any path enters a file set:

- **Device and pipe paths** (`\\.\pipe\...`, `\\.\PhysicalDrive0`, console
  handles) are not files and are dropped entirely.
- **Intermediates** under the traced session's `%TMP%`/`%TEMP%` are dropped
  from the comparison sets.
- **Telemetry processes** (currently `vctip.exe`) are tagged and their
  accesses excluded by default, though the raw per-process trace is kept.

Normalization (applied by the reader, never by the writer): strip a `\\?\`
long-path prefix, fold separators and case. Resolving relative paths
against the recording process's working directory is a known gap (the
interceptor does not yet record a per-call CWD); until then a relative
path is compared verbatim, which is stable run-to-run for a fixed working
directory. These rules will be tightened by measurement during M1/M2; this
section is the single place they are defined.

## 7. JSON export

`sembazuru-trace export --json` emits:

```json
{
  "schema": "sembazuru-trace/v0",
  "root_pid": 1234,
  "processes": [
    {
      "pid": 1234,
      "parent_pid": 1000,
      "exe": "C:\\...\\cl.exe",
      "command_line": "cl hello.c",
      "children": [5678],
      "tags": []
    }
  ],
  "inputs":  [ { "path": "C:\\src\\hello.c", "kinds": ["read"], "pids": [1234] } ],
  "outputs": [ { "path": "C:\\src\\hello.obj", "kinds": ["write"], "pids": [1234] } ],
  "deletions": [ { "path": "C:\\build\\_cl_0001.tmp", "kinds": ["delete"], "pids": [1234] } ],
  "registry": [ { "key": "HKLM\\...", "value": "...", "pids": [1234] } ],
  "env": [ { "name": "INCLUDE", "found": true, "pids": [1234] } ],
  "warnings": [ "child 9999 has no trace file (injection failed?)" ]
}
```

`kinds` is the union of access kinds observed for that path
(`read`, `write`, `probe`, `probe-miss`, `enumerate`, `delete`, `move`).
Env values and full event timelines are available via
`export --json --full`, which additionally includes the raw per-process
event list (omitted here for size).

## 8. Known limitations of v0 (deliberate)

- Win32-layer hooks only. Processes that issue `Nt*` syscalls directly
  (msys2/Cygwin toolchains) are not captured; this is the documented gap
  of the user-mode approach (see `docs/decisions/0001-vfs-approach.md`)
  and is compensated in M1 by the `/showIncludes` completeness check.
  NT-layer hooks arrive with the M3 VFS.
- Memory-mapped reads after an open are attributed to the open, not
  tracked per-page.
- `FindNextFile` results are not recorded individually; the enumeration
  pattern stands for the directory dependency.
- No 32-bit interceptor build yet; cross-bitness children would today be
  a completeness warning. The DLL naming convention (`...64.dll`) already
  anticipates the 32-bit sibling.
