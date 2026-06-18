# Sembazuru — EDR / AV vendor disclosure and allowlist request

This document is written for anti-malware and EDR vendors (Microsoft Defender and
third parties). It discloses, in full, the techniques Sembazuru uses that overlap
with malware tradecraft — API hooking and DLL injection — and explains why they
are a legitimate, documented part of a build-acceleration tool. Its purpose is to
support a false-positive / allowlist submission so that Sembazuru's signed
binaries are not flagged when developers run them.

We disclose more than a typical submission would, on purpose: API hooking *is* a
malware technique, so the honest path is full transparency plus a reproducible,
open-source, code-signed build.

## What Sembazuru is

Sembazuru is an open-source, zero-configuration distributed-build system for
Windows (Apache-2.0). It runs an existing build (MSVC `cl.exe`, `clang-cl`, the
linker) across remote workers without changing the build scripts. It does this by
**virtualizing a process's file I/O**: it injects a small DLL into the compiler,
intercepts the files the compiler opens, and supplies them on demand from the
developer's machine while the compiler runs on a worker. Source, build, and design
rationale are public: <https://github.com/SioKo-Shox3/Sembazuru> (see
`docs/DESIGN.md`, `docs/decisions/0001-vfs-approach.md`).

## Components

| Binary | Role | Signed |
|---|---|---|
| `sembazuru.exe` | Build-system launcher (the compiler wrapper a build invokes) | yes |
| `sembazuru-daemon.exe` | Local agent: schedules actions, serves files | yes |
| `sembazuru-worker.exe` | Remote worker: runs the compiler under virtualization | yes |
| `sembazuru-gui.exe` | Resident dashboard (user-session tray; **non-elevated, no injection**) | yes |
| `launcher.exe` | Injector: starts the compiler with the hook DLL loaded | **yes — EDR-relevant** |
| `sbz_interceptor64.dll` (and `…32.dll`) | The injected hook DLL | **yes — EDR-relevant** |

All are Authenticode-signed (see "Signing" below). The two EDR-relevant components
are the injector and the hook DLL.

## Techniques used (full disclosure)

### 1. DLL injection via the documented Detours API

`launcher.exe` starts the compiler with the hook DLL loaded using Microsoft
Research **Detours**' documented injection entry point
`DetourCreateProcessWithDllExW` (`hooks/src/launcher.cpp`). This is the
standard, documented Detours path: the child is created suspended and the DLL is
added to the new process's import table, so the loader maps it at process
initialization. **There is no `CreateRemoteThread`, no `QueueUserAPC`, no
`SetWindowsHookEx`, no manual mapping, and no thread hijacking.** Child processes
the compiler itself spawns (e.g. `cl.exe` → `link.exe`) are propagated to by the
hook DLL's own `CreateProcessW/A` hooks, again via
`DetourCreateProcessWithDllEx` — never by injecting into an already-running
process.

### 2. Inline API hooks via Detours trampolines

Inside the injected process, the DLL installs inline trampoline hooks with the
documented Detours transaction API (`DetourTransactionBegin` /
`DetourAttach` / `DetourTransactionCommit`, `hooks/src/interceptor.cpp`). The
hooked functions are exactly:

- `kernel32!CreateFileW` / `CreateFileA` — to redirect a read-only open under the
  virtualized root to a locally-materialized copy.
- `kernel32!CreateProcessW` / `CreateProcessA` — to propagate the hook to child
  processes (re-using `DetourCreateProcessWithDllEx`).
- `ntdll!NtSetInformationFile` — to observe a temp-file → final-name rename so the
  produced output is correctly attributed (the compiler/linker writes to a temp
  name then renames).

The hooks modify only these named functions' prologues, in the DLL's own process,
through Detours' trampolines. **No direct syscalls / SSDT patching, no kernel
component, no AMSI or ETW patching, no tampering with security products.**

### 3. Named-pipe IPC

The hook DLL talks to its local `sembazuru-worker.exe` over a named pipe
(`\\.\pipe\sbz-exec-…`) to request file contents. This is ordinary, local,
named-pipe IPC — no network sockets are opened by the hook DLL itself.

## What Sembazuru explicitly does NOT do

- No `CreateRemoteThread` / `NtCreateThreadEx` / APC injection / thread hijacking.
- No manual DLL mapping, reflective loading, or module unlinking.
- No RWX memory allocation or self-modifying / packed code.
- No direct syscalls or SSDT / IDT / inline-ntdll-syscall-stub patching.
- No kernel driver of any kind.
- No AMSI, ETW, or EDR/AV tampering, unhooking, or bypass.
- No process hollowing / doppelgänging / herpaderping.
- Persistence is limited to **two auto-start services** (`SembazuruDaemon`,
  `SembazuruWorker`) **plus one per-user Startup-folder shortcut** that launches the
  non-elevated, non-injecting GUI dashboard at logon — all three disclosed under
  "Persistence" below. No Run keys, no scheduled tasks, no WMI subscriptions, no
  Event Log source registration.
- No credential, browser, or keystroke access; no anti-debug / anti-VM evasion.
- No code obfuscation or string encryption — the binaries are debuggable and the
  source is public.

## Steady-state behavior (what an EDR will observe in normal use)

In production, on **every distributed compile**, this is the steady-state pattern,
by design and always-on (not a one-off installer action):

1. A build system invokes `sembazuru.exe <compiler> <args>`.
2. The action is scheduled to a `sembazuru-worker.exe`.
3. The worker runs `launcher.exe sbz_interceptor64.dll <compiler> <args>`, which
   starts the real compiler (`cl.exe` / `clang-cl.exe`) with the hook DLL loaded
   via `DetourCreateProcessWithDllEx`.
4. The hooked compiler opens files; the hook redirects reads under the build root
   to bytes supplied over the local named pipe; the compiler writes its `.obj`.

So an EDR will repeatedly see `launcher.exe` (signed) spawn a Microsoft/LLVM
compiler (signed) with an injected, signed DLL. This is the normal, expected
behavior of the product, not anomalous activity.

## Persistence (two auto-start services + one GUI autostart)

The installer registers **two** Windows Services so both the daemon and the worker
are available without a logged-in user (a worker PC must be reachable before login),
and creates **one** per-user Startup-folder shortcut so the user-session dashboard
GUI starts at logon. These three are the *only* persistence mechanisms Sembazuru
creates; they are disclosed here in full so the registered behavior matches this
document exactly.

The **daemon** service:

- **Service name:** `SembazuruDaemon` — **Display name:** `Sembazuru Build Daemon`
- **Type / start:** `SERVICE_WIN32_OWN_PROCESS`, `AUTO_START` (registered via the
  documented `windows-service` crate → `CreateServiceW`; MITRE T1543.003).
- **ImagePath:** `…\sembazuru-daemon.exe --service` (the same signed binary; the
  `--service` argument selects SCM mode over the plain CLI).
- **Account:** least-privilege in the production installer — a virtual service
  account (`NT SERVICE\SembazuruDaemon`) granted read access to the configured
  source roots it serves; the dev self-install (`sembazuru-daemon install`) may use
  LocalSystem for zero-config convenience. The daemon itself performs **no DLL
  injection** (it schedules actions and serves files); injection happens only in the
  worker's compiler children (the steady-state above).

The **worker** service is registered identically (added M9.3c):

- **Service name:** `SembazuruWorker` — **Display name:** `Sembazuru Build Worker`
- **Type / start:** `SERVICE_WIN32_OWN_PROCESS`, `AUTO_START` (registered via the
  documented `windows-service` crate → `CreateServiceW`; MITRE T1543.003).
- **ImagePath:** `…\sembazuru-worker.exe --service` (the same signed binary; the
  `--service` argument selects SCM mode over the plain CLI).
- **Account:** least-privilege **by default** — a virtual service account
  (`NT SERVICE\SembazuruWorker`). Unlike the daemon, the worker needs no broad file
  access: it injects the Sembazuru hook only into the compilers it spawns and
  receives build inputs over the data plane, so it does **not** read the developer's
  source tree directly and does not default to LocalSystem. That injection is exactly
  the steady-state behavior disclosed above — confined to the worker's own child
  processes, never an already-running process.

The **GUI autostart** (added M9.5c) is the one persistence mechanism that is *not* a
service:

- **Mechanism:** a single shortcut in the **all-users Startup folder**
  (`…\Start Menu\Programs\StartUp\Sembazuru.lnk`), created by the MSI (MITRE
  T1547.001, Startup folder). It launches `sembazuru-gui.exe` at logon.
- **What it launches:** the resident dashboard GUI — **non-elevated** (asInvoker
  manifest), with **no DLL injection** and no network sockets beyond the loopback
  Status RPC it reads. It controls the services only through a UAC-prompted
  elevation (the `svcctl` path), so the autostart itself grants no elevated
  capability.
- **Why not a service:** a session-0 service cannot draw a user-session UI, so the
  dashboard must run in the interactive session and needs a per-user logon trigger
  (ADR 0008 §3, amended 2026-06-18). A Run key or scheduled task was deliberately
  *not* used — the Startup-folder shortcut is the most visible, least-privileged
  option and is removed cleanly on uninstall.

- **No other persistence:** the two services and this one GUI Startup-folder shortcut
  are the *only* persistence Sembazuru creates — no Run keys, no scheduled tasks, no
  WMI subscriptions, no Event Log source registration. Uninstall (the MSI, or the dev
  `sembazuru-daemon uninstall` / `sembazuru-worker uninstall`) stops and deletes the
  services and removes the shortcut, adding nothing else.

## Signing

All distributed binaries are Authenticode-signed (SHA-256). The two EDR-relevant
components — `launcher.exe` and `sbz_interceptor64.dll` (and the 32-bit DLL once
shipped) — are always signed; the CI signing pipeline
(`hooks/test/sign_smoke.ps1`) signs every produced PE so none ships unsigned. The
signing certificate is an OV Authenticode certificate with a hardware-token /
HSM-stored key (CA/Browser Forum requirement since 2023). SmartScreen reputation
accrues with download volume over time; signing alone does not grant immediate
reputation (this is true of OV and EV alike since Microsoft's 2024 change that
stopped granting EV instant reputation).

## How to submit / request allowlisting

### Microsoft Defender

- False-positive / "this is clean software" submission:
  <https://www.microsoft.com/en-us/wdsi/filesubmission> (developer submission; free).
- Enterprise submission portal: <https://security.microsoft.com/reportsubmission>.
- Attach: the signed binaries, this document, and the public repository URL. Note
  that the binaries are reproducible from source.

### Third-party EDR (CrowdStrike, SentinelOne, Carbon Black, etc.)

There is no universal developer false-positive channel; submit per-vendor through
each support portal after a tagged release, attaching the signed binaries and this
document. A signed binary with accruing reputation is the strongest supporting
evidence.

## Reproducibility

Every binary is built from the public source. The compiler outputs Sembazuru
distributes are byte-reproducible (verified in CI; see `docs/determinism.md`). The
injector and hook DLL are built by the project's CMake configuration
(`hooks/CMakeLists.txt`) and are not obfuscated.

---

*Status (M7.2): the disclosure package and the CI signing pipeline are in place.
Acquiring the real OV certificate and filing the Microsoft Defender / vendor
submissions are owned by the project lead and tracked separately — the mechanism
ships first so the submission only needs a real certificate swapped in.*
