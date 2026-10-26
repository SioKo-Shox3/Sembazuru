# Sembazuru LAN smoke test

This package checks authenticated Coordination and Execution between two Windows 11 x64 PCs over a wired LAN. It runs eight deterministic CPU burn actions and requires every action to finish on the remote worker.

## Requirements

- Windows 11 x64 on both PCs
- A wired network connection and AC power
- No Rust, C++ compiler, or other development environment
- Microsoft Visual C++ v14 x64 runtime. Install it from [Microsoft's latest supported Visual C++ Redistributable page](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist) or download the [x64 installer](https://aka.ms/vc14/vc_redist.x64.exe)
- One IPv4 address configured on each PC's physical, connected network adapter

Before extraction, compare the archive SHA256 values from the folder containing the ZIP. Both PCs must use the same value.

```powershell
Get-FileHash .\Sembazuru-lan-smoke.zip -Algorithm SHA256
```

Extract the same `Sembazuru-lan-smoke.zip` into any folder on both PCs, then run the following commands from the extracted folder. `Check` verifies the package files and displays the local network and runtime state without changing Windows services, firewall rules, or the existing Sembazuru installation.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\lan_smoke.ps1 -Mode Check
```

The manifest inside the extracted folder is checked again by every mode that starts a process.

## Run the smoke

Choose one 32-byte token once and use it on both PCs. Generate it on either PC and copy the single hexadecimal line through a trusted channel.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\lan_smoke.ps1 -Mode Token
```

On PC-B, start the worker first. Replace `B_IPV4` with the IPv4 address shown by `Check` and `A_IPV4` with PC-A's address. The command prompts for the token as a `SecureString`. The worker makes a verified, read-and-execute copy of `burn.exe` in its new `LocalAppData\SembazuruLan\<guid>` run directory and prints that absolute path; pass the printed path to the coordinator.

The worker's dedicated override enables the existing `unsafe_allow_insecure_execution_lan` LAN bind opt-in for this foreground process. It only permits the explicit LAN endpoint; the shared cluster token remains required for Coordination and Execution.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\lan_smoke.ps1 -Mode Worker `
    -LocalAddress B_IPV4 `
    -CoordinatorAddress A_IPV4:50170
```

Leave this process in the foreground. On PC-A, start the coordinator and provide the absolute `burn.exe` path printed by PC-B.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\lan_smoke.ps1 -Mode Coordinator `
    -LocalAddress A_IPV4 `
    -WorkerProgram 'C:\Users\<user>\AppData\Local\SembazuruLan\<guid>\burn.exe'
```

The coordinator prints a result line like this:

```text
SCALE workers=1 actions=8 makespan_ms=... remote=8 local=0 ok=true
```

`remote=8 local=0 ok=true` is the passing result. Stop the worker with Ctrl+C after the coordinator exits. The token is supplied to child processes through the process environment and is not written to the worker configuration or the ZIP archive.

## Firewall rules, if required

The smoke script does not request elevation and does not create firewall rules. If Windows Firewall blocks the connection, run these commands once in an elevated PowerShell, replacing the address and program placeholders with the exact peer address and extracted path. `-Profile Any` permits the rule on a Public profile while the address pair keeps its scope to the two PCs.

On PC-A, allow PC-B to reach the coordinator:

```powershell
New-NetFirewallRule -DisplayName 'Sembazuru LAN smoke coordinator 50170' `
    -Direction Inbound -Action Allow -Protocol TCP `
    -LocalAddress A_IPV4 -RemoteAddress B_IPV4 -LocalPort 50170 `
    -Program 'C:\path\to\scale_harness.exe' -Profile Any
```

On PC-B, allow PC-A to reach the worker:

```powershell
New-NetFirewallRule -DisplayName 'Sembazuru LAN smoke worker 50161' `
    -Direction Inbound -Action Allow -Protocol TCP `
    -LocalAddress B_IPV4 -RemoteAddress A_IPV4 -LocalPort 50161 `
    -Program 'C:\path\to\sembazuru-worker.exe' -Profile Any
```

Remove only these named rules when the test is finished:

```powershell
Remove-NetFirewallRule -DisplayName 'Sembazuru LAN smoke coordinator 50170'
Remove-NetFirewallRule -DisplayName 'Sembazuru LAN smoke worker 50161'
```

TCP port 50170 is inbound on PC-A from PC-B. TCP port 50161 is inbound on PC-B from PC-A. The commands constrain both the local and peer addresses, local port, and executable path.

## What this result means

The smoke demonstrates that the two processes authenticate with the shared token, register over Coordination, dispatch plain CPU burn actions, and return successful remote exit codes. It does not measure compile speed or prove VFS behavior, file I/O, output writeback, cache behavior, output equivalence, or local fallback acceptance. It is one LAN preparation check and does not complete the M10 milestone by itself.
