# M6.1b gate: the WORKER DAEMON's Execute redirects reads through the VFS.
#
# Unlike vfs_redirect.ps1 (which drives launcher.exe directly against a
# co-located vfs_host), this proves the *production* path: a real
# `sembazuru-worker` process, told to run an action in VFS mode over gRPC
# (ExecuteRequest.vfs), starts its own per-action pipe, injects the hook DLL via
# launcher.exe, dials the agent file server, and hydrates the read into scratch.
#
# Provenance (same trick as vfs_redirect.ps1): the logical path holds STALE local
# bytes; the agent (remap) serves DIFFERENT correct bytes from a backing dir. The
# read is correct ONLY if the worker actually pulled from the agent through the
# VFS. The probe READS THE FILE AND COMPARES IT to the agent-served content,
# exiting 0 only on an exact match — so the action's own exit code proves both that
# the open was redirected (a non-redirected open would read the STALE local bytes)
# and the provenance (the bytes came from the agent).
#
# Why content, not the scratch file: since M9.2 (deferred #8) the worker removes the
# per-action hydrated scratch tree once the action completes, to bound a resident
# worker's disk. So the scratch copy no longer exists by the time this script could
# inspect it. Checking what the process actually READ (live, before cleanup) is the
# robust, eviction-proof way to prove the redirect — and a strictly stronger check
# than inspecting the hydrated file after the fact.
#
# Requires cl.exe + cargo on PATH and the cmake-built launcher/DLL (CI hooks job).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m6-vfs-work')
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcher, $dll)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
    throw 'cl.exe not on PATH (run from a VS dev shell or after msvc-dev-cmd)'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    & cargo build -q -p sembazuru-worker --bin sembazuru-worker `
        --example exec_vfs 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'worker bin/exec_vfs build failed' }
    & cargo build -q -p sembazuru-agent --example fileserver_host 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'fileserver_host build failed' }
} finally { Pop-Location }
$workerExe = Join-Path $repo 'target\debug\sembazuru-worker.exe'
$execVfs = Join-Path $repo 'target\debug\examples\exec_vfs.exe'
$fsHost = Join-Path $repo 'target\debug\examples\fileserver_host.exe'

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# Probe: open argv[1] (read-only, the open the DLL redirects), read it, and assert
# the content EXACTLY equals argv[2] (the agent-served bytes). Exit codes encode the
# provenance so the gate needs no post-run scratch file (cleaned up since M9.2):
#   0 = content matched the agent bytes  -> redirect + provenance proven
#   1 = open failed / read failed
#   2 = bad args
#   3 = content mismatch (STALE local bytes) -> NOT redirected through the VFS
# Static CRT (/MT) so it needs no runtime DLL beyond the cleared+rebuilt env.
$probeSrc = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) return 2;
    HANDLE h = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 1;
    char buf[256]; DWORD r = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf), &r, nullptr);
    CloseHandle(h);
    if (!ok) return 1;
    char exp[256];
    int en = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, exp, sizeof(exp),
                                 nullptr, nullptr);
    if (en <= 1) return 2;
    DWORD elen = (DWORD)(en - 1); // drop the NUL
    if (r != elen) return 3;
    return memcmp(buf, exp, elen) == 0 ? 0 : 3;
}
'@
Set-Content (Join-Path $WorkRoot 'probe.cpp') $probeSrc -Encoding ascii
Push-Location $WorkRoot
try {
    $o = & cl /nologo /EHsc /MT 'probe.cpp' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $o; throw 'probe compile failed' }
} finally { Pop-Location }
$probe = Join-Path $WorkRoot 'probe.exe'

# Layout: logical holds STALE bytes; backing holds CORRECT bytes the agent serves.
$logicalRoot = Join-Path $WorkRoot 'logical'
$backingRoot = Join-Path $WorkRoot 'backing'
$scratchRoot = Join-Path $WorkRoot 'scratch'
$casRoot = Join-Path $WorkRoot 'cas'
$traceDir = Join-Path $WorkRoot 'trace'
$rel = 'src\input.txt'
$correct = 'hello-from-the-agent-vfs'
$stale = 'STALE-LOCAL-MUST-NOT-BE-READ'
New-Item -ItemType Directory -Force (Split-Path (Join-Path $logicalRoot $rel)) | Out-Null
New-Item -ItemType Directory -Force (Split-Path (Join-Path $backingRoot $rel)) | Out-Null
foreach ($d in @($scratchRoot, $casRoot, $traceDir)) { New-Item -ItemType Directory -Force $d | Out-Null }
Set-Content (Join-Path $logicalRoot $rel) $stale -Encoding ascii -NoNewline
Set-Content (Join-Path $backingRoot $rel) $correct -Encoding ascii -NoNewline
$logicalInput = Join-Path $logicalRoot $rel

$fsAddr = '127.0.0.1:50082'
$workerAddr = '127.0.0.1:50061'

# Agent file server in REMAP mode: paths under logicalRoot are served from backingRoot.
$fsProc = Start-Process -FilePath $fsHost -ArgumentList @($fsAddr, $logicalRoot, $backingRoot) `
    -PassThru -WindowStyle Hidden

# Worker with VFS execution enabled (install paths via env). No SEMBAZURU_AGENT:
# it just serves Execution; exec_vfs dials it directly.
$env:SEMBAZURU_LAUNCHER = $launcher
$env:SEMBAZURU_DLL = $dll
$env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot
$env:SEMBAZURU_CAS_ROOT = $casRoot
$workerProc = Start-Process -FilePath $workerExe -ArgumentList @($workerAddr) `
    -PassThru -WindowStyle Hidden

$exit = 99
try {
    # Wait for the worker's Execution port to accept connections.
    $ready = $false
    for ($i = 0; $i -lt 100; $i++) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', 50061); $c.Close(); $ready = $true; break
        } catch { Start-Sleep -Milliseconds 50 }
    }
    if (-not $ready) { throw 'worker Execution port did not come up' }

    & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $traceDir -- $probe $logicalInput $correct 2>&1 |
        Out-String | Write-Host
    $exit = $LASTEXITCODE
} finally {
    Remove-Item Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, Env:\SEMBAZURU_SCRATCH_ROOT, `
        Env:\SEMBAZURU_CAS_ROOT -ErrorAction SilentlyContinue
    foreach ($p in @($workerProc, $fsProc)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}

# The action's exit code IS the provenance proof (the probe compared the bytes it
# read to the agent-served content). No post-run scratch inspection: the worker
# removes the per-action scratch tree on completion (M9.2 / deferred #8).
$failures = @()
switch ($exit) {
    0 { }
    1 { $failures += 'the redirected open/read failed (exit 1): the VFS-mode Execute did not produce a readable handle' }
    2 { $failures += 'probe argument error (exit 2): the test harness invoked the probe incorrectly' }
    3 { $failures += 'the probe read the STALE local bytes, not the agent-served content (exit 3): the read was NOT redirected through the VFS' }
    default { $failures += "the VFS-mode Execute failed (exit=$exit)" }
}

# Belt-and-suspenders: the per-action scratch tree must NOT linger after the run
# (M9.2 eviction). Its absence is expected; a lingering tree is a disk-leak
# regression, not a redirect failure, so report it distinctly (still a failure).
$leftover = Get-ChildItem -Recurse -File -Filter 'input.txt' $scratchRoot -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($leftover) {
    $failures += "per-action scratch was not cleaned up after the run ($($leftover.FullName)): M9.2 eviction regressed"
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.1b WORKER VFS GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'M6.1b WORKER VFS GATE PASS (worker Execute redirected the read to the agent-served bytes; per-action scratch cleaned up)'
