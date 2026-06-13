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
# VFS. We assert on the hydrated SCRATCH copy (the worker doesn't mirror child
# stdout yet, M6.1), which also proves the redirect happened (the file only
# appears in scratch if the DLL intercepted the open and hydrated it).
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

# Probe: open a file (read-only) and exit 0; the open is what the DLL redirects.
# Static CRT (/MT) so it needs no runtime DLL beyond the cleared+rebuilt env.
$probeSrc = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return 2;
    HANDLE h = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 1;
    char buf[256]; DWORD r = 0;
    ReadFile(h, buf, sizeof(buf), &r, nullptr);
    CloseHandle(h);
    return 0;
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

    & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $traceDir -- $probe $logicalInput 2>&1 |
        Out-String | Write-Host
    $exit = $LASTEXITCODE
} finally {
    Remove-Item Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, Env:\SEMBAZURU_SCRATCH_ROOT, `
        Env:\SEMBAZURU_CAS_ROOT -ErrorAction SilentlyContinue
    foreach ($p in @($workerProc, $fsProc)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}

$failures = @()
if ($exit -ne 0) { $failures += "action did not exit 0 (exit=$exit): the VFS-mode Execute failed" }

# The hydrated scratch copy proves the redirect AND the provenance.
$hydrated = Get-ChildItem -Recurse -File -Filter 'input.txt' $scratchRoot -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $hydrated) {
    $failures += 'no hydrated copy under the worker scratch root: the read was not redirected through the VFS'
} else {
    $bytes = Get-Content $hydrated.FullName -Raw
    if ($bytes -ne $correct) {
        $failures += "hydrated bytes are not the agent-served content (got '$bytes'): provenance check failed"
    }
    if ($bytes -eq $stale) {
        $failures += 'STALE local bytes were hydrated: the worker read the local copy, not the agent'
    }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.1b WORKER VFS GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'M6.1b WORKER VFS GATE PASS (worker Execute redirected the read to agent-served bytes in a per-action scratch copy)'
