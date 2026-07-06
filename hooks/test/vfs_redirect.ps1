# M3.2(c) read-VFS redirect gate.
#
# Proves the observe->virtualize flip end to end AND that the bytes come from the
# agent, not the local disk:
#   * the probe opens a file under SEMBAZURU_VFS_ROOT whose LOCAL copy holds
#     STALE bytes;
#   * the agent (remapped) serves DIFFERENT, CORRECT bytes from a backing dir;
#   * the hook redirects the read to a hydrated scratch copy.
# So the content check is provenance-distinguishing (CORRECT only if the redirect
# really pulled from the agent) and the path check proves a redirect happened
# (the handle resolves under the scratch root, not the original path). Scratch
# lives OUTSIDE the VFS root, and SEMBAZURU_VFS_SCRATCH is set so the DLL refuses
# to re-redirect scratch opens or trust an out-of-scratch path.
#
# Requires cl.exe + cargo on PATH (CI dev shell).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\vfs-work')
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
    & cargo build -q -p sembazuru-worker --example vfs_host 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'vfs_host example build failed' }
} finally { Pop-Location }
$hostExe = Join-Path $repo 'target\debug\examples\vfs_host.exe'
if (-not (Test-Path $hostExe)) { throw "host not built: $hostExe" }

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# Probe: open a file, print its real (post-redirect) path and its bytes.
$probeSrc = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        fwprintf(stderr, L"usage: vfs_probe <path>\n");
        return 2;
    }
    HANDLE h = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        wprintf(L"OPENFAIL:%lu\n", GetLastError());
        return 1;
    }
    wchar_t fin[1024];
    DWORD fn = GetFinalPathNameByHandleW(h, fin, 1024,
                                         FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    wprintf(L"PATH:%s\n", (fn > 0 && fn < 1024) ? fin : L"?");
    char buf[4096];
    DWORD r = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &r, nullptr);
    buf[r] = 0;
    CloseHandle(h);
    printf("CONTENT:%s\n", buf);
    return 0;
}
'@
Set-Content (Join-Path $WorkRoot 'vfs_probe.cpp') $probeSrc -Encoding ascii
Push-Location $WorkRoot
try {
    $out = & cl /nologo /EHsc 'vfs_probe.cpp' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $out; throw 'probe compile failed' }
} finally { Pop-Location }
$probe = Join-Path $WorkRoot 'vfs_probe.exe'

# Layout: the VFS root (logical) holds a STALE local copy; the backing dir holds
# the CORRECT bytes the agent serves; scratch is a sibling, OUTSIDE the root.
$logicalRoot = Join-Path $WorkRoot 'logical'
$backingRoot = Join-Path $WorkRoot 'backing'
$scratch = Join-Path $WorkRoot 'scratch'
$rel = 'src\input.txt'
$correct = 'hello-from-the-agent-vfs'
$stale = 'STALE-LOCAL-MUST-NOT-BE-READ'

New-Item -ItemType Directory -Force (Split-Path (Join-Path $logicalRoot $rel)) | Out-Null
New-Item -ItemType Directory -Force (Split-Path (Join-Path $backingRoot $rel)) | Out-Null
New-Item -ItemType Directory -Force $scratch | Out-Null
Set-Content (Join-Path $logicalRoot $rel) $stale -Encoding ascii -NoNewline
Set-Content (Join-Path $backingRoot $rel) $correct -Encoding ascii -NoNewline

$logicalInput = Join-Path $logicalRoot $rel
$pipe = "sbz-vfs-redirect-$PID"
$full = "\\.\pipe\$pipe"

$hostProc = Start-Process -FilePath $hostExe `
    -ArgumentList @($pipe, $scratch, $logicalRoot, $backingRoot) `
    -PassThru -WindowStyle Hidden
$out = ''
try {
    $ready = $false
    for ($i = 0; $i -lt 100; $i++) {
        if (Test-Path $full) { $ready = $true; break }
        Start-Sleep -Milliseconds 50
    }
    if (-not $ready) { throw 'vfs pipe did not come up (host failed to start?)' }

    $env:SEMBAZURU_MODE = 'vfs'
    $env:SEMBAZURU_VFS_ROOT = $logicalRoot
    $env:SEMBAZURU_VFS_PIPE = $pipe
    $env:SEMBAZURU_VFS_SCRATCH = $scratch
    try {
        $out = & $launcher $dll $probe $logicalInput 2>&1 | Out-String
    } finally {
        Remove-Item Env:\SEMBAZURU_MODE, Env:\SEMBAZURU_VFS_ROOT, `
            Env:\SEMBAZURU_VFS_PIPE, Env:\SEMBAZURU_VFS_SCRATCH `
            -ErrorAction SilentlyContinue
    }
    Write-Host $out
} finally {
    if ($hostProc -and -not $hostProc.HasExited) {
        Stop-Process -Id $hostProc.Id -Force -ErrorAction SilentlyContinue
    }
}

$failures = @()
# Provenance: CORRECT bytes only appear if the read was served by the agent.
if ($out -notmatch "CONTENT:$([regex]::Escape($correct))") {
    $failures += 'content is not the agent-served bytes (redirect did not pull from the agent)'
}
# Never read the stale local copy.
if ($out -match [regex]::Escape($stale)) {
    $failures += 'STALE local bytes were read (redirect failed to a local open)'
}
# Mechanism: the handle resolves under the scratch root.
$scratchFull = ([System.IO.Path]::GetFullPath($scratch)).ToLower()
if (-not ($out.ToLower().Contains($scratchFull))) {
    $failures += 'handle did not resolve under the scratch root: no redirect happened'
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'VFS REDIRECT GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'VFS REDIRECT GATE PASS (read redirected to agent-served bytes in a scratch copy; stale local copy not read)'
