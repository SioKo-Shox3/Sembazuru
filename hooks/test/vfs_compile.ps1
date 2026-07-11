# M3 "Done when" gate: remote compile under the read VFS.
#
# Runs a compiler under the interceptor in VFS mode so its source inputs are
# supplied by the agent on demand (redirected to hydrated scratch copies), with
# the object written locally in a work dir. Asserts:
#   * the compiler produced an object, and
#   * the VFS was actually exercised (the source appears in the scratch tree),
#   * and for clang-cl, the object is BYTE-IDENTICAL to a local build of the same
#     source with the same flags -- the M3 "Done when" (a remote .obj that equals
#     the local one). MSVC cl is run for the mechanism only (its .obj embeds the
#     absolute object path, so cross-directory byte-identity is not expected;
#     clang-cl is the gating path per CLAUDE.md / docs/determinism.md).
#
# Single machine: the agent file server and the worker VFS pipe are co-located by
# the `vfs_host` example; the compiler reads the agent's bytes through the pipe.
# Requires cl.exe + cargo on PATH; clang-cl when present (required in CI).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\vfs-compile-work'),
    [switch]$RequireClangCl
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
    $savedErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $cargoOutput = @(& cargo build -p sembazuru-worker --example vfs_host 2>&1 | ForEach-Object { "$_" })
        $cargoExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorPreference
    }
    Write-Host ($cargoOutput -join [Environment]::NewLine)
    if ($cargoExitCode -ne 0) { throw "vfs_host example build failed with exit code $cargoExitCode" }
} finally { Pop-Location }
$hostExe = Join-Path $repo 'target\debug\examples\vfs_host.exe'

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# Source corpus on the agent side (this dir is the VFS root the compiler reads).
$agentSrc = Join-Path $WorkRoot 'agent-src'
New-Item -ItemType Directory -Force $agentSrc | Out-Null
Set-Content (Join-Path $agentSrc 'shared.h') @'
#pragma once
template <typename T> struct Box { T v; T twice() const { return v + v; } };
int k();
'@ -Encoding ascii
Set-Content (Join-Path $agentSrc 'a.cpp') @'
#include "shared.h"
int k() { return 1729; }
double widen(int x) { Box<double> b{(double)x}; return b.twice(); }
'@ -Encoding ascii
$srcAbs = Join-Path $agentSrc 'a.cpp'

# Compiles $srcAbs under the VFS, writing the object to $outObj. Returns nothing;
# throws on failure. $scratch must be OUTSIDE the VFS root.
function Compile-UnderVfs {
    param([string]$Cc, [string[]]$Flags, [string]$OutObj, [string]$Scratch,
          [hashtable]$ExtraEnv)

    $workdir = Join-Path $WorkRoot ("work-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force $workdir | Out-Null
    New-Item -ItemType Directory -Force $Scratch | Out-Null
    $pipe = "sbz-vfs-compile-$PID-" + [System.IO.Path]::GetRandomFileName().Substring(0, 8)
    $full = "\\.\pipe\$pipe"

    $proc = Start-Process -FilePath $hostExe -ArgumentList @($pipe, $Scratch) `
        -PassThru -WindowStyle Hidden
    try {
        $ready = $false
        for ($i = 0; $i -lt 100; $i++) {
            if (Test-Path $full) { $ready = $true; break }
            Start-Sleep -Milliseconds 50
        }
        if (-not $ready) { throw 'vfs pipe did not come up' }

        $env:SEMBAZURU_MODE = 'vfs'
        $env:SEMBAZURU_VFS_ROOT = $agentSrc
        $env:SEMBAZURU_VFS_PIPE = $pipe
        $env:SEMBAZURU_VFS_SCRATCH = $Scratch
        if ($ExtraEnv) { $ExtraEnv.GetEnumerator() | ForEach-Object { Set-Item "Env:\$($_.Key)" $_.Value } }
        Push-Location $workdir
        try {
            $out = & $launcher $dll $Cc '/nologo' '/c' @Flags $srcAbs "/Fo$OutObj" 2>&1 | Out-String
            if ($LASTEXITCODE -ne 0) { Write-Host $out; throw "$Cc under VFS exited $LASTEXITCODE" }
        } finally {
            Pop-Location
            Remove-Item Env:\SEMBAZURU_MODE, Env:\SEMBAZURU_VFS_ROOT, Env:\SEMBAZURU_VFS_PIPE, `
                Env:\SEMBAZURU_VFS_SCRATCH -ErrorAction SilentlyContinue
            if ($ExtraEnv) { $ExtraEnv.Keys | ForEach-Object { Remove-Item "Env:\$_" -ErrorAction SilentlyContinue } }
        }
    } finally {
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    }
}

$failures = @()

# --- MSVC cl: mechanism only (no cross-dir byte-identity expected) ----------
Write-Host '=== cl under VFS (mechanism) ==='
$clScratch = Join-Path $WorkRoot 'scratch-cl'
$clObj = Join-Path $WorkRoot 'cl-remote.obj'
Compile-UnderVfs -Cc 'cl' -Flags @('/Brepro') -OutObj $clObj -Scratch $clScratch
if (-not (Test-Path $clObj)) {
    $failures += 'cl: no object produced under VFS'
} elseif (-not (Get-ChildItem -Recurse -File $clScratch -ErrorAction SilentlyContinue)) {
    $failures += 'cl: VFS not exercised (scratch tree empty -> source was not hydrated)'
} else {
    Write-Host "GATE PASS  cl: object produced under VFS and source hydrated via the agent"
}

# --- clang-cl: byte-identity to a local build (the M3 Done-when) -------------
$clang = Get-Command clang-cl -ErrorAction SilentlyContinue
if ($null -eq $clang) {
    if ($RequireClangCl) { $failures += 'clang-cl: required but not on PATH' }
    else { Write-Host 'GATE SKIP  clang-cl not on PATH' }
} else {
    Write-Host '=== clang-cl under VFS (byte-identity) ==='
    $clangFlags = @('/Brepro', '-ffile-compilation-dir=.', '-no-canonical-prefixes',
        '-Wno-builtin-macro-redefined', '-D__DATE__=', '-D__TIME__=', '-D__TIMESTAMP__=')
    $epoch = @{ SOURCE_DATE_EPOCH = '0' }

    # Local reference build (reads the agent source directly, no VFS).
    $refObj = Join-Path $WorkRoot 'clang-ref.obj'
    $refDir = Join-Path $WorkRoot 'refdir'
    New-Item -ItemType Directory -Force $refDir | Out-Null
    Push-Location $refDir
    try {
        $env:SOURCE_DATE_EPOCH = '0'
        try { $o = & clang-cl '/nologo' '/c' @clangFlags $srcAbs "/Fo$refObj" 2>&1 | Out-String
              if ($LASTEXITCODE -ne 0) { Write-Host $o; throw 'clang-cl ref build failed' } }
        finally { Remove-Item Env:\SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue }
    } finally { Pop-Location }

    # Remote build under VFS.
    $clangScratch = Join-Path $WorkRoot 'scratch-clang'
    $remoteObj = Join-Path $WorkRoot 'clang-remote.obj'
    Compile-UnderVfs -Cc 'clang-cl' -Flags $clangFlags -OutObj $remoteObj -Scratch $clangScratch -ExtraEnv $epoch

    if (-not (Test-Path $remoteObj)) {
        $failures += 'clang-cl: no object produced under VFS'
    } elseif (-not (Get-ChildItem -Recurse -File $clangScratch -ErrorAction SilentlyContinue)) {
        $failures += 'clang-cl: VFS not exercised (scratch tree empty)'
    } else {
        $hRef = (Get-FileHash $refObj -Algorithm SHA256).Hash
        $hRemote = (Get-FileHash $remoteObj -Algorithm SHA256).Hash
        if ($hRef -ne $hRemote) {
            $failures += "clang-cl: remote .obj NOT byte-identical to local (ref $hRef vs remote $hRemote)"
        } else {
            Write-Host "GATE PASS  clang-cl: remote .obj is byte-identical to local ($hRemote)"
        }
    }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'VFS COMPILE GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host ''
Write-Host 'VFS COMPILE GATE PASS (remote compile under the read VFS; clang-cl byte-identical to local)'
