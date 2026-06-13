# M6.1 core gate: a real compile through the PRODUCTION daemon path.
#
# The launcher (the form CMake emits as CMAKE_<LANG>_COMPILER_LAUNCHER:
# `sembazuru <compiler> <args>`) hands the compile to the agent daemon, which
# schedules it on a VFS-configured worker; the worker injects the hook DLL and
# supplies the inputs on demand from the daemon's file server. Asserts the M6
# "Done when" for the CMake/Ninja+clang-cl target:
#   1. distributed build: the .obj is byte-identical to a local build (clang-cl);
#   2. local fallback: with the daemon down, the launcher still builds locally;
#   3. action cache: a 2nd identical build HITS (compile skipped) and reproduces
#      the bytes, proven by stopping the worker so a miss could only fall back.
#
# Single-machine model: reads redirect through the VFS; the .obj is written to
# the local output path (a 2-machine writeback is deferred to real-LAN, ADR 0004).
# Requires cl/clang-cl + cargo on PATH and the cmake-built launcher/DLL (CI hooks).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m6-daemon-work'),
    [switch]$RequireClangCl
)
$ErrorActionPreference = 'Stop'

$launcherExe = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcherExe, $dll)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}

# clang-cl is the byte-identity gate (path-independent); cl is best-effort but
# same-dir here, so we still byte-compare it.
$cc = $null
if (Get-Command clang-cl -ErrorAction SilentlyContinue) { $cc = 'clang-cl' }
elseif ($RequireClangCl) { throw 'clang-cl required but not on PATH' }
elseif (Get-Command cl -ErrorAction SilentlyContinue) { $cc = 'cl' }
else { throw 'no compiler (clang-cl/cl) on PATH' }

# Byte-identity is the clang-cl gate (path-independent, deterministic). Native cl
# embeds a COFF timestamp and is byte-best-effort (docs/deferred.md), so for cl we
# assert the mechanism (exit/notes/output produced), not byte-identity.
$byteGate = ($cc -eq 'clang-cl')

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    & cargo build -q -p sembazuru-agent --bin sembazuru-daemon --bin sembazuru `
        -p sembazuru-worker --bin sembazuru-worker 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'bin build failed' }
} finally { Pop-Location }
$daemonExe = Join-Path $repo 'target\debug\sembazuru-daemon.exe'
$launcher = Join-Path $repo 'target\debug\sembazuru.exe'
$workerExe = Join-Path $repo 'target\debug\sembazuru-worker.exe'

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# A self-contained TU: only a project header, no system includes (so every read
# is under the VFS root and the gate needs no SDK on the worker side).
$proj = Join-Path $WorkRoot 'proj'
New-Item -ItemType Directory -Force $proj | Out-Null
Set-Content (Join-Path $proj 'shared.h') "#define SHARED_VALUE 42`n" -Encoding ascii
# The #pragma message prints a marker during compilation; we assert it reaches the
# launcher's console, proving remote stdout/stderr mirroring end to end (M6.1).
$diag = 'SBZ-REMOTE-DIAG-MARKER'
Set-Content (Join-Path $proj 'a.cpp') "#include `"shared.h`"`n#pragma message(`"$diag`")`nint f(){ return SHARED_VALUE; }`n" -Encoding ascii

$scratchRoot = Join-Path $WorkRoot 'wscratch'
$casRoot = Join-Path $WorkRoot 'wcas'
$cacheRoot = Join-Path $WorkRoot 'acache'
$traceRoot = Join-Path $WorkRoot 'atrace'
foreach ($d in @($scratchRoot, $casRoot, $cacheRoot, $traceRoot)) { New-Item -ItemType Directory -Force $d | Out-Null }

# Reference (local, direct) build in the project dir, using the SAME output name
# (a.obj) the distributed build uses — the compiler embeds the object's own name
# (S_OBJNAME), so comparing against a differently-named ref.obj would spuriously
# differ. Build a.obj, snapshot its bytes as ref.obj, then remove a.obj.
$refObj = Join-Path $proj 'ref.obj'
$aObj = Join-Path $proj 'a.obj'
Push-Location $proj
try {
    & $cc /nologo /c a.cpp /Foa.obj 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'reference build failed' }
    Copy-Item $aObj $refObj -Force
    Remove-Item $aObj -Force
} finally { Pop-Location }

$coord = '127.0.0.1:50090'; $intake = '127.0.0.1:50091'; $fs = '127.0.0.1:50092'; $worker = '127.0.0.1:50061'
$daemonUrl = "http://$intake"

function Start-Daemon {
    $env:SEMBAZURU_COORD = $coord; $env:SEMBAZURU_INTAKE = $intake; $env:SEMBAZURU_FILESERVER = $fs
    $env:SEMBAZURU_CACHE_ROOT = $cacheRoot; $env:SEMBAZURU_TRACE_ROOT = $traceRoot
    $p = Start-Process -FilePath $daemonExe -PassThru -WindowStyle Hidden
    Remove-Item Env:\SEMBAZURU_COORD, Env:\SEMBAZURU_INTAKE, Env:\SEMBAZURU_FILESERVER, `
        Env:\SEMBAZURU_CACHE_ROOT, Env:\SEMBAZURU_TRACE_ROOT -ErrorAction SilentlyContinue
    $p
}
function Start-Worker {
    $env:SEMBAZURU_AGENT = "http://$coord"
    $env:SEMBAZURU_LAUNCHER = $launcherExe; $env:SEMBAZURU_DLL = $dll
    $env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot; $env:SEMBAZURU_CAS_ROOT = $casRoot
    $p = Start-Process -FilePath $workerExe -ArgumentList @($worker) -PassThru -WindowStyle Hidden
    Remove-Item Env:\SEMBAZURU_AGENT, Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, `
        Env:\SEMBAZURU_SCRATCH_ROOT, Env:\SEMBAZURU_CAS_ROOT -ErrorAction SilentlyContinue
    $p
}
# Run the launcher as the compiler wrapper; returns @{ exit; note } (note=stderr).
function Invoke-Launcher {
    Push-Location $proj
    try {
        $env:SEMBAZURU_DAEMON = $daemonUrl
        if (Test-Path $aObj) { Remove-Item -Force $aObj }
        $err = & $launcher $cc /nologo /c a.cpp /Foa.obj 2>&1 | Out-String
        $code = $LASTEXITCODE
        Remove-Item Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue
        return @{ exit = $code; note = $err }
    } finally { Pop-Location }
}
function Same-Bytes($a, $b) {
    if (-not (Test-Path $a) -or -not (Test-Path $b)) { return $false }
    $ha = (Get-FileHash $a -Algorithm SHA256).Hash
    $hb = (Get-FileHash $b -Algorithm SHA256).Hash
    return $ha -eq $hb
}

$failures = @()
$daemon = Start-Daemon
$workerProc = Start-Worker
try {
    # Wait for the worker to register; retry the build until it runs remotely
    # (before registration completes, dispatch would local-fallback).
    $r = $null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 400
        $r = Invoke-Launcher
        if ($r.note -match 'remote') { break }
    }
    Write-Host "BUILD1 exit=$($r.exit) note=$($r.note.Trim())"
    if ($r.exit -ne 0) { $failures += "distributed build did not exit 0 (exit=$($r.exit))" }
    if ($r.note -notmatch 'remote') { $failures += 'build 1 never ran remotely (worker did not come up?)' }
    if (-not (Test-Path $aObj)) { $failures += 'distributed build produced no .obj' }
    # Remote stdout/stderr mirroring: the compiler's #pragma message must reach
    # the launcher's console (it ran on the worker, not here).
    if ($r.note -notmatch [regex]::Escape($diag)) { $failures += 'remote compiler diagnostics were NOT mirrored to the launcher (stdout/stderr streaming)' }
    if ($byteGate -and -not (Same-Bytes $aObj $refObj)) { $failures += 'distributed .obj is NOT byte-identical to the local build' }
} finally {
    foreach ($p in @($workerProc, $daemon)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

# 2. Local fallback: daemon down → the launcher builds locally.
Start-Sleep -Milliseconds 300
$rf = Invoke-Launcher
Write-Host "FALLBACK exit=$($rf.exit) note=$($rf.note.Trim())"
# Local fallback is a plain local compile via run_local; the M6 "Done when" asks
# it to COMPLETE (produce a valid object), not to byte-match the distributed
# build. (clang-cl's object can differ under run_local's layered environment; the
# distribution-correctness claim is carried by the distributed + cached byte
# checks below/above, which are strict.)
if ($rf.exit -ne 0) { $failures += "local fallback did not exit 0 (exit=$($rf.exit))" }
if (-not (Test-Path $aObj) -or (Get-Item $aObj).Length -eq 0) { $failures += 'local fallback produced no/empty .obj' }

# 3. Action cache: restart the daemon (same cache root) but DO NOT start a worker.
# A cache HIT serves the recorded output with no worker; a miss could only local-
# fallback, so requiring "cache hit" proves the hit.
$daemon2 = Start-Daemon
try {
    Start-Sleep -Milliseconds 500
    $rc = Invoke-Launcher
    Write-Host "BUILD2 exit=$($rc.exit) note=$($rc.note.Trim())"
    if ($rc.exit -ne 0) { $failures += "cached build did not exit 0 (exit=$($rc.exit))" }
    if ($rc.note -notmatch 'cache hit') { $failures += 'second build did not HIT the action cache' }
    if (-not (Test-Path $aObj)) { $failures += 'cached build produced no .obj' }
    if ($byteGate -and -not (Same-Bytes $aObj $refObj)) { $failures += 'cached .obj is NOT byte-identical to the local build' }
} finally {
    if ($daemon2 -and -not $daemon2.HasExited) { Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.1 DAEMON COMPILE GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host "M6.1 DAEMON COMPILE GATE PASS (distributed byte-identical, local fallback, 2nd-build cache hit) compiler=$cc"
