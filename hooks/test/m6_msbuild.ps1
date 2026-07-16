# M6.2 gate: MSBuild / Visual Studio integration via a CLToolExe shim.
#
# MSBuild's CL task runs `<CLToolPath>\<CLToolExe> <CL-args>`. Pointing CLToolExe
# at the sembazuru launcher (with SEMBAZURU_SHIM_CC naming the real compiler) routes
# every compile through the agent daemon — the same production path CMake/Ninja use
# via CMAKE_<LANG>_COMPILER_LAUNCHER, but for projects MSBuild drives. A multi-TU
# (a/b/c.cpp) /Zi static library hard-asserts:
#   1. the objects are produced by a compile that ran through the daemon ("remote");
#   2. a second build with the daemon up but NO worker is a cache HIT that restores
#      every object AND the shared /Zi PDB (a separate bin\ subtree) — batched
#      response-file action caching, keyed on the right sources under one declared
#      input root (SEMBAZURU_INPUT_ROOT);
#   3. after a breaking edit to a.cpp the build FAILS — a stale object is never served
#      (the strong key covers the response-file source content; BLOCK-A);
#   4. with the daemon down, the build still completes (local fallback).
# Byte-identity remains the clang-cl gate's job elsewhere; the MSVC toolset here is
# byte-best-effort, so this gate asserts the caching mechanism and the stale-serve
# guarantee, not raw MSVC bytes. (Caching was a non-fatal DIAG before — now a hard
# gate; docs/deferred.md.)
#
# Requires MSBuild + cl + cargo on PATH (CI hooks job, after msvc-dev-cmd).
param(
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m6-msbuild-work')
)
$ErrorActionPreference = 'Stop'

$msbuild = (Get-Command msbuild -ErrorAction SilentlyContinue)
if (-not $msbuild) { throw 'msbuild not on PATH (run after msvc-dev-cmd / from a VS dev shell)' }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    & cargo build -q -p sembazuru-agent --bin sembazuru-daemon --bin sembazuru `
        -p sembazuru-worker --bin sembazuru-worker 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'bin build failed' }
} finally { Pop-Location }
$daemonExe = Join-Path $repo 'target\debug\sembazuru-daemon.exe'
$launcher = Join-Path $repo 'target\debug\sembazuru.exe'
$launcherDir = Join-Path $repo 'target\debug'
$workerExe = Join-Path $repo 'target\debug\sembazuru-worker.exe'

# The cmake-built injector for the worker's VFS execution.
$BuildDir = Join-Path $PSScriptRoot '..\build\Release'
$launcherC = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcherC, $dll)) { if (-not (Test-Path $f)) { throw "missing build artifact: $f" } }

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null
$daemonConfig = Join-Path $WorkRoot 'daemon-override.toml'
$workerConfig = Join-Path $WorkRoot 'worker-override.toml'

$proj = Join-Path $WorkRoot 'proj'
New-Item -ItemType Directory -Force $proj | Out-Null
Set-Content (Join-Path $proj 'shared.h') "#define SHARED_VALUE 42`n" -Encoding ascii
Set-Content (Join-Path $proj 'a.cpp') "#include `"shared.h`"`nint f(){ return SHARED_VALUE; }`n" -Encoding ascii
Set-Content (Join-Path $proj 'b.cpp') "#include `"shared.h`"`nint g(){ return SHARED_VALUE + 1; }`n" -Encoding ascii
Set-Content (Join-Path $proj 'c.cpp') "#include `"shared.h`"`nint h(){ return SHARED_VALUE + 2; }`n" -Encoding ascii

# Minimal C++ static-library project. The final PropertyGroup (after all imports,
# so it wins evaluation) redirects the CL task to the sembazuru launcher shim and
# pins the intermediate/output dirs so the gate can find the .obj. This same
# CLToolExe/CLToolPath pair is what a user drops into Directory.Build.targets
# (docs/integrations/msbuild/Directory.Build.targets).
$vcxproj = @"
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <ProjectGuid>{B5E9C0A1-1111-2222-3333-444455556666}</ProjectGuid>
    <RootNamespace>sbztest</RootNamespace>
  </PropertyGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Label="Configuration">
    <ConfigurationType>StaticLibrary</ConfigurationType>
    <PlatformToolset>v143</PlatformToolset>
  </PropertyGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ItemGroup>
    <ClCompile Include="a.cpp" />
    <ClCompile Include="b.cpp" />
    <ClCompile Include="c.cpp" />
  </ItemGroup>
  <Import Project="`$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <PropertyGroup>
    <IntDir>$proj\obj\</IntDir>
    <OutDir>$proj\bin\</OutDir>
    <CLToolPath>$launcherDir</CLToolPath>
    <CLToolExe>sembazuru.exe</CLToolExe>
  </PropertyGroup>
</Project>
"@
Set-Content (Join-Path $proj 'test.vcxproj') $vcxproj -Encoding utf8

$scratchRoot = Join-Path $WorkRoot 'wscratch'; $casRoot = Join-Path $WorkRoot 'wcas'
$cacheRoot = Join-Path $WorkRoot 'acache'; $traceRoot = Join-Path $WorkRoot 'atrace'
foreach ($d in @($scratchRoot, $casRoot, $cacheRoot, $traceRoot)) { New-Item -ItemType Directory -Force $d | Out-Null }
$coord = '127.0.0.1:50090'; $fs = '127.0.0.1:50092'; $worker = '127.0.0.1:50061'
$daemonUrl = 'npipe://Sembazuru.LocalIntake.v1'

function Start-Daemon {
    $hadConfig = Test-Path Env:\SEMBAZURU_CONFIG
    $oldConfig = $env:SEMBAZURU_CONFIG
    try {
        $env:SEMBAZURU_CONFIG = $daemonConfig
        $env:SEMBAZURU_COORD = $coord; $env:SEMBAZURU_INTAKE = $daemonUrl; $env:SEMBAZURU_FILESERVER = $fs
        $env:SEMBAZURU_CACHE_ROOT = $cacheRoot; $env:SEMBAZURU_TRACE_ROOT = $traceRoot
        $p = Start-Process -FilePath $daemonExe -PassThru -WindowStyle Hidden
    } finally {
        Remove-Item Env:\SEMBAZURU_COORD, Env:\SEMBAZURU_INTAKE, Env:\SEMBAZURU_FILESERVER, `
            Env:\SEMBAZURU_CACHE_ROOT, Env:\SEMBAZURU_TRACE_ROOT -ErrorAction SilentlyContinue
        if ($hadConfig) { $env:SEMBAZURU_CONFIG = $oldConfig }
        else { Remove-Item Env:\SEMBAZURU_CONFIG -ErrorAction SilentlyContinue }
    }
    $p
}
function Start-Worker {
    $hadConfig = Test-Path Env:\SEMBAZURU_WORKER_CONFIG
    $oldConfig = $env:SEMBAZURU_WORKER_CONFIG
    try {
        $env:SEMBAZURU_WORKER_CONFIG = $workerConfig
        $env:SEMBAZURU_AGENT = "http://$coord"; $env:SEMBAZURU_LAUNCHER = $launcherC; $env:SEMBAZURU_DLL = $dll
        $env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot; $env:SEMBAZURU_CAS_ROOT = $casRoot
        $p = Start-Process -FilePath $workerExe -ArgumentList @($worker) -PassThru -WindowStyle Hidden
    } finally {
        Remove-Item Env:\SEMBAZURU_AGENT, Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, `
            Env:\SEMBAZURU_SCRATCH_ROOT, Env:\SEMBAZURU_CAS_ROOT -ErrorAction SilentlyContinue
        if ($hadConfig) { $env:SEMBAZURU_WORKER_CONFIG = $oldConfig }
        else { Remove-Item Env:\SEMBAZURU_WORKER_CONFIG -ErrorAction SilentlyContinue }
    }
    $p
}
# The object set MSBuild produces in IntDir (one per source). MSBuild's CL task
# batches all sources into ONE cl invocation, so the shim sees a single multi-source
# action -> the daemon discovers the object set from the action trace (the /Fo
# heuristic only names one).
# The artifacts MSBuild produces: one object per source in IntDir (obj\) plus the
# shared /Zi PDB in OutDir (bin\) — a SEPARATE subtree. A correct cache HIT must
# restore EVERY one of these, proving the declared input root spans both obj\ and
# bin\ (the BLOCK-B fix: obj\ and bin\ relativize/publish under one root).
$objPaths = @('a.obj', 'b.obj', 'c.obj') | ForEach-Object { Join-Path $proj "obj\$_" }
$pdbPath = Join-Path $proj 'bin\test.pdb'
$outPaths = @($objPaths) + @($pdbPath)
function Clean-Outputs { foreach ($o in $outPaths) { if (Test-Path $o) { Remove-Item -Force $o } } }
function Outputs-Present { foreach ($o in $outPaths) { if (-not (Test-Path $o) -or (Get-Item $o).Length -eq 0) { return $false } } ; return $true }
# Run msbuild; the CL task invokes the sembazuru shim. Cleans every output first so a
# build actually recompiles (and so a cache-served build must RESTORE every output).
# SEMBAZURU_INPUT_ROOT = the project root spanning obj\, bin\, and the response file,
# so the action cache keys on the real sources and republishes obj\ + the PDB on a hit
# (the production-recommended MSBuild config, docs/integrations/msbuild).
function Invoke-MSBuild {
    param([switch]$NoInputRoot)
    Clean-Outputs
    $env:SEMBAZURU_SHIM_CC = 'cl'      # the real compiler the shim prepends
    $env:SEMBAZURU_DAEMON = $daemonUrl
    if (-not $NoInputRoot) { $env:SEMBAZURU_INPUT_ROOT = $proj }
    $out = & msbuild (Join-Path $proj 'test.vcxproj') /nologo /v:minimal /t:Build `
        /p:Configuration=Release /p:Platform=x64 2>&1 | Out-String
    $code = $LASTEXITCODE
    Remove-Item Env:\SEMBAZURU_SHIM_CC, Env:\SEMBAZURU_DAEMON, Env:\SEMBAZURU_INPUT_ROOT -ErrorAction SilentlyContinue
    return @{ exit = $code; out = $out }
}

$failures = @()

# 1. Distributed multi-TU build through the shim (worker up).
$daemon = Start-Daemon
$workerProc = Start-Worker
try {
    $r = $null
    $remoteSeen = $false
    $cachePopulated = $false
    $outputsMissing = $false
    $attempts = 0
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 400
        $r = Invoke-MSBuild
        $attempts = $i + 1
        $remoteThisAttempt = [bool]($r.out -match 'sembazuru: remote')
        $cacheHitThisAttempt = [bool]($r.out -match 'sembazuru: cache hit')
        $outputsPresent = Outputs-Present
        $remoteSeenBeforeAttempt = $remoteSeen
        if ($remoteThisAttempt) { $remoteSeen = $true }
        if ($remoteSeenBeforeAttempt -and $cacheHitThisAttempt) { $cachePopulated = $true }
        if (-not $outputsPresent) { $outputsMissing = $true }
        Write-Host "MSBUILD1 attempt=$attempts exit=$($r.exit) remote=$remoteThisAttempt remote-seen=$remoteSeen cache-hit=$cacheHitThisAttempt cache-populated=$cachePopulated outputs=$outputsPresent"
        if ($r.exit -ne 0 -or $cachePopulated) { break }
    }
    Write-Host "MSBUILD1 result attempts=$attempts exit=$($r.exit) remote-seen=$remoteSeen cache-populated=$cachePopulated outputs-missing=$outputsMissing"
    if ($r.exit -ne 0) { $failures += "msbuild via shim did not succeed (exit=$($r.exit))`n$($r.out)" }
    if (-not $remoteSeen) { $failures += 'compile did not run through the daemon (no "remote" note in 40 attempts)' }
    if (-not $cachePopulated) { $failures += 'phase 1 did not observe an action-cache HIT after remote execution in 40 attempts' }
    if ($outputsMissing) { $failures += 'msbuild produced missing/empty outputs during phase 1 population' }
} finally {
    foreach ($p in @($workerProc, $daemon)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

# 2. Action cache — HARD assert (was DIAG). Restart the daemon (same cache root) with
# NO worker, then clean every output. A correct HIT must serve the recorded objects
# AND the shared /Zi PDB (a separate bin\ subtree) with no worker running — proving the
# batched response-file action now caches and the declared input root spans obj\+bin\.
# (Previously a KNOWN LIMITATION; fixed — docs/deferred.md.)
$daemon2 = Start-Daemon
try {
    Start-Sleep -Milliseconds 600
    $rc = Invoke-MSBuild
    $cacheHit = [bool]($rc.out -match 'sembazuru: cache hit')
    Write-Host "MSBUILD2 exit=$($rc.exit) cache-hit=$cacheHit outputs=$(Outputs-Present)"
    if ($rc.exit -ne 0) { $failures += "cached msbuild did not succeed (exit=$($rc.exit))`n$($rc.out)" }
    if (-not $cacheHit) { $failures += "no action-cache HIT through the MSBuild shim (worker down)`n$($rc.out)" }
    if (-not (Outputs-Present)) { $failures += 'cache HIT did not restore every output (objects + /Zi PDB)' }
    if ($cacheHit -and (Outputs-Present)) {
        Write-Host 'MSBUILD CACHE: action cache HIT restored all objects + the shared PDB with no worker (batched-action caching works)'
    }
} finally {
    if ($daemon2 -and -not $daemon2.HasExited) { Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue }
}

# 3. Stale-serve guard — HARD assert (the BLOCK-A correctness gate). Break a.cpp, then
# rebuild against the SAME populated cache with NO worker. The edit changes a.cpp's
# content but not the response-file name, so a buggy strong key (one that dropped the
# bare-relative source) would still HIT and serve the stale, good object — and the build
# would SUCCEED. A correct strong key re-hashes a.cpp, MISSES, and local-falls-back to a
# real compile of the now-broken source, which FAILS. So: after a breaking edit the build
# MUST fail. A success here means a stale object was served (the bug we are gating).
$daemon3 = Start-Daemon
try {
    Start-Sleep -Milliseconds 600
    # 3a. Break a SOURCE (a.cpp). A correct strong key re-hashes it and MISSES.
    $goodA = Get-Content (Join-Path $proj 'a.cpp') -Raw
    Set-Content (Join-Path $proj 'a.cpp') "#include `"shared.h`"`nint f(){ return SHARED_VALUE  /* unterminated" -Encoding ascii
    $rs = Invoke-MSBuild
    Set-Content (Join-Path $proj 'a.cpp') $goodA -Encoding ascii   # restore
    $staleSrc = ($rs.exit -eq 0)
    Write-Host "MSBUILD3-EDIT-SRC exit=$($rs.exit) served-stale=$staleSrc"
    if ($staleSrc) {
        $failures += 'STALE SERVE (source): a broken a.cpp still built successfully — the cache served a stale object (strong key did not cover the edited source)'
    }
    # 3b. Break a HEADER (shared.h), included by every TU. A VFS-supplied header
    # must also be in the strong key (the hook records redirected reads), so this
    # too must MISS and fail the compile — not serve stale objects.
    $goodH = Get-Content (Join-Path $proj 'shared.h') -Raw
    Set-Content (Join-Path $proj 'shared.h') "#define SHARED_VALUE 42 +`n#error broken-header" -Encoding ascii
    $rh = Invoke-MSBuild
    Set-Content (Join-Path $proj 'shared.h') $goodH -Encoding ascii   # restore
    $staleHdr = ($rh.exit -eq 0)
    Write-Host "MSBUILD3-EDIT-HDR exit=$($rh.exit) served-stale=$staleHdr"
    if ($staleHdr) {
        $failures += 'STALE SERVE (header): a broken shared.h still built successfully — the cache served stale objects (strong key did not cover the VFS-supplied header)'
    }
} finally {
    if ($daemon3 -and -not $daemon3.HasExited) { Stop-Process -Id $daemon3.Id -Force -ErrorAction SilentlyContinue }
}

# 4. Local fallback: daemon down -> msbuild still builds via the shim's local exec.
Start-Sleep -Milliseconds 300
$rf = Invoke-MSBuild
Write-Host "MSBUILD-FALLBACK exit=$($rf.exit) fallback=$([bool]($rf.out -match 'running locally'))"
if ($rf.exit -ne 0) { $failures += "msbuild fallback did not succeed (exit=$($rf.exit))`n$($rf.out)" }
if ($rf.out -notmatch 'running locally') { $failures += 'fallback did not run locally (no "running locally" note)' }
if (-not (Outputs-Present)) { $failures += 'fallback produced missing/empty outputs' }

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.2 MSBUILD GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'M6.2 MSBUILD GATE PASS (multi-TU /Zi MSBuild CL task routed through the daemon via the CLToolExe shim; action cache HIT restores all objects + the shared PDB with no worker; a breaking edit is never served stale; local fallback works)'
