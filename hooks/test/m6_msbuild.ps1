# M6.2 gate: MSBuild / Visual Studio integration via a CLToolExe shim.
#
# MSBuild's CL task runs `<CLToolPath>\<CLToolExe> <CL-args>`. Pointing CLToolExe
# at the sembazuru launcher (with SEMBAZURU_SHIM_CC naming the real compiler) routes
# every compile through the agent daemon — the same production path CMake/Ninja use
# via CMAKE_<LANG>_COMPILER_LAUNCHER, but for projects MSBuild drives. A multi-TU
# (a/b/c.cpp) static library asserts:
#   1. the objects are produced by a compile that ran through the daemon ("remote");
#   2. with the daemon down, the build still completes (local fallback).
# Action caching across the MSBuild shim is reported as a non-fatal DIAG: MSBuild
# batches all sources into one CL invocation (often via a response file), which the
# launcher's per-file /Fo inference + argv key do not cache the way the CMake/Ninja
# per-file path does (KNOWN LIMITATION, docs/deferred.md). Byte-identity is the
# clang-cl gate elsewhere; the MSVC toolset here is byte-best-effort, so this gate
# checks the mechanism, not the bytes.
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
$coord = '127.0.0.1:50090'; $intake = '127.0.0.1:50091'; $fs = '127.0.0.1:50092'; $worker = '127.0.0.1:50061'

function Start-Daemon {
    $env:SEMBAZURU_COORD = $coord; $env:SEMBAZURU_INTAKE = $intake; $env:SEMBAZURU_FILESERVER = $fs
    $env:SEMBAZURU_CACHE_ROOT = $cacheRoot; $env:SEMBAZURU_TRACE_ROOT = $traceRoot
    $p = Start-Process -FilePath $daemonExe -PassThru -WindowStyle Hidden
    Remove-Item Env:\SEMBAZURU_COORD, Env:\SEMBAZURU_INTAKE, Env:\SEMBAZURU_FILESERVER, `
        Env:\SEMBAZURU_CACHE_ROOT, Env:\SEMBAZURU_TRACE_ROOT -ErrorAction SilentlyContinue
    $p
}
function Start-Worker {
    $env:SEMBAZURU_AGENT = "http://$coord"; $env:SEMBAZURU_LAUNCHER = $launcherC; $env:SEMBAZURU_DLL = $dll
    $env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot; $env:SEMBAZURU_CAS_ROOT = $casRoot
    $p = Start-Process -FilePath $workerExe -ArgumentList @($worker) -PassThru -WindowStyle Hidden
    Remove-Item Env:\SEMBAZURU_AGENT, Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, `
        Env:\SEMBAZURU_SCRATCH_ROOT, Env:\SEMBAZURU_CAS_ROOT -ErrorAction SilentlyContinue
    $p
}
# The object set MSBuild produces in IntDir (one per source). MSBuild's CL task
# batches all sources into ONE cl invocation, so the shim sees a single multi-source
# action -> the daemon discovers the object set from the action trace (the /Fo
# heuristic only names one).
$objPaths = @('a.obj', 'b.obj', 'c.obj') | ForEach-Object { Join-Path $proj "obj\$_" }
function Clean-Objs { foreach ($o in $objPaths) { if (Test-Path $o) { Remove-Item -Force $o } } }
function Objs-Present { foreach ($o in $objPaths) { if (-not (Test-Path $o) -or (Get-Item $o).Length -eq 0) { return $false } } ; return $true }
# Run msbuild; the CL task invokes the sembazuru shim. Cleans the objects first so a
# build actually recompiles (and so a cache-served build must restore every object).
function Invoke-MSBuild {
    Clean-Objs
    $env:SEMBAZURU_SHIM_CC = 'cl'      # the real compiler the shim prepends
    $env:SEMBAZURU_DAEMON = "http://$intake"
    $out = & msbuild (Join-Path $proj 'test.vcxproj') /nologo /v:minimal /t:Build `
        /p:Configuration=Release /p:Platform=x64 2>&1 | Out-String
    $code = $LASTEXITCODE
    Remove-Item Env:\SEMBAZURU_SHIM_CC, Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue
    return @{ exit = $code; out = $out }
}

$failures = @()

# 1. Distributed multi-TU build through the shim (worker up).
$daemon = Start-Daemon
$workerProc = Start-Worker
try {
    $r = $null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 400
        $r = Invoke-MSBuild
        if ($r.out -match 'sembazuru: remote') { break }
    }
    Write-Host "MSBUILD1 exit=$($r.exit) remote=$([bool]($r.out -match 'sembazuru: remote'))"
    if ($r.exit -ne 0) { $failures += "msbuild via shim did not succeed (exit=$($r.exit))`n$($r.out)" }
    if ($r.out -notmatch 'sembazuru: remote') { $failures += 'compile did not run through the daemon (no "remote" note)' }
    if (-not (Objs-Present)) { $failures += 'msbuild produced missing/empty objects via the shim' }
} finally {
    foreach ($p in @($workerProc, $daemon)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

# 2. Action cache — DIAGNOSTIC (non-fatal). Restart the daemon (same cache root) with
# NO worker; a cache HIT would serve the recorded objects without a worker. MSBuild's
# CL task batches all sources into ONE compiler invocation (commonly via a response
# file), so the shim sees a single multi-source action. The launcher's /Fo output
# inference names only one object and the argv-based key is not stable across the
# batched/response-file form, so the action does not cache the way the per-file
# CMake/Ninja path does (which hits reliably — see m6_ninja.ps1). This is a KNOWN
# LIMITATION (docs/deferred.md), reported here; the build still completes (a miss just
# local-falls-back with the worker stopped). The build must still produce every object.
$daemon2 = Start-Daemon
try {
    Start-Sleep -Milliseconds 600
    $rc = Invoke-MSBuild
    $cacheHit = [bool]($rc.out -match 'sembazuru: cache hit')
    Write-Host "MSBUILD2 exit=$($rc.exit) cache-hit=$cacheHit"
    if ($rc.exit -ne 0) { $failures += "cached msbuild did not succeed (exit=$($rc.exit))`n$($rc.out)" }
    if (-not (Objs-Present)) { $failures += 'second build did not produce every object' }
    if ($cacheHit) {
        Write-Host 'MSBUILD CACHE: action cache HIT through the MSBuild shim (batched-action caching now works)'
    } else {
        Write-Host 'MSBUILD CACHE DIAG (non-fatal): no cache hit through the MSBuild shim — batched multi-source / response-file actions are not cached like the per-file CMake/Ninja path (KNOWN LIMITATION, docs/deferred.md)'
    }
} finally {
    if ($daemon2 -and -not $daemon2.HasExited) { Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue }
}

# 3. Local fallback: daemon down -> msbuild still builds via the shim's local exec.
Start-Sleep -Milliseconds 300
$rf = Invoke-MSBuild
Write-Host "MSBUILD-FALLBACK exit=$($rf.exit) fallback=$([bool]($rf.out -match 'running locally'))"
if ($rf.exit -ne 0) { $failures += "msbuild fallback did not succeed (exit=$($rf.exit))`n$($rf.out)" }
if ($rf.out -notmatch 'running locally') { $failures += 'fallback did not run locally (no "running locally" note)' }
if (-not (Objs-Present)) { $failures += 'fallback produced missing/empty objects' }

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.2 MSBUILD GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'M6.2 MSBUILD GATE PASS (multi-TU MSBuild CL task routed through the daemon via the CLToolExe shim; local fallback works; action caching reported as DIAG)'
