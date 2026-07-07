# M4 "Done when" gate: the second build of an unchanged project skips
# compilation (the action cache hits) and reproduces the first build's output.
#
# DESIGN.md M4 Done-when: "the second build of the same project transfers ~no
# files and runs ~no compiles." This gate proves the *compile-execution* half
# end to end with a real compiler:
#
#   1. Trace-compile a tiny project (launcher + interceptor record the input /
#      output sets) -> a.obj (snapshot it as "build 1").
#   2. `cache_cli record` keys the action (argv + env + toolchain) to the
#      observed input manifest and ingests a.obj into the CAS.
#   3. Delete a.obj and `cache_cli resolve`: it must report HIT (so the compile
#      is SKIPPED) and republish a.obj from the CAS, byte-identical to build 1.
#   4. A fresh rebuild in the same root reproduces build 1 (content
#      determinism), so the cached output equals what a real rebuild produces.
#   5. Change the source: resolve must now MISS (correct invalidation), so a
#      changed input is never served a stale result.
#
# The *transfer* half (worker-local cache => ~zero bytes on rebuild) is proven
# by the Rust integration test
# `worker_cache_eliminates_retransfer_on_second_build` (agent/tests/vfs_pipe.rs)
# via the agent's ServerStats; this gate focuses on compile-execution = 0.
#
# Requires cl.exe + cargo on PATH; clang-cl is exercised when present.
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m4-cache-work'),
    [switch]$RequireClangCl
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$dll      = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcher, $dll)) { if (-not (Test-Path $f)) { throw "missing build artifact: $f" } }
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) { throw 'cl.exe not on PATH' }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    & cargo build -p sembazuru-agent --example cache_cli 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'cache_cli build failed' }
} finally { Pop-Location }
$cli = Join-Path $repo 'target\debug\examples\cache_cli.exe'
$traceCli = Join-Path $repo 'target\release\sembazuru-trace.exe'

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

$src = @'
#include "k.h"
int main() { return K; }
'@
$hdr = "#pragma once`r`n#define K 7"

# Trace-compiles a.cpp -> a.obj under the interceptor, writing traces to $TraceDir.
function Trace-Compile {
    param([string]$Root, [string]$TraceDir, [string]$Cc, [string[]]$Flags)
    New-Item -ItemType Directory -Force $Root, $TraceDir | Out-Null
    if (-not (Test-Path (Join-Path $Root 'k.h')))   { Set-Content (Join-Path $Root 'k.h') $hdr -Encoding ascii }
    if (-not (Test-Path (Join-Path $Root 'a.cpp'))) { Set-Content (Join-Path $Root 'a.cpp') $src -Encoding ascii }
    Get-ChildItem $TraceDir -Filter *.sbzt -ErrorAction SilentlyContinue | Remove-Item -Force
    $env:SEMBAZURU_TRACE_DIR = $TraceDir
    Push-Location $Root
    try {
        & $launcher $dll $Cc '/nologo' '/c' @Flags 'a.cpp' '/Foa.obj' 2>&1 | Out-String | Write-Host
        if ($LASTEXITCODE -ne 0) { throw "$Cc compile exited $LASTEXITCODE" }
    } finally {
        Pop-Location
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue
    }
    if (-not (Test-Path (Join-Path $Root 'a.obj'))) { throw "$Cc produced no a.obj" }
}

function Bytes-Equal {
    param([string]$P, [string]$Q)
    [System.Linq.Enumerable]::SequenceEqual(
        [System.IO.File]::ReadAllBytes($P), [System.IO.File]::ReadAllBytes($Q))
}

function Write-TraceSideEffectSummary {
    param([string]$TraceDir)

    if (-not (Test-Path $traceCli)) {
        Write-Host "trace side-effect diagnostic unavailable: missing $traceCli"
        return
    }

    try {
        $json = & $traceCli export --trace-dir $TraceDir --json 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host "trace side-effect diagnostic export failed:"
            Write-Host $json
            return
        }
        $graph = $json | ConvertFrom-Json
    } catch {
        Write-Host "trace side-effect diagnostic failed: $_"
        return
    }

    Write-Host '--- trace side-effect diagnostic ---'
    if ($graph.warnings.Count -gt 0) {
        Write-Host 'warnings:'
        $graph.warnings | ForEach-Object { Write-Host "  $_" }
    }
    if ($graph.registry.Count -gt 0) {
        Write-Host "registry reads: $($graph.registry.Count)"
        $graph.registry | Select-Object -First 40 | ForEach-Object {
            Write-Host "  $($_.key) :: $($_.value)"
        }
    }
    $envBlock = @($graph.env | Where-Object { $_.name -eq '<environment-block>' })
    if ($envBlock.Count -gt 0) {
        Write-Host "whole environment block reads: $($envBlock.Count)"
    }
    $enumerated = @($graph.inputs | Where-Object { $_.kinds -contains 'enumerate' })
    if ($enumerated.Count -gt 0) {
        Write-Host "directory enumerations: $($enumerated.Count)"
        $enumerated | Select-Object -First 40 | ForEach-Object {
            Write-Host "  $($_.path)"
        }
    }
    Write-Host '--- end trace side-effect diagnostic ---'
}

# Runs the full record -> hit -> rebuild -> miss cycle for one compiler.
# Returns $null on pass, or a failure message.
function Invoke-CacheGate {
    param([string]$Name, [string]$Cc, [string[]]$Flags)
    $root  = Join-Path $WorkRoot $Name
    $trace = Join-Path $WorkRoot "$Name-trace"
    $cache = Join-Path $WorkRoot "$Name-cache"
    # The action's logical command (must be identical for record and resolve).
    $argv = @($Cc, '/nologo', '/c') + $Flags + @('a.cpp', '/Foa.obj')

    # 1. Build 1 (traced) + snapshot.
    Trace-Compile -Root $root -TraceDir $trace -Cc $Cc -Flags $Flags
    $obj1 = Join-Path $WorkRoot "$Name-obj1.bin"
    Copy-Item (Join-Path $root 'a.obj') $obj1 -Force

    # 2. Record the action.
    & $cli record --cache $cache --trace-dir $trace --build-root $root --output a.obj -- @argv | Out-Host
    if ($LASTEXITCODE -ne 0) { return "${Cc}: record failed" }

    # 3. Second build: delete the output, resolve -> must HIT and republish.
    Remove-Item (Join-Path $root 'a.obj') -Force
    $r = (& $cli resolve --cache $cache --build-root $root -- @argv | Out-String).Trim()
    Write-Host "resolve(unchanged) -> $r"
    if ($LASTEXITCODE -ne 0 -or -not ($r -match '^HIT')) {
        Write-TraceSideEffectSummary -TraceDir $trace
        return "${Cc}: second build was not a cache hit (got '$r', exit $LASTEXITCODE)"
    }
    if (-not (Test-Path (Join-Path $root 'a.obj'))) { return "${Cc}: hit did not republish a.obj" }
    if (-not (Bytes-Equal (Join-Path $root 'a.obj') $obj1)) {
        return "${Cc}: cached output is not byte-identical to build 1"
    }

    # 4. A fresh rebuild in the same root reproduces build 1 (content
    #    determinism), so the cached output equals a real rebuild.
    Trace-Compile -Root $root -TraceDir $trace -Cc $Cc -Flags $Flags
    if (-not (Bytes-Equal (Join-Path $root 'a.obj') $obj1)) {
        return "${Cc}: rebuild differs from build 1 (cannot claim cached==rebuilt)"
    }

    # 5. Change the source: resolve must MISS (correct invalidation).
    Set-Content (Join-Path $root 'a.cpp') ($src + "`r`nint extra() { return 1; }") -Encoding ascii
    $m = (& $cli resolve --cache $cache --build-root $root -- @argv | Out-String).Trim()
    Write-Host "resolve(changed)   -> $m"
    if ($LASTEXITCODE -eq 0 -or -not ($m -match 'MISS')) {
        return "${Cc}: a changed input must MISS, got '$m' (exit $LASTEXITCODE)"
    }

    return $null
}

$failures = @()

Write-Host '=== MSVC cl: action-cache rebuild ==='
$msvc = Invoke-CacheGate -Name 'msvc' -Cc 'cl' -Flags @('/Brepro')
if ($msvc) { $failures += $msvc } else { Write-Host 'GATE PASS  cl: 2nd build hit (compile skipped), output reproduced, change invalidates' }

$clang = Get-Command clang-cl -ErrorAction SilentlyContinue
if ($null -eq $clang) {
    if ($RequireClangCl) { $failures += 'clang-cl: required (-RequireClangCl) but not found on PATH' }
    else { Write-Host 'GATE SKIP  clang-cl not on PATH' }
} else {
    Write-Host '=== clang-cl: action-cache rebuild ==='
    $env:SOURCE_DATE_EPOCH = '0'
    try {
        $cf = Invoke-CacheGate -Name 'clang' -Cc 'clang-cl' -Flags @('/Brepro')
    } finally {
        Remove-Item Env:\SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue
    }
    if ($cf) { $failures += $cf } else { Write-Host 'GATE PASS  clang-cl: 2nd build hit (compile skipped), output reproduced, change invalidates' }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M4 CACHE REBUILD GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host ''
Write-Host 'M4 CACHE REBUILD GATE PASS (2nd build skips compilation via the action cache)'
