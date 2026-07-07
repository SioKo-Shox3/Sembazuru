# M1 tracer smoke + acceptance harness.
#
# Proves the M1 "Done when" (docs/DESIGN.md §7): for a compiler invocation we
# can obtain a complete, reproducible dependency graph of its input and output
# files. Gates, in order:
#
#   1. Completeness  - every header cl.exe reports via /showIncludes appears in
#                      the trace's input set (the cross-check that justifies
#                      hooking only the Win32 layer in M1, not the NT layer).
#   2. Propagation   - a compile+link run produces a trace for cl.exe AND its
#                      link.exe child, with no injection-gap warnings.
#   3. Reproducibility - two runs of the same source yield identical normalized
#                      input/output sets after dropping compiler-internal temp
#                      files whose names are randomized by MSVC/link.
#   4. clang-cl      - if present, its source file is captured too (clang-cl is
#                      a first-class target per CLAUDE.md).
#
# Requires cl.exe on PATH (run from a VS dev shell or after msvc-dev-cmd in CI).
param(
    [string]$BuildDir  = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$TracerExe = (Join-Path $PSScriptRoot '..\..\target\release\sembazuru-trace.exe'),
    # Work area must NOT be under %TEMP%: the reader tags temp paths as
    # intermediates, which would hide real build artifacts in this test.
    [string]$WorkRoot  = (Join-Path $PSScriptRoot '..\build\smoke-work'),
    # CI sets this (the runner ships LLVM on PATH): turn the clang-cl gate from
    # a soft skip into a hard failure so clang-cl staying first-class
    # (CLAUDE.md) is actually enforced, not assumed.
    [switch]$RequireClangCl
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$dll      = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcher, $dll, $TracerExe)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}

if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# A source that pulls in both a system header (absolute paths, exercises the
# include search) and a local quoted header (relative resolution).
$mainC = @'
#include <stdio.h>
#include "dep.h"
int main(void) { return VALUE; }
'@
$depH = "#define VALUE 0`r`n"

# Runs the compiler under the interceptor; returns the directory that holds
# the .sbzt trace files. Captures compiler stdout+stderr into
# $script:LastOutput. `SrcName` selects the source directory so reproducibility
# runs can share one directory: compilers resolve includes/outputs to absolute
# paths, so two *different* directories legitimately differ — the honest
# reproducibility test reuses one source tree and varies only the trace output.
function Invoke-Traced {
    param([string]$Name, [string[]]$CompilerCmd, [string]$SrcName = $Name)

    $src = Join-Path $WorkRoot $SrcName
    $traceDir = Join-Path $WorkRoot "$Name-trace"
    New-Item -ItemType Directory -Force $src | Out-Null
    New-Item -ItemType Directory -Force $traceDir | Out-Null
    Set-Content (Join-Path $src 'main.c') $mainC -Encoding ascii
    Set-Content (Join-Path $src 'dep.h')  $depH  -Encoding ascii

    $env:SEMBAZURU_TRACE_DIR = $traceDir
    Push-Location $src
    try {
        $script:LastOutput = & $launcher $dll @CompilerCmd 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host $script:LastOutput
            throw "${Name}: compiler exited $LASTEXITCODE"
        }
    } finally {
        Pop-Location
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue
    }
    return $traceDir
}

function Export-Graph {
    param([string]$TraceDir)
    $json = & $TracerExe export --trace-dir $TraceDir --json
    if ($LASTEXITCODE -ne 0) { throw "tracer export failed for $TraceDir" }
    return $json | ConvertFrom-Json
}

function Is-Volatile-MsvcTempPath {
    param([string]$Path)
    $lower = $Path.ToLowerInvariant()
    if ($lower -notlike '*\appdata\local\temp\*') { return $false }

    $leaf = [IO.Path]::GetFileName($lower)
    return ($leaf -match '^_cl_[0-9a-f]+lk$') -or
        ($leaf -match '^lnk\{[0-9a-f-]+\}\.tmp$')
}

function Stable-PathSet {
    param($Items)
    return @(
        $Items |
            ForEach-Object { $_.path.ToLowerInvariant() } |
            Where-Object { -not (Is-Volatile-MsvcTempPath $_) } |
            Sort-Object -Unique
    )
}

function Compare-PathSets {
    param([string[]]$A, [string[]]$B)
    $setA = @{}
    foreach ($p in $A) { $setA[$p] = $true }
    $setB = @{}
    foreach ($p in $B) { $setB[$p] = $true }

    $missing = @($A | Where-Object { -not $setB.ContainsKey($_) })
    $added = @($B | Where-Object { -not $setA.ContainsKey($_) })
    return [pscustomobject]@{ Missing = $missing; Added = $added }
}

$failures = @()

# --- Gate 1 + 2: completeness and child propagation -------------------------
# Compile AND link with /showIncludes so one run exercises both the include
# search (gate 1) and the link.exe child (gate 2).
$traceMsvc = Invoke-Traced 'msvc' @('cl', '/nologo', '/showIncludes', 'main.c')

# Headers cl reported via /showIncludes. The "Note: including file:" prefix is
# localized (e.g. Japanese "メモ: インクルード ファイル:"), so key on the path
# shape at the end of the line, not the prefix text: each line ends with an
# absolute drive or UNC path. Lines without one (the echoed source name,
# blank lines) are skipped.
$reported = @()
foreach ($line in ($script:LastOutput -split "`r?`n")) {
    if ($line -match '((?:[A-Za-z]:\\|\\\\)[^\r\n]+?)\s*$') {
        $reported += $Matches[1].ToLowerInvariant()
    }
}
if ($reported.Count -eq 0) {
    $failures += 'completeness: cl reported no /showIncludes headers (parser or locale mismatch)'
}

$graphMsvc = Export-Graph $traceMsvc
$inputSet = @{}
foreach ($p in $graphMsvc.inputs) { $inputSet[$p.path.ToLowerInvariant()] = $true }

$missing = @()
foreach ($h in ($reported | Select-Object -Unique)) {
    if (-not $inputSet.ContainsKey($h)) { $missing += $h }
}
$uniqueReported = ($reported | Select-Object -Unique).Count
if ($missing.Count -gt 0) {
    $failures += "completeness: $($missing.Count) /showIncludes header(s) absent from trace inputs"
    Write-Host '--- headers missing from trace inputs (first 10) ---'
    $missing | Select-Object -First 10 | ForEach-Object { Write-Host "  $_" }
} else {
    Write-Host "GATE 1 PASS  completeness: all $uniqueReported /showIncludes headers present in trace inputs"
}

# Child propagation: cl + its link child each produced a trace; no gaps.
$pidCount = (Get-ChildItem $traceMsvc -Filter *.sbzt).Count
$gapWarnings = @($graphMsvc.warnings | Where-Object { $_ -like '*no trace file*' })
$exeNames = @($graphMsvc.processes | ForEach-Object { (Split-Path $_.exe -Leaf).ToLower() })
if ($pidCount -lt 2) {
    $failures += "propagation: expected >=2 trace files (cl + link), got $pidCount"
} elseif ($gapWarnings.Count -gt 0) {
    $failures += "propagation: injection-gap warning(s): $($gapWarnings -join '; ')"
} elseif (-not ($exeNames -contains 'link.exe')) {
    $failures += "propagation: no link.exe in process tree (exes: $($exeNames -join ', '))"
} else {
    Write-Host "GATE 2 PASS  propagation: $pidCount processes traced incl. link.exe, no injection gaps"
}

# main.c must be an input; an output binary must be produced. The reader now
# resolves the relative source ('main.c') against the trace's recorded cwd, so
# it appears as an absolute path -- match on the suffix, not the bare name.
if (-not (@($graphMsvc.inputs.path | Where-Object { $_ -like '*main.c' }).Count -gt 0)) {
    $failures += 'graph: main.c not in inputs'
}
$hasExe = @($graphMsvc.outputs.path | Where-Object { $_ -like '*.exe' }).Count -gt 0
if (-not $hasExe) {
    $failures += 'graph: no .exe in outputs'
}

# --- Gate 3: reproducibility ------------------------------------------------
$traceA = Invoke-Traced 'reproA' @('cl', '/nologo', 'main.c') -SrcName 'repro'
$traceB = Invoke-Traced 'reproB' @('cl', '/nologo', 'main.c') -SrcName 'repro'
$graphA = Export-Graph $traceA
$graphB = Export-Graph $traceB
$inputDiff = Compare-PathSets (Stable-PathSet $graphA.inputs) (Stable-PathSet $graphB.inputs)
$outputDiff = Compare-PathSets (Stable-PathSet $graphA.outputs) (Stable-PathSet $graphB.outputs)
if ($inputDiff.Missing.Count -gt 0 -or $inputDiff.Added.Count -gt 0 -or
    $outputDiff.Missing.Count -gt 0 -or $outputDiff.Added.Count -gt 0) {
    $failures += 'reproducibility: input/output sets differ between two identical runs'
    Write-Host '--- diff output ---'
    $inputDiff.Missing | ForEach-Object { Write-Host "input  - $_" }
    $inputDiff.Added | ForEach-Object { Write-Host "input  + $_" }
    $outputDiff.Missing | ForEach-Object { Write-Host "output - $_" }
    $outputDiff.Added | ForEach-Object { Write-Host "output + $_" }
} else {
    Write-Host 'GATE 3 PASS  reproducibility: two runs produced identical input/output sets'
}

# --- Gate 4: clang-cl (first-class target) ----------------------------------
$clang = Get-Command clang-cl -ErrorAction SilentlyContinue
if ($null -eq $clang) {
    if ($RequireClangCl) {
        $failures += 'clang-cl: required (-RequireClangCl) but not found on PATH'
    } else {
        Write-Host 'GATE 4 SKIP  clang-cl not on PATH'
    }
} else {
    $traceClang = Invoke-Traced 'clang' @('clang-cl', '/nologo', '/c', 'main.c')
    $graphClang = Export-Graph $traceClang
    if (-not (@($graphClang.inputs.path | Where-Object { $_ -like '*main.c' }).Count -gt 0)) {
        $failures += 'clang-cl: main.c not captured in inputs'
    } else {
        $depSeen = @($graphClang.inputs.path | Where-Object { $_ -like '*dep.h' }).Count -gt 0
        Write-Host "GATE 4 PASS  clang-cl: main.c captured (dep.h seen: $depSeen)"
    }
}

# --- Verdict ----------------------------------------------------------------
if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'SMOKE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host ''
Write-Host 'SMOKE PASS (M1 tracer: completeness + propagation + reproducibility verified)'
