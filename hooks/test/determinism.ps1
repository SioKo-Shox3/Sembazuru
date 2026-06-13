# M2 determinism harness.
#
# Proves the M2 "Done when" (docs/DESIGN.md §7): for a representative set of C++
# translation units, the same logical input reproduces the same output *bytes*.
# Where M1's smoke.ps1 checks that two runs agree on the input/output path
# *sets*, this checks the output *contents*.
#
# Method: compile the corpus in TWO different work roots (so absolute paths
# differ between runs) with the recommended deterministic flags, then hand the
# two trace dirs + work roots to `sembazuru-trace verify-determinism`, which
# compares each surviving output byte-for-byte and, on a difference, masks the
# documented non-deterministic regions (timestamps, PE Rich header) before
# comparing again. An *unexplained* difference fails the gate. See
# docs/determinism.md for the flag rationale and primary sources.
#
# Scope: .obj (COFF) byte determinism is the primary target (M3's "Done when"
# is a byte-identical .obj). clang-cl is exercised when present (first-class
# target per CLAUDE.md). PDB is out of scope (documented in docs/determinism.md).
#
# Requires cl.exe on PATH (a VS dev shell or msvc-dev-cmd in CI).
param(
    [string]$BuildDir  = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$TracerExe = (Join-Path $PSScriptRoot '..\..\target\release\sembazuru-trace.exe'),
    # Work area must NOT be under %TEMP%: the reader tags temp paths as
    # intermediates and would drop the very outputs we compare.
    [string]$WorkRoot  = (Join-Path $PSScriptRoot '..\build\determinism-work'),
    # CI sets this (the runner ships LLVM): turn the clang-cl path from a soft
    # skip into a hard failure so clang-cl stays first-class (CLAUDE.md).
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

# --- Corpus -----------------------------------------------------------------
# Chosen to surface the classic non-determinism sources documented in
# docs/determinism.md: a time macro (__DATE__/__TIME__), a header dependency,
# and a template instantiation (multiple TUs, COMDAT folding candidates).
$sharedH = @'
#pragma once
template <typename T>
struct Box {
    T value;
    T twice() const { return value + value; }
};
int shared_constant();
'@

$aCpp = @'
#include <cstdio>
#include "shared.h"
// A time macro: without deterministic flags this bakes the build time into
// the object's string data. The harness proves the recommended flags (or, as
// a fallback, byte normalization) neutralize it.
const char* build_stamp() { return __DATE__ " " __TIME__; }
int shared_constant() { return 1729; }
int main() {
    Box<int> b{21};
    std::printf("%d %s\n", b.twice(), build_stamp());
    return 0;
}
'@

$bCpp = @'
#include "shared.h"
// Second TU: forces a multi-object build (folding/order effects) and reuses
// the template from the header.
double widen(int x) {
    Box<double> b{static_cast<double>(x)};
    return b.twice();
}
'@

# Materializes the corpus into $dir.
function New-Corpus {
    param([string]$Dir)
    New-Item -ItemType Directory -Force $Dir | Out-Null
    Set-Content (Join-Path $Dir 'shared.h') $sharedH -Encoding ascii
    Set-Content (Join-Path $Dir 'a.cpp')    $aCpp    -Encoding ascii
    Set-Content (Join-Path $Dir 'b.cpp')    $bCpp    -Encoding ascii
}

# Compiles the corpus under the interceptor in work root $Root, writing traces
# to $TraceDir. $Cc is the compiler ('cl' or 'clang-cl'); $Flags is the
# recommended deterministic flag set for that compiler. Compile-only (/c): the
# .obj is the primary M2 artifact, and skipping the link keeps PDB (out of
# scope) out of the picture.
function Build-Run {
    param([string]$Root, [string]$TraceDir, [string]$Cc, [string[]]$Flags)
    New-Corpus $Root
    New-Item -ItemType Directory -Force $TraceDir | Out-Null
    $env:SEMBAZURU_TRACE_DIR = $TraceDir
    Push-Location $Root
    try {
        $out = & $launcher $dll $Cc '/nologo' '/c' @Flags 'a.cpp' 'b.cpp' 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            Write-Host $out
            throw "$Cc compile exited $LASTEXITCODE"
        }
    } finally {
        Pop-Location
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue
    }
    # Defense in depth (the gate must compare something): a successful compile
    # that produced no .obj would otherwise let verify-determinism pass vacuously.
    $objCount = @(Get-ChildItem $Root -Filter *.obj).Count
    if ($objCount -lt 1) { throw "$Cc produced no .obj in $Root" }
}

# Content-determinism gate: build twice in the SAME build root (snapshotting
# run A's outputs before run B overwrites them), then verify. This proves the
# M2 "Done when" (same input -> same output bytes) without requiring path
# independence. Used for MSVC, whose .obj embeds the absolute object path
# (S_OBJNAME) with no documented flag to remove it — see docs/determinism.md.
function Invoke-SameRootGate {
    param([string]$Name, [string]$Cc, [string[]]$Flags)

    $root   = Join-Path $WorkRoot "$Name-build"
    $snap   = Join-Path $WorkRoot "$Name-snap"
    $traceA = Join-Path $WorkRoot "$Name-A-trace"
    $traceB = Join-Path $WorkRoot "$Name-B-trace"

    Build-Run -Root $root -TraceDir $traceA -Cc $Cc -Flags $Flags
    New-Item -ItemType Directory -Force $snap | Out-Null
    Copy-Item (Join-Path $root '*.obj') $snap -Force
    Build-Run -Root $root -TraceDir $traceB -Cc $Cc -Flags $Flags

    # Both runs built in $root, so the trace cwd relativizes outputs to a.obj /
    # b.obj; run A's bytes are read from the snapshot, run B's from $root.
    # Out-Host (not the pipeline) so the report prints but does not become this
    # function's return value, leaving $LASTEXITCODE the only thing returned.
    & $TracerExe verify-determinism `
        --trace-a $traceA --root-a $snap `
        --trace-b $traceB --root-b $root `
        --output a.obj --output b.obj | Out-Host
    return $LASTEXITCODE
}

# Path-independence gate: build in two DIFFERENT roots, then verify the outputs
# are still byte-identical. The stronger property distribution needs (M3/M4).
# clang-cl + the prefix-map flags achieve it; this is the guaranteed
# deterministic path per docs/determinism.md and CLAUDE.md (clang-cl
# first-class).
function Invoke-DiffRootGate {
    param([string]$Name, [string]$Cc, [string[]]$Flags)

    $rootA  = Join-Path $WorkRoot "$Name-A"
    $rootB  = Join-Path $WorkRoot "$Name-B"
    $traceA = Join-Path $WorkRoot "$Name-A-trace"
    $traceB = Join-Path $WorkRoot "$Name-B-trace"

    Build-Run -Root $rootA -TraceDir $traceA -Cc $Cc -Flags $Flags
    Build-Run -Root $rootB -TraceDir $traceB -Cc $Cc -Flags $Flags

    & $TracerExe verify-determinism `
        --trace-a $traceA --root-a $rootA `
        --trace-b $traceB --root-b $rootB `
        --output a.obj --output b.obj | Out-Host
    return $LASTEXITCODE
}

$failures = @()

# --- Gate: MSVC cl (content determinism, same build root) -------------------
# /Brepro fixes the COFF TimeDateStamp and the __DATE__/__TIME__ macros
# (implies /d1nodatetime). MSVC's .obj embeds the absolute build path, so
# cross-directory byte-identity is not achievable with documented flags
# (docs/determinism.md); the same-root gate proves content determinism.
Write-Host '=== MSVC cl determinism (same build root) ==='
$clCode = Invoke-SameRootGate -Name 'msvc' -Cc 'cl' -Flags @('/Brepro')
if ($clCode -ne 0) {
    $failures += 'msvc: verify-determinism reported an unexplained output difference'
} else {
    Write-Host 'GATE PASS  msvc: corpus reproduces byte-for-byte (or normalized-equal)'
}

# --- Gate: clang-cl (first-class target) ------------------------------------
$clang = Get-Command clang-cl -ErrorAction SilentlyContinue
if ($null -eq $clang) {
    if ($RequireClangCl) {
        $failures += 'clang-cl: required (-RequireClangCl) but not found on PATH'
    } else {
        Write-Host 'GATE SKIP  clang-cl not on PATH'
    }
} else {
    Write-Host '=== clang-cl determinism ==='
    # SOURCE_DATE_EPOCH fixes the time macros; the prefix-map/compilation-dir
    # flags keep paths out of the object. See docs/determinism.md.
    $env:SOURCE_DATE_EPOCH = '0'
    try {
        $clangFlags = @(
            '/Brepro',
            '-ffile-compilation-dir=.',
            '-no-canonical-prefixes',
            '-Wno-builtin-macro-redefined',
            '-D__DATE__=',
            '-D__TIME__=',
            '-D__TIMESTAMP__='
        )
        # Different roots: clang-cl is expected to be path-independent.
        $clangCode = Invoke-DiffRootGate -Name 'clang' -Cc 'clang-cl' -Flags $clangFlags
    } finally {
        Remove-Item Env:\SOURCE_DATE_EPOCH -ErrorAction SilentlyContinue
    }
    if ($clangCode -ne 0) {
        $failures += 'clang-cl: outputs differ across build directories (expected path-independent)'
    } else {
        Write-Host 'GATE PASS  clang-cl: byte-identical across different build directories'
    }
}

# --- Verdict ----------------------------------------------------------------
if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'DETERMINISM HARNESS FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host ''
Write-Host 'DETERMINISM HARNESS PASS (M2: representative C++ TUs reproduce output bytes)'
