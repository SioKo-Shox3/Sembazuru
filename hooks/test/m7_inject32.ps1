# M7.3 cross-bitness injection gate.
#
# Proves the 32-bit interceptor (sbz_interceptor32.dll) is injected into a 32-bit
# child when a 64-bit injector spawns it — the case that needs BOTH bitnesses of
# the DLL (docs/deferred.md M7 "32/64bit 双方の DLL"). The 64-bit launcher.exe
# passes the 64-bit DLL to DetourCreateProcessWithDllEx; for a 32-bit target,
# Detours derives the sibling sbz_interceptor32.dll (same directory) and injects
# THAT. So the 32-bit interceptor only loads if it is present alongside the 64-bit
# one and is a correct 32-bit PE exporting the Detours helper.
#
# Positive: with the 32-bit sibling present, the injected interceptor traces the
# 32-bit child's file open. Negative control: remove the sibling and the same run
# produces no trace — proving the trace came from the 32-bit DLL, not by accident.
#
# clang-cl/lld are not needed here; this exercises the injection mechanism with a
# tiny C++ probe (built x86), so it runs wherever cl is available (local + CI).
param(
    [string]$Build64 = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$Build32 = (Join-Path $PSScriptRoot '..\build32\Release'),
    [string]$TracerExe = (Join-Path $PSScriptRoot '..\..\target\release\sembazuru-trace.exe'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\inject32-work')
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $Build64 'launcher.exe'         # 64-bit injector
$dll64 = Join-Path $Build64 'sbz_interceptor64.dll'   # 64-bit hook DLL
$dll32src = Join-Path $Build32 'sbz_interceptor32.dll' # 32-bit hook DLL (sibling)
$probe32 = Join-Path $Build32 'probe.exe'             # 32-bit child to inject into
foreach ($f in @($launcher, $dll64, $dll32src, $probe32, $TracerExe)) {
    if (-not (Test-Path $f)) { throw "missing artifact: $f" }
}

# The sibling lookup is by directory: the 32-bit DLL must sit next to the 64-bit
# one. (CI copies it here too; do it defensively so the gate is self-contained.)
$dll32 = Join-Path $Build64 'sbz_interceptor32.dll'
Copy-Item $dll32src $dll32 -Force

if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null
$victim = Join-Path $WorkRoot 'opened-by-32bit-child.txt'
Set-Content $victim "read me from a 32-bit process`n" -Encoding ascii

# Runs the 64-bit launcher -> 32-bit probe (which opens $victim), tracing into a
# fresh dir; returns the count of trace files produced.
function Invoke-Probe32 {
    param([string]$Tag)
    $traceDir = Join-Path $WorkRoot "$Tag-trace"
    New-Item -ItemType Directory -Force $traceDir | Out-Null
    $env:SEMBAZURU_TRACE_DIR = $traceDir
    try {
        $out = & $launcher $dll64 $probe32 $victim 2>&1 | Out-String
        $code = $LASTEXITCODE
    } finally {
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue
    }
    if ($code -ne 0) { Write-Host $out; throw "${Tag}: probe exited $code" }
    return @{
        traceDir = $traceDir
        count    = (Get-ChildItem $traceDir -Filter *.sbzt -ErrorAction SilentlyContinue).Count
    }
}

$failures = @()

# --- Artifact correctness: the DLL and probe are 32-bit PEs -----------------
function Is-X86Pe([string]$path) {
    $fs = [System.IO.File]::OpenRead($path)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOff = $br.ReadInt32()
        $fs.Seek($peOff, 'Begin') | Out-Null
        $sig = $br.ReadUInt32()           # 'PE\0\0'
        $machine = $br.ReadUInt16()       # IMAGE_FILE_MACHINE_*
        return ($sig -eq 0x00004550) -and ($machine -eq 0x014C) # 0x14C = I386
    } finally { $fs.Close() }
}
if (-not (Is-X86Pe $dll32src)) { $failures += 'sbz_interceptor32.dll is not a 32-bit PE' }
if (-not (Is-X86Pe $probe32)) { $failures += 'probe.exe (32-bit build) is not a 32-bit PE' }

# --- Positive: with the 32-bit sibling present, injection traces the child ---
$pos = Invoke-Probe32 'with32'
if ($pos.count -lt 1) {
    $failures += 'cross-bitness injection produced NO trace (32-bit interceptor did not load)'
} else {
    # Stronger: the trace captured the file the 32-bit child opened.
    $graph = & $TracerExe export --trace-dir $pos.traceDir --json | ConvertFrom-Json
    $seen = @($graph.inputs.path | Where-Object { $_ -like '*opened-by-32bit-child.txt' }).Count -gt 0
    if (-not $seen) {
        $failures += 'cross-bitness trace did not capture the file the 32-bit child opened'
    } else {
        Write-Host "POSITIVE PASS: 32-bit interceptor injected; $($pos.count) trace(s), child's open captured"
    }
}

# --- Negative control: remove the sibling -> no injection, no trace ----------
Remove-Item $dll32 -Force
$neg = Invoke-Probe32 'no32'
if ($neg.count -ne 0) {
    $failures += "negative control FAILED: trace produced ($($neg.count)) with the 32-bit DLL removed"
} else {
    Write-Host 'NEGATIVE PASS: with the 32-bit sibling removed, no injection/trace (control holds)'
}

# Restore the staged 32-bit sibling so a later signing step (sign_smoke.ps1) finds
# it — the negative control above removed it.
Copy-Item $dll32src $dll32 -Force

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M7.3 CROSS-BITNESS INJECTION GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'M7.3 CROSS-BITNESS INJECTION GATE PASS (64-bit injector -> 32-bit child gets sbz_interceptor32.dll)'
