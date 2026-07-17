# M3.5 speed gate: the compile under the read VFS must not be broken by
# round-trip latency, and must not be much slower than a local compile.
#
# The realistic split is "toolchain + SDK live on the worker; the project sources
# come from the agent over the VFS." So only a handful of project files traverse
# the data plane; the hundreds of SDK headers are read locally. This gate makes
# that measurable by injecting a synthetic worker<->agent RTT (the prestudy's
# in-process delay shim, since clumsy/QoS cannot shape Windows loopback) and
# showing the compile time barely moves between 0 ms and 1 ms RTT -- i.e. the
# round-trip count is small and bounded, the literal "往復で破綻していない".
#
# Asserts:
#   * the 1 ms-RTT compile is within a small delta of the 0 ms-RTT compile
#     (round-trips do not blow it up), and
#   * the VFS compile is not catastrophically slower than a local compile.
# Reports all numbers for the record (feeds ADR 0002).
#
# Requires cl.exe + cargo on PATH (clang-cl optional).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\vfs-bench-work'),
    [int]$Runs = 5,
    [switch]$ConnectionReuseOnly
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcher, $dll)) { if (-not (Test-Path $f)) { throw "missing: $f" } }
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) { throw 'cl.exe not on PATH' }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    $savedErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        # Windows PowerShell 5 wraps native stderr as ErrorRecord; stringify it to avoid
        # replaying verbose NativeCommandError metadata. LASTEXITCODE remains authoritative.
        $cargoOutput = @(& cargo build -p sembazuru-worker --example vfs_host 2>&1 | ForEach-Object { "$_" })
        $cargoExitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedErrorPreference
    }
    Write-Host ($cargoOutput -join [Environment]::NewLine)
    if ($cargoExitCode -ne 0) { throw "vfs_host build failed with exit code $cargoExitCode" }
} finally { Pop-Location }
$hostExe = Join-Path $repo 'target\debug\examples\vfs_host.exe'

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# Project source set that pulls several PROJECT headers (these traverse the VFS),
# plus a system header (read locally on the worker, not via the VFS).
$agentSrc = Join-Path $WorkRoot 'agent-src'
New-Item -ItemType Directory -Force $agentSrc | Out-Null
$chain = 0..5 | ForEach-Object { "#include `"h$_.h`"" }
0..5 | ForEach-Object { Set-Content (Join-Path $agentSrc "h$_.h") "#pragma once`r`nconstexpr int K$_ = $_;" -Encoding ascii }
Set-Content (Join-Path $agentSrc 'shared.h') (@('#pragma once') + $chain -join "`r`n") -Encoding ascii
Set-Content (Join-Path $agentSrc 'a.cpp') @'
#include <stdio.h>
#include "shared.h"
int main(){ return K0+K1+K2+K3+K4+K5; }
'@ -Encoding ascii
$srcAbs = Join-Path $agentSrc 'a.cpp'

# M3.5 pipe connection-reuse gate. The hook makes one length-prefixed hydrate
# request for every redirected CreateFile/read. The dev-only vfs_host metrics
# file observes server accepts and requests without altering the production pipe
# wire. This is deliberately exercised before the latency benchmark: a timing
# result without bounded connection count could hide reconnect churn.
$reuseProbeSrc = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <algorithm>
#include <process.h>
#include <vector>

struct Work { const wchar_t* root; int index; int rounds; volatile LONG* failures; volatile LONG* openFailures; volatile LONG* contentFailures; volatile LONG* lastError; std::vector<LONGLONG>* openTicks; };

unsigned __stdcall ReadLoop(void* raw) {
    Work* work = static_cast<Work*>(raw);
    wchar_t path[MAX_PATH];
    char expected[64];
    std::snprintf(expected, sizeof(expected), "agent-%d", work->index);
    for (int i = 0; i < work->rounds; ++i) {
        std::swprintf(path, MAX_PATH, L"%s\\input-%d.txt", work->root, work->index);
        LARGE_INTEGER start, end;
        QueryPerformanceCounter(&start);
        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        QueryPerformanceCounter(&end);
        if (i >= 50) work->openTicks->push_back(end.QuadPart - start.QuadPart);
        if (h == INVALID_HANDLE_VALUE) { InterlockedIncrement(work->failures); InterlockedIncrement(work->openFailures); InterlockedExchange(work->lastError, GetLastError()); continue; }
        char bytes[80] = {}; DWORD read = 0;
        BOOL ok = ReadFile(h, bytes, sizeof(bytes) - 1, &read, nullptr);
        CloseHandle(h);
        if (!ok || std::strcmp(bytes, expected) != 0) { InterlockedIncrement(work->failures); InterlockedIncrement(work->contentFailures); }
    }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc != 4) return 2;
    int threads = _wtoi(argv[2]), rounds = _wtoi(argv[3]);
    if (threads < 1 || rounds < 1) return 2;
    volatile LONG failures = 0, openFailures = 0, contentFailures = 0, lastError = 0;
    HANDLE handles[32] = {}; Work work[32] = {};
    std::vector<LONGLONG> perThread[32];
    if (threads > 32) return 2;
    for (int i = 0; i < threads; ++i) {
        work[i] = { argv[1], i, rounds, &failures, &openFailures, &contentFailures, &lastError, &perThread[i] };
        uintptr_t thread = _beginthreadex(nullptr, 0, ReadLoop, &work[i], 0, nullptr);
        if (!thread) return 3;
        handles[i] = reinterpret_cast<HANDLE>(thread);
    }
    WaitForMultipleObjects(threads, handles, TRUE, INFINITE);
    for (int i = 0; i < threads; ++i) CloseHandle(handles[i]);
    std::vector<LONGLONG> allTicks;
    for (int i = 0; i < threads; ++i) allTicks.insert(allTicks.end(), perThread[i].begin(), perThread[i].end());
    std::sort(allTicks.begin(), allTicks.end());
    LARGE_INTEGER frequency; QueryPerformanceFrequency(&frequency);
    double medianUs = allTicks.empty() ? 0.0 : (allTicks[(allTicks.size() - 1) / 2] * 1000000.0 / frequency.QuadPart);
    size_t p90Index = allTicks.empty() ? 0 : ((allTicks.size() * 90 + 99) / 100 - 1);
    double p90Us = allTicks.empty() ? 0.0 : (allTicks[p90Index] * 1000000.0 / frequency.QuadPart);
    std::printf("READS:%d FAILURES:%ld OPEN_FAILURES:%ld CONTENT_FAILURES:%ld LAST_ERROR:%ld\n", threads * rounds, failures, openFailures, contentFailures, lastError);
    std::printf("MEDIAN_OPEN_US:%.3f P90_OPEN_US:%.3f SAMPLES:%zu\n", medianUs, p90Us, allTicks.size());
    return failures == 0 ? 0 : 1;
}
'@
Set-Content (Join-Path $WorkRoot 'vfs_reuse_probe.cpp') $reuseProbeSrc -Encoding ascii
Push-Location $WorkRoot
try {
    $out = & cl /nologo /EHsc 'vfs_reuse_probe.cpp' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $out; throw 'reuse probe compile failed' }
} finally { Pop-Location }
$reuseProbe = Join-Path $WorkRoot 'vfs_reuse_probe.exe'

function Read-VfsHarnessMetrics {
    param([string]$Metrics)
    if (-not (Test-Path $Metrics)) { throw "vfs_host did not publish metrics: $Metrics" }
    $lines = Get-Content -LiteralPath $Metrics
    $values = @{}
    foreach ($line in $lines) {
        $pair = $line.Split('=', 2)
        if ($pair.Count -eq 2) { $values[$pair[0]] = [int]$pair[1] }
    }
    foreach ($key in @('connections', 'active_connections', 'requests')) {
        if (-not $values.ContainsKey($key)) { throw "vfs_host metrics missing $key" }
    }
    return $values
}

function Read-OpenTiming {
    param([string]$Output)
    $match = [regex]::Match($Output, 'MEDIAN_OPEN_US:([0-9.]+) P90_OPEN_US:([0-9.]+) SAMPLES:(\d+)')
    if (-not $match.Success) { throw "reuse probe did not publish open timing: $Output" }
    return @{ MedianUs = [double]$match.Groups[1].Value; P90Us = [double]$match.Groups[2].Value; Samples = [int]$match.Groups[3].Value }
}

function Invoke-ReuseScenario {
    param([int]$Threads, [int]$Rounds, [int]$DropResponses = 0, [switch]$Strict,
          [switch]$CloseAfterResponse)
    $name = "reuse-$PID-" + [System.IO.Path]::GetRandomFileName().Substring(0, 8)
    $scratch = Join-Path $WorkRoot ("reuse-scratch-" + [System.IO.Path]::GetRandomFileName())
    $logical = Join-Path $WorkRoot ("reuse-logical-" + [System.IO.Path]::GetRandomFileName())
    $backing = Join-Path $WorkRoot ("reuse-backing-" + [System.IO.Path]::GetRandomFileName())
    $metrics = Join-Path $WorkRoot ("reuse-metrics-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force $scratch, $logical, $backing | Out-Null
    for ($i = 0; $i -lt $Threads; ++$i) {
        Set-Content (Join-Path $logical "input-$i.txt") "STALE-$i" -NoNewline -Encoding ascii
        Set-Content (Join-Path $backing "input-$i.txt") "agent-$i" -NoNewline -Encoding ascii
    }
    $args = @($name, $scratch, $logical, $backing, '--metrics', $metrics, '--drop-responses', $DropResponses)
    if ($CloseAfterResponse) { $args += '--close-after-response' }
    $hostProc = Start-Process -FilePath $hostExe -ArgumentList $args -PassThru -WindowStyle Hidden
    try {
        # `Test-Path \\.\pipe\...` itself opens a client connection. Wait for
        # the harness' zeroed metrics file instead, so the measured connection
        # count belongs entirely to the hooked probe.
        for ($i = 0; $i -lt 100; ++$i) { if (Test-Path $metrics) { break }; Start-Sleep -Milliseconds 25 }
        if (-not (Test-Path $metrics)) { throw 'reuse vfs host did not publish initial metrics' }
        $env:SEMBAZURU_MODE = 'vfs'; $env:SEMBAZURU_VFS_ROOT = $logical
        $env:SEMBAZURU_VFS_PIPE = $name; $env:SEMBAZURU_VFS_SCRATCH = $scratch
        if ($Strict) { $env:SEMBAZURU_VFS_STRICT = '1' }
        try {
            $out = & $launcher $dll $reuseProbe $logical $Threads $Rounds 2>&1 | Out-String
            $exit = $LASTEXITCODE
        } finally {
            Remove-Item Env:\SEMBAZURU_MODE, Env:\SEMBAZURU_VFS_ROOT, Env:\SEMBAZURU_VFS_PIPE, `
                Env:\SEMBAZURU_VFS_SCRATCH, Env:\SEMBAZURU_VFS_STRICT -ErrorAction SilentlyContinue
        }
        $snapshot = $null
        for ($i = 0; $i -lt 100; ++$i) {
            $snapshot = Read-VfsHarnessMetrics $metrics
            if ($snapshot.active_connections -eq 0) { break }
            Start-Sleep -Milliseconds 25
        }
        if ($snapshot.active_connections -ne 0) { throw "vfs_host retained a client connection after probe exit: $($snapshot.active_connections)" }
        return @{ Output = $out; Exit = $exit; Timing = (Read-OpenTiming $out); Metrics = $snapshot; Scratch = $scratch }
    } finally {
        if ($hostProc -and -not $hostProc.HasExited) { Stop-Process -Id $hostProc.Id -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-HostGoneStrictScenario {
    $scratch = Join-Path $WorkRoot ("gone-scratch-" + [System.IO.Path]::GetRandomFileName())
    $logical = Join-Path $WorkRoot ("gone-logical-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force $scratch, $logical | Out-Null
    Set-Content (Join-Path $logical 'input-0.txt') 'STALE-0' -NoNewline -Encoding ascii
    $env:SEMBAZURU_MODE = 'vfs'; $env:SEMBAZURU_VFS_ROOT = $logical
    $env:SEMBAZURU_VFS_PIPE = "gone-$PID-" + [System.IO.Path]::GetRandomFileName().Substring(0, 8)
    $env:SEMBAZURU_VFS_SCRATCH = $scratch; $env:SEMBAZURU_VFS_STRICT = '1'
    try {
        $out = & $launcher $dll $reuseProbe $logical 1 1 2>&1 | Out-String
        return @{ Output = $out; Exit = $LASTEXITCODE; Scratch = $scratch }
    } finally {
        Remove-Item Env:\SEMBAZURU_MODE, Env:\SEMBAZURU_VFS_ROOT, Env:\SEMBAZURU_VFS_PIPE, `
            Env:\SEMBAZURU_VFS_SCRATCH, Env:\SEMBAZURU_VFS_STRICT -ErrorAction SilentlyContinue
    }
}

# 1000 sequential opens must be 1000 protocol requests but at most two server
# accepts (initial dial plus a tolerated reconnect). The dev-only control closes
# every COMPLETE response, forcing a stale-handle write failure and one fresh
# reconnect before the next hydrate. It is not the pre-change implementation;
# it measures the upper bound of connection setup that persistent handles avoid.
# QPC covers only CreateFileW, drops the first 50 opens, and compares paired
# medians. One warmup pair is discarded, then nine AB/BA-order pairs use a
# one-sided sign test: 8+ forced medians above persistent gives p=10/512≈0.02.
function Assert-OpenLatencyScenario {
    param($Result, [string]$Name, [switch]$Forced)
    if ($Result.Exit -ne 0 -or $Result.Output -notmatch 'READS:1000 FAILURES:0' -or
        $Result.Metrics.requests -ne 1000 -or $Result.Timing.Samples -ne 950) {
        throw "$Name latency scenario failed: exit=$($Result.Exit) requests=$($Result.Metrics.requests) samples=$($Result.Timing.Samples) output=$($Result.Output)"
    }
    if ($Forced) {
        if ($Result.Metrics.connections -lt 900) {
            throw "$Name forced reconnect control did not churn connections: $($Result.Metrics.connections)"
        }
    } elseif ($Result.Metrics.connections -gt 2) {
        throw "$Name persistent pipe reused too few connections: $($Result.Metrics.connections)"
    }
}

$pairDeltas = @()
$forcedWins = 0
$single = $null
$forcedReconnect = $null
for ($pair = 0; $pair -lt 10; ++$pair) {
    $persistentFirst = ($pair % 2) -eq 0
    if ($persistentFirst) {
        $persistent = Invoke-ReuseScenario -Threads 1 -Rounds 1000
        $forced = Invoke-ReuseScenario -Threads 1 -Rounds 1000 -CloseAfterResponse
    } else {
        $forced = Invoke-ReuseScenario -Threads 1 -Rounds 1000 -CloseAfterResponse
        $persistent = Invoke-ReuseScenario -Threads 1 -Rounds 1000
    }
    Assert-OpenLatencyScenario $persistent "pair $pair persistent"
    Assert-OpenLatencyScenario $forced "pair $pair forced" -Forced
    $delta = $forced.Timing.MedianUs - $persistent.Timing.MedianUs
    Write-Host ('pipe pair {0} ({1}): persistent={2:N3} us forced={3:N3} us delta={4:N3} us' -f $pair, $(if ($persistentFirst) { 'AB' } else { 'BA' }), $persistent.Timing.MedianUs, $forced.Timing.MedianUs, $delta)
    if ($pair -eq 0) { continue }
    $pairDeltas += $delta
    if ($delta -gt 0) { $forcedWins++ }
    $single = $persistent
    $forcedReconnect = $forced
}
$sortedDeltas = @($pairDeltas | Sort-Object)
$medianDelta = $sortedDeltas[4]
Write-Host ('pipe latency sign test: forced-wins={0}/9 median-delta={1:N3} us deltas=[{2}]' -f $forcedWins, $medianDelta, ($pairDeltas -join ', '))
if ($forcedWins -lt 8) {
    throw "persistent pipe did not reduce median CreateFile latency reliably: forced-wins=$forcedWins/9 (expected >=8)"
}
foreach ($threads in @(8, 16, 32)) {
    $parallel = Invoke-ReuseScenario -Threads $threads -Rounds 125
    $expected = $threads * 125
    if ($parallel.Exit -ne 0 -or $parallel.Output -notmatch "READS:$expected FAILURES:0" -or
        $parallel.Metrics.requests -ne $expected -or $parallel.Metrics.connections -gt $threads) {
        throw "per-thread pipe reuse/frame isolation failed: threads=$threads exit=$($parallel.Exit) requests=$($parallel.Metrics.requests) connections=$($parallel.Metrics.connections) output=$($parallel.Output)"
    }
}

# A mid-response close is a transport failure, never stale-local success. The
# idempotent hydrate is allowed exactly one fresh-connection retry. Two faults
# exhaust that retry, drop the strict marker, and leave the stale bytes unread.
$oneFault = Invoke-ReuseScenario -Threads 1 -Rounds 1 -DropResponses 1
if ($oneFault.Exit -ne 0 -or $oneFault.Output -notmatch 'READS:1 FAILURES:0' -or
    $oneFault.Metrics.connections -ne 2 -or $oneFault.Metrics.requests -ne 2) {
    throw "single broken response did not retry exactly once: exit=$($oneFault.Exit) requests=$($oneFault.Metrics.requests) connections=$($oneFault.Metrics.connections) output=$($oneFault.Output)"
}
$twoFaults = Invoke-ReuseScenario -Threads 1 -Rounds 1 -DropResponses 2 -Strict
if ($twoFaults.Exit -eq 0 -or $twoFaults.Output -match 'STALE-0' -or
    $twoFaults.Metrics.connections -ne 2 -or $twoFaults.Metrics.requests -ne 2 -or
    -not (Test-Path (Join-Path $twoFaults.Scratch '.sbz-unvirtualized'))) {
    throw "two broken responses must strict-fallback without stale bytes: exit=$($twoFaults.Exit) requests=$($twoFaults.Metrics.requests) connections=$($twoFaults.Metrics.connections) output=$($twoFaults.Output)"
}
$gone = Invoke-HostGoneStrictScenario
if ($gone.Exit -eq 0 -or $gone.Output -match 'STALE-0' -or
    -not (Test-Path (Join-Path $gone.Scratch '.sbz-unvirtualized'))) {
    throw "missing host must strict-fallback without stale bytes: exit=$($gone.Exit) output=$($gone.Output)"
}
Write-Host "VFS PIPE REUSE GATE PASS (requests=1000 persistent-connections=$($single.Metrics.connections) forced-connections=$($forcedReconnect.Metrics.connections); median-delta-us=$([Math]::Round($medianDelta,3)); 8/16/32-thread frame isolation; one retry; strict fallback)"
if ($ConnectionReuseOnly) { exit 0 }

function Median-Min { param([double[]]$xs) ($xs | Measure-Object -Minimum).Minimum }

# One compile under VFS at the given RTT (microseconds); returns elapsed ms.
function Time-Vfs {
    param([int]$RttUs)
    $workdir = Join-Path $WorkRoot ("w-" + [System.IO.Path]::GetRandomFileName())
    $scratch = Join-Path $WorkRoot ("s-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force $workdir, $scratch | Out-Null
    $pipe = "sbz-bench-$PID-" + [System.IO.Path]::GetRandomFileName().Substring(0, 8)
    $full = "\\.\pipe\$pipe"
    $env:SEMBAZURU_VFS_RTT_US = "$RttUs"
    $proc = Start-Process -FilePath $hostExe -ArgumentList @($pipe, $scratch) -PassThru -WindowStyle Hidden
    try {
        for ($i = 0; $i -lt 100; $i++) { if (Test-Path $full) { break }; Start-Sleep -Milliseconds 50 }
        $env:SEMBAZURU_MODE = 'vfs'; $env:SEMBAZURU_VFS_ROOT = $agentSrc
        $env:SEMBAZURU_VFS_PIPE = $pipe; $env:SEMBAZURU_VFS_SCRATCH = $scratch
        try {
            $ms = (Measure-Command {
                    Push-Location $workdir
                    try { & $launcher $dll cl /nologo /c /Brepro $srcAbs "/Foout.obj" 1>$null 2>$null } finally { Pop-Location }
                }).TotalMilliseconds
            # Self-validate: the measurement is only meaningful if the compile
            # actually ran AND went through the VFS. Without this, a silently
            # broken redirect would measure a plain local compile (and, with no
            # VFS, the RTT shim never fires -> delta ~= 0 -> a false pass).
            if ($LASTEXITCODE -ne 0) { throw "vfs compile (rtt=$RttUs us) exited $LASTEXITCODE" }
            if (-not (Test-Path (Join-Path $workdir 'out.obj'))) { throw "vfs compile produced no out.obj (rtt=$RttUs us)" }
            if (-not (Get-ChildItem -Recurse -File $scratch -ErrorAction SilentlyContinue)) {
                throw "VFS not exercised: scratch empty (rtt=$RttUs us) -> measuring a local compile"
            }
        } finally {
            Remove-Item Env:\SEMBAZURU_MODE, Env:\SEMBAZURU_VFS_ROOT, Env:\SEMBAZURU_VFS_PIPE, Env:\SEMBAZURU_VFS_SCRATCH -ErrorAction SilentlyContinue
        }
    } finally {
        Remove-Item Env:\SEMBAZURU_VFS_RTT_US -ErrorAction SilentlyContinue
        if ($proc -and -not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    }
    return $ms
}

function Time-Local {
    $workdir = Join-Path $WorkRoot ("L-" + [System.IO.Path]::GetRandomFileName())
    New-Item -ItemType Directory -Force $workdir | Out-Null
    return (Measure-Command {
            Push-Location $workdir
            try { & cl /nologo /c /Brepro $srcAbs "/Foout.obj" 1>$null 2>$null } finally { Pop-Location }
        }).TotalMilliseconds
}

# Warm up (first compile pays one-time costs), then take the best of $Runs.
Time-Local | Out-Null; Time-Vfs 0 | Out-Null
$local = Median-Min (1..$Runs | ForEach-Object { Time-Local })
$vfs0 = Median-Min (1..$Runs | ForEach-Object { Time-Vfs 0 })
$vfs1 = Median-Min (1..$Runs | ForEach-Object { Time-Vfs 1000 })

Write-Host ('local           : {0,7:N1} ms' -f $local)
Write-Host ('vfs  (0 ms RTT) : {0,7:N1} ms' -f $vfs0)
Write-Host ('vfs  (1 ms RTT) : {0,7:N1} ms' -f $vfs1)
$delta = $vfs1 - $vfs0
Write-Host ('RTT delta       : {0,7:N1} ms  (1ms-RTT minus 0ms-RTT; ~= round-trips x 1ms)' -f $delta)

$failures = @()
# Round-trips do not blow it up: a 1 ms RTT (injected accurately via spin-wait)
# adds only ~one ms per project file fetched (the corpus has ~8), i.e. ~8 ms. A
# blow-up where the hundreds of SDK headers wrongly traversed the VFS would add
# hundreds of ms. 100 ms cleanly separates the two while tolerating wall-clock
# noise on a shared CI runner.
if ($delta -gt 100) {
    $failures += "round-trip latency dominates: 1ms RTT added $([int]$delta) ms (expected ~8 ms for a handful of project files; a blow-up would be hundreds)"
}
# Not catastrophically slower than local. The VFS path also pays fixed
# injection/pipe/agent overhead, so allow generous headroom; this guards against
# an order-of-magnitude regression, not micro-overhead.
if ($vfs1 -gt ($local * 4 + 500)) {
    $failures += "VFS compile far slower than local: vfs(1ms)=$([int]$vfs1) ms vs local=$([int]$local) ms"
}

if ($failures.Count -gt 0) {
    Write-Host ''; Write-Host 'VFS BENCH GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host ''
Write-Host 'VFS BENCH GATE PASS (round-trip latency does not break the compile; speed within bounds)'
