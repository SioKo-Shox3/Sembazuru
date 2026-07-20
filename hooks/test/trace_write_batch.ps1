param(
    [Parameter(Mandatory)] [string]$CandidateDll,
    [string]$BaselineDll,
    [string]$Launcher,
    [string]$Probe,
    [int]$Iterations = 10000,
    [switch]$FunctionalOnly,
    [switch]$ExpectNoDifference
)
$ErrorActionPreference = 'Stop'

if ($Iterations -le 0) { throw 'Iterations must be positive' }
if (-not (Test-Path $CandidateDll)) { throw "missing candidate: $CandidateDll" }
if ($BaselineDll -and -not (Test-Path $BaselineDll)) { throw "missing baseline: $BaselineDll" }
if ($ExpectNoDifference) {
    if (-not $BaselineDll) { throw 'ExpectNoDifference requires BaselineDll' }
    if ($FunctionalOnly) { throw 'ExpectNoDifference cannot be combined with FunctionalOnly' }
    if ($Iterations -ne 10000) { throw 'the negative-control sanity gate is fixed at Iterations=10000' }
    $candidatePath = (Resolve-Path -LiteralPath $CandidateDll).ProviderPath
    $baselinePath = (Resolve-Path -LiteralPath $BaselineDll).ProviderPath
    if (-not [StringComparer]::OrdinalIgnoreCase.Equals($candidatePath, $baselinePath)) {
        throw 'ExpectNoDifference requires CandidateDll and BaselineDll to be the same DLL'
    }
}
if (-not $Launcher) { $Launcher = Join-Path (Split-Path $CandidateDll) 'launcher.exe' }
if (-not $Probe) { $Probe = Join-Path (Split-Path $CandidateDll) 'trace_write_probe.exe' }
foreach ($file in @($Launcher, $Probe)) {
    if (-not (Test-Path $file)) { throw "missing fixture: $file" }
}
$script:ProbeInput = Join-Path ([IO.Path]::GetTempPath()) ("sbz-trace-write-" + $PID + '-input.txt')
[IO.File]::WriteAllText($script:ProbeInput, 'trace-write-probe')

function Read-NormalizedTrace {
    param([string]$TraceDir, [switch]$StructureOnly)
    $files = @(Get-ChildItem -LiteralPath $TraceDir -Filter '*.sbzt' -File)
    if ($files.Count -ne 1) { throw "expected exactly one trace, got $($files.Count)" }
    [byte[]]$bytes = [IO.File]::ReadAllBytes($files[0].FullName)
    if ($bytes.Length -lt 40) { throw 'truncated trace header' }
    if ([Text.Encoding]::ASCII.GetString($bytes, 0, 4) -ne 'SBZT') { throw 'bad trace magic' }
    $offset = 40
    foreach ($unused in 1..3) {
        if ($offset + 4 -gt $bytes.Length) { throw 'truncated trace header string' }
        $chars = [BitConverter]::ToUInt32($bytes, $offset); $offset += 4
        $fieldBytes = [UInt64]$chars * 2
        if ($fieldBytes -gt [UInt64]($bytes.Length - $offset)) { throw 'truncated trace header string data' }
        $offset += [int]$fieldBytes
    }
    $probes = 0
    $normalized = @()
    while ($offset -lt $bytes.Length) {
        if ($bytes.Length - $offset -lt 28) { throw 'truncated final record' }
        $type = $bytes[$offset]
        $op = $bytes[$offset + 1]
        $status = [BitConverter]::ToUInt32($bytes, $offset + 4)
        $extra = [BitConverter]::ToUInt64($bytes, $offset + 20)
        $offset += 28
        $strings = $null
        if (-not $StructureOnly) { $strings = @() }
        foreach ($unused in 1..2) {
            if ($offset + 4 -gt $bytes.Length) { throw 'truncated final record string' }
            $chars = [BitConverter]::ToUInt32($bytes, $offset); $offset += 4
            $fieldBytes = [UInt64]$chars * 2
            if ($fieldBytes -gt [UInt64]($bytes.Length - $offset)) { throw 'truncated final record string data' }
            if (-not $StructureOnly) {
                $strings += [Text.Encoding]::Unicode.GetString($bytes, $offset, [int]$fieldBytes)
            }
            $offset += [int]$fieldBytes
        }
        if ($type -eq 1 -and $op -eq 4) { ++$probes }
        if (-not $StructureOnly) {
            $normalized += ('{0}|{1}|{2}|{3}|{4}|{5}' -f $type, $op, $status, $extra, $strings[0], $strings[1])
        }
    }
    return [pscustomobject]@{
        ProbeCount = $probes
        Normalized = if ($StructureOnly) { $null } else { @($normalized) }
    }
}

function Invoke-TraceProbe {
    param([string]$Dll, [string]$Label, [switch]$FreeLibrary, [switch]$RequireOneWritePerRecord,
          [switch]$StructureOnly)
    $trace = Join-Path ([IO.Path]::GetTempPath()) ("sbz-trace-write-" + [guid]::NewGuid())
    $hadAmbientTraceDir = Test-Path Env:\SEMBAZURU_TRACE_DIR
    $ambientTraceDir = if ($hadAmbientTraceDir) { (Get-Item Env:\SEMBAZURU_TRACE_DIR).Value } else { $null }
    New-Item -ItemType Directory -Force $trace | Out-Null
    try {
        $env:SEMBAZURU_TRACE_DIR = $trace
        $args = @($Dll, $Probe, $script:ProbeInput, $Iterations)
        if ($FreeLibrary) { $args += '--free-library' }
        $processWatch = [Diagnostics.Stopwatch]::StartNew()
        $output = & $Launcher @args 2>&1 | Out-String
        $processWatch.Stop()
        $processExitCode = $LASTEXITCODE
        if ($processExitCode -ne 0) { throw "$Label exited $processExitCode`n$output" }
        $writeMatch = [regex]::Match($output, 'write_ops_delta=(\d+)')
        if (-not $writeMatch.Success) { throw "$Label did not print write_ops_delta`n$output" }
        $writes = [UInt64]$writeMatch.Groups[1].Value
        $canaryMatch = [regex]::Match($output, 'canary_ticks=(\d+)')
        if (-not $canaryMatch.Success) { throw "$Label did not print canary_ticks`n$output" }
        $canaryTicks = [UInt64]$canaryMatch.Groups[1].Value
        $hookLoopMatch = [regex]::Match($output, 'hook_loop_ticks=(\d+)')
        if (-not $hookLoopMatch.Success) { throw "$Label did not print hook_loop_ticks`n$output" }
        $hookLoopTicks = [UInt64]$hookLoopMatch.Groups[1].Value
        if ($canaryTicks -eq 0 -or $hookLoopTicks -eq 0) {
            throw "$Label reported zero timing ticks: canary=$canaryTicks hook_loop=$hookLoopTicks"
        }
        $records = 0
        $normalized = $null
        $parsed = Read-NormalizedTrace $trace -StructureOnly:$StructureOnly
        if ($parsed.ProbeCount -ne $Iterations + 1) {
            throw "$Label expected $($Iterations + 1) probe records including warmup, got $($parsed.ProbeCount)"
        }
        $records = $parsed.ProbeCount
        $normalized = $parsed.Normalized
        if ($RequireOneWritePerRecord -and $writes -ne $Iterations) {
            throw "$Label expected WriteOperationCount delta $Iterations, got $writes"
        }
        return [pscustomobject]@{
            Label = $Label
            Writes = $writes
            Records = $records
            Normalized = $normalized
            ProcessElapsedMilliseconds = [double]$processWatch.Elapsed.TotalMilliseconds
            ProcessExitCode = [int]$processExitCode
            CanaryTicks = $canaryTicks
            HookLoopTicks = $hookLoopTicks
        }
    } finally {
        if ($hadAmbientTraceDir) {
            $env:SEMBAZURU_TRACE_DIR = $ambientTraceDir
        } else {
            Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $trace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

$candidate = Invoke-TraceProbe $CandidateDll 'candidate' -RequireOneWritePerRecord
$freeLibrary = Invoke-TraceProbe $CandidateDll 'candidate-free-library' -FreeLibrary -RequireOneWritePerRecord
Write-Host "candidate WriteOperationCount=$($candidate.Writes) records=$($candidate.Records)"
Write-Host "candidate FreeLibrary WriteOperationCount=$($freeLibrary.Writes) records=$($freeLibrary.Records)"

if (-not $BaselineDll) {
    Remove-Item -LiteralPath $script:ProbeInput -Force -ErrorAction SilentlyContinue
    exit 0
}
if (-not $FunctionalOnly -and -not $ExpectNoDifference -and $Iterations -ne 100000) {
    throw 'the local wall gate is fixed at Iterations=100000'
}
if ($ExpectNoDifference -and $Iterations -ne 10000) {
    throw 'the negative-control sanity gate is fixed at Iterations=10000'
}

function Get-Median {
    param([double[]]$Values)
    $ordered = @($Values | Sort-Object)
    $middle = [int]($ordered.Count / 2)
    if ($ordered.Count % 2 -eq 1) { return [double]$ordered[$middle] }
    return ([double]$ordered[$middle - 1] + [double]$ordered[$middle]) / 2.0
}

function Measure-Leg {
    param([string]$Dll, [string]$Label, [switch]$Candidate, [int]$Runs)
    $launcherChildSamples = @()
    $canaryTicks = @()
    $hookLoopTicks = @()
    for ($run = 0; $run -lt $Runs; ++$run) {
        $result = Invoke-TraceProbe $Dll "$Label-$run" -RequireOneWritePerRecord:$Candidate -StructureOnly
        $launcherChildSamples += [double]$result.ProcessElapsedMilliseconds
        $canaryTicks += [UInt64]$result.CanaryTicks
        $hookLoopTicks += [UInt64]$result.HookLoopTicks
    }
    $minimum = @($launcherChildSamples | Measure-Object -Minimum).Minimum
    $hookLoopMinimum = @($hookLoopTicks | Measure-Object -Minimum).Minimum
    Write-Host ("{0} launcher-child-samples-ms=[{1}] launcher-child-min-ms={2:N3} canary-ticks=[{3}] hook-loop-ticks=[{4}] hook-loop-min-ticks={5}" -f $Label,
                (($launcherChildSamples | ForEach-Object { '{0:N3}' -f $_ }) -join ', '),
                $minimum, ($canaryTicks -join ', '), ($hookLoopTicks -join ', '), $hookLoopMinimum)
    return [pscustomobject]@{
        LauncherChildSamples = [double[]]$launcherChildSamples
        LauncherChildMinimum = [double]$minimum
        CanaryTicks = [UInt64[]]$canaryTicks
        HookLoopTicks = [UInt64[]]$hookLoopTicks
        Minimum = [double]$minimum
        HookLoopMinimum = [UInt64]$hookLoopMinimum
    }
}

function Get-OneSidedWilcoxonP {
    param([double[]]$Deltas)
    $nonzero = @($Deltas | Where-Object { $_ -ne 0 })
    if ($nonzero.Count -eq 0) { return 1.0 }
    $indexed = for ($i = 0; $i -lt $nonzero.Count; ++$i) {
        [pscustomobject]@{ Index = $i; Absolute = [Math]::Abs([double]$nonzero[$i]); Positive = ([double]$nonzero[$i] -gt 0) }
    }
    $sorted = @($indexed | Sort-Object Absolute)
    $ranks = New-Object double[] $nonzero.Count
    $position = 0
    while ($position -lt $sorted.Count) {
        $end = $position + 1
        while ($end -lt $sorted.Count -and $sorted[$end].Absolute -eq $sorted[$position].Absolute) { ++$end }
        $rank = (($position + 1) + $end) / 2.0
        for ($j = $position; $j -lt $end; ++$j) { $ranks[$sorted[$j].Index] = $rank }
        $position = $end
    }
    $observed = 0.0
    for ($i = 0; $i -lt $nonzero.Count; ++$i) { if ($nonzero[$i] -gt 0) { $observed += $ranks[$i] } }
    $atLeast = 0
    $permutations = 1 -shl $nonzero.Count
    for ($mask = 0; $mask -lt $permutations; ++$mask) {
        $sum = 0.0
        for ($i = 0; $i -lt $nonzero.Count; ++$i) { if (($mask -band (1 -shl $i)) -ne 0) { $sum += $ranks[$i] } }
        if ($sum -ge $observed) { ++$atLeast }
    }
    return [double]$atLeast / [double]$permutations
}

function Get-BootstrapMedianLower {
    param([double[]]$Deltas)
    $random = [System.Random]::new(20260717)
    $replicates = New-Object double[] 10000
    for ($replicate = 0; $replicate -lt $replicates.Length; ++$replicate) {
        $resample = New-Object double[] $Deltas.Length
        for ($i = 0; $i -lt $Deltas.Length; ++$i) { $resample[$i] = $Deltas[$random.Next($Deltas.Length)] }
        $replicates[$replicate] = Get-Median $resample
    }
    $ordered = @($replicates | Sort-Object)
    return [double]$ordered[[int][Math]::Floor(0.025 * $ordered.Count)]
}

# The older 9-pair / 1,000 and 10,000-call pilots recorded 7/9 wins despite a
# positive median, so they are intentionally not pooled here.  This one set is
# the only decision: AB/BA order and three fresh processes per leg.  A pair is
# accepted only when its six fixed-work canary samples are within 1.25x.
$baselineSanity = Invoke-TraceProbe $BaselineDll 'baseline'
if (-not $ExpectNoDifference -and $baselineSanity.Writes -le $Iterations) {
    throw "baseline did not prove the pre-batching write amplification: $($baselineSanity.Writes)"
}
Write-Host "baseline WriteOperationCount=$($baselineSanity.Writes) records=$($baselineSanity.Records)"
if (Compare-Object -ReferenceObject $candidate.Normalized -DifferenceObject $baselineSanity.Normalized) {
    throw 'candidate and baseline normalized v0 records differ'
}
if ($FunctionalOnly) {
    Remove-Item -LiteralPath $script:ProbeInput -Force -ErrorAction SilentlyContinue
    exit 0
}
$null = Measure-Leg $CandidateDll 'warmup-candidate' -Candidate -Runs 2
$null = Measure-Leg $BaselineDll 'warmup-baseline' -Candidate:$ExpectNoDifference -Runs 2

$deltas = @()
$baselineMins = @()
$validPairs = 0
$invalidPairs = 0
$attempt = 0
while ($validPairs -lt 20) {
    $firstCandidate = ($validPairs % 2 -eq 0)
    if ($firstCandidate) {
        $candidateLeg = Measure-Leg $CandidateDll "pair-$attempt-candidate" -Candidate -Runs 3
        $baselineLeg = Measure-Leg $BaselineDll "pair-$attempt-baseline" -Candidate:$ExpectNoDifference -Runs 3
    } else {
        $baselineLeg = Measure-Leg $BaselineDll "pair-$attempt-baseline" -Candidate:$ExpectNoDifference -Runs 3
        $candidateLeg = Measure-Leg $CandidateDll "pair-$attempt-candidate" -Candidate -Runs 3
    }
    $canarySamples = @($candidateLeg.CanaryTicks + $baselineLeg.CanaryTicks)
    $canaryMinimum = @($canarySamples | Measure-Object -Minimum).Minimum
    $canaryMaximum = @($canarySamples | Measure-Object -Maximum).Maximum
    $canaryRatio = [double]$canaryMaximum / [double]$canaryMinimum
    if ($canaryRatio -gt 1.25) {
        ++$invalidPairs
        Write-Host ("pair={0} order={1} INVALID canary-max-min-ratio={2:N3} canary-min-ticks={3} canary-max-ticks={4} candidate-hook-min-ticks={5} baseline-hook-min-ticks={6}" -f
                    $attempt, $(if ($firstCandidate) { 'AB' } else { 'BA' }), $canaryRatio,
                    $canaryMinimum, $canaryMaximum, $candidateLeg.HookLoopMinimum, $baselineLeg.HookLoopMinimum)
        if ($invalidPairs -gt 8) { throw "wall gate exceeded invalid-pair limit: invalid=$invalidPairs valid=$validPairs" }
        ++$attempt
        continue
    }
    $delta = $baselineLeg.LauncherChildMinimum - $candidateLeg.LauncherChildMinimum
    $deltas += [double]$delta
    $baselineMins += [double]$baselineLeg.LauncherChildMinimum
    Write-Host ("pair={0} valid={1}/20 order={2} canary-max-min-ratio={3:N3} candidate-min-ms={4:N3} baseline-min-ms={5:N3} delta-ms={6:N3} candidate-hook-min-ticks={7} baseline-hook-min-ticks={8}" -f
                $attempt, ($validPairs + 1), $(if ($firstCandidate) { 'AB' } else { 'BA' }), $canaryRatio,
                $candidateLeg.LauncherChildMinimum, $baselineLeg.LauncherChildMinimum, $delta,
                $candidateLeg.HookLoopMinimum, $baselineLeg.HookLoopMinimum)
    ++$validPairs
    ++$attempt
}

$medianDelta = Get-Median ([double[]]$deltas)
$medianBaseline = Get-Median ([double[]]$baselineMins)
$ratio = $medianDelta / $medianBaseline
$p = Get-OneSidedWilcoxonP ([double[]]$deltas)
$lower = Get-BootstrapMedianLower ([double[]]$deltas)
$gatePassed = $p -le 0.05 -and $lower -gt 0 -and $ratio -ge 0.02
Write-Host ("wall-gate valid-pairs=20 invalid-pairs={0} wilcoxon-one-sided-p={1:N6} bootstrap-median-95-lower-ms={2:N3} paired-median-ms={3:N3} baseline-median-ms={4:N3} improvement-ratio={5:P3}" -f
            $invalidPairs, $p, $lower, $medianDelta, $medianBaseline, $ratio)
if ($ExpectNoDifference) {
    if ($gatePassed) { throw 'negative-control sanity unexpectedly passed the normal wall gate' }
    Write-Host 'NEGATIVE CONTROL PASS: identical candidate/baseline was rejected by the normal wall gate'
    Remove-Item -LiteralPath $script:ProbeInput -Force -ErrorAction SilentlyContinue
    exit 0
}
if (-not $gatePassed) {
    throw "wall gate failed: p=$p lower=$lower ratio=$ratio"
}
Remove-Item -LiteralPath $script:ProbeInput -Force -ErrorAction SilentlyContinue
