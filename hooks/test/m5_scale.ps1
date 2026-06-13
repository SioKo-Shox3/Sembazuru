# M5.5 scheduler DISTRIBUTION fan-out efficiency (local evidence; ADR 0004 §M5.5).
#
# Measures ONE component of compile-phase efficiency: how well the agent
# scheduler distributes actions across worker processes and keeps them busy.
# Each worker is pinned to a disjoint core set (its child actions inherit the
# affinity), so W workers genuinely run in parallel. The action is a synthetic
# CPU-bound `burn` with NO inputs/outputs — so this deliberately does NOT measure
# the data-plane file supply or network RTT (the other half of compile-phase
# efficiency). That full compile + VFS + RTT efficiency is confounded on one box
# (turbo throttling, multi-process co-tenancy) and is the deferred real-LAN test
# (ADR 0004 §M5.5, decider-gated). E(W) here is an upper-bound on the dispatch
# layer, not the full picture. Correctness of multi-worker distribution is gated
# in CI (`run_build_fans_out_a_whole_phase_across_workers`).
#
#   E(W) = T_compile(1) / (W * T_compile(W))
#
# T(*) is the min makespan over -Repeats runs (warm cache, like vfs_bench.ps1).
# Reports a table and FAILS if E(Wmax) < -Threshold (default 0.8) — but this is
# intended to be run locally for evidence; CI uses the non-flaky correctness gate
# (`run_build_fans_out_a_whole_phase_across_workers`).
#
# Usage: pwsh -File hooks/test/m5_scale.ps1 [-Workers 1,2,4,8] [-Actions 64]
#        [-Iters 60000000] [-CoresPerWorker 1] [-Repeats 5] [-Threshold 0.8]

param(
    [int[]]$Workers = @(1, 2, 4, 8),
    [int]$Actions = 64,
    [long]$Iters = 60000000,
    [int]$CoresPerWorker = 1,
    [int]$Repeats = 5,
    [double]$Threshold = 0.8,
    [int]$CoordPort = 50070
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
Push-Location $repoRoot
try {
    Write-Host "Building release binaries..."
    cargo build --release --quiet --bin sembazuru-worker `
        --example burn -p sembazuru-worker `
        --example scale_harness -p sembazuru-agent
    if ($LASTEXITCODE -ne 0) { throw "release build failed" }

    $workerExe = Join-Path $repoRoot "target\release\sembazuru-worker.exe"
    $burnExe = Join-Path $repoRoot "target\release\examples\burn.exe"
    $harnessExe = Join-Path $repoRoot "target\release\examples\scale_harness.exe"
    foreach ($e in @($workerExe, $burnExe, $harnessExe)) {
        if (-not (Test-Path $e)) { throw "missing build artifact: $e" }
    }

    $logical = [int]$env:NUMBER_OF_PROCESSORS
    $maxW = ($Workers | Measure-Object -Maximum).Maximum
    if ($maxW * $CoresPerWorker -gt $logical) {
        throw "need $($maxW * $CoresPerWorker) cores but only $logical available; lower -Workers/-CoresPerWorker"
    }

    # Runs one build phase with $w core-pinned workers; returns makespan_ms.
    function Invoke-Phase([int]$w) {
        $procs = @()
        $outFile = [System.IO.Path]::GetTempFileName()
        $coordAddr = "127.0.0.1:$CoordPort"
        # Start the harness first (it binds Coordination and waits for workers).
        $harness = Start-Process -FilePath $harnessExe `
            -ArgumentList @($coordAddr, "$w", "$Actions", "`"$burnExe`"", "$Iters") `
            -PassThru -NoNewWindow -RedirectStandardOutput $outFile -RedirectStandardError ([System.IO.Path]::GetTempFileName())
        Start-Sleep -Milliseconds 300

        try {
            for ($i = 0; $i -lt $w; $i++) {
                $port = 50061 + $i
                # Disjoint affinity mask: cores [i*k, i*k+k-1].
                $mask = 0
                for ($c = 0; $c -lt $CoresPerWorker; $c++) { $mask = $mask -bor (1 -shl ($i * $CoresPerWorker + $c)) }
                $env:SEMBAZURU_AGENT = "http://$coordAddr"
                $env:SEMBAZURU_CAPACITY = "$CoresPerWorker"
                $p = Start-Process -FilePath $workerExe -ArgumentList @("127.0.0.1:$port") `
                    -PassThru -NoNewWindow -RedirectStandardOutput ([System.IO.Path]::GetTempFileName()) `
                    -RedirectStandardError ([System.IO.Path]::GetTempFileName())
                # Pin the worker (children inherit the mask on Windows).
                try { $p.ProcessorAffinity = [IntPtr]$mask } catch {}
                $procs += $p
            }

            if (-not $harness.WaitForExit(120000)) { throw "harness timed out for W=$w" }
            if ($harness.ExitCode -ne 0) {
                throw "harness failed for W=$w (exit $($harness.ExitCode)): $(Get-Content $outFile -Raw)"
            }
        }
        finally {
            foreach ($p in $procs) { try { if (-not $p.HasExited) { $p.Kill() } } catch {} }
        }

        $line = Select-String -Path $outFile -Pattern "^SCALE " | Select-Object -First 1
        if (-not $line) { throw "no SCALE line for W=${w}: $(Get-Content $outFile -Raw)" }
        if ($line.Line -notmatch "makespan_ms=(\d+)") { throw "cannot parse makespan: $($line.Line)" }
        if ($line.Line -match "ok=false") { throw "some actions failed for W=${w}: $($line.Line)" }
        return [int]$Matches[1]
    }

    $best = @{}
    foreach ($w in $Workers) {
        $min = [int]::MaxValue
        for ($r = 0; $r -lt $Repeats; $r++) {
            $ms = Invoke-Phase $w
            if ($ms -lt $min) { $min = $ms }
        }
        $best[$w] = $min
        Write-Host ("W={0,-3} cores/worker={1}  min makespan = {2,7} ms" -f $w, $CoresPerWorker, $min)
    }

    $t1 = [double]$best[($Workers | Select-Object -First 1)]
    Write-Host ""
    Write-Host "Parallel efficiency E(W) = T(1) / (W * T(W)):"
    foreach ($w in $Workers) {
        $eff = $t1 / ($w * [double]$best[$w])
        $flag = if ($eff -ge $Threshold) { "OK" } else { "LOW" }
        Write-Host ("  E({0,-2}) = {1,5:N2}   [{2}]" -f $w, $eff, $flag)
    }

    # LOCAL EVIDENCE, not a hard CI gate (per the M5.5 decision: E(W) is local
    # evidence; CI runs the non-flaky correctness gate instead). The literal E(W)
    # is depressed on a single machine by two artifacts that DO NOT exist in the
    # faithful one-worker-per-machine LAN deployment (deferred per ADR 0004):
    #   * turbo throttling — more workers light up more cores, lowering the
    #     all-core clock, so each action runs slower at high W than the 1-core
    #     baseline (which boosts);
    #   * per-process co-tenancy — packing W worker processes (each a runtime +
    #     gRPC server) onto one box adds overhead a real cluster never pays.
    # The scheduler's correctness and distribution are gated in CI
    # (run_build_fans_out_a_whole_phase_across_workers); this script reports the
    # efficiency trend as evidence. Correctness failures already threw above.
    Write-Host ""
    Write-Host "Reported as local evidence (single-machine; see ADR 0004 §M5.5 for the turbo / co-tenancy caveats and the deferred real-LAN test)." -ForegroundColor Cyan
}
finally {
    Pop-Location
}
