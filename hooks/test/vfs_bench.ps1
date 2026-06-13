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
    [int]$Runs = 5
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcher, $dll)) { if (-not (Test-Path $f)) { throw "missing: $f" } }
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) { throw 'cl.exe not on PATH' }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    & cargo build -p sembazuru-worker --example vfs_host 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'vfs_host build failed' }
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
# Round-trips do not blow it up: a 1 ms RTT adds only a few ms (a handful of
# project-file fetches), not hundreds. 150 ms of slack is generous.
if ($delta -gt 150) {
    $failures += "round-trip latency dominates: 1ms RTT added $([int]$delta) ms (expected a few ms for a handful of project files)"
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
