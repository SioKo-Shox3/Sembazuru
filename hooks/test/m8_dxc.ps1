# M8.4 Done-when gate: an ARBITRARY (non-compiler) process distributed with NO
# dedicated support. The workload is dxc (the HLSL shader compiler) — a single-
# process, no-children tool that resolves #includes like a C++ compiler. It runs
# through the SAME launcher -> daemon -> worker -> VFS path as clang-cl, with no
# dxc-specific code anywhere in the binaries (DESIGN §7 M8: "compilation-other
# workloads distribute with no dedicated support"). It exercises:
#   * M8.1 trace-based output discovery: dxc's `-Fo a.dxil` (space-separated) is
#     NOT inferred by the launcher, so the daemon must discover a.dxil from the
#     action trace to cache it — proving the cache is compiler-independent;
#   * M8.2 strict VFS (SEMBAZURU_VFS_STRICT=1): inputs under the root must be
#     supplied by the agent or the action fails -> local fallback. Here supply
#     works, so strict must NOT spuriously fire (a clean distributed build);
#   * the M8 Done-when triplet, same as the M6 compile gate:
#       1. distributed build byte-identical to a local build (dxc -Qstrip_debug
#          is byte-reproducible same-dir AND cross-dir — ADR 0007 appendix);
#       2. local fallback completes with the daemon down;
#       3. a 2nd identical build HITS the action cache (worker stopped, so a miss
#          could only fall back) and reproduces the bytes.
#
# Single-machine model (reads redirect through the VFS; the .dxil is written to
# the local output path). Requires dxc (+ dxcompiler.dll/dxil.dll beside it) and
# cargo on PATH, and the cmake-built launcher/DLL (CI hooks job).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m8-dxc-work'),
    # Path to dxc.exe. Default: PATH, else a couple of well-known SDK locations.
    [string]$DxcPath = '',
    # When set, fail hard if dxc cannot be found (CI). Locally, a missing dxc
    # SKIPs (exit 0) so the gate is opt-in off-CI.
    [switch]$RequireDxc,
    # M8.5: mark the action non-deterministic (SEMBAZURU_NONDETERMINISTIC=1). It
    # must still DISTRIBUTE (build 1 runs remotely), but must NOT be cached — so
    # build 2 (worker stopped) does NOT hit the cache and instead falls back
    # locally (ADR 0007 §c: separate distribution from caching). Proves the flag
    # controls caching, using the same real dxc workload. (dxc is actually
    # deterministic, so the locally-fallen-back .dxil still byte-matches — we are
    # testing the policy switch, the mechanism a genuine test runner would use.)
    [switch]$NonDeterministic,
    # Shared cluster token (ADR 0006): when set the whole distributed path runs
    # authenticated. The .dxil must still be byte-identical (auth is connection
    # level). Empty = unauthenticated LAN start (default).
    [string]$AuthToken = ''
)
$ErrorActionPreference = 'Stop'

$launcherExe = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcherExe, $dll)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}

# Resolve dxc: explicit param > PATH > known SDK locations.
function Resolve-Dxc {
    if ($DxcPath -and (Test-Path $DxcPath)) { return (Resolve-Path $DxcPath).Path }
    $onPath = Get-Command dxc -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $cands = @()
    if ($env:VULKAN_SDK) { $cands += (Join-Path $env:VULKAN_SDK 'Bin\dxc.exe') }
    # Windows SDK ships dxc.exe (+ dxcompiler.dll/dxil.dll) under bin\<ver>\x64.
    # Prefer the NEWEST version dir (sort descending). The gate is dxc-version-
    # agnostic — it compares ref vs distributed built by the SAME dxc — so any
    # SDK dxc that is deterministic with -Qstrip_debug works.
    $cands += Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin\*\x64\dxc.exe' -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | ForEach-Object FullName
    foreach ($c in $cands) { if ($c -and (Test-Path $c)) { return (Resolve-Path $c).Path } }
    return $null
}
$dxc = Resolve-Dxc
if (-not $dxc) {
    if ($RequireDxc) { throw 'dxc required but not found (PATH / VULKAN_SDK / Windows SDK)' }
    Write-Host 'M8.4 DXC GATE SKIP: dxc not found (pass -RequireDxc on CI)'
    exit 0
}
Write-Host "using dxc: $dxc"

function Same-Bytes($a, $b) {
    if (-not (Test-Path $a) -or -not (Test-Path $b)) { return $false }
    return (Get-FileHash $a -Algorithm SHA256).Hash -eq (Get-FileHash $b -Algorithm SHA256).Hash
}
function Dump-Diff($label, $a, $b) {
    Write-Host "--- DIFF DIAG ($label) ---"
    if (-not (Test-Path $a) -or -not (Test-Path $b)) { Write-Host "  missing file"; return }
    $ba = [System.IO.File]::ReadAllBytes($a); $bb = [System.IO.File]::ReadAllBytes($b)
    Write-Host ("  sizes: A={0} B={1}" -f $ba.Length, $bb.Length)
    $min = [Math]::Min($ba.Length, $bb.Length); $off = -1; $ndiff = 0
    for ($i = 0; $i -lt $min; $i++) { if ($ba[$i] -ne $bb[$i]) { if ($off -lt 0) { $off = $i }; $ndiff++ } }
    if ($off -lt 0) { Write-Host ("  common {0} identical; len diff {1}" -f $min, [Math]::Abs($ba.Length - $bb.Length)) }
    else { Write-Host ("  first diff @ {0} (0x{0:X}); {1} differing bytes" -f $off, $ndiff) }
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    & cargo build -q -p sembazuru-agent --bin sembazuru-daemon --bin sembazuru `
        -p sembazuru-worker --bin sembazuru-worker 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'bin build failed' }
} finally { Pop-Location }
$daemonExe = Join-Path $repo 'target\debug\sembazuru-daemon.exe'
$launcher = Join-Path $repo 'target\debug\sembazuru.exe'
$workerExe = Join-Path $repo 'target\debug\sembazuru-worker.exe'

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null
$daemonConfig = Join-Path $WorkRoot 'daemon-override.toml'
$workerConfig = Join-Path $WorkRoot 'worker-override.toml'

# A self-contained HLSL TU: a shader that #includes a project header, so every
# read is under the VFS root (no SDK include needed on the worker side). The
# #include exercises the small-file probe path the VFS is built for.
$proj = Join-Path $WorkRoot 'proj'
New-Item -ItemType Directory -Force $proj | Out-Null
Set-Content (Join-Path $proj 'common.hlsli') "float4 shade(float2 uv){ float s=0; [unroll] for(int i=0;i<5;i++) s+=uv.x*i-uv.y; return float4(s,uv,1); }`n" -Encoding ascii
Set-Content (Join-Path $proj 'main.hlsl') "#include `"common.hlsli`"`nfloat4 main(float2 uv : TEXCOORD0) : SV_Target { return shade(uv); }`n" -Encoding ascii

$scratchRoot = Join-Path $WorkRoot 'wscratch'; $casRoot = Join-Path $WorkRoot 'wcas'
$cacheRoot = Join-Path $WorkRoot 'acache'; $traceRoot = Join-Path $WorkRoot 'atrace'
foreach ($d in @($scratchRoot, $casRoot, $cacheRoot, $traceRoot)) { New-Item -ItemType Directory -Force $d | Out-Null }

# dxc args (shared by reference and distributed builds). -Qstrip_debug makes the
# DXIL byte-reproducible (ADR 0007 appendix: identical same-dir and cross-dir).
$dxcArgs = @('-T', 'ps_6_0', '-E', 'main', '-Qstrip_debug', '-Fo', 'a.dxil', 'main.hlsl')
$refDxil = Join-Path $proj 'ref.dxil'; $ref2Dxil = Join-Path $proj 'ref2.dxil'
$aDxil = Join-Path $proj 'a.dxil'

# Reference (local) build, twice, to confirm dxc is reproducible in this env.
Push-Location $proj
try {
    & $dxc @dxcArgs > refout.txt 2>&1
    if ($LASTEXITCODE -ne 0) { Get-Content refout.txt | Write-Host; throw 'reference dxc build failed' }
    Copy-Item $aDxil $refDxil -Force; Remove-Item $aDxil -Force
    & $dxc @dxcArgs > refout2.txt 2>&1
    if ($LASTEXITCODE -ne 0) { Get-Content refout2.txt | Write-Host; throw 'reference dxc build #2 failed' }
    Copy-Item $aDxil $ref2Dxil -Force; Remove-Item $aDxil -Force
} finally { Pop-Location }
if (Same-Bytes $refDxil $ref2Dxil) { Write-Host 'DIAG: dxc is deterministic in this env (ref == ref2)' }
else { Write-Host 'DIAG: dxc NON-deterministic in this env (ref != ref2)'; Dump-Diff 'ref-vs-ref2' $refDxil $ref2Dxil }

$coord = '127.0.0.1:50190'; $fs = '127.0.0.1:50192'; $worker = '127.0.0.1:50161'
$daemonUrl = 'npipe://Sembazuru.LocalIntake.v1'

function Start-Daemon {
    $hadConfig = Test-Path Env:\SEMBAZURU_CONFIG
    $oldConfig = $env:SEMBAZURU_CONFIG
    try {
        $env:SEMBAZURU_CONFIG = $daemonConfig
        $env:SEMBAZURU_COORD = $coord; $env:SEMBAZURU_INTAKE = $daemonUrl; $env:SEMBAZURU_FILESERVER = $fs
        $env:SEMBAZURU_CACHE_ROOT = $cacheRoot; $env:SEMBAZURU_TRACE_ROOT = $traceRoot
        if ($AuthToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $AuthToken }
        $p = Start-Process -FilePath $daemonExe -PassThru -WindowStyle Hidden
    } finally {
        Remove-Item Env:\SEMBAZURU_COORD, Env:\SEMBAZURU_INTAKE, Env:\SEMBAZURU_FILESERVER, `
            Env:\SEMBAZURU_CACHE_ROOT, Env:\SEMBAZURU_TRACE_ROOT, Env:\SEMBAZURU_CLUSTER_TOKEN `
            -ErrorAction SilentlyContinue
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
        $env:SEMBAZURU_AGENT = "http://$coord"
        $env:SEMBAZURU_LAUNCHER = $launcherExe; $env:SEMBAZURU_DLL = $dll
        $env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot; $env:SEMBAZURU_CAS_ROOT = $casRoot
        if ($AuthToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $AuthToken }
        $p = Start-Process -FilePath $workerExe -ArgumentList @($worker) -PassThru -WindowStyle Hidden
    } finally {
        Remove-Item Env:\SEMBAZURU_AGENT, Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, `
            Env:\SEMBAZURU_SCRATCH_ROOT, Env:\SEMBAZURU_CAS_ROOT, Env:\SEMBAZURU_CLUSTER_TOKEN `
            -ErrorAction SilentlyContinue
        if ($hadConfig) { $env:SEMBAZURU_WORKER_CONFIG = $oldConfig }
        else { Remove-Item Env:\SEMBAZURU_WORKER_CONFIG -ErrorAction SilentlyContinue }
    }
    $p
}
# Run dxc through the launcher with STRICT VFS on (M8.2): an unsuppliable input
# under the root would fail -> fallback; here supply works so it must not fire.
function Invoke-Launcher {
    Push-Location $proj
    try {
        $env:SEMBAZURU_DAEMON = $daemonUrl; $env:SEMBAZURU_VFS_STRICT = '1'
        if ($NonDeterministic) { $env:SEMBAZURU_NONDETERMINISTIC = '1' }
        if (Test-Path $aDxil) { Remove-Item -Force $aDxil }
        $err = & $launcher $dxc @dxcArgs 2>&1 | Out-String
        $code = $LASTEXITCODE
        Remove-Item Env:\SEMBAZURU_DAEMON, Env:\SEMBAZURU_VFS_STRICT, Env:\SEMBAZURU_NONDETERMINISTIC -ErrorAction SilentlyContinue
        return @{ exit = $code; note = $err }
    } finally { Pop-Location }
}

$failures = @()
$daemon = Start-Daemon
$workerProc = Start-Worker
try {
    $r = $null
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 400
        $r = Invoke-Launcher
        if ($r.note -match 'remote') { break }
    }
    Write-Host "BUILD1 exit=$($r.exit) note=$($r.note.Trim())"
    if ($r.exit -ne 0) { $failures += "distributed dxc build did not exit 0 (exit=$($r.exit))" }
    if ($r.note -notmatch 'remote') { $failures += 'build 1 never ran remotely (worker did not come up?)' }
    if (-not (Test-Path $aDxil)) { $failures += 'distributed build produced no .dxil' }
    if (-not (Same-Bytes $aDxil $refDxil)) {
        $failures += 'distributed .dxil is NOT byte-identical to the local build'
        Dump-Diff 'distributed-vs-ref' $aDxil $refDxil
    }
} finally {
    foreach ($p in @($workerProc, $daemon)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

# 2. Local fallback: daemon down -> the launcher builds locally.
Start-Sleep -Milliseconds 300
$rf = Invoke-Launcher
Write-Host "FALLBACK exit=$($rf.exit) note=$($rf.note.Trim())"
if ($rf.exit -ne 0) { $failures += "local fallback did not exit 0 (exit=$($rf.exit))" }
if (-not (Test-Path $aDxil) -or (Get-Item $aDxil).Length -eq 0) { $failures += 'local fallback produced no/empty .dxil' }
# dxc is path-independent and byte-reproducible, so the fallback should also match.
if ((Test-Path $aDxil) -and -not (Same-Bytes $aDxil $refDxil)) {
    Write-Host 'DIAG: fallback .dxil != ref (unexpected for dxc -Qstrip_debug)'; Dump-Diff 'fallback-vs-ref' $aDxil $refDxil
}

# 3. Action cache: restart the daemon (same cache root), NO worker. A hit serves
# the recorded output (discovered from the trace, M8.1) with no worker; a miss
# could only fall back, so requiring "cache hit" proves the hit.
$daemon2 = Start-Daemon
try {
    Start-Sleep -Milliseconds 500
    $rc = Invoke-Launcher
    Write-Host "BUILD2 exit=$($rc.exit) note=$($rc.note.Trim())"
    if ($rc.exit -ne 0) { $failures += "second build did not exit 0 (exit=$($rc.exit))" }
    if ($NonDeterministic) {
        # M8.5: a non-deterministic action is distributed but NEVER recorded, so
        # build 2 (no worker) must NOT hit the cache — it falls back locally.
        if ($rc.note -match 'cache hit') { $failures += 'non-deterministic action was cached (must distribute-but-not-cache, ADR 0007 §c)' }
    } else {
        if ($rc.note -notmatch 'cache hit') { $failures += 'second build did not HIT the action cache (trace-based output discovery, M8.1)' }
    }
    if (-not (Test-Path $aDxil)) { $failures += 'second build produced no .dxil' }
    if (-not (Same-Bytes $aDxil $refDxil)) {
        $failures += 'second-build .dxil is NOT byte-identical to the local build'
        Dump-Diff 'build2-vs-ref' $aDxil $refDxil
    }
} finally {
    if ($daemon2 -and -not $daemon2.HasExited) { Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M8.4 DXC GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
$authLabel = if ($AuthToken) { 'AUTH=on' } else { 'auth=off' }
if ($NonDeterministic) {
    Write-Host "M8.5 DXC NON-DETERMINISTIC GATE PASS (distributed but NOT cached: build2 did not hit, fell back locally) tool=dxc strict=on $authLabel"
} else {
    Write-Host "M8.4 DXC GATE PASS (arbitrary process distributed: byte-identical, local fallback, trace-discovered cache hit) tool=dxc strict=on $authLabel"
}
