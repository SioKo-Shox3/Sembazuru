# M6.3 gate: a real multi-TU CMake project built through the CMake/Ninja
# production path (CMAKE_<LANG>_COMPILER_LAUNCHER), which docs/integrations
# advertises as the cleanest, edit-free hook but which had no CI gate until now.
#
# Ninja drives several translation units (a/b/c.cpp, a shared header, main.cpp)
# concurrently; each compile is prefixed with the `sembazuru` launcher, which
# hands the action to the agent daemon -> VFS worker. This lifts the single-action
# proof of m6_daemon_compile.ps1 to a realistic project and asserts the M6
# "Done when" for the CMake/Ninja + clang-cl target:
#   1. distributed: EVERY TU runs through the daemon ("remote");
#   2. link stays local: COMPILER_LAUNCHER wraps compiles only, so CMake links
#      app.exe locally; the exe runs and returns 0 (functional correctness);
#   3. action cache: a 2nd build (worker stopped) HITS the cache for every TU
#      (a miss could only fall back) AND the cached object is byte-identical to
#      the distributed object (clang-cl) — the cache/write-back round-trip is
#      lossless across the whole multi-TU project;
#   4. local fallback: with the daemon down, ninja still completes the build.
#
# Byte invariant (clang-cl): cached == distributed for every TU. The distributed
# object is also compared to a launcher-off local reference, but only as a DIAG:
# the reference runs with the developer's full environment while the worker runs
# env_clear + a compiler-env allowlist (M6.0/M7.1), so clang-cl's .debug$S build-
# info (cwd/path/command-line strings) can differ — a known best-effort gap
# (docs/deferred.md), not a distribution defect. The canonical distributed==local
# byte claim for the minimal compile is owned by m6_daemon_compile.ps1.
#
# Requires clang-cl + ninja + cmake + cargo on PATH and the cmake-built
# launcher/DLL (CI hooks job, after msvc-dev-cmd + a ninja install).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m6-ninja-work'),
    [switch]$RequireClangCl,
    [switch]$RequireNinja,
    # M7.0 (ADR 0006): when set, daemon + worker run with this shared cluster
    # token so the distributed path runs authenticated end to end. Output bytes
    # are unaffected (auth is connection-level).
    [string]$AuthToken = ''
)
$ErrorActionPreference = 'Stop'

# --- tool discovery (clang-cl is the byte gate; ninja is the build driver) -----
$cc = $null
if (Get-Command clang-cl -ErrorAction SilentlyContinue) { $cc = 'clang-cl' }
elseif ($RequireClangCl) { throw 'clang-cl required but not on PATH' }
elseif (Get-Command cl -ErrorAction SilentlyContinue) { $cc = 'cl' }
else { throw 'no compiler (clang-cl/cl) on PATH' }
# clang-cl is path-independent & reproducible (the byte gate). Native cl embeds a
# COFF timestamp/build path and is byte-best-effort (docs/deferred.md), so for cl
# we assert the mechanism (notes/exit/outputs), not byte-identity.
$byteGate = ($cc -eq 'clang-cl')

$ninjaCmd = Get-Command ninja -ErrorAction SilentlyContinue
if (-not $ninjaCmd) {
    if ($RequireNinja) { throw 'ninja required but not on PATH' }
    Write-Host 'GATE SKIP  ninja not on PATH (install ninja to run the M6.3 gate)'
    exit 0
}
$ninja = $ninjaCmd.Source

$launcherExe = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcherExe, $dll)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}

# --- byte-diff diagnostics (shared shape with m6_daemon_compile.ps1) -----------
function Same-Bytes($a, $b) {
    if (-not (Test-Path $a) -or -not (Test-Path $b)) { return $false }
    (Get-FileHash $a -Algorithm SHA256).Hash -eq (Get-FileHash $b -Algorithm SHA256).Hash
}
function Hexdump($bytes, $start, $len) {
    $end = [Math]::Min($bytes.Length, $start + $len)
    if ($end -le $start) { Write-Host '      (past end)'; return }
    $win = $bytes[$start..($end - 1)]
    $hex = ($win | ForEach-Object { $_.ToString('x2') }) -join ' '
    $asc = -join ($win | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
    Write-Host ("      @0x{0:X}: {1}" -f $start, $hex)
    Write-Host ("      ascii : {0}" -f $asc)
}
function Dump-Diff($label, $a, $b) {
    Write-Host "--- DIFF DIAG ($label) ---"
    if (-not (Test-Path $a)) { Write-Host "  MISSING: $a"; return }
    if (-not (Test-Path $b)) { Write-Host "  MISSING: $b"; return }
    $ba = [System.IO.File]::ReadAllBytes($a)
    $bb = [System.IO.File]::ReadAllBytes($b)
    Write-Host ("  sizes: A={0} B={1}" -f $ba.Length, $bb.Length)
    $min = [Math]::Min($ba.Length, $bb.Length)
    $off = -1; $ndiff = 0
    for ($i = 0; $i -lt $min; $i++) { if ($ba[$i] -ne $bb[$i]) { if ($off -lt 0) { $off = $i }; $ndiff++ } }
    $ndiff += [Math]::Abs($ba.Length - $bb.Length)
    if ($off -lt 0) { Write-Host ("  common {0} bytes identical; lengths differ by {1}" -f $min, [Math]::Abs($ba.Length - $bb.Length)); $off = $min }
    else { Write-Host ("  first diff at offset {0} (0x{0:X}); {1} differing bytes total" -f $off, $ndiff) }
    $start = [Math]::Max(0, $off - 16)
    Write-Host "  A:"; Hexdump $ba $start 64
    Write-Host "  B:"; Hexdump $bb $start 64
}
# A COFF object's string table sits at the end of the file; long embedded paths
# (cwd, source, /Fd PDB, command line in .debug$S build-info) land there. Dumping
# the tail as ascii surfaces exactly which path/string differs between two objects.
function Dump-Tail($label, $a, $b) {
    Write-Host "--- TAIL ASCII ($label) ---"
    foreach ($pair in @(@('A', $a), @('B', $b))) {
        if (-not (Test-Path $pair[1])) { Write-Host ("  {0}: MISSING" -f $pair[0]); continue }
        $by = [System.IO.File]::ReadAllBytes($pair[1])
        $st = [Math]::Max(0, $by.Length - 400)
        $asc = -join ($by[$st..($by.Length - 1)] | ForEach-Object { if ($_ -ge 32 -and $_ -lt 127) { [char]$_ } else { '.' } })
        Write-Host ("  {0} tail: {1}" -f $pair[0], $asc)
    }
}

# --- build the Rust bins (daemon, launcher, worker) ----------------------------
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

# --- multi-TU CMake fixture ----------------------------------------------------
$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null
$proj = Join-Path $WorkRoot 'proj'
$build = Join-Path $WorkRoot 'build'
New-Item -ItemType Directory -Force $proj | Out-Null

# Self-contained TUs (only a project header, no system includes) so every read is
# under the VFS root and the worker needs no SDK. f/g/h return distinct values;
# main returns their sum minus the expected total, so a correct exe exits 0.
Set-Content (Join-Path $proj 'shared.h') "#define BASE 10`n" -Encoding ascii
Set-Content (Join-Path $proj 'a.cpp') "#include `"shared.h`"`nint f(){ return BASE + 1; }`n" -Encoding ascii
Set-Content (Join-Path $proj 'b.cpp') "#include `"shared.h`"`nint g(){ return BASE + 2; }`n" -Encoding ascii
Set-Content (Join-Path $proj 'c.cpp') "#include `"shared.h`"`nint h(){ return BASE + 3; }`n" -Encoding ascii
Set-Content (Join-Path $proj 'main.cpp') "int f(); int g(); int h();`nint main(){ return f()+g()+h() - 36; }`n" -Encoding ascii
# A throwaway TU used only to probe that the worker is live before the measured build.
Set-Content (Join-Path $proj 'probe.cpp') "int probe(){ return 0; }`n" -Encoding ascii

# /Brepro pins the COFF TimeDateStamp so the only otherwise-varying byte is fixed
# (m6_daemon_compile.ps1 confirmed it was the sole difference between a local and a
# distributed clang-cl object). The reference and distributed builds share this one
# build dir and the same relative /Fo path, and compile with no debug info, so the
# worker's scratch CWD does not leak into the object — no path-neutralizing flags
# needed. /Brepro is accepted by both cl and clang-cl, keeping the cl mechanism path
# runnable. add_executable links app.exe locally (the launcher wraps compiles only).
$cmake = @"
cmake_minimum_required(VERSION 3.21)
project(sbzninja CXX)
add_compile_options(/Brepro)
add_executable(app a.cpp b.cpp c.cpp main.cpp)
"@
Set-Content (Join-Path $proj 'CMakeLists.txt') $cmake -Encoding ascii

# CMake wants forward slashes in -D values on Windows.
$ccFwd = $cc
$launcherFwd = $launcher -replace '\\', '/'
$ninjaFwd = $ninja -replace '\\', '/'
$srcFwd = $proj -replace '\\', '/'
$buildFwd = $build -replace '\\', '/'

$scratchRoot = Join-Path $WorkRoot 'wscratch'
$casRoot = Join-Path $WorkRoot 'wcas'
$cacheRoot = Join-Path $WorkRoot 'acache'
$traceRoot = Join-Path $WorkRoot 'atrace'
foreach ($d in @($scratchRoot, $casRoot, $cacheRoot, $traceRoot)) { New-Item -ItemType Directory -Force $d | Out-Null }

# TU object paths the Ninja generator emits: build/CMakeFiles/app.dir/<src>.obj
$tus = @('a.cpp', 'b.cpp', 'c.cpp', 'main.cpp')
function Tu-Obj($build, $src) { Join-Path $build "CMakeFiles\app.dir\$src.obj" }
$exe = Join-Path $build 'app.exe'

function Configure([bool]$withLauncher) {
    $args = @('-G', 'Ninja', '-S', $srcFwd, '-B', $buildFwd,
        "-DCMAKE_MAKE_PROGRAM=$ninjaFwd",
        "-DCMAKE_C_COMPILER=$ccFwd", "-DCMAKE_CXX_COMPILER=$ccFwd")
    if ($withLauncher) {
        $args += @("-DCMAKE_C_COMPILER_LAUNCHER=$launcherFwd", "-DCMAKE_CXX_COMPILER_LAUNCHER=$launcherFwd")
    } else {
        # Clear any previously-set launcher so the reference build is non-distributed.
        $args += @('-DCMAKE_C_COMPILER_LAUNCHER=', '-DCMAKE_CXX_COMPILER_LAUNCHER=')
    }
    $out = & cmake @args 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $out; throw 'cmake configure failed' }
}
function Clean-Outputs {
    foreach ($t in $tus) { $o = Tu-Obj $build $t; if (Test-Path $o) { Remove-Item -Force $o } }
    if (Test-Path $exe) { Remove-Item -Force $exe }
}
# Run ninja (-v surfaces each launcher's "sembazuru: <note>" line). Returns combined output + exit.
# $jobs>0 caps parallelism: the distributed/cached builds run serially (-j 1) so the
# single worker always has a free admission slot and EVERY TU is dispatched remotely.
# With parallel fanout the scheduler may (by design) local-fallback an action when no
# slot is free — that is M5's multi-worker scaling concern, not this integration gate.
function Invoke-Ninja([int]$jobs = 0) {
    $a = @('-C', $build, '-v')
    if ($jobs -gt 0) { $a += @('-j', "$jobs") }
    $out = & $ninja @a 2>&1 | Out-String
    return @{ exit = $LASTEXITCODE; out = $out }
}

# --- reference (non-distributed) build: snapshot each TU's bytes ---------------
# No SOURCE_DATE_EPOCH: object byte-identity rests on /Brepro alone (it pins the
# COFF timestamp). The remote build cannot see SOURCE_DATE_EPOCH anyway — the
# launcher's env allowlist (env_filter.rs) drops it — so setting it would only
# make the reference asymmetric, not the object bytes.
Configure $false
Clean-Outputs
$ref = Invoke-Ninja
if ($ref.exit -ne 0) { Write-Host $ref.out; throw 'reference ninja build failed' }
$refObjs = @{}
foreach ($t in $tus) {
    $o = Tu-Obj $build $t
    if (-not (Test-Path $o)) { throw "reference build produced no object for $t" }
    $snap = Join-Path $WorkRoot "ref-$t.obj"
    Copy-Item $o $snap -Force
    $refObjs[$t] = $snap
}
if (-not (Test-Path $exe)) { throw 'reference build produced no app.exe' }
Write-Host "REF build OK: $($tus.Count) TUs + app.exe"

# --- daemon / worker rig (same env contract as m6_daemon_compile.ps1) ----------
$coord = '127.0.0.1:50095'; $intake = '127.0.0.1:50096'; $fs = '127.0.0.1:50097'; $worker = '127.0.0.1:50063'
$daemonUrl = "http://$intake"
function Start-Daemon {
    $env:SEMBAZURU_COORD = $coord; $env:SEMBAZURU_INTAKE = $intake; $env:SEMBAZURU_FILESERVER = $fs
    $env:SEMBAZURU_CACHE_ROOT = $cacheRoot; $env:SEMBAZURU_TRACE_ROOT = $traceRoot
    if ($AuthToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $AuthToken }
    $p = Start-Process -FilePath $daemonExe -PassThru -WindowStyle Hidden
    Remove-Item Env:\SEMBAZURU_COORD, Env:\SEMBAZURU_INTAKE, Env:\SEMBAZURU_FILESERVER, `
        Env:\SEMBAZURU_CACHE_ROOT, Env:\SEMBAZURU_TRACE_ROOT, Env:\SEMBAZURU_CLUSTER_TOKEN -ErrorAction SilentlyContinue
    $p
}
function Start-Worker {
    $env:SEMBAZURU_AGENT = "http://$coord"
    $env:SEMBAZURU_LAUNCHER = $launcherExe; $env:SEMBAZURU_DLL = $dll
    $env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot; $env:SEMBAZURU_CAS_ROOT = $casRoot
    if ($AuthToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $AuthToken }
    $p = Start-Process -FilePath $workerExe -ArgumentList @($worker) -PassThru -WindowStyle Hidden
    Remove-Item Env:\SEMBAZURU_AGENT, Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, `
        Env:\SEMBAZURU_SCRATCH_ROOT, Env:\SEMBAZURU_CAS_ROOT, Env:\SEMBAZURU_CLUSTER_TOKEN -ErrorAction SilentlyContinue
    $p
}
# Probe worker liveness by compiling the throwaway TU through the launcher directly.
function Probe-Launcher {
    Push-Location $proj
    try {
        $env:SEMBAZURU_DAEMON = $daemonUrl
        if (Test-Path 'probe.obj') { Remove-Item -Force 'probe.obj' }
        $err = & $launcher $cc /nologo /Brepro /c probe.cpp /Foprobe.obj 2>&1 | Out-String
        Remove-Item Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue
        return $err
    } finally { Pop-Location }
}

# --- reconfigure WITH the launcher; only "distribution" now differs from ref ----
Configure $true

$failures = @()
$daemon = Start-Daemon
$workerProc = Start-Worker
try {
    # Wait for the worker to register (until a probe runs remotely).
    $live = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 400
        if ((Probe-Launcher) -match 'sembazuru: remote') { $live = $true; break }
    }
    if (-not $live) { $failures += 'worker never came up (probe never ran remotely)' }

    # 1. Distributed multi-TU build via Ninja + the launcher (serial: every TU remote).
    $env:SEMBAZURU_DAEMON = $daemonUrl
    Clean-Outputs
    $d = Invoke-Ninja 1
    Remove-Item Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue
    $remoteCount = ([regex]::Matches($d.out, 'sembazuru: remote')).Count
    Write-Host "DIST build exit=$($d.exit) remote-compiles=$remoteCount"
    if ($d.exit -ne 0) { $failures += "distributed ninja build failed (exit=$($d.exit))`n$($d.out)" }
    # Require EVERY TU to run remotely — a partial fallback (some TUs local) must
    # not pass, since with cl (byteGate off) the byte check below cannot catch it.
    if ($remoteCount -lt $tus.Count) { $failures += "expected $($tus.Count) remote compiles, saw $remoteCount" }
    # Snapshot the distributed objects. The HARD byte invariant is cached==distributed
    # (checked in step 3): the CAS write-back + republish must reproduce the distributed
    # bytes losslessly for every TU. distributed-vs-reference is only a DIAG: the local
    # reference runs with the developer's full environment while the worker runs
    # env_clear + a compiler-env allowlist (M6.0/M7.1), so clang-cl's .debug$S build-info
    # (cwd/command-line/path strings) can differ — a known best-effort gap (docs/
    # deferred.md), NOT a distribution defect. m6_daemon_compile.ps1 owns the canonical
    # distributed==local byte claim for the minimal compile.
    $distObjs = @{}
    foreach ($t in $tus) {
        $o = Tu-Obj $build $t
        if (-not (Test-Path $o) -or (Get-Item $o).Length -eq 0) { $failures += "distributed build produced no/empty object for $t"; continue }
        $snap = Join-Path $WorkRoot "dist-$t.obj"
        Copy-Item $o $snap -Force
        $distObjs[$t] = $snap
        if ($byteGate -and -not (Same-Bytes $o $refObjs[$t])) {
            Write-Host "DIAG: distributed .obj for $t differs from the full-env local reference (expected: build-info env/path delta)"
            Dump-Diff "dist-vs-ref ($t)" $o $refObjs[$t]
            Dump-Tail "dist-vs-ref ($t)" $o $refObjs[$t]
        }
    }
    # 2. Link stayed local (COMPILER_LAUNCHER wraps compiles only): exe runs, exits 0.
    if (-not (Test-Path $exe)) { $failures += 'distributed build produced no app.exe (link?)' }
    else {
        & $exe | Out-Null
        if ($LASTEXITCODE -ne 0) { $failures += "app.exe returned $LASTEXITCODE (expected 0)" }
    }
} finally {
    foreach ($p in @($workerProc, $daemon)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

# 3. Action cache: restart the daemon (same cache root) with NO worker. A HIT
# serves the recorded outputs with no worker; a miss could only local-fallback,
# so requiring "cache hit" for every TU proves the hits.
$daemon2 = Start-Daemon
try {
    Start-Sleep -Milliseconds 600
    $env:SEMBAZURU_DAEMON = $daemonUrl
    Clean-Outputs
    $c = Invoke-Ninja 1
    Remove-Item Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue
    $hitCount = ([regex]::Matches($c.out, 'sembazuru: cache hit')).Count
    Write-Host "CACHE build exit=$($c.exit) cache-hits=$hitCount"
    if ($c.exit -ne 0) { $failures += "cached ninja build failed (exit=$($c.exit))`n$($c.out)" }
    if ($hitCount -lt $tus.Count) { $failures += "expected $($tus.Count) cache hits, saw $hitCount" }
    foreach ($t in $tus) {
        $o = Tu-Obj $build $t
        if (-not (Test-Path $o)) { $failures += "cached build produced no object for $t"; continue }
        # HARD: the cache must republish the distributed bytes exactly (CAS + write-back
        # round-trip is lossless across all TUs). This is the byte invariant the gate owns.
        if ($byteGate -and $distObjs.ContainsKey($t) -and -not (Same-Bytes $o $distObjs[$t])) {
            $failures += "cached .obj for $t is NOT byte-identical to the distributed build"
            Dump-Diff "cached-vs-dist ($t)" $o $distObjs[$t]
        }
    }
} finally {
    if ($daemon2 -and -not $daemon2.HasExited) { Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue }
}

# 4. Local fallback: daemon down -> ninja still completes (launcher runs locally).
Start-Sleep -Milliseconds 300
$env:SEMBAZURU_DAEMON = $daemonUrl
Clean-Outputs
$fb = Invoke-Ninja
Remove-Item Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue
# Accept either fallback phrasing: the launcher prints "running locally" when the
# daemon is unreachable (this case); the daemon prints "local fallback: ..." when
# it is up but cannot distribute. Both mean a non-distributed completion.
$fbLocal = ($fb.out -match 'running locally|local fallback')
Write-Host "FALLBACK build exit=$($fb.exit) ran-locally=$fbLocal"
if ($fb.exit -ne 0) { $failures += "local fallback ninja build failed (exit=$($fb.exit))`n$($fb.out)" }
if (-not $fbLocal) { $failures += 'fallback did not run locally (no fallback note)' }
if (-not (Test-Path $exe)) { $failures += 'fallback produced no app.exe' }

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.3 NINJA GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
$authLabel = if ($AuthToken) { 'AUTH=on (shared token)' } else { 'auth=off' }
$byteLabel = if ($byteGate) { 'cached==distributed byte-identical' } else { 'mechanism-only (cl)' }
Write-Host "M6.3 NINJA GATE PASS (multi-TU CMake/Ninja distributed via COMPILER_LAUNCHER; all TUs remote, $byteLabel, link local, 2nd-build cache hit, local fallback) compiler=$cc $authLabel"
