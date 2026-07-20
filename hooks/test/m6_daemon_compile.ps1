# M6.1 core gate: a real compile through the PRODUCTION daemon path.
#
# The launcher (the form CMake emits as CMAKE_<LANG>_COMPILER_LAUNCHER:
# `sembazuru <compiler> <args>`) hands the compile to the agent daemon, which
# schedules it on a VFS-configured worker; the worker injects the hook DLL and
# supplies the inputs on demand from the daemon's file server. Asserts the M6
# "Done when" for the CMake/Ninja+clang-cl target:
#   1. distributed build: the .obj is byte-identical to a local build (clang-cl);
#   2. local fallback: with the daemon down, the launcher still builds locally;
#   3. action cache: a 2nd identical build HITS (compile skipped) and reproduces
#      the bytes, proven by stopping the worker so a miss could only fall back.
#
# Single-machine model: reads redirect through the VFS; the .obj is written to
# the local output path (a 2-machine writeback is deferred to real-LAN, ADR 0004).
# Requires cl/clang-cl + cargo on PATH and the cmake-built launcher/DLL (CI hooks).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m6-daemon-work'),
    [switch]$RequireClangCl,
    # M7.0 (ADR 0006): when set, the daemon and worker both run with this shared
    # cluster token, so the full distributed path (Register + data-plane Hello)
    # runs AUTHENTICATED end to end. The .obj must still be byte-identical — auth
    # is connection-level and does not touch compiler output. Empty = M5/M6
    # unauthenticated path (back-compat), which is the default gate.
    [string]$AuthToken = '',
    # P0: run the production VFS child-injection failure path after the normal
    # remote compile. This is opt-in so the historical M6.1 contract remains
    # unchanged for callers that do not request the additional failure gate.
    [switch]$RequireInjectionFallback
)
$ErrorActionPreference = 'Stop'

if ($RequireInjectionFallback -and $AuthToken) {
    throw 'RequireInjectionFallback is only defined for the unauthenticated M6.1 gate'
}
if ($RequireInjectionFallback -and [IntPtr]::Size -ne 8) {
    throw 'RequireInjectionFallback requires a 64-bit PowerShell host'
}

$launcherExe = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcherExe, $dll)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}
if ($RequireInjectionFallback) {
    $dll32 = Join-Path $BuildDir 'sbz_interceptor32.dll'
    $system32Cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $sysWow64Cmd = Join-Path $env:SystemRoot 'SysWOW64\cmd.exe'
    foreach ($f in @($dll32, $system32Cmd, $sysWow64Cmd)) {
        if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
            throw "missing injection-fallback artifact: $f"
        }
    }
}

# clang-cl is the byte-identity gate (path-independent); cl is best-effort but
# same-dir here, so we still byte-compare it.
$cc = $null
if (Get-Command clang-cl -ErrorAction SilentlyContinue) { $cc = 'clang-cl' }
elseif ($RequireClangCl) { throw 'clang-cl required but not on PATH' }
elseif (Get-Command cl -ErrorAction SilentlyContinue) { $cc = 'cl' }
else { throw 'no compiler (clang-cl/cl) on PATH' }

# Byte-identity is the clang-cl gate (path-independent, deterministic). Native cl
# embeds a COFF timestamp and is byte-best-effort (docs/deferred.md), so for cl we
# assert the mechanism (exit/notes/output produced), not byte-identity.
$byteGate = ($cc -eq 'clang-cl')

# --- diagnostic helpers (M7.0: capture WHY a byte mismatch happens) ----------
function Same-Bytes($a, $b) {
    if (-not (Test-Path $a) -or -not (Test-Path $b)) { return $false }
    $ha = (Get-FileHash $a -Algorithm SHA256).Hash
    $hb = (Get-FileHash $b -Algorithm SHA256).Hash
    return $ha -eq $hb
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
# On a mismatch, report sizes, the first differing offset, a hex+ascii window
# around it (an embedded path/string shows up in ascii), and the total number of
# differing bytes — enough to tell "one embedded path" from "codegen divergence".
function Dump-Diff($label, $a, $b) {
    Write-Host "--- DIFF DIAG ($label) ---"
    if (-not (Test-Path $a)) { Write-Host "  MISSING: $a"; return }
    if (-not (Test-Path $b)) { Write-Host "  MISSING: $b"; return }
    $ba = [System.IO.File]::ReadAllBytes($a)
    $bb = [System.IO.File]::ReadAllBytes($b)
    Write-Host ("  sizes: A={0} B={1}" -f $ba.Length, $bb.Length)
    $min = [Math]::Min($ba.Length, $bb.Length)
    $off = -1
    $ndiff = 0
    for ($i = 0; $i -lt $min; $i++) { if ($ba[$i] -ne $bb[$i]) { if ($off -lt 0) { $off = $i }; $ndiff++ } }
    $ndiff += [Math]::Abs($ba.Length - $bb.Length)
    if ($off -lt 0) {
        Write-Host ("  common {0} bytes identical; lengths differ by {1}" -f $min, [Math]::Abs($ba.Length - $bb.Length))
        $off = $min
    } else {
        Write-Host ("  first diff at offset {0} (0x{0:X}); {1} differing bytes total" -f $off, $ndiff)
    }
    $start = [Math]::Max(0, $off - 16)
    Write-Host "  A:"; Hexdump $ba $start 64
    Write-Host "  B:"; Hexdump $bb $start 64
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$workerBuildExtra = @()
if ($RequireInjectionFallback) { $workerBuildExtra = @('--example', 'exec_vfs') }
Push-Location $repo
try {
    & cargo build -q -p sembazuru-agent --bin sembazuru-daemon --bin sembazuru `
        -p sembazuru-worker --bin sembazuru-worker @workerBuildExtra 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'bin build failed' }
} finally { Pop-Location }
$daemonExe = Join-Path $repo 'target\debug\sembazuru-daemon.exe'
$launcher = Join-Path $repo 'target\debug\sembazuru.exe'
$workerExe = Join-Path $repo 'target\debug\sembazuru-worker.exe'
if ($RequireInjectionFallback) {
    $execVfs = Join-Path $repo 'target\debug\examples\exec_vfs.exe'
    if (-not (Test-Path -LiteralPath $execVfs -PathType Leaf)) {
        throw "missing injection-fallback driver: $execVfs"
    }
}

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null
if ($RequireInjectionFallback) {
    # Deliberately do not alter the canonical BuildDir artifacts: the worker
    # receives this private sibling pair, then the negative case removes only
    # the private x86 sibling.
    $runtimeSource = Join-Path $WorkRoot 'injection-runtime'
    New-Item -ItemType Directory -Force $runtimeSource | Out-Null
    $runtimeDll = Join-Path $runtimeSource 'sbz_interceptor64.dll'
    $runtimeDll32 = Join-Path $runtimeSource 'sbz_interceptor32.dll'
    Copy-Item -LiteralPath $dll -Destination $runtimeDll -Force
    Copy-Item -LiteralPath $dll32 -Destination $runtimeDll32 -Force
}
$daemonConfig = Join-Path $WorkRoot 'daemon-override.toml'
$workerConfig = Join-Path $WorkRoot 'worker-override.toml'

# A self-contained TU: only a project header, no system includes (so every read
# is under the VFS root and the gate needs no SDK on the worker side).
$proj = Join-Path $WorkRoot 'proj'
New-Item -ItemType Directory -Force $proj | Out-Null
Set-Content (Join-Path $proj 'shared.h') "#define SHARED_VALUE 42`n" -Encoding ascii
# The #pragma message prints a marker during compilation; we assert it reaches the
# launcher's console, proving remote stdout/stderr mirroring end to end (M6.1).
$diag = 'SBZ-REMOTE-DIAG-MARKER'
$remoteSuccessNote = 'sembazuru: remote'
function Test-RemoteSuccessNote([string]$note) {
    return (($note -split '\r?\n') -contains $remoteSuccessNote)
}
if (Test-RemoteSuccessNote $diag) { throw 'compiler diagnostic must not count as remote success' }
Set-Content (Join-Path $proj 'a.cpp') "#include `"shared.h`"`n#pragma message(`"$diag`")`nint f(){ return SHARED_VALUE; }`n" -Encoding ascii

$scratchRoot = Join-Path $WorkRoot 'wscratch'
$casRoot = Join-Path $WorkRoot 'wcas'
$cacheRoot = Join-Path $WorkRoot 'acache'
$traceRoot = Join-Path $WorkRoot 'atrace'
foreach ($d in @($scratchRoot, $casRoot, $cacheRoot, $traceRoot)) { New-Item -ItemType Directory -Force $d | Out-Null }

# Reference (local) build in the project dir, matched to the distributed build in
# two ways so the byte comparison is apples-to-apples:
#   * same output name (a.obj): the compiler embeds the object's own name
#     (S_OBJNAME), so a differently-named ref.obj would spuriously differ;
#   * NON-TTY stdio (redirected to a file): clang-cl's object depends on whether
#     stdout/stderr is a console, and a real build system (ninja/msbuild) and the
#     worker both run the compiler with piped (non-tty) handles. A raw console
#     reference would not match the piped distributed/fallback builds.
# Build a.obj, snapshot its bytes as ref.obj, then remove a.obj.
$refObj = Join-Path $proj 'ref.obj'
$ref2Obj = Join-Path $proj 'ref2.obj'
$distObj = Join-Path $proj 'dist.obj'   # snapshot of the distributed build (DIAG)
$fbObj = Join-Path $proj 'fb.obj'       # snapshot of the run_local fallback (DIAG)
$aObj = Join-Path $proj 'a.obj'
# /Brepro makes clang-cl emit a REPRODUCIBLE object: without it the COFF header's
# TimeDateStamp (offset 4) is the wall clock, so two builds a second apart differ
# in exactly that one field — which made this gate flaky (the distributed build
# lands a second or two after the local reference, only matching when they happen
# to share a wall-clock second). The byte difference was never distribution
# changing the output; it was the timestamp. /Brepro pins it to a sentinel so the
# comparison tests real content. (M7.0 CI diag: the only differing byte across
# ref/distributed/cached/fallback was offset 4, the timestamp.)
Push-Location $proj
try {
    cmd /c "$cc /nologo /Brepro /c a.cpp /Foa.obj > refout.txt 2>&1"
    if ($LASTEXITCODE -ne 0) { Get-Content refout.txt | Write-Host; throw 'reference build failed' }
    Copy-Item $aObj $refObj -Force
    Remove-Item $aObj -Force
    # Build the reference a SECOND time to prove clang-cl is itself reproducible
    # in this environment (ref == ref2 with /Brepro).
    cmd /c "$cc /nologo /Brepro /c a.cpp /Foa.obj > refout2.txt 2>&1"
    if ($LASTEXITCODE -ne 0) { Get-Content refout2.txt | Write-Host; throw 'reference build #2 failed' }
    Copy-Item $aObj $ref2Obj -Force
    Remove-Item $aObj -Force
} finally { Pop-Location }
if ($byteGate) {
    if (Same-Bytes $refObj $ref2Obj) {
        Write-Host "DIAG: reference clang-cl is deterministic in this env (ref == ref2)"
    } else {
        Write-Host "DIAG: reference clang-cl is NON-deterministic in this env (ref != ref2) — the byte flake is the compiler/runner, not the daemon path"
        Dump-Diff 'ref-vs-ref2' $refObj $ref2Obj
    }
}

$coord = '127.0.0.1:50090'; $fs = '127.0.0.1:50092'; $worker = '127.0.0.1:50061'
$daemonUrl = 'npipe://Sembazuru.LocalIntake.v1'

function Start-Daemon {
    $hadConfig = Test-Path Env:\SEMBAZURU_CONFIG
    $oldConfig = $env:SEMBAZURU_CONFIG
    $hadClusterToken = Test-Path Env:\SEMBAZURU_CLUSTER_TOKEN
    $oldClusterToken = $env:SEMBAZURU_CLUSTER_TOKEN
    try {
        $env:SEMBAZURU_CONFIG = $daemonConfig
        $env:SEMBAZURU_COORD = $coord; $env:SEMBAZURU_INTAKE = $daemonUrl; $env:SEMBAZURU_FILESERVER = $fs
        $env:SEMBAZURU_CACHE_ROOT = $cacheRoot; $env:SEMBAZURU_TRACE_ROOT = $traceRoot
        if ($AuthToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $AuthToken }
        else { Remove-Item Env:\SEMBAZURU_CLUSTER_TOKEN -ErrorAction SilentlyContinue }
        $p = Start-Process -FilePath $daemonExe -PassThru -WindowStyle Hidden
    } finally {
        Remove-Item Env:\SEMBAZURU_COORD, Env:\SEMBAZURU_INTAKE, Env:\SEMBAZURU_FILESERVER, `
            Env:\SEMBAZURU_CACHE_ROOT, Env:\SEMBAZURU_TRACE_ROOT `
            -ErrorAction SilentlyContinue
        if ($hadConfig) { $env:SEMBAZURU_CONFIG = $oldConfig }
        else { Remove-Item Env:\SEMBAZURU_CONFIG -ErrorAction SilentlyContinue }
        if ($hadClusterToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $oldClusterToken }
        else { Remove-Item Env:\SEMBAZURU_CLUSTER_TOKEN -ErrorAction SilentlyContinue }
    }
    $p
}
function Start-Worker {
    $hadConfig = Test-Path Env:\SEMBAZURU_WORKER_CONFIG
    $oldConfig = $env:SEMBAZURU_WORKER_CONFIG
    $hadClusterToken = Test-Path Env:\SEMBAZURU_CLUSTER_TOKEN
    $oldClusterToken = $env:SEMBAZURU_CLUSTER_TOKEN
    try {
        $env:SEMBAZURU_WORKER_CONFIG = $workerConfig
        $env:SEMBAZURU_AGENT = "http://$coord"
        $env:SEMBAZURU_LAUNCHER = $launcherExe
        $env:SEMBAZURU_DLL = if ($RequireInjectionFallback) { $runtimeDll } else { $dll }
        $env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot; $env:SEMBAZURU_CAS_ROOT = $casRoot
        if ($AuthToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $AuthToken }
        else { Remove-Item Env:\SEMBAZURU_CLUSTER_TOKEN -ErrorAction SilentlyContinue }
        $p = Start-Process -FilePath $workerExe -ArgumentList @($worker) -PassThru -WindowStyle Hidden
    } finally {
        Remove-Item Env:\SEMBAZURU_AGENT, Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, `
            Env:\SEMBAZURU_SCRATCH_ROOT, Env:\SEMBAZURU_CAS_ROOT `
            -ErrorAction SilentlyContinue
        if ($hadConfig) { $env:SEMBAZURU_WORKER_CONFIG = $oldConfig }
        else { Remove-Item Env:\SEMBAZURU_WORKER_CONFIG -ErrorAction SilentlyContinue }
        if ($hadClusterToken) { $env:SEMBAZURU_CLUSTER_TOKEN = $oldClusterToken }
        else { Remove-Item Env:\SEMBAZURU_CLUSTER_TOKEN -ErrorAction SilentlyContinue }
    }
    $p
}
# Run the launcher as the compiler wrapper; returns @{ exit; note } (note=stderr).
function Invoke-Launcher {
    Push-Location $proj
    try {
        $env:SEMBAZURU_DAEMON = $daemonUrl
        if (Test-Path $aObj) { Remove-Item -Force $aObj }
        $err = & $launcher $cc /nologo /Brepro /c a.cpp /Foa.obj 2>&1 | Out-String
        $code = $LASTEXITCODE
        Remove-Item Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue
        return @{ exit = $code; note = $err }
    } finally { Pop-Location }
}

function Restore-ProcessEnvironment([string]$Name, [bool]$HadValue, [string]$OldValue) {
    if ($HadValue) { Set-Item -LiteralPath "Env:$Name" -Value $OldValue }
    else { Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue }
}

function Get-ExactLineCount([string]$Text, [string]$Expected) {
    return @(($Text -split '\r?\n') | Where-Object { $_ -eq $Expected }).Count
}
$failures = @()
$daemon = Start-Daemon
$workerProc = Start-Worker
try {
    # Wait for the worker to register; retry the build until it runs remotely
    # (before registration completes, dispatch would local-fallback).
    $r = $null
    $remoteSucceeded = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 400
        $r = Invoke-Launcher
        $remoteSucceeded = Test-RemoteSuccessNote $r.note
        if ($remoteSucceeded) { break }
    }
    Write-Host "BUILD1 exit=$($r.exit) note=$($r.note.Trim())"
    if ($r.exit -ne 0) { $failures += "distributed build did not exit 0 (exit=$($r.exit))" }
    if (-not $remoteSucceeded) { $failures += 'build 1 never ran remotely (worker did not come up?)' }
    if (-not (Test-Path $aObj)) { $failures += 'distributed build produced no .obj' }
    # Remote stdout/stderr mirroring: the compiler's #pragma message must reach
    # the launcher's console (it ran on the worker, not here).
    if ($r.note -notmatch [regex]::Escape($diag)) { $failures += 'remote compiler diagnostics were NOT mirrored to the launcher (stdout/stderr streaming)' }
    if ($byteGate -and -not (Same-Bytes $aObj $refObj)) {
        $failures += 'distributed .obj is NOT byte-identical to the local build'
        Dump-Diff 'distributed-vs-ref' $aObj $refObj
    }
    # Snapshot the distributed object for the post-fallback comparison below.
    if (Test-Path $aObj) { Copy-Item $aObj $distObj -Force }

    if ($RequireInjectionFallback) {
        # Use only Windows' signed, readable cmd.exe pair here. The restricted
        # worker action token intentionally cannot execute a repo-local probe,
        # so this checks injection rather than an unrelated test-fixture ACL.
        $p0FailuresBefore = $failures.Count
        $p0Trace = Join-Path $WorkRoot 'p0-injection-trace'
        $p0SentinelDir = Join-Path $WorkRoot 'p0 fallback output'
        $p0Sentinel = Join-Path $p0SentinelDir 'local-fallback.sentinel'
        New-Item -ItemType Directory -Force $p0Trace | Out-Null
        New-Item -ItemType Directory -Force $p0SentinelDir | Out-Null
        # cmd.exe receives this as one argv element. The output directory has
        # spaces so the successful local fallback proves the production quoting
        # path; the VFS branch never touches that user-writable output path.
        $crossBitnessCommand = 'if /I "%SEMBAZURU_MODE%"=="vfs" ("' + $sysWow64Cmd +
            '" /d /c echo SBZ-REMOTE-UNINSTRUMENTED-CHILD) else (echo SBZ-LOCAL-FALLBACK>>"' +
            $p0Sentinel + '")'
        $oldNativeEap = $null
        $hasNativeEap = Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue
        if ($hasNativeEap) {
            $oldNativeEap = $PSNativeCommandUseErrorActionPreference
            $PSNativeCommandUseErrorActionPreference = $false
        }
        try {
            # a. A private sibling pair proves the positive 64->32 VFS child
            # injection path before the negative test takes the sibling away.
            $positiveOutput = & $execVfs "http://$worker" $fs $proj $p0Trace -- `
                $system32Cmd '/d' '/s' '/c' $crossBitnessCommand 2>&1 | Out-String
            $positiveExit = $LASTEXITCODE
            Write-Host "P0 direct positive exit=$positiveExit output=$($positiveOutput.Trim())"
            if ($positiveExit -ne 0 -or $positiveOutput -notmatch
                'exec_vfs:\s*states=\[\s*1\s*,\s*2\s*,\s*3\s*,\s*4\s*\]\s*exit=0') {
                $failures += 'P0 direct positive did not complete with states=[1, 2, 3, 4], exit=0'
            }
            if ((Get-ExactLineCount $positiveOutput 'SBZ-REMOTE-UNINSTRUMENTED-CHILD') -ne 1) {
                $failures += 'P0 direct positive did not emit exactly one remote child marker'
            }
            if (Test-Path -LiteralPath $p0Sentinel) {
                $failures += 'P0 direct positive unexpectedly ran the local fallback sentinel path'
                Remove-Item -LiteralPath $p0Sentinel -Force
            }

            # b. The removal is confined to the worker's isolated runtime source;
            # canonical BuildDir artifacts remain intact for the rest of the gate.
            Remove-Item -LiteralPath $runtimeDll32 -Force
            $negativeOutput = & $execVfs "http://$worker" $fs $proj $p0Trace -- `
                $system32Cmd '/d' '/s' '/c' $crossBitnessCommand 2>&1 | Out-String
            $negativeExit = $LASTEXITCODE
            Write-Host "P0 direct negative exit=$negativeExit output=$($negativeOutput.Trim())"
            if ($negativeOutput -notmatch
                'exec_vfs:\s*states=\[\s*1\s*,\s*2\s*,\s*3\s*,\s*5\s*\]\s*exit=-1') {
                $failures += 'P0 direct negative was not a worker Failed outcome (states=[1, 2, 3, 5], exit=-1)'
            }
            if ((Get-ExactLineCount $negativeOutput 'SBZ-REMOTE-UNINSTRUMENTED-CHILD') -ne 0) {
                $failures += 'P0 direct negative ran the remote child after injection failure'
            }
            if (Test-Path -LiteralPath $p0Sentinel) {
                $failures += 'P0 direct negative unexpectedly ran a local fallback outside the production scheduler'
                Remove-Item -LiteralPath $p0Sentinel -Force
            }

            # c. The daemon scheduler must translate that exact worker failure
            # into one local execution. Non-deterministic policy prevents a cache
            # entry from masking the failed remote action.
            $hadDaemon = Test-Path Env:\SEMBAZURU_DAEMON
            $oldDaemon = $env:SEMBAZURU_DAEMON
            $hadNonDeterministic = Test-Path Env:\SEMBAZURU_NONDETERMINISTIC
            $oldNonDeterministic = $env:SEMBAZURU_NONDETERMINISTIC
            try {
                $env:SEMBAZURU_DAEMON = $daemonUrl
                $env:SEMBAZURU_NONDETERMINISTIC = '1'
                $fallbackOutput = & $launcher $system32Cmd '/d' '/s' '/c' $crossBitnessCommand 2>&1 | Out-String
                $fallbackExit = $LASTEXITCODE
            } finally {
                Restore-ProcessEnvironment 'SEMBAZURU_DAEMON' $hadDaemon $oldDaemon
                Restore-ProcessEnvironment 'SEMBAZURU_NONDETERMINISTIC' $hadNonDeterministic $oldNonDeterministic
            }
            Write-Host "P0 scheduler fallback exit=$fallbackExit output=$($fallbackOutput.Trim())"
            if ($fallbackExit -ne 0) { $failures += "P0 scheduler fallback exited $fallbackExit" }
            if ($fallbackOutput -match 'SBZ-REMOTE-UNINSTRUMENTED-CHILD') {
                $failures += 'P0 scheduler fallback accepted remote child execution after injection failure'
            }
            if (Test-RemoteSuccessNote $fallbackOutput) {
                $failures += 'P0 scheduler fallback reported remote success after injection failure'
            }
            if ($fallbackOutput -match 'cache hit') {
                $failures += 'P0 scheduler fallback was masked by an action-cache hit'
            }
            if ($fallbackOutput -notmatch 'sembazuru: local fallback: worker .+ did not complete the action') {
                $failures += 'P0 scheduler fallback did not report the failed worker fallback reason'
            }
            if (-not (Test-Path -LiteralPath $p0Sentinel) -or
                (Get-ExactLineCount ((Get-Content -LiteralPath $p0Sentinel -Raw)) 'SBZ-LOCAL-FALLBACK') -ne 1) {
                $failures += 'P0 scheduler fallback did not run the local command exactly once'
            }
        } finally {
            if ($hasNativeEap) { $PSNativeCommandUseErrorActionPreference = $oldNativeEap }
        }
        if ($failures.Count -eq $p0FailuresBefore) {
            Write-Host 'P0 INJECTION FALLBACK PASS (positive cross-bitness remote completed; injection failure produced worker Failed; scheduler local fallback completed once)'
        }
    }
} finally {
    foreach ($p in @($workerProc, $daemon)) { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } }
}

# 2. Local fallback: daemon down → the launcher builds locally.
Start-Sleep -Milliseconds 300
$rf = Invoke-Launcher
Write-Host "FALLBACK exit=$($rf.exit) note=$($rf.note.Trim())"
# Local fallback is a plain local compile via run_local; the M6 "Done when" asks
# it to COMPLETE with a valid object, not to byte-match. (The distribution-
# correctness claim is carried by the strict distributed + cached byte checks; a
# residual run_local-vs-reference byte difference for clang-cl is noted in
# docs/deferred.md and does not affect a functionally-valid local build.)
if ($rf.exit -ne 0) { $failures += "local fallback did not exit 0 (exit=$($rf.exit))" }
if (-not (Test-Path $aObj) -or (Get-Item $aObj).Length -eq 0) { $failures += 'local fallback produced no/empty .obj' }
# M7.0 DIAG (not a gate failure): how does run_local relate to ref and to the
# distributed object? If distributed == fallback but both != ref, the launcher
# full-env forwarding (the M7.1 allowlist target) is the shared cause; if
# distributed == ref but fallback != ref, only run_local diverges (the known
# residual). This is the decisive split for the byte flake.
if ($byteGate -and (Test-Path $aObj)) {
    Copy-Item $aObj $fbObj -Force
    Write-Host ("DIAG: fallback==ref? {0}; distributed==ref? {1}; distributed==fallback? {2}" -f `
        (Same-Bytes $fbObj $refObj), (Same-Bytes $distObj $refObj), (Same-Bytes $distObj $fbObj))
    if (-not (Same-Bytes $fbObj $refObj)) { Dump-Diff 'fallback-vs-ref' $fbObj $refObj }
    if ((Test-Path $distObj) -and -not (Same-Bytes $distObj $fbObj)) { Dump-Diff 'distributed-vs-fallback' $distObj $fbObj }
}

# 3. Action cache: restart the daemon (same cache root) but DO NOT start a worker.
# A cache HIT serves the recorded output with no worker; a miss could only local-
# fallback, so requiring "cache hit" proves the hit.
$daemon2 = Start-Daemon
try {
    Start-Sleep -Milliseconds 500
    $rc = Invoke-Launcher
    Write-Host "BUILD2 exit=$($rc.exit) note=$($rc.note.Trim())"
    if ($rc.exit -ne 0) { $failures += "cached build did not exit 0 (exit=$($rc.exit))" }
    if ($rc.note -notmatch 'cache hit') { $failures += 'second build did not HIT the action cache' }
    if (-not (Test-Path $aObj)) { $failures += 'cached build produced no .obj' }
    if ($byteGate -and -not (Same-Bytes $aObj $refObj)) {
        $failures += 'cached .obj is NOT byte-identical to the local build'
        Dump-Diff 'cached-vs-ref' $aObj $refObj
    }
} finally {
    if ($daemon2 -and -not $daemon2.HasExited) { Stop-Process -Id $daemon2.Id -Force -ErrorAction SilentlyContinue }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.1 DAEMON COMPILE GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
$authLabel = if ($AuthToken) { 'AUTH=on (shared token)' } else { 'auth=off' }
$injectionLabel = if ($RequireInjectionFallback) { '; P0 injection fallback' } else { '' }
Write-Host "M6.1 DAEMON COMPILE GATE PASS (distributed byte-identical, local fallback, 2nd-build cache hit$injectionLabel) compiler=$cc $authLabel"
