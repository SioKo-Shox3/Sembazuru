# M6.1b gate: the WORKER DAEMON's Execute redirects reads through the VFS.
#
# Unlike vfs_redirect.ps1 (which drives launcher.exe directly against a
# co-located vfs_host), this proves the *production* path: a real
# `sembazuru-worker` process, told to run an action in VFS mode over gRPC
# (ExecuteRequest.vfs), starts its own per-action pipe, injects the hook DLL via
# launcher.exe, dials the agent file server, and hydrates the read into scratch.
#
# Provenance (same trick as vfs_redirect.ps1): the logical path holds STALE local
# bytes; the agent (remap) serves DIFFERENT correct bytes from a backing dir. The
# read is correct ONLY if the worker actually pulled from the agent through the
# VFS. The probe reads by relative and verbatim DOS paths and compares the bytes
# to the agent-served content, exiting 0 only on an exact match - so the action's
# own exit code proves both that the open was redirected (a non-redirected open
# would read the STALE local bytes) and the provenance (the bytes came from the
# agent).
#
# Why content, not the scratch file: since M9.2 (deferred #8) the worker removes the
# per-action hydrated scratch tree once the action completes, to bound a resident
# worker's disk. So the scratch copy no longer exists by the time this script could
# inspect it. Checking what the process actually READ (live, before cleanup) is the
# robust, eviction-proof way to prove the redirect - and a strictly stronger check
# than inspecting the hydrated file after the fact.
#
# Requires cl.exe + cargo on PATH and the cmake-built launcher/DLL (CI hooks job).
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\m6-vfs-work')
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$dll = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcher, $dll)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
    throw 'cl.exe not on PATH (run from a VS dev shell or after msvc-dev-cmd)'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
Push-Location $repo
try {
    & cargo build -q -p sembazuru-worker --bin sembazuru-worker `
        --example exec_vfs 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'worker bin/exec_vfs build failed' }
    & cargo build -q -p sembazuru-agent --example fileserver_host 2>&1 | Out-String | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'fileserver_host build failed' }
} finally { Pop-Location }
$workerExe = Join-Path $repo 'target\debug\sembazuru-worker.exe'
$execVfs = Join-Path $repo 'target\debug\examples\exec_vfs.exe'
$fsHost = Join-Path $repo 'target\debug\examples\fileserver_host.exe'

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# Probe: verify process-visible cwd/path APIs still expose the logical cwd, then
# make argv[1] absolute with GetFullPathNameW (common in runtimes/tools), probe
# its attributes before CreateFileW, open it read-only, read it, and assert the
# content EXACTLY equals argv[2] (the agent-served bytes). Because the worker may
# start from scratch, this exercises logical cwd preservation, attribute-probe
# hydration, scratch-absolute -> logical path remap, and relative cwd handling.
# Exit codes encode the provenance so the gate needs no post-run scratch file
# (cleaned up since M9.2):
#   0 = content matched the agent bytes  -> redirect + provenance proven
#   1 = open failed / read failed
#   2 = bad args
#   3 = content mismatch (STALE local bytes) -> NOT redirected through the VFS
#   4 = GetCurrentDirectoryW did not return the submitted logical cwd
#   5 = GetFullPathNameW did not resolve relative paths under the logical cwd
#   6 = GetFileAttributesW failed before CreateFileW hydrated the file
#   7 = wildcard enumeration unexpectedly reached the real filesystem
#   8 = SetCurrentDirectoryW failed
# Static CRT (/MT) so it needs no runtime DLL beyond the cleared+rebuilt env.
$probeSrc = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <wchar.h>
static int WideArgToAcp(const wchar_t* src, char* dst, int cap) {
    int n = WideCharToMultiByte(CP_ACP, 0, src, -1, dst, cap, nullptr, nullptr);
    return n > 0 && n <= cap ? n : 0;
}
int wmain(int argc, wchar_t** argv) {
    if (argc >= 3 && wcscmp(argv[1], L"--chdir") == 0) {
        return SetCurrentDirectoryW(argv[2]) ? 0 : 8;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--chdir-a") == 0) {
        char path[1024];
        if (!WideArgToAcp(argv[2], path, sizeof(path))) return 2;
        return SetCurrentDirectoryA(path) ? 0 : 8;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--wildcard-enum") == 0) {
        WIN32_FIND_DATAW data;
        HANDLE h = FindFirstFileW(argv[2], &data);
        if (h == INVALID_HANDLE_VALUE) return 0;
        FindClose(h);
        return 7;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--wildcard-enum-a") == 0) {
        char pattern[1024];
        if (!WideArgToAcp(argv[2], pattern, sizeof(pattern))) return 2;
        WIN32_FIND_DATAA data;
        HANDLE h = FindFirstFileA(pattern, &data);
        if (h == INVALID_HANDLE_VALUE) return 0;
        FindClose(h);
        return 7;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--wildcard-enum-exw") == 0) {
        WIN32_FIND_DATAW data;
        HANDLE h = FindFirstFileExW(argv[2], FindExInfoStandard, &data,
                                    FindExSearchNameMatch, nullptr, 0);
        if (h == INVALID_HANDLE_VALUE) return 0;
        FindClose(h);
        return 7;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--wildcard-enum-exa") == 0) {
        char pattern[1024];
        if (!WideArgToAcp(argv[2], pattern, sizeof(pattern))) return 2;
        WIN32_FIND_DATAA data;
        HANDLE h = FindFirstFileExA(pattern, FindExInfoStandard, &data,
                                    FindExSearchNameMatch, nullptr, 0);
        if (h == INVALID_HANDLE_VALUE) return 0;
        FindClose(h);
        return 7;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--find-exact") == 0) {
        WIN32_FIND_DATAW data;
        HANDLE h = FindFirstFileW(argv[2], &data);
        if (h == INVALID_HANDLE_VALUE) return 1;
        FindClose(h);
        return 0;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--find-exact-exw") == 0) {
        WIN32_FIND_DATAW data;
        HANDLE h = FindFirstFileExW(argv[2], FindExInfoStandard, &data,
                                    FindExSearchNameMatch, nullptr, 0);
        if (h == INVALID_HANDLE_VALUE) return 1;
        FindClose(h);
        return 0;
    }
    if (argc >= 3 && wcscmp(argv[1], L"--write-output") == 0) {
        HANDLE out = CreateFileW(argv[2], GENERIC_WRITE, 0, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (out == INVALID_HANDLE_VALUE) return 1;
        const char bytes[] = "scratch-output-must-not-complete-remotely";
        DWORD written = 0;
        BOOL ok = WriteFile(out, bytes, sizeof(bytes) - 1, &written, nullptr);
        CloseHandle(out);
        return ok && written == sizeof(bytes) - 1 ? 0 : 1;
    }
    if (argc >= 4 && wcscmp(argv[1], L"--open-exact") == 0) {
        if (GetFileAttributesW(argv[2]) == INVALID_FILE_ATTRIBUTES) return 6;
        HANDLE h = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) return 1;
        char buf[256]; DWORD r = 0;
        BOOL ok = ReadFile(h, buf, sizeof(buf), &r, nullptr);
        CloseHandle(h);
        if (!ok) return 1;
        char exp[256];
        int en = WideCharToMultiByte(CP_UTF8, 0, argv[3], -1, exp, sizeof(exp),
                                     nullptr, nullptr);
        if (en <= 1) return 2;
        DWORD elen = (DWORD)(en - 1);
        if (r != elen) return 3;
        return memcmp(buf, exp, elen) == 0 ? 0 : 3;
    }
    if (argc < 5) return 2;
    wchar_t cwd[1024];
    DWORD cn = GetCurrentDirectoryW(1024, cwd);
    if (cn == 0 || cn >= 1024 || wcscmp(cwd, argv[3]) != 0) return 4;
    wchar_t openPath[1024];
    DWORD pn = GetFullPathNameW(argv[1], 1024, openPath, nullptr);
    const wchar_t* path = (pn > 0 && pn < 1024) ? openPath : argv[1];
    if (wcscmp(path, argv[4]) != 0) return 5;
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return 6;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 1;
    char buf[256]; DWORD r = 0;
    BOOL ok = ReadFile(h, buf, sizeof(buf), &r, nullptr);
    CloseHandle(h);
    if (!ok) return 1;
    char exp[256];
    int en = WideCharToMultiByte(CP_UTF8, 0, argv[2], -1, exp, sizeof(exp),
                                 nullptr, nullptr);
    if (en <= 1) return 2;
    DWORD elen = (DWORD)(en - 1); // drop the NUL
    if (r != elen) return 3;
    return memcmp(buf, exp, elen) == 0 ? 0 : 3;
}
'@
Set-Content (Join-Path $WorkRoot 'probe.cpp') $probeSrc -Encoding ascii
Push-Location $WorkRoot
try {
    $o = & cl /nologo /EHsc /MT 'probe.cpp' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $o; throw 'probe compile failed' }
} finally { Pop-Location }
$probe = Join-Path $WorkRoot 'probe.exe'

# Layout: logical holds STALE bytes; backing holds CORRECT bytes the agent serves.
$logicalRoot = Join-Path $WorkRoot 'LoGiCaL'
$backingRoot = Join-Path $WorkRoot 'backing'
$scratchRoot = Join-Path $WorkRoot 'scratch'
$casRoot = Join-Path $WorkRoot 'cas'
$traceDir = Join-Path $WorkRoot 'trace'
$miscTraceDir = Join-Path $WorkRoot 'trace-misc'
$verbatimTraceDir = Join-Path $WorkRoot 'trace-verbatim'
$smuggledTraceDir = Join-Path $WorkRoot 'smuggled-trace'
$fakeVfsCwd = Join-Path $WorkRoot 'fake-vfs-cwd'
$rel = 'Src\Input.txt'
$correct = 'hello-from-the-agent-vfs'
$stale = 'STALE-LOCAL-MUST-NOT-BE-READ'
New-Item -ItemType Directory -Force (Split-Path (Join-Path $logicalRoot $rel)) | Out-Null
New-Item -ItemType Directory -Force (Split-Path (Join-Path $backingRoot $rel)) | Out-Null
foreach ($d in @($scratchRoot, $casRoot, $traceDir, $miscTraceDir, $verbatimTraceDir, $smuggledTraceDir, $fakeVfsCwd)) {
    New-Item -ItemType Directory -Force $d | Out-Null
}
Set-Content (Join-Path $logicalRoot $rel) $stale -Encoding ascii -NoNewline
Set-Content (Join-Path $backingRoot $rel) $correct -Encoding ascii -NoNewline

$fsAddr = '127.0.0.1:50082'
$workerPort = 50083
$workerAddr = "127.0.0.1:$workerPort"

# Agent file server in REMAP mode: paths under logicalRoot are served from backingRoot.
$fsProc = Start-Process -FilePath $fsHost -ArgumentList @($fsAddr, $logicalRoot, $backingRoot) `
    -PassThru -WindowStyle Hidden

# Worker with VFS execution enabled (install paths via env). No SEMBAZURU_AGENT:
# it just serves Execution; exec_vfs dials it directly.
$env:SEMBAZURU_LAUNCHER = $launcher
$env:SEMBAZURU_DLL = $dll
$env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot
$env:SEMBAZURU_CAS_ROOT = $casRoot
$workerProc = Start-Process -FilePath $workerExe -ArgumentList @($workerAddr) `
    -PassThru -WindowStyle Hidden

$exit = 99
$verbatimExit = 99
$verbatimFindExit = 99
$verbatimFindExWExit = 99
$outputExit = 99
$wildcardExit = 99
$wildcardAExit = 99
$wildcardExWExit = 99
$wildcardExAExit = 99
$chdirExit = 99
$chdirAExit = 99
$emptyTraceExit = 99
$oldSmuggledVfsCwd = $env:SEMBAZURU_VFS_CWD
$oldSmuggledTraceDir = $env:SEMBAZURU_TRACE_DIR
try {
    # Wait for the worker's Execution port to accept connections.
    $ready = $false
    for ($i = 0; $i -lt 100; $i++) {
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $c.Connect('127.0.0.1', $workerPort); $c.Close(); $ready = $true; break
        } catch { Start-Sleep -Milliseconds 50 }
    }
    if (-not $ready) { throw 'worker Execution port did not come up' }

    Push-Location $logicalRoot
    try {
        $expectedInputPath = [System.IO.Path]::GetFullPath((Join-Path $logicalRoot $rel))
        $verbatimInputPath = '\\?\' + $expectedInputPath
        $oldNativeEap = $null
        $hasNativeEap = Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue
        if ($hasNativeEap) {
            $oldNativeEap = $PSNativeCommandUseErrorActionPreference
            $PSNativeCommandUseErrorActionPreference = $false
        }
        try {
            $logicalSrc = [System.IO.Path]::GetFullPath((Join-Path $logicalRoot 'Src'))
            $env:SEMBAZURU_VFS_CWD = $fakeVfsCwd
            $env:SEMBAZURU_TRACE_DIR = $smuggledTraceDir
            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $traceDir -- `
                $probe $rel $correct $logicalRoot $expectedInputPath 2>&1 |
                Out-String | Write-Host
            $exit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $verbatimTraceDir -- `
                $probe --open-exact $verbatimInputPath $correct 2>&1 |
                Out-String | Write-Host
            $verbatimExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $verbatimTraceDir -- `
                $probe --find-exact $verbatimInputPath 2>&1 |
                Out-String | Write-Host
            $verbatimFindExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $verbatimTraceDir -- `
                $probe --find-exact-exw $verbatimInputPath 2>&1 |
                Out-String | Write-Host
            $verbatimFindExWExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --write-output 'out.txt' 2>&1 |
                Out-String | Write-Host
            $outputExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --wildcard-enum 'Src\*.txt' 2>&1 |
                Out-String | Write-Host
            $wildcardExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --wildcard-enum-a 'Src\*.txt' 2>&1 |
                Out-String | Write-Host
            $wildcardAExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --wildcard-enum-exw 'Src\*.txt' 2>&1 |
                Out-String | Write-Host
            $wildcardExWExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --wildcard-enum-exa 'Src\*.txt' 2>&1 |
                Out-String | Write-Host
            $wildcardExAExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --chdir $logicalSrc 2>&1 |
                Out-String | Write-Host
            $chdirExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --chdir-a $logicalSrc 2>&1 |
                Out-String | Write-Host
            $chdirAExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot --empty-trace-dir -- `
                $probe $rel $correct $logicalRoot $expectedInputPath 2>&1 |
                Out-String | Write-Host
            $emptyTraceExit = $LASTEXITCODE
        } finally {
            if ($hasNativeEap) { $PSNativeCommandUseErrorActionPreference = $oldNativeEap }
        }
    } finally {
        Pop-Location
    }
} finally {
    Remove-Item Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, Env:\SEMBAZURU_SCRATCH_ROOT, `
        Env:\SEMBAZURU_CAS_ROOT -ErrorAction SilentlyContinue
    if ($null -eq $oldSmuggledVfsCwd) {
        Remove-Item Env:\SEMBAZURU_VFS_CWD -ErrorAction SilentlyContinue
    } else {
        $env:SEMBAZURU_VFS_CWD = $oldSmuggledVfsCwd
    }
    if ($null -eq $oldSmuggledTraceDir) {
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue
    } else {
        $env:SEMBAZURU_TRACE_DIR = $oldSmuggledTraceDir
    }
    foreach ($p in @($workerProc, $fsProc)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
}

# The action's exit code IS the provenance proof (the probe compared the bytes it
# read to the agent-served content). No post-run scratch inspection: the worker
# removes the per-action scratch tree on completion (M9.2 / deferred #8).
$failures = @()
switch ($exit) {
    0 { }
    1 { $failures += 'the redirected open/read failed (exit 1): the VFS-mode Execute did not produce a readable handle' }
    2 { $failures += 'probe argument error (exit 2): the test harness invoked the probe incorrectly' }
    3 { $failures += 'the probe read the STALE local bytes, not the agent-served content (exit 3): the read was NOT redirected through the VFS' }
    4 { $failures += 'GetCurrentDirectoryW returned the scratch cwd instead of the logical submitted cwd (exit 4)' }
    5 { $failures += 'GetFullPathNameW resolved the relative input outside the logical submitted cwd (exit 5)' }
    6 { $failures += 'GetFileAttributesW failed before CreateFileW hydrated the VFS input (exit 6)' }
    default { $failures += "the VFS-mode Execute failed (exit=$exit)" }
}
if ($verbatimExit -ne 0) {
    $failures += "VFS Execute with verbatim DOS input failed (exit=$verbatimExit); expected agent-served bytes through the VFS"
}
if ($verbatimFindExit -ne 0) {
    $failures += "FindFirstFileW exact verbatim DOS input failed (exit=$verbatimFindExit); the verbatim prefix must not be treated as a wildcard"
}
if ($verbatimFindExWExit -ne 0) {
    $failures += "FindFirstFileExW exact verbatim DOS input failed (exit=$verbatimFindExWExit); the verbatim prefix must not be treated as a wildcard"
}
if ($outputExit -eq 0) {
    $failures += 'a scratch-cwd action that wrote a relative output completed remotely; outputs would be stranded without WriteBack'
}
if ($wildcardExit -ne -1) {
    $failures += "wildcard enumeration under the logical cwd completed remotely (exit=$wildcardExit); expected worker fallback exit=-1"
}
if ($wildcardAExit -ne -1) {
    $failures += "FindFirstFileA wildcard enumeration under the logical cwd completed remotely (exit=$wildcardAExit); expected worker fallback exit=-1"
}
if ($wildcardExWExit -ne -1) {
    $failures += "FindFirstFileExW wildcard enumeration under the logical cwd completed remotely (exit=$wildcardExWExit); expected worker fallback exit=-1"
}
if ($wildcardExAExit -ne -1) {
    $failures += "FindFirstFileExA wildcard enumeration under the logical cwd completed remotely (exit=$wildcardExAExit); expected worker fallback exit=-1"
}
if ($chdirExit -ne -1) {
    $failures += "SetCurrentDirectoryW in scratch-cwd VFS mode completed remotely (exit=$chdirExit); expected worker fallback exit=-1"
}
if ($chdirAExit -ne -1) {
    $failures += "SetCurrentDirectoryA in scratch-cwd VFS mode completed remotely (exit=$chdirAExit); expected worker fallback exit=-1"
}
if ($emptyTraceExit -ne 0) {
    $failures += "VFS Execute with empty worker trace_dir failed (exit=$emptyTraceExit); expected successful read with smuggled trace env removed"
}
$smuggledTrace = Get-ChildItem $smuggledTraceDir -Filter '*.sbzt' -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($smuggledTrace) {
    $failures += "worker allowed smuggled SEMBAZURU_TRACE_DIR to produce a trace ($($smuggledTrace.FullName))"
}
if (Test-Path (Join-Path $logicalRoot 'out.txt')) {
    $failures += 'the unsafe-output probe unexpectedly wrote into the logical tree during direct worker execution'
}

# Trace correctness: the worker may run the child from scratch, but the trace must
# keep the logical input path so cache keys move when the real source changes.
$traceJson = & cargo run -q -p sembazuru-tracer --bin sembazuru-trace -- export --trace-dir $traceDir --json |
    ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { $failures += 'tracer export failed for the VFS run' }
$expectedInputExact = [System.IO.Path]::GetFullPath((Join-Path $logicalRoot $rel))
$expectedInput = $expectedInputExact.ToLowerInvariant()
$scratchFull = ([System.IO.Path]::GetFullPath($scratchRoot)).ToLowerInvariant()
$inputPathText = @($traceJson.inputs | ForEach-Object { $_.path })
$inputPaths = @($traceJson.inputs | ForEach-Object { $_.path.ToLowerInvariant() })
if (-not ($inputPaths -contains $expectedInput)) {
    $failures += "trace did not record the logical input path ($expectedInput)"
}
if (-not ($inputPathText -contains $expectedInputExact)) {
    $failures += "trace did not preserve logical input path spelling ($expectedInputExact)"
}
$scratchHits = @($inputPathText | Where-Object { $_.ToLowerInvariant().StartsWith($scratchFull) } | Select-Object -First 5)
if ($scratchHits.Count -gt 0) {
    $failures += "trace recorded scratch paths as inputs; logical cwd/path preservation regressed: $($scratchHits -join '; ')"
}

# The verbatim exact probes must record the normal logical DOS path, not the raw
# \\?\ spelling. The normal relative run above would otherwise mask this.
$verbatimTraceJson = & cargo run -q -p sembazuru-tracer --bin sembazuru-trace -- export --trace-dir $verbatimTraceDir --json |
    ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { $failures += 'tracer export failed for the verbatim VFS run' }
$verbatimInputRaw = ('\\?\' + $expectedInputExact).ToLowerInvariant()
$verbatimInputPathText = @($verbatimTraceJson.inputs | ForEach-Object { $_.path })
$verbatimInputPaths = @($verbatimTraceJson.inputs | ForEach-Object { $_.path.ToLowerInvariant() })
if (-not ($verbatimInputPaths -contains $expectedInput)) {
    $failures += "verbatim trace did not record the normalized logical input path ($expectedInput)"
}
if ($verbatimInputPaths -contains $verbatimInputRaw) {
    $failures += "verbatim trace recorded the raw verbatim input path ($verbatimInputRaw)"
}
if ($verbatimInputPathText | Where-Object { $_.StartsWith('\\?\') } | Select-Object -First 1) {
    $failures += 'verbatim trace preserved a raw \\?\ path spelling'
}
$verbatimScratchHits = @($verbatimInputPathText | Where-Object { $_.ToLowerInvariant().StartsWith($scratchFull) } | Select-Object -First 5)
if ($verbatimScratchHits.Count -gt 0) {
    $failures += "verbatim trace recorded scratch paths as inputs; logical cwd/path preservation regressed: $($verbatimScratchHits -join '; ')"
}

# Belt-and-suspenders: the per-action scratch tree must NOT linger after the run
# (M9.2 eviction). Its absence is expected; a lingering tree is a disk-leak
# regression, not a redirect failure, so report it distinctly (still a failure).
$leftover = Get-ChildItem -Recurse -File -Filter 'input.txt' $scratchRoot -ErrorAction SilentlyContinue |
    Select-Object -First 1
if ($leftover) {
    $failures += "per-action scratch was not cleaned up after the run ($($leftover.FullName)): M9.2 eviction regressed"
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.1b WORKER VFS GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'M6.1b WORKER VFS GATE PASS (worker Execute redirected the read to the agent-served bytes; per-action scratch cleaned up)'
