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

function Remove-RestrictionCanary {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    # The fixture deliberately omits DELETE. Its owner (the runner) restores
    # cleanup rights only after every restricted action has finished.
    $ownerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $grant = "*$($ownerSid):(F)"
    & icacls.exe $Path '/grant:r' $grant '/c' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not restore cleanup rights for restriction canary: $Path" }
    Remove-Item -LiteralPath $Path -Force
}

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
$previousRestrictionCanary = Join-Path $WorkRoot 'restricted-token-canary.txt'
Remove-RestrictionCanary $previousRestrictionCanary
if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# A restricted token must satisfy both the normal-user SID and restricting-SID
# access checks. This protected DACL admits only the normal CI runner SID, so a
# direct read is a deliberate negative control while the action's restricted
# token must receive ERROR_ACCESS_DENIED. Keep it outside logicalRoot: the VFS
# hook must delegate this access to the real filesystem.
$restrictionCanaryPath = Join-Path $WorkRoot 'restricted-token-canary.txt'
$restrictionCanaryText = 'normal-runner-only restriction canary'
Set-Content -LiteralPath $restrictionCanaryPath -Value $restrictionCanaryText -Encoding ascii -NoNewline
$currentRunnerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($null -eq $currentRunnerSid) { throw 'could not determine the current runner SID for restriction canary' }
$canaryReadRights = [System.Security.AccessControl.FileSystemRights]::Read
$fileSystemAclExtensions = 'System.IO.FileSystemAclExtensions' -as [type]
if ($fileSystemAclExtensions) {
    $canaryInfo = [System.IO.FileInfo]::new($restrictionCanaryPath)
    $canaryAcl = [System.IO.FileSystemAclExtensions]::GetAccessControl($canaryInfo)
} else {
    $canaryAcl = [System.IO.File]::GetAccessControl($restrictionCanaryPath)
}
$canaryAcl.SetAccessRuleProtection($true, $false)
foreach ($accessRule in @($canaryAcl.Access)) {
    [void]$canaryAcl.RemoveAccessRuleAll($accessRule)
}
$canaryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
    $currentRunnerSid, $canaryReadRights, [System.Security.AccessControl.AccessControlType]::Allow))
if ($fileSystemAclExtensions) {
    [System.IO.FileSystemAclExtensions]::SetAccessControl($canaryInfo, $canaryAcl)
    $canaryAcl = [System.IO.FileSystemAclExtensions]::GetAccessControl($canaryInfo)
} else {
    [System.IO.File]::SetAccessControl($restrictionCanaryPath, $canaryAcl)
    $canaryAcl = [System.IO.File]::GetAccessControl($restrictionCanaryPath)
}
$canaryRules = @($canaryAcl.Access)
if (-not $canaryAcl.AreAccessRulesProtected -or $canaryRules.Count -ne 1) {
    throw 'restriction canary DACL is not protected and limited to one explicit rule'
}
$canaryRuleSid = $canaryRules[0].IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
$expectedCanaryRights = $canaryReadRights -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
if ($canaryRuleSid.Value -ne $currentRunnerSid.Value -or
    $canaryRules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    $canaryRules[0].FileSystemRights -ne $expectedCanaryRights) {
    throw "restriction canary DACL unexpectedly grants access: $($canaryRules[0].IdentityReference) $($canaryRules[0].AccessControlType) $($canaryRules[0].FileSystemRights)"
}

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
#   9 = restriction canary was readable (restricted-token regression)
#  10 = process was not assigned to a Job (or membership could not be queried)
#  12 = restriction canary fixture or its access check failed
# Static CRT (/MT) so it needs no runtime DLL beyond the cleared+rebuilt env.
$probeSrc = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>
#include <wchar.h>
static int CheckRestrictionCanary() {
    wchar_t path[32768];
    DWORD length = GetEnvironmentVariableW(
        L"SBZ_M6_RESTRICTION_CANARY", path, static_cast<DWORD>(sizeof(path) / sizeof(path[0])));
    if (length == 0 || length >= sizeof(path) / sizeof(path[0])) return 12;
    HANDLE canary = CreateFileW(path, GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (canary != INVALID_HANDLE_VALUE) {
        CloseHandle(canary);
        return 9;
    }
    return GetLastError() == ERROR_ACCESS_DENIED ? 0 : 12;
}
static int WideArgToAcp(const wchar_t* src, char* dst, int cap) {
    int n = WideCharToMultiByte(CP_ACP, 0, src, -1, dst, cap, nullptr, nullptr);
    return n > 0 && n <= cap ? n : 0;
}
static ULONGLONG FileTimeValue(FILETIME value) {
    return (static_cast<ULONGLONG>(value.dwHighDateTime) << 32) |
           value.dwLowDateTime;
}
static bool SameMetadata(const WIN32_FILE_ATTRIBUTE_DATA& a,
                         const WIN32_FILE_ATTRIBUTE_DATA& b) {
    return a.dwFileAttributes == b.dwFileAttributes &&
           a.nFileSizeHigh == b.nFileSizeHigh && a.nFileSizeLow == b.nFileSizeLow &&
           FileTimeValue(a.ftCreationTime) == FileTimeValue(b.ftCreationTime) &&
           FileTimeValue(a.ftLastAccessTime) == FileTimeValue(b.ftLastAccessTime) &&
           FileTimeValue(a.ftLastWriteTime) == FileTimeValue(b.ftLastWriteTime);
}
static int CheckPresentMetadata(const wchar_t* logical, const wchar_t* backing,
                                unsigned repeats, ULONGLONG* calls) {
    char logicalA[1024];
    char backingA[1024];
    if (!WideArgToAcp(logical, logicalA, sizeof(logicalA)) ||
        !WideArgToAcp(backing, backingA, sizeof(backingA))) return 2;
    const DWORD sentinel = 0x51BADA55;
    WIN32_FILE_ATTRIBUTE_DATA expected{};
    SetLastError(sentinel);
    DWORD expectedAttrs = GetFileAttributesW(backing);
    if (expectedAttrs == INVALID_FILE_ATTRIBUTES || GetLastError() != sentinel ||
        !GetFileAttributesExW(backing, GetFileExInfoStandard, &expected)) return 13;
    for (unsigned i = 0; i < repeats; ++i) {
        SetLastError(sentinel);
        DWORD attrsW = GetFileAttributesW(logical);
        if (attrsW != expectedAttrs || GetLastError() != sentinel) return 14;
        ++*calls;
        SetLastError(sentinel);
        DWORD attrsA = GetFileAttributesA(logicalA);
        if (attrsA != expectedAttrs || GetLastError() != sentinel) return 15;
        ++*calls;
        WIN32_FILE_ATTRIBUTE_DATA dataW{};
        SetLastError(sentinel);
        if (!GetFileAttributesExW(logical, GetFileExInfoStandard, &dataW) ||
            !SameMetadata(dataW, expected) || GetLastError() != sentinel) return 16;
        ++*calls;
        WIN32_FILE_ATTRIBUTE_DATA dataA{};
        SetLastError(sentinel);
        if (!GetFileAttributesExA(logicalA, GetFileExInfoStandard, &dataA) ||
            !SameMetadata(dataA, expected) || GetLastError() != sentinel) return 17;
        ++*calls;
    }
    return 0;
}
static int CheckAbsentMetadata(const wchar_t* logical, const wchar_t* backing) {
    char logicalA[1024];
    char backingA[1024];
    if (!WideArgToAcp(logical, logicalA, sizeof(logicalA)) ||
        !WideArgToAcp(backing, backingA, sizeof(backingA))) return 2;
    DWORD expectedW = GetFileAttributesW(backing);
    DWORD expectedWError = GetLastError();
    DWORD expectedA = GetFileAttributesA(backingA);
    DWORD expectedAError = GetLastError();
    if (expectedW != INVALID_FILE_ATTRIBUTES || expectedA != INVALID_FILE_ATTRIBUTES)
        return 19;
    BYTE expectedExW[sizeof(WIN32_FILE_ATTRIBUTE_DATA)];
    memset(expectedExW, 0xA5, sizeof(expectedExW));
    BOOL expectedExWOk = GetFileAttributesExW(backing, GetFileExInfoStandard, expectedExW);
    DWORD expectedExWError = GetLastError();
    BYTE expectedExA[sizeof(WIN32_FILE_ATTRIBUTE_DATA)];
    memset(expectedExA, 0xA5, sizeof(expectedExA));
    BOOL expectedExAOk = GetFileAttributesExA(backingA, GetFileExInfoStandard, expectedExA);
    DWORD expectedExAError = GetLastError();
    BYTE actualExW[sizeof(WIN32_FILE_ATTRIBUTE_DATA)];
    memset(actualExW, 0xA5, sizeof(actualExW));
    DWORD actualW = GetFileAttributesW(logical);
    DWORD actualWError = GetLastError();
    BYTE actualExA[sizeof(WIN32_FILE_ATTRIBUTE_DATA)];
    memset(actualExA, 0xA5, sizeof(actualExA));
    DWORD actualA = GetFileAttributesA(logicalA);
    DWORD actualAError = GetLastError();
    BOOL actualExWOk = GetFileAttributesExW(logical, GetFileExInfoStandard, actualExW);
    DWORD actualExWError = GetLastError();
    BOOL actualExAOk = GetFileAttributesExA(logicalA, GetFileExInfoStandard, actualExA);
    DWORD actualExAError = GetLastError();
    return actualW == expectedW && actualWError == expectedWError &&
           actualA == expectedA && actualAError == expectedAError &&
           actualExWOk == expectedExWOk && actualExWError == expectedExWError &&
           actualExAOk == expectedExAOk && actualExAError == expectedExAError &&
           memcmp(actualExW, expectedExW, sizeof(actualExW)) == 0 &&
           memcmp(actualExA, expectedExA, sizeof(actualExA)) == 0 ? 0 : 20;
}
static int SpawnReadChild(const wchar_t* path, const wchar_t* expected,
                          BOOL ansi) {
    wchar_t exe[1024];
    DWORD exeLen = GetModuleFileNameW(nullptr, exe, 1024);
    if (exeLen == 0 || exeLen >= 1024) return 11;
    wchar_t command[4096];
    int commandLen = _snwprintf_s(
        command, 4096, _TRUNCATE, L"\"%s\" --open-exact \"%s\" \"%s\"",
        exe, path, expected);
    if (commandLen < 0) return 11;
    PROCESS_INFORMATION process{};
    BOOL created = FALSE;
    if (ansi) {
        char exeA[1024];
        char commandA[4096];
        if (!WideArgToAcp(exe, exeA, sizeof(exeA)) ||
            !WideArgToAcp(command, commandA, sizeof(commandA))) return 11;
        STARTUPINFOA startup{};
        startup.cb = sizeof(startup);
        created = CreateProcessA(exeA, commandA, nullptr, nullptr, FALSE, 0,
                                 nullptr, nullptr, &startup, &process);
    } else {
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        created = CreateProcessW(exe, command, nullptr, nullptr, FALSE, 0,
                                 nullptr, nullptr, &startup, &process);
    }
    if (!created) return 11;
    DWORD wait = WaitForSingleObject(process.hProcess, 30000);
    DWORD exitCode = 11;
    if (wait == WAIT_OBJECT_0) GetExitCodeProcess(process.hProcess, &exitCode);
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    return static_cast<int>(exitCode);
}
int wmain(int argc, wchar_t** argv) {
    int canary = CheckRestrictionCanary();
    if (canary != 0) return canary;
    BOOL inJob = FALSE;
    if (!IsProcessInJob(GetCurrentProcess(), nullptr, &inJob) || !inJob) return 10;
    if (argc >= 4 && wcscmp(argv[1], L"--spawn-child-w") == 0) {
        return SpawnReadChild(argv[2], argv[3], FALSE);
    }
    if (argc >= 4 && wcscmp(argv[1], L"--spawn-child-a") == 0) {
        return SpawnReadChild(argv[2], argv[3], TRUE);
    }
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
    if (argc >= 8 && wcscmp(argv[1], L"--metadata-api") == 0) {
        ULONGLONG started = GetTickCount64();
        ULONGLONG calls = 0;
        int result = CheckPresentMetadata(argv[2], argv[3], 2500, &calls);
        if (result != 0) return result;
        result = CheckAbsentMetadata(argv[4], argv[5]);
        if (result != 0) return result;
        result = CheckPresentMetadata(argv[6], argv[7], 1, &calls);
        if (result != 0) return result;
        wprintf(L"METADATA_NATIVE PASS calls=%llu wall_ms=%llu present=W/A/ExW/ExA absent=PASS sparse_4GiB=PASS\n",
                calls, GetTickCount64() - started);
        return 0;
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
$metadataAbsentRel = 'Src\metadata-absent.h'
$metadataSparseRel = 'Src\metadata-sparse.bin'
$correct = 'hello-from-the-agent-vfs'
$stale = 'STALE-LOCAL-MUST-NOT-BE-READ'
New-Item -ItemType Directory -Force (Split-Path (Join-Path $logicalRoot $rel)) | Out-Null
New-Item -ItemType Directory -Force (Split-Path (Join-Path $backingRoot $rel)) | Out-Null
foreach ($d in @($scratchRoot, $casRoot, $traceDir, $miscTraceDir, $verbatimTraceDir, $smuggledTraceDir, $fakeVfsCwd)) {
    New-Item -ItemType Directory -Force $d | Out-Null
}
Set-Content (Join-Path $logicalRoot $rel) $stale -Encoding ascii -NoNewline
Set-Content (Join-Path $backingRoot $rel) $correct -Encoding ascii -NoNewline
# The metadata gate must exercise the FILETIME high/low size composition without
# writing 4 GiB of data. Mark the backing file sparse first, then SetLength.
$logicalSparse = Join-Path $logicalRoot $metadataSparseRel
$backingSparse = Join-Path $backingRoot $metadataSparseRel
Set-Content $logicalSparse 'stale-small' -Encoding ascii -NoNewline
New-Item -ItemType File -Force $backingSparse | Out-Null
$sparseOutput = & fsutil sparse setflag $backingSparse 2>&1 | Out-String
if ($LASTEXITCODE -ne 0) { throw "failed to mark sparse metadata fixture: $sparseOutput" }
$sparseStream = [System.IO.File]::Open($backingSparse, [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
try { $sparseStream.SetLength([Int64]4294967301) } finally { $sparseStream.Dispose() }

$fsAddr = '127.0.0.1:50082'
$workerPort = 50083
$workerAddr = "127.0.0.1:$workerPort"

# Agent file server in REMAP mode: paths under logicalRoot are served from backingRoot.
$fsProc = Start-Process -FilePath $fsHost -ArgumentList @($fsAddr, $logicalRoot, $backingRoot) `
    -PassThru -WindowStyle Hidden

# Worker with VFS execution enabled (install paths via env). No SEMBAZURU_AGENT:
# it just serves Execution; exec_vfs dials it directly.
$hadWorkerConfig = Test-Path Env:\SEMBAZURU_WORKER_CONFIG
$oldWorkerConfig = $env:SEMBAZURU_WORKER_CONFIG
$workerConfig = Join-Path $WorkRoot 'worker-override.toml'
$workerProc = $null
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
$emptyTraceChildWExit = 99
$emptyTraceChildAExit = 99
$metadataExit = 99
$oldSmuggledVfsCwd = $env:SEMBAZURU_VFS_CWD
$oldSmuggledTraceDir = $env:SEMBAZURU_TRACE_DIR
$hadRestrictionCanary = Test-Path Env:\SBZ_M6_RESTRICTION_CANARY
$oldRestrictionCanary = $env:SBZ_M6_RESTRICTION_CANARY
try {
    $env:SEMBAZURU_LAUNCHER = $launcher
    $env:SEMBAZURU_DLL = $dll
    $env:SEMBAZURU_SCRATCH_ROOT = $scratchRoot
    $env:SEMBAZURU_CAS_ROOT = $casRoot
    $env:SBZ_M6_RESTRICTION_CANARY = $restrictionCanaryPath
    # An explicit absent path selects the development/test override identity. The
    # worker then loads defaults plus the env overrides above without acquiring the
    # canonical machine service-runtime guard used by production installations.
    $env:SEMBAZURU_WORKER_CONFIG = $workerConfig
    $workerProc = Start-Process -FilePath $workerExe -ArgumentList @($workerAddr) `
        -PassThru -WindowStyle Hidden

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
        $metadataLogicalPath = [System.IO.Path]::GetFullPath((Join-Path $logicalRoot $rel))
        $metadataBackingPath = [System.IO.Path]::GetFullPath((Join-Path $backingRoot $rel))
        $metadataLogicalAbsent = [System.IO.Path]::GetFullPath((Join-Path $logicalRoot $metadataAbsentRel))
        $metadataBackingAbsent = [System.IO.Path]::GetFullPath((Join-Path $backingRoot $metadataAbsentRel))
        $metadataLogicalSparse = [System.IO.Path]::GetFullPath($logicalSparse)
        $metadataBackingSparse = [System.IO.Path]::GetFullPath($backingSparse)
        $oldNativeEap = $null
        $hasNativeEap = Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue
        if ($hasNativeEap) {
            $oldNativeEap = $PSNativeCommandUseErrorActionPreference
            $PSNativeCommandUseErrorActionPreference = $false
        }
        try {
            # Negative control: the unmodified runner token must read the canary,
            # and the same native probe must therefore report exit 9 before an
            # action starts. The action uses a restricted token and must instead
            # receive ERROR_ACCESS_DENIED, then continue through its VFS checks.
            $normalCanaryText = [System.IO.File]::ReadAllText($restrictionCanaryPath)
            if ($normalCanaryText -ne $restrictionCanaryText) {
                throw 'normal runner could not read the restriction canary content'
            }
            & $probe 2>&1 | Out-String | Write-Host
            $normalCanaryProbeExit = $LASTEXITCODE
            if ($normalCanaryProbeExit -ne 9) {
                throw "restriction canary negative control failed: normal native probe exit=$normalCanaryProbeExit, expected 9"
            }
            Write-Host 'RESTRICTION_CANARY NEGATIVE_CONTROL PASS normal_probe_exit=9'

            $logicalSrc = [System.IO.Path]::GetFullPath((Join-Path $logicalRoot 'Src'))
            $env:SEMBAZURU_VFS_CWD = $fakeVfsCwd
            $env:SEMBAZURU_TRACE_DIR = $smuggledTraceDir
            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $miscTraceDir -- `
                $probe --metadata-api $metadataLogicalPath $metadataBackingPath `
                $metadataLogicalAbsent $metadataBackingAbsent `
                $metadataLogicalSparse $metadataBackingSparse 2>&1 |
                Out-String | Write-Host
            $metadataExit = $LASTEXITCODE

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

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot --empty-trace-dir -- `
                $probe --spawn-child-w $expectedInputPath $correct 2>&1 |
                Out-String | Write-Host
            $emptyTraceChildWExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot --empty-trace-dir -- `
                $probe --spawn-child-a $expectedInputPath $correct 2>&1 |
                Out-String | Write-Host
            $emptyTraceChildAExit = $LASTEXITCODE
        } finally {
            if ($hasNativeEap) { $PSNativeCommandUseErrorActionPreference = $oldNativeEap }
        }
    } finally {
        Pop-Location
    }
} finally {
    Remove-Item Env:\SEMBAZURU_LAUNCHER, Env:\SEMBAZURU_DLL, Env:\SEMBAZURU_SCRATCH_ROOT, `
        Env:\SEMBAZURU_CAS_ROOT -ErrorAction SilentlyContinue
    if ($hadWorkerConfig) {
        $env:SEMBAZURU_WORKER_CONFIG = $oldWorkerConfig
    } else {
        Remove-Item Env:\SEMBAZURU_WORKER_CONFIG -ErrorAction SilentlyContinue
    }
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
    if ($hadRestrictionCanary) {
        $env:SBZ_M6_RESTRICTION_CANARY = $oldRestrictionCanary
    } else {
        Remove-Item Env:\SBZ_M6_RESTRICTION_CANARY -ErrorAction SilentlyContinue
    }
    foreach ($p in @($workerProc, $fsProc)) {
        if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    }
    Remove-RestrictionCanary $restrictionCanaryPath
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
    9 { $failures += 'the restricted action could read the runner-only restriction canary (exit 9)' }
    10 { $failures += 'the target entered outside the worker Job object (exit 10)' }
    12 { $failures += 'the restriction canary could not be checked (exit 12): fixture ACL or real filesystem access failed' }
    default { $failures += "the VFS-mode Execute failed (exit=$exit)" }
}
if ($verbatimExit -ne 0) {
    $failures += "VFS Execute with verbatim DOS input failed (exit=$verbatimExit); expected agent-served bytes through the VFS"
}
if ($metadataExit -ne 0) {
    $failures += "GetFileAttributesW/A and GetFileAttributesExW/A metadata fast path failed (exit=$metadataExit); expected remote attributes, 64-bit size, FILETIMEs, and preserved LastError"
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
if ($emptyTraceChildWExit -ne 0) {
    $failures += "CreateProcessW child under empty worker trace_dir failed provenance (exit=$emptyTraceChildWExit); the child must inherit VFS injection and read agent bytes"
}
if ($emptyTraceChildAExit -ne 0) {
    $failures += "CreateProcessA child under empty worker trace_dir failed provenance (exit=$emptyTraceChildAExit); the child must inherit VFS injection and read agent bytes"
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
