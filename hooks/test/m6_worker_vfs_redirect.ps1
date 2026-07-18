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

function Test-M6AsciiPrintable {
    param([string]$Value, [int]$Maximum)

    if ([string]::IsNullOrEmpty($Value) -or $Value.Length -gt $Maximum) { return $false }
    foreach ($character in $Value.ToCharArray()) {
        $code = [int][char]$character
        if ($code -lt 0x20 -or $code -gt 0x7e) { return $false }
    }
    return $true
}

function Test-M6JsonIntegerUInt32 {
    param([object]$Value)

    return ($Value -is [int] -or $Value -is [long]) -and
        $Value -ge 0 -and $Value -le 4294967295
}

function Test-M6ExactPropertySet {
    param([object]$Value, [string[]]$Expected)

    if ($null -eq $Value) { return $false }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    return ($actual.Count -eq $wanted.Count) -and (($actual -join ',') -eq ($wanted -join ','))
}

function Test-M6RenderedLine {
    param([string]$Line, [string[]]$KnownSecrets)

    if (-not (Test-M6AsciiPrintable $Line 1024)) { return $false }
    foreach ($secret in $KnownSecrets) {
        if (-not [string]::IsNullOrEmpty($secret) -and
            $Line.IndexOf($secret, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $false
        }
    }
    return $true
}

function Compare-M6FailureTuple {
    param([object]$Left, [object]$Right)

    $leftDenied = $Left.status -eq 5
    $rightDenied = $Right.status -eq 5
    if ($leftDenied -ne $rightDenied) { return $(if ($leftDenied) { -1 } else { 1 }) }
    $pathComparison = [string]::CompareOrdinal($Left.path, $Right.path)
    if ($pathComparison -ne 0) { return $pathComparison }
    foreach ($name in @('status', 'access', 'disposition')) {
        if ($Left.$name -lt $Right.$name) { return -1 }
        if ($Left.$name -gt $Right.$name) { return 1 }
    }
    return 0
}

function Get-M6SafeClGlDiagnostic {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RawText,
        [string[]]$KnownSecrets = @('secret')
    )

    if (-not (Test-M6AsciiPrintable $RawText 8192)) { return $null }
    try {
        $diagnostic = $RawText | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return $null
    }
    $envelopeProperties = @('schema', 'complete', 'result', 'process', 'target_traces', 'total_failed', 'emitted', 'omitted', 'reason', 'failures')
    if (-not (Test-M6ExactPropertySet $diagnostic $envelopeProperties) -or
        $diagnostic.schema -cne 'sembazuru.createfile-diagnostic.v1' -or
        $diagnostic.process -cne 'cl.exe' -or
        -not ($diagnostic.complete -is [bool]) -or
        -not ($diagnostic.result -is [string]) -or
        -not (Test-M6JsonIntegerUInt32 $diagnostic.target_traces) -or
        -not (Test-M6JsonIntegerUInt32 $diagnostic.total_failed) -or
        -not (Test-M6JsonIntegerUInt32 $diagnostic.emitted) -or
        -not (Test-M6JsonIntegerUInt32 $diagnostic.omitted) -or
        $diagnostic.emitted -gt 32 -or
        $diagnostic.total_failed -ne ($diagnostic.emitted + $diagnostic.omitted) -or
        -not ($diagnostic.reason -is [string]) -or
        -not ($diagnostic.failures -is [array]) -or
        @($diagnostic.failures).Count -ne $diagnostic.emitted) {
        return $null
    }
    $incompleteReasons = @{
        'trace-load-incomplete' = 'trace-load-incomplete'
        'target-trace-missing' = 'target-trace-missing'
        'target-trace-truncated' = 'target-trace-truncated'
        'diagnostic-root-invalid' = 'diagnostic-root-invalid'
        'target-unknown-failed-event' = 'target-unknown-failed-event'
        'target-failed-probe-ambiguous' = 'target-failed-probe-ambiguous'
        'target-failed-open-path-not-absolute' = 'target-failed-open-path-not-absolute'
        'target-failed-open-path-ambiguous' = 'target-failed-open-path-ambiguous'
        'diagnostic-path-too-long' = 'diagnostic-path-too-long'
    }
    $completeReasons = @{
        'no-failed-target-opens' = 'no-failed-target-opens'
        'target-failed-open-outside-scratch' = 'target-failed-open-outside-scratch'
        'failed-target-opens-under-scratch' = 'failed-target-opens-under-scratch'
    }
    $reason = $null
    $safeResult = $null
    if ($diagnostic.complete) {
        if ($diagnostic.target_traces -lt 1) { return $null }
        if ($diagnostic.result -ceq 'clean' -and $diagnostic.total_failed -eq 0 -and
            $diagnostic.emitted -eq 0 -and $diagnostic.omitted -eq 0 -and
            $diagnostic.reason -ceq 'no-failed-target-opens') {
            $reason = $completeReasons['no-failed-target-opens']
            $safeResult = 'clean'
        } elseif ($diagnostic.result -ceq 'failed' -and $diagnostic.total_failed -gt 0 -and
            $completeReasons.ContainsKey($diagnostic.reason) -and
            $diagnostic.reason -cne 'no-failed-target-opens') {
            $reason = $completeReasons[$diagnostic.reason]
            $safeResult = 'failed'
        } else {
            return $null
        }
    } else {
        if ($diagnostic.result -cne 'incomplete' -or $diagnostic.total_failed -ne 0 -or
            $diagnostic.emitted -ne 0 -or $diagnostic.omitted -ne 0 -or
            -not $incompleteReasons.ContainsKey($diagnostic.reason)) {
            return $null
        }
        if ($diagnostic.reason -ceq 'target-trace-missing' -and $diagnostic.target_traces -ne 0) {
            return $null
        }
        $reason = $incompleteReasons[$diagnostic.reason]
        $safeResult = 'incomplete'
    }

    $records = @()
    $previous = $null
    foreach ($failure in @($diagnostic.failures)) {
        if (-not (Test-M6ExactPropertySet $failure @('path', 'status', 'access', 'disposition')) -or
            -not ($failure.path -is [string]) -or
            -not ($failure.path -cmatch '^<scratch>(\\[A-Za-z0-9_.\-]{1,64}){1,8}$') -or
            $failure.path.Length -gt 200 -or
            [System.Text.Encoding]::UTF8.GetByteCount($failure.path) -gt 512 -or
            -not (Test-M6JsonIntegerUInt32 $failure.status) -or
            -not (Test-M6JsonIntegerUInt32 $failure.access) -or
            -not (Test-M6JsonIntegerUInt32 $failure.disposition)) {
            return $null
        }
        foreach ($component in $failure.path.Substring(9).Split('\')) {
            if ($component -in @('.', '..') -or $component.EndsWith('.')) { return $null }
        }
        if ($null -ne $previous -and (Compare-M6FailureTuple $previous $failure) -gt 0) {
            return $null
        }
        $safeRecord = [pscustomobject][ordered]@{
            schema = 'sembazuru.createfile-diagnostic.v1'
            path = $failure.path
            status = [uint32]$failure.status
            access = [uint32]$failure.access
            disposition = [uint32]$failure.disposition
        }
        $line = 'M6_CL_GL_CREATEFILE_FAILURE ' + ($safeRecord | ConvertTo-Json -Compress)
        if (-not (Test-M6RenderedLine $line $KnownSecrets)) { return $null }
        $records += $line
        $previous = $failure
    }
    $safeComplete = if ($diagnostic.complete) { 'true' } else { 'false' }
    $summary = "M6_CL_GL_CREATEFILE_DIAGNOSTIC schema=sembazuru.createfile-diagnostic.v1 complete=$safeComplete result=$safeResult target_traces=$([uint32]$diagnostic.target_traces) total_failed=$([uint32]$diagnostic.total_failed) emitted=$([uint32]$diagnostic.emitted) omitted=$([uint32]$diagnostic.omitted) reason=$reason"
    if (-not (Test-M6RenderedLine $summary $KnownSecrets)) { return $null }
    return [pscustomobject]@{
        summary = $summary
        records = @($records)
        complete = $diagnostic.complete
        result = $safeResult
    }
}

function Assert-M6DiagnosticRawAccepted {
    param([string]$RawText, [int]$ExpectedRecords)

    $safe = Get-M6SafeClGlDiagnostic -RawText $RawText
    if ($null -eq $safe -or @($safe.records).Count -ne $ExpectedRecords) {
        throw 'golden CreateFile diagnostic fixture was rejected'
    }
    $lines = @($safe.summary) + @($safe.records)
    $invalidLines = @($lines | Where-Object { -not (Test-M6RenderedLine $_ @('secret')) })
    if ($lines.Count -ne (1 + $ExpectedRecords) -or $invalidLines.Count -ne 0) {
        throw 'safe CreateFile diagnostic fixture rendered an invalid line'
    }
}

function Assert-M6DiagnosticRawRejected {
    param([string]$RawText)

    $safe = Get-M6SafeClGlDiagnostic -RawText $RawText
    if ($null -ne $safe) { throw 'unsafe CreateFile diagnostic fixture was accepted' }
    $fixtureFailures = @('hosted cl.exe /GL CreateFile diagnostic was unsafe or invalid')
    $lines = @('M6_CL_GL_CREATEFILE_DIAGNOSTIC_UNSAFE')
    if ($fixtureFailures.Count -ne 1 -or $lines.Count -ne 1 -or
        -not (Test-M6RenderedLine $lines[0] @('secret'))) {
        throw 'unsafe CreateFile diagnostic render was not one fixed safe line'
    }
}

$m6DiagnosticFailedGolden = '{"schema":"sembazuru.createfile-diagnostic.v1","complete":true,"result":"failed","process":"cl.exe","target_traces":1,"total_failed":2,"emitted":2,"omitted":0,"reason":"failed-target-opens-under-scratch","failures":[{"path":"<scratch>\\_CL.tmp","status":5,"access":0,"disposition":3},{"path":"<scratch>\\_CL2.tmp","status":3,"access":1,"disposition":3}]}'
$m6DiagnosticCleanGolden = '{"schema":"sembazuru.createfile-diagnostic.v1","complete":true,"result":"clean","process":"cl.exe","target_traces":1,"total_failed":0,"emitted":0,"omitted":0,"reason":"no-failed-target-opens","failures":[]}'
$m6DiagnosticMissingGolden = '{"schema":"sembazuru.createfile-diagnostic.v1","complete":false,"result":"incomplete","process":"cl.exe","target_traces":0,"total_failed":0,"emitted":0,"omitted":0,"reason":"target-trace-missing","failures":[]}'
$m6DiagnosticDuplicateGolden = '{"schema":"sembazuru.createfile-diagnostic.v1","complete":true,"result":"failed","process":"cl.exe","target_traces":1,"total_failed":2,"emitted":2,"omitted":0,"reason":"failed-target-opens-under-scratch","failures":[{"path":"<scratch>\\_CL.tmp","status":5,"access":0,"disposition":3},{"path":"<scratch>\\_CL.tmp","status":5,"access":0,"disposition":3}]}'
Assert-M6DiagnosticRawAccepted $m6DiagnosticFailedGolden 2
Assert-M6DiagnosticRawAccepted $m6DiagnosticCleanGolden 0
Assert-M6DiagnosticRawAccepted $m6DiagnosticMissingGolden 0
Assert-M6DiagnosticRawAccepted $m6DiagnosticDuplicateGolden 2
$m6Diagnostic201Path = $m6DiagnosticFailedGolden.Replace('<scratch>\\_CL.tmp', "<scratch>\\$($('a' * 191))")
$m6Diagnostic513BytePath = $m6DiagnosticFailedGolden.Replace('<scratch>\\_CL.tmp', "<scratch>\\$($('a' * 503))")
foreach ($raw in @(
    $m6DiagnosticFailedGolden.Replace('failed-target-opens-under-scratch', "failed`ntarget"),
    $m6DiagnosticFailedGolden.Replace('<scratch>\\_CL.tmp', '<scratch>\\secret space.tmp'),
    $m6DiagnosticFailedGolden.Replace('"status":5', '"status":"5"'),
    $m6DiagnosticFailedGolden.Replace('"access":0', '"access":4294967296'),
    $m6DiagnosticFailedGolden.Replace('"emitted":2', '"emitted":33'),
    $m6DiagnosticFailedGolden.Replace('<scratch>\\_CL.tmp","status":5', '<scratch>\\z.tmp","status":3'),
    $m6Diagnostic201Path,
    $m6Diagnostic513BytePath,
    ($m6DiagnosticFailedGolden + "`r`n"),
    ('{' + ('a' * 8192) + '}'),
    '',
    '{bad json}'
)) { Assert-M6DiagnosticRawRejected $raw }
Write-Host 'M6_DIAGNOSTIC_STATIC_FIXTURES PASS'

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
$clCommand = Get-Command cl.exe -CommandType Application -ErrorAction SilentlyContinue
if (-not $clCommand) {
    throw 'cl.exe not on PATH (run from a VS dev shell or after msvc-dev-cmd)'
}
$clExe = (Resolve-Path -LiteralPath $clCommand.Source).Path

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
$expectedCanaryRights = $canaryReadRights -bor [System.Security.AccessControl.FileSystemRights]::Synchronize
$canaryAcl = [System.Security.AccessControl.FileSecurity]::new()
$canaryAcl.SetSecurityDescriptorSddlForm(
    "D:P(A;;FR;;;$($currentRunnerSid.Value))", [System.Security.AccessControl.AccessControlSections]::Access)
$fileSystemAclExtensions = 'System.IO.FileSystemAclExtensions' -as [type]
if ($fileSystemAclExtensions) {
    $canaryInfo = [System.IO.FileInfo]::new($restrictionCanaryPath)
    [System.IO.FileSystemAclExtensions]::SetAccessControl($canaryInfo, $canaryAcl)
    $canaryAcl = [System.IO.FileSystemAclExtensions]::GetAccessControl($canaryInfo)
} else {
    [System.IO.File]::SetAccessControl($restrictionCanaryPath, $canaryAcl)
    $canaryAcl = [System.IO.File]::GetAccessControl($restrictionCanaryPath)
}
$canaryRules = @($canaryAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
if (-not $canaryAcl.AreAccessRulesProtected -or $canaryRules.Count -ne 1) {
    throw 'restriction canary DACL is not protected and limited to one explicit rule'
}
$canaryRule = $canaryRules[0]
if ($canaryRule.IsInherited -or
    $canaryRule.IdentityReference.Value -ne $currentRunnerSid.Value -or
    $canaryRules[0].AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
    $canaryRules[0].FileSystemRights -ne $expectedCanaryRights) {
    throw "restriction canary DACL unexpectedly grants access: $($canaryRule.IdentityReference) $($canaryRule.AccessControlType) $($canaryRule.FileSystemRights) inherited=$($canaryRule.IsInherited)"
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
#include <stdio.h>
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
    DWORD error = GetLastError();
    if (error == ERROR_ACCESS_DENIED) return 0;
    fprintf(stderr, "restriction canary unexpected Win32 error=%lu\\n", error);
    return 12;
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
static bool IsPathSeparator(wchar_t value) {
    return value == L'\\' || value == L'/';
}
static bool IsFullyQualifiedWindowsPath(const wchar_t* path) {
    if (path == nullptr || path[0] == L'\0') return false;
    bool driveAbsolute = ((path[0] >= L'A' && path[0] <= L'Z') ||
                          (path[0] >= L'a' && path[0] <= L'z')) &&
                         path[1] == L':' && IsPathSeparator(path[2]);
    if (driveAbsolute) return true;
    if (!IsPathSeparator(path[0]) || !IsPathSeparator(path[1])) return false;
    const wchar_t* server = path + 2;
    const wchar_t* cursor = server;
    while (*cursor != L'\0' && !IsPathSeparator(*cursor)) ++cursor;
    if (cursor == server || *cursor == L'\0') return false;
    const wchar_t* share = cursor + 1;
    cursor = share;
    while (*cursor != L'\0' && !IsPathSeparator(*cursor)) ++cursor;
    return cursor != share;
}
static bool IsDirectActionScratch(const wchar_t* path,
                                  const wchar_t* expectedRoot) {
    if (!IsFullyQualifiedWindowsPath(path) ||
        !IsFullyQualifiedWindowsPath(expectedRoot)) return false;
    size_t rootLength = wcslen(expectedRoot);
    while (rootLength > 0 && IsPathSeparator(expectedRoot[rootLength - 1]))
        --rootLength;
    size_t pathLength = wcslen(path);
    if (rootLength == 0 || pathLength <= rootLength + 1 ||
        _wcsnicmp(path, expectedRoot, rootLength) != 0 ||
        !IsPathSeparator(path[rootLength])) return false;
    const wchar_t* leaf = path + rootLength + 1;
    if ((leaf[0] == L'.' && leaf[1] == L'\0') ||
        (leaf[0] == L'.' && leaf[1] == L'.' && leaf[2] == L'\0')) return false;
    return _wcsnicmp(leaf, L"action-", 7) == 0 && leaf[7] != L'\0' &&
           wcschr(leaf, L'\\') == nullptr && wcschr(leaf, L'/') == nullptr;
}
static const int kScratchCanaryATemp = 30;
static const int kScratchCanaryAOpen = 31;
static const int kScratchCanaryAMapping = 32;
static const int kScratchCanaryAMap = 33;
static const int kScratchCanaryAUnmap = 34;
static const int kScratchCanaryAMapClose = 35;
static const int kScratchCanaryADisposition = 36;
static const int kScratchCanaryAFileClose = 37;
static const int kScratchCanaryAAbsence = 38;
static const int kScratchCanaryACleanup = 39;
static const int kScratchCanaryBTemp = 40;
static const int kScratchCanaryBOpen = 41;
static const int kScratchCanaryBMapping = 42;
static const int kScratchCanaryBMap = 43;
static const int kScratchCanaryBUnmap = 44;
static const int kScratchCanaryBMapClose = 45;
static const int kScratchCanaryBFileClose = 46;
static const int kScratchCanaryBAbsence = 47;
static const int kScratchCanaryBCleanup = 48;
static const int kScratchCanaryNegativeSentinel = 49;
static BOOL ScratchCanaryIsAbsent(const wchar_t* path, DWORD expectedError) {
    SetLastError(ERROR_SUCCESS);
    return GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES &&
           GetLastError() == expectedError;
}
static BOOL ScratchCanaryRemoveResidue(const wchar_t* path) {
    SetLastError(ERROR_SUCCESS);
    DWORD attributes = GetFileAttributesW(path);
    DWORD error = GetLastError();
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    if (DeleteFileW(path)) return TRUE;
    error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
static int RunScratchCanaryCase(const wchar_t* tmp, BOOL deleteOnClose,
                                DWORD* primaryError, BOOL* cleanupFailed) {
    static const char kKnownBytes[] = "sembazuru-scratch-canary";
    wchar_t path[32768]{};
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = nullptr;
    void* view = nullptr;
    const int tempFailure = deleteOnClose ? kScratchCanaryBTemp : kScratchCanaryATemp;
    const int openFailure = deleteOnClose ? kScratchCanaryBOpen : kScratchCanaryAOpen;
    const int mappingFailure = deleteOnClose ? kScratchCanaryBMapping : kScratchCanaryAMapping;
    const int mapFailure = deleteOnClose ? kScratchCanaryBMap : kScratchCanaryAMap;
    const int unmapFailure = deleteOnClose ? kScratchCanaryBUnmap : kScratchCanaryAUnmap;
    const int mapCloseFailure = deleteOnClose ? kScratchCanaryBMapClose : kScratchCanaryAMapClose;
    const int fileCloseFailure = deleteOnClose ? kScratchCanaryBFileClose : kScratchCanaryAFileClose;
    const int absenceFailure = deleteOnClose ? kScratchCanaryBAbsence : kScratchCanaryAAbsence;
    const int cleanupFailure = deleteOnClose ? kScratchCanaryBCleanup : kScratchCanaryACleanup;
    int result = tempFailure;
    DWORD attributes = INVALID_FILE_ATTRIBUTES;
    DWORD absenceError = ERROR_SUCCESS;
    *primaryError = ERROR_SUCCESS;
    *cleanupFailed = FALSE;
    if (GetTempFileNameW(tmp, L"SBZ", 0, path) == 0) {
        *primaryError = GetLastError();
        goto cleanup;
    }
    file = CreateFileW(path, GENERIC_READ | GENERIC_WRITE | DELETE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING,
                       deleteOnClose ? FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE
                                     : FILE_ATTRIBUTE_TEMPORARY,
                       nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        result = openFailure;
        *primaryError = GetLastError();
        goto cleanup;
    }
    mapping = CreateFileMappingW(file, nullptr, PAGE_READWRITE, 0, 4096, nullptr);
    if (mapping == nullptr) {
        result = mappingFailure;
        *primaryError = GetLastError();
        goto cleanup;
    }
    view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 4096);
    if (view == nullptr) {
        result = mapFailure;
        *primaryError = GetLastError();
        goto cleanup;
    }
    memcpy(view, kKnownBytes, sizeof(kKnownBytes));
    if (!UnmapViewOfFile(view)) {
        result = unmapFailure;
        *primaryError = GetLastError();
        goto cleanup;
    }
    view = nullptr;
    if (!CloseHandle(mapping)) {
        result = mapCloseFailure;
        *primaryError = GetLastError();
        goto cleanup;
    }
    mapping = nullptr;
    if (!deleteOnClose) {
        FILE_DISPOSITION_INFO disposition{};
        disposition.DeleteFile = TRUE;
        if (!SetFileInformationByHandle(file, FileDispositionInfo, &disposition,
                                        sizeof(disposition))) {
            result = kScratchCanaryADisposition;
            *primaryError = GetLastError();
            goto cleanup;
        }
    }
    if (!CloseHandle(file)) {
        result = fileCloseFailure;
        *primaryError = GetLastError();
        goto cleanup;
    }
    file = INVALID_HANDLE_VALUE;
    SetLastError(ERROR_SUCCESS);
    attributes = GetFileAttributesW(path);
    absenceError = GetLastError();
    if (attributes != INVALID_FILE_ATTRIBUTES || absenceError != ERROR_FILE_NOT_FOUND) {
        result = absenceFailure;
        *primaryError = absenceError;
        goto cleanup;
    }
    return 0;
cleanup:
    BOOL cleanupOk = TRUE;
    if (view != nullptr && !UnmapViewOfFile(view)) cleanupOk = FALSE;
    if (mapping != nullptr && !CloseHandle(mapping)) cleanupOk = FALSE;
    if (file != INVALID_HANDLE_VALUE && !CloseHandle(file)) cleanupOk = FALSE;
    if (path[0] != L'\0' && !ScratchCanaryRemoveResidue(path)) cleanupOk = FALSE;
    if (!cleanupOk) {
        *cleanupFailed = TRUE;
        return cleanupFailure;
    }
    return result;
}
static int RunScratchCanary(const wchar_t* tmp, DWORD* primaryError,
                            BOOL* cleanupFailed) {
    int result = RunScratchCanaryCase(tmp, FALSE, primaryError, cleanupFailed);
    if (result != 0) return result;
    return RunScratchCanaryCase(tmp, TRUE, primaryError, cleanupFailed);
}
static const ULONGLONG kClGlTimeoutMs = 30000;
static const ULONGLONG kClGlTerminateGraceMs = 2000;
static const int kClGlSetupGetStdin = 60;
static const int kClGlSetupGetStdout = 61;
static const int kClGlSetupGetStderr = 62;
static const int kClGlSetupDuplicateStdin = 63;
static const int kClGlSetupDuplicateStdout = 64;
static const int kClGlSetupDuplicateStderr = 65;
static const int kClGlSetupQueryAttributeSize = 66;
static const int kClGlSetupAllocateAttributes = 67;
static const int kClGlSetupInitializeAttributes = 68;
static const int kClGlSetupUpdateHandleList = 69;
static const int kClGlSetupCreateProcess = 70;
static BOOL WaitForClGlExit(HANDLE process, ULONGLONG deadline) {
    for (;;) {
        ULONGLONG now = GetTickCount64();
        if (now >= deadline) return FALSE;
        DWORD remaining = static_cast<DWORD>(deadline - now);
        DWORD wait = WaitForSingleObject(process, remaining < 25 ? remaining : 25);
        if (wait == WAIT_OBJECT_0) return TRUE;
        if (wait != WAIT_TIMEOUT) return FALSE;
    }
}
static BOOL StopClGlProcess(HANDLE process, ULONGLONG hardDeadline) {
    DWORD state = WaitForSingleObject(process, 0);
    if (state == WAIT_OBJECT_0) return TRUE;
    BOOL terminated = TerminateProcess(process, 1);
    ULONGLONG now = GetTickCount64();
    ULONGLONG graceDeadline = now + kClGlTerminateGraceMs;
    if (graceDeadline > hardDeadline) graceDeadline = hardDeadline;
    BOOL stopped = WaitForClGlExit(process, graceDeadline);
    return terminated && stopped;
}
static void EmitClGlSpawnFailure(const char* stage, DWORD error) {
    fprintf(stderr, "CL_GL_SPAWN: stage=%s error=%lu\n", stage,
            static_cast<unsigned long>(error));
}
static void EmitScratchCanaryFailure(int stage, DWORD error, BOOL cleanupFailed) {
    fprintf(stderr, "M6_CL_GL_SCRATCH_CANARY_FAIL stage=%d error=%lu cleanup=%d\n",
            stage, static_cast<unsigned long>(error), cleanupFailed ? 1 : 0);
}
static int SpawnClGl(const wchar_t* expectedScratchRoot, const wchar_t* clExe,
                     BOOL scratchCanaryNegative) {
    wchar_t tmp[32768];
    wchar_t temp[32768];
    wchar_t scratch[32768];
    DWORD tmpLength = GetEnvironmentVariableW(
        L"TMP", tmp, static_cast<DWORD>(sizeof(tmp) / sizeof(tmp[0])));
    DWORD tempLength = GetEnvironmentVariableW(
        L"TEMP", temp, static_cast<DWORD>(sizeof(temp) / sizeof(temp[0])));
    DWORD scratchLength = GetEnvironmentVariableW(
        L"SEMBAZURU_VFS_SCRATCH", scratch,
        static_cast<DWORD>(sizeof(scratch) / sizeof(scratch[0])));
    if (tmpLength == 0 || tmpLength >= sizeof(tmp) / sizeof(tmp[0]) ||
        tempLength == 0 || tempLength >= sizeof(temp) / sizeof(temp[0]) ||
        scratchLength == 0 || scratchLength >= sizeof(scratch) / sizeof(scratch[0]) ||
        wcscmp(tmp, temp) != 0 || wcscmp(tmp, scratch) != 0 ||
        !IsDirectActionScratch(tmp, expectedScratchRoot))
        return 21;
    wchar_t missingScratch[32768]{};
    wchar_t marker[32768]{};
    if (scratchCanaryNegative) {
        int missingLength = _snwprintf_s(
            missingScratch, sizeof(missingScratch) / sizeof(missingScratch[0]),
            _TRUNCATE, L"%s\\missing-scratch-canary", tmp);
        int markerLength = _snwprintf_s(
            marker, sizeof(marker) / sizeof(marker[0]), _TRUNCATE,
            L"%s\\scratch-canary-sentinel.marker", tmp);
        if (missingLength < 0 || markerLength < 0 ||
            !ScratchCanaryIsAbsent(marker, ERROR_FILE_NOT_FOUND))
            return kScratchCanaryNegativeSentinel;
    }
    const wchar_t* canaryRoot = scratchCanaryNegative ? missingScratch : tmp;
    DWORD canaryError = ERROR_SUCCESS;
    BOOL canaryCleanupFailed = FALSE;
    int canaryResult = RunScratchCanary(canaryRoot, &canaryError, &canaryCleanupFailed);
    if (canaryResult != 0) {
        if (scratchCanaryNegative && marker[0] != L'\0')
            ScratchCanaryRemoveResidue(marker);
        EmitScratchCanaryFailure(canaryResult, canaryError, canaryCleanupFailed);
        return canaryResult;
    }
    wprintf(L"M6_CL_GL_SCRATCH_CANARY PASS A=delete-disposition B=delete-on-close\n");
    wchar_t object[32768];
    int objectLength = _snwprintf_s(
        object, sizeof(object) / sizeof(object[0]), _TRUNCATE, L"%s\\gl_tmp.obj", tmp);
    if (objectLength < 0) return 22;
    if (GetFileAttributesW(object) != INVALID_FILE_ATTRIBUTES && !DeleteFileW(object))
        return 23;
    wchar_t command[32768];
    int commandLength = 0;
    if (scratchCanaryNegative) {
        commandLength = _snwprintf_s(
            command, sizeof(command) / sizeof(command[0]), _TRUNCATE,
            L"\"%s\" --scratch-canary-sentinel \"%s\"", clExe, marker);
    } else {
        commandLength = _snwprintf_s(
            command, sizeof(command) / sizeof(command[0]), _TRUNCATE,
            L"\"%s\" /nologo /c /GL \"Src\\gl_tmp.cpp\" /Fo\"%s\"", clExe, object);
    }
    if (commandLength < 0) return 22;
    SetEnvironmentVariableW(L"CL", nullptr);
    SetEnvironmentVariableW(L"_CL_", nullptr);
    HANDLE parentStdin = INVALID_HANDLE_VALUE;
    HANDLE parentStdout = INVALID_HANDLE_VALUE;
    HANDLE parentStderr = INVALID_HANDLE_VALUE;
    HANDLE inheritedStdin = INVALID_HANDLE_VALUE;
    HANDLE inheritedStdout = INVALID_HANDLE_VALUE;
    HANDLE inheritedStderr = INVALID_HANDLE_VALUE;
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
    BOOL attributesInitialized = FALSE;
    PROCESS_INFORMATION process{};
    BOOL processCreated = FALSE;
    int result = 24;
    SIZE_T attributesSize = 0;
    STARTUPINFOEXW startup{};
    DWORD exitCode = 25;
    LARGE_INTEGER objectSize{};
    HANDLE objectHandle = INVALID_HANDLE_VALUE;
    BOOL hasContent = FALSE;
    ULONGLONG hardDeadline = 0;
    ULONGLONG executionDeadline = 0;
    const char* spawnStage = nullptr;
    DWORD spawnError = ERROR_SUCCESS;
    BOOL attributeSizeQueried = FALSE;
    DWORD attributeSizeError = ERROR_SUCCESS;
    HANDLE inheritableHandles[3]{};
    parentStdin = GetStdHandle(STD_INPUT_HANDLE);
    if (parentStdin == nullptr || parentStdin == INVALID_HANDLE_VALUE) {
        spawnStage = "get-stdin";
        spawnError = GetLastError();
        result = kClGlSetupGetStdin;
        goto cleanup;
    }
    parentStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    if (parentStdout == nullptr || parentStdout == INVALID_HANDLE_VALUE) {
        spawnStage = "get-stdout";
        spawnError = GetLastError();
        result = kClGlSetupGetStdout;
        goto cleanup;
    }
    parentStderr = GetStdHandle(STD_ERROR_HANDLE);
    if (parentStderr == nullptr || parentStderr == INVALID_HANDLE_VALUE) {
        spawnStage = "get-stderr";
        spawnError = GetLastError();
        result = kClGlSetupGetStderr;
        goto cleanup;
    }
    if (!DuplicateHandle(GetCurrentProcess(), parentStdin, GetCurrentProcess(),
                         &inheritedStdin, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        spawnStage = "duplicate-stdin";
        spawnError = GetLastError();
        result = kClGlSetupDuplicateStdin;
        goto cleanup;
    }
    if (!DuplicateHandle(GetCurrentProcess(), parentStdout, GetCurrentProcess(),
                         &inheritedStdout, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        spawnStage = "duplicate-stdout";
        spawnError = GetLastError();
        result = kClGlSetupDuplicateStdout;
        goto cleanup;
    }
    if (!DuplicateHandle(GetCurrentProcess(), parentStderr, GetCurrentProcess(),
                         &inheritedStderr, 0, TRUE, DUPLICATE_SAME_ACCESS)) {
        spawnStage = "duplicate-stderr";
        spawnError = GetLastError();
        result = kClGlSetupDuplicateStderr;
        goto cleanup;
    }
    attributeSizeQueried = InitializeProcThreadAttributeList(
        nullptr, 1, 0, &attributesSize);
    attributeSizeError = GetLastError();
    if (attributeSizeQueried || attributeSizeError != ERROR_INSUFFICIENT_BUFFER) {
        spawnStage = "query-attribute-size";
        spawnError = attributeSizeQueried ? ERROR_SUCCESS : attributeSizeError;
        result = kClGlSetupQueryAttributeSize;
        goto cleanup;
    }
    attributes = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(
        HeapAlloc(GetProcessHeap(), 0, attributesSize));
    if (attributes == nullptr) {
        spawnStage = "allocate-attributes";
        spawnError = GetLastError();
        result = kClGlSetupAllocateAttributes;
        goto cleanup;
    }
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributesSize)) {
        spawnStage = "initialize-attributes";
        spawnError = GetLastError();
        result = kClGlSetupInitializeAttributes;
        goto cleanup;
    }
    attributesInitialized = TRUE;
    inheritableHandles[0] = inheritedStdin;
    inheritableHandles[1] = inheritedStdout;
    inheritableHandles[2] = inheritedStderr;
    if (!UpdateProcThreadAttribute(
            attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inheritableHandles,
            sizeof(inheritableHandles), nullptr, nullptr)) {
        spawnStage = "update-handle-list";
        spawnError = GetLastError();
        result = kClGlSetupUpdateHandleList;
        goto cleanup;
    }
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = inheritedStdin;
    startup.StartupInfo.hStdOutput = inheritedStdout;
    startup.StartupInfo.hStdError = inheritedStderr;
    startup.lpAttributeList = attributes;
    if (!CreateProcessW(clExe, command, nullptr, nullptr, TRUE,
                        EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
                        &startup.StartupInfo, &process)) {
        spawnStage = "create-process";
        spawnError = GetLastError();
        result = kClGlSetupCreateProcess;
        goto cleanup;
    }
    processCreated = TRUE;
    hardDeadline = GetTickCount64() + kClGlTimeoutMs;
    if (attributesInitialized) {
        DeleteProcThreadAttributeList(attributes);
        attributesInitialized = FALSE;
    }
    HeapFree(GetProcessHeap(), 0, attributes);
    attributes = nullptr;
    if (CloseHandle(inheritedStderr)) inheritedStderr = INVALID_HANDLE_VALUE;
    if (CloseHandle(inheritedStdout)) inheritedStdout = INVALID_HANDLE_VALUE;
    if (CloseHandle(inheritedStdin)) inheritedStdin = INVALID_HANDLE_VALUE;
    executionDeadline = hardDeadline - kClGlTerminateGraceMs;
    if (!WaitForClGlExit(process.hProcess, executionDeadline)) {
        result = 25;
        goto cleanup;
    }
    if (!GetExitCodeProcess(process.hProcess, &exitCode)) {
        result = 25;
        goto cleanup;
    }
    if (exitCode != 0) { result = 26; goto cleanup; }
    if (scratchCanaryNegative) {
        BOOL sentinelCreated = !ScratchCanaryIsAbsent(marker, ERROR_FILE_NOT_FOUND);
        if (sentinelCreated) ScratchCanaryRemoveResidue(marker);
        result = kScratchCanaryNegativeSentinel;
        goto cleanup;
    }
    objectHandle = CreateFileW(object, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (objectHandle == INVALID_HANDLE_VALUE) {
        result = 27;
        goto cleanup;
    }
    hasContent = GetFileSizeEx(objectHandle, &objectSize) && objectSize.QuadPart > 0;
    CloseHandle(objectHandle);
    objectHandle = INVALID_HANDLE_VALUE;
    if (!hasContent) {
        result = 28;
        goto cleanup;
    }
    result = DeleteFileW(object) ? 0 : 29;
cleanup:
    // A grace expiry reports exit 25; the enclosing worker action Job owns
    // kill-on-close containment after this probe releases its local handles.
    if (processCreated && !StopClGlProcess(process.hProcess, hardDeadline))
        result = 25;
    if (objectHandle != INVALID_HANDLE_VALUE) CloseHandle(objectHandle);
    if (process.hThread != nullptr) CloseHandle(process.hThread);
    if (process.hProcess != nullptr) CloseHandle(process.hProcess);
    if (attributesInitialized) DeleteProcThreadAttributeList(attributes);
    if (attributes != nullptr) HeapFree(GetProcessHeap(), 0, attributes);
    if (inheritedStderr != INVALID_HANDLE_VALUE) CloseHandle(inheritedStderr);
    if (inheritedStdout != INVALID_HANDLE_VALUE) CloseHandle(inheritedStdout);
    if (inheritedStdin != INVALID_HANDLE_VALUE) CloseHandle(inheritedStdin);
    if (result == 24 && spawnStage != nullptr)
        EmitClGlSpawnFailure(spawnStage, spawnError);
    return result;
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
    if (argc >= 4 && wcscmp(argv[1], L"--spawn-cl-gl") == 0) {
        return SpawnClGl(argv[2], argv[3], FALSE);
    }
    if (argc >= 4 && wcscmp(argv[1], L"--spawn-cl-gl-negative") == 0) {
        return SpawnClGl(argv[2], argv[3], TRUE);
    }
    if (argc >= 3 && wcscmp(argv[1], L"--scratch-canary-sentinel") == 0) {
        HANDLE marker = CreateFileW(argv[2], GENERIC_WRITE, 0, nullptr,
                                    CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (marker == INVALID_HANDLE_VALUE) return 1;
        BOOL closed = CloseHandle(marker);
        return closed ? 0 : 1;
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
$scratchCanaryStaticRequirements = @(
    'static int RunScratchCanary(const wchar_t* tmp, DWORD* primaryError,',
    'GetTempFileNameW(tmp, L"SBZ", 0,',
    'GENERIC_READ | GENERIC_WRITE | DELETE',
    'FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE',
    'CreateFileMappingW(',
    'MapViewOfFile(',
    'SetFileInformationByHandle(',
    'FileDispositionInfo',
    'M6_CL_GL_SCRATCH_CANARY PASS A=delete-disposition B=delete-on-close',
    '--spawn-cl-gl-negative',
    '--scratch-canary-sentinel',
    'kScratchCanaryATemp = 30',
    'kScratchCanaryACleanup = 39',
    'kScratchCanaryBTemp = 40',
    'kScratchCanaryBCleanup = 48',
    'kScratchCanaryNegativeSentinel = 49',
    'const wchar_t* canaryRoot = scratchCanaryNegative ? missingScratch : tmp;',
    'int canaryResult = RunScratchCanary(canaryRoot, &canaryError, &canaryCleanupFailed);',
    'M6_CL_GL_SCRATCH_CANARY_FAIL stage=%d error=%lu cleanup=%d',
    'BOOL sentinelCreated = !ScratchCanaryIsAbsent(marker, ERROR_FILE_NOT_FOUND);'
)
foreach ($requirement in $scratchCanaryStaticRequirements) {
    if (-not $probeSrc.Contains($requirement)) {
        throw "scratch canary source contract missing: $requirement"
    }
}
$scratchCanarySpawnClGl = $probeSrc.IndexOf('static int SpawnClGl(')
if ($scratchCanarySpawnClGl -lt 0) {
    throw 'scratch canary SpawnClGl source contract missing'
}
$scratchCanarySpawnBody = $probeSrc.Substring($scratchCanarySpawnClGl)
$scratchCanaryRoot = $scratchCanarySpawnBody.IndexOf('const wchar_t* canaryRoot = scratchCanaryNegative ? missingScratch : tmp;')
$scratchCanaryCall = $scratchCanarySpawnBody.IndexOf('int canaryResult = RunScratchCanary(canaryRoot, &canaryError, &canaryCleanupFailed);')
$scratchCanaryCommonReturn = $scratchCanarySpawnBody.IndexOf('if (canaryResult != 0) {')
$scratchCanaryCreateProcess = $scratchCanarySpawnBody.IndexOf('CreateProcessW(')
$scratchCanaryReturnBody = if ($scratchCanaryCommonReturn -ge 0) {
    $scratchCanarySpawnBody.Substring($scratchCanaryCommonReturn, 300)
} else { '' }
if ($scratchCanaryRoot -lt 0 -or $scratchCanaryCall -lt 0 -or
    $scratchCanaryCommonReturn -lt 0 -or $scratchCanaryCreateProcess -lt 0 -or
    $scratchCanaryRoot -ge $scratchCanaryCall -or
    $scratchCanaryCall -ge $scratchCanaryCommonReturn -or
    $scratchCanaryCommonReturn -ge $scratchCanaryCreateProcess -or
    -not $scratchCanaryReturnBody.Contains('return canaryResult;') -or
    $scratchCanarySpawnBody.Contains('RunScratchCanary(tmp)') -or
    $scratchCanarySpawnBody.Contains('RunScratchCanary(missingScratch)') -or
    $scratchCanarySpawnBody.Contains('return kScratchCanaryATemp;')) {
    throw 'scratch canary is not statically ordered before CreateProcessW'
}
Write-Host 'M6_CL_GL_SCRATCH_CANARY_STATIC PASS'
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
$glTraceDir = Join-Path $WorkRoot 'trace-gl'
$verbatimTraceDir = Join-Path $WorkRoot 'trace-verbatim'
$smuggledTraceDir = Join-Path $WorkRoot 'smuggled-trace'
$fakeVfsCwd = Join-Path $WorkRoot 'fake-vfs-cwd'
$rel = 'Src\Input.txt'
$glRel = 'Src\gl_tmp.cpp'
$metadataAbsentRel = 'Src\metadata-absent.h'
$metadataSparseRel = 'Src\metadata-sparse.bin'
$correct = 'hello-from-the-agent-vfs'
$stale = 'STALE-LOCAL-MUST-NOT-BE-READ'
$glStale = 'int gl_tmp( { return 0; }'
$glCorrect = 'int gl_tmp() { return 42; }'
New-Item -ItemType Directory -Force (Split-Path (Join-Path $logicalRoot $rel)) | Out-Null
New-Item -ItemType Directory -Force (Split-Path (Join-Path $backingRoot $rel)) | Out-Null
foreach ($d in @($scratchRoot, $casRoot, $traceDir, $miscTraceDir, $glTraceDir, $verbatimTraceDir, $smuggledTraceDir, $fakeVfsCwd)) {
    New-Item -ItemType Directory -Force $d | Out-Null
}
Set-Content (Join-Path $logicalRoot $rel) $stale -Encoding ascii -NoNewline
Set-Content (Join-Path $backingRoot $rel) $correct -Encoding ascii -NoNewline
Set-Content (Join-Path $logicalRoot $glRel) $glStale -Encoding ascii -NoNewline
Set-Content (Join-Path $backingRoot $glRel) $glCorrect -Encoding ascii -NoNewline
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
$glNegativeCanaryExit = 99
$glExit = 99
$glDiagnosticExit = 99
$glDiagnosticText = ''
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
                $probe --spawn-cl-gl-negative $scratchRoot $probe 2>&1 |
                Out-String | Write-Host
            $glNegativeCanaryExit = $LASTEXITCODE

            & $execVfs "http://$workerAddr" $fsAddr $logicalRoot $glTraceDir -- `
                $probe --spawn-cl-gl $scratchRoot $clExe 2>&1 |
                Out-String | Write-Host
            $glExit = $LASTEXITCODE

            $glDiagnosticLines = @(& cargo run -q -p sembazuru-tracer --bin sembazuru-trace -- `
                diagnose-createfile --trace-dir $glTraceDir --exe-name cl.exe --under $scratchRoot 2>&1)
            $glDiagnosticExit = $LASTEXITCODE
            if ($glDiagnosticLines.Count -eq 1) {
                $glDiagnosticText = [string]$glDiagnosticLines[0]
            }

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
        if ($p -and -not $p.HasExited) {
            Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
            if (-not $p.WaitForExit(5000)) { throw "process did not stop: $($p.Id)" }
        }
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
$glScratchCanaryStages = @{
    30 = 'A GetTempFileNameW'
    31 = 'A CreateFileW'
    32 = 'A CreateFileMappingW'
    33 = 'A MapViewOfFile'
    34 = 'A UnmapViewOfFile'
    35 = 'A CloseHandle mapping'
    36 = 'A SetFileInformationByHandle FileDispositionInfo'
    37 = 'A CloseHandle file'
    38 = 'A GetFileAttributesW absence'
    39 = 'A cleanup DeleteFileW'
    40 = 'B GetTempFileNameW'
    41 = 'B CreateFileW delete-on-close'
    42 = 'B CreateFileMappingW'
    43 = 'B MapViewOfFile'
    44 = 'B UnmapViewOfFile'
    45 = 'B CloseHandle mapping'
    46 = 'B CloseHandle file delete-on-close'
    47 = 'B GetFileAttributesW absence'
    48 = 'B cleanup DeleteFileW'
    49 = 'negative sentinel child or residual'
}
switch ($glNegativeCanaryExit) {
    30 { Write-Host 'M6_CL_GL_SCRATCH_CANARY_NEGATIVE PASS exit=30' }
    31 { $failures += 'scratch canary negative action unexpectedly reached A CreateFileW (exit=31)' }
    32 { $failures += 'scratch canary negative action unexpectedly reached A CreateFileMappingW (exit=32)' }
    33 { $failures += 'scratch canary negative action unexpectedly reached A MapViewOfFile (exit=33)' }
    34 { $failures += 'scratch canary negative action unexpectedly reached A UnmapViewOfFile (exit=34)' }
    35 { $failures += 'scratch canary negative action unexpectedly reached A CloseHandle mapping (exit=35)' }
    36 { $failures += 'scratch canary negative action unexpectedly reached A SetFileInformationByHandle (exit=36)' }
    37 { $failures += 'scratch canary negative action unexpectedly reached A CloseHandle file (exit=37)' }
    38 { $failures += 'scratch canary negative action unexpectedly reached A absence check (exit=38)' }
    39 { $failures += 'scratch canary negative action cleanup failed (exit=39)' }
    40 { $failures += 'scratch canary negative action unexpectedly reached B GetTempFileNameW (exit=40)' }
    41 { $failures += 'scratch canary negative action unexpectedly reached B CreateFileW (exit=41)' }
    42 { $failures += 'scratch canary negative action unexpectedly reached B CreateFileMappingW (exit=42)' }
    43 { $failures += 'scratch canary negative action unexpectedly reached B MapViewOfFile (exit=43)' }
    44 { $failures += 'scratch canary negative action unexpectedly reached B UnmapViewOfFile (exit=44)' }
    45 { $failures += 'scratch canary negative action unexpectedly reached B CloseHandle mapping (exit=45)' }
    46 { $failures += 'scratch canary negative action unexpectedly reached B CloseHandle file (exit=46)' }
    47 { $failures += 'scratch canary negative action unexpectedly reached B absence check (exit=47)' }
    48 { $failures += 'scratch canary negative action cleanup failed (exit=48)' }
    49 { $failures += 'scratch canary negative action created its sentinel or left a residue (exit=49)' }
    default { $failures += "scratch canary negative action returned unexpected exit=$glNegativeCanaryExit; expected 30" }
}
$glSetupStages = @{
    60 = 'get-stdin'
    61 = 'get-stdout'
    62 = 'get-stderr'
    63 = 'duplicate-stdin'
    64 = 'duplicate-stdout'
    65 = 'duplicate-stderr'
    66 = 'query-attribute-size'
    67 = 'allocate-attributes'
    68 = 'initialize-attributes'
    69 = 'update-handle-list'
    70 = 'create-process'
}
if ($glSetupStages.ContainsKey([int]$glExit)) {
    $failures += "hosted cl.exe /GL setup failed: stage=$($glSetupStages[[int]$glExit]) exit=$glExit"
} else {
    switch ($glExit) {
        0 { }
        21 { $failures += 'hosted cl.exe /GL saw mismatched TMP, TEMP, and SEMBAZURU_VFS_SCRATCH; private scratch was not staged consistently' }
        22 { $failures += 'hosted cl.exe /GL could not construct its private-scratch object path' }
        23 { $failures += 'hosted cl.exe /GL could not clear a pre-existing private-scratch object' }
        24 { $failures += 'hosted cl.exe /GL could not be created through the staged launcher/interceptor path' }
        25 { $failures += 'hosted cl.exe /GL did not finish before the probe timeout' }
        26 { $failures += 'hosted cl.exe /GL failed; expected backing Src\\gl_tmp.cpp and writable private scratch (inspect compiler output above)' }
        27 { $failures += 'hosted cl.exe /GL did not create %TMP%\\gl_tmp.obj' }
        28 { $failures += 'hosted cl.exe /GL created an empty %TMP%\\gl_tmp.obj' }
        29 { $failures += 'hosted cl.exe /GL could not delete %TMP%\\gl_tmp.obj' }
        30 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[30]) (exit=30)" }
        31 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[31]) (exit=31)" }
        32 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[32]) (exit=32)" }
        33 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[33]) (exit=33)" }
        34 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[34]) (exit=34)" }
        35 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[35]) (exit=35)" }
        36 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[36]) (exit=36)" }
        37 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[37]) (exit=37)" }
        38 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[38]) (exit=38)" }
        39 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[39]) (exit=39)" }
        40 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[40]) (exit=40)" }
        41 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[41]) (exit=41)" }
        42 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[42]) (exit=42)" }
        43 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[43]) (exit=43)" }
        44 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[44]) (exit=44)" }
        45 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[45]) (exit=45)" }
        46 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[46]) (exit=46)" }
        47 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[47]) (exit=47)" }
        48 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[48]) (exit=48)" }
        49 { $failures += "hosted cl.exe /GL scratch canary failed: $($glScratchCanaryStages[49]) (exit=49)" }
        default { $failures += "hosted cl.exe /GL VFS probe failed (exit=$glExit)" }
    }
}
$glSafeDiagnostic = Get-M6SafeClGlDiagnostic -RawText $glDiagnosticText `
    -KnownSecrets @($scratchRoot, $clExe, 'secret')
if ($null -eq $glSafeDiagnostic) {
    $failures += 'hosted cl.exe /GL CreateFile diagnostic was unsafe or invalid'
    Write-Host 'M6_CL_GL_CREATEFILE_DIAGNOSTIC_UNSAFE'
} else {
    $glDiagnosticExpectedExit = if (-not $glSafeDiagnostic.complete) { 3 } elseif ($glSafeDiagnostic.result -eq 'clean') { 0 } else { 1 }
    if ($glDiagnosticExit -ne $glDiagnosticExpectedExit) {
        $failures += "hosted cl.exe /GL CreateFile diagnostic exit disagreed with validated result (exit=$glDiagnosticExit)"
    }
    if ($glDiagnosticExit -notin @(0, 1)) {
        $failures += "hosted cl.exe /GL CreateFile diagnostic was incomplete or invalid (exit=$glDiagnosticExit)"
    }
    if ($glExit -eq 0 -and $glDiagnosticExit -ne 0) {
        $failures += 'hosted cl.exe /GL succeeded but its CreateFile diagnostic was not clean'
    }
    if ($glExit -eq 26 -and $glDiagnosticExit -notin @(0, 1)) {
        $failures += 'hosted cl.exe /GL failed but its CreateFile diagnostic was incomplete'
    }
    Write-Host $glSafeDiagnostic.summary
    foreach ($record in @($glSafeDiagnostic.records)) { Write-Host $record }
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

# The worker is stopped above. Its dedicated per-action scratch root must now be
# empty: checking the full entry set catches a failed /GL object's temp files as
# well as a surviving action leaf, rather than only the original input fixture.
$leftovers = @(Get-ChildItem -Force $scratchRoot -ErrorAction SilentlyContinue |
    Select-Object -First 5)
if ($leftovers.Count -gt 0) {
    $leftoverPaths = $leftovers | ForEach-Object { $_.FullName }
    $failures += "per-action scratch was not cleaned up after worker shutdown: $($leftoverPaths -join '; ')"
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M6.1b WORKER VFS GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'M6.1b WORKER VFS GATE PASS (worker Execute redirected the read to the agent-served bytes; per-action scratch cleaned up)'
