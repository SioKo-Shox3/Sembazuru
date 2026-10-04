param(
    [string]$ArtifactPath,
    [string]$ExpectedSha256,
    [string]$StationMask = '0x0002',
    [string]$InitProbePath,
    [string]$InitProbeSha256,
    [string]$EntryProbePath,
    [string]$EntryProbeSha256,
    [string]$TerminateProbePath,
    [string]$TerminateProbeSha256
)

function Assert-Session0ProbeParameters([string]$InitPath, [string]$InitHash, [string]$EntryPath, [string]$EntryHash,
    [string]$TerminatePath, [string]$TerminateHash) {
    if ([string]::IsNullOrEmpty($InitPath) -ne [string]::IsNullOrEmpty($InitHash) -or
        [string]::IsNullOrEmpty($EntryPath) -ne [string]::IsNullOrEmpty($EntryHash) -or
        [string]::IsNullOrEmpty($TerminatePath) -ne [string]::IsNullOrEmpty($TerminateHash)) {
        throw '診断EXEのパスとSHA-256は組で指定してください。'
    }
    if ($EntryPath -and -not $InitPath) { throw '固定終了値診断にはInitProbeの指定が必要です。' }
    if ($TerminatePath -and (-not $InitPath -or -not $EntryPath)) {
        throw '固定自己終了診断にはInitProbeとEntryProbeの指定が必要です。'
    }
}

function Get-Session0ServiceDeadline([bool]$InitRequested, [bool]$EntryRequested, [bool]$TerminateRequested = $false) {
    if ($TerminateRequested) {
        if (-not $InitRequested -or -not $EntryRequested) { throw '固定自己終了診断にはInitProbeとEntryProbeの指定が必要です。' }
        # 旧4runに新runの終了10秒/回収35秒/EOF1秒/Drop30+30秒/runtime停止1秒と余裕30秒を加える。
        return 4 * (10 + 35 + 30 + 30 + 1) + (10 + 35 + 1 + 30 + 30 + 1) + 30
    }
    if ($EntryRequested) {
        if (-not $InitRequested) { throw '固定終了値診断にはInitProbeの指定が必要です。' }
        # 4runの実行10秒+再wait35秒+Dropの直下子30秒/Job30秒+runtime停止1秒、外側余裕30秒。
        return 4 * (10 + 35 + 30 + 30 + 1) + 30
    }
    if ($InitRequested) { return 360 }
    return 30
}

function ConvertFrom-Session0StationMask([string]$Value) {
    switch -CaseSensitive ($Value) {
        '0x0002' { return [uint32]0x0002 }
        '0x0022' { return [uint32]0x0022 }
        default { throw '診断の station mask は 0x0002 または 0x0022 が必要です。' }
    }
}

function Assert-Session0FixtureArguments([string[]]$Arguments) {
    if ($Arguments.Count -lt 11 -or $Arguments.Count -gt 14) { throw 'SCM 診断の引数数が一致しません。' }
    $fixed = @('--ignored', '--exact', 'sandbox::tests::window_station_scm_dispatcher_smoke_role',
        '--nocapture', '--test-threads=1', '--')
    if ([IO.Path]::GetFileName($Arguments[0]) -cne 'SbzWindowStationScmSmoke.exe') {
        throw 'SCM 診断の実行ファイル名が一致しません。'
    }
    for ($i = 0; $i -lt $fixed.Count; $i++) {
        if ($Arguments[$i + 1] -cne $fixed[$i]) { throw 'SCM 診断の固定引数が一致しません。' }
    }
    if (-not [IO.Path]::IsPathFullyQualified($Arguments[7]) -or
        -not [IO.Path]::IsPathFullyQualified($Arguments[8]) -or
        $Arguments[9] -cnotmatch '\A[0-9a-fA-F]{32}\z') {
        throw 'SCM 診断のパスまたは nonce が不正です。'
    }
    $null = ConvertFrom-Session0StationMask $Arguments[10]
    if ($Arguments.Count -ge 12) {
        if ($Arguments.Count -eq 14) { Assert-Session0InitProbeHash $Arguments[13] }
        if ($Arguments.Count -ge 13) { Assert-Session0InitProbeHash $Arguments[12] }
        Assert-Session0InitProbeHash $Arguments[11]
        $root = $Arguments[7]
        if ($root -cnotmatch '\A[A-Za-z]:\\[^\r\n]+\z' -or
            @($root.Substring(3).Split('\') | Where-Object {
                $_.Length -eq 0 -or $_.EndsWith('.') -or $_.EndsWith(' ') -or $_ -match '[\p{Cc}"<>|?*:/]'
            }).Count -ne 0 -or $Arguments[8] -cne $root -or
            $Arguments[0] -cne ($root + '\SbzWindowStationScmSmoke.exe')) {
            throw '追加診断の固定配置が一致しません。'
        }
    }
}

$record = $null
$requestedStationMask = ConvertFrom-Session0StationMask $StationMask

$env:PSModulePath = "$PSHOME\Modules"
$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    [Console]::Error.WriteLine('This probe requires an already-elevated Administrator PowerShell.')
    [Console]::Error.WriteLine('No service or fixture state was changed.')
    exit 1
}

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# SECURITY CONTRACT: this file is a runner payload, never an elevated `-File` target. The
# outer bootstrap must run in an already-elevated PowerShell, open these runner bytes once
# with FileShare.Read, verify their final local path and expected SHA-256, then invoke exactly
# those bytes via ScriptBlock::Create. A ScriptBlock invocation has no PSCommandPath.
# Do not add cmdlets outside the $PSHOME startup set; native P/Invoke is required for SCM reads.
if (-not [string]::IsNullOrEmpty($PSCommandPath)) {
    throw 'Elevated direct -File execution is forbidden; use the verified in-memory bootstrap.'
}
if ($args.Count -ne 0) { throw '指定できる引数は ArtifactPath、ExpectedSha256、StationMask、InitProbePath、InitProbeSha256、EntryProbePath、EntryProbeSha256、TerminateProbePath、TerminateProbeSha256 だけです。' }
if ([string]::IsNullOrWhiteSpace($ArtifactPath) -or
    [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
    throw 'ArtifactPath and ExpectedSha256 are required after elevation.'
}
if ($ExpectedSha256 -notmatch '\A[0-9a-fA-F]{64}\z') {
    throw 'ExpectedSha256 must be exactly 64 hexadecimal characters.'
}
$ExpectedSha256 = $ExpectedSha256.ToLowerInvariant()
Assert-Session0ProbeParameters $InitProbePath $InitProbeSha256 $EntryProbePath $EntryProbeSha256 $TerminateProbePath $TerminateProbeSha256

$serviceName = 'SembazuruWindowStationProbeSmoke'
$workerServiceName = 'SembazuruWorker'
$fixtureBasename = 'SbzWindowStationScmSmoke.exe'
$selector = 'sandbox::tests::window_station_scm_dispatcher_smoke_role'
$noWindowCausalMagic = [uint32]0x53425b31
$noWindowNotSufficientMagic = [uint32]0x53425b32
$indeterminateMagic = [uint32]0x53425b33
$actionStartsMagic = [uint32]0x53425b34
$contractFailureMagic = [uint32]0x53425aff
$diagnosticFailureMagic = [uint32]0x53425afe
$brokerTokenFailureMagic = [uint32]0x53425af0
$publishFailureMagic = [uint32]0x53425af1
$scratchCleanupFailureMagic = [uint32]0x53425af2
$runtimeFailureMagic = [uint32]0x53425af3
$errorServiceSpecific = [uint32]1066
$serviceStopped = [uint32]1
$serviceRunning = [uint32]4
$root = $null
$rootHandle = $null
$rootIdentity = $null
$targetHandle = $null
$targetIdentity = $null
$targetLease = $null
$leaseIdentity = $null
$cleanupHandle = $null
$targetStream = $null
$sourceStream = $null
$initProbe = @{ Path = ''; Hash = ''; Source = $null; Target = $null; Identity = $null; Lease = $null; ReadHold = $null; ServiceSid = '' }
$entryProbe = @{ Path = ''; Hash = ''; Source = $null; Target = $null; Identity = $null; Lease = $null; ReadHold = $null; ServiceSid = '' }
$terminateProbe = @{ Path = ''; Hash = ''; Source = $null; Target = $null; Identity = $null; Lease = $null; ReadHold = $null; ServiceSid = '' }
$serviceHandle = [IntPtr]::Zero
$ownedRoot = $false
$ownedService = $false
$serviceStartAttempted = $false
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$workerBefore = $null
$workerAfter = $null
$diagnosticNonce = [Guid]::NewGuid().ToString('N')
$diagnosticRecordPath = $null
$throwawayProcessId = [uint32]0
$throwawayProcess = $null
$diagnosticClassification = $null
$diagnosticDetail = $null

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Sembazuru {
    public sealed class ProbeServiceStatus {
        public uint State { get; set; }
        public uint Win32ExitCode { get; set; }
        public uint ServiceSpecificExitCode { get; set; }
        public uint ProcessId { get; set; }
    }

    public sealed class ProbeFileIdentity {
        public uint Attributes { get; set; }
        public uint LinkCount { get; set; }
        public string FileId { get; set; }
        public string FinalPath { get; set; }
        public string SecuritySddl { get; set; }
        public bool DaclPresent { get; set; }
        public bool DaclNonNull { get; set; }
    }

    public sealed class ProbeWorkerSnapshot {
        public bool Exists { get; set; }
        public bool DeletePending { get; set; }
        public uint ConfigServiceType { get; set; }
        public uint StartType { get; set; }
        public uint ErrorControl { get; set; }
        public uint TagId { get; set; }
        public string BinaryPath { get; set; }
        public string LoadOrderGroup { get; set; }
        public string[] Dependencies { get; set; }
        public string ServiceStartName { get; set; }
        public string DisplayName { get; set; }
        public uint StatusState { get; set; }
        public uint StatusServiceType { get; set; }
        public uint ControlsAccepted { get; set; }
        public uint? ProcessId { get; set; }
    }

    public sealed class HeldPath : IDisposable {
        public IntPtr Handle { get; private set; }
        internal HeldPath(IntPtr handle) { Handle = handle; }
        public void Dispose() {
            if (Handle != IntPtr.Zero) {
                if (!WindowStationProbeNative.CloseHandle(Handle))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                Handle = IntPtr.Zero;
            }
        }
    }

    public sealed class HeldProcess : IDisposable {
        public IntPtr Handle { get; private set; }
        internal HeldProcess(IntPtr handle) { Handle = handle; }
        public void Dispose() {
            if (Handle != IntPtr.Zero) {
                if (!WindowStationProbeNative.CloseHandle(Handle))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                Handle = IntPtr.Zero;
            }
        }
    }

    public sealed class RestorePrivilege : IDisposable {
        internal IntPtr Token;
        internal WindowStationProbeNative.TOKEN_PRIVILEGES Previous;
        private bool active;
        internal RestorePrivilege(
            IntPtr token, WindowStationProbeNative.TOKEN_PRIVILEGES previous) {
            Token = token;
            Previous = previous;
            active = true;
        }
        public void Dispose() {
            if (!active) return;
            try { WindowStationProbeNative.RestoreTokenPrivileges(Token, ref Previous); }
            finally {
                WindowStationProbeNative.CloseHandle(Token);
                Token = IntPtr.Zero;
                active = false;
            }
        }
    }

    public static class WindowStationProbeNative {
        internal const uint ERROR_NOT_ALL_ASSIGNED = 1300;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES {
            internal uint nLength;
            internal IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] internal bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            internal uint dwFileAttributes;
            internal System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            internal System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            internal uint dwVolumeSerialNumber;
            internal uint nFileSizeHigh;
            internal uint nFileSizeLow;
            internal uint nNumberOfLinks;
            internal uint nFileIndexHigh;
            internal uint nFileIndexLow;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS_PROCESS {
            internal uint dwServiceType;
            internal uint dwCurrentState;
            internal uint dwControlsAccepted;
            internal uint dwWin32ExitCode;
            internal uint dwServiceSpecificExitCode;
            internal uint dwCheckPoint;
            internal uint dwWaitHint;
            internal uint dwProcessId;
            internal uint dwServiceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_STATUS {
            internal uint dwServiceType;
            internal uint dwCurrentState;
            internal uint dwControlsAccepted;
            internal uint dwWin32ExitCode;
            internal uint dwServiceSpecificExitCode;
            internal uint dwCheckPoint;
            internal uint dwWaitHint;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SERVICE_SID_INFO { internal uint dwServiceSidType; }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct QUERY_SERVICE_CONFIG {
            internal uint dwServiceType;
            internal uint dwStartType;
            internal uint dwErrorControl;
            internal IntPtr lpBinaryPathName;
            internal IntPtr lpLoadOrderGroup;
            internal uint dwTagId;
            internal IntPtr lpDependencies;
            internal IntPtr lpServiceStartName;
            internal IntPtr lpDisplayName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_DISPOSITION_INFO {
            [MarshalAs(UnmanagedType.Bool)] internal bool DeleteFile;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID { internal uint LowPart; internal int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        internal struct LUID_AND_ATTRIBUTES {
            internal LUID Luid;
            internal uint Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_PRIVILEGES {
            internal uint PrivilegeCount;
            internal LUID_AND_ATTRIBUTES Privileges;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string descriptor, uint revision, out IntPtr securityDescriptor, out uint size);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle, int objectType, uint securityInformation,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl,
            out IntPtr securityDescriptor);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint SetSecurityInfo(
            IntPtr handle, int objectType, uint securityInformation,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetSecurityDescriptorDacl(
            IntPtr securityDescriptor, [MarshalAs(UnmanagedType.Bool)] out bool present,
            out IntPtr dacl, [MarshalAs(UnmanagedType.Bool)] out bool defaulted);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr descriptor, uint revision, uint securityInformation,
            out IntPtr text, out uint textLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateDirectoryW(
            string path, ref SECURITY_ATTRIBUTES securityAttributes);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(
            string path, uint desiredAccess, uint shareMode, IntPtr securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "CreateFileW")]
        private static extern IntPtr CreateFileWithSecurityW(
            string path, uint desiredAccess, uint shareMode, ref SECURITY_ATTRIBUTES securityAttributes,
            uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandleW(
            IntPtr file, char[] path, uint pathLength, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(
            IntPtr file, out BY_HANDLE_FILE_INFORMATION information);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(
            IntPtr file, int fileInformationClass, ref FILE_DISPOSITION_INFO fileInformation,
            uint bufferSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateProcess(IntPtr process, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);
        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(
            IntPtr process, uint desiredAccess, out IntPtr token);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool LookupPrivilegeValueW(
            string systemName, string name, out LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr token, bool disableAll, ref TOKEN_PRIVILEGES newState,
            uint bufferLength, out TOKEN_PRIVILEGES previousState, out uint returnLength);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManagerW(
            string machineName, string databaseName, uint desiredAccess);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenServiceW(
            IntPtr manager, string serviceName, uint desiredAccess);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateServiceW(
            IntPtr manager, string serviceName, string displayName, uint desiredAccess,
            uint serviceType, uint startType, uint errorControl, string binaryPath,
            string loadOrderGroup, IntPtr tagId, string dependencies,
            string serviceStartName, string password);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ChangeServiceConfig2W(
            IntPtr service, uint infoLevel, ref SERVICE_SID_INFO info);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceConfig2W(
            IntPtr service, uint infoLevel, IntPtr buffer, uint bufferSize,
            out uint bytesNeeded);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryServiceConfigW(
            IntPtr service, IntPtr buffer, uint bufferSize, out uint bytesNeeded);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceStatusEx(
            IntPtr service, int infoLevel, out SERVICE_STATUS_PROCESS status,
            uint bufferSize, out uint bytesNeeded);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool StartServiceW(
            IntPtr service, uint argumentCount, IntPtr arguments);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool ControlService(
            IntPtr service, uint control, out SERVICE_STATUS status);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool DeleteService(IntPtr service);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr handle);

        public static void CreateProtectedDirectory(string path, string sddl) {
            IntPtr descriptor;
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, out descriptor, out size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
                attributes.nLength = (uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                attributes.lpSecurityDescriptor = descriptor;
                attributes.bInheritHandle = false;
                if (!CreateDirectoryW(path, ref attributes))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            finally { LocalFree(descriptor); }
        }

        public static RestorePrivilege EnableRestorePrivilege() {
            const uint TOKEN_ADJUST_PRIVILEGES = 0x20;
            const uint TOKEN_QUERY = 0x8;
            const uint SE_PRIVILEGE_ENABLED = 0x2;
            IntPtr token;
            if (!OpenProcessToken(
                GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                LUID luid;
                if (!LookupPrivilegeValueW(null, "SeRestorePrivilege", out luid))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                TOKEN_PRIVILEGES requested = new TOKEN_PRIVILEGES();
                requested.PrivilegeCount = 1;
                requested.Privileges.Luid = luid;
                requested.Privileges.Attributes = SE_PRIVILEGE_ENABLED;
                TOKEN_PRIVILEGES previous;
                uint returned;
                if (!AdjustTokenPrivileges(
                    token, false, ref requested,
                    (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), out previous, out returned))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                int adjustment = Marshal.GetLastWin32Error();
                if (adjustment == ERROR_NOT_ALL_ASSIGNED)
                    throw new Win32Exception(adjustment);
                if (adjustment != 0) throw new Win32Exception(adjustment);
                return new RestorePrivilege(token, previous);
            }
            catch {
                CloseHandle(token);
                throw;
            }
        }

        internal static void RestoreTokenPrivileges(
            IntPtr token, ref TOKEN_PRIVILEGES previous) {
            TOKEN_PRIVILEGES discarded;
            uint returned;
            if (!AdjustTokenPrivileges(
                token, false, ref previous,
                (uint)Marshal.SizeOf(typeof(TOKEN_PRIVILEGES)), out discarded, out returned))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            int adjustment = Marshal.GetLastWin32Error();
            if (adjustment != 0) throw new Win32Exception(adjustment);
        }

        public static HeldPath OpenDirectory(string path, bool denyDeleteShare) {
            const uint READ_CONTROL = 0x00020000;
            const uint DELETE = 0x00010000;
            const uint FILE_READ_ATTRIBUTES = 0x80;
            const uint FILE_LIST_DIRECTORY = 0x1;
            const uint FILE_SHARE_READ = 0x1;
            const uint FILE_SHARE_WRITE = 0x2;
            const uint FILE_SHARE_DELETE = 0x4;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            uint share = FILE_SHARE_READ | FILE_SHARE_WRITE;
            if (!denyDeleteShare) share |= FILE_SHARE_DELETE;
            IntPtr handle = CreateFileW(
                path, READ_CONTROL | DELETE | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                share, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new HeldPath(handle);
        }

        public static HeldPath CreateProtectedFile(string path, string sddl) {
            const uint GENERIC_READ = 0x80000000;
            const uint GENERIC_WRITE = 0x40000000;
            const uint DELETE = 0x00010000;
            const uint FILE_SHARE_READ = 0x1;
            const uint CREATE_NEW = 1;
            const uint FILE_ATTRIBUTE_NORMAL = 0x80;
            IntPtr descriptor;
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, out descriptor, out size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
                attributes.nLength = (uint)Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                attributes.lpSecurityDescriptor = descriptor;
                attributes.bInheritHandle = false;
                IntPtr handle = CreateFileWithSecurityW(
                    path, GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ,
                    ref attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (handle == new IntPtr(-1))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return new HeldPath(handle);
            }
            finally { LocalFree(descriptor); }
        }

        public static HeldPath OpenLease(string path) {
            const uint READ_CONTROL = 0x00020000;
            const uint FILE_READ_ATTRIBUTES = 0x80;
            const uint FILE_SHARE_READ = 0x1;
            const uint FILE_SHARE_WRITE = 0x2;
            const uint FILE_SHARE_DELETE = 0x4;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            IntPtr handle = CreateFileW(
                path, READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new HeldPath(handle);
        }

        public static HeldPath OpenAclMutation(string path, bool directory) {
            const uint READ_CONTROL = 0x00020000;
            const uint WRITE_DAC = 0x00040000;
            const uint FILE_READ_ATTRIBUTES = 0x80;
            const uint FILE_SHARE_READ = 0x1;
            const uint FILE_SHARE_WRITE = 0x2;
            const uint FILE_SHARE_DELETE = 0x4;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            uint flags = FILE_FLAG_OPEN_REPARSE_POINT;
            if (directory) flags |= FILE_FLAG_BACKUP_SEMANTICS;
            IntPtr handle = CreateFileW(
                path, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, flags, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new HeldPath(handle);
        }

        public static HeldPath OpenCleanupDelete(string path) {
            const uint READ_CONTROL = 0x00020000;
            const uint DELETE = 0x00010000;
            const uint FILE_READ_ATTRIBUTES = 0x80;
            const uint FILE_SHARE_READ = 0x1;
            const uint FILE_SHARE_WRITE = 0x2;
            const uint FILE_SHARE_DELETE = 0x4;
            const uint OPEN_EXISTING = 3;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            IntPtr handle = CreateFileW(
                path, DELETE | READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new HeldPath(handle);
        }

        public static string FinalPath(IntPtr handle) {
            char[] buffer = new char[32768];
            uint used = GetFinalPathNameByHandleW(handle, buffer, (uint)buffer.Length, 0);
            if (used == 0 || used >= buffer.Length)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            string value = new string(buffer, 0, (int)used);
            if (value.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                return @"\\" + value.Substring(8);
            if (value.StartsWith(@"\\?\", StringComparison.Ordinal))
                return value.Substring(4);
            return value;
        }

        private static string SecuritySddl(
            IntPtr handle, out bool daclPresent, out bool daclNonNull) {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint result = GetSecurityInfo(
                handle, 1, 0x00000005, out owner, out group, out dacl, out sacl,
                out descriptor);
            if (result != 0) throw new Win32Exception((int)result);
            IntPtr text = IntPtr.Zero;
            try {
                bool defaulted;
                if (!GetSecurityDescriptorDacl(
                    descriptor, out daclPresent, out dacl, out defaulted))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                daclNonNull = dacl != IntPtr.Zero;
                uint length;
                if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, 1, 0x00000005, out text, out length))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return Marshal.PtrToStringUni(text);
            }
            finally {
                if (text != IntPtr.Zero) LocalFree(text);
                if (descriptor != IntPtr.Zero) LocalFree(descriptor);
            }
        }

        public static ProbeFileIdentity InspectHandle(IntPtr handle) {
            BY_HANDLE_FILE_INFORMATION info;
            if (!GetFileInformationByHandle(handle, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            bool daclPresent;
            bool daclNonNull;
            string securitySddl = SecuritySddl(handle, out daclPresent, out daclNonNull);
            return new ProbeFileIdentity {
                Attributes = info.dwFileAttributes,
                LinkCount = info.nNumberOfLinks,
                FileId = info.dwVolumeSerialNumber.ToString("x8") + ":" +
                    info.nFileIndexHigh.ToString("x8") + info.nFileIndexLow.ToString("x8"),
                FinalPath = FinalPath(handle),
                SecuritySddl = securitySddl,
                DaclPresent = daclPresent,
                DaclNonNull = daclNonNull
            };
        }

        public static void SetProtectedDacl(IntPtr handle, string sddl) {
            const uint DACL_SECURITY_INFORMATION = 0x4;
            const uint PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000;
            IntPtr descriptor;
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, 1, out descriptor, out size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                bool present, defaulted;
                IntPtr dacl;
                if (!GetSecurityDescriptorDacl(descriptor, out present, out dacl, out defaulted) ||
                    !present || dacl == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                uint result = SetSecurityInfo(
                    handle, 1, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
                if (result != 0) throw new Win32Exception((int)result);
            }
            finally { LocalFree(descriptor); }
        }

        public static string ServiceAccountSid(string serviceName) {
            System.Security.Principal.NTAccount account = new System.Security.Principal.NTAccount(
                "NT SERVICE", serviceName);
            return ((System.Security.Principal.SecurityIdentifier)account.Translate(
                typeof(System.Security.Principal.SecurityIdentifier))).Value;
        }

        public static void MarkDelete(IntPtr handle) {
            FILE_DISPOSITION_INFO disposition = new FILE_DISPOSITION_INFO();
            disposition.DeleteFile = true;
            if (!SetFileInformationByHandle(
                handle, 4, ref disposition,
                (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO))))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        private static IntPtr OpenManager(uint access) {
            IntPtr manager = OpenSCManagerW(null, null, access);
            if (manager == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return manager;
        }
        public static bool ServiceExists(string serviceName) {
            IntPtr manager = OpenManager(0x0001);
            try {
                IntPtr service = OpenServiceW(manager, serviceName, 0x0004);
                if (service != IntPtr.Zero) {
                    CloseServiceHandle(service);
                    return true;
                }
                int error = Marshal.GetLastWin32Error();
                if (error == 1060) return false;
                if (error == 1072) return true;
                throw new Win32Exception(error);
            }
            finally { CloseServiceHandle(manager); }
        }
        private static string ReadServiceString(IntPtr value) {
            return value == IntPtr.Zero ? null : Marshal.PtrToStringUni(value);
        }
        private static string[] ReadServiceMultiString(IntPtr value) {
            if (value == IntPtr.Zero) return null;
            System.Collections.Generic.List<string> segments =
                new System.Collections.Generic.List<string>();
            IntPtr current = value;
            while (true) {
                string segment = Marshal.PtrToStringUni(current);
                if (String.IsNullOrEmpty(segment)) break;
                segments.Add(segment);
                current = IntPtr.Add(current, (segment.Length + 1) * 2);
            }
            return segments.ToArray();
        }
        public static ProbeWorkerSnapshot GetWorkerSnapshot(string serviceName) {
            IntPtr manager = OpenManager(0x0001);
            try {
                IntPtr service = OpenServiceW(manager, serviceName, 0x0001 | 0x0004);
                if (service == IntPtr.Zero) {
                    int error = Marshal.GetLastWin32Error();
                    if (error == 1060) return new ProbeWorkerSnapshot {
                        Exists = false, DeletePending = false
                    };
                    if (error == 1072) return new ProbeWorkerSnapshot {
                        Exists = false, DeletePending = true
                    };
                    throw new Win32Exception(error);
                }
                try {
                    uint needed;
                    QueryServiceConfigW(service, IntPtr.Zero, 0, out needed);
                    if (needed == 0) throw new Win32Exception(Marshal.GetLastWin32Error());
                    IntPtr buffer = Marshal.AllocHGlobal((int)needed);
                    try {
                        if (!QueryServiceConfigW(service, buffer, needed, out needed))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        QUERY_SERVICE_CONFIG config =
                            (QUERY_SERVICE_CONFIG)Marshal.PtrToStructure(
                                buffer, typeof(QUERY_SERVICE_CONFIG));
                        SERVICE_STATUS_PROCESS status;
                        uint statusNeeded;
                        if (!QueryServiceStatusEx(
                            service, 0, out status,
                            (uint)Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS)),
                            out statusNeeded))
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        return new ProbeWorkerSnapshot {
                            Exists = true,
                            DeletePending = false,
                            ConfigServiceType = config.dwServiceType,
                            StartType = config.dwStartType,
                            ErrorControl = config.dwErrorControl,
                            TagId = config.dwTagId,
                            BinaryPath = ReadServiceString(config.lpBinaryPathName),
                            LoadOrderGroup = ReadServiceString(config.lpLoadOrderGroup),
                            Dependencies = ReadServiceMultiString(config.lpDependencies),
                            ServiceStartName = ReadServiceString(config.lpServiceStartName),
                            DisplayName = ReadServiceString(config.lpDisplayName),
                            StatusState = status.dwCurrentState,
                            StatusServiceType = status.dwServiceType,
                            ControlsAccepted = status.dwControlsAccepted,
                            ProcessId = status.dwCurrentState == 4 ?
                                (uint?)status.dwProcessId : null
                        };
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
                finally { CloseServiceHandle(service); }
            }
            finally { CloseServiceHandle(manager); }
        }
        public static IntPtr CreateProbeService(
            string serviceName, string binaryPath, string serviceAccount) {
            IntPtr manager = OpenManager(0x0003);
            try {
                IntPtr service = CreateServiceW(
                    manager, serviceName, serviceName, 0x000f01ff,
                    0x00000010, 0x00000003, 0x00000001, binaryPath,
                    null, IntPtr.Zero, null, serviceAccount, null);
                if (service == IntPtr.Zero)
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return service;
            }
            finally { CloseServiceHandle(manager); }
        }
        public static void SetUnrestrictedServiceSid(IntPtr service) {
            SERVICE_SID_INFO info = new SERVICE_SID_INFO();
            info.dwServiceSidType = 1;
            if (!ChangeServiceConfig2W(service, 5, ref info))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public static uint QueryServiceSidType(IntPtr service) {
            uint needed;
            QueryServiceConfig2W(service, 5, IntPtr.Zero, 0, out needed);
            if (needed < 4) throw new Win32Exception(Marshal.GetLastWin32Error());
            IntPtr buffer = Marshal.AllocHGlobal((int)needed);
            try {
                if (!QueryServiceConfig2W(service, 5, buffer, needed, out needed))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                return (uint)Marshal.ReadInt32(buffer);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        public static void StartWithoutArguments(IntPtr service) {
            if (!StartServiceW(service, 0, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public static ProbeServiceStatus QueryStatus(IntPtr service) {
            SERVICE_STATUS_PROCESS native;
            uint needed;
            if (!QueryServiceStatusEx(
                service, 0, out native,
                (uint)Marshal.SizeOf(typeof(SERVICE_STATUS_PROCESS)), out needed))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            return new ProbeServiceStatus {
                State = native.dwCurrentState,
                Win32ExitCode = native.dwWin32ExitCode,
                ServiceSpecificExitCode = native.dwServiceSpecificExitCode,
                ProcessId = native.dwProcessId
            };
        }
        public static HeldProcess HoldProcess(uint processId) {
            const uint PROCESS_TERMINATE = 0x0001;
            const uint SYNCHRONIZE = 0x00100000;
            IntPtr process = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, false, processId);
            if (process == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            return new HeldProcess(process);
        }
        public static void TerminateHeldProcessAndWait(HeldProcess process, uint milliseconds) {
            if (process == null || process.Handle == IntPtr.Zero)
                throw new InvalidOperationException("throwaway process handle is unavailable");
            if (!TerminateProcess(process.Handle, 1)) {
                int error = Marshal.GetLastWin32Error();
                if (error != 5) throw new Win32Exception(error);
            }
            uint wait = WaitForSingleObject(process.Handle, milliseconds);
            if (wait == 258) throw new TimeoutException("held throwaway process reap timed out");
            if (wait != 0) throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        public static void RequestStop(IntPtr service) {
            SERVICE_STATUS status;
            if (!ControlService(service, 1, out status)) {
                int error = Marshal.GetLastWin32Error();
                if (error != 1052 && error != 1062) throw new Win32Exception(error);
            }
        }
        public static void Delete(IntPtr service) {
            if (!DeleteService(service)) {
                int error = Marshal.GetLastWin32Error();
                if (error != 1072) throw new Win32Exception(error);
            }
        }
        public static void CloseService(IntPtr service) {
            if (service != IntPtr.Zero && !CloseServiceHandle(service))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@

function Assert-LocalAbsolutePath([string]$Path, [string]$Label) {
    if (-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')) {
        throw "$Label must be an absolute local path."
    }
    $rootPart = [IO.Path]::GetPathRoot($Path)
    if ($rootPart -notmatch '\A[A-Za-z]:\\\z') { throw "$Label is not on a local drive." }
}

function Assert-ExactPath([string]$Actual, [string]$Expected, [string]$Label) {
    $actualFull = [IO.Path]::GetFullPath($Actual).TrimEnd('\')
    $expectedFull = [IO.Path]::GetFullPath($Expected).TrimEnd('\')
    if (-not [string]::Equals(
        $actualFull, $expectedFull, [StringComparison]::OrdinalIgnoreCase
    )) { throw "$Label final path mismatch: $actualFull != $expectedFull" }
}

function Convert-AccessMaskToUInt32([int]$Mask) {
    return [BitConverter]::ToUInt32([BitConverter]::GetBytes($Mask), 0)
}

function Get-RawDescriptor([string]$Sddl) {
    return [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
}

function Assert-ProgramFilesParentAcl($Identity) {
    if (-not $Identity.DaclPresent -or -not $Identity.DaclNonNull) {
        throw 'Program Files parent DACL is absent or NULL.'
    }
    $descriptor = Get-RawDescriptor $Identity.SecuritySddl
    $dangerous = [uint32]0x500d0044
    $trustedInstaller = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    $whitelist = @('S-1-5-18', 'S-1-5-32-544', $trustedInstaller)
    if ($whitelist -notcontains $descriptor.Owner.Value) {
        throw "Program Files parent owner is not trusted: $($descriptor.Owner.Value)"
    }
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.QualifiedAce] -or
            $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
            ($ace.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) -ne 0) {
            continue
        }
        $mask = Convert-AccessMaskToUInt32 $ace.AccessMask
        if (($mask -band $dangerous) -ne 0 -and
            $whitelist -notcontains $ace.SecurityIdentifier.Value) {
            throw ("Program Files parent grants dangerous rights 0x{0:x8} to {1}" -f
                $mask, $ace.SecurityIdentifier.Value)
        }
    }
}

function Assert-ExactRootSecurity($Identity) {
    if (-not $Identity.DaclPresent -or -not $Identity.DaclNonNull) {
        throw 'fixture root DACL is absent or NULL'
    }
    $descriptor = Get-RawDescriptor $Identity.SecuritySddl
    if ($descriptor.Owner.Value -ne 'S-1-5-18' -or
        ($descriptor.ControlFlags -band
            [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
        throw 'fixture root owner/protected-DACL mismatch'
    }
    $aces = @($descriptor.DiscretionaryAcl)
    if ($aces.Count -ne 2) { throw "fixture root ACE count mismatch: $($aces.Count)" }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $matched = @($aces | Where-Object {
            $_ -is [Security.AccessControl.CommonAce] -and
            $_.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
            $_.SecurityIdentifier.Value -eq $sid -and
            (Convert-AccessMaskToUInt32 $_.AccessMask) -eq [uint32]0x001f01ff -and
            ($_.AceFlags -band [Security.AccessControl.AceFlags]::ContainerInherit) -ne 0 -and
            ($_.AceFlags -band [Security.AccessControl.AceFlags]::ObjectInherit) -ne 0 -and
            ($_.AceFlags -band [Security.AccessControl.AceFlags]::InheritOnly) -eq 0
        })
        if ($matched.Count -ne 1) { throw "fixture root DACL mismatch for $sid" }
    }
}

function Assert-ExactFileSecurity($Identity) {
    if (-not $Identity.DaclPresent -or -not $Identity.DaclNonNull) {
        throw 'fixture executable DACL is absent or NULL'
    }
    $descriptor = Get-RawDescriptor $Identity.SecuritySddl
    if ($descriptor.Owner.Value -ne 'S-1-5-18' -or
        ($descriptor.ControlFlags -band
            [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
        throw 'fixture executable owner/protected-DACL mismatch'
    }
    $aces = @($descriptor.DiscretionaryAcl)
    if ($aces.Count -ne 2) { throw "fixture executable ACE count mismatch: $($aces.Count)" }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $matched = @($aces | Where-Object {
            $_ -is [Security.AccessControl.CommonAce] -and
            $_.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
            $_.SecurityIdentifier.Value -eq $sid -and
            (Convert-AccessMaskToUInt32 $_.AccessMask) -eq [uint32]0x001f01ff -and
            $_.AceFlags -eq [Security.AccessControl.AceFlags]::None
        })
        if ($matched.Count -ne 1) { throw "fixture executable DACL mismatch for $sid" }
    }
}

function Assert-RegularIdentity($Identity, [string]$ExpectedPath, [string]$Label) {
    Assert-ExactPath $Identity.FinalPath $ExpectedPath $Label
    if (($Identity.Attributes -band [uint32]0x10) -ne 0 -or
        ($Identity.Attributes -band [uint32]0x400) -ne 0 -or
        $Identity.LinkCount -ne 1) {
        throw "$Label is not a regular non-reparse single-link file"
    }
}

function Assert-RegularDirectoryIdentity($Identity, [string]$ExpectedPath, [string]$Label) {
    Assert-ExactPath $Identity.FinalPath $ExpectedPath $Label
    if (($Identity.Attributes -band [uint32]0x10) -eq 0 -or
        ($Identity.Attributes -band [uint32]0x400) -ne 0) {
        throw "$Label is not a regular non-reparse directory"
    }
}

function Assert-EquivalentFileIdentity(
    $Expected, $Actual, [string]$ExpectedPath, [string]$Label,
    [switch]$AllowSecuritySddlChange
) {
    Assert-RegularIdentity $Actual $ExpectedPath $Label
    foreach ($property in @('FileId', 'DaclPresent', 'DaclNonNull')) {
        if (-not [object]::Equals($Expected.$property, $Actual.$property)) {
            throw "$Label $property mismatch"
        }
    }
    foreach ($property in @('FinalPath')) {
        if (-not [string]::Equals(
            $Expected.$property, $Actual.$property, [StringComparison]::Ordinal
        )) { throw "$Label $property mismatch" }
    }
    if (-not $AllowSecuritySddlChange) {
        if (-not [string]::Equals(
            $Expected.SecuritySddl, $Actual.SecuritySddl, [StringComparison]::Ordinal
        )) { throw "$Label SecuritySddl mismatch" }
        Assert-ExactFileSecurity $Actual
    }
}

function Assert-EquivalentRootIdentity(
    $Expected, $Actual, [string]$ExpectedPath, [string]$Label,
    [switch]$AllowSecuritySddlChange
) {
    Assert-RegularDirectoryIdentity $Actual $ExpectedPath $Label
    foreach ($property in @('FileId', 'DaclPresent', 'DaclNonNull')) {
        if (-not [object]::Equals($Expected.$property, $Actual.$property)) {
            throw "$Label $property mismatch"
        }
    }
    if (-not $AllowSecuritySddlChange -and -not [string]::Equals(
        $Expected.SecuritySddl, $Actual.SecuritySddl, [StringComparison]::Ordinal
    )) { throw "$Label SecuritySddl mismatch" }
}

function Get-WorkerSnapshot {
    return [Sembazuru.WindowStationProbeNative]::GetWorkerSnapshot($workerServiceName)
}

function Test-SnapshotEqual($Left, $Right) {
    foreach ($property in @(
        'Exists', 'DeletePending', 'ConfigServiceType', 'StartType', 'ErrorControl', 'TagId',
        'BinaryPath', 'LoadOrderGroup', 'ServiceStartName', 'DisplayName', 'StatusState',
        'StatusServiceType', 'ControlsAccepted', 'ProcessId'
    )) {
        if (-not [object]::Equals($Left.$property, $Right.$property)) { return $false }
    }
    if ($null -eq $Left.Dependencies -or $null -eq $Right.Dependencies) {
        return $null -eq $Left.Dependencies -and $null -eq $Right.Dependencies
    }
    if ($Left.Dependencies.Length -ne $Right.Dependencies.Length) { return $false }
    for ($index = 0; $index -lt $Left.Dependencies.Length; $index++) {
        if (-not [string]::Equals(
            $Left.Dependencies[$index], $Right.Dependencies[$index],
            [StringComparison]::Ordinal
        )) { return $false }
    }
    return $true
}

function Get-StreamSha256([IO.Stream]$Stream) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return -join ($sha.ComputeHash($Stream) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
}

function Assert-Session0InitProbeHash([string]$Hash) {
    if ($Hash -cnotmatch '\A[0-9a-f]{64}\z') {
        throw '追加診断 EXE の SHA-256 は小文字16進64桁が必要です。'
    }
}

function Assert-Session0ProbeContentHash([string]$Actual, [string]$Expected) {
    Assert-Session0InitProbeHash $Expected
    if ($Actual -cne $Expected) { throw '追加診断EXEの実SHA-256が期待値と一致しません。' }
}

function Assert-Session0InitProbeSecurity($Identity, [string]$ServiceSid) {
    if ([string]::IsNullOrEmpty($ServiceSid)) { Assert-ExactFileSecurity $Identity; return }
    if (-not $Identity.DaclPresent -or -not $Identity.DaclNonNull) {
        throw '追加診断 EXE の DACL がありません。'
    }
    $descriptor = Get-RawDescriptor $Identity.SecuritySddl
    $aces = @($descriptor.DiscretionaryAcl)
    if ($descriptor.Owner.Value -ne 'S-1-5-18' -or $aces.Count -ne 3 -or
        ($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0) {
        throw '追加診断 EXE の所有者・保護 DACL・ACE 数が一致しません。'
    }
    foreach ($entry in @(@('S-1-5-18', [uint32]0x001f01ff),
        @('S-1-5-32-544', [uint32]0x001f01ff), @($ServiceSid, [uint32]0x001200a9))) {
        $matching = @($aces | Where-Object {
            $_ -is [Security.AccessControl.CommonAce] -and
            $_.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
            $_.SecurityIdentifier.Value -eq $entry[0] -and
            (Convert-AccessMaskToUInt32 $_.AccessMask) -eq $entry[1] -and
            $_.AceFlags -eq [Security.AccessControl.AceFlags]::None
        })
        if ($matching.Count -ne 1) { throw '追加診断 EXE の許可権限が一致しません。' }
    }
}

# 種別と用途から固定名だけを選ぶ。sourceと保護先を交換できない。
function Get-Session0ProbeBasename([string]$Kind, [bool]$Source) {
    switch -CaseSensitive ($Kind) {
        'Init' { if ($Source) { return 'session0_init_probe.exe' }; return 'SbzSession0InitProbe.exe' }
        'Entry' { if ($Source) { return 'session0_entry_probe.exe' }; return 'SbzSession0EntryProbe.exe' }
        'Terminate' { if ($Source) { return 'session0_terminate_probe.exe' }; return 'SbzSession0TerminateProbe.exe' }
        default { throw '追加診断 EXE の種別が不正です。' }
    }
}

function Get-Session0ProbeSourcePath([string]$Path, [string]$Kind) {
    $basename = Get-Session0ProbeBasename $Kind $true
    Assert-LocalAbsolutePath $Path '追加診断の source'
    $canonical = [IO.Path]::GetFullPath($Path)
    if ([IO.Path]::GetFileName($canonical) -cne $basename) {
        throw '追加診断 EXE の source 名が一致しません。'
    }
    return $canonical
}

function Open-Session0InitProbeSource([hashtable]$State, [string]$Path, [string]$Hash, [string]$Kind = 'Init') {
    $canonical = Get-Session0ProbeSourcePath $Path $Kind
    $State.Kind = $Kind
    Assert-Session0InitProbeHash $Hash
    $State.Hash = $Hash
    $State.Source = [IO.FileStream]::new(
        $canonical, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    $identity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
        $State.Source.SafeFileHandle.DangerousGetHandle()
    )
    Assert-RegularIdentity $identity $canonical '追加診断の source'
    Assert-Session0ProbeContentHash (Get-StreamSha256 $State.Source) $Hash
    $State.Source.Position = 0
}

function Copy-Session0InitProbe([hashtable]$State, [string]$Root) {
    $basename = Get-Session0ProbeBasename $State.Kind $false
    $State.Path = Join-Path $Root $basename
    $State.Target = [Sembazuru.WindowStationProbeNative]::CreateProtectedFile(
        $State.Path, 'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'
    )
    $State.Identity = [Sembazuru.WindowStationProbeNative]::InspectHandle($State.Target.Handle)
    Assert-RegularIdentity $State.Identity $State.Path '追加診断の target'
    Assert-Session0InitProbeSecurity $State.Identity ''
    $stream = [IO.FileStream]::new(
        [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($State.Target.Handle, $false),
        [IO.FileAccess]::ReadWrite
    )
    try {
        $State.Source.CopyTo($stream)
        $stream.Flush($true)
        $stream.Position = 0
        Assert-Session0ProbeContentHash (Get-StreamSha256 $stream) $State.Hash
    }
    finally { $stream.Dispose() }
    $State.Lease = [Sembazuru.WindowStationProbeNative]::OpenLease($State.Path)
    $identity = [Sembazuru.WindowStationProbeNative]::InspectHandle($State.Lease.Handle)
    Assert-EquivalentFileIdentity $State.Identity $identity $State.Path '追加診断の lease'
    $State.Target.Dispose()
    $State.Target = $null
    # 書込みハンドルを閉じた後も、実体と hash を再照合した読取りハンドルで変更・削除を拒む。
    $State.ReadHold = [IO.FileStream]::new(
        $State.Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    $identity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
        $State.ReadHold.SafeFileHandle.DangerousGetHandle()
    )
    Assert-EquivalentFileIdentity $State.Identity $identity $State.Path '追加診断の read hold'
    Assert-Session0ProbeContentHash (Get-StreamSha256 $State.ReadHold) $State.Hash
}

function Grant-Session0InitProbeRead([hashtable]$State, [string]$ServiceSid) {
    $mutation = [Sembazuru.WindowStationProbeNative]::OpenAclMutation($State.Path, $false)
    try {
        $identity = [Sembazuru.WindowStationProbeNative]::InspectHandle($mutation.Handle)
        Assert-EquivalentFileIdentity $State.Identity $identity $State.Path '追加診断の ACL 更新'
        [Sembazuru.WindowStationProbeNative]::SetProtectedDacl($mutation.Handle,
            ('O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a9;;;{0})' -f $ServiceSid))
    }
    finally { $mutation.Dispose() }
    $identity = [Sembazuru.WindowStationProbeNative]::InspectHandle($State.Lease.Handle)
    Assert-EquivalentFileIdentity $State.Identity $identity $State.Path '追加診断の service lease' -AllowSecuritySddlChange
    Assert-Session0InitProbeSecurity $identity $ServiceSid
    $State.ServiceSid = $ServiceSid
}

function Remove-Session0InitProbe([hashtable]$State) {
    # 呼出元がサービスの停止と不在を確認してから、保持中の実体だけを削除する。
    if ($null -ne $State.ReadHold) { $State.ReadHold.Dispose(); $State.ReadHold = $null }
    if ($null -ne $State.Target) {
        [Sembazuru.WindowStationProbeNative]::MarkDelete($State.Target.Handle)
        $State.Target.Dispose()
        $State.Target = $null
    }
    elseif ($null -ne $State.Lease) {
        $held = [Sembazuru.WindowStationProbeNative]::InspectHandle($State.Lease.Handle)
        Assert-EquivalentFileIdentity $State.Identity $held $State.Path '追加診断の削除 lease' -AllowSecuritySddlChange
        Assert-Session0InitProbeSecurity $held $State.ServiceSid
        $cleanup = [Sembazuru.WindowStationProbeNative]::OpenCleanupDelete($State.Path)
        try {
            $identity = [Sembazuru.WindowStationProbeNative]::InspectHandle($cleanup.Handle)
            Assert-EquivalentFileIdentity $State.Identity $identity $State.Path '追加診断の削除 target' -AllowSecuritySddlChange
            Assert-Session0InitProbeSecurity $identity $State.ServiceSid
            [Sembazuru.WindowStationProbeNative]::MarkDelete($cleanup.Handle)
        }
        finally { $cleanup.Dispose() }
    }
    if ($null -ne $State.Lease) { $State.Lease.Dispose(); $State.Lease = $null }
}

function Read-Session0InitProbeOutput([byte[]]$Stdout, [byte[]]$Stderr, [Nullable[uint32]]$ChildExit) {
    if ($Stdout.Length -gt 1024 -or $Stderr.Length -gt 1024 -or $Stderr.Length -ne 0) {
        throw '到達点診断の出力上限または stderr が不正です。'
    }
    # '?' は GLE の小文字16進数字1桁だけに一致する。行末も含め固定列と照合する。
    $prefix = "SBZ_INIT_PROBE_V1 entry`nSBZ_INIT_PROBE_V1 user32_preloaded="
    $load = "0`nSBZ_INIT_PROBE_V1 user32_load_begin`nSBZ_INIT_PROBE_V1 user32_load_result="
    $tail = " gle=0x????????`nSBZ_INIT_PROBE_V1 complete`n"
    $templates = @(
        [pscustomobject]@{ Text = $prefix + $load + '1' + $tail; Preloaded = $false; Result = $true; Exit = 0 },
        [pscustomobject]@{ Text = $prefix + $load + '0' + $tail; Preloaded = $false; Result = $false; Exit = 11 },
        [pscustomobject]@{ Text = $prefix + "1`nSBZ_INIT_PROBE_V1 complete`n"; Preloaded = $true; Result = $false; Exit = 12 }
    )
    $matched = $null
    foreach ($candidate in $templates) {
        if ($Stdout.Length -gt $candidate.Text.Length) { continue }
        $valid = $true
        for ($i = 0; $i -lt $Stdout.Length; $i++) {
            $expected = [int][char]$candidate.Text[$i]
            $actual = [int]$Stdout[$i]
            if ($expected -eq 63) {
                if (-not (($actual -ge 48 -and $actual -le 57) -or ($actual -ge 97 -and $actual -le 102))) {
                    $valid = $false
                    break
                }
            } elseif ($actual -ne $expected) {
                $valid = $false
                break
            }
        }
        if ($valid) { $matched = $candidate; break }
    }
    if ($null -eq $matched) { throw '到達点診断の版、段階、順序または文字が不正です。' }
    $complete = $Stdout.Length -eq $matched.Text.Length
    # 出力完了と終了は別の観測。契約上の終了値だけを列と照合し、異常終了は証拠を残す。
    if ($null -ne $ChildExit -and $ChildExit -in @(0, 11, 12) -and
        (-not $complete -or $ChildExit -ne $matched.Exit)) {
        throw '到達点診断の段階列と終了値が一致しません。'
    }
    # ASCII の固定列照合後に変換し、LF まで観測できた行だけを数える。
    $text = [Text.Encoding]::ASCII.GetString($Stdout)
    $lines = $text.Split("`n")
    $count = $lines.Length - 1
    $stage = switch ($count) {
        0 { 0 }
        1 { 1 }
        2 { 2 }
        3 { if ($matched.Preloaded) { 5 } else { 3 } }
        4 { 4 }
        default { 5 }
    }
    $preloaded = $null
    if ($count -ge 2) { $preloaded = [int]$matched.Preloaded }
    $result = $null
    $gle = $null
    if (-not $matched.Preloaded -and $count -ge 4) {
        $result = [int]$matched.Result
        $gle = [Convert]::ToUInt32($lines[3].Substring($lines[3].Length - 8), 16)
    }
    # 開始後の列の中断は観測不足であり、DLL の失敗と断定しない。
    $outcome = 0
    if ($complete -and $null -ne $ChildExit -and $ChildExit -eq $matched.Exit) {
        $outcome = if ($matched.Preloaded) { 1 } elseif ($matched.Result) { 3 } else { 2 }
    }
    return [pscustomobject]@{ Stage = $stage; Preloaded = $preloaded; LoadResult = $result; Gle = $gle; Outcome = $outcome }
}

function Read-Session0U32([byte[]]$Bytes, [ref]$Offset) {
    if ($Offset.Value -gt $Bytes.Length - 4) { throw 'Session 0 diagnostic record is truncated.' }
    $value = [BitConverter]::ToUInt32($Bytes, $Offset.Value)
    $Offset.Value += 4
    return $value
}

function Read-Session0Text([byte[]]$Bytes, [ref]$Offset) {
    $length = Read-Session0U32 $Bytes $Offset
    if ($length -gt 32768 -or $Offset.Value -gt $Bytes.Length - [int]$length) {
        throw 'Session 0 diagnostic text is invalid or exceeds its bound.'
    }
    $value = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes, $Offset.Value, [int]$length)
    $Offset.Value += [int]$length
    return $value
}

function Expand-Session0JobUi([uint32]$Mask) {
    $named = @(
        @([uint32]1, 'handles'), @([uint32]2, 'readclipboard'), @([uint32]4, 'writeclipboard'),
        @([uint32]8, 'systemparameters'), @([uint32]16, 'displaysettings'),
        @([uint32]32, 'globalatoms'), @([uint32]64, 'desktop'), @([uint32]128, 'exitwindows')
    )
    $parts = [Collections.Generic.List[string]]::new()
    $covered = [uint32]0
    foreach ($entry in $named) {
        $bit = [uint32]$entry[0]
        $covered = [uint32]($covered -bor $bit)
        $parts.Add(('{0}={1}' -f $entry[1], $(if (($Mask -band $bit) -ne 0) { 1 } else { 0 })))
    }
    $parts.Add(('unknown=0x{0:x8}' -f [uint32]($Mask -bxor ($Mask -band $covered))))
    return $parts -join ';'
}

function Test-Session0TargetEvidence([string]$Dacl, [string]$Sacl, [string]$Access, [string]$Isolation, [uint32]$RequestedMask) {
    # 保護 DACL の2主体、完全な label、アクセスと隔離の実測が全て必要。
    $sid = 'S-1-[0-9]+(?:-[0-9]+)+'
    $pattern = '\Acontrol=0x([0-9a-fA-F]{4});aces=\[type=0;flags=0;mask=0x000f01ff;sid=(' +
        $sid + '),type=0;flags=0;mask=0x000201ff;sid=(' + $sid + ')\]\z'
    if ($Dacl -cnotmatch $pattern) { return $false }
    if (([Convert]::ToUInt16($Matches[1], 16) -band 0x1000) -eq 0 -or $Matches[2] -ceq $Matches[3]) {
        return $false
    }
    if ($Sacl -cne 'label=absent;implied_integrity=8192') {
        if ($Sacl -cnotmatch '\Alabel_aces=\[(.+)\]\z') { return $false }
        $aces = $Matches[1].Split(',')
        foreach ($ace in $aces) {
            if ($ace -cnotmatch '\Atype=17;flags=([0-9]+);mask=0x[0-9a-fA-F]{8};sid=S-1-16-([0-9]+)\z') {
                return $false
            }
            $flags = [uint32]0
            $integrity = [uint32]0
            if (-not [uint32]::TryParse($Matches[1], [ref]$flags) -or $flags -gt 255 -or
                -not [uint32]::TryParse($Matches[2], [ref]$integrity)) { return $false }
        }
    }
    $expectedAccess = 'scope=broker-impersonated;first_failure=none;steps=[' +
        'station:maximum_allowed:mask=0x02000000;allowed=true;gle=0,' +
        'station:read_attributes:mask=0x00000002;allowed=true;gle=0,' +
        ('station:action_mask:mask=0x{0:x8};allowed=true;gle=0,' -f $RequestedMask) +
        'desktop:maximum_allowed:mask=0x02000000;allowed=true;gle=0,' +
        'desktop:read_objects:mask=0x00000001;allowed=true;gle=0,' +
        'desktop:action_mask:mask=0x000201ff;allowed=true;gle=0]'
    $expectedIsolation = 'own=Ok(true);other_maximum=Err(5);default_maximum=Err(5);' +
        'write_dac=Err(5);write_owner=Err(5);default_dacl_safe=true;tcb_absent=true'
    return $Access -ceq $expectedAccess -and $Isolation -ceq $expectedIsolation
}

function Read-Session0DiagnosticRun([byte[]]$Bytes, [ref]$Offset, [uint32]$RequestedMask) {
    $jobUi = Read-Session0U32 $Bytes $Offset
    $jobUiLimits = Read-Session0Text $Bytes $Offset
    if ($jobUiLimits -cne (Expand-Session0JobUi $jobUi)) {
        throw '診断の Job UI 名称が mask と一致しません。'
    }
    $creationFlags = Read-Session0U32 $Bytes $Offset
    if ($Offset.Value -ge $Bytes.Length -or ($Bytes[$Offset.Value] -ne 0 -and $Bytes[$Offset.Value] -ne 1)) {
        throw '診断の起動成功フラグが不正です。'
    }
    $spawnSucceeded = $Bytes[$Offset.Value] -eq 1
    $Offset.Value++
    $spawnError = Read-Session0Text $Bytes $Offset
    if ($Offset.Value -ge $Bytes.Length -or ($Bytes[$Offset.Value] -ne 0 -and $Bytes[$Offset.Value] -ne 1)) {
        throw '診断の子プロセス終了フラグが不正です。'
    }
    $hasExit = $Bytes[$Offset.Value] -eq 1
    $Offset.Value++
    $childExit = $null
    if ($hasExit) { $childExit = Read-Session0U32 $Bytes $Offset }
    $stdout = Read-Session0Text $Bytes $Offset
    $stderr = Read-Session0Text $Bytes $Offset
    $targetDesktop = Read-Session0Text $Bytes $Offset
    $targetDacl = Read-Session0Text $Bytes $Offset
    $targetSacl = Read-Session0Text $Bytes $Offset
    $targetAccess = Read-Session0Text $Bytes $Offset
    # 明示された測定 mask は、分類や隔離確認ビットと独立して照合する。
    $maskSteps = $targetAccess.Split([string[]]@('station:action_mask:mask=0x'), [StringSplitOptions]::None)
    for ($i = 1; $i -lt $maskSteps.Count; $i++) {
        if ($maskSteps[$i].Split(';')[0] -cne ('{0:x8}' -f $RequestedMask)) {
            throw 'TargetAccess の station mask が要求と一致しません。'
        }
    }
    $isolation = Read-Session0Text $Bytes $Offset
    if ($Offset.Value -ge $Bytes.Length) { throw '診断の終了処理情報がありません。' }
    $lifecycle = $Bytes[$Offset.Value]
    $Offset.Value++
    if (($lifecycle -band 0xf0) -ne 0 -or
        (($lifecycle -band 14) -ne 0 -and ($lifecycle -band 1) -eq 0) -or
        (($lifecycle -band 4) -ne 0 -and -not $spawnSucceeded) -or
        (($lifecycle -band 2) -ne 0 -and -not (Test-Session0TargetEvidence $targetDacl $targetSacl $targetAccess $isolation $RequestedMask))) {
        throw '診断の作成・終了処理情報が矛盾しています。'
    }
    return [PSCustomObject]@{
        JobUi = $jobUi; JobUiLimits = $jobUiLimits; CreationFlags = $creationFlags
        SpawnSucceeded = $spawnSucceeded; SpawnError = $spawnError
        ChildExit = $childExit; Stdout = $stdout; Stderr = $stderr
        TargetDesktop = $targetDesktop; TargetDacl = $targetDacl; TargetSacl = $targetSacl
        TargetAccess = $targetAccess; Isolation = $isolation; Lifecycle = $lifecycle
    }
}

function Test-Session0InitTreeSafe([bool]$Requested, [bool]$StartAttempted, $Record) {
    return -not $Requested -or -not $StartAttempted -or ($null -ne $Record -and $null -ne $Record.InitProbe -and
        ($Record.InitProbe.Run.Lifecycle -band 12) -eq 12)
}

function Test-Session0EntryTreeSafe([bool]$Requested, [bool]$StartAttempted, $Record) {
    return -not $Requested -or -not $StartAttempted -or ($null -ne $Record -and $null -ne $Record.EntryProbe -and
        ($Record.EntryProbe.Run.Lifecycle -band 12) -eq 12)
}

function Get-Session0EntryObserved($Run) {
    # 取得済み終了値の観測を、後続の出力・desktop回収エラーから独立させる。
    return $Run.SpawnSucceeded -and $null -ne $Run.ChildExit -and
        $Run.ChildExit -eq [uint32]0x53425a45 -and -not $Run.SpawnError.StartsWith('wait:', [StringComparison]::Ordinal)
}

function Test-Session0EntryGates($Record) {
    if ($null -eq $Record.EntryProbe) { return $false }
    $run = $Record.EntryProbe.Run
    return $Record.SessionId -eq 0 -and $Record.WorkerActionsSid.Length -gt 0 -and
        $Record.StationAce -ceq ('count=1;flags=0;mask=0x{0:x8}' -f $Record.RequestedStationMask) -and
        $Record.StationCleanup -ceq 'removed' -and $run.SpawnSucceeded -and $run.Lifecycle -eq 15 -and
        (Test-Session0TargetEvidence $run.TargetDacl $run.TargetSacl $run.TargetAccess $run.Isolation $Record.RequestedStationMask) -and
        $run.Stdout.Length -eq 0 -and $run.Stderr.Length -eq 0 -and -not $run.SpawnError.Contains('output_read_failed')
}

function Assert-Session0EntryGates($Record, [string]$Detail = '') {
    if (-not (Test-Session0EntryGates $Record)) {
        throw "固定終了値診断の空出力・隔離・終了確認ゲートが未達です: $Detail"
    }
}

function Read-Session0EntryRecord([byte[]]$Bytes, [ref]$Offset, [uint32]$Mask, [string]$Station,
    [string]$ExpectedPath, [string]$ExpectedHash, $Init, $Baseline, $NoWindow) {
    if ($null -eq $Init) { throw '固定終了値診断にはInitProbeの記録が必要です。' }
    $path = Read-Session0Text $Bytes $Offset
    $hash = Read-Session0Text $Bytes $Offset
    Assert-Session0InitProbeHash $hash
    if ($path -cne $ExpectedPath -or $hash -cne $ExpectedHash -or
        -not $path.EndsWith('\SbzSession0EntryProbe.exe', [StringComparison]::Ordinal) -or
        $path -cnotmatch '\A[A-Za-z]:\\[^\r\n]+\z' -or
        @($path.Substring(3).Split('\') | Where-Object {
            $_.Length -eq 0 -or $_.EndsWith('.') -or $_.EndsWith(' ') -or $_ -match '[\p{Cc}"<>|?*:/]'
        }).Count -ne 0 -or
        $Init.Path -cne ([IO.Path]::GetDirectoryName($path) + '\SbzSession0InitProbe.exe')) {
        throw '固定終了値診断のpath・hashが呼出側の期待値と一致しません。'
    }
    $run = Read-Session0DiagnosticRun $Bytes $Offset $Mask
    if ((-not $run.SpawnSucceeded -and $null -ne $run.ChildExit) -or
        ($run.SpawnSucceeded -and ($run.JobUi -ne 0xfe -or $run.CreationFlags -ne 0x00080404 -or ($run.Lifecycle -band 1) -eq 0)) -or
        (($run.Lifecycle -band 1) -ne 0 -and -not $run.TargetDesktop.StartsWith(($Station + '\sbz-'), [StringComparison]::Ordinal)) -or
        ($run.TargetDesktop.Length -ne 0 -and ($run.TargetDesktop -ceq $Baseline.TargetDesktop -or
            $run.TargetDesktop -ceq $NoWindow.TargetDesktop -or $run.TargetDesktop -ceq $Init.Run.TargetDesktop))) {
        throw '固定終了値診断のJob・製品flags・専用desktopが一致しません。'
    }
    if ($Offset.Value -ge $Bytes.Length -or $Bytes[$Offset.Value] -gt 1) { throw '固定終了値診断の肯定bitが不正です。' }
    $observed = $Bytes[$Offset.Value] -eq 1
    $Offset.Value++
    if ($observed -ne (Get-Session0EntryObserved $run)) { throw '固定終了値診断の肯定bitと子の終了値が一致しません。' }
    return [PSCustomObject]@{ Path=$path; Sha256=$hash; Run=$run; EntryObserved=$observed }
}

function Test-Session0TerminateTreeSafe([bool]$Requested, [bool]$StartAttempted, $Record) {
    return -not $Requested -or -not $StartAttempted -or ($null -ne $Record -and $null -ne $Record.TerminateProbe -and
        ($Record.TerminateProbe.Run.Lifecycle -band 12) -eq 12)
}

function Get-Session0TerminateObserved($Run) {
    # 取得済み終了値の観測を、後続の出力・desktop回収エラーから独立させる。
    return $Run.SpawnSucceeded -and $null -ne $Run.ChildExit -and
        $Run.ChildExit -eq [uint32]0x53425a54
}

function Test-Session0TerminateGates($Record) {
    if ($null -eq $Record.TerminateProbe) { return $false }
    $run = $Record.TerminateProbe.Run
    return $Record.SessionId -eq 0 -and $Record.WorkerActionsSid.Length -gt 0 -and
        $Record.StationAce -ceq ('count=1;flags=0;mask=0x{0:x8}' -f $Record.RequestedStationMask) -and
        $Record.StationCleanup -ceq 'removed' -and $run.SpawnSucceeded -and $run.Lifecycle -eq 15 -and
        (Test-Session0TargetEvidence $run.TargetDacl $run.TargetSacl $run.TargetAccess $run.Isolation $Record.RequestedStationMask) -and
        $run.Stdout.Length -eq 0 -and $run.Stderr.Length -eq 0 -and $run.SpawnError.Length -eq 0 -and
        $Record.TerminateProbe.OutputEof -and $Record.TerminateProbe.DeadlineMet -and $null -ne $run.ChildExit
}

function Assert-Session0TerminateGates($Record, [string]$Detail = '') {
    if (-not (Test-Session0TerminateGates $Record)) {
        throw "固定自己終了診断の空出力・隔離・終了確認ゲートが未達です: $Detail"
    }
}

function Read-Session0TerminateRecord([byte[]]$Bytes, [ref]$Offset, [uint32]$Mask, [string]$Station,
    [string]$ExpectedPath, [string]$ExpectedHash, $Init, $Entry, $Baseline, $NoWindow) {
    if ($null -eq $Init) { throw '固定自己終了診断にはInitProbeの記録が必要です。' }
    if ($null -eq $Entry) { throw '固定自己終了診断にはEntryProbeの記録が必要です。' }
    $path = Read-Session0Text $Bytes $Offset
    $hash = Read-Session0Text $Bytes $Offset
    Assert-Session0InitProbeHash $hash
    if ($path -cne $ExpectedPath -or $hash -cne $ExpectedHash -or
        -not $path.EndsWith('\SbzSession0TerminateProbe.exe', [StringComparison]::Ordinal) -or
        $path -cnotmatch '\A[A-Za-z]:\\[^\r\n]+\z' -or
        @($path.Substring(3).Split('\') | Where-Object {
            $_.Length -eq 0 -or $_.EndsWith('.') -or $_.EndsWith(' ') -or $_ -match '[\p{Cc}"<>|?*:/]'
        }).Count -ne 0 -or
        $Init.Path -cne ([IO.Path]::GetDirectoryName($path) + '\SbzSession0InitProbe.exe') -or
        $Entry.Path -cne ([IO.Path]::GetDirectoryName($path) + '\SbzSession0EntryProbe.exe')) {
        throw '固定自己終了診断のpath・hashが呼出側の期待値と一致しません。'
    }
    $run = Read-Session0DiagnosticRun $Bytes $Offset $Mask
    if ((-not $run.SpawnSucceeded -and $null -ne $run.ChildExit) -or
        ($run.SpawnSucceeded -and ($run.JobUi -ne 0xfe -or $run.CreationFlags -ne 0x00080404 -or ($run.Lifecycle -band 1) -eq 0)) -or
        (($run.Lifecycle -band 1) -ne 0 -and -not $run.TargetDesktop.StartsWith(($Station + '\sbz-'), [StringComparison]::Ordinal)) -or
        ($run.TargetDesktop.Length -ne 0 -and ($run.TargetDesktop -ceq $Baseline.TargetDesktop -or
            $run.TargetDesktop -ceq $NoWindow.TargetDesktop -or $run.TargetDesktop -ceq $Init.Run.TargetDesktop -or $run.TargetDesktop -ceq $Entry.Run.TargetDesktop))) {
        throw '固定自己終了診断のJob・製品flags・専用desktopが一致しません。'
    }
    if ($Offset.Value -ge $Bytes.Length -or $Bytes[$Offset.Value] -gt 1) { throw '固定自己終了診断の肯定bitが不正です。' }
    $observed = $Bytes[$Offset.Value] -eq 1
    $Offset.Value++
    if ($observed -ne (Get-Session0TerminateObserved $run)) { throw '固定自己終了診断の肯定bitと子の終了値が一致しません。' }
    if ($Offset.Value + 2 -gt $Bytes.Length -or $Bytes[$Offset.Value] -gt 1 -or $Bytes[$Offset.Value + 1] -gt 1) {
        throw '固定自己終了診断のEOF・期限bitが不正です。'
    }
    $outputEof = $Bytes[$Offset.Value] -eq 1
    $deadlineMet = $Bytes[$Offset.Value + 1] -eq 1
    $Offset.Value += 2
    if (($outputEof -and (-not $run.SpawnSucceeded -or ($run.Lifecycle -band 4) -eq 0)) -or
        ($deadlineMet -and (-not $run.SpawnSucceeded -or $null -eq $run.ChildExit))) {
        throw '固定自己終了診断の終了値・EOF・期限が実行記録と矛盾しています。'
    }
    return [PSCustomObject]@{ Path=$path; Sha256=$hash; Run=$run; EntryObserved=$observed; OutputEof=$outputEof; DeadlineMet=$deadlineMet }
}

function Get-Session0InitRunEvidence($Run) {
    if (-not $Run.SpawnSucceeded -and ($null -ne $Run.ChildExit -or $Run.Stdout.Length -ne 0 -or $Run.Stderr.Length -ne 0)) {
        throw '追加診断の spawn と終了・出力が矛盾しています。'
    }
    $evidence = Read-Session0InitProbeOutput ([Text.Encoding]::UTF8.GetBytes($Run.Stdout)) ([Text.Encoding]::UTF8.GetBytes($Run.Stderr)) $Run.ChildExit
    if ($Run.Lifecycle -ne 15 -or $Run.SpawnError.Length -ne 0) { $evidence.Outcome = 0 }
    $values = foreach ($property in @('Stage', 'Preloaded', 'LoadResult', 'Gle', 'Outcome')) {
        if ($null -eq $evidence.$property) { 'none' } else { [string]$evidence.$property }
    }
    return $values -join ','
}

function Read-Session0InitRecord([byte[]]$Bytes, [ref]$Offset, [uint32]$Mask, [string]$Station,
    [string]$ExpectedPath, [string]$ExpectedHash) {
    if ($Offset.Value -ge $Bytes.Length -or $Bytes[$Offset.Value] -gt 1) { throw '追加診断の有無が不正です。' }
    $present = $Bytes[$Offset.Value] -eq 1
    $Offset.Value++
    if (-not $present) {
        if ($ExpectedPath.Length -ne 0 -or $ExpectedHash.Length -ne 0) { throw '要求した追加診断がありません。' }
        return $null
    }
    $path = Read-Session0Text $Bytes $Offset
    $hash = Read-Session0Text $Bytes $Offset
    Assert-Session0InitProbeHash $hash
    if ($path -cne $ExpectedPath -or $hash -cne $ExpectedHash -or
        -not $path.EndsWith('\SbzSession0InitProbe.exe', [StringComparison]::Ordinal) -or
        $path -cnotmatch '\A[A-Za-z]:\\[^\r\n]+\z' -or
        @($path.Substring(3).Split('\') | Where-Object {
            $_.Length -eq 0 -or $_.EndsWith('.') -or $_.EndsWith(' ') -or $_ -match '[\p{Cc}"<>|?*:/]'
        }).Count -ne 0) {
        throw '追加診断の固定path・hashが呼出側の期待値と一致しません。'
    }
    $run = Read-Session0DiagnosticRun $Bytes $Offset $Mask
    if (($run.SpawnSucceeded -and ($run.JobUi -ne 0xfe -or $run.CreationFlags -ne 0x00080404 -or ($run.Lifecycle -band 1) -eq 0)) -or
        (($run.Lifecycle -band 1) -ne 0 -and -not $run.TargetDesktop.StartsWith(($Station + '\sbz-'), [StringComparison]::Ordinal))) {
        throw '追加診断のJob・製品flags・専用desktopが一致しません。'
    }
    $evidence = Read-Session0Text $Bytes $Offset
    if ($evidence -cne (Get-Session0InitRunEvidence $run)) { throw '追加診断の段階証拠が出力と一致しません。' }
    return [PSCustomObject]@{ Path=$path; Sha256=$hash; Run=$run; Evidence=$evidence }
}

function Read-Session0DiagnosticRecord([byte[]]$Bytes, [string]$Nonce, [uint32]$ExpectedMask,
    [string]$ExpectedInitPath = '', [string]$ExpectedInitHash = '',
    [string]$ExpectedEntryPath = '', [string]$ExpectedEntryHash = '',
    [string]$ExpectedTerminatePath = '', [string]$ExpectedTerminateHash = '') {
    Assert-Session0ProbeParameters $ExpectedInitPath $ExpectedInitHash $ExpectedEntryPath $ExpectedEntryHash $ExpectedTerminatePath $ExpectedTerminateHash
    if ($ExpectedMask -ne 0x0002 -and $ExpectedMask -ne 0x0022) {
        throw '呼出側の station mask が許容範囲外です。'
    }
    if ($Bytes.Length -lt 44 -or $Bytes.Length -gt 65580) {
        throw '診断レコードの長さが許容範囲外です。'
    }
    $expectedVersion = if ($ExpectedTerminatePath) { [uint32]11 } elseif ($ExpectedEntryPath) { [uint32]10 } else { [uint32]9 }
    if ([BitConverter]::ToUInt32($Bytes, 0) -ne [uint32]0x53424434 -or
        [BitConverter]::ToUInt32($Bytes, 4) -ne $expectedVersion) {
        throw '診断レコードの magic または version が一致しません。'
    }
    if ($Nonce -cnotmatch '\A[0-9a-fA-F]{32}\z') { throw '診断の nonce の形式が不正です。' }
    $nonceBytes = [Text.Encoding]::ASCII.GetBytes($Nonce)
    if ($nonceBytes.Length -ne 32) { throw '診断の nonce の形式が不正です。' }
    for ($index = 0; $index -lt 32; $index++) {
        if ($Bytes[8 + $index] -ne $nonceBytes[$index]) {
            throw '診断レコードの nonce が一致しません。'
        }
    }
    $payloadLength = [BitConverter]::ToUInt32($Bytes, 40)
    if ($payloadLength -ne $Bytes.Length - 44) {
        throw '診断 payload の長さが一致しません。'
    }
    $offset = [ref]44
    if ($offset.Value -ge $Bytes.Length) { throw '診断の進行マーカーがありません。' }
    $markers = $Bytes[$offset.Value]
    $offset.Value++
    if ($offset.Value -ge $Bytes.Length) { throw '診断の分類がありません。' }
    $classification = $Bytes[$offset.Value]
    $offset.Value++
    $sessionId = Read-Session0U32 $Bytes $offset
    $requestedMask = Read-Session0U32 $Bytes $offset
    if ($requestedMask -ne $ExpectedMask) {
        throw '要求 station mask が呼出側の期待値と一致しません。'
    }
    $fields = [Collections.Generic.List[string]]::new()
    for ($index = 0; $index -lt 14; $index++) { $fields.Add((Read-Session0Text $Bytes $offset)) }
    $baseline = Read-Session0DiagnosticRun $Bytes $offset $requestedMask
    $noWindow = Read-Session0DiagnosticRun $Bytes $offset $requestedMask
    $workerActionsSid = Read-Session0Text $Bytes $offset
    $stationAce = Read-Session0Text $Bytes $offset
    $stationCleanup = Read-Session0Text $Bytes $offset
    $initProbeRecord = Read-Session0InitRecord $Bytes $offset $requestedMask $fields[2] $ExpectedInitPath $ExpectedInitHash
    $entryProbeRecord = $null
    if ($ExpectedEntryPath) {
        $entryProbeRecord = Read-Session0EntryRecord $Bytes $offset $requestedMask $fields[2] `
            $ExpectedEntryPath $ExpectedEntryHash $initProbeRecord $baseline $noWindow
    }
    $terminateProbeRecord = $null
    if ($ExpectedTerminatePath) {
        $terminateProbeRecord = Read-Session0TerminateRecord $Bytes $offset $requestedMask $fields[2] `
            $ExpectedTerminatePath $ExpectedTerminateHash $initProbeRecord $entryProbeRecord $baseline $noWindow
    }
    if ($null -ne $initProbeRecord -and $initProbeRecord.Run.TargetDesktop.Length -ne 0 -and
        ($initProbeRecord.Run.TargetDesktop -ceq $baseline.TargetDesktop -or $initProbeRecord.Run.TargetDesktop -ceq $noWindow.TargetDesktop)) {
        throw '追加診断のdesktopがcmdと重複しています。'
    }
    $maskSeparator = $stationAce.LastIndexOf(';mask=0x', [StringComparison]::Ordinal)
    if ($maskSeparator -ge 0 -and $stationAce.Substring($maskSeparator + 8) -cne ('{0:x8}' -f $requestedMask)) {
        throw '実測した station ACE の mask が要求と一致しません。'
    }
    if ($offset.Value -ne $Bytes.Length) { throw '診断レコードに余分な末尾データがあります。' }
    if (($markers -band 0xf8) -ne 0 -or ($markers -band 1) -eq 0) {
        throw '診断の進行マーカーが不正です。'
    }
    if ($classification -lt 1 -or $classification -gt 4) {
        throw '診断の分類が不正です。'
    }
    if ($fields[13] -cnotmatch '\A[0-9a-fA-F]{64}\z') {
        throw '診断の環境ハッシュが不正です。'
    }
    if (($baseline.SpawnSucceeded -and ($baseline.JobUi -ne [uint32]0x000000fe -or
            $baseline.CreationFlags -ne [uint32]0x00080404)) -or
        ($noWindow.SpawnSucceeded -and ($noWindow.JobUi -ne [uint32]0x000000fe -or
            $noWindow.CreationFlags -ne [uint32]0x08080404))) {
        throw '診断の作成フラグまたは Job UI の契約に違反しています。'
    }
    $expectedClassification = 3
    $isolationVerified = $workerActionsSid.Length -gt 0 -and
        $stationAce -ceq ('count=1;flags=0;mask=0x{0:x8}' -f $requestedMask) -and $stationCleanup -ceq 'removed' -and
        $baseline.Lifecycle -eq 15 -and $noWindow.Lifecycle -eq 15 -and
        (Test-Session0TargetEvidence $baseline.TargetDacl $baseline.TargetSacl $baseline.TargetAccess $baseline.Isolation $requestedMask) -and
        (Test-Session0TargetEvidence $noWindow.TargetDacl $noWindow.TargetSacl $noWindow.TargetAccess $noWindow.Isolation $requestedMask) -and
        $baseline.SpawnError.Length -eq 0 -and $noWindow.SpawnError.Length -eq 0 -and
        $baseline.TargetDesktop.StartsWith(($fields[2] + '\sbz-'), [StringComparison]::Ordinal) -and
        $noWindow.TargetDesktop.StartsWith(($fields[2] + '\sbz-'), [StringComparison]::Ordinal)
    if ($isolationVerified -and $markers -eq 7 -and $sessionId -eq 0 -and
        $baseline.SpawnSucceeded -and $noWindow.SpawnSucceeded -and
        $baseline.JobUi -eq [uint32]0x000000fe -and $noWindow.JobUi -eq [uint32]0x000000fe -and
        $baseline.CreationFlags -eq [uint32]0x00080404 -and
        $noWindow.CreationFlags -eq [uint32]0x08080404 -and
        $null -ne $baseline.ChildExit -and $baseline.ChildExit -eq [uint32]0 -and
        $null -ne $noWindow.ChildExit -and $noWindow.ChildExit -eq [uint32]0) {
        # 両方の腕が起動した。Rust 側と同じく、ベースラインの失敗を前提とする分類より先に判定する。
        $expectedClassification = 4
    } elseif ($isolationVerified -and $markers -eq 7 -and $sessionId -eq 0 -and
        $baseline.SpawnSucceeded -and $noWindow.SpawnSucceeded -and
        $baseline.JobUi -eq [uint32]0x000000fe -and $noWindow.JobUi -eq [uint32]0x000000fe -and
        $baseline.CreationFlags -eq [uint32]0x00080404 -and
        $noWindow.CreationFlags -eq [uint32]0x08080404 -and
        $baseline.ChildExit -eq [uint32]3221225794) { # 0xc0000142
        if ($null -ne $noWindow.ChildExit -and $noWindow.ChildExit -eq [uint32]0) {
            $expectedClassification = 1
        } elseif ($noWindow.ChildExit -eq [uint32]3221225794) { # 0xc0000142
            $expectedClassification = 2
        }
    }
    if ($classification -ne $expectedClassification) {
        throw '診断の分類が記録内容と一致しません。'
    }
    return [PSCustomObject]@{
        Nonce = $Nonce; Markers = $markers; Classification = $classification; SessionId = $sessionId
        RequestedStationMask = $requestedMask
        Broker = $fields[0]; Action = $fields[1]; Station = $fields[2]; Desktop = $fields[3]
        StationDacl = $fields[4]; StationSacl = $fields[5]; DesktopDacl = $fields[6]
        DesktopSacl = $fields[7]; StationAccess = $fields[8]; DesktopAccess = $fields[9]
        UiProbe = $fields[10]; ActionDesktop = $fields[11]; Cwd = $fields[12]
        EnvironmentHash = $fields[13]
        Baseline = $baseline; NoWindow = $noWindow; InitProbe = $initProbeRecord; EntryProbe = $entryProbeRecord; TerminateProbe = $terminateProbeRecord
        WorkerActionsSid = $workerActionsSid; StationAce = $stationAce; StationCleanup = $stationCleanup
    }
}

function Format-BoundedDiagnosticText([string]$Value) {
    $normalized = $Value.Replace("`r", '\\r').Replace("`n", '\\n')
    return $normalized
}

try {
    if ([Sembazuru.WindowStationProbeNative]::ServiceExists($serviceName)) {
        throw "$serviceName already exists; refused to alter it."
    }
    $workerBefore = Get-WorkerSnapshot

    $artifactCanonical = [IO.Path]::GetFullPath($ArtifactPath)
    Assert-LocalAbsolutePath $artifactCanonical 'ArtifactPath'
    $sourceStream = [IO.FileStream]::new(
        $artifactCanonical, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    $sourceIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
        $sourceStream.SafeFileHandle.DangerousGetHandle()
    )
    Assert-RegularIdentity $sourceIdentity $artifactCanonical 'artifact'
    $sourceHash = Get-StreamSha256 $sourceStream
    if ($sourceHash -ne $ExpectedSha256) { throw 'artifact SHA-256 mismatch' }
    $sourceStream.Position = 0
    if ($InitProbePath) { Open-Session0InitProbeSource $initProbe $InitProbePath $InitProbeSha256 }
    if ($EntryProbePath) { Open-Session0InitProbeSource $entryProbe $EntryProbePath $EntryProbeSha256 'Entry' }
    if ($TerminateProbePath) { Open-Session0InitProbeSource $terminateProbe $TerminateProbePath $TerminateProbeSha256 'Terminate' }

    $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
    if ([string]::IsNullOrWhiteSpace($programFiles)) { throw 'Program Files known folder is empty.' }
    $programFiles = [IO.Path]::GetFullPath($programFiles).TrimEnd('\')
    Assert-LocalAbsolutePath $programFiles 'Program Files'
    $parentHandle = [Sembazuru.WindowStationProbeNative]::OpenDirectory($programFiles, $false)
    try {
        $parentIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle($parentHandle.Handle)
        Assert-ExactPath $parentIdentity.FinalPath $programFiles 'Program Files'
        if (($parentIdentity.Attributes -band [uint32]0x10) -eq 0 -or
            ($parentIdentity.Attributes -band [uint32]0x400) -ne 0) {
            throw 'Program Files is not a regular non-reparse directory.'
        }
        Assert-ProgramFilesParentAcl $parentIdentity
    }
    finally { $parentHandle.Dispose() }

    $root = Join-Path $programFiles 'Sembazuru Test Fixtures'
    if (Test-Path -LiteralPath $root) { throw 'fixed fixture root already exists; refused adoption.' }
    $restore = [Sembazuru.WindowStationProbeNative]::EnableRestorePrivilege()
    try {
        [Sembazuru.WindowStationProbeNative]::CreateProtectedDirectory(
            $root, 'O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        )
        $ownedRoot = $true
        $rootHandle = [Sembazuru.WindowStationProbeNative]::OpenDirectory($root, $true)
        $rootIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle($rootHandle.Handle)
        Assert-ExactPath $rootIdentity.FinalPath $root 'fixture root'
        if (($rootIdentity.Attributes -band [uint32]0x10) -eq 0 -or
            ($rootIdentity.Attributes -band [uint32]0x400) -ne 0) {
            throw 'fixture root is not a regular non-reparse directory.'
        }
        Assert-ExactRootSecurity $rootIdentity
        if (@(Get-ChildItem -LiteralPath $root -Force).Count -ne 0) {
            throw 'new fixture root was not empty.'
        }
        $fixtureExe = Join-Path $root $fixtureBasename
        $targetHandle = [Sembazuru.WindowStationProbeNative]::CreateProtectedFile(
            $fixtureExe, 'O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)'
        )
        if ($InitProbePath) { Copy-Session0InitProbe $initProbe $root }
        if ($EntryProbePath) { Copy-Session0InitProbe $entryProbe $root }
        if ($TerminateProbePath) { Copy-Session0InitProbe $terminateProbe $root }
    }
    finally { $restore.Dispose() }

    $targetIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle($targetHandle.Handle)
    Assert-RegularIdentity $targetIdentity $fixtureExe 'fixture executable'
    Assert-ExactFileSecurity $targetIdentity
    $targetStream = [IO.FileStream]::new(
        [Microsoft.Win32.SafeHandles.SafeFileHandle]::new($targetHandle.Handle, $false),
        [IO.FileAccess]::ReadWrite
    )
    try {
        $sourceStream.CopyTo($targetStream)
        $targetStream.Flush($true)
        $targetStream.Position = 0
        $targetHash = Get-StreamSha256 $targetStream
        if ($targetHash -ne $ExpectedSha256) { throw 'fixture executable SHA-256 mismatch' }
    }
    finally {
        $targetStream.Dispose()
        $targetStream = $null
    }
    $targetLease = [Sembazuru.WindowStationProbeNative]::OpenLease($fixtureExe)
    try {
        $leaseIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
            $targetLease.Handle
        )
        Assert-EquivalentFileIdentity $targetIdentity $leaseIdentity $fixtureExe 'fixture lease'
    }
    catch {
        $targetLease.Dispose()
        $targetLease = $null
        throw
    }
    $targetHandle.Dispose()
    $targetHandle = $null
    $sourceStream.Dispose()
    $sourceStream = $null

    $diagnosticRecordPath = Join-Path $root ($diagnosticNonce + '.session0.rec')
    $fixtureArguments = @($fixtureExe, '--ignored', '--exact', $selector,
        '--nocapture', '--test-threads=1', '--', $root, $root, $diagnosticNonce, $StationMask)
    if ($InitProbePath) { $fixtureArguments += $initProbe.Hash }
    if ($EntryProbePath) { $fixtureArguments += $entryProbe.Hash }
    if ($TerminateProbePath) { $fixtureArguments += $terminateProbe.Hash }
    Assert-Session0FixtureArguments $fixtureArguments
    $imagePath = '"' + $fixtureExe + '" --ignored --exact ' + $selector +
        ' --nocapture --test-threads=1 -- "' + $root + '" "' + $root + '" ' +
        $diagnosticNonce + ' ' + $StationMask
    if ($InitProbePath) { $imagePath += ' ' + $initProbe.Hash }
    if ($EntryProbePath) { $imagePath += ' ' + $entryProbe.Hash }
    if ($TerminateProbePath) { $imagePath += ' ' + $terminateProbe.Hash }
    $serviceAccount = 'NT SERVICE\' + $serviceName
    $serviceHandle = [Sembazuru.WindowStationProbeNative]::CreateProbeService(
        $serviceName, $imagePath, $serviceAccount
    )
    $ownedService = $true
    [Sembazuru.WindowStationProbeNative]::SetUnrestrictedServiceSid($serviceHandle)
    if ([Sembazuru.WindowStationProbeNative]::QueryServiceSidType($serviceHandle) -ne 1) {
        throw 'SERVICE_SID_TYPE_UNRESTRICTED was not retained.'
    }
    $serviceSid = [Sembazuru.WindowStationProbeNative]::ServiceAccountSid($serviceName)
    if ([string]::IsNullOrWhiteSpace($serviceSid)) { throw 'throwaway service SID is unavailable.' }
    # 長期保持ハンドルには WRITE_DAC を付けず、最終 path と file ID を照合した
    # 短命のハンドルだけで DACL を更新する。
    $rootAclHandle = [Sembazuru.WindowStationProbeNative]::OpenAclMutation($root, $true)
    try {
        $rootAclIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
            $rootAclHandle.Handle
        )
        Assert-EquivalentRootIdentity $rootIdentity $rootAclIdentity $root 'ACL mutation root'
        Assert-ExactRootSecurity $rootAclIdentity
        [Sembazuru.WindowStationProbeNative]::SetProtectedDacl(
            $rootAclHandle.Handle,
            ('O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x001301bf;;;{0})' -f $serviceSid)
        )
    }
    finally { $rootAclHandle.Dispose() }
    $targetAclHandle = [Sembazuru.WindowStationProbeNative]::OpenAclMutation($fixtureExe, $false)
    try {
        $targetAclIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
            $targetAclHandle.Handle
        )
        Assert-EquivalentFileIdentity $targetIdentity $targetAclIdentity $fixtureExe `
            'ACL mutation fixture executable'
        [Sembazuru.WindowStationProbeNative]::SetProtectedDacl(
            $targetAclHandle.Handle,
            ('O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x001200a9;;;{0})' -f $serviceSid)
        )
    }
    finally { $targetAclHandle.Dispose() }
    if ($InitProbePath) { Grant-Session0InitProbeRead $initProbe $serviceSid }
    if ($EntryProbePath) { Grant-Session0InitProbeRead $entryProbe $serviceSid }
    if ($TerminateProbePath) { Grant-Session0InitProbeRead $terminateProbe $serviceSid }
    $serviceRootIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle($rootHandle.Handle)
    $serviceExeIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle($targetLease.Handle)
    $leaseIdentity = $serviceExeIdentity
    foreach ($check in @(
        @($serviceRootIdentity, [uint32]0x001301bf, 'fixture root'),
        @($serviceExeIdentity, [uint32]0x001200a9, 'fixture executable')
    )) {
        $ace = @((Get-RawDescriptor $check[0].SecuritySddl).DiscretionaryAcl | Where-Object {
            $_ -is [Security.AccessControl.CommonAce] -and
            $_.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
            $_.SecurityIdentifier.Value -eq $serviceSid -and
            (Convert-AccessMaskToUInt32 $_.AccessMask) -eq $check[1]
        })
        if ($ace.Count -ne 1) { throw "$($check[2]) lacks the exact throwaway service SID right." }
    }
    $serviceStartAttempted = $true
    try { [Sembazuru.WindowStationProbeNative]::StartWithoutArguments($serviceHandle) }
    catch {
        $nativeError = $null
        if ($_.Exception -is [ComponentModel.Win32Exception]) {
            $nativeError = $_.Exception.NativeErrorCode
        }
        elseif ($null -ne $_.Exception.InnerException -and
            $_.Exception.InnerException -is [ComponentModel.Win32Exception]) {
            $nativeError = $_.Exception.InnerException.NativeErrorCode
        }
        if ($nativeError -eq 1053 -or $nativeError -eq 1063) {
            Write-Host "REFUTED: SCM dispatcher error $nativeError."
        }
        throw
    }

    # 旧形式の期限を保ち、追加runごとの終了確認時間を割り当てる。
    $serviceDeadlineSeconds = Get-Session0ServiceDeadline ([bool]$InitProbePath) ([bool]$EntryProbePath) ([bool]$TerminateProbePath)
    $deadline = [DateTime]::UtcNow.AddSeconds($serviceDeadlineSeconds)
    $sawRunning = $false
    do {
        $status = [Sembazuru.WindowStationProbeNative]::QueryStatus($serviceHandle)
        if ($status.ProcessId -ne 0) {
            $throwawayProcessId = $status.ProcessId
            if ($null -eq $throwawayProcess) {
                $throwawayProcess = [Sembazuru.WindowStationProbeNative]::HoldProcess(
                    $throwawayProcessId
                )
            }
        }
        if ($status.State -eq $serviceRunning) { $sawRunning = $true }
        if ($status.State -eq $serviceStopped) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw ('SCM 診断が {0} 秒以内に停止しませんでした。' -f $serviceDeadlineSeconds) }
        Start-Sleep -Milliseconds 100
    } while ($true)
    if ($status.Win32ExitCode -ne $errorServiceSpecific -or
        ($status.ServiceSpecificExitCode -ne $noWindowCausalMagic -and
         $status.ServiceSpecificExitCode -ne $noWindowNotSufficientMagic -and
         $status.ServiceSpecificExitCode -ne $indeterminateMagic -and
         $status.ServiceSpecificExitCode -ne $actionStartsMagic -and
         $status.ServiceSpecificExitCode -ne $brokerTokenFailureMagic -and
         $status.ServiceSpecificExitCode -ne $publishFailureMagic -and
         $status.ServiceSpecificExitCode -ne $scratchCleanupFailureMagic -and
         $status.ServiceSpecificExitCode -ne $runtimeFailureMagic)) {
        if ($status.Win32ExitCode -eq 1053 -or $status.Win32ExitCode -eq 1063) {
            Write-Host "REFUTED: SCM stopped with dispatcher error $($status.Win32ExitCode)."
        }
        if ($status.ServiceSpecificExitCode -eq $contractFailureMagic) {
            throw 'SCM ServiceMain argument contract rejected the launch.'
        }
        if ($status.ServiceSpecificExitCode -eq $diagnosticFailureMagic) {
            throw 'Session 0 diagnostic did not publish its bounded record.'
        }
        throw ("SCM status mismatch: state={0} win32={1} service={2}" -f
            $status.State, $status.Win32ExitCode, $status.ServiceSpecificExitCode)
    }
    if (-not $sawRunning) {
        Write-Host 'SCM status note: Running completed inside the polling interval.'
    }
    $failureStages = @{
        $brokerTokenFailureMagic = 'broker-token'
        $publishFailureMagic = 'record-publish'
        $scratchCleanupFailureMagic = 'scratch-cleanup'
        $runtimeFailureMagic = 'runtime'
    }
    if ($failureStages.ContainsKey($status.ServiceSpecificExitCode)) {
        throw ('Session 0 diagnostic harness failure stage={0} service=0x{1:x8}' -f
            $failureStages[$status.ServiceSpecificExitCode], $status.ServiceSpecificExitCode)
    }
    if ($null -eq $diagnosticRecordPath -or -not [IO.File]::Exists($diagnosticRecordPath)) {
        throw 'Session 0 diagnostic record is missing.'
    }
    $record = Read-Session0DiagnosticRecord ([IO.File]::ReadAllBytes($diagnosticRecordPath)) `
        $diagnosticNonce $requestedStationMask $initProbe.Path $initProbe.Hash $entryProbe.Path $entryProbe.Hash $terminateProbe.Path $terminateProbe.Hash
    $classificationMap = @{
        1 = @{ Name = 'NO_WINDOW_CAUSAL'; Magic = $noWindowCausalMagic }
        2 = @{ Name = 'NO_WINDOW_NOT_SUFFICIENT'; Magic = $noWindowNotSufficientMagic }
        3 = @{ Name = 'INDETERMINATE'; Magic = $indeterminateMagic }
        4 = @{ Name = 'ACTION_STARTS'; Magic = $actionStartsMagic }
    }
    if (-not $classificationMap.ContainsKey([int]$record.Classification)) {
        throw '診断の分類が不正です。'
    }
    $classification = $classificationMap[[int]$record.Classification]
    if ($status.ServiceSpecificExitCode -ne $classification.Magic) {
        throw 'SCM diagnostic outcome magic disagrees with the bounded record.'
    }
    $diagnosticClassification = $classification.Name
    $detail = [Collections.Generic.List[string]]::new()
    $detail.Add(('RequestedStationMask=0x{0:x8}' -f $record.RequestedStationMask))
    $detail.Add(('service=0x{0:x8} session={1} markers=0x{2:x2}' -f
        $status.ServiceSpecificExitCode, $record.SessionId, $record.Markers))
    foreach ($property in @(
        'Broker', 'Action', 'Station', 'Desktop', 'StationDacl', 'StationSacl',
        'DesktopDacl', 'DesktopSacl', 'StationAccess', 'DesktopAccess', 'UiProbe',
        'ActionDesktop', 'Cwd', 'EnvironmentHash', 'WorkerActionsSid', 'StationAce', 'StationCleanup'
    )) {
        # 既存の Desktop 系測定は broker の Default。起動対象の証拠は各 run の Target*。
        $label = if ($property -in @('Desktop', 'DesktopDacl', 'DesktopSacl', 'DesktopAccess', 'UiProbe')) {
            'Broker' + $property
        } else { $property }
        $detail.Add(('{0}={1}' -f $label, (Format-BoundedDiagnosticText $record.$property)))
    }
    foreach ($name in @('Baseline', 'NoWindow', 'InitProbe', 'EntryProbe', 'TerminateProbe')) {
        if ($name -in @('InitProbe', 'EntryProbe', 'TerminateProbe') -and $null -eq $record.$name) { continue }
        $run = if ($name -in @('InitProbe', 'EntryProbe', 'TerminateProbe')) { $record.$name.Run } else { $record.$name }
        if ($name -eq 'TerminateProbe') {
            $terminateOutcome = if ($record.TerminateProbe.EntryObserved) { 'entry-observed' } else { 'indeterminate' }
            $detail.Add(('TerminateProbePath={0} TerminateProbeSha256={1} TerminateEntryObserved={2} TerminateProbeOutcome={3} TerminateProbeGatesVerified={4} TerminateProbeOutputEof={5} TerminateProbeDeadlineMet={6}' -f
                $record.TerminateProbe.Path, $record.TerminateProbe.Sha256, $record.TerminateProbe.EntryObserved,
                $terminateOutcome, (Test-Session0TerminateGates $record), $record.TerminateProbe.OutputEof, $record.TerminateProbe.DeadlineMet))
        }
        if ($name -eq 'EntryProbe') {
            $entryOutcome = if ($record.EntryProbe.EntryObserved) { 'entry-observed' } else { 'indeterminate' }
            $detail.Add(('EntryProbePath={0} EntryProbeSha256={1} EntryObserved={2} EntryProbeOutcome={3} EntryProbeGatesVerified={4}' -f
                $record.EntryProbe.Path, $record.EntryProbe.Sha256, $record.EntryProbe.EntryObserved, $entryOutcome, (Test-Session0EntryGates $record)))
        }
        if ($name -eq 'InitProbe') {
            $detail.Add(('InitProbePath={0} InitProbeSha256={1} InitProbeEvidence={2}' -f $record.InitProbe.Path, $record.InitProbe.Sha256, $record.InitProbe.Evidence))
            $stage = $record.InitProbe.Evidence.Split(',')
            $stageNames = @('entry-unobserved', 'entry', 'preloaded-observed', 'load-begin', 'load-result', 'complete')
            $outcomeNames = @('indeterminate', 'already-loaded', 'load-failed', 'load-complete')
            $gle = if ($stage[3] -ceq 'none') { 'none' } else { '0x{0:x8}' -f [uint32]$stage[3] }
            $detail.Add(('InitProbeStage={0} InitProbePreloaded={1} InitProbeLoadResult={2} InitProbeGLE={3} InitProbeOutcome={4}' -f
                $stageNames[[int]$stage[0]], $stage[1], $stage[2], $gle, $outcomeNames[[int]$stage[4]]))
        }
        $exitText = if ($null -eq $run.ChildExit) { 'none' } else { '0x{0:x8}' -f $run.ChildExit }
        $detail.Add(('{0}JobUi=0x{1:x8} {0}CreationFlags=0x{2:x8} {0}SpawnSucceeded={3} {0}ChildExit={4}' -f
            $name, $run.JobUi, $run.CreationFlags, $run.SpawnSucceeded, $exitText))
        $initialization = if ($null -eq $run.ChildExit) { 'unobserved' }
            elseif ($run.ChildExit -eq [uint32]3221225794) { 'dll-init-failed' }
            elseif ($run.ChildExit -eq 0) { 'normal-exit' } else { 'other-exit' }
        $detail.Add(('{0}DesktopCreated={1} {0}IsolationVerified={2} {0}TreeFinished={3} {0}DesktopRemoved={4} {0}Initialization={5}' -f
            $name, (($run.Lifecycle -band 1) -ne 0), (($run.Lifecycle -band 2) -ne 0),
            (($run.Lifecycle -band 4) -ne 0), (($run.Lifecycle -band 8) -ne 0), $initialization))
        $detail.Add(('{0}JobUiLimits={1}'  -f $name, (Format-BoundedDiagnosticText $run.JobUiLimits)))
        foreach ($property in @('SpawnError', 'Stdout', 'Stderr', 'TargetDesktop', 'TargetDacl', 'TargetSacl', 'TargetAccess', 'Isolation')) {
            $detail.Add(('{0}{1}={2}' -f $name, $property, (Format-BoundedDiagnosticText $run.$property)))
        }
    }
    $diagnosticDetail = $detail -join ' '
    if ($EntryProbePath) { Assert-Session0EntryGates $record $diagnosticDetail }
    if ($TerminateProbePath) { Assert-Session0TerminateGates $record $diagnosticDetail }

}
catch { $primaryError = $_.Exception }
finally {
    if ($null -ne $sourceStream) {
        try { $sourceStream.Dispose() }
        catch { $cleanupErrors.Add("artifact handle close: $($_.Exception.Message)") }
        $sourceStream = $null
    }

    $stopSafe = $true
    $absenceSafe = $true
    $serviceAbsent = -not $ownedService
    if ($serviceHandle -ne [IntPtr]::Zero) {
        try {
            $cleanupStatus = [Sembazuru.WindowStationProbeNative]::QueryStatus($serviceHandle)
            if ($cleanupStatus.State -ne $serviceStopped) {
                if ($cleanupStatus.ProcessId -ne 0) { $throwawayProcessId = $cleanupStatus.ProcessId }
                try { [Sembazuru.WindowStationProbeNative]::RequestStop($serviceHandle) }
                catch {
                    if ($null -eq $throwawayProcess) { throw }
                    [Sembazuru.WindowStationProbeNative]::TerminateHeldProcessAndWait(
                        $throwawayProcess, 15000
                    )
                }
                $stopDeadline = [DateTime]::UtcNow.AddSeconds(15)
                do {
                    $cleanupStatus = [Sembazuru.WindowStationProbeNative]::QueryStatus($serviceHandle)
                    if ($cleanupStatus.State -eq $serviceStopped) { break }
                    if ([DateTime]::UtcNow -ge $stopDeadline) {
                        if ($null -eq $throwawayProcess) {
                            throw 'cleanup stop timed out without held process handle'
                        }
                        [Sembazuru.WindowStationProbeNative]::TerminateHeldProcessAndWait(
                            $throwawayProcess, 15000
                        )
                        $cleanupStatus = [Sembazuru.WindowStationProbeNative]::QueryStatus(
                            $serviceHandle
                        )
                        if ($cleanupStatus.State -ne $serviceStopped) {
                            throw 'cleanup forced termination did not stop the throwaway service'
                        }
                        break
                    }
                    Start-Sleep -Milliseconds 100
                } while ($true)
            }
        }
        catch {
            $stopSafe = $false
            $cleanupErrors.Add("service stop: $($_.Exception.Message)")
        }
        try { [Sembazuru.WindowStationProbeNative]::Delete($serviceHandle) }
        catch { $cleanupErrors.Add("service delete: $($_.Exception.Message)") }
        try { [Sembazuru.WindowStationProbeNative]::CloseService($serviceHandle) }
        catch { $cleanupErrors.Add("service handle close: $($_.Exception.Message)") }
        $serviceHandle = [IntPtr]::Zero
    }
    if ($ownedService) {
        try {
            $deleteDeadline = [DateTime]::UtcNow.AddSeconds(15)
            while ([Sembazuru.WindowStationProbeNative]::ServiceExists($serviceName)) {
                if ([DateTime]::UtcNow -ge $deleteDeadline) {
                    throw 'probe service remains present or marked for delete'
                }
                Start-Sleep -Milliseconds 100
            }
            $serviceAbsent = $true
        }
        catch {
            $absenceSafe = $false
            $cleanupErrors.Add("service absence: $($_.Exception.Message)")
        }
    }

    $initTreeSafe = Test-Session0InitTreeSafe ([bool]$InitProbePath) $serviceStartAttempted $record
    $entryTreeSafe = Test-Session0EntryTreeSafe ([bool]$EntryProbePath) $serviceStartAttempted $record
    $terminateTreeSafe = Test-Session0TerminateTreeSafe ([bool]$TerminateProbePath) $serviceStartAttempted $record
    $probesTreeSafe = $initTreeSafe -and $entryTreeSafe -and $terminateTreeSafe
    if ($ownedRoot) {
        if (-not $probesTreeSafe -or -not $serviceAbsent -or -not $stopSafe -or -not $absenceSafe) {
            $cleanupErrors.Add('fixture root preserved because SCM cleanup was not proven safe')
        }
        else {
            try {
                if ($null -eq $rootHandle -or $null -eq $rootIdentity) {
                    throw 'fixture root handle identity is unavailable'
                }
                $cleanupIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
                    $rootHandle.Handle
                )
                Assert-EquivalentRootIdentity $rootIdentity $cleanupIdentity $root `
                    'cleanup fixture root' -AllowSecuritySddlChange
                if ($null -ne $diagnosticRecordPath -and [IO.File]::Exists($diagnosticRecordPath)) {
                    $recordCleanup = [Sembazuru.WindowStationProbeNative]::OpenCleanupDelete(
                        $diagnosticRecordPath
                    )
                    try { [Sembazuru.WindowStationProbeNative]::MarkDelete($recordCleanup.Handle) }
                    finally { $recordCleanup.Dispose() }
                }
                Remove-Session0InitProbe $terminateProbe
                Remove-Session0InitProbe $entryProbe
                Remove-Session0InitProbe $initProbe
                if ($null -ne $targetLease) {
                    if ($null -eq $targetIdentity -or $null -eq $leaseIdentity) {
                        throw 'fixture executable lease identity is unavailable'
                    }
                    Assert-EquivalentFileIdentity $targetIdentity $leaseIdentity $fixtureExe `
                        'cleanup lease' -AllowSecuritySddlChange
                    $cleanupHandle = [Sembazuru.WindowStationProbeNative]::OpenCleanupDelete(
                        $fixtureExe
                    )
                    $cleanupTargetIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
                        $cleanupHandle.Handle
                    )
                    Assert-EquivalentFileIdentity $targetIdentity $cleanupTargetIdentity $fixtureExe `
                        'cleanup fixture executable' -AllowSecuritySddlChange
                    [Sembazuru.WindowStationProbeNative]::MarkDelete($cleanupHandle.Handle)
                    $cleanupHandle.Dispose()
                    $cleanupHandle = $null
                    $targetLease.Dispose()
                    $targetLease = $null
                }
                elseif ($null -ne $targetHandle) {
                    if ($null -ne $targetIdentity) {
                        $cleanupTargetIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
                            $targetHandle.Handle
                        )
                        Assert-EquivalentFileIdentity $targetIdentity $cleanupTargetIdentity `
                            $fixtureExe 'cleanup high fixture executable' -AllowSecuritySddlChange
                    }
                    [Sembazuru.WindowStationProbeNative]::MarkDelete($targetHandle.Handle)
                    $targetHandle.Dispose()
                    $targetHandle = $null
                }
                [Sembazuru.WindowStationProbeNative]::MarkDelete($rootHandle.Handle)
                $rootHandle.Dispose()
                $rootHandle = $null
            }
            catch { $cleanupErrors.Add("fixture cleanup: $($_.Exception.Message)") }
        }
    }
    foreach ($probe in @($initProbe, $entryProbe, $terminateProbe)) {
        foreach ($name in @('Source', 'Target', 'Lease', 'ReadHold')) {
            if (-not $probesTreeSafe -and $name -ne 'Source') { continue }
            if ($null -ne $probe[$name]) {
                try { $probe[$name].Dispose() }
                catch { $cleanupErrors.Add("診断 $name のハンドル解放: $($_.Exception.Message)") }
                $probe[$name] = $null
            }
        }
    }
    if (-not $probesTreeSafe) {
        # ホスト終了まで保持する。確認不能を通常cleanupへ読み替えない。
        $retained = Get-Variable -Name SembazuruSession0RetainedInitProbes -Scope Global -ErrorAction SilentlyContinue
        if ($null -eq $retained) { $global:SembazuruSession0RetainedInitProbes = [Collections.Generic.List[object]]::new() }
        $global:SembazuruSession0RetainedInitProbes.Add(@{ InitProbe=$initProbe; EntryProbe=$entryProbe; TerminateProbe=$terminateProbe; Root=$rootHandle })
        $rootHandle = $null
    }
    if ($null -ne $targetHandle) {
        try { $targetHandle.Dispose() }
        catch { $cleanupErrors.Add("fixture executable handle close: $($_.Exception.Message)") }
        $targetHandle = $null
    }
    if ($null -ne $cleanupHandle) {
        try { $cleanupHandle.Dispose() }
        catch { $cleanupErrors.Add("fixture cleanup handle close: $($_.Exception.Message)") }
        $cleanupHandle = $null
    }
    if ($null -ne $targetLease) {
        try { $targetLease.Dispose() }
        catch { $cleanupErrors.Add("fixture executable lease close: $($_.Exception.Message)") }
        $targetLease = $null
    }
    if ($null -ne $rootHandle) {
        try { $rootHandle.Dispose() }
        catch { $cleanupErrors.Add("fixture root handle close: $($_.Exception.Message)") }
        $rootHandle = $null
    }
    if ($null -ne $throwawayProcess) {
        try { $throwawayProcess.Dispose() }
        catch { $cleanupErrors.Add("throwaway process handle close: $($_.Exception.Message)") }
        $throwawayProcess = $null
    }

    try {
        if ($null -ne $workerBefore) {
            $workerAfter = Get-WorkerSnapshot
            if (-not (Test-SnapshotEqual $workerBefore $workerAfter)) {
                throw 'canonical SembazuruWorker service changed during the probe'
            }
        }
    }
    catch { $cleanupErrors.Add("worker snapshot: $($_.Exception.Message)") }
}

if ($null -ne $primaryError -or $cleanupErrors.Count -ne 0) {
    if ($null -ne $primaryError) {
        [Console]::Error.WriteLine("PRIMARY ERROR: $($primaryError.Message)")
    }
    foreach ($cleanupError in $cleanupErrors) {
        [Console]::Error.WriteLine("CLEANUP ERROR: $cleanupError")
    }
    exit 1
}

if ($diagnosticClassification -eq 'INDETERMINATE') {
    [Console]::Error.WriteLine(
        "INDETERMINATE: $diagnosticDetail; 起動・隔離・後始末の判定に必要な観測が揃っていません。"
    )
    exit 1
}
if ($diagnosticClassification -eq 'ACTION_STARTS') {
    Write-Host "ACTION_STARTS: $diagnosticDetail; 両方の起動が正常終了し、隔離と後始末を確認しました。権限の最小性は未判定です。"
    exit 0
}
if ($diagnosticClassification -eq 'NO_WINDOW_CAUSAL') {
    Write-Host "NO_WINDOW_CAUSAL: $diagnosticDetail; CREATE_NO_WINDOW の追加で終了値が 0xc0000142 から 0 に変わりました。"
    exit 0
}
if ($diagnosticClassification -eq 'NO_WINDOW_NOT_SUFFICIENT') {
    Write-Host "NO_WINDOW_NOT_SUFFICIENT: $diagnosticDetail; 子は引き続き 0xc0000142 で終了しました。"
    exit 0
}
[Console]::Error.WriteLine('INDETERMINATE: 診断の分類が公開されませんでした。')
exit 1
