param(
    [string]$ArtifactPath,
    [string]$ExpectedSha256
)

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
# outer bootstrap (constructed by the orchestrator at execution time, not stored in this repo)
# must open these runner bytes once with FileShare.Read, verify their final local path and
# expected SHA-256, then invoke exactly those bytes via ScriptBlock::Create. It must elevate a
# protected absolute pwsh.exe with -NoProfile -NonInteractive and ProcessStartInfo.ArgumentList,
# UseShellExecute=true, Verb=runas. A ScriptBlock invocation has no PSCommandPath.
# Do not add cmdlets outside the $PSHOME startup set; native P/Invoke is required for SCM reads.
if (-not [string]::IsNullOrEmpty($PSCommandPath)) {
    throw 'Elevated direct -File execution is forbidden; use the verified in-memory bootstrap.'
}
if ($args.Count -ne 0) { throw 'This probe accepts only ArtifactPath and ExpectedSha256.' }
if ([string]::IsNullOrWhiteSpace($ArtifactPath) -or
    [string]::IsNullOrWhiteSpace($ExpectedSha256)) {
    throw 'ArtifactPath and ExpectedSha256 are required after elevation.'
}
if ($ExpectedSha256 -notmatch '\A[0-9a-fA-F]{64}\z') {
    throw 'ExpectedSha256 must be exactly 64 hexadecimal characters.'
}
$ExpectedSha256 = $ExpectedSha256.ToLowerInvariant()

$serviceName = 'SembazuruWindowStationProbeSmoke'
$workerServiceName = 'SembazuruWorker'
$fixtureBasename = 'SbzWindowStationScmSmoke.exe'
$selector = 'sandbox::tests::window_station_scm_dispatcher_smoke_role'
$successMagic = [uint32]0x53425a31
$contractFailureMagic = [uint32]0x53425aff
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
$serviceHandle = [IntPtr]::Zero
$ownedRoot = $false
$ownedService = $false
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
$workerBefore = $null
$workerAfter = $null

Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace Sembazuru {
    public sealed class ProbeServiceStatus {
        public uint State { get; set; }
        public uint Win32ExitCode { get; set; }
        public uint ServiceSpecificExitCode { get; set; }
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
        public static IntPtr CreateProbeService(string serviceName, string binaryPath) {
            IntPtr manager = OpenManager(0x0003);
            try {
                IntPtr service = CreateServiceW(
                    manager, serviceName, serviceName, 0x000f01ff,
                    0x00000010, 0x00000003, 0x00000001, binaryPath,
                    null, IntPtr.Zero, null, "LocalSystem", null);
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
                ServiceSpecificExitCode = native.dwServiceSpecificExitCode
            };
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

function Assert-EquivalentFileIdentity(
    $Expected, $Actual, [string]$ExpectedPath, [string]$Label
) {
    Assert-RegularIdentity $Actual $ExpectedPath $Label
    foreach ($property in @('FileId', 'DaclPresent', 'DaclNonNull')) {
        if (-not [object]::Equals($Expected.$property, $Actual.$property)) {
            throw "$Label $property mismatch"
        }
    }
    foreach ($property in @('FinalPath', 'SecuritySddl')) {
        if (-not [string]::Equals(
            $Expected.$property, $Actual.$property, [StringComparison]::Ordinal
        )) { throw "$Label $property mismatch" }
    }
    Assert-ExactFileSecurity $Actual
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

    $imagePath = '"' + $fixtureExe + '" --ignored --exact ' + $selector +
        ' --nocapture --test-threads=1'
    $serviceHandle = [Sembazuru.WindowStationProbeNative]::CreateProbeService(
        $serviceName, $imagePath
    )
    $ownedService = $true
    [Sembazuru.WindowStationProbeNative]::SetUnrestrictedServiceSid($serviceHandle)
    if ([Sembazuru.WindowStationProbeNative]::QueryServiceSidType($serviceHandle) -ne 1) {
        throw 'SERVICE_SID_TYPE_UNRESTRICTED was not retained.'
    }
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

    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    $sawRunning = $false
    do {
        $status = [Sembazuru.WindowStationProbeNative]::QueryStatus($serviceHandle)
        if ($status.State -eq $serviceRunning) { $sawRunning = $true }
        if ($status.State -eq $serviceStopped) { break }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'SCM smoke did not stop in 30 seconds.' }
        Start-Sleep -Milliseconds 100
    } while ($true)
    if ($status.Win32ExitCode -ne $errorServiceSpecific -or
        $status.ServiceSpecificExitCode -ne $successMagic) {
        if ($status.Win32ExitCode -eq 1053 -or $status.Win32ExitCode -eq 1063) {
            Write-Host "REFUTED: SCM stopped with dispatcher error $($status.Win32ExitCode)."
        }
        if ($status.ServiceSpecificExitCode -eq $contractFailureMagic) {
            throw 'SCM ServiceMain argument contract rejected the launch.'
        }
        throw ("SCM status mismatch: state={0} win32={1} service={2}" -f
            $status.State, $status.Win32ExitCode, $status.ServiceSpecificExitCode)
    }
    if (-not $sawRunning) {
        Write-Host 'SCM status note: Running completed inside the polling interval.'
    }
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
                [Sembazuru.WindowStationProbeNative]::RequestStop($serviceHandle)
                $stopDeadline = [DateTime]::UtcNow.AddSeconds(15)
                do {
                    $cleanupStatus = [Sembazuru.WindowStationProbeNative]::QueryStatus($serviceHandle)
                    if ($cleanupStatus.State -eq $serviceStopped) { break }
                    if ([DateTime]::UtcNow -ge $stopDeadline) { throw 'cleanup stop timed out' }
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

    if ($ownedRoot) {
        if (-not $serviceAbsent -or -not $stopSafe -or -not $absenceSafe) {
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
                Assert-ExactPath $cleanupIdentity.FinalPath $root 'cleanup fixture root'
                if ($cleanupIdentity.FileId -ne $rootIdentity.FileId) {
                    throw 'fixture root file identity changed'
                }
                Assert-ExactRootSecurity $cleanupIdentity
                if ($null -ne $targetLease) {
                    if ($null -eq $targetIdentity -or $null -eq $leaseIdentity) {
                        throw 'fixture executable lease identity is unavailable'
                    }
                    Assert-EquivalentFileIdentity $targetIdentity $leaseIdentity $fixtureExe `
                        'cleanup lease'
                    $cleanupHandle = [Sembazuru.WindowStationProbeNative]::OpenCleanupDelete(
                        $fixtureExe
                    )
                    $cleanupTargetIdentity = [Sembazuru.WindowStationProbeNative]::InspectHandle(
                        $cleanupHandle.Handle
                    )
                    Assert-EquivalentFileIdentity $leaseIdentity $cleanupTargetIdentity $fixtureExe `
                        'cleanup fixture executable'
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
                            $fixtureExe 'cleanup high fixture executable'
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

Write-Host ("PASS: dispatcher=started handler=registered status=StartPending->Running->Stopped " +
    "magic=0x{0:x8} cleanup=service+fixture-removed worker-unchanged=true" -f $successMagic)
