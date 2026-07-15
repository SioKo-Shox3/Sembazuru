[CmdletBinding(DefaultParameterSetName = 'Static')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Static')]
    [switch]$StaticOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [ValidateNotNullOrEmpty()]
    [string]$PackagePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$packageUnderTestInput = $PackagePath
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$aclGatePath = Join-Path $PSScriptRoot 'm9_installer_acl.ps1'
. $aclGatePath -Static
if ($StaticOnly) { return }

function Initialize-PrepositionNative {
    if ($null -ne ('Sembazuru.PrepositionNative' -as [type])) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Sembazuru {
    public sealed class FileIdentity {
        public string FileId { get; set; }
        public uint Attributes { get; set; }
        public uint ReparseTag { get; set; }
        public string OwnerSid { get; set; }
    }

    public static class PrepositionNative {
        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ATTRIBUTE_TAG_INFO {
            internal uint FileAttributes;
            internal uint ReparseTag;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ID_128 {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            internal byte[] Identifier;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILE_ID_INFO {
            internal ulong VolumeSerialNumber;
            internal FILE_ID_128 FileId;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(
            string fileName, uint desiredAccess, FileShare shareMode,
            IntPtr securityAttributes, FileMode creationDisposition,
            uint flagsAndAttributes, IntPtr templateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file, int fileInformationClass,
            out FILE_ATTRIBUTE_TAG_INFO fileInformation, uint bufferSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandleEx(
            SafeFileHandle file, int fileInformationClass,
            out FILE_ID_INFO fileInformation, uint bufferSize);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle, int objectType, uint securityInfo,
            out IntPtr ownerSid, IntPtr groupSid, IntPtr dacl, IntPtr sacl,
            out IntPtr securityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSidToStringSidW(IntPtr sid, out IntPtr stringSid);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool RemoveDirectoryW(string path);

        public static FileIdentity InspectNoFollow(string path) {
            const uint READ_CONTROL = 0x00020000;
            const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
            const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
            using (SafeFileHandle handle = CreateFileW(
                path, READ_CONTROL, FileShare.Read | FileShare.Write | FileShare.Delete,
                IntPtr.Zero, FileMode.Open, FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero)) {
                if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                FILE_ATTRIBUTE_TAG_INFO tag;
                if (!GetFileInformationByHandleEx(handle, 9, out tag,
                    (uint)Marshal.SizeOf(typeof(FILE_ATTRIBUTE_TAG_INFO))))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                FILE_ID_INFO id;
                if (!GetFileInformationByHandleEx(handle, 18, out id,
                    (uint)Marshal.SizeOf(typeof(FILE_ID_INFO))))
                    throw new Win32Exception(Marshal.GetLastWin32Error());

                IntPtr owner;
                IntPtr descriptor;
                uint securityResult = GetSecurityInfo(handle.DangerousGetHandle(), 1, 1,
                    out owner, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out descriptor);
                if (securityResult != 0) throw new Win32Exception((int)securityResult);
                IntPtr ownerText = IntPtr.Zero;
                try {
                    if (!ConvertSidToStringSidW(owner, out ownerText))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    return new FileIdentity {
                        FileId = BitConverter.ToString(id.FileId.Identifier)
                            .Replace("-", "").ToLowerInvariant(),
                        Attributes = tag.FileAttributes,
                        ReparseTag = tag.ReparseTag,
                        OwnerSid = Marshal.PtrToStringUni(ownerText)
                    };
                }
                finally {
                    if (ownerText != IntPtr.Zero) LocalFree(ownerText);
                    if (descriptor != IntPtr.Zero) LocalFree(descriptor);
                }
            }
        }

        public static void UnlinkJunction(string path) {
            if (!RemoveDirectoryW(path))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }
}
'@
}

function Get-NormalizedResolvedPath {
    param([string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    return [IO.Path]::GetFullPath($resolved).TrimEnd('\')
}

function Get-PathOwnerSid {
    param([string]$Path)
    $owner = (Get-Acl -LiteralPath $Path).Owner
    return ([Security.Principal.NTAccount]$owner).Translate(
        [Security.Principal.SecurityIdentifier]).Value
}

function Get-LinkIdentity {
    param([string]$Path, [string]$ExpectedTarget)

    $native = [Sembazuru.PrepositionNative]::InspectNoFollow($Path)
    $item = Get-Item -LiteralPath $Path -Force
    $targetValue = [string](@($item.Target)[0])
    $target = Get-NormalizedResolvedPath -Path $targetValue
    $expected = Get-NormalizedResolvedPath -Path $ExpectedTarget
    if (-not [string]::Equals($target, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw "junction target mismatch: got $target, want $expected"
    }
    return [pscustomobject][ordered]@{
        FileId = $native.FileId
        Attributes = $native.Attributes
        ReparseTag = $native.ReparseTag
        OwnerSid = $native.OwnerSid
        Target = $target
    }
}

function Get-TargetSnapshot {
    param([string]$TargetPath, [string]$SentinelPath)

    $native = [Sembazuru.PrepositionNative]::InspectNoFollow($TargetPath)
    $acl = Get-Acl -LiteralPath $TargetPath
    $prefix = $TargetPath.TrimEnd('\') + '\'
    $children = @(Get-ChildItem -LiteralPath $TargetPath -Force -Recurse | ForEach-Object {
        $relative = $_.FullName.Substring($prefix.Length)
        $kind = if ($_.PSIsContainer) { 'D' } else { 'F' }
        $length = if ($_.PSIsContainer) { '-' } else { [string]$_.Length }
        $hash = if ($_.PSIsContainer) { '-' } else {
            (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        "$kind|$relative|$length|$hash"
    } | Sort-Object)
    return [pscustomobject][ordered]@{
        OwnerSid = Get-PathOwnerSid -Path $TargetPath
        FileId = $native.FileId
        DaclSddl = $acl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access)
        SentinelOwnerSid = Get-PathOwnerSid -Path $SentinelPath
        SentinelSha256 = (Get-FileHash -LiteralPath $SentinelPath -Algorithm SHA256).Hash.ToLowerInvariant()
        Children = $children
    }
}

function ConvertTo-StableJson {
    param([object]$Value)
    return $Value | ConvertTo-Json -Compress -Depth 8
}

function Invoke-UserPrepositionSetup {
    param(
        [string]$User,
        [string]$Password,
        [string]$ProbeRoot,
        [string]$TargetPath,
        [string]$SentinelPath,
        [string]$JunctionPath
    )

    $targetLiteral = ConvertTo-SingleQuotedLiteral $TargetPath
    $sentinelLiteral = ConvertTo-SingleQuotedLiteral $SentinelPath
    $junctionLiteral = ConvertTo-SingleQuotedLiteral $JunctionPath
    $childScript = @"
`$ErrorActionPreference = 'Stop'
`$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
New-Item -ItemType Directory -Path $targetLiteral -ErrorAction Stop | Out-Null
Set-Content -LiteralPath $sentinelLiteral -Value 'sembazuru-preposition-sentinel-v1' -Encoding ascii
New-Item -ItemType Junction -Path $junctionLiteral -Target $targetLiteral -ErrorAction Stop | Out-Null
[pscustomobject]@{
    Sid = `$identity.User.Value
    JunctionCreated = `$true
} | ConvertTo-Json -Compress
"@
    $scriptPath = Join-Path $ProbeRoot 'setup.ps1'
    $stdoutPath = Join-Path $ProbeRoot 'setup.stdout.txt'
    $stderrPath = Join-Path $ProbeRoot 'setup.stderr.txt'
    Set-Content -LiteralPath $scriptPath -Value $childScript -Encoding Unicode
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $credential = [Management.Automation.PSCredential]::new(
        "$([Environment]::MachineName)\$User", $secure)
    $windowsPowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $argumentLine = "-NoProfile -NonInteractive -File `"$scriptPath`""
    $commandLine = "`"$windowsPowerShell`" $argumentLine"
    if ($commandLine.Length -ge 1024) {
        throw "preposition setup command line is too long: $($commandLine.Length) >= 1024"
    }
    Write-Host "PREPOSITION USER COMMAND: length=$($commandLine.Length) limit=1024"
    $process = Start-Process -FilePath $windowsPowerShell -ArgumentList $argumentLine `
        -Credential $credential -LoadUserProfile -WorkingDirectory $ProbeRoot `
        -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath `
        -WindowStyle Hidden -Wait -PassThru
    [string]$stderrText = if (Test-Path -LiteralPath $stderrPath) {
        Get-Content -LiteralPath $stderrPath -Raw
    } else { '<missing>' }
    [string]$stdoutText = if (Test-Path -LiteralPath $stdoutPath) {
        Get-Content -LiteralPath $stdoutPath -Raw
    } else { '<missing>' }
    if ($process.ExitCode -ne 0 -or $stderrText -ne '') {
        throw "preposition user setup failed: exit=$($process.ExitCode) stderr=$stderrText stdout=$stdoutText"
    }
    try { return $stdoutText | ConvertFrom-Json }
    catch { throw "preposition user setup JSON failed: $($_.Exception.Message); stdout=$stdoutText" }
}

function Assert-PrepositionOwnership {
    param(
        [string]$ExpectedSid,
        [object]$SetupResult,
        [object]$TargetSnapshot,
        [object]$LinkIdentity
    )

    if ($SetupResult.Sid -ne $ExpectedSid -or $SetupResult.Sid -eq 'S-1-5-18') {
        throw "setup caller SID mismatch: got $($SetupResult.Sid), want $ExpectedSid"
    }
    if ($SetupResult.JunctionCreated -ne $true) {
        throw 'standard user did not report junction creation'
    }
    $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
    $adminSids = @(Get-LocalGroupMember -Group $administrators | ForEach-Object { $_.SID.Value })
    if ($adminSids -contains $ExpectedSid) { throw 'preposition caller is an Administrator' }
    foreach ($actual in @(
        $TargetSnapshot.OwnerSid, $TargetSnapshot.SentinelOwnerSid, $LinkIdentity.OwnerSid)) {
        if ($actual -ne $ExpectedSid) {
            throw "preposition object owner mismatch: got $actual, want $ExpectedSid"
        }
    }
    if ([uint32]$LinkIdentity.ReparseTag -ne [uint32]0xa0000003) {
        throw "canonical path is not a mount-point junction: tag=0x$(([uint32]$LinkIdentity.ReparseTag).ToString('x8'))"
    }
    if (([uint32]$LinkIdentity.Attributes -band [uint32]0x400) -eq 0) {
        throw "canonical path lacks FILE_ATTRIBUTE_REPARSE_POINT: attributes=0x$(([uint32]$LinkIdentity.Attributes).ToString('x8'))"
    }
    Write-Host "PREPOSITION OWNERSHIP PASS: caller/target/sentinel/junction owner=$ExpectedSid"
}

function Test-LinkIdentityEqual {
    param([object]$Baseline, [object]$Current)
    return (ConvertTo-StableJson $Baseline) -ceq (ConvertTo-StableJson $Current)
}

function Unlink-OwnedJunction {
    param([string]$Path)
    [Sembazuru.PrepositionNative]::UnlinkJunction($Path)
}

function Start-TargetWatcher {
    param([string]$Path, [string]$Tag)

    $queue = [Collections.Concurrent.ConcurrentQueue[object]]::new()
    $watcher = [IO.FileSystemWatcher]::new($Path)
    $watcher.IncludeSubdirectories = $true
    $watcher.NotifyFilter = [IO.NotifyFilters]::FileName -bor `
        [IO.NotifyFilters]::DirectoryName -bor [IO.NotifyFilters]::Attributes -bor `
        [IO.NotifyFilters]::Size -bor [IO.NotifyFilters]::LastWrite -bor `
        [IO.NotifyFilters]::Security
    $action = {
        $meta = $Event.MessageData
        $args = $Event.SourceEventArgs
        $record = [ordered]@{
            Kind = $meta.Kind
            Path = ''
            OldPath = ''
            Error = ''
            Utc = [DateTime]::UtcNow.ToString('o')
        }
        if ($meta.Kind -eq 'Error') {
            $record.Error = $args.GetException().ToString()
        } else {
            $record.Path = $args.FullPath
            if ($meta.Kind -eq 'Renamed') { $record.OldPath = $args.OldFullPath }
        }
        $meta.Queue.Enqueue([pscustomobject]$record)
    }
    $subscriptions = [Collections.Generic.List[object]]::new()
    foreach ($kind in @('Created', 'Changed', 'Deleted', 'Renamed', 'Error')) {
        $identifier = "SbzM9Preposition.$Tag.$kind"
        $message = [pscustomobject]@{ Queue = $queue; Kind = $kind }
        $subscriptions.Add((Register-ObjectEvent -InputObject $watcher -EventName $kind `
            -SourceIdentifier $identifier -MessageData $message -Action $action))
    }
    $watcher.EnableRaisingEvents = $true
    return [pscustomobject]@{
        Watcher = $watcher
        Queue = $queue
        Subscriptions = @($subscriptions)
    }
}

function Wait-WatcherQueueStable {
    param([Collections.Concurrent.ConcurrentQueue[object]]$Queue, [string]$Phase)

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    $stableSince = [DateTime]::UtcNow
    $lastCount = $Queue.Count
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 100
        $count = $Queue.Count
        if ($count -ne $lastCount) {
            $lastCount = $count
            $stableSince = [DateTime]::UtcNow
        } elseif (([DateTime]::UtcNow - $stableSince).TotalSeconds -ge 1) {
            Write-Host "WATCHER STABLE: phase=$Phase callbacks=$count stableSeconds=1"
            return
        }
    }
    throw "watcher queue did not stabilize within 10 seconds: phase=$Phase callbacks=$($Queue.Count)"
}

function Stop-TargetWatcher {
    param([object]$Context)

    Wait-WatcherQueueStable -Queue $Context.Queue -Phase 'enabled-quiescence'
    $Context.Watcher.EnableRaisingEvents = $false
    Wait-WatcherQueueStable -Queue $Context.Queue -Phase 'disabled-callback-drain'
    foreach ($subscription in $Context.Subscriptions) {
        foreach ($jobError in @($subscription.ChildJobs | ForEach-Object { $_.Error })) {
            $Context.Queue.Enqueue([pscustomobject]@{
                Kind = 'Error'; Path = ''; OldPath = ''
                Error = "watcher callback failed: $jobError"; Utc = [DateTime]::UtcNow.ToString('o')
            })
        }
        Unregister-Event -SourceIdentifier $subscription.Name -ErrorAction SilentlyContinue
        Remove-Job -Job $subscription -Force -ErrorAction SilentlyContinue
    }
    $events = [Collections.Generic.List[object]]::new()
    $entry = $null
    while ($Context.Queue.TryDequeue([ref]$entry)) { $events.Add($entry) }
    $Context.Watcher.Dispose()
    return @($events)
}

function Close-TargetWatcherEmergency {
    param([object]$Context)
    try { $Context.Watcher.EnableRaisingEvents = $false } catch {}
    foreach ($subscription in @($Context.Subscriptions)) {
        Unregister-Event -SourceIdentifier $subscription.Name -ErrorAction SilentlyContinue
        Remove-Job -Job $subscription -Force -ErrorAction SilentlyContinue
    }
    try { $Context.Watcher.Dispose() } catch {}
}

function Stop-AttemptServices {
    $appeared = [Collections.Generic.List[string]]::new()
    foreach ($serviceName in @('SembazuruDaemon', 'SembazuruWorker')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -eq $service) { continue }
        $appeared.Add($serviceName)
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -Force -ErrorAction Stop
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        }
    }
    return @($appeared)
}

function Get-ActionEvidence {
    param([string]$LogPath, [string]$CanonicalDataRoot)

    if (-not (Test-Path -LiteralPath $LogPath -PathType Leaf)) {
        return [pscustomobject][ordered]@{ LogExists = $false }
    }
    $log = Get-Content -LiteralPath $LogPath -Raw
    $canonicalMention = $log.IndexOf(
        $CanonicalDataRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0
    $started = {
        param([string]$Name)
        return [regex]::IsMatch($log, "(?im)Action start .*?:\s*$([regex]::Escape($Name))\.")
    }
    $actionTouchesCanonical = {
        param([string]$Name)
        $escapedName = [regex]::Escape($Name)
        $pattern = "(?ims)^[^\r\n]*Action start[^\r\n]*:\s*$escapedName\.\s*\r?\n.*?^[^\r\n]*Action ended[^\r\n]*:\s*$escapedName\."
        foreach ($block in [regex]::Matches($log, $pattern)) {
            if ($block.Value.IndexOf(
                    $CanonicalDataRoot, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                return $true
            }
        }
        return $false
    }
    return [pscustomobject][ordered]@{
        LogExists = $true
        CanonicalDataRootMentioned = $canonicalMention
        CreateFoldersCanonical = & $actionTouchesCanonical 'CreateFolders'
        MsiLockPermissionsExCanonical = & $actionTouchesCanonical 'MsiLockPermissionsEx'
        SeedDaemonConfigStarted = & $started 'SeedDaemonConfig'
        SeedDaemonConfigFailed = [regex]::IsMatch($log,
            '(?im)(CustomAction SeedDaemonConfig returned actual error code [^0]|Action ended .*?: SeedDaemonConfig\. Return value 3)')
        SeedWorkerConfigStarted = & $started 'SeedWorkerConfig'
        InstallServicesStarted = & $started 'InstallServices'
        StartServicesStarted = & $started 'StartServices'
    }
}

function Get-NewResidue {
    param([string[]]$Baseline, [string[]]$Current)
    $known = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($item in @($Baseline)) { $null = $known.Add($item) }
    return @($Current | Where-Object { -not $known.Contains($_) })
}

Assert-Administrator
$packageUnderTest = (Resolve-Path -LiteralPath $packageUnderTestInput -ErrorAction Stop).Path
$commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$canonicalDataRoot = Join-Path $commonData 'Sembazuru'
$installRoot = Join-Path $programFiles 'Sembazuru'
$productKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Sembazuru'
Assert-CleanPreflight -DataRoot $canonicalDataRoot -InstallRoot $installRoot `
    -ProductKey $productKey
Initialize-PrepositionNative

$tag = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$gateUser = "SbzPos$tag"
$gatePassword = "SbZ!9p$tag"
$probeRoot = Join-Path $commonData "Sembazuru-M9-Preposition-$tag"
$targetPath = Join-Path $probeRoot 'target'
$sentinelPath = Join-Path $targetPath 'sentinel.txt'
$logRoot = Join-Path ([IO.Path]::GetTempPath()) "sembazuru-m9-preposition-$tag"
$installLog = Join-Path $logRoot 'install.log'
$uninstallLog = Join-Path $logRoot 'uninstall.log'
$createdGateUser = $false
$createdCallerProbeRoot = $false
$watcherContext = $null
$junctionBaseline = $null
$targetBaseline = $null
$baselineResidue = @()
$postAttemptResidue = @()
$msiAttempted = $false
$servicesQuiesced = $false
$watcherStopped = $false
$appearedServices = @()
$watcherEvents = @()
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

try {
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $gateSid = New-StandardGateUser -Name $gateUser -Password $gatePassword
    New-StandardProbeRoot -Path $probeRoot -UserSid $gateSid
    $setup = Invoke-UserPrepositionSetup -User $gateUser -Password $gatePassword `
        -ProbeRoot $probeRoot -TargetPath $targetPath -SentinelPath $sentinelPath `
        -JunctionPath $canonicalDataRoot
    $junctionBaseline = Get-LinkIdentity -Path $canonicalDataRoot -ExpectedTarget $targetPath
    $targetBaseline = Get-TargetSnapshot -TargetPath $targetPath -SentinelPath $sentinelPath
    Assert-PrepositionOwnership -ExpectedSid $gateSid -SetupResult $setup `
        -TargetSnapshot $targetBaseline -LinkIdentity $junctionBaseline
    $baselineResidue = @(Get-InstallResidue -DataRoot $canonicalDataRoot `
        -InstallRoot $installRoot -ProductKey $productKey)
    if ($baselineResidue.Count -ne 1 -or $baselineResidue[0] -ne "path:$canonicalDataRoot") {
        throw "unexpected setup residue baseline: $($baselineResidue -join '; ')"
    }
    Write-Host "BASELINE LINK: $(ConvertTo-StableJson $junctionBaseline)"
    Write-Host "BASELINE TARGET: $(ConvertTo-StableJson $targetBaseline)"

    $watcherContext = Start-TargetWatcher -Path $probeRoot -Tag $tag
    $msiAttempted = $true
    $installExit = $null
    $installInvocationError = ''
    try {
        $install = Invoke-Msi -Action Install -Path $packageUnderTest -LogPath $installLog
        $installExit = $install.ExitCode
    }
    catch { $installInvocationError = $_.Exception.Message }
    Write-Host "MSI PREPOSITION ATTEMPT: exit=$installExit invocationError=$installInvocationError log=$installLog"
    $actionEvidence = Get-ActionEvidence -LogPath $installLog `
        -CanonicalDataRoot $canonicalDataRoot
    Write-Host "ACTION EVIDENCE: $(ConvertTo-StableJson $actionEvidence)"

    $appearedServices = @(Stop-AttemptServices)
    $servicesQuiesced = $true
    Write-Host "SERVICE APPEARANCE: $(ConvertTo-StableJson $appearedServices)"
    $watcherEvents = @(Stop-TargetWatcher -Context $watcherContext)
    $watcherStopped = $true
    $watcherContext = $null
    Write-Host "WATCHER EVIDENCE: $(ConvertTo-StableJson $watcherEvents)"
    $postAttemptResidue = @(Get-InstallResidue -DataRoot $canonicalDataRoot `
        -InstallRoot $installRoot -ProductKey $productKey)
    Write-Host "POST-ATTEMPT RESIDUE: $(ConvertTo-StableJson $postAttemptResidue)"

    $junctionFinal = Get-LinkIdentity -Path $canonicalDataRoot -ExpectedTarget $targetPath
    $targetFinal = Get-TargetSnapshot -TargetPath $targetPath -SentinelPath $sentinelPath
    $newResidue = @(Get-NewResidue -Baseline $baselineResidue -Current $postAttemptResidue)
    $normalizedTarget = Get-NormalizedResolvedPath -Path $targetPath
    $targetPrefix = $normalizedTarget + '\'
    $targetEvents = @($watcherEvents | Where-Object {
        $_.Kind -ne 'Error' -and
        ([string]::Equals($_.Path, $normalizedTarget, [StringComparison]::OrdinalIgnoreCase) -or
         $_.Path.StartsWith($targetPrefix, [StringComparison]::OrdinalIgnoreCase))
    })
    $watcherErrors = @($watcherEvents | Where-Object { $_.Kind -eq 'Error' })
    Write-Host "FINAL LINK: $(ConvertTo-StableJson $junctionFinal)"
    Write-Host "FINAL TARGET: $(ConvertTo-StableJson $targetFinal)"

    $findings = [Collections.Generic.List[string]]::new()
    if ($installInvocationError -ne '') { $findings.Add("MSI invocation failed: $installInvocationError") }
    if ($null -eq $installExit) {
        $findings.Add('MSI did not return a nonzero fail-closed exit code')
    } elseif ($installExit -in @(0, 3010)) {
        $findings.Add("MSI install unexpectedly succeeded: $installExit")
    }
    if ($targetEvents.Count -ne 0) { $findings.Add("target watcher observed $($targetEvents.Count) event(s)") }
    if ($watcherErrors.Count -ne 0) { $findings.Add("watcher reported $($watcherErrors.Count) Error event(s)") }
    if (-not (Test-LinkIdentityEqual $junctionBaseline $junctionFinal)) {
        $findings.Add('junction identity changed')
    }
    if ((ConvertTo-StableJson $targetBaseline) -cne (ConvertTo-StableJson $targetFinal)) {
        $findings.Add('target owner/FileId/DACL/sentinel/child snapshot changed')
    }
    if ($appearedServices.Count -ne 0) { $findings.Add("service(s) appeared: $($appearedServices -join ',')") }
    if ($newResidue.Count -ne 0) { $findings.Add("new installer residue: $($newResidue -join '; ')") }
    if (-not $actionEvidence.LogExists) { $findings.Add('MSI verbose log is missing') }
    $seedFailureBoundary = $actionEvidence.PSObject.Properties['SeedDaemonConfigStarted'] -and
        $actionEvidence.PSObject.Properties['SeedDaemonConfigFailed'] -and
        $actionEvidence.SeedDaemonConfigStarted -and $actionEvidence.SeedDaemonConfigFailed
    if (-not $seedFailureBoundary) {
        $findings.Add('MSI failed before the required SeedDaemonConfig start/failure boundary')
    }
    foreach ($property in @(
        'CreateFoldersCanonical', 'MsiLockPermissionsExCanonical',
        'SeedWorkerConfigStarted', 'InstallServicesStarted', 'StartServicesStarted')) {
        if ($actionEvidence.PSObject.Properties[$property] -and $actionEvidence.$property) {
            $findings.Add("forbidden MSI action reached: $property")
        }
    }
    if ($findings.Count -ne 0) {
        throw "PREPOSITION RED: $($findings -join '; ')"
    }
    Write-Host 'PASS: MSI failed closed before changing the pre-positioned ProgramData target.'
}
catch {
    $primaryError = $_
}
finally {
    if ($msiAttempted -and -not $servicesQuiesced) {
        if ($null -eq $watcherContext) {
            $cleanupErrors.Add('watcher unavailable before exceptional service quiescence')
        } else {
            try {
                $cleanupServices = @(Stop-AttemptServices)
                $servicesQuiesced = $true
                Write-Host "EXCEPTIONAL SERVICE QUIESCENCE: $(ConvertTo-StableJson $cleanupServices)"
            }
            catch { $cleanupErrors.Add("exceptional service quiescence failed: $($_.Exception.Message)") }
        }
    }
    if ($msiAttempted -and $servicesQuiesced -and -not $watcherStopped) {
        if ($null -eq $watcherContext) {
            $cleanupErrors.Add('watcher unavailable before exceptional bounded drain')
        } else {
            try {
                $cleanupWatcherEvents = @(Stop-TargetWatcher -Context $watcherContext)
                $watcherStopped = $true
                $watcherContext = $null
                Write-Host "EXCEPTIONAL WATCHER EVIDENCE: $(ConvertTo-StableJson $cleanupWatcherEvents)"
            }
            catch { $cleanupErrors.Add("exceptional watcher drain failed: $($_.Exception.Message)") }
        }
    }
    if ($null -ne $watcherContext) {
        Close-TargetWatcherEmergency -Context $watcherContext
        $watcherContext = $null
    }
    $observationSafe = -not $msiAttempted -or ($servicesQuiesced -and $watcherStopped)
    $identitySafe = $false
    $linkPresent = Test-Path -LiteralPath $canonicalDataRoot
    if (-not $observationSafe) {
        $cleanupErrors.Add('service/watcher observation incomplete; unlink/uninstall/probe/user preserved')
    } elseif ($null -ne $junctionBaseline -and $linkPresent) {
        try {
            $cleanupIdentity = Get-LinkIdentity -Path $canonicalDataRoot -ExpectedTarget $targetPath
            if (Test-LinkIdentityEqual $junctionBaseline $cleanupIdentity) {
                $identitySafe = $true
            } else {
                $cleanupErrors.Add('junction identity mismatch; unlink/uninstall/probe/user preserved')
            }
        }
        catch {
            $cleanupErrors.Add("junction identity could not be proven; cleanup preserved: $($_.Exception.Message)")
        }
    } elseif ($null -eq $junctionBaseline -and -not $linkPresent) {
        $identitySafe = $true
    } else {
        $cleanupErrors.Add('junction baseline/presence mismatch; unlink/uninstall/probe/user preserved')
    }

    if ($identitySafe) {
        if ($linkPresent) {
            try {
                Unlink-OwnedJunction -Path $canonicalDataRoot
                if (Test-Path -LiteralPath $canonicalDataRoot) {
                    throw 'canonical DataRoot still exists after RemoveDirectoryW'
                }
                if (-not (Test-Path -LiteralPath $targetPath -PathType Container)) {
                    throw 'pre-position target disappeared during junction unlink'
                }
                Write-Host 'JUNCTION CLEANUP PASS: RemoveDirectoryW unlinked canonical path; target remains.'
            }
            catch { $cleanupErrors.Add("junction unlink verification failed: $($_.Exception.Message)") }
        }
        if ($msiAttempted -and $cleanupErrors.Count -eq 0) {
            try {
                $residueAfterUnlink = @(Get-InstallResidue -DataRoot $canonicalDataRoot `
                    -InstallRoot $installRoot -ProductKey $productKey)
                if ($residueAfterUnlink.Count -ne 0) {
                    $uninstall = Invoke-Msi -Action Uninstall -Path $packageUnderTest `
                        -LogPath $uninstallLog
                    if ($uninstall.ExitCode -notin @(0, 3010)) {
                        throw "same-MSI uninstall failed: exit=$($uninstall.ExitCode) log=$uninstallLog"
                    }
                    Write-Host "SAME-MSI UNINSTALL: exit=$($uninstall.ExitCode) log=$uninstallLog"
                }
                Wait-ForUninstallCleanup -DataRoot $canonicalDataRoot `
                    -InstallRoot $installRoot -ProductKey $productKey
                Write-Host 'POST-ATTEMPT CLEANUP PASS: installer residue absent.'
            }
            catch { $cleanupErrors.Add("post-attempt MSI cleanup failed: $($_.Exception.Message)") }
        }
        if ($createdCallerProbeRoot -and $cleanupErrors.Count -eq 0) {
            try { Remove-StandardProbeRoot -Path $probeRoot }
            catch { $cleanupErrors.Add("probe root cleanup failed: $($_.Exception.Message)") }
        }
        if ($createdGateUser -and $cleanupErrors.Count -eq 0) {
            try { Remove-GateUser -Name $gateUser }
            catch { $cleanupErrors.Add("gate user cleanup failed: $($_.Exception.Message)") }
        }
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -ne 0) { Write-Warning "cleanup also failed: $($cleanupErrors -join '; ')" }
    throw $primaryError
}
if ($cleanupErrors.Count -ne 0) { throw "preposition cleanup failed: $($cleanupErrors -join '; ')" }
