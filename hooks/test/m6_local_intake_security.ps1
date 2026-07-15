param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serviceName = 'SembazuruDaemon'
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    throw "FAIL: $serviceName already exists; refused to run and made no service, config, or account changes."
}

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'LocalIntake security gate requires an elevated Administrator process.'
}

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$profile = $Configuration.ToLowerInvariant()
$sourceDir = Join-Path $repo "target\$profile"
$sourceDaemon = Join-Path $sourceDir 'sembazuru-daemon.exe'
$sourceLauncher = Join-Path $sourceDir 'sembazuru.exe'
foreach ($binary in @($sourceDaemon, $sourceLauncher)) {
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) {
        throw "required binary is missing: $binary (run cargo build -p sembazuru-agent --$profile)"
    }
}

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try { return ([Net.IPEndPoint]$listener.LocalEndpoint).Port }
    finally { $listener.Stop() }
}

$tag = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$userA = "SbzA$tag"
$userB = "SbzB$tag"
$passwordA = "SbZ!A9a$tag"
$passwordB = "SbZ!B9b$tag"
$root = Join-Path $env:ProgramData "Sembazuru-LocalIntake-Gate-$tag"
$ioRoot = Join-Path $root 'caller-io'
$daemonExe = Join-Path $root 'sembazuru-daemon.exe'
$launcherExe = Join-Path $root 'sembazuru.exe'
$configPath = Join-Path $root 'daemon.toml'
$sidFileA = Join-Path $ioRoot 'child-a.sid'
$sidFileB = Join-Path $ioRoot 'child-b.sid'
$fallbackSidFile = Join-Path $ioRoot 'fallback-a.sid'
$createdUsers = [Collections.Generic.List[string]]::new()
$ownedService = $false

function New-GateUser([string]$Name, [string]$Password) {
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    New-LocalUser -Name $Name -Password $secure -PasswordNeverExpires `
        -UserMayNotChangePassword -AccountNeverExpires | Out-Null
    $script:createdUsers.Add($Name)
    $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $usersGroup -Member $Name
}

function Invoke-LauncherAsUser {
    param(
        [string]$User,
        [string]$Password,
        [string]$SidPath,
        [string]$LogStem
    )
    Remove-Item -LiteralPath $SidPath -Force -ErrorAction SilentlyContinue
    $stdout = Join-Path $ioRoot "$LogStem.stdout.txt"
    $stderr = Join-Path $ioRoot "$LogStem.stderr.txt"
    Remove-Item -LiteralPath $stdout, $stderr -Force -ErrorAction SilentlyContinue

    $escapedPath = $SidPath.Replace("'", "''")
    $childScript = "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value | Set-Content -LiteralPath '$escapedPath' -Encoding ascii"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childScript))
    $windowsPowerShell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$User", $secure)
    $oldEndpoint = [Environment]::GetEnvironmentVariable('SEMBAZURU_DAEMON', 'Process')
    try {
        $env:SEMBAZURU_DAEMON = 'npipe://Sembazuru.LocalIntake.v1'
        $process = Start-Process -FilePath $launcherExe `
            -ArgumentList @($windowsPowerShell, '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded) `
            -Credential $credential -LoadUserProfile -WorkingDirectory $ioRoot -WindowStyle Hidden `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr -Wait -PassThru
    }
    finally {
        if ($null -eq $oldEndpoint) { Remove-Item Env:\SEMBAZURU_DAEMON -ErrorAction SilentlyContinue }
        else { $env:SEMBAZURU_DAEMON = $oldEndpoint }
    }
    $note = if (Test-Path -LiteralPath $stderr) {
        Get-Content -LiteralPath $stderr -Raw
    } else {
        ''
    }
    $stdoutText = if (Test-Path -LiteralPath $stdout) {
        Get-Content -LiteralPath $stdout -Raw
    } else {
        ''
    }
    $sidExists = Test-Path -LiteralPath $SidPath
    $sidValue = if ($sidExists) { (Get-Content -LiteralPath $SidPath -Raw).Trim() } else { '' }
    return @{
        ExitCode = $process.ExitCode
        Note = $note
        Stdout = $stdoutText
        SidExists = $sidExists
        SidValue = $sidValue
        LauncherProcessId = $process.Id
    }
}

function Get-LocalIntakeAttemptJson {
    param([int]$Attempt, [string]$User, [hashtable]$Run)
    $serviceState = 'absent'
    $serviceProcessId = $null
    $serviceExitCode = $null
    try {
        $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
        if ($null -ne $service) {
            $serviceState = $service.State
            $serviceProcessId = $service.ProcessId
            $serviceExitCode = $service.ExitCode
        }
    }
    catch {
        $serviceState = "CIM failed: $($_.Exception.Message)"
    }
    try {
        $canonicalPipeExists = [IO.Directory]::GetFiles('\\.\pipe\') -contains `
            '\\.\pipe\Sembazuru.LocalIntake.v1'
    }
    catch {
        $canonicalPipeExists = "pipe enumeration failed: $($_.Exception.Message)"
    }
    return [ordered]@{
        attempt = $Attempt
        user = $User
        ExitCode = $Run.ExitCode
        Note = $Run.Note
        Stdout = $Run.Stdout
        SidExists = $Run.SidExists
        SidValue = $Run.SidValue
        LauncherProcessId = $Run.LauncherProcessId
        ServiceState = $serviceState
        ServiceProcessId = $serviceProcessId
        ServiceExitCode = $serviceExitCode
        CanonicalPipeExists = $canonicalPipeExists
    } | ConvertTo-Json -Compress
}

function Invoke-DaemonFallbackAsUser {
    param(
        [string]$User,
        [string]$Password,
        [string]$SidPath
    )
    $lastAttemptJson = $null
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $run = Invoke-LauncherAsUser $User $Password $SidPath "daemon-$User-$attempt"
        if ($run.ExitCode -eq 0 -and
            $run.Note -match 'local fallback:' -and
            $run.Note -notmatch 'daemon unavailable' -and
            (Test-Path -LiteralPath $SidPath)) {
            return $run
        }
        try {
            $lastAttemptJson = Get-LocalIntakeAttemptJson $attempt $User $run
        }
        catch {
            $lastAttemptJson = [ordered]@{
                attempt = $attempt
                user = $User
                DiagnosticError = $_.Exception.Message
            } | ConvertTo-Json -Compress
        }
        Write-Host "LOCALINTAKE ATTEMPT $lastAttemptJson"
        Start-Sleep -Milliseconds 250
    }
    throw "launcher for $User never reached daemon-side local fallback; last attempt: $lastAttemptJson"
}

function Format-CleanupError([object]$Record) {
    if ($null -eq $Record) { return 'none' }
    return "type=$($Record.Exception.GetType().FullName), message=$($Record.Exception.Message), " +
        "HResult=$($Record.Exception.HResult.ToString('X8')), FQID=$($Record.FullyQualifiedErrorId), " +
        "TargetObject=$($Record.TargetObject)"
}

function Assert-GateAcl {
    param(
        [string]$Path,
        [bool]$ExpectedProtected,
        [Security.AccessControl.FileSystemRights]$RequiredUserRights,
        [bool]$RequireInheritedRules,
        [bool]$ForbidUserMutation
    )
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.AreAccessRulesProtected -ne $ExpectedProtected) {
        throw "ACL inheritance mismatch for ${Path}: protected=$($acl.AreAccessRulesProtected)"
    }
    $requiredBySid = @{
        'S-1-5-18' = [Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-544' = [Security.AccessControl.FileSystemRights]::FullControl
        'S-1-5-32-545' = $RequiredUserRights
    }
    $actualBySid = @{}
    foreach ($sid in $requiredBySid.Keys) {
        $actualBySid[$sid] = [Security.AccessControl.FileSystemRights]0
    }
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($RequireInheritedRules -and -not $rule.IsInherited)) {
            continue
        }
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($actualBySid.ContainsKey($sid)) {
            $actualBySid[$sid] = $actualBySid[$sid] -bor $rule.FileSystemRights
        }
    }
    foreach ($sid in $requiredBySid.Keys) {
        $required = $requiredBySid[$sid]
        $actual = $actualBySid[$sid]
        if (($actual -band $required) -ne $required) {
            throw "ACL rights mismatch for $Path SID ${sid}: got $actual, require $required"
        }
    }
    if ($ForbidUserMutation) {
        $forbidden = [Security.AccessControl.FileSystemRights]::Write -bor
            [Security.AccessControl.FileSystemRights]::Delete -bor
            [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
            [Security.AccessControl.FileSystemRights]::TakeOwnership
        $userRights = $actualBySid['S-1-5-32-545']
        if (($userRights -band $forbidden) -ne 0) {
            throw "Builtin Users can mutate protected path ${Path}: rights=$userRights"
        }
    }
}

$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()
try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    & icacls.exe $root /inheritance:r /grant:r `
        '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' |
        Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'failed to protect the temporary service directory' }
    New-Item -ItemType Directory -Path $ioRoot -Force | Out-Null
    Copy-Item -LiteralPath $sourceDaemon -Destination $daemonExe
    Copy-Item -LiteralPath $sourceLauncher -Destination $launcherExe

    New-GateUser $userA $passwordA
    New-GateUser $userB $passwordB
    # Both standard callers need only the disposable evidence directory. The
    # service binary and config remain outside their writable ACL.
    & icacls.exe $ioRoot /grant:r '*S-1-5-32-545:(OI)(CI)M' | Write-Host
    if ($LASTEXITCODE -ne 0) { throw 'failed to grant caller evidence directory to Builtin Users' }

    $coord = "127.0.0.1:$(Get-FreeTcpPort)"
    $fileserver = "127.0.0.1:$(Get-FreeTcpPort)"
    $status = "127.0.0.1:$(Get-FreeTcpPort)"
    @"
coord_addr = "$coord"
intake_addr = "npipe://Sembazuru.LocalIntake.v1"
fileserver_addr = "$fileserver"
status_addr = "$status"
status_admin = false
"@ | Set-Content -LiteralPath $configPath -Encoding utf8

    Assert-GateAcl $root $true ([Security.AccessControl.FileSystemRights]::ReadAndExecute) $false $true
    Assert-GateAcl $ioRoot $false ([Security.AccessControl.FileSystemRights]::Modify) $false $false
    foreach ($protectedLeaf in @($daemonExe, $launcherExe, $configPath)) {
        Assert-GateAcl $protectedLeaf $false `
            ([Security.AccessControl.FileSystemRights]::ReadAndExecute) $true $true
    }

    $installOutput = & $daemonExe install --account system 2>&1 | Out-String
    $ownedService = $null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)
    if ($LASTEXITCODE -ne 0 -or -not $ownedService) {
        throw "failed to install temporary LocalSystem service: $installOutput"
    }
    $serviceKey = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    $serviceAccount = (Get-ItemProperty -Path $serviceKey -Name ObjectName).ObjectName
    if ($serviceAccount -ne 'LocalSystem') {
        throw "temporary daemon service is not LocalSystem: $serviceAccount"
    }
    New-ItemProperty -Path $serviceKey -Name Environment -PropertyType MultiString `
        -Value @("SEMBAZURU_CONFIG=$configPath") -Force | Out-Null
    Start-Service -Name $serviceName

    $expectedA = (Get-LocalUser -Name $userA).SID.Value
    $expectedB = (Get-LocalUser -Name $userB).SID.Value
    $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
    $administratorSids = Get-LocalGroupMember -Group $administrators | ForEach-Object { $_.SID.Value }
    if ($administratorSids -contains $expectedA -or $administratorSids -contains $expectedB) {
        throw 'gate caller was unexpectedly a member of Builtin Administrators'
    }
    Invoke-DaemonFallbackAsUser $userA $passwordA $sidFileA | Out-Null
    Invoke-DaemonFallbackAsUser $userB $passwordB $sidFileB | Out-Null
    $actualA = (Get-Content -LiteralPath $sidFileA -Raw).Trim()
    $actualB = (Get-Content -LiteralPath $sidFileB -Raw).Trim()

    if ($actualA -ne $expectedA) { throw "caller A child SID mismatch: got $actualA, want $expectedA" }
    if ($actualB -ne $expectedB) { throw "caller B child SID mismatch: got $actualB, want $expectedB" }
    if ($actualA -eq 'S-1-5-18' -or $actualB -eq 'S-1-5-18') {
        throw 'daemon-side fallback child ran as LocalSystem'
    }
    if ($actualA -eq $expectedB -or $actualB -eq $expectedA -or $actualA -eq $actualB) {
        throw 'caller identities crossed between LocalIntake sessions'
    }
    Write-Host "DAEMON FALLBACK: A=$actualA B=$actualB SYSTEM=false crossed=false"

    Stop-Service -Name $serviceName -Force
    (Get-Service -Name $serviceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
    $fallback = Invoke-LauncherAsUser $userA $passwordA $fallbackSidFile 'daemon-down-a'
    $fallbackSid = (Get-Content -LiteralPath $fallbackSidFile -Raw).Trim()
    if ($fallback.ExitCode -ne 0) { throw "daemon-down launcher fallback exited $($fallback.ExitCode)" }
    if ($fallback.Note -notmatch 'daemon unavailable, running locally') {
        throw "daemon-down launcher did not report local fallback: $($fallback.Note)"
    }
    if ($fallbackSid -ne $expectedA) {
        throw "daemon-down fallback SID mismatch: got $fallbackSid, want $expectedA"
    }
    Write-Host "DAEMON DOWN FALLBACK: caller=$fallbackSid note=verified"
    Write-Host 'PASS: standard users cannot turn LocalSystem LocalIntake into SYSTEM command execution; legitimate daemon and launcher fallback paths both work.'
}
catch {
    $primaryError = $_
}
finally {
    if ($ownedService) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.Status -ne 'Stopped') {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            try {
                $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
            }
            catch {
                $cleanupErrors.Add("temporary service stop wait failed: $($_.Exception.Message)")
            }
        }
        if (Test-Path -LiteralPath $daemonExe) {
            try { & $daemonExe uninstall 2>&1 | Out-Null }
            catch { $cleanupErrors.Add("temporary service uninstall failed: $($_.Exception.Message)") }
        }
        for ($attempt = 0; $attempt -lt 20; $attempt++) {
            if ($null -eq (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) { break }
            if ($attempt -eq 0) {
                try { & sc.exe delete $serviceName 2>&1 | Out-Null }
                catch { $cleanupErrors.Add("temporary service delete failed: $($_.Exception.Message)") }
            }
            Start-Sleep -Milliseconds 250
        }
        if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            $cleanupErrors.Add("temporary service $serviceName still exists")
        }
    }
    foreach ($user in $createdUsers) {
        Remove-LocalUser -Name $user -ErrorAction SilentlyContinue
        if ($null -ne (Get-LocalUser -Name $user -ErrorAction SilentlyContinue)) {
            $cleanupErrors.Add("temporary user $user still exists")
        }
    }
    try {
        $firstRootCleanupError = $null
        $lastRootCleanupError = $null
        for ($attempt = 0; $attempt -lt 20 -and (Test-Path -LiteralPath $root); $attempt++) {
            try {
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
            }
            catch {
                if ($null -eq $firstRootCleanupError) { $firstRootCleanupError = $_ }
                $lastRootCleanupError = $_
            }
            if (Test-Path -LiteralPath $root) { Start-Sleep -Milliseconds 250 }
        }
        if (Test-Path -LiteralPath $root) {
            $detail = "temporary directory $root still exists; " +
                "first Remove-Item error: $(Format-CleanupError $firstRootCleanupError); " +
                "last Remove-Item error: $(Format-CleanupError $lastRootCleanupError)"
            try {
                $remainingPaths = @($root) + @(
                    Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop |
                        ForEach-Object { $_.FullName }
                )
                $detail += "; remaining paths: $($remainingPaths -join ', ')"
            }
            catch {
                $detail += "; remaining path enumeration failed: $($_.Exception.Message)"
            }
            try {
                $aclSnapshot = (& icacls.exe $root /T /C 2>&1 | Out-String).Trim()
                $detail += "; icacls snapshot: $aclSnapshot"
            }
            catch {
                $detail += "; icacls snapshot failed: $($_.Exception.Message)"
            }
            try {
                $serviceSnapshot = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" |
                    Select-Object State, ProcessId, PathName | ConvertTo-Json -Compress
                if (-not $serviceSnapshot) { $serviceSnapshot = 'none' }
                $detail += "; service snapshot: $serviceSnapshot"
            }
            catch {
                $detail += "; service snapshot failed: $($_.Exception.Message)"
            }
            try {
                $processSnapshot = Get-CimInstance Win32_Process |
                    Where-Object {
                        $_.ExecutablePath -like "*$root*" -or $_.CommandLine -like "*$root*"
                    } |
                    Select-Object ProcessId, Name, ExecutablePath, CommandLine |
                    ConvertTo-Json -Compress
                if (-not $processSnapshot) { $processSnapshot = 'none' }
                $detail += "; root process snapshot: $processSnapshot"
            }
            catch {
                $detail += "; root process snapshot failed: $($_.Exception.Message)"
            }
            $cleanupErrors.Add($detail)
        }
    }
    catch {
        $cleanupErrors.Add("temporary directory cleanup failed: $($_.Exception.Message)")
    }
}

if ($null -ne $primaryError) {
    Write-Error -ErrorRecord $primaryError -ErrorAction Continue
    if ($cleanupErrors.Count -eq 0) {
        throw $primaryError
    }
    throw "LocalIntake gate failed: $($primaryError.Exception.Message); cleanup failed: $($cleanupErrors -join '; ')"
}
if ($cleanupErrors.Count -ne 0) {
    throw "LocalIntake gate cleanup failed: $($cleanupErrors -join '; ')"
}
