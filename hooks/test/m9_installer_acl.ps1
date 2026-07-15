[CmdletBinding(DefaultParameterSetName = 'Static')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Static')]
    [switch]$Static,

    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [ValidateNotNullOrEmpty()]
    [string]$Msi,

    [string]$Source
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$workerSid = 'S-1-5-80-934400648-3059976913-1740392721-646658299-1483742795'
$rootSddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$workerSid)"
$workerWriteSddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$workerSid)"

if ([string]::IsNullOrWhiteSpace($Source)) {
    $Source = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) `
        'installer\sembazuru.wxs'
}

function Assert-StaticAclSource {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "WiX source not found: $Path"
    }

    [xml]$document = Get-Content -LiteralPath $Path -Raw
    $namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespaces.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
    $namespaces.AddNamespace('util', 'http://wixtoolset.org/schemas/v4/wxs/util')
    $failures = [Collections.Generic.List[string]]::new()
    $expectations = @(
        [pscustomobject]@{ Component = 'DataFolderComp'; Sddl = $rootSddl },
        [pscustomobject]@{ Component = 'ScratchFolderComp'; Sddl = $workerWriteSddl },
        [pscustomobject]@{ Component = 'CasFolderComp'; Sddl = $workerWriteSddl }
    )

    foreach ($expectation in $expectations) {
        $component = $document.SelectSingleNode(
            "//w:Component[@Id='$($expectation.Component)']", $namespaces)
        if ($null -eq $component) {
            $failures.Add("missing Component $($expectation.Component)")
            continue
        }
        $createFolder = $component.SelectSingleNode('w:CreateFolder', $namespaces)
        if ($null -eq $createFolder) {
            $failures.Add("$($expectation.Component) is missing CreateFolder")
            continue
        }
        $permissions = @($createFolder.SelectNodes('w:PermissionEx', $namespaces))
        if ($permissions.Count -ne 1) {
            $failures.Add(
                "$($expectation.Component) requires exactly one core PermissionEx; found $($permissions.Count)")
            continue
        }
        if ($permissions[0].GetAttribute('Sddl') -cne $expectation.Sddl) {
            $failures.Add(
                "$($expectation.Component) Sddl mismatch: '$($permissions[0].GetAttribute('Sddl'))'")
        }
    }

    $legacyPermissions = @($document.SelectNodes('//util:PermissionEx', $namespaces))
    if ($legacyPermissions.Count -ne 0) {
        $failures.Add("util:PermissionEx must be absent; found $($legacyPermissions.Count)")
    }
    $removeFolderEx = @($document.SelectNodes('//util:RemoveFolderEx', $namespaces))
    if ($removeFolderEx.Count -ne 1) {
        $failures.Add("exactly one util:RemoveFolderEx must remain; found $($removeFolderEx.Count)")
    }

    if ($failures.Count -ne 0) {
        throw "STATIC ACL SOURCE FAIL:`n - $($failures -join "`n - ")"
    }
    Write-Host "STATIC ACL SOURCE PASS: protected root + worker-only scratch/cas; SID=$workerSid"
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Installer ACL integration gate requires an elevated Administrator process.'
    }
}

function Get-UninstallRegistrations {
    $roots = @(
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $properties = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            $displayProperty = $properties.PSObject.Properties['DisplayName']
            $productProperty = $properties.PSObject.Properties['ProductName']
            $displayName = if ($null -ne $displayProperty) { [string]$displayProperty.Value } else { '' }
            $productName = if ($null -ne $productProperty) { [string]$productProperty.Value } else { '' }
            if ($displayName -match '^Sembazuru(?:\s|$)' -or $productName -eq 'Sembazuru') {
                [pscustomobject]@{
                    Path = $key.PSPath
                    DisplayName = $displayName
                    ProductName = $productName
                }
            }
        }
    }
}

function Get-RelatedProductCodes {
    $upgradeCode = '{7B3C2E9A-1D4F-4C8B-9E6A-0F2D5A7C1B30}'
    if ($null -eq ('Sembazuru.MsiNativeMethods' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace Sembazuru {
    public static class MsiNativeMethods {
        [DllImport("msi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        public static extern UInt32 MsiEnumRelatedProductsW(
            string upgradeCode, UInt32 reserved, UInt32 productIndex,
            StringBuilder productCode);
    }
}
'@
    }

    for ([uint32]$index = 0; ; $index++) {
        $productCode = [Text.StringBuilder]::new(39)
        $result = [Sembazuru.MsiNativeMethods]::MsiEnumRelatedProductsW(
            $upgradeCode, 0, $index, $productCode)
        if ($result -eq 259) { return }
        if ($result -ne 0) {
            throw "MsiEnumRelatedProductsW failed closed: result=$result index=$index upgrade=$upgradeCode"
        }
        $value = $productCode.ToString()
        if ($value -notmatch '^\{[0-9A-Fa-f-]{36}\}$') {
            throw "MsiEnumRelatedProductsW returned an invalid ProductCode: '$value'"
        }
        $value
    }
}

function Get-InstallResidue {
    param(
        [string]$DataRoot,
        [string]$InstallRoot,
        [string]$ProductKey
    )

    $residue = [Collections.Generic.List[string]]::new()
    foreach ($serviceName in @('SembazuruDaemon', 'SembazuruWorker')) {
        if ($null -ne (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {
            $residue.Add("service:$serviceName")
        }
    }
    foreach ($path in @($DataRoot, $InstallRoot, $ProductKey)) {
        if (Test-Path -LiteralPath $path) { $residue.Add("path:$path") }
    }
    $currentUserProductKey = 'Registry::HKEY_CURRENT_USER\Software\Sembazuru'
    $commonStartupShortcut = Join-Path `
        ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonStartup)) 'Sembazuru.lnk'
    $commonProgramsFolder = Join-Path `
        ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonPrograms)) 'Sembazuru'
    $commonProgramsShortcut = Join-Path $commonProgramsFolder 'Sembazuru.lnk'
    foreach ($path in @(
        $currentUserProductKey, $commonStartupShortcut,
        $commonProgramsFolder, $commonProgramsShortcut)) {
        if (Test-Path -LiteralPath $path) { $residue.Add("path:$path") }
    }
    $normalizedInstallRoot = $InstallRoot.TrimEnd('\')
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    foreach ($segment in @([string]$machinePath -split ';')) {
        if ([string]::Equals($segment.Trim().TrimEnd('\'), $normalizedInstallRoot,
                [StringComparison]::OrdinalIgnoreCase)) {
            $residue.Add("machine-path:$segment")
        }
    }
    $firewallNames = @(
        'Sembazuru Coordination', 'Sembazuru File Supply', 'Sembazuru Worker Execution')
    $firewallRules = @(Get-NetFirewallRule -ErrorAction Stop)
    foreach ($firewallName in $firewallNames) {
        if (@($firewallRules | Where-Object { $_.DisplayName -eq $firewallName }).Count -ne 0) {
            $residue.Add("firewall:$firewallName")
        }
    }
    foreach ($productCode in @(Get-RelatedProductCodes)) {
        $residue.Add("related-product:$productCode")
    }
    foreach ($registration in @(Get-UninstallRegistrations)) {
        $residue.Add("uninstall:$($registration.Path)")
    }
    return @($residue)
}

function Assert-CleanPreflight {
    param(
        [string]$DataRoot,
        [string]$InstallRoot,
        [string]$ProductKey
    )

    $conflicts = @(Get-InstallResidue -DataRoot $DataRoot -InstallRoot $InstallRoot `
        -ProductKey $ProductKey)
    if ($conflicts.Count -ne 0) {
        throw "preflight refused to modify an existing Sembazuru installation: $($conflicts -join '; ')"
    }
    Write-Host 'PREFLIGHT PASS: no related MSI, service, data, shortcut, PATH, firewall, product key, or 32/64-bit uninstall registration exists.'
}

function Get-RuleSid {
    param([Security.AccessControl.FileSystemAccessRule]$Rule)
    return $Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
}

function Assert-ExactAclRules {
    param(
        [string]$Path,
        [bool]$ExpectedProtected,
        [bool]$ExpectedInherited,
        [int64]$WorkerMask,
        [bool]$RequireContainerInheritance
    )

    $acl = Get-Acl -LiteralPath $Path
    if ($acl.AreAccessRulesProtected -ne $ExpectedProtected) {
        throw "ACL protection mismatch for ${Path}: got $($acl.AreAccessRulesProtected), want $ExpectedProtected"
    }
    $rules = @($acl.Access)
    if ($rules.Count -ne 3) {
        throw "ACL rule count mismatch for ${Path}: got $($rules.Count), want 3"
    }
    $expectedMasks = @{
        'S-1-5-18' = [int64]0x1f01ff
        'S-1-5-32-544' = [int64]0x1f01ff
        $workerSid = $WorkerMask
    }
    $seen = @{}
    $expectedInheritance = [Security.AccessControl.InheritanceFlags]::None
    if ($RequireContainerInheritance) {
        $expectedInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    }
    foreach ($rule in $rules) {
        $sid = Get-RuleSid -Rule $rule
        if (-not $expectedMasks.ContainsKey($sid)) {
            throw "unexpected ACL SID on ${Path}: $sid"
        }
        if ($seen.ContainsKey($sid)) { throw "duplicate ACL SID on ${Path}: $sid" }
        $seen[$sid] = $true
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw "non-allow ACL rule on ${Path}: $sid $($rule.AccessControlType)"
        }
        if ($rule.IsInherited -ne $ExpectedInherited) {
            throw "ACL inheritance source mismatch on ${Path}: $sid inherited=$($rule.IsInherited)"
        }
        if ([int64]$rule.FileSystemRights -ne $expectedMasks[$sid]) {
            throw "ACL rights mismatch on ${Path}: $sid mask=0x$(([int64]$rule.FileSystemRights).ToString('x')) want=0x$($expectedMasks[$sid].ToString('x'))"
        }
        if ($rule.InheritanceFlags -ne $expectedInheritance) {
            throw "ACL propagation mismatch on ${Path}: $sid flags=$($rule.InheritanceFlags)"
        }
        if ($rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "unexpected ACL propagation flags on ${Path}: $sid $($rule.PropagationFlags)"
        }
    }
    foreach ($requiredSid in $expectedMasks.Keys) {
        if (-not $seen.ContainsKey($requiredSid)) {
            throw "required ACL SID missing from ${Path}: $requiredSid"
        }
    }
}

function Assert-ServiceSidAntiDrift {
    $output = & sc.exe showsid SembazuruWorker 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) {
        throw "sc.exe showsid SembazuruWorker failed ($LASTEXITCODE): $output"
    }
    $reported = @([regex]::Matches($output, 'S-1-5-80-(?:\d+-){4}\d+') |
        ForEach-Object { $_.Value } | Sort-Object -Unique)
    if ($reported.Count -ne 1 -or $reported[0] -ne $workerSid) {
        throw "worker service SID drift: embedded=$workerSid sc.exe=$($reported -join ',') output=$output"
    }
    Write-Host "SERVICE SID PASS: embedded SDDL SID matches sc.exe showsid: $workerSid"
}

function Assert-ServicesRunning {
    foreach ($expectation in @(
        [pscustomobject]@{ Name = 'SembazuruDaemon'; Account = 'LocalSystem' },
        [pscustomobject]@{ Name = 'SembazuruWorker'; Account = 'NT SERVICE\SembazuruWorker' }
    )) {
        $service = Get-Service -Name $expectation.Name -ErrorAction Stop
        if ($service.Status -ne 'Running') {
            $service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
            $service.Refresh()
        }
        if ($service.Status -ne 'Running') {
            throw "$($expectation.Name) did not reach Running: $($service.Status)"
        }
        $cim = Get-CimInstance Win32_Service -Filter "Name='$($expectation.Name)'" -ErrorAction Stop
        if ($cim.StartName -ne $expectation.Account) {
            throw "$($expectation.Name) account mismatch: got $($cim.StartName), want $($expectation.Account)"
        }
        Write-Host "SERVICE RUNNING: $($expectation.Name) account=$($cim.StartName) pid=$($cim.ProcessId)"
    }
}

function New-StandardGateUser {
    param([string]$Name, [string]$Password)

    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    New-LocalUser -Name $Name -Password $secure -PasswordNeverExpires `
        -UserMayNotChangePassword -AccountNeverExpires | Out-Null
    $script:createdGateUser = $true
    $usersGroup = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $usersGroup -Member $Name
    $administrators = Get-LocalGroup -SID 'S-1-5-32-544'
    $adminSids = @(Get-LocalGroupMember -Group $administrators | ForEach-Object { $_.SID.Value })
    $userSid = (Get-LocalUser -Name $Name).SID.Value
    if ($adminSids -contains $userSid) {
        throw "temporary ACL caller is unexpectedly an Administrator: $Name $userSid"
    }
    return $userSid
}

function ConvertTo-SingleQuotedLiteral {
    param([string]$Value)
    return "'$($Value.Replace("'", "''"))'"
}

function New-StandardProbeRoot {
    param([string]$Path, [string]$UserSid)

    New-Item -ItemType Directory -Path $Path -ErrorAction Stop | Out-Null
    $script:createdCallerProbeRoot = $true
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm(
        "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$UserSid)")
    Set-Acl -LiteralPath $Path -AclObject $acl

    $applied = Get-Acl -LiteralPath $Path
    $expected = @{
        'S-1-5-18' = [int64]0x1f01ff
        'S-1-5-32-544' = [int64]0x1f01ff
        $UserSid = [int64]0x1301bf
    }
    $rules = @($applied.Access)
    if (-not $applied.AreAccessRulesProtected -or $rules.Count -ne 3) {
        throw "standard-user probe root DACL shape mismatch: protected=$($applied.AreAccessRulesProtected) rules=$($rules.Count)"
    }
    foreach ($rule in $rules) {
        $sid = Get-RuleSid -Rule $rule
        if (-not $expected.ContainsKey($sid) -or $rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            [int64]$rule.FileSystemRights -ne $expected[$sid]) {
            throw "standard-user probe root DACL mismatch: sid=$sid inherited=$($rule.IsInherited) rights=$($rule.FileSystemRights)"
        }
    }
}

function Assert-StandardUserDenied {
    param(
        [string]$User,
        [string]$Password,
        [string]$DataRoot,
        [string]$ScratchRoot,
        [string]$CasRoot,
        [string]$DaemonConfig,
        [string]$WorkerConfig,
        [string]$ProbeRoot
    )

    $paths = [ordered]@{
        DataRoot = ConvertTo-SingleQuotedLiteral $DataRoot
        ScratchRoot = ConvertTo-SingleQuotedLiteral $ScratchRoot
        CasRoot = ConvertTo-SingleQuotedLiteral $CasRoot
        DaemonConfig = ConvertTo-SingleQuotedLiteral $DaemonConfig
        WorkerConfig = ConvertTo-SingleQuotedLiteral $WorkerConfig
    }
    $childScript = @"
`$ErrorActionPreference = 'Stop'
function Test-AccessDenied([scriptblock]`$Action) {
    try {
        `$null = & `$Action
        return [pscustomobject]@{ Denied = `$false; Error = 'operation succeeded' }
    }
    catch {
        `$errorRecord = `$_
        `$exception = `$errorRecord.Exception
        `$denied = `$exception -is [UnauthorizedAccessException] -or
            `$exception.HResult -eq -2147024891 -or
            `$errorRecord.FullyQualifiedErrorId -match 'UnauthorizedAccess|PermissionDenied'
        return [pscustomobject]@{ Denied = `$denied; Error = `$exception.Message }
    }
}
`$results = [ordered]@{}
`$results.RootList = Test-AccessDenied { Get-ChildItem -LiteralPath $($paths.DataRoot) -ErrorAction Stop }
`$results.DaemonRead = Test-AccessDenied { Get-Content -LiteralPath $($paths.DaemonConfig) -Raw -ErrorAction Stop }
`$results.WorkerRead = Test-AccessDenied { Get-Content -LiteralPath $($paths.WorkerConfig) -Raw -ErrorAction Stop }
`$results.RootCreate = Test-AccessDenied { Set-Content -LiteralPath (Join-Path $($paths.DataRoot) 'standard-user-root.probe') -Value denied -ErrorAction Stop }
`$results.DaemonWrite = Test-AccessDenied { Add-Content -LiteralPath $($paths.DaemonConfig) -Value denied -ErrorAction Stop }
`$results.WorkerWrite = Test-AccessDenied { Add-Content -LiteralPath $($paths.WorkerConfig) -Value denied -ErrorAction Stop }
`$results.ScratchCreate = Test-AccessDenied { Set-Content -LiteralPath (Join-Path $($paths.ScratchRoot) 'standard-user-scratch.probe') -Value denied -ErrorAction Stop }
`$results.CasCreate = Test-AccessDenied { Set-Content -LiteralPath (Join-Path $($paths.CasRoot) 'standard-user-cas.probe') -Value denied -ErrorAction Stop }
[pscustomobject]`$results | ConvertTo-Json -Compress
"@
    $scriptPath = Join-Path $ProbeRoot 'p.ps1'
    $stdout = Join-Path $ProbeRoot 'o.txt'
    $stderr = Join-Path $ProbeRoot 'e.txt'
    Set-Content -LiteralPath $scriptPath -Value $childScript -Encoding Unicode
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    $credential = [Management.Automation.PSCredential]::new(
        "$([Environment]::MachineName)\$User", $secure)
    $windowsPowerShell = (Get-Command powershell.exe -ErrorAction Stop).Source
    $argumentLine = "-NoProfile -NonInteractive -File `"$scriptPath`""
    $commandLine = "`"$windowsPowerShell`" $argumentLine"
    if ($commandLine.Length -ge 1024) {
        throw "standard-user child command line is too long: $($commandLine.Length) >= 1024"
    }
    Write-Host "STANDARD USER COMMAND: length=$($commandLine.Length) limit=1024 script=$scriptPath"
    $process = Start-Process -FilePath $windowsPowerShell `
        -ArgumentList $argumentLine `
        -Credential $credential -LoadUserProfile -WorkingDirectory ([Environment]::SystemDirectory) `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr -WindowStyle Hidden `
        -Wait -PassThru
    [string]$stderrText = if (Test-Path -LiteralPath $stderr) {
        [string](Get-Content -LiteralPath $stderr -Raw)
    } else { '<missing>' }
    $stdoutText = if (Test-Path -LiteralPath $stdout) {
        [string](Get-Content -LiteralPath $stdout -Raw)
    } else { '<missing>' }
    if ($process.ExitCode -ne 0 -or $stderrText -ne '') {
        throw "standard-user access probe failed: exit=$($process.ExitCode) stderr=$stderrText stdout=$stdoutText"
    }
    try { $result = $stdoutText | ConvertFrom-Json }
    catch { throw "standard-user access probe JSON failed: $($_.Exception.Message); stdout=$stdoutText" }
    $failed = [Collections.Generic.List[string]]::new()
    foreach ($name in @(
        'RootList', 'DaemonRead', 'WorkerRead', 'RootCreate',
        'DaemonWrite', 'WorkerWrite', 'ScratchCreate', 'CasCreate')) {
        $entry = $result.PSObject.Properties[$name].Value
        if (-not $entry.Denied) { $failed.Add("${name}: $($entry.Error)") }
    }
    if ($failed.Count -ne 0) {
        throw "standard user escaped ProgramData ACL: $($failed -join '; ')"
    }
    Write-Host "STANDARD USER ACCESS PASS: root listing/config reads/root+config+scratch+cas writes all denied; user=$User"
}

function Invoke-Msi {
    param(
        [ValidateSet('Install', 'Uninstall')]
        [string]$Action,
        [string]$Path,
        [string]$LogPath
    )

    $verb = if ($Action -eq 'Install') { '/i' } else { '/x' }
    return Start-Process -FilePath 'msiexec.exe' `
        -ArgumentList @($verb, "`"$Path`"", '/qn', '/norestart', '/l*v', "`"$LogPath`"") `
        -Wait -PassThru
}

function Remove-GateUser {
    param([string]$Name)

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        if ($null -eq (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) { return }
        try { Remove-LocalUser -Name $Name -ErrorAction Stop }
        catch {
            if ($attempt -eq 5) { throw }
        }
        Start-Sleep -Milliseconds 250
    }
    if ($null -ne (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue)) {
        throw "temporary ACL caller still exists after cleanup: $Name"
    }
}

function Remove-StandardProbeRoot {
    param([string]$Path)

    for ($attempt = 1; $attempt -le 5; $attempt++) {
        if (-not (Test-Path -LiteralPath $Path)) { return }
        try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
        catch {
            if ($attempt -eq 5) { throw }
        }
        Start-Sleep -Milliseconds 250
    }
    if (Test-Path -LiteralPath $Path) {
        throw "standard-user probe root still exists after cleanup: $Path"
    }
}

function Wait-ForUninstallCleanup {
    param(
        [string]$DataRoot,
        [string]$InstallRoot,
        [string]$ProductKey
    )

    $residue = @()
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        $residue = @(Get-InstallResidue -DataRoot $DataRoot -InstallRoot $InstallRoot `
            -ProductKey $ProductKey)
        if ($residue.Count -eq 0) { return }
        Start-Sleep -Milliseconds 250
    }
    throw "uninstall residue remained: $($residue -join '; ')"
}

Assert-StaticAclSource -Path $Source
if ($Static) { return }

Assert-Administrator
$Msi = (Resolve-Path -LiteralPath $Msi -ErrorAction Stop).Path
$commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$dataRoot = Join-Path $commonData 'Sembazuru'
$scratchRoot = Join-Path $dataRoot 'scratch'
$casRoot = Join-Path $dataRoot 'cas'
$daemonConfig = Join-Path $dataRoot 'daemon.toml'
$workerConfig = Join-Path $dataRoot 'worker.toml'
$installRoot = Join-Path $programFiles 'Sembazuru'
$productKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Sembazuru'

Assert-CleanPreflight -DataRoot $dataRoot -InstallRoot $installRoot -ProductKey $productKey

$tag = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$gateUser = "SbzAcl$tag"
$gatePassword = "SbZ!9a$tag"
$callerProbeRoot = Join-Path $commonData "Sembazuru-M9-Acl-Probe-$tag"
$logRoot = Join-Path ([IO.Path]::GetTempPath()) "sembazuru-m9-acl-$tag"
$installLog = Join-Path $logRoot 'install.log'
$uninstallLog = Join-Path $logRoot 'uninstall.log'
$installSucceeded = $false
$createdGateUser = $false
$createdCallerProbeRoot = $false
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

try {
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $install = Invoke-Msi -Action Install -Path $Msi -LogPath $installLog
    if ($install.ExitCode -notin @(0, 3010)) {
        throw "MSI install failed: exit=$($install.ExitCode) log=$installLog"
    }
    $installSucceeded = $true
    Write-Host "MSI INSTALL PASS: exit=$($install.ExitCode) log=$installLog"

    Assert-ServiceSidAntiDrift
    Assert-ServicesRunning
    Assert-ExactAclRules -Path $dataRoot -ExpectedProtected $true -ExpectedInherited $false `
        -WorkerMask 0x1200a9 -RequireContainerInheritance $true
    Assert-ExactAclRules -Path $scratchRoot -ExpectedProtected $true -ExpectedInherited $false `
        -WorkerMask 0x1301bf -RequireContainerInheritance $true
    Assert-ExactAclRules -Path $casRoot -ExpectedProtected $true -ExpectedInherited $false `
        -WorkerMask 0x1301bf -RequireContainerInheritance $true
    Write-Host 'DIRECTORY ACL PASS: protected, non-inherited, exact SY/BA/worker masks; no Users/AU/Everyone.'

    foreach ($config in @($daemonConfig, $workerConfig)) {
        if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
            throw "seeded config is missing: $config"
        }
        Assert-ExactAclRules -Path $config -ExpectedProtected $false -ExpectedInherited $true `
            -WorkerMask 0x1200a9 -RequireContainerInheritance $false
    }
    Write-Host 'CONFIG ACL PASS: daemon.toml/worker.toml inherit SY/BA Full + worker RX only.'

    foreach ($probeRoot in @($scratchRoot, $casRoot)) {
        $probeDir = Join-Path $probeRoot 'm9-acl-probe-dir'
        $probeFile = Join-Path $probeRoot 'm9-acl-probe-file'
        New-Item -ItemType Directory -Path $probeDir -Force | Out-Null
        Set-Content -LiteralPath $probeFile -Value 'acl inheritance probe' -Encoding ascii
        Assert-ExactAclRules -Path $probeDir -ExpectedProtected $false -ExpectedInherited $true `
            -WorkerMask 0x1301bf -RequireContainerInheritance $true
        Assert-ExactAclRules -Path $probeFile -ExpectedProtected $false -ExpectedInherited $true `
            -WorkerMask 0x1301bf -RequireContainerInheritance $false
        Remove-Item -LiteralPath $probeFile -Force
        Remove-Item -LiteralPath $probeDir -Recurse -Force
    }
    Write-Host 'CHILD ACL PASS: scratch/cas file+directory probes inherit worker Modify and no other SID.'

    $gateSid = New-StandardGateUser -Name $gateUser -Password $gatePassword
    New-StandardProbeRoot -Path $callerProbeRoot -UserSid $gateSid
    Assert-StandardUserDenied -User $gateUser -Password $gatePassword -DataRoot $dataRoot `
        -ScratchRoot $scratchRoot -CasRoot $casRoot -DaemonConfig $daemonConfig `
        -WorkerConfig $workerConfig -ProbeRoot $callerProbeRoot
    Write-Host "STANDARD USER SID: $gateSid"

    Write-Host 'WORKER CAPABILITY EVIDENCE: SembazuruWorker is Running under its virtual account; exact worker SID grants worker.toml RX and scratch/cas Modify. The packaged worker exposes no minimal self-probe for isolated filesystem operations.'
}
catch {
    $primaryError = $_
}
finally {
    if ($createdCallerProbeRoot) {
        try { Remove-StandardProbeRoot -Path $callerProbeRoot }
        catch { $cleanupErrors.Add("standard-user probe root cleanup failed: $($_.Exception.Message)") }
    }
    if ($createdGateUser) {
        try { Remove-GateUser -Name $gateUser }
        catch { $cleanupErrors.Add("temporary user cleanup failed: $($_.Exception.Message)") }
    }
    if ($installSucceeded) {
        $uninstallSucceeded = $false
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                $uninstall = Invoke-Msi -Action Uninstall -Path $Msi -LogPath $uninstallLog
                if ($uninstall.ExitCode -in @(0, 3010)) {
                    $uninstallSucceeded = $true
                    Write-Host "MSI UNINSTALL PASS: attempt=$attempt exit=$($uninstall.ExitCode) log=$uninstallLog"
                    break
                }
                if ($uninstall.ExitCode -ne 1618) {
                    $cleanupErrors.Add("MSI uninstall failed: exit=$($uninstall.ExitCode) log=$uninstallLog")
                    break
                }
            }
            catch {
                $cleanupErrors.Add("MSI uninstall invocation failed: $($_.Exception.Message); log=$uninstallLog")
                break
            }
            Start-Sleep -Seconds $attempt
        }
        if (-not $uninstallSucceeded -and $cleanupErrors.Count -eq 0) {
            $cleanupErrors.Add("MSI uninstall remained busy after 3 attempts; log=$uninstallLog")
        }
        if ($uninstallSucceeded) {
            try {
                Wait-ForUninstallCleanup -DataRoot $dataRoot -InstallRoot $installRoot `
                    -ProductKey $productKey
                Write-Host 'UNINSTALL CLEANUP PASS: services/data/Program Files/HKLM key/uninstall registration absent.'
            }
            catch { $cleanupErrors.Add($_.Exception.Message) }
        }
    }
}

if ($null -ne $primaryError) {
    if ($cleanupErrors.Count -ne 0) {
        Write-Warning "cleanup also failed: $($cleanupErrors -join '; ')"
    }
    throw $primaryError
}
if ($cleanupErrors.Count -ne 0) {
    throw "installer ACL cleanup failed: $($cleanupErrors -join '; ')"
}

Write-Host 'PASS: MSI ProgramData ACLs deny standard users, preserve worker-only access, and uninstall cleanly.'
