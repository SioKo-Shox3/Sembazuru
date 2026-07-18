[CmdletBinding(DefaultParameterSetName = 'Static')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Static')]
    [switch]$Static,

    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [ValidateNotNullOrEmpty()]
    [string]$Msi,

    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [ValidateNotNullOrEmpty()]
    [string]$StoreCtl,

    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [ValidateNotNullOrEmpty()]
    [string]$ExecVfs,

    [string]$Source
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$daemonSid = 'S-1-5-80-1935860780-3819908813-1334579252-621723184-2190217863'
$workerSid = 'S-1-5-80-934400648-3059976913-1740392721-646658299-1483742795'
$rootSddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;$workerSid)(A;;0x1200a9;;;$daemonSid)"
$workerWriteSddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;$workerSid)"
$safeUpgradeMessage = 'Automatic upgrade is blocked until a safe legacy migration is available. The earlier installation was left unchanged.'

if ([string]::IsNullOrWhiteSpace($Source)) {
    $Source = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) `
        'installer\sembazuru.wxs'
}

function Assert-StaticLifecycleSource {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "WiX source not found: $Path"
    }

    [xml]$document = Get-Content -LiteralPath $Path -Raw
    $namespaces = [Xml.XmlNamespaceManager]::new($document.NameTable)
    $namespaces.AddNamespace('w', 'http://wixtoolset.org/schemas/v4/wxs')
    $failures = [Collections.Generic.List[string]]::new()

    $repoRoot = Split-Path (Split-Path $Path -Parent) -Parent
    $agentConfigSource = Get-Content -LiteralPath (Join-Path $repoRoot 'crates\agent\src\config.rs') -Raw
    $workerConfigSource = Get-Content -LiteralPath (Join-Path $repoRoot 'crates\worker\src\config.rs') -Raw
    foreach ($expectation in @(
        [pscustomobject]@{ Source = $agentConfigSource; Name = 'daemon'; Target = 'MachineConfigTarget::Daemon' },
        [pscustomobject]@{ Source = $workerConfigSource; Name = 'worker'; Target = 'MachineConfigTarget::Worker' }
    )) {
        if ($expectation.Source -notmatch 'seed_machine_config' -or
            $expectation.Source -notmatch [regex]::Escape($expectation.Target)) {
            $failures.Add("$($expectation.Name) canonical seed must dispatch through $($expectation.Target)")
        }
    }
    if ($agentConfigSource -notmatch 'replace_machine_config') {
        $failures.Add('daemon canonical replace must dispatch through replace_machine_config')
    }

    $binary = @($document.SelectNodes("//w:Binary[@Id='MachineStoreCtlBinary']", $namespaces))
    if ($binary.Count -ne 1 -or $binary[0].GetAttribute('SourceFile') -cne '$(var.StoreCtl)') {
        $failures.Add('MachineStoreCtlBinary must appear exactly once with SourceFile=$(var.StoreCtl)')
    }

    $actionExpectations = @(
        [pscustomobject]@{ Id = 'RollbackMachineStoreProvision'; Command = 'rollback-provision'; Execute = 'rollback' },
        [pscustomobject]@{ Id = 'ProvisionMachineStore'; Command = 'provision'; Execute = 'deferred' },
        [pscustomobject]@{ Id = 'CommitMachineStoreProvision'; Command = 'commit-provision'; Execute = 'commit' },
        [pscustomobject]@{ Id = 'UninstallMachineStore'; Command = 'uninstall'; Execute = 'deferred' }
    )
    foreach ($expectation in $actionExpectations) {
        $action = @($document.SelectNodes(
            "//w:CustomAction[@Id='$($expectation.Id)']", $namespaces))
        if ($action.Count -ne 1) {
            $failures.Add("$($expectation.Id) must appear exactly once")
            continue
        }
        foreach ($attribute in @(
            [pscustomobject]@{ Name = 'BinaryRef'; Value = 'MachineStoreCtlBinary' },
            [pscustomobject]@{ Name = 'ExeCommand'; Value = $expectation.Command },
            [pscustomobject]@{ Name = 'Execute'; Value = $expectation.Execute },
            [pscustomobject]@{ Name = 'Impersonate'; Value = 'no' },
            [pscustomobject]@{ Name = 'Return'; Value = 'check' })) {
            if ($action[0].GetAttribute($attribute.Name) -cne $attribute.Value) {
                $failures.Add("$($expectation.Id) $($attribute.Name) must be '$($attribute.Value)'")
            }
        }
    }

    foreach ($seedId in @('SeedDaemonConfig', 'SeedWorkerConfig')) {
        $seed = @($document.SelectNodes("//w:CustomAction[@Id='$seedId']", $namespaces))
        if ($seed.Count -ne 1 -or $seed[0].GetAttribute('Execute') -cne 'deferred' -or
            $seed[0].GetAttribute('Impersonate') -cne 'no' -or
            $seed[0].GetAttribute('Return') -cne 'check') {
            $failures.Add("$seedId must be one deferred, non-impersonated, checked action")
        }
    }

    $scheduleExpectations = @(
        [pscustomobject]@{ Id = 'RollbackMachineStoreProvision'; Anchor = 'After'; Value = 'InstallInitialize'; Condition = 'NOT Installed' },
        [pscustomobject]@{ Id = 'ProvisionMachineStore'; Anchor = 'After'; Value = 'RollbackMachineStoreProvision'; Condition = 'NOT Installed' },
        [pscustomobject]@{ Id = 'SeedDaemonConfig'; Anchor = 'After'; Value = 'InstallFiles'; Condition = 'NOT Installed' },
        [pscustomobject]@{ Id = 'SeedWorkerConfig'; Anchor = 'After'; Value = 'SeedDaemonConfig'; Condition = 'NOT Installed' },
        [pscustomobject]@{ Id = 'CommitMachineStoreProvision'; Anchor = 'After'; Value = 'StartServices'; Condition = 'NOT Installed' },
        [pscustomobject]@{ Id = 'UninstallMachineStore'; Anchor = 'After'; Value = 'StopServices'; Condition = 'REMOVE~=&quot;ALL&quot; AND NOT UPGRADINGPRODUCTCODE' }
    )
    foreach ($expectation in $scheduleExpectations) {
        $row = @($document.SelectNodes(
            "//w:InstallExecuteSequence/w:Custom[@Action='$($expectation.Id)']", $namespaces))
        if ($row.Count -ne 1) {
            $failures.Add("schedule for $($expectation.Id) must appear exactly once")
            continue
        }
        if ($row[0].GetAttribute($expectation.Anchor) -cne $expectation.Value) {
            $failures.Add("$($expectation.Id) must be $($expectation.Anchor) $($expectation.Value)")
        }
        if ($row[0].GetAttribute('Condition') -cne
            [Net.WebUtility]::HtmlDecode($expectation.Condition)) {
            $failures.Add("$($expectation.Id) condition mismatch")
        }
    }

    $launch = @($document.SelectNodes('//w:Launch', $namespaces))
    if ($launch.Count -ne 1 -or
        $launch[0].GetAttribute('Condition') -cne 'Installed OR NOT WIX_UPGRADE_DETECTED' -or
        $launch[0].GetAttribute('Message') -cne $safeUpgradeMessage) {
        $failures.Add('legacy major upgrades must use the required safe Launch condition and message')
    }

    foreach ($query in @(
        '//w:StandardDirectory[@Id="CommonAppDataFolder"]',
        '//w:Directory[@Id="DataFolder" or @Id="ScratchFolder" or @Id="CasFolder"]',
        '//w:ComponentGroup[@Id="DataDirs"]',
        '//w:ComponentGroupRef[@Id="DataDirs"]',
        '//w:Component[@Id="DataFolderComp" or @Id="ScratchFolderComp" or @Id="CasFolderComp"]',
        '//w:Property[@Id="SBZ_DATADIR"]',
        '//*[local-name()="RegistrySearch"]', '//*[local-name()="CreateFolder"]',
        '//*[local-name()="PermissionEx"]', '//*[local-name()="RemoveFolderEx"]')) {
        $found = @($document.SelectNodes($query, $namespaces))
        if ($found.Count -ne 0) { $failures.Add("legacy ProgramData authoring remains: $query") }
    }
    $externalStoreCtl = @($document.SelectNodes(
        "//w:File[contains(@Source, 'storectl') or contains(@Id, 'StoreCtl')]", $namespaces))
    if ($externalStoreCtl.Count -ne 0) {
        $failures.Add('storectl must remain an embedded Binary stream, not an installed File')
    }

    $projectPath = Join-Path (Split-Path $Path -Parent) 'Package.wixproj'
    [xml]$project = Get-Content -LiteralPath $projectPath -Raw
    $storeCtlProperty = @($project.SelectNodes('//SbzStoreCtl'))
    if ($storeCtlProperty.Count -ne 1 -or
        ($storeCtlProperty.Count -eq 1 -and (
            $storeCtlProperty[0].GetAttribute('Condition') -cne "'`$(SbzStoreCtl)' == ''" -or
            [string]$storeCtlProperty[0].InnerText -cne '$(SbzRustTarget)\sembazuru-storectl.exe'))) {
        $failures.Add('Package.wixproj must default SbzStoreCtl from SbzRustTarget')
    }
    $constantsNode = @($project.SelectNodes('//DefineConstants'))
    $constants = if ($constantsNode.Count -eq 1) { [string]$constantsNode[0].InnerText } else { '' }
    if ($constants -notmatch '(?:^|;)StoreCtl=\$\(SbzStoreCtl\)(?:;|$)') {
        $failures.Add('DefineConstants must export StoreCtl=$(SbzStoreCtl)')
    }
    $rollbackProperty = @($project.SelectNodes('//SbzRollbackFixture'))
    if ($rollbackProperty.Count -ne 1 -or
        ($rollbackProperty.Count -eq 1 -and (
            $rollbackProperty[0].GetAttribute('Condition') -cne
                "'`$(SbzRollbackFixture)' == ''" -or
            [string]$rollbackProperty[0].InnerText -cne '0'))) {
        $failures.Add('Package.wixproj must default SbzRollbackFixture to 0')
    }
    if ($constants -notmatch '(?:^|;)RollbackFixture=\$\(SbzRollbackFixture\)(?:;|$)') {
        $failures.Add('DefineConstants must export RollbackFixture=$(SbzRollbackFixture)')
    }
    $utilReferences = @($project.SelectNodes(
        '//PackageReference[@Include="WixToolset.Util.wixext"]'))
    if ($utilReferences.Count -ne 1 -or
        ($utilReferences.Count -eq 1 -and (
            $utilReferences[0].GetAttribute('Version') -cne '5.0.2' -or
            $utilReferences[0].GetAttribute('Condition') -ne '' -or
            $utilReferences[0].ParentNode.Name -cne 'ItemGroup' -or
            $utilReferences[0].ParentNode.GetAttribute('Condition') -cne
                "'`$(SbzRollbackFixture)' == '1'"))) {
        $failures.Add('WixToolset.Util.wixext must appear exactly once in the SbzRollbackFixture=1 ItemGroup at version 5.0.2')
    }

    if ($failures.Count -ne 0) {
        throw "STATIC LIFECYCLE SOURCE FAIL:`n - $($failures -join "`n - ")"
    }
    Write-Host 'STATIC LIFECYCLE SOURCE PASS: embedded storectl owns fresh/rollback/commit/uninstall; legacy directory authoring is absent.'
}

function Invoke-MsiQuery {
    param(
        [Parameter(Mandatory = $true)]$Database,
        [Parameter(Mandatory = $true)][string]$Sql,
        [Parameter(Mandatory = $true)][int]$Columns
    )

    $view = $Database.GetType().InvokeMember(
        'OpenView', 'InvokeMethod', $null, $Database, @($Sql))
    try {
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        while ($true) {
            $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
            if ($null -eq $record) { break }
            $values = @()
            try {
                for ($index = 1; $index -le $Columns; $index++) {
                    $values += $record.GetType().InvokeMember(
                        'StringData', 'GetProperty', $null, $record, @($index))
                }
            }
            finally {
                [Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) | Out-Null
            }
            ,$values
        }
    }
    finally {
        try { $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null }
        catch { }
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    }
}

function Get-MsiBinaryStreamSize {
    param([Parameter(Mandatory = $true)]$Database, [string]$Name)

    $view = $Database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $Database,
        @("SELECT ``Name``, ``Data`` FROM ``Binary`` WHERE ``Name``='$Name'"))
    $record = $null
    try {
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $record) { return 0 }
        return [int64]$record.GetType().InvokeMember(
            'DataSize', 'GetProperty', $null, $record, @(2))
    }
    finally {
        if ($null -ne $record) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) | Out-Null
        }
        try { $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null }
        catch { }
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    }
}

function Assert-MsiLifecycleTables {
    param([string]$Path)

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null
    try {
        $database = $installer.GetType().InvokeMember(
            'OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
        $failures = [Collections.Generic.List[string]]::new()

        $streamSize = 0L
        $binaryRows = @(Invoke-MsiQuery -Database $database -Columns 1 -Sql `
            'SELECT `Name` FROM `Binary` WHERE `Name`=''MachineStoreCtlBinary''')
        if ($binaryRows.Count -ne 1) {
            $failures.Add("Binary.MachineStoreCtlBinary row count must be 1; got $($binaryRows.Count)")
        } else {
            $streamSize = Get-MsiBinaryStreamSize -Database $database `
                -Name 'MachineStoreCtlBinary'
            if ($streamSize -le 0) {
                $failures.Add("embedded storectl Binary stream must be nonempty; size=$streamSize")
            }
        }

        $actionExpectations = @(
            [pscustomobject]@{ Id = 'ProvisionMachineStore'; Type = '3074'; Source = 'MachineStoreCtlBinary'; Target = 'provision' },
            [pscustomobject]@{ Id = 'UninstallMachineStore'; Type = '3074'; Source = 'MachineStoreCtlBinary'; Target = 'uninstall' },
            [pscustomobject]@{ Id = 'RollbackMachineStoreProvision'; Type = '3330'; Source = 'MachineStoreCtlBinary'; Target = 'rollback-provision' },
            [pscustomobject]@{ Id = 'CommitMachineStoreProvision'; Type = '3586'; Source = 'MachineStoreCtlBinary'; Target = 'commit-provision' },
            [pscustomobject]@{ Id = 'SeedDaemonConfig'; Type = '3090'; Source = 'DaemonExeFile'; Target = 'seed-config' },
            [pscustomobject]@{ Id = 'SeedWorkerConfig'; Type = '3090'; Source = 'WorkerExeFile'; Target = 'seed-config' }
        )
        foreach ($expectation in $actionExpectations) {
            $rows = @(Invoke-MsiQuery -Database $database -Columns 4 -Sql `
                "SELECT ``Action``, ``Type``, ``Source``, ``Target`` FROM ``CustomAction`` WHERE ``Action``='$($expectation.Id)'")
            if ($rows.Count -ne 1) {
                $failures.Add("CustomAction $($expectation.Id) row count must be 1; got $($rows.Count)")
                continue
            }
            $row = $rows[0]
            if ([string]$row[1] -cne $expectation.Type -or
                [string]$row[2] -cne $expectation.Source -or
                [string]$row[3] -cne $expectation.Target) {
                $failures.Add("CustomAction $($expectation.Id) mismatch: Type=$($row[1]) Source=$($row[2]) Target=$($row[3])")
            }
            if (([int]$row[1] -band 64) -ne 0) {
                $failures.Add("CustomAction $($expectation.Id) has forbidden Continue bit")
            }
        }

        $sequenceRows = @(Invoke-MsiQuery -Database $database -Columns 3 -Sql `
            'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`')
        $sequence = @{}
        $conditions = @{}
        foreach ($row in $sequenceRows) {
            $sequence[[string]$row[0]] = [int]$row[2]
            $conditions[[string]$row[0]] = [string]$row[1]
        }
        foreach ($name in @(
            'InstallInitialize', 'RollbackMachineStoreProvision', 'ProvisionMachineStore',
            'ProcessComponents', 'InstallFiles', 'SeedDaemonConfig', 'SeedWorkerConfig',
            'InstallServices', 'StartServices', 'CommitMachineStoreProvision', 'InstallFinalize',
            'StopServices', 'UninstallMachineStore', 'DeleteServices',
            'FindRelatedProducts', 'LaunchConditions', 'RemoveExistingProducts')) {
            if (-not $sequence.ContainsKey($name)) { $failures.Add("InstallExecuteSequence row missing: $name") }
        }
        foreach ($pair in @(
            @('InstallInitialize', 'RollbackMachineStoreProvision'),
            @('RollbackMachineStoreProvision', 'ProvisionMachineStore'),
            @('ProvisionMachineStore', 'ProcessComponents'),
            @('ProcessComponents', 'InstallFiles'),
            @('InstallFiles', 'SeedDaemonConfig'),
            @('SeedDaemonConfig', 'SeedWorkerConfig'),
            @('SeedWorkerConfig', 'InstallServices'),
            @('InstallServices', 'StartServices'),
            @('StartServices', 'CommitMachineStoreProvision'),
            @('CommitMachineStoreProvision', 'InstallFinalize'),
            @('StopServices', 'UninstallMachineStore'),
            @('UninstallMachineStore', 'DeleteServices'),
            @('FindRelatedProducts', 'LaunchConditions'),
            @('LaunchConditions', 'RemoveExistingProducts'))) {
            if ($sequence.ContainsKey($pair[0]) -and $sequence.ContainsKey($pair[1]) -and
                $sequence[$pair[0]] -ge $sequence[$pair[1]]) {
                $failures.Add("sequence order violated: $($pair[0])=$($sequence[$pair[0]]) !< $($pair[1])=$($sequence[$pair[1]])")
            }
        }
        foreach ($name in @(
            'RollbackMachineStoreProvision', 'ProvisionMachineStore', 'SeedDaemonConfig',
            'SeedWorkerConfig', 'CommitMachineStoreProvision')) {
            if ($conditions[$name] -cne 'NOT Installed') {
                $failures.Add("$name condition must be NOT Installed; got '$($conditions[$name])'")
            }
        }
        if ($conditions['UninstallMachineStore'] -cne
            'REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE') {
            $failures.Add("UninstallMachineStore condition mismatch: '$($conditions['UninstallMachineStore'])'")
        }

        $launchRows = @(Invoke-MsiQuery -Database $database -Columns 2 -Sql `
            'SELECT `Condition`, `Description` FROM `LaunchCondition`')
        if (@($launchRows | Where-Object {
                $_[0] -ceq 'Installed OR NOT WIX_UPGRADE_DETECTED' -and
                $_[1] -ceq $safeUpgradeMessage }).Count -ne 1) {
            $failures.Add('required legacy-upgrade LaunchCondition/Description row is missing')
        }

        $legacyPropertyRows = @(Invoke-MsiQuery -Database $database -Columns 1 -Sql `
            'SELECT `Property` FROM `Property` WHERE `Property`=''SBZ_DATADIR''')
        if ($legacyPropertyRows.Count -ne 0) {
            $failures.Add('legacy Property.SBZ_DATADIR row remains')
        }

        $allActionRows = @(Invoke-MsiQuery -Database $database -Columns 1 -Sql `
            'SELECT `Action` FROM `CustomAction`')
        $legacyActionRows = @($allActionRows | Where-Object {
            [string]$_[0] -match '(?i)RemoveFoldersEx|MsiLockPermissionsEx'
        })
        if ($legacyActionRows.Count -ne 0) {
            $failures.Add("legacy directory custom action row(s) remain: $(@($legacyActionRows | ForEach-Object { $_[0] }) -join ', ')")
        }

        foreach ($legacy in @(
            [pscustomobject]@{ Table = 'Directory'; Column = 'Directory'; Values = @('DataFolder', 'ScratchFolder', 'CasFolder') },
            [pscustomobject]@{ Table = 'Component'; Column = 'Component'; Values = @('DataFolderComp', 'ScratchFolderComp', 'CasFolderComp') },
            [pscustomobject]@{ Table = 'CustomAction'; Column = 'Action'; Values = @('WixRemoveFoldersEx', 'MsiLockPermissionsEx') },
            [pscustomobject]@{ Table = 'File'; Column = 'File'; Values = @('MachineStoreCtlBinary', 'StoreCtlExeFile') })) {
            foreach ($value in $legacy.Values) {
                $rows = @(Invoke-MsiQuery -Database $database -Columns 1 -Sql `
                    "SELECT ``$($legacy.Column)`` FROM ``$($legacy.Table)`` WHERE ``$($legacy.Column)``='$value'")
                if ($rows.Count -ne 0) {
                    $failures.Add("legacy/external row remains: $($legacy.Table).$($legacy.Column)=$value")
                }
            }
        }
        $fileRows = @(Invoke-MsiQuery -Database $database -Columns 2 -Sql `
            'SELECT `File`, `FileName` FROM `File`')
        foreach ($row in $fileRows) {
            if ([string]$row[0] -match '(?i)storectl' -or
                [string]$row[1] -match '(?i)storectl') {
                $failures.Add("storectl escaped into File table: File=$($row[0]) FileName=$($row[1])")
            }
        }

        if ($failures.Count -ne 0) {
            throw "MSI LIFECYCLE TABLE FAIL:`n - $($failures -join "`n - ")"
        }
        Write-Host "MSI LIFECYCLE TABLE PASS: embedded stream=$streamSize bytes, exact checked CA types, fresh/repair/uninstall sequencing, and upgrade block verified."
    }
    finally {
        if ($null -ne $database) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
        }
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
    }
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
        [int64]$DaemonMask = -1,
        [bool]$RequireContainerInheritance,
        [string]$ExpectedOwnerSid = '',
        [string]$ExpectedGroupSid = ''
    )

    $acl = Get-Acl -LiteralPath $Path
    if ($ExpectedOwnerSid) {
        $ownerSid = ([Security.Principal.NTAccount]$acl.Owner).Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($ownerSid -ne $ExpectedOwnerSid) {
            throw "ACL owner mismatch for ${Path}: got $ownerSid, want $ExpectedOwnerSid"
        }
    }
    if ($ExpectedGroupSid) {
        $groupSid = ([Security.Principal.NTAccount]$acl.Group).Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($groupSid -ne $ExpectedGroupSid) {
            throw "ACL group mismatch for ${Path}: got $groupSid, want $ExpectedGroupSid"
        }
    }
    if ($acl.AreAccessRulesProtected -ne $ExpectedProtected) {
        throw "ACL protection mismatch for ${Path}: got $($acl.AreAccessRulesProtected), want $ExpectedProtected"
    }
    $expectedMasks = @{
        'S-1-5-18' = [int64]0x1f01ff
        'S-1-5-32-544' = [int64]0x1f01ff
        $workerSid = $WorkerMask
    }
    if ($DaemonMask -ge 0) {
        $expectedMasks[$daemonSid] = $DaemonMask
    }
    $rules = @($acl.Access)
    if ($rules.Count -ne $expectedMasks.Count) {
        throw "ACL rule count mismatch for ${Path}: got $($rules.Count), want $($expectedMasks.Count)"
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
        $ruleExpectedInheritance = $expectedInheritance
        if ($sid -eq $daemonSid) {
            $ruleExpectedInheritance = [Security.AccessControl.InheritanceFlags]::None
        }
        if ($rule.InheritanceFlags -ne $ruleExpectedInheritance) {
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
    foreach ($expectation in @(
        [pscustomobject]@{ Name = 'SembazuruDaemon'; Sid = $daemonSid },
        [pscustomobject]@{ Name = 'SembazuruWorker'; Sid = $workerSid }
    )) {
        $output = & sc.exe showsid $expectation.Name 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "sc.exe showsid $($expectation.Name) failed ($LASTEXITCODE): $output"
        }
        $reported = @([regex]::Matches($output, 'S-1-5-80-(?:\d+-){4}\d+') |
            ForEach-Object { $_.Value } | Sort-Object -Unique)
        if ($reported.Count -ne 1 -or $reported[0] -ne $expectation.Sid) {
            throw "$($expectation.Name) service SID drift: embedded=$($expectation.Sid) sc.exe=$($reported -join ',') output=$output"
        }
        Write-Host "SERVICE SID PASS: $($expectation.Name) embedded SDDL SID matches sc.exe showsid: $($expectation.Sid)"
    }
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

function Stop-ServicesForOfflineTokenMaintenance {
    foreach ($name in @('SembazuruWorker', 'SembazuruDaemon')) {
        $service = Get-Service -Name $name -ErrorAction Stop
        if ($service.Status -ne 'Stopped') {
            Stop-Service -Name $name -ErrorAction Stop
            $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            $service.Refresh()
        }
        if ($service.Status -ne 'Stopped') {
            throw "$name did not reach Stopped for offline token maintenance: $($service.Status)"
        }
        Write-Host "SERVICE STOPPED: $name for offline token maintenance"
    }
}

function Initialize-TestOnlyClusterToken {
    param([string]$StoreCtl)

    $offlineMaintenanceStarted = $false
    $childReaped = $true
    $rotationFailure = $null
    $restartFailures = [Collections.Generic.List[string]]::new()
    try {
        $offlineMaintenanceStarted = $true
        Stop-ServicesForOfflineTokenMaintenance
        $token = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
        if ($token.Length -ne 64 -or $token -notmatch '\A[0-9a-f]{64}\z') {
            throw 'test-only cluster token generation did not produce the required opaque shape'
        }
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $process = $null
        $processStarted = $false
        $stdin = $null
        $stdoutReader = $null
        $stderrReader = $null
        $processFailure = $null
        $processCleanupFailures = [Collections.Generic.List[string]]::new()
        try {
            $startInfo.FileName = $StoreCtl
            [void]$startInfo.ArgumentList.Add('rotate-token')
            $startInfo.UseShellExecute = $false
            $startInfo.RedirectStandardInput = $true
            $startInfo.RedirectStandardOutput = $true
            $startInfo.RedirectStandardError = $true
            $startInfo.CreateNoWindow = $true

            $process = [System.Diagnostics.Process]::new()
            $process.StartInfo = $startInfo
            $processStarted = $process.Start()
            if (-not $processStarted) {
                throw 'test-only cluster token setup could not start rotate-token'
            }
            $childReaped = $false
            $stdin = $process.StandardInput
            $stdoutReader = $process.StandardOutput
            $stderrReader = $process.StandardError
            $stdoutTask = $stdoutReader.ReadToEndAsync()
            $stderrTask = $stderrReader.ReadToEndAsync()
            try {
                $stdin.WriteLine($token)
            }
            finally {
                $stdin.Close()
            }
            $timedOut = -not $process.WaitForExit(30000)
            $childReaped = -not $timedOut
            if ($timedOut) {
                $process.Kill($true)
                $childReaped = $process.WaitForExit(5000)
                if (-not $childReaped) {
                    throw 'test-only cluster token setup timed out and child was not reaped within 5 seconds'
                }
            }
            [string]$stdout = $stdoutTask.GetAwaiter().GetResult()
            [string]$stderr = $stderrTask.GetAwaiter().GetResult()
            $exitCode = $process.ExitCode
            if ($timedOut) {
                throw 'test-only cluster token setup timed out after 30 seconds'
            }
            if ($exitCode -ne 0 -or $stdout -cnotmatch '\Atoken-rotated(?:\r?\n)?\z' -or
                $stderr -cne '') {
                $diagnostic = [regex]::Match(
                    $stderr,
                    '\Asembazuru-storectl: backend operation=(?<operation>[A-Za-z0-9-]+); context=(?<context>[A-Za-z0-9 -]+); raw-os-error=(?<raw>none|-?[0-9]+)\r?\nsembazuru-storectl: token-io-failed\r?\n\z')
                if (-not $diagnostic.Success -or $exitCode -ne 11 -or $stdout -cne '') {
                    throw 'test-only cluster token setup backend diagnostic missing or malformed'
                }
                throw "test-only cluster token setup failed: backend-operation=$($diagnostic.Groups['operation'].Value) context=$($diagnostic.Groups['context'].Value) raw-os-error=$($diagnostic.Groups['raw'].Value)"
            }
        }
        catch {
            $processFailure = $_
        }
        finally {
            if ($processStarted -and -not $childReaped) {
                $hasExited = $false
                try { $hasExited = $process.HasExited }
                catch { $processCleanupFailures.Add("process-state:$($_.Exception.GetType().Name)") }
                try {
                    if (-not $hasExited) { $process.Kill($true) }
                }
                catch {
                    $processCleanupFailures.Add("process-kill:$($_.Exception.GetType().Name)")
                }
                try { $childReaped = $process.WaitForExit(5000) }
                catch { $processCleanupFailures.Add("process-reap:$($_.Exception.GetType().Name)") }
                if (-not $childReaped) { $processCleanupFailures.Add('child-not-reaped') }
            }
            foreach ($stream in @($stdin, $stdoutReader, $stderrReader)) {
                if ($null -eq $stream) { continue }
                try { $stream.Dispose() }
                catch { $processCleanupFailures.Add("stream:$($_.Exception.GetType().Name)") }
            }
            if ($null -ne $process) {
                try { $process.Dispose() }
                catch { $processCleanupFailures.Add("process-dispose:$($_.Exception.GetType().Name)") }
            }
        }

        if ($null -ne $processFailure) {
            if ($processCleanupFailures.Count -ne 0) {
                throw [Exception]::new(
                    "$($processFailure.Exception.Message); process cleanup failed: $($processCleanupFailures -join ',')",
                    $processFailure.Exception)
            }
            throw $processFailure
        }
        if ($processCleanupFailures.Count -ne 0) {
            throw "test-only cluster token process cleanup failed: $($processCleanupFailures -join ',')"
        }
    }
    catch {
        $rotationFailure = $_
    }
    finally {
        if ($offlineMaintenanceStarted) {
            if (-not $childReaped) {
                $restartFailures.Add('service-restart-skipped:child-not-reaped')
            } else {
                foreach ($name in @('SembazuruDaemon', 'SembazuruWorker')) {
                    try { Start-Service -Name $name -ErrorAction Stop }
                    catch { $restartFailures.Add("${name}:$($_.Exception.GetType().Name)") }
                }
            }
        }
    }

    if ($null -ne $rotationFailure) {
        if ($restartFailures.Count -ne 0) {
            throw [Exception]::new(
                "$($rotationFailure.Exception.Message); service restart failed: $($restartFailures -join ',')",
                $rotationFailure.Exception)
        }
        throw $rotationFailure
    }
    if ($restartFailures.Count -ne 0) {
        throw "test-only cluster token service restart failed: $($restartFailures -join ',')"
    }
    Assert-ServicesRunning
    Wait-ForWorkerExecutionEndpoint
    Write-Host 'TEST-ONLY CLUSTER TOKEN PASS: offline DPAPI token rotation completed without exposing token material.'
}

function Assert-ClusterTokenSecret {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "cluster token DPAPI blob is missing: $Path"
    }
    Assert-ExactAclRules -Path $Path -ExpectedProtected $true -ExpectedInherited $false `
        -WorkerMask 0x1200a9 -DaemonMask 0x1200a9 -RequireContainerInheritance $false `
        -ExpectedOwnerSid 'S-1-5-18' -ExpectedGroupSid 'S-1-5-18'
    Write-Host 'CLUSTER TOKEN ACL PASS: cluster-token.dpapi is SYSTEM-owned with the protected machine-secret DACL.'
}

function Assert-OfflineTokenSetupSource {
    param([string]$Path)

    $source = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ($source -match '\$token\s*\|\s*&\s*\$StoreCtl\s+rotate-token' -or
        $source -notmatch '\[System\.Diagnostics\.ProcessStartInfo\]::new\(\)' -or
        $source -notmatch '\$startInfo\.ArgumentList\.Add\(''rotate-token''\)' -or
        $source -notmatch '\$startInfo\.UseShellExecute\s*=\s*\$false' -or
        $source -notmatch '\$startInfo\.RedirectStandardInput\s*=\s*\$true' -or
        $source -notmatch '\$startInfo\.RedirectStandardOutput\s*=\s*\$true' -or
        $source -notmatch '\$startInfo\.RedirectStandardError\s*=\s*\$true' -or
        $source -notmatch '\$startInfo\.CreateNoWindow\s*=\s*\$true' -or
        $source -notmatch '\$stdin\.WriteLine\(\$token\)' -or
        $source -notmatch '\$stdin\.Close\(\)') {
        throw 'offline token setup must provide the token only through rotate-token stdin'
    }
    $unsafeTokenLines = @($source -split "`r?`n" | Where-Object {
        $_ -match '(?<!\\)\$token\b' -and $_ -match '(?:Write-(?:Host|Output|Warning|Error)|throw|Arguments?|Set-Content|Add-Content|Out-File|\$env:|Set-Item\s+(?:-Path\s+)?Env:|SetEnvironmentVariable)'
    })
    if ($unsafeTokenLines.Count -ne 0) {
        throw 'offline token setup source exposes token material through output, argv, or a plain-text file sink'
    }
    if ($source -notmatch [regex]::Escape('backend operation=') -or
        $source -notmatch [regex]::Escape('raw-os-error=') -or
        $source -notmatch [regex]::Escape('backend diagnostic missing or malformed')) {
        throw 'offline token setup must strictly parse the fixed backend diagnostic without exposing stderr'
    }
    Write-Host 'STATIC TOKEN SETUP PASS: rotate-token uses redirected stdin and has no token output, argv, or plain-text sink.'
}

function Get-ServiceStatusSummary {
    $summaries = foreach ($name in @('SembazuruDaemon', 'SembazuruWorker')) {
        try {
            $service = Get-Service -Name $name -ErrorAction Stop
            $cim = Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
            "${name}:status=$($service.Status),account=$($cim.StartName),pid=$($cim.ProcessId)"
        }
        catch {
            "${name}:unavailable=$($_.Exception.Message)"
        }
    }
    return ($summaries -join '; ')
}

function Wait-ForWorkerExecutionEndpoint {
    param([int]$TimeoutSeconds = 30)

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $lastError = 'no connection attempt completed'
    while ([DateTime]::UtcNow -lt $deadline) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $connect = $client.ConnectAsync('127.0.0.1', 50061)
            if ($connect.Wait(1000) -and $client.Connected) {
                Write-Host "WORKER ENDPOINT READY: 127.0.0.1:50061; $(Get-ServiceStatusSummary)"
                return
            }
            $lastError = 'connection attempt timed out'
        }
        catch {
            $lastError = $_.Exception.Message
        }
        finally {
            $client.Dispose()
        }
        Start-Sleep -Milliseconds 250
    }
    throw "worker endpoint 127.0.0.1:50061 did not become ready in ${TimeoutSeconds}s; services=$(Get-ServiceStatusSummary); last=$lastError"
}

function Get-InstalledWorkerIdentity {
    $computer = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($computer)) {
        throw 'COMPUTERNAME is unavailable for the installed worker identity'
    }
    $worker = Get-CimInstance Win32_Service -Filter "Name='SembazuruWorker'" `
        -ErrorAction Stop
    if ($worker.State -ne 'Running' -or [uint32]$worker.ProcessId -eq 0) {
        throw "SembazuruWorker has no live process identity: state=$($worker.State) pid=$($worker.ProcessId)"
    }
    return "${computer}#$($worker.ProcessId)"
}

function Test-ExecVfsReachedRunningAndCompleted {
    param([string]$Output)

    return $Output -match 'exec_vfs:\s*states=\[[^\]]*\b3\b[^\]]*\b4\b[^\]]*\]\s*exit='
}

function ConvertTo-SafeEventBasename {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $candidate = [IO.Path]::GetFileName($Value.Trim())
    if ($candidate -notmatch '\A[A-Za-z0-9][A-Za-z0-9._ -]{0,127}\.(?:exe|dll|sys)\z') {
        return $null
    }
    return $candidate
}

function ConvertTo-SafeHexCode {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()
    if ($trimmed -match '\A0x([0-9A-Fa-f]{1,8})\z') {
        return "0x$($Matches[1].ToUpperInvariant())"
    }
    if ($trimmed -match '\A([0-9A-Fa-f]{8})\z') {
        return "0x$($Matches[1].ToUpperInvariant())"
    }
    return $null
}

function ConvertTo-SafeUInt32 {
    param([AllowNull()][string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $trimmed = $Value.Trim()
    [uint64]$parsed = 0
    if ($trimmed -match '\A0x([0-9A-Fa-f]{1,8})\z') {
        if (-not [uint64]::TryParse($Matches[1], [Globalization.NumberStyles]::AllowHexSpecifier,
                [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)) {
            return $null
        }
    }
    elseif (-not [uint64]::TryParse($trimmed, [ref]$parsed)) {
        return $null
    }
    if ($parsed -gt [uint32]::MaxValue) { return $null }
    return [uint32]$parsed
}

function Get-NamedEventDataValue {
    param(
        [xml]$Document,
        [string[]]$Names
    )

    foreach ($data in @($Document.Event.EventData.Data)) {
        if ($Names -contains [string]$data.Name) {
            return [string]$data.InnerText
        }
    }
    return $null
}

function Format-InstalledWorkerApplicationEvent {
    param(
        [string]$Provider,
        [int]$Id,
        [AllowNull()][long]$RecordId,
        [datetime]$TimeCreated,
        [string]$Xml
    )

    if (($Provider -cne 'Application Error' -or $Id -ne 1000) -and
        ($Provider -cne 'Windows Error Reporting' -or $Id -ne 1001) -and
        ($Provider -cne 'SideBySide' -or $Id -notin @(33, 59))) {
        return $null
    }
    $time = $TimeCreated.ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    if ($Provider -ceq 'SideBySide') {
        return "provider=$Provider id=$Id time=$time"
    }
    try { [xml]$document = $Xml }
    catch { return $null }

    $systemPid = ConvertTo-SafeUInt32 -Value ([string]$document.Event.System.Execution.ProcessID)
    if ($Provider -ceq 'Application Error') {
        $app = ConvertTo-SafeEventBasename -Value (Get-NamedEventDataValue -Document $document `
            -Names @('AppPath', 'FaultingApplicationPath'))
        $module = ConvertTo-SafeEventBasename -Value (Get-NamedEventDataValue -Document $document `
            -Names @('ModulePath', 'FaultingModulePath'))
        $code = ConvertTo-SafeHexCode -Value (Get-NamedEventDataValue -Document $document `
            -Names @('ExceptionCode'))
        $eventPid = ConvertTo-SafeUInt32 -Value (Get-NamedEventDataValue -Document $document `
            -Names @('ProcessId'))
        if ($null -eq $eventPid) { $eventPid = $systemPid }
    }
    else {
        # WER 1001 problem-signature mapping: P1=application, P4=module,
        # P7=exception code. Other P fields and attached files are never emitted.
        $app = ConvertTo-SafeEventBasename -Value (Get-NamedEventDataValue -Document $document -Names @('P1'))
        $module = ConvertTo-SafeEventBasename -Value (Get-NamedEventDataValue -Document $document -Names @('P4'))
        $code = ConvertTo-SafeHexCode -Value (Get-NamedEventDataValue -Document $document -Names @('P7'))
        $eventPid = $systemPid
    }

    $fields = [Collections.Generic.List[string]]::new()
    $fields.Add("provider=$Provider")
    $fields.Add("id=$Id")
    $fields.Add("record=$RecordId")
    $fields.Add("time=$time")
    if ($null -ne $app) { $fields.Add("app=$app") }
    if ($null -ne $module) { $fields.Add("module=$module") }
    if ($null -ne $code) { $fields.Add("code=$code") }
    if ($null -ne $eventPid) { $fields.Add("pid=$eventPid") }
    return ($fields -join ' ')
}

function Assert-InstalledWorkerEventFormatter {
    $sentinel = 'SENTINEL-MUST-NOT-LEAK-7d1c'
    $xml = @"
<Event><System><Execution ProcessID="1234" /></System><EventData>
<Data Name="AppPath">C:\Windows\System32\cmd.exe</Data>
<Data Name="ModulePath">C:\Windows\System32\kernel32.dll</Data>
<Data Name="ExceptionCode">c0000142</Data>
<Data Name="Secret">$sentinel</Data>
</EventData></Event>
"@
    $formatted = Format-InstalledWorkerApplicationEvent -Provider 'Application Error' -Id 1000 `
        -RecordId 9 -TimeCreated ([datetime]'2026-07-18T00:00:00Z') -Xml $xml
    foreach ($field in @('provider=Application Error', 'id=1000', 'record=9',
            'time=2026-07-18T00:00:00.0000000Z', 'app=cmd.exe', 'module=kernel32.dll',
            'code=0xC0000142', 'pid=1234')) {
        if ($formatted -notmatch [regex]::Escape($field)) {
            throw "installed worker event formatter omitted expected field: $field"
        }
    }
    if ($formatted -match [regex]::Escape($sentinel)) {
        throw 'installed worker event formatter leaked a non-allowlisted EventData value'
    }
    $sideBySide = Format-InstalledWorkerApplicationEvent -Provider 'SideBySide' -Id 33 `
        -RecordId 9 -TimeCreated ([datetime]'2026-07-18T00:00:00Z') -Xml $xml
    if ($sideBySide -cne 'provider=SideBySide id=33 time=2026-07-18T00:00:00.0000000Z') {
        throw 'installed worker SideBySide formatter emitted data beyond provider/id/time'
    }
    $werXml = @"
<Event><System><Execution ProcessID="4321" /></System><EventData>
<Data Name="P1">cmd.exe</Data><Data Name="P4">kernel32.dll</Data>
<Data Name="P7">0xc0000142</Data><Data Name="P8">$sentinel</Data>
</EventData></Event>
"@
    $wer = Format-InstalledWorkerApplicationEvent -Provider 'Windows Error Reporting' -Id 1001 `
        -RecordId 10 -TimeCreated ([datetime]'2026-07-18T00:00:00Z') -Xml $werXml
    foreach ($field in @('app=cmd.exe', 'module=kernel32.dll', 'code=0xC0000142', 'pid=4321')) {
        if ($wer -notmatch [regex]::Escape($field)) {
            throw "installed worker WER formatter omitted fixed P mapping field: $field"
        }
    }
    if ($wer -match [regex]::Escape($sentinel)) {
        throw 'installed worker WER formatter leaked a non-allowlisted P field'
    }
    Write-Host 'STATIC INSTALLED WORKER EVENT FORMATTER PASS: allowlisted fields render and sentinel EventData does not leak.'
}

function Write-InstalledWorkerApplicationDiagnostics {
    param(
        [string]$Output,
        [int]$ExitCode,
        [datetime]$StartedUtc,
        [datetime]$EndedUtc
    )

    if ($ExitCode -eq 0 -or -not (Test-ExecVfsReachedRunningAndCompleted -Output $Output)) {
        return
    }
    $start = $StartedUtc.AddSeconds(-2).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $end = $EndedUtc.AddSeconds(2).ToUniversalTime().ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    $filterXPath = "*[System[TimeCreated[@SystemTime >= '$start' and @SystemTime <= '$end'] and ((Provider[@Name='Application Error'] and EventID=1000) or (Provider[@Name='Windows Error Reporting'] and EventID=1001) or (Provider[@Name='SideBySide'] and (EventID=33 or EventID=59)))]]"
    $events = @()
    for ($query = 1; $query -le 2; $query++) {
        try {
            $events = @(Get-WinEvent -LogName Application -FilterXPath $filterXPath `
                -MaxEvents 8 -ErrorAction Stop)
        }
        catch [UnauthorizedAccessException] {
            Write-Host 'INSTALLED WORKER INJECTED EVENT DIAGNOSTIC: unavailable=access-denied'
            return
        }
        catch {
            Write-Host 'INSTALLED WORKER INJECTED EVENT DIAGNOSTIC: unavailable=query-failed'
            return
        }
        if ($events.Count -ne 0 -or $query -eq 2) { break }
        Start-Sleep -Milliseconds 250
    }
    $reported = 0
    foreach ($event in $events) {
        try {
            $line = Format-InstalledWorkerApplicationEvent -Provider ([string]$event.ProviderName) `
                -Id ([int]$event.Id) -RecordId ([long]$event.RecordId) `
                -TimeCreated ([datetime]$event.TimeCreated) -Xml $event.ToXml()
            if ($null -ne $line) {
                Write-Host "INSTALLED WORKER INJECTED EVENT DIAGNOSTIC: $line"
                $reported++
            }
        }
        catch {
            # A malformed event is diagnostic-only and must not replace the action failure.
        }
    }
    if ($reported -eq 0) {
        Write-Host 'INSTALLED WORKER INJECTED EVENT DIAGNOSTIC: no-allowlisted-event'
    }
}

function Test-ExecVfsExpectedStates {
    param([string]$Output)

    return $Output -match 'exec_vfs:\s*states=\[\s*1\s*,\s*2\s*,\s*3\s*,\s*4\s*\]\s*exit='
}

function Test-ExecVfsIdentityChanged {
    param(
        [int]$ExitCode,
        [string]$Output
    )

    return $ExitCode -eq 86 -and $Output.Contains(
        'exec_vfs: worker identity changed before action admission')
}

function Invoke-InstalledWorkerVfsGate {
    param(
        [string]$Driver,
        [string]$RepoRoot,
        [string]$ScratchRoot,
        [string]$Tag
    )

    $traceDestination = Join-Path $ScratchRoot "m9-installed-vfs-trace-$Tag"
    $whereExe = Join-Path ([Environment]::SystemDirectory) 'where.exe'
    $cmdExe = Join-Path ([Environment]::SystemDirectory) 'cmd.exe'
    if (-not (Test-Path -LiteralPath $whereExe -PathType Leaf) -or
        -not (Test-Path -LiteralPath $cmdExe -PathType Leaf)) {
        throw "System32 VFS probe command is missing: where=$whereExe cmd=$cmdExe"
    }

    $plainOutput = ''
    $plainExitCode = $null
    $output = ''
    $exitCode = $null
    $gateError = $null
    try {
        New-Item -ItemType Directory -Path $traceDestination -ErrorAction Stop | Out-Null
        $hadNativePreference = Test-Path Variable:\PSNativeCommandUseErrorActionPreference
        if ($hadNativePreference) {
            $oldNativePreference = $PSNativeCommandUseErrorActionPreference
            $PSNativeCommandUseErrorActionPreference = $false
        }
        Push-Location $RepoRoot
        try {
            for ($attempt = 1; $attempt -le 2; $attempt++) {
                # Read immediately before launching the driver: default_worker_id is
                # COMPUTERNAME#PID, and a service restart invalidates the capability.
                # The plain control and injected action deliberately share this one identity.
                $workerId = Get-InstalledWorkerIdentity
                $plainOutput = & $Driver 'http://127.0.0.1:50061' '127.0.0.1:50072' `
                    $RepoRoot $traceDestination --no-vfs --worker-id $workerId -- $cmdExe /d /c `
                    'exit 0' 2>&1 | Out-String
                $plainExitCode = $LASTEXITCODE
                if (Test-ExecVfsIdentityChanged -ExitCode $plainExitCode -Output $plainOutput) {
                    if ($attempt -eq 1) {
                        Write-Host 'INSTALLED WORKER ACTION PAIR RETRY: service PID changed before plain control admission; refreshing identity once.'
                        continue
                    }
                    throw "installed worker plain control identity changed twice: stdout/stderr=$plainOutput"
                }

                $plainTraceFiles = @(Get-ChildItem -LiteralPath $traceDestination -Filter '*.sbzt' `
                    -File -ErrorAction Stop)
                if ($plainExitCode -ne 0 -or -not (Test-ExecVfsExpectedStates -Output $plainOutput) -or
                    $plainTraceFiles.Count -ne 0) {
                    throw "installed worker plain control failed: exit=$plainExitCode states-ok=$(Test-ExecVfsExpectedStates -Output $plainOutput) traces=$($plainTraceFiles.Count) stdout/stderr=$plainOutput"
                }

                $injectedStartedUtc = [DateTime]::UtcNow
                $output = & $Driver 'http://127.0.0.1:50061' '127.0.0.1:50072' `
                    $RepoRoot $traceDestination --worker-id $workerId -- $whereExe /R `
                    ([Environment]::SystemDirectory) 'cmd.exe' 2>&1 | Out-String
                $exitCode = $LASTEXITCODE
                $injectedEndedUtc = [DateTime]::UtcNow
                if (Test-ExecVfsIdentityChanged -ExitCode $exitCode -Output $output) {
                    if ($attempt -eq 1) {
                        Write-Host 'INSTALLED WORKER ACTION PAIR RETRY: service PID changed before VFS admission; rerunning plain control and injected action once.'
                        continue
                    }
                    throw "installed worker VFS action identity changed twice: stdout/stderr=$output"
                }
                if ($exitCode -ne 0) {
                    Write-InstalledWorkerApplicationDiagnostics -Output $output -ExitCode $exitCode `
                        -StartedUtc $injectedStartedUtc -EndedUtc $injectedEndedUtc
                }
                break
            }
        }
        finally {
            Pop-Location
            if ($hadNativePreference) {
                $PSNativeCommandUseErrorActionPreference = $oldNativePreference
            }
        }

        $traceFiles = @(Get-ChildItem -LiteralPath $traceDestination -Filter '*.sbzt' `
            -File -ErrorAction Stop)
        $services = Get-ServiceStatusSummary
        if ($exitCode -ne 0 -or $traceFiles.Count -eq 0) {
            throw "installed worker VFS action failed: exit=$exitCode traces=$($traceFiles.Count) services=$services stdout/stderr=$output"
        }
        Write-Host "INSTALLED WORKER PLAIN CONTROL PASS: restricted non-VFS action exit=$plainExitCode states=[1,2,3,4] traces=0 worker=$workerId"
        Write-Host "INSTALLED WORKER VFS PASS: restricted VFS action through staged launcher/DLL exit=$exitCode traces=$($traceFiles.Count)"
        Write-Host "INSTALLED WORKER VFS COMMAND: $whereExe /R $([Environment]::SystemDirectory) cmd.exe"
        Write-Host "INSTALLED WORKER VFS SERVICES: $services"
        Write-Host "INSTALLED WORKER VFS STDOUT/STDERR: $($output.Trim())"
    }
    catch {
        $gateError = $_
    }

    $cleanupError = $null
    if (Test-Path -LiteralPath $traceDestination) {
        try {
            Remove-Item -LiteralPath $traceDestination -Recurse -Force -ErrorAction Stop
        }
        catch {
            $cleanupError = $_
        }
    }
    if ($null -ne $gateError) {
        if ($null -ne $cleanupError) {
            throw "installed worker VFS gate failed: $($gateError.Exception.Message); trace cleanup also failed: $($cleanupError.Exception.Message)"
        }
        throw $gateError
    }
    if ($null -ne $cleanupError) {
        throw "installed worker VFS trace cleanup failed: $($cleanupError.Exception.Message)"
    }
}

function Get-StoreSnapshot {
    param([string]$DataRoot)

    $items = [Collections.Generic.List[object]]::new()
    foreach ($path in @($DataRoot, (Join-Path $DataRoot 'scratch'), (Join-Path $DataRoot 'cas'))) {
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        $items.Add([ordered]@{
            RelativePath = $item.FullName.Substring($DataRoot.Length).TrimStart('\')
            Kind = 'Directory'
            Sddl = (Get-Acl -LiteralPath $item.FullName).Sddl
        })
    }
    foreach ($item in @(Get-ChildItem -LiteralPath $DataRoot -Force -Recurse -ErrorAction Stop |
            Sort-Object FullName)) {
        $relative = $item.FullName.Substring($DataRoot.Length).TrimStart('\')
        if ($item.PSIsContainer) {
            if ($relative -in @('scratch', 'cas')) { continue }
            $items.Add([ordered]@{
                RelativePath = $relative
                Kind = 'Directory'
                Sddl = (Get-Acl -LiteralPath $item.FullName).Sddl
            })
        } else {
            $items.Add([ordered]@{
                RelativePath = $relative
                Kind = 'File'
                Length = $item.Length
                Hash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
                Sddl = (Get-Acl -LiteralPath $item.FullName).Sddl
            })
        }
    }
    return ($items | ConvertTo-Json -Compress -Depth 5)
}

function Assert-CheckedActionsNotStarted {
    param([string]$LogPath, [string[]]$Actions)

    $log = Get-Content -LiteralPath $LogPath -Raw -ErrorAction Stop
    $started = @($Actions | Where-Object {
        [regex]::IsMatch($log, "(?im)Action start .*?:\s*$([regex]::Escape($_))\.")
    })
    if ($started.Count -ne 0) {
        throw "repair unexpectedly started fresh/uninstall action(s): $($started -join ', ')"
    }
    Write-Host "REPAIR ACTION PASS: $($Actions.Count) lifecycle/seed actions did not start."
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

function New-StandardUserProbeScript {
    param(
        [string]$DataRoot,
        [string]$ScratchRoot,
        [string]$CasRoot,
        [string]$DaemonConfig,
        [string]$WorkerConfig,
        [string]$ProbeRoot,
        [string]$StoreCtl
    )

    $paths = [ordered]@{
        DataRoot = ConvertTo-SingleQuotedLiteral $DataRoot
        ScratchRoot = ConvertTo-SingleQuotedLiteral $ScratchRoot
        CasRoot = ConvertTo-SingleQuotedLiteral $CasRoot
        DaemonConfig = ConvertTo-SingleQuotedLiteral $DaemonConfig
        WorkerConfig = ConvertTo-SingleQuotedLiteral $WorkerConfig
        StoreCtl = ConvertTo-SingleQuotedLiteral $StoreCtl
        ProbeRoot = ConvertTo-SingleQuotedLiteral $ProbeRoot
    }
    return @"
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
`$results.StoreCtl = [ordered]@{}
foreach (`$verb in @('provision', 'rollback-provision', 'commit-provision', 'uninstall')) {
    `$verbTag = `$verb.Replace('-', '_')
    `$verbOut = Join-Path $($paths.ProbeRoot) "storectl-`$verbTag.out"
    `$verbErr = Join-Path $($paths.ProbeRoot) "storectl-`$verbTag.err"
    `$startArguments = @{
        FilePath = $($paths.StoreCtl)
        ArgumentList = @(`$verb)
        WorkingDirectory = [Environment]::SystemDirectory
        WindowStyle = 'Hidden'
        Wait = `$true
        PassThru = `$true
        RedirectStandardOutput = `$verbOut
        RedirectStandardError = `$verbErr
    }
    `$attempt = Start-Process @startArguments
    `$results.StoreCtl[`$verb] = [ordered]@{
        ExitCode = `$attempt.ExitCode
        Stdout = [string](Get-Content -LiteralPath `$verbOut -Raw -ErrorAction Stop)
        Stderr = [string](Get-Content -LiteralPath `$verbErr -Raw -ErrorAction Stop)
    }
}
[pscustomobject]`$results | ConvertTo-Json -Compress -Depth 5
"@
}

function Assert-StandardUserProbeScriptParses {
    param([string]$Script)

    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput(
        $Script, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -ne 0) {
        throw "generated standard-user probe parse failed: $(@($parseErrors | ForEach-Object { $_.Message }) -join '; ')"
    }
    $commands = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    }, $true))
    $detachedParameters = @($commands | Where-Object {
        $null -ne $_.GetCommandName() -and $_.GetCommandName().StartsWith('-')
    })
    if ($detachedParameters.Count -ne 0) {
        throw "generated standard-user probe contains detached parameter command(s): $(@($detachedParameters | ForEach-Object { $_.GetCommandName() }) -join ', ')"
    }
    $startProcessCommands = @($commands | Where-Object {
        $_.GetCommandName() -eq 'Start-Process'
    })
    if ($startProcessCommands.Count -ne 1) {
        throw "generated standard-user probe must contain one Start-Process command; found $($startProcessCommands.Count)"
    }
    Write-Host 'STANDARD USER CHILD PARSE PASS: generated script has one splatted Start-Process and no detached parameter commands.'
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
        [string]$ProbeRoot,
        [string]$StoreCtl
    )

    $childScript = New-StandardUserProbeScript -DataRoot $DataRoot `
        -ScratchRoot $ScratchRoot -CasRoot $CasRoot -DaemonConfig $DaemonConfig `
        -WorkerConfig $WorkerConfig -ProbeRoot $ProbeRoot -StoreCtl $StoreCtl
    Assert-StandardUserProbeScriptParses -Script $childScript
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
    foreach ($verb in @('provision', 'rollback-provision', 'commit-provision', 'uninstall')) {
        $entry = $result.StoreCtl.PSObject.Properties[$verb].Value
        if ([int]$entry.ExitCode -ne 3 -or [string]$entry.Stdout -cne '' -or
            [string]$entry.Stderr -cnotmatch
                '\Asembazuru-storectl: unauthorized\r?\n\z') {
            throw "standard user storectl boundary failed: verb=$verb exit=$($entry.ExitCode) stdout='$($entry.Stdout)' stderr='$($entry.Stderr)'"
        }
    }
    Write-Host "STANDARD USER ACCESS PASS: filesystem denied and all four storectl verbs exited 3 with exact unauthorized stderr; user=$User"
}

function Invoke-Msi {
    param(
        [ValidateSet('Install', 'Repair', 'Uninstall')]
        [string]$Action,
        [string]$Path,
        [string]$LogPath
    )

    $verb = switch ($Action) {
        'Install' { '/i' }
        'Repair' { '/fa' }
        'Uninstall' { '/x' }
    }
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

Assert-StaticLifecycleSource -Path $Source
Assert-OfflineTokenSetupSource -Path $PSCommandPath
Assert-InstalledWorkerEventFormatter
$staticChildScript = New-StandardUserProbeScript `
    -DataRoot 'C:\ProgramData\Sembazuru' `
    -ScratchRoot 'C:\ProgramData\Sembazuru\scratch' `
    -CasRoot 'C:\ProgramData\Sembazuru\cas' `
    -DaemonConfig 'C:\ProgramData\Sembazuru\daemon.toml' `
    -WorkerConfig 'C:\ProgramData\Sembazuru\worker.toml' `
    -ProbeRoot "C:\ProgramData\Sembazuru Probe\operator's" `
    -StoreCtl "C:\ProgramData\Sembazuru Probe\operator's\sembazuru-storectl.exe"
Assert-StandardUserProbeScriptParses -Script $staticChildScript
if ($Static) { return }

$Msi = (Resolve-Path -LiteralPath $Msi -ErrorAction Stop).Path
$StoreCtl = (Resolve-Path -LiteralPath $StoreCtl -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $ExecVfs -PathType Leaf)) {
    throw "exec_vfs driver is not a file: $ExecVfs"
}
$ExecVfs = (Resolve-Path -LiteralPath $ExecVfs -ErrorAction Stop).Path
Assert-MsiLifecycleTables -Path $Msi
Assert-Administrator
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..\..') -ErrorAction Stop).Path
$commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$dataRoot = Join-Path $commonData 'Sembazuru'
$scratchRoot = Join-Path $dataRoot 'scratch'
$casRoot = Join-Path $dataRoot 'cas'
$provisionMarker = Join-Path $dataRoot '.provisioning-v1'
$daemonConfig = Join-Path $dataRoot 'daemon.toml'
$workerConfig = Join-Path $dataRoot 'worker.toml'
$clusterToken = Join-Path $dataRoot 'cluster-token.dpapi'
$installRoot = Join-Path $programFiles 'Sembazuru'
$productKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Sembazuru'

Assert-CleanPreflight -DataRoot $dataRoot -InstallRoot $installRoot -ProductKey $productKey

$tag = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$gateUser = "SbzAcl$tag"
$gatePassword = "SbZ!9a$tag"
$callerProbeRoot = Join-Path $commonData "Sembazuru-M9-Acl-Probe-$tag"
$logRoot = Join-Path ([IO.Path]::GetTempPath()) "sembazuru-m9-acl-$tag"
$installLog = Join-Path $logRoot 'install.log'
$repairLog = Join-Path $logRoot 'repair.log'
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
    Wait-ForWorkerExecutionEndpoint
    if (Test-Path -LiteralPath $provisionMarker) {
        throw "fresh install left the fixed provision marker behind: $provisionMarker"
    }
    Write-Host 'PROVISION COMMIT PASS: services are running and the fixed provision marker is absent.'
    Assert-ExactAclRules -Path $dataRoot -ExpectedProtected $true -ExpectedInherited $false `
        -WorkerMask 0x1200a9 -DaemonMask 0x1200a9 -RequireContainerInheritance $true
    Assert-ExactAclRules -Path $scratchRoot -ExpectedProtected $true -ExpectedInherited $false `
        -WorkerMask 0x1301bf -RequireContainerInheritance $true
    Assert-ExactAclRules -Path $casRoot -ExpectedProtected $true -ExpectedInherited $false `
        -WorkerMask 0x1301bf -RequireContainerInheritance $true
    Write-Host 'DIRECTORY ACL PASS: root has exact non-inherited daemon RX; scratch/cas remain exact SY/BA/worker only; no Users/AU/Everyone.'

    foreach ($config in @($daemonConfig, $workerConfig)) {
        if (-not (Test-Path -LiteralPath $config -PathType Leaf)) {
            throw "seeded config is missing: $config"
        }
        Assert-ExactAclRules -Path $config -ExpectedProtected $true -ExpectedInherited $false `
            -WorkerMask 0x1200a9 -DaemonMask 0x1200a9 -RequireContainerInheritance $false `
            -ExpectedOwnerSid 'S-1-5-18' -ExpectedGroupSid 'S-1-5-18'
    }
    Write-Host 'CONFIG ACL PASS: daemon.toml/worker.toml owner+group SYSTEM, protected non-inherited exact SY/BA Full + worker/daemon RX only.'

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

    Initialize-TestOnlyClusterToken -StoreCtl $StoreCtl
    Assert-ClusterTokenSecret -Path $clusterToken

    $gateSid = New-StandardGateUser -Name $gateUser -Password $gatePassword
    New-StandardProbeRoot -Path $callerProbeRoot -UserSid $gateSid
    $storeCtlProbe = Join-Path $callerProbeRoot 'sembazuru-storectl.exe'
    Copy-Item -LiteralPath $StoreCtl -Destination $storeCtlProbe -Force -ErrorAction Stop
    $storeCtlProbeHash = (Get-FileHash -LiteralPath $storeCtlProbe -Algorithm SHA256).Hash
    if ($storeCtlProbeHash -cne (Get-FileHash -LiteralPath $StoreCtl -Algorithm SHA256).Hash) {
        throw 'standard-user storectl probe copy does not match the supplied artifact'
    }
    $beforeStandardProbe = Get-StoreSnapshot -DataRoot $dataRoot
    Assert-StandardUserDenied -User $gateUser -Password $gatePassword -DataRoot $dataRoot `
        -ScratchRoot $scratchRoot -CasRoot $casRoot -DaemonConfig $daemonConfig `
        -WorkerConfig $workerConfig -ProbeRoot $callerProbeRoot -StoreCtl $storeCtlProbe
    if ($storeCtlProbeHash -cne
        (Get-FileHash -LiteralPath $storeCtlProbe -Algorithm SHA256).Hash) {
        throw 'standard-user storectl probe copy changed during authorization checks'
    }
    $afterStandardProbe = Get-StoreSnapshot -DataRoot $dataRoot
    if ($beforeStandardProbe -cne $afterStandardProbe) {
        throw 'standard-user storectl/filesystem probes changed the machine-store snapshot'
    }
    Write-Host 'STANDARD USER STORE PASS: recursive store/config/ACL snapshot is unchanged.'
    Write-Host "STANDARD USER SID: $gateSid"

    $beforeRepair = Get-StoreSnapshot -DataRoot $dataRoot
    $repair = Invoke-Msi -Action Repair -Path $Msi -LogPath $repairLog
    if ($repair.ExitCode -notin @(0, 3010)) {
        throw "MSI repair failed: exit=$($repair.ExitCode) log=$repairLog"
    }
    Assert-CheckedActionsNotStarted -LogPath $repairLog -Actions @(
        'RollbackMachineStoreProvision', 'ProvisionMachineStore',
        'CommitMachineStoreProvision', 'UninstallMachineStore',
        'SeedDaemonConfig', 'SeedWorkerConfig')
    $afterRepair = Get-StoreSnapshot -DataRoot $dataRoot
    if ($beforeRepair -cne $afterRepair) {
        throw 'MSI repair changed the recursive store/config/ACL snapshot'
    }
    Assert-ServicesRunning
    Write-Host "MSI REPAIR PASS: exit=$($repair.ExitCode) store/config/ACL unchanged; services running; log=$repairLog"

    Invoke-InstalledWorkerVfsGate -Driver $ExecVfs -RepoRoot $repoRoot `
        -ScratchRoot $scratchRoot -Tag $tag
    Write-Host 'WORKER CAPABILITY EVIDENCE: the installed virtual-account worker accepted a direct VFS Execute and ran the System32 probe through its restricted-token, pre-Job-assigned staged launcher/DLL path.'
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
