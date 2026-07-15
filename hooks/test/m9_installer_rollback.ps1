[CmdletBinding(DefaultParameterSetName = 'TablesOnly')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'TablesOnly')]
    [switch]$TablesOnly,

    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [switch]$Full,

    [Parameter(Mandatory = $true, ParameterSetName = 'TablesOnly')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [ValidateNotNullOrEmpty()]
    [string]$ProductionMsi,

    [Parameter(Mandatory = $true, ParameterSetName = 'TablesOnly')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Full')]
    [ValidateNotNullOrEmpty()]
    [string]$FixtureMsi
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$prepositionGate = Join-Path $PSScriptRoot 'm9_programdata_preposition.ps1'
. $prepositionGate -StaticOnly

function Get-LifecycleSignature {
    param($Database)

    $names = @(
        'RollbackMachineStoreProvision', 'ProvisionMachineStore',
        'CommitMachineStoreProvision', 'UninstallMachineStore',
        'SeedDaemonConfig', 'SeedWorkerConfig')
    $actions = @(Invoke-MsiQuery -Database $Database -Columns 4 -Sql `
        'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')
    $sequences = @(Invoke-MsiQuery -Database $Database -Columns 2 -Sql `
        'SELECT `Action`, `Condition` FROM `InstallExecuteSequence`')
    $signature = [Collections.Generic.List[string]]::new()
    foreach ($name in $names) {
        $action = @($actions | Where-Object { $_[0] -ceq $name })
        $sequence = @($sequences | Where-Object { $_[0] -ceq $name })
        if ($action.Count -ne 1 -or $sequence.Count -ne 1) {
            throw "lifecycle signature row count mismatch: action=$name CustomAction=$($action.Count) sequence=$($sequence.Count)"
        }
        $signature.Add(
            "$name|$($action[0][1])|$($action[0][2])|$($action[0][3])|$($sequence[0][1])")
    }
    return @($signature)
}

function Assert-RollbackFixtureTables {
    param([string]$ProductionPath, [string]$FixturePath)

    Assert-MsiLifecycleTables -Path $ProductionPath
    Assert-MsiLifecycleTables -Path $FixturePath

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $productionDatabase = $null
    $fixtureDatabase = $null
    try {
        $productionDatabase = $installer.GetType().InvokeMember(
            'OpenDatabase', 'InvokeMethod', $null, $installer, @($ProductionPath, 0))
        $fixtureDatabase = $installer.GetType().InvokeMember(
            'OpenDatabase', 'InvokeMethod', $null, $installer, @($FixturePath, 0))
        $failures = [Collections.Generic.List[string]]::new()
        $failAction = 'Wix4FailWhenDeferred_X64'
        $utilBinary = 'Wix4UtilCA_X64'

        $productionActions = @(Invoke-MsiQuery -Database $productionDatabase -Columns 4 -Sql `
            'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')
        $productionSequences = @(Invoke-MsiQuery -Database $productionDatabase -Columns 3 -Sql `
            'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`')
        $productionBinaries = @(Invoke-MsiQuery -Database $productionDatabase -Columns 1 -Sql `
            'SELECT `Name` FROM `Binary`')
        $productionProperties = @(Invoke-MsiQuery -Database $productionDatabase -Columns 1 -Sql `
            'SELECT `Property` FROM `Property`')
        if (@($productionActions | Where-Object { $_[0] -ceq $failAction }).Count -ne 0) {
            $failures.Add("production CustomAction contains $failAction")
        }
        if (@($productionSequences | Where-Object { $_[0] -ceq $failAction }).Count -ne 0) {
            $failures.Add("production sequence contains $failAction")
        }
        if (@($productionBinaries | Where-Object { $_[0] -ceq $utilBinary }).Count -ne 0) {
            $failures.Add("production Binary contains $utilBinary")
        }
        foreach ($property in @('WIXFAILWHENDEFERRED', 'RollbackFixture', 'ROLLBACKFIXTURE')) {
            if (@($productionProperties | Where-Object { $_[0] -ceq $property }).Count -ne 0) {
                $failures.Add("production Property contains $property")
            }
        }

        $fixtureActions = @(Invoke-MsiQuery -Database $fixtureDatabase -Columns 4 -Sql `
            'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')
        $fixtureSequences = @(Invoke-MsiQuery -Database $fixtureDatabase -Columns 3 -Sql `
            'SELECT `Action`, `Condition`, `Sequence` FROM `InstallExecuteSequence`')
        $fixtureBinaries = @(Invoke-MsiQuery -Database $fixtureDatabase -Columns 1 -Sql `
            'SELECT `Name` FROM `Binary`')
        $binaryRows = @($fixtureBinaries | Where-Object { $_[0] -ceq $utilBinary })
        if ($binaryRows.Count -ne 1) {
            $failures.Add("fixture Binary $utilBinary row count must be 1; got $($binaryRows.Count)")
        } else {
            $binarySize = Get-MsiBinaryStreamSize -Database $fixtureDatabase -Name $utilBinary
            if ($binarySize -le 0) {
                $failures.Add("fixture Binary $utilBinary stream must be nonempty; size=$binarySize")
            }
        }

        $actionRows = @($fixtureActions | Where-Object { $_[0] -ceq $failAction })
        if ($actionRows.Count -ne 1) {
            $failures.Add("fixture CustomAction $failAction row count must be 1; got $($actionRows.Count)")
        } else {
            $action = $actionRows[0]
            # WiX 5.0.2 intentionally authors the fixture-only fail-fast CA as
            # type 1025 (deferred DLL, impersonated). It has no side effect beyond
            # failure. The actual security boundary remains the separately checked
            # LocalSystem Provision/Rollback actions (types 3074/3330).
            if ([string]$action[1] -cne '1025' -or
                [string]$action[2] -cne $utilBinary -or
                [string]$action[3] -cne 'WixFailWhenDeferred') {
                $failures.Add("fixture official fail-fast CustomAction mismatch: Type=$($action[1]) (expected fixture-only 1025; do not override to 3073) Source=$($action[2]) Target=$($action[3])")
            }
            if (([int]$action[1] -band 64) -ne 0) {
                $failures.Add('fixture failure action has forbidden Continue bit')
            }
        }

        $sequenceRows = @($fixtureSequences | Where-Object { $_[0] -ceq $failAction })
        if ($sequenceRows.Count -ne 1) {
            $failures.Add("fixture sequence $failAction row count must be 1; got $($sequenceRows.Count)")
        } else {
            $failSequence = [int]$sequenceRows[0][2]
            if ([string]$sequenceRows[0][1] -cne 'NOT Installed') {
                $failures.Add("fixture failure condition must be NOT Installed; got '$($sequenceRows[0][1])'")
            }
            $required = @{}
            foreach ($name in @(
                'RollbackMachineStoreProvision', 'ProvisionMachineStore', 'ProcessComponents')) {
                $row = @($fixtureSequences | Where-Object { $_[0] -ceq $name })
                if ($row.Count -ne 1) {
                    $failures.Add("fixture sequence row missing or duplicated: $name")
                } else {
                    $required[$name] = [int]$row[0][2]
                }
            }
            if ($required.Count -eq 3) {
                if (-not ($required.RollbackMachineStoreProvision -lt
                        $required.ProvisionMachineStore -and
                        $required.ProvisionMachineStore -lt $failSequence -and
                        $failSequence -lt $required.ProcessComponents)) {
                    $failures.Add(
                        "fixture rollback/provision/fail/process order invalid: rollback=$($required.RollbackMachineStoreProvision) provision=$($required.ProvisionMachineStore) fail=$failSequence process=$($required.ProcessComponents)")
                }
                $between = @($fixtureSequences | Where-Object {
                    [int]$_[2] -gt $required.ProvisionMachineStore -and
                    [int]$_[2] -lt $failSequence
                })
                if ($between.Count -ne 0) {
                    $failures.Add("unexpected sequence row(s) between provision and failure: $(@($between | ForEach-Object { $_[0] }) -join ', ')")
                }
            }
        }

        $productionSignature = @(Get-LifecycleSignature -Database $productionDatabase)
        $fixtureSignature = @(Get-LifecycleSignature -Database $fixtureDatabase)
        if (($productionSignature -join "`n") -cne ($fixtureSignature -join "`n")) {
            $failures.Add('production/fixture lifecycle and seed rows differ')
        }

        if ($failures.Count -ne 0) {
            throw "ROLLBACK FIXTURE TABLE FAIL:`n - $($failures -join "`n - ")"
        }
        Write-Host "ROLLBACK FIXTURE TABLE PASS: production excludes fixture; official fixture-only Type 1025 CA embeds $utilBinary and orders rollback < provision < fail < process; LocalSystem lifecycle rows have production parity."
    }
    finally {
        if ($null -ne $fixtureDatabase) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($fixtureDatabase) | Out-Null
        }
        if ($null -ne $productionDatabase) {
            [Runtime.InteropServices.Marshal]::FinalReleaseComObject($productionDatabase) | Out-Null
        }
        [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
    }
}

function Get-RollbackExecutionProofEvents {
    param([string]$Log)

    $recordPrefix = '^MSI \((?:s|c)\)\s+\([^()\r\n]+\)\s+\[[^\]\r\n]+\]:\s*'
    $operationPatterns = @(
        [pscustomobject]@{
            Kind = 'RollbackReserved'
            Pattern = $recordPrefix + 'Executing op:\s*CustomActionSchedule\(Action=RollbackMachineStoreProvision,ActionType=3330,Source=BinaryData,Target=rollback-provision,\)\s*$'
        },
        [pscustomobject]@{
            Kind = 'ProvisionScheduled'
            Pattern = $recordPrefix + 'Executing op:\s*CustomActionSchedule\(Action=ProvisionMachineStore,ActionType=3074,Source=BinaryData,Target=provision,\)\s*$'
        },
        [pscustomobject]@{
            Kind = 'FailureScheduled'
            Pattern = $recordPrefix + 'Executing op:\s*CustomActionSchedule\(Action=Wix4FailWhenDeferred_X64,ActionType=1025,Source=BinaryData,Target=WixFailWhenDeferred,\)\s*$'
        },
        [pscustomobject]@{
            Kind = 'RollbackExecuted'
            Pattern = $recordPrefix + 'Executing op:\s*CustomActionRollback\(Action=RollbackMachineStoreProvision,ActionType=3330,Source=BinaryData,Target=rollback-provision,\)\s*$'
        }
    )
    $resultPattern = '^CustomAction (?<Action>ProvisionMachineStore|Wix4FailWhenDeferred_X64|RollbackMachineStoreProvision) returned actual error code (?<Code>-?\d+)(?:\s+\([^\r\n]*\))?\s*$'
    $returnThreePattern = '^Action ended [^\r\n]*?:\s*(?<Action>ProvisionMachineStore|RollbackMachineStoreProvision)\.\s*Return value 3\.[^\r\n]*$'
    $lines = if ($Log.Length -eq 0) { @() } else {
        @([regex]::Split($Log, '\r\n|\n|\r'))
    }
    $events = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $line = [string]$lines[$index]
        foreach ($expectation in $operationPatterns) {
            if ([regex]::IsMatch($line, $expectation.Pattern)) {
                $events.Add([pscustomobject]@{
                    Kind = $expectation.Kind
                    LineNumber = $index + 1
                    Code = $null
                    Line = $line
                })
            }
        }
        $result = [regex]::Match($line, $resultPattern)
        if ($result.Success) {
            $events.Add([pscustomobject]@{
                Kind = "$($result.Groups['Action'].Value)Result"
                LineNumber = $index + 1
                Code = [int64]$result.Groups['Code'].Value
                Line = $line
            })
        }
        $returnThree = [regex]::Match($line, $returnThreePattern)
        if ($returnThree.Success) {
            $events.Add([pscustomobject]@{
                Kind = "$($returnThree.Groups['Action'].Value)ReturnValue3"
                LineNumber = $index + 1
                Code = 3L
                Line = $line
            })
        }
    }
    return @($events)
}

function Test-RollbackExecutionProof {
    param([string]$Log)

    $events = @(Get-RollbackExecutionProofEvents -Log $Log)
    $findings = [Collections.Generic.List[string]]::new()
    $requiredKinds = @(
        'RollbackReserved', 'ProvisionScheduled', 'FailureScheduled',
        'Wix4FailWhenDeferred_X64Result', 'RollbackExecuted')
    $required = @{}
    foreach ($kind in $requiredKinds) {
        $matches = @($events | Where-Object { $_.Kind -ceq $kind })
        if ($matches.Count -ne 1) {
            $findings.Add("required rollback proof event $kind count must be 1; got $($matches.Count)")
        } else {
            $required[$kind] = $matches[0]
        }
    }
    if ($required.Count -eq $requiredKinds.Count) {
        $lineNumbers = @($requiredKinds | ForEach-Object {
            [int]$required[$_].LineNumber
        })
        for ($index = 1; $index -lt $lineNumbers.Count; $index++) {
            if ($lineNumbers[$index - 1] -ge $lineNumbers[$index]) {
                $findings.Add(
                    "rollback proof event order invalid: $($requiredKinds -join ' < ') at lines $($lineNumbers -join ',')")
                break
            }
        }
        if ([int64]$required['Wix4FailWhenDeferred_X64Result'].Code -ne 1603) {
            $findings.Add(
                "fixture failure result must be 1603; got $($required['Wix4FailWhenDeferred_X64Result'].Code)")
        }
    }

    foreach ($action in @('ProvisionMachineStore', 'RollbackMachineStoreProvision')) {
        $results = @($events | Where-Object { $_.Kind -ceq "${action}Result" })
        if ($results.Count -gt 1) {
            $findings.Add("optional success result for $action appeared more than once: $($results.Count)")
        }
        $nonzero = @($results | Where-Object { [int64]$_.Code -ne 0 })
        if ($nonzero.Count -ne 0) {
            $findings.Add("$action has forbidden nonzero actual error code(s): $(@($nonzero | ForEach-Object { $_.Code }) -join ',')")
        }
        if (@($events | Where-Object {
                $_.Kind -ceq "${action}ReturnValue3"
            }).Count -ne 0) {
            $findings.Add("$action unexpectedly ended with Return value 3")
        }
    }
    return [pscustomobject]@{
        Passed = $findings.Count -eq 0
        Findings = @($findings)
        Events = @($events)
    }
}

function Wait-RollbackFixtureResidue {
    param(
        [string]$DataRoot,
        [string]$InstallRoot,
        [string]$ProductKey,
        [int]$Attempts = 30
    )

    $residue = @()
    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        $residue = @(Get-InstallResidue -DataRoot $DataRoot -InstallRoot $InstallRoot `
            -ProductKey $ProductKey)
        if ($residue.Count -eq 0) { return @() }
        if ($attempt -lt $Attempts) { Start-Sleep -Milliseconds 250 }
    }
    return @($residue)
}

function Get-OrdinalOccurrenceCount {
    param([string]$Text, [string]$Needle)

    $count = 0
    $start = 0
    while ($start -lt $Text.Length) {
        $index = $Text.IndexOf($Needle, $start, [StringComparison]::Ordinal)
        if ($index -lt 0) { break }
        $count++
        $start = $index + $Needle.Length
    }
    return $count
}

function Get-MsiLogFileMetadata {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ ByteLength = 0L; Bom = 'missing' }
    }
    $file = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $prefix = New-Object byte[] 3
    $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $read = $stream.Read($prefix, 0, $prefix.Length)
    }
    finally {
        $stream.Dispose()
    }
    $bom = if ($read -ge 3 -and $prefix[0] -eq 0xef -and
        $prefix[1] -eq 0xbb -and $prefix[2] -eq 0xbf) {
        'UTF-8 BOM'
    } elseif ($read -ge 2 -and $prefix[0] -eq 0xff -and $prefix[1] -eq 0xfe) {
        'UTF-16LE BOM'
    } elseif ($read -ge 2 -and $prefix[0] -eq 0xfe -and $prefix[1] -eq 0xff) {
        'UTF-16BE BOM'
    } else {
        'none/unknown'
    }
    return [pscustomobject]@{ ByteLength = [int64]$file.Length; Bom = $bom }
}

function Get-BoundedRollbackLogDiagnostic {
    param(
        [string]$Log,
        [int64]$ByteLength,
        [string]$Bom,
        [int]$MaxLines = 120,
        [int]$MaxCharacters = 24000
    )

    $actionNames = @(
        'ProvisionMachineStore', 'Wix4FailWhenDeferred_X64',
        'RollbackMachineStoreProvision')
    $tokens = @(
        $actionNames[0], $actionNames[1], $actionNames[2],
        'InstallInitialize', 'InstallFinalize', 'ActionStart',
        'CustomActionSchedule', 'returned actual error code', 'Return value',
        'Error 1722', '1603')
    $occurrences = [ordered]@{}
    foreach ($name in $actionNames) {
        $occurrences[$name] = Get-OrdinalOccurrenceCount -Text $Log -Needle $name
    }

    $allLines = if ($Log.Length -eq 0) { @() } else {
        @([regex]::Split($Log, '\r\n|\n|\r'))
    }
    $selected = [Collections.Generic.List[string]]::new()
    $matchingLineCount = 0
    $characters = 0
    $truncated = $false
    for ($index = 0; $index -lt $allLines.Count; $index++) {
        $line = [string]$allLines[$index]
        $matchesToken = $false
        foreach ($token in $tokens) {
            if ($line.IndexOf($token, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $matchesToken = $true
                break
            }
        }
        if (-not $matchesToken) { continue }
        $matchingLineCount++
        if ($selected.Count -ge $MaxLines) {
            $truncated = $true
            continue
        }
        $entry = "L$($index + 1): $line"
        $separatorLength = if ($selected.Count -eq 0) { 0 } else { 1 }
        $remaining = $MaxCharacters - $characters - $separatorLength
        if ($remaining -le 0) {
            $truncated = $true
            continue
        }
        if ($entry.Length -gt $remaining) {
            $entry = $entry.Substring(0, $remaining)
            $truncated = $true
        }
        $selected.Add($entry)
        $characters += $entry.Length + $separatorLength
    }
    if ($matchingLineCount -gt $selected.Count) { $truncated = $true }

    return [pscustomobject]@{
        ByteLength = $ByteLength
        CharacterLength = $Log.Length
        LineCount = $allLines.Count
        Bom = $Bom
        MaxLines = $MaxLines
        MaxCharacters = $MaxCharacters
        OrdinalOccurrences = [pscustomobject]$occurrences
        MatchingLineCount = $matchingLineCount
        EmittedLineCount = $selected.Count
        Truncated = $truncated
        SelectedText = $selected -join "`n"
    }
}

function Write-BoundedRollbackLogDiagnostic {
    param([string]$Path, [string]$Log)

    $file = Get-MsiLogFileMetadata -Path $Path
    $diagnostic = Get-BoundedRollbackLogDiagnostic -Log $Log `
        -ByteLength $file.ByteLength -Bom $file.Bom
    $metadata = [ordered]@{
        ByteLength = $diagnostic.ByteLength
        CharacterLength = $diagnostic.CharacterLength
        LineCount = $diagnostic.LineCount
        Bom = $diagnostic.Bom
        MaxLines = $diagnostic.MaxLines
        MaxCharacters = $diagnostic.MaxCharacters
        MatchingLineCount = $diagnostic.MatchingLineCount
        EmittedLineCount = $diagnostic.EmittedLineCount
        Truncated = $diagnostic.Truncated
    }
    Write-Host "ROLLBACK FIXTURE LOG METADATA: $(ConvertTo-StableJson $metadata)"
    Write-Host "ROLLBACK FIXTURE LOG ORDINAL OCCURRENCES: $(ConvertTo-StableJson $diagnostic.OrdinalOccurrences)"
    Write-Host "ROLLBACK FIXTURE FILTERED LOG BEGIN: maxLines=$($diagnostic.MaxLines) maxCharacters=$($diagnostic.MaxCharacters)"
    if ($diagnostic.SelectedText.Length -eq 0) {
        Write-Host '<no matching diagnostic lines>'
    } else {
        Write-Host $diagnostic.SelectedText
    }
    Write-Host "ROLLBACK FIXTURE FILTERED LOG END: emitted=$($diagnostic.EmittedLineCount) matched=$($diagnostic.MatchingLineCount) truncated=$($diagnostic.Truncated)"
}

function Assert-BoundedRollbackLogDiagnosticFixture {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('Action start: ProvisionMachineStore. Executing op: CustomActionSchedule(Action=ProvisionMachineStore)')
    $lines.Add('Executing op: CustomActionSchedule(Action=Wix4FailWhenDeferred_X64) Error 1722')
    $lines.Add('Executing op: CustomActionSchedule(Action=RollbackMachineStoreProvision) returned actual error code 0')
    for ($index = 0; $index -lt 20; $index++) {
        $lines.Add("Error 1603 synthetic diagnostic line $index $('x' * 80)")
    }
    $synthetic = $lines -join "`r`n"
    $diagnostic = Get-BoundedRollbackLogDiagnostic -Log $synthetic `
        -ByteLength 999 -Bom 'fixture' -MaxLines 4 -MaxCharacters 500
    if ($diagnostic.EmittedLineCount -gt 4 -or
        $diagnostic.SelectedText.Length -gt 500 -or -not $diagnostic.Truncated) {
        throw 'bounded rollback diagnostic fixture exceeded its line/character limits'
    }
    foreach ($action in @(
        'ProvisionMachineStore', 'Wix4FailWhenDeferred_X64',
        'RollbackMachineStoreProvision')) {
        if ($diagnostic.OrdinalOccurrences.$action -lt 1 -or
            $diagnostic.SelectedText.IndexOf($action, [StringComparison]::Ordinal) -lt 0) {
            throw "bounded rollback diagnostic fixture lost action evidence: $action"
        }
    }
    Write-Host 'ROLLBACK LOG DIAGNOSTIC FIXTURE PASS: three actions retained within maxLines=4 and maxCharacters=500 with truncation.'
}

function Assert-RollbackExecutionProofFixture {
    $baseLines = @(
        'MSI (s) (10:20) [00:00:00:000]: Executing op: CustomActionSchedule(Action=RollbackMachineStoreProvision,ActionType=3330,Source=BinaryData,Target=rollback-provision,)',
        'MSI (s) (10:20) [00:00:00:001]: Executing op: CustomActionSchedule(Action=ProvisionMachineStore,ActionType=3074,Source=BinaryData,Target=provision,)',
        'MSI (s) (10:20) [00:00:00:002]: Executing op: CustomActionSchedule(Action=Wix4FailWhenDeferred_X64,ActionType=1025,Source=BinaryData,Target=WixFailWhenDeferred,)',
        'CustomAction Wix4FailWhenDeferred_X64 returned actual error code 1603 (note this may not be 100% accurate if translation happened inside sandbox)',
        'MSI (s) (10:20) [00:00:00:004]: Executing op: CustomActionRollback(Action=RollbackMachineStoreProvision,ActionType=3330,Source=BinaryData,Target=rollback-provision,)'
    )
    $assertAccepted = {
        param([object[]]$Lines, [string]$Label)
        $proof = Test-RollbackExecutionProof -Log ($Lines -join "`r`n")
        if (-not $proof.Passed) {
            throw "rollback proof positive fixture rejected ${Label}: $($proof.Findings -join '; ')"
        }
    }
    $assertRejected = {
        param([object[]]$Lines, [string]$Label)
        $proof = Test-RollbackExecutionProof -Log ($Lines -join "`r`n")
        if ($proof.Passed) {
            throw "rollback proof negative fixture was accepted: $Label"
        }
    }

    & $assertAccepted -Lines $baseLines -Label 'real format without optional code 0'
    & $assertAccepted -Lines @($baseLines | ForEach-Object {
            $_.Replace('MSI (s)', 'MSI (c)').Replace('(10:20)', '(A4:123)')
        }) -Label 'client logger record with variable-width thread fields'
    $withOptionalZero = @(
        $baseLines[0], $baseLines[1],
        'CustomAction ProvisionMachineStore returned actual error code 0',
        $baseLines[2], $baseLines[3], $baseLines[4],
        'CustomAction RollbackMachineStoreProvision returned actual error code 0')
    & $assertAccepted -Lines $withOptionalZero -Label 'optional code 0 evidence'
    & $assertAccepted -Label 'property echo result and Return value 3 noise' -Lines @(
        $baseLines[0], $baseLines[1], $baseLines[2], $baseLines[3], $baseLines[4],
        'MSI (s) (10:20) [00:00:00:005]: PROPERTY CHANGE: Adding FakeProvisionResult property. Its value is CustomAction ProvisionMachineStore returned actual error code 10',
        'MSI (s) (10:20) [00:00:00:006]: PROPERTY CHANGE: Adding FakeReturnValue property. Its value is Action ended 00:00:01: ProvisionMachineStore. Return value 3.')

    & $assertRejected -Label 'ActionStart only' -Lines @(
        'MSI (s): Executing op: ActionStart(Name=RollbackMachineStoreProvision)',
        'MSI (s): Action start: ProvisionMachineStore.',
        'MSI (s): Action start: Wix4FailWhenDeferred_X64.')
    & $assertRejected -Label 'property echo containing all proof text' -Lines @(
        "MSI (s) (10:20) [00:00:00:000]: PROPERTY CHANGE: Adding FakeRollbackReserved property. Its value is $($baseLines[0].Split(': ', 2)[1])",
        "MSI (s) (10:20) [00:00:00:001]: PROPERTY CHANGE: Adding FakeProvisionScheduled property. Its value is $($baseLines[1].Split(': ', 2)[1])",
        "MSI (s) (10:20) [00:00:00:002]: PROPERTY CHANGE: Adding FakeFailureScheduled property. Its value is $($baseLines[2].Split(': ', 2)[1])",
        'MSI (s) (10:20) [00:00:00:003]: PROPERTY CHANGE: Adding FakeFailureResult property. Its value is CustomAction Wix4FailWhenDeferred_X64 returned actual error code 1603',
        "MSI (s) (10:20) [00:00:00:004]: PROPERTY CHANGE: Adding FakeRollbackExecuted property. Its value is $($baseLines[4].Split(': ', 2)[1])")
    & $assertRejected -Label 'required operation missing' -Lines @(
        $baseLines[0], $baseLines[1], $baseLines[3], $baseLines[4])
    & $assertRejected -Label 'required operation order changed' -Lines @(
        $baseLines[0], $baseLines[2], $baseLines[1], $baseLines[3], $baseLines[4])

    $typeChanged = @($baseLines)
    $typeChanged[1] = $typeChanged[1].Replace('ActionType=3074', 'ActionType=3075')
    & $assertRejected -Lines $typeChanged -Label 'Provision ActionType changed'

    & $assertRejected -Label 'Provision nonzero result' -Lines @(
        $baseLines[0], $baseLines[1],
        'CustomAction ProvisionMachineStore returned actual error code 10',
        $baseLines[2], $baseLines[3], $baseLines[4])
    & $assertRejected -Label 'Rollback nonzero result' -Lines @(
        $baseLines[0], $baseLines[1], $baseLines[2], $baseLines[3], $baseLines[4],
        'CustomAction RollbackMachineStoreProvision returned actual error code 10')
    & $assertRejected -Label 'Provision Return value 3' -Lines @(
        $baseLines[0], $baseLines[1], $baseLines[2], $baseLines[3], $baseLines[4],
        'Action ended 00:00:01: ProvisionMachineStore. Return value 3.')

    $actionPrefix = @($baseLines)
    $actionPrefix[1] = $actionPrefix[1].Replace(
        'Action=ProvisionMachineStore,', 'Action=ProvisionMachineStoreExtra,')
    & $assertRejected -Lines $actionPrefix -Label 'same-name prefix action'
    $targetChanged = @($baseLines)
    $targetChanged[4] = $targetChanged[4].Replace(
        'Target=rollback-provision,', 'Target=rollback-provision-extra,')
    & $assertRejected -Lines $targetChanged -Label 'Rollback target changed'

    & $assertRejected -Label 'duplicate required event' -Lines @(
        $baseLines[0], $baseLines[1], $baseLines[2], $baseLines[2],
        $baseLines[3], $baseLines[4])
    Write-Host 'ROLLBACK EXECUTION PROOF FIXTURE PASS: real server/client records and optional code 0 accepted; property echoes, ActionStart, missing/reordered/mutated/nonzero/prefix/target/duplicate evidence rejected.'
}

Assert-BoundedRollbackLogDiagnosticFixture
Assert-RollbackExecutionProofFixture

$ProductionMsi = (Resolve-Path -LiteralPath $ProductionMsi -ErrorAction Stop).Path
$FixtureMsi = (Resolve-Path -LiteralPath $FixtureMsi -ErrorAction Stop).Path
Assert-RollbackFixtureTables -ProductionPath $ProductionMsi -FixturePath $FixtureMsi
if ($TablesOnly) { return }

Assert-Administrator
$commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
$programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$dataRoot = Join-Path $commonData 'Sembazuru'
$installRoot = Join-Path $programFiles 'Sembazuru'
$productKey = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Sembazuru'
Assert-CleanPreflight -DataRoot $dataRoot -InstallRoot $installRoot -ProductKey $productKey

$tag = [Guid]::NewGuid().ToString('N').Substring(0, 8)
$logRoot = Join-Path ([IO.Path]::GetTempPath()) "sembazuru-m9-rollback-$tag"
$installLog = Join-Path $logRoot 'fixture-install.log'
$cleanupLog = Join-Path $logRoot 'fixture-cleanup.log'
$msiAttempted = $false
$postAttemptResidue = @()
$primaryError = $null
$cleanupErrors = [Collections.Generic.List[string]]::new()

try {
    New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
    $msiAttempted = $true
    $install = Invoke-Msi -Action Install -Path $FixtureMsi -LogPath $installLog
    Write-Host "ROLLBACK FIXTURE MSI ATTEMPT: exit=$($install.ExitCode) log=$installLog"

    $findings = [Collections.Generic.List[string]]::new()
    if ($install.ExitCode -ne 1603) {
        $findings.Add("fixture MSI exit must be exactly 1603; got $($install.ExitCode)")
    }
    if (-not (Test-Path -LiteralPath $installLog -PathType Leaf)) {
        $findings.Add('fixture MSI verbose log is missing')
        $log = ''
    } else {
        $log = Get-Content -LiteralPath $installLog -Raw
    }

    $rollbackProof = Test-RollbackExecutionProof -Log $log
    foreach ($proofFinding in @($rollbackProof.Findings)) {
        $findings.Add("rollback execution proof: $proofFinding")
    }

    $execution = Get-MsiExecutionClassifier -Log $log
    foreach ($property in @(
        'SeedDaemonConfigExecuted', 'SeedWorkerConfigExecuted',
        'CommitMachineStoreProvisionExecuted', 'UninstallMachineStoreExecuted',
        'SembazuruServiceInstallExecuted', 'SembazuruServiceControlExecuted')) {
        if ($execution.$property) {
            $findings.Add("forbidden downstream actual operation reached: $property")
        }
    }

    $postAttemptResidue = @(Wait-RollbackFixtureResidue -DataRoot $dataRoot `
        -InstallRoot $installRoot -ProductKey $productKey)
    $proofCounts = [ordered]@{}
    foreach ($kind in @(
        'RollbackReserved', 'ProvisionScheduled', 'FailureScheduled',
        'Wix4FailWhenDeferred_X64Result', 'RollbackExecuted',
        'ProvisionMachineStoreResult', 'RollbackMachineStoreProvisionResult')) {
        $proofCounts[$kind] = @($rollbackProof.Events | Where-Object {
            $_.Kind -ceq $kind
        }).Count
    }
    Write-Host "ROLLBACK FIXTURE PROOF EVENTS: $(ConvertTo-StableJson $proofCounts)"
    Write-Host "ROLLBACK FIXTURE RESIDUE: $(ConvertTo-StableJson $postAttemptResidue)"
    if ($postAttemptResidue.Count -ne 0) {
        $findings.Add("rollback residue remained: $($postAttemptResidue -join '; ')")
    }

    if ($findings.Count -ne 0) {
        Write-BoundedRollbackLogDiagnostic -Path $installLog -Log $log
        throw "ROLLBACK FIXTURE DYNAMIC FAIL:`n - $($findings -join "`n - ")"
    }
    Write-Host 'PASS: fixture failed with 1603 after exact rollback reservation < provision schedule < fail schedule/result < CustomActionRollback evidence, no lifecycle nonzero result, no forbidden downstream operation, and zero residue.'
}
catch {
    $primaryError = $_
}
finally {
    if ($msiAttempted) {
        $cleanupResidue = @(Wait-RollbackFixtureResidue -DataRoot $dataRoot `
            -InstallRoot $installRoot -ProductKey $productKey -Attempts 1)
        if ($cleanupResidue.Count -ne 0) {
            try {
                $null = Stop-AttemptServices
                $uninstall = Invoke-Msi -Action Uninstall -Path $FixtureMsi -LogPath $cleanupLog
                if ($uninstall.ExitCode -notin @(0, 3010, 1605)) {
                    $cleanupErrors.Add("bounded fixture cleanup uninstall failed: exit=$($uninstall.ExitCode) log=$cleanupLog")
                }
                $cleanupResidue = @(Wait-RollbackFixtureResidue -DataRoot $dataRoot `
                    -InstallRoot $installRoot -ProductKey $productKey -Attempts 12)
            }
            catch {
                $cleanupErrors.Add("bounded fixture cleanup invocation failed: $($_.Exception.Message)")
            }
            if ($cleanupResidue.Count -ne 0) {
                $cleanupErrors.Add("bounded fixture cleanup left residue: $($cleanupResidue -join '; ')")
            }
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
    throw "rollback fixture cleanup failed: $($cleanupErrors -join '; ')"
}
