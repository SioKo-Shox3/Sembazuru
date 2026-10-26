[CmdletBinding()]
param(
    [string] $OutputPath = (Join-Path (Join-Path $PSScriptRoot '..\target\lan-preparation') 'Sembazuru-lan-smoke.zip')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$Version = '0.0.3'
$Kind = 'lan-smoke'
$RepoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$PreparationRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot 'target\lan-preparation'))
$OutputWasExplicit = $PSBoundParameters.ContainsKey('OutputPath')

$SourcePaths = @(
    'crates/agent/examples/scale_harness.rs',
    'hooks/test/lan_smoke.ps1',
    'installer/build_lan_bundle.ps1',
    'docs/lan-smoke.md'
)

$PackageFiles = @(
    [pscustomobject]@{ Source = (Join-Path $RepoRoot 'target\release\sembazuru-worker.exe'); Relative = 'sembazuru-worker.exe' },
    [pscustomobject]@{ Source = (Join-Path $RepoRoot 'target\release\examples\scale_harness.exe'); Relative = 'scale_harness.exe' },
    [pscustomobject]@{ Source = (Join-Path $RepoRoot 'target\release\examples\burn.exe'); Relative = 'burn.exe' },
    [pscustomobject]@{ Source = (Join-Path $RepoRoot 'hooks\test\lan_smoke.ps1'); Relative = 'lan_smoke.ps1' },
    [pscustomobject]@{ Source = (Join-Path $RepoRoot 'docs\lan-smoke.md'); Relative = 'README.md' },
    [pscustomobject]@{ Source = (Join-Path $RepoRoot 'LICENSE'); Relative = 'LICENSE' }
)

$ZipEntries = @(
    'LICENSE',
    'README.md',
    'burn.exe',
    'lan_smoke.ps1',
    'manifest.json',
    'scale_harness.exe',
    'sembazuru-worker.exe'
)

function Invoke-GitLines {
    param([string[]] $Arguments)

    $lines = @(& git -C $RepoRoot @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw ('git command failed: ' + ($Arguments -join ' '))
    }
    return $lines
}

function Get-SourceDiffHash {
    $diffArguments = @('diff', '--no-ext-diff', '--binary', 'HEAD', '--') + $SourcePaths
    $diffLines = @(Invoke-GitLines $diffArguments)
    $untrackedArguments = @('ls-files', '--others', '--exclude-standard', '--') + $SourcePaths
    $untrackedLines = @(Invoke-GitLines $untrackedArguments | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

    $stream = New-Object System.IO.MemoryStream
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    try {
        $diffText = $diffLines -join "`n"
        $diffBytes = $utf8.GetBytes($diffText)
        $stream.Write($diffBytes, 0, $diffBytes.Length)
        foreach ($relative in ($untrackedLines | Sort-Object)) {
            $markerBytes = $utf8.GetBytes(("`nUNTRACKED:{0}`n" -f $relative))
            $stream.Write($markerBytes, 0, $markerBytes.Length)
            $absolute = Join-Path $RepoRoot ($relative.Replace('/', '\'))
            $fileBytes = [System.IO.File]::ReadAllBytes($absolute)
            $stream.Write($fileBytes, 0, $fileBytes.Length)
        }
        $stream.Position = 0
        $hash = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($hash.ComputeHash($stream)).Replace('-', '')).ToLowerInvariant()
        } finally {
            $hash.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Write-DeterministicZip {
    param(
        [string] $StagingPath,
        [string] $DestinationPath
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    $destinationDirectory = Split-Path -Parent $DestinationPath
    if (-not (Test-Path -LiteralPath $destinationDirectory -PathType Container)) {
        New-Item -ItemType Directory -Path $destinationDirectory | Out-Null
    }
    if (Test-Path -LiteralPath $DestinationPath) {
        if (-not $OutputWasExplicit) {
            throw "Refusing to replace an existing ZIP without explicit -OutputPath: $DestinationPath"
        }
        Remove-Item -LiteralPath $DestinationPath -Force
    }

    $archive = [System.IO.Compression.ZipFile]::Open(
        $DestinationPath,
        [System.IO.Compression.ZipArchiveMode]::Create
    )
    $fixedTime = [System.DateTimeOffset]::Parse('1980-01-01T00:00:00+00:00')
    try {
        foreach ($relative in $ZipEntries) {
            $source = Join-Path $StagingPath $relative
            if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
                throw "Staging file is missing: $relative"
            }
            $entry = $archive.CreateEntry($relative, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $fixedTime
            $input = [System.IO.File]::OpenRead($source)
            $output = $entry.Open()
            try {
                $input.CopyTo($output)
            } finally {
                $output.Dispose()
                $input.Dispose()
            }
        }
    } finally {
        $archive.Dispose()
    }
}

$stagingPath = $null
$stagingCreated = $false
try {
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        throw 'OutputPath must not be empty.'
    }
    $outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
    foreach ($file in $PackageFiles) {
        if (-not (Test-Path -LiteralPath $file.Source -PathType Leaf)) {
            throw "Required bundle input is missing: $($file.Source)"
        }
    }

    $sourceCommit = [string]((Invoke-GitLines @('rev-parse', 'HEAD')) | Select-Object -First 1)
    if ([string]::IsNullOrWhiteSpace($sourceCommit)) {
        throw 'Unable to determine source commit.'
    }
    $sourceDiffHash = Get-SourceDiffHash

    if (-not (Test-Path -LiteralPath $PreparationRoot -PathType Container)) {
        New-Item -ItemType Directory -Path $PreparationRoot | Out-Null
    }
    $stagingPath = Join-Path $PreparationRoot ('staging-' + ([Guid]::NewGuid().ToString('N')))
    if (Test-Path -LiteralPath $stagingPath) {
        throw "Refusing to reuse staging path: $stagingPath"
    }
    New-Item -ItemType Directory -Path $stagingPath | Out-Null
    $stagingCreated = $true

    foreach ($file in $PackageFiles) {
        Copy-Item -LiteralPath $file.Source -Destination (Join-Path $stagingPath $file.Relative)
    }

    $manifestFiles = @(
        foreach ($file in $PackageFiles | Sort-Object Relative) {
            $hash = (Get-FileHash -LiteralPath (Join-Path $stagingPath $file.Relative) -Algorithm SHA256).Hash
            [pscustomobject][ordered]@{
                path = $file.Relative
                sha256 = $hash.ToLowerInvariant()
            }
        }
    )
    $manifest = [ordered]@{
        version = $Version
        kind = $Kind
        sourceCommit = $sourceCommit
        sourceDiffHash = $sourceDiffHash
        files = $manifestFiles
    }
    $manifestJson = $manifest | ConvertTo-Json -Depth 4 -Compress
    [System.IO.File]::WriteAllText(
        (Join-Path $stagingPath 'manifest.json'),
        $manifestJson,
        (New-Object System.Text.UTF8Encoding($false))
    )

    Write-DeterministicZip $stagingPath $outputFullPath
    $bundleHash = (Get-FileHash -LiteralPath $outputFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Output ("Bundle created: {0}" -f $outputFullPath)
    Write-Output ("Bundle SHA256: {0}" -f $bundleHash)
} catch {
    Write-Error $_.Exception.Message
    exit 1
} finally {
    if ($stagingCreated -and (Test-Path -LiteralPath $stagingPath -PathType Container)) {
        $preparationRootWithSeparator = ([System.IO.Path]::GetFullPath($PreparationRoot)).TrimEnd('\') + '\'
        $stagingFullPath = [System.IO.Path]::GetFullPath($stagingPath)
        if (-not $stagingFullPath.StartsWith($preparationRootWithSeparator, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove staging path outside target/lan-preparation: $stagingFullPath"
        }
        Remove-Item -LiteralPath $stagingFullPath -Recurse -Force
    }
}
