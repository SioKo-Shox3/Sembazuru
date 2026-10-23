# Prepare the Microsoft Visual C++ redistributables for the WiX Burn bundle.
# With no local paths this downloads the official aka.ms installers. Supplying
# both paths makes an offline/local build possible while retaining signature checks.
param(
    [string]$X64Path,
    [string]$X86Path
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$OutputRoot = Join-Path $repoRoot 'target\installer\redist'
$OutputRoot = [IO.Path]::GetFullPath($OutputRoot)
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$X64Url = 'https://aka.ms/vc14/vc_redist.x64.exe'
$X86Url = 'https://aka.ms/vc14/vc_redist.x86.exe'

function Get-VerifiedRedist {
    param(
        [Parameter(Mandatory)][string]$Architecture,
        [AllowEmptyString()][string]$InputPath,
        [Parameter(Mandatory)][string]$DownloadUrl,
        [Parameter(Mandatory)][string]$OutputPath
    )

    if ([string]::IsNullOrWhiteSpace($InputPath)) {
        Write-Host "Downloading official VC++ redistributable ($Architecture)."
        Invoke-WebRequest -UseBasicParsing -Uri $DownloadUrl -OutFile $OutputPath
        $InputPath = $OutputPath
    } elseif (-not (Test-Path -LiteralPath $InputPath -PathType Leaf)) {
        throw "redistributable not found: $InputPath"
    } else {
        $source = (Resolve-Path -LiteralPath $InputPath).Path
        $destination = [IO.Path]::GetFullPath($OutputPath)
        if (-not [StringComparer]::OrdinalIgnoreCase.Equals($source, $destination)) {
            Copy-Item -LiteralPath $source -Destination $destination -Force
        }
        $InputPath = $destination
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $InputPath
    if ($signature.Status -ne 'Valid') {
        throw "$Architecture redistributable signature status is '$($signature.Status)'"
    }
    if ($null -eq $signature.SignerCertificate) {
        throw "$Architecture redistributable has no signer certificate"
    }
    $signer = $signature.SignerCertificate.GetNameInfo(
        [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
        $false)
    if ($signer -ne 'Microsoft Corporation' -and
        $signature.SignerCertificate.Subject -notmatch '(^|,\s*)CN=Microsoft Corporation(,|$)') {
        throw "$Architecture redistributable signer is not Microsoft Corporation"
    }

    $productVersion = (Get-Item -LiteralPath $InputPath).VersionInfo.ProductVersion
    if ($productVersion -notmatch '^\d+\.\d+\.\d+\.\d+$') {
        throw "$Architecture redistributable ProductVersion is not numeric four-part: $productVersion"
    }
    $version = [version]$productVersion

    [pscustomobject]@{
        Architecture = $Architecture
        Path = [IO.Path]::GetFullPath($InputPath)
        Version = $version.ToString(4)
        Sha256 = (Get-FileHash -LiteralPath $InputPath -Algorithm SHA256).Hash
        Length = (Get-Item -LiteralPath $InputPath).Length
    }
}

$x64 = Get-VerifiedRedist -Architecture 'x64' -InputPath $X64Path -DownloadUrl $X64Url `
    -OutputPath (Join-Path $OutputRoot 'vc_redist.x64.exe')
$x86 = Get-VerifiedRedist -Architecture 'x86' -InputPath $X86Path -DownloadUrl $X86Url `
    -OutputPath (Join-Path $OutputRoot 'vc_redist.x86.exe')

# This generated props file is the explicit hand-off consumed by Bundle.wixproj.
$escape = { param([string]$value) [System.Security.SecurityElement]::Escape($value) }
$propsPath = Join-Path $OutputRoot 'Sembazuru.Redist.props'
$props = @"
<Project>
  <PropertyGroup>
    <SbzVCRedistX64>$(& $escape $x64.Path)</SbzVCRedistX64>
    <SbzVCRedistX86>$(& $escape $x86.Path)</SbzVCRedistX86>
    <SbzVCRedistX64Version>$($x64.Version)</SbzVCRedistX64Version>
    <SbzVCRedistX86Version>$($x86.Version)</SbzVCRedistX86Version>
  </PropertyGroup>
</Project>
"@
[IO.File]::WriteAllText($propsPath, $props, (New-Object Text.UTF8Encoding($false)))

Write-Host "VC++ x64: version=$($x64.Version) size=$($x64.Length) sha256=$($x64.Sha256)"
Write-Host "VC++ x86: version=$($x86.Version) size=$($x86.Length) sha256=$($x86.Sha256)"
Write-Host "MSBuild props: $propsPath"
Write-Host 'REDIST PREPARATION OK'
