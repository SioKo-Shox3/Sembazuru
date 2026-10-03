# Release-hygiene gate: the workspace Cargo version and the installer's default WiX
# ProductVersion (SbzVersion) must agree.
#
# Why this matters: a release MSI advertises its ProductVersion (SbzVersion) to
# Windows Installer for MajorUpgrade, while the running binaries report
# CARGO_PKG_VERSION — which the cluster's version-gated admission (ADR 0011) compares
# to decide which workers may join a build. If the two drift, a freshly built release
# ships one version to Windows Installer and another to the admission gate, so a
# manually installed node could register at a version the agent then excludes. Run
# this in CI / before cutting a (manual-distribution) release; a non-zero exit means
# "reconcile the versions before shipping".
#
# Note: CI may pass -p:SbzVersion=<cargo version> explicitly (the recommended path);
# this gate checks the *default* in Package.wixproj so the checked-in fallback never
# silently lags the crate version.
$ErrorActionPreference = 'Stop'

$root    = Split-Path -Parent $PSScriptRoot
$cargo   = Join-Path $root 'Cargo.toml'
$wixproj = Join-Path $PSScriptRoot 'Package.wixproj'
$bundle  = Join-Path $PSScriptRoot 'Bundle.wixproj'

foreach ($f in @($cargo, $wixproj, $bundle)) {
    if (-not (Test-Path $f)) { throw "missing file: $f" }
}

# The workspace [workspace.package] version is the first top-level `version = "..."`.
$cargoMatch = Select-String -Path $cargo -Pattern '^version\s*=\s*"([^"]+)"' | Select-Object -First 1
if (-not $cargoMatch) { throw "could not find the workspace version in $cargo" }
$cargoVersion = $cargoMatch.Matches.Groups[1].Value

# The installer's default ProductVersion fallback.
$wixMatch = Select-String -Path $wixproj -Pattern '<SbzVersion[^>]*>([^<]+)</SbzVersion>' | Select-Object -First 1
if (-not $wixMatch) { throw "could not find SbzVersion in $wixproj" }
$wixVersion = $wixMatch.Matches.Groups[1].Value

$bundleMatch = Select-String -Path $bundle -Pattern '<SbzVersion[^>]*>([^<]+)</SbzVersion>' | Select-Object -First 1
if (-not $bundleMatch) { throw "could not find SbzVersion in $bundle" }
$bundleVersion = $bundleMatch.Matches.Groups[1].Value

Write-Host "Cargo workspace version : $cargoVersion"
Write-Host "WiX default SbzVersion   : $wixVersion"
Write-Host "Bundle default SbzVersion: $bundleVersion"

if ($cargoVersion -ne $wixVersion -or $cargoVersion -ne $bundleVersion) {
    Write-Error ("VERSION MISMATCH: Cargo '$cargoVersion', MSI WiX '$wixVersion', Bundle WiX '$bundleVersion'. " +
        "Update both installer project <SbzVersion> defaults (or pass -p:SbzVersion=$cargoVersion) " +
        "so the MSI ProductVersion and the binaries' reported version (version-gated admission, ADR 0011) agree.")
    exit 1
}

Write-Host "VERSION SYNC OK: Cargo and WiX ProductVersion agree ($cargoVersion)."
