# Release-hygiene gate (ADR 0009): the workspace Cargo version and the installer's
# default WiX ProductVersion (SbzVersion) must agree.
#
# Why this matters: the GUI self-update compares the latest GitHub release tag
# against CARGO_PKG_VERSION (the Cargo version), while the installed MSI advertises
# its own ProductVersion (SbzVersion) for MajorUpgrade. If the two drift, a freshly
# built release reports one version to the updater and another to Windows Installer,
# so the update check and the in-place upgrade disagree. Run this in CI / before a
# release; a non-zero exit means "reconcile the versions before shipping".
#
# Note: CI may pass -p:SbzVersion=<cargo version> explicitly (the recommended path);
# this gate checks the *default* in Package.wixproj so the checked-in fallback never
# silently lags the crate version.
$ErrorActionPreference = 'Stop'

$root    = Split-Path -Parent $PSScriptRoot
$cargo   = Join-Path $root 'Cargo.toml'
$wixproj = Join-Path $PSScriptRoot 'Package.wixproj'

foreach ($f in @($cargo, $wixproj)) {
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

Write-Host "Cargo workspace version : $cargoVersion"
Write-Host "WiX default SbzVersion   : $wixVersion"

if ($cargoVersion -ne $wixVersion) {
    Write-Error ("VERSION MISMATCH: Cargo '$cargoVersion' != WiX SbzVersion '$wixVersion'. " +
        "Update installer/Package.wixproj's <SbzVersion> default (or pass -p:SbzVersion=$cargoVersion) " +
        "so the self-update check and the MSI ProductVersion agree (ADR 0009).")
    exit 1
}

Write-Host "VERSION SYNC OK: Cargo and WiX ProductVersion agree ($cargoVersion)."
