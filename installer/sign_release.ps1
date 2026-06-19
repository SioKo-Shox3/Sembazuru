# Real-certificate Authenticode signing for a release (ADR 0008 / 0009).
#
# Signs each given file with the REAL release code-signing certificate and an
# RFC3161 timestamp, then asserts every signature reads back as VALID (a trusted
# chain). This is the release counterpart of hooks/test/sign_smoke.ps1, which only
# proves the sign->verify *mechanism* with an ephemeral self-signed cert and so
# accepts an untrusted chain. Here we require `Valid`, because the whole point of a
# release is a publicly trusted signature — and because the GUI self-update
# (crates/gui/src/verify) refuses to run an MSI whose Authenticode does not validate
# and whose publisher does not match the pin.
#
# The cert is supplied as a base64 PFX (works for a software OV cert or for testing
# the pipeline). NOTE: a real OV cert is required by the CA/Browser Forum to live on
# an HSM / hardware token (ADR 0006), whose private key cannot be exported to a PFX.
# For that, swap THIS step for the signing provider's tool — Azure Trusted Signing,
# DigiCert KeyLocker, or `signtool` with the token's KSP — keeping the same contract:
# sign the listed files, then verify each is `Valid`. The release workflow only calls
# this script when a signing secret is configured; with no secret it skips signing
# and publishes a draft (so self-update never consumes an unsigned MSI).
param(
    [Parameter(Mandatory)][string[]]$Files,
    # Base64-encoded PFX (from a CI secret).
    [Parameter(Mandatory)][string]$PfxBase64,
    [string]$Password = '',
    # RFC3161 timestamp authority URL (strongly recommended so signatures outlive the
    # cert's validity, e.g. http://timestamp.digicert.com). Empty = no timestamp.
    [string]$TimestampServer = ''
)
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($PfxBase64)) {
    throw 'no signing certificate provided (PfxBase64 is empty)'
}

# Load the cert with an EPHEMERAL key set so nothing is persisted to a machine/user
# store on the runner. The private key lives only for this process.
$pfxBytes = [Convert]::FromBase64String($PfxBase64)
$flags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfxBytes, $Password, $flags)
if (-not $cert.HasPrivateKey) {
    throw 'the signing certificate has no usable private key'
}
Write-Host "Signing with: $($cert.Subject) (thumbprint $($cert.Thumbprint))"

$failures = @()
foreach ($f in $Files) {
    if (-not (Test-Path $f)) { throw "file to sign not found: $f" }
    $leaf = Split-Path $f -Leaf
    $signArgs = @{ FilePath = $f; Certificate = $cert; HashAlgorithm = 'SHA256' }
    if ($TimestampServer) { $signArgs['TimestampServer'] = $TimestampServer }
    $res = Set-AuthenticodeSignature @signArgs
    $v = Get-AuthenticodeSignature -FilePath $f
    $ts = if ($v.TimeStamperCertificate) { 'timestamped' } else { 'no-ts' }
    Write-Host "SIGNED ${leaf}: set=$($res.Status) verify=$($v.Status) $ts"
    # A release requires a fully VALID signature (present + trusted chain). A real OV
    # cert chains to a public CA root trusted on the Windows runner.
    if ($v.Status -ne 'Valid') {
        $failures += "${leaf}: signature status is '$($v.Status)' (expected 'Valid')"
    }
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'RELEASE SIGNING FAILED:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host "RELEASE SIGNING OK: $($Files.Count) artifact(s) signed and chain-valid."
