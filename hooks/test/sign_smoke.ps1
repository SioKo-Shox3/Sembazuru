# M7.2 Authenticode signing pipeline — MECHANISM validation with a placeholder cert.
#
# Ships the sign->verify machinery so a real release only swaps in a real
# certificate. The EDR-sensitive components (the injector launcher and the hook
# DLL) are the ones AV/EDR vendors scrutinize (docs/security/edr-allowlist.md),
# so signing them is what makes the vendor allowlist submission credible.
#
# A REAL release signs with an OV Authenticode certificate from an HSM/hardware
# token (CA/B Forum requires hardware key storage since 2023; ADR 0001 discusses
# the personal-developer path). That purchase is deferred (decider, M7.2). Here we
# prove the sign->verify mechanism end to end with an EPHEMERAL self-signed cert,
# trusted only for this run, so CI gates the pipeline without a real cert.
#
# Generic over whatever signable artifacts the build produced, so when the 32-bit
# interceptor lands (M7.3) it is signed automatically.
param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release')
)
$ErrorActionPreference = 'Stop'

# Our produced, distributable PE artifacts. The injector pieces come first because
# they carry the EDR-relevant TTPs (inline hook + DLL injection).
$names = @('launcher.exe', 'sbz_interceptor64.dll', 'sbz_interceptor32.dll')
$targets = $names | ForEach-Object { Join-Path $BuildDir $_ } | Where-Object { Test-Path $_ }
if ($targets.Count -eq 0) { throw "no signable artifacts under $BuildDir (build the hooks first)" }

# Ephemeral self-signed code-signing cert, valid for a day, trusted only here.
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject 'CN=Sembazuru CI Placeholder (NOT FOR RELEASE)' `
    -CertStoreLocation 'Cert:\CurrentUser\My' -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable -NotAfter (Get-Date).AddDays(1)

# What this gate proves with a PLACEHOLDER cert: the binary can be Authenticode-
# signed and the signature reads back as OURS (the signer thumbprint matches the
# cert we just signed with). It deliberately does NOT require a trusted chain
# (`Status -eq 'Valid'`): a self-signed cert terminates in an untrusted root, so
# `Get-AuthenticodeSignature` returns `UnknownError` by design. Chain validity is
# a property of the REAL OV certificate (from a CA), not of the sign->embed->read
# mechanism. A real release additionally runs `signtool verify /pa` to assert the
# trusted chain; here we assert the mechanism.
function Remove-FromStore($storeName, $thumbprint) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, 'CurrentUser')
        $store.Open('ReadWrite')
        $found = $store.Certificates | Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($found) { $store.Remove($found) }
        $store.Close()
    } catch {}
}

$failures = @()
try {
    foreach ($t in $targets) {
        $leaf = Split-Path $t -Leaf
        $res = Set-AuthenticodeSignature -FilePath $t -Certificate $cert -HashAlgorithm SHA256
        $v = Get-AuthenticodeSignature -FilePath $t
        $thumb = if ($v.SignerCertificate) { $v.SignerCertificate.Thumbprint } else { '(none)' }
        Write-Host "SIGNED ${leaf}: set=$($res.Status) verify=$($v.Status) signer=$thumb"
        # A signature must be present (not NotSigned) and be the one we applied.
        if ($v.Status -eq 'NotSigned') {
            $failures += "${leaf}: no signature was applied"
        } elseif (-not $v.SignerCertificate -or $v.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
            $failures += "${leaf}: signature is not from our cert (signer=$thumb)"
        }
    }
} finally {
    Remove-FromStore 'My' $cert.Thumbprint
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'M7.2 SIGNING GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host "M7.2 SIGNING GATE PASS (Authenticode sign+verify mechanism, placeholder cert) on $($targets.Count) artifact(s)"
