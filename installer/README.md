# Sembazuru Windows installer

This directory contains two WiX 5.0.2 projects:

- `Package.wixproj` builds `Sembazuru.msi`, which installs the daemon, worker,
  build-system launcher, GUI, and C++ hook layer. It embeds
  `sembazuru-storectl.exe` as an MSI Binary for machine-store custom actions;
  the helper is not installed as a product file.
- `Bundle.wixproj` builds `Sembazuru-Setup.exe`, a standard Burn bootstrapper
  that embeds the Microsoft Visual C++ runtimes and the MSI.

`Setup.exe` is the end-user entry point on 64-bit Windows. It installs the x64
VC++ runtime, the x86 VC++ runtime, and then Sembazuru. Both runtime packages are
permanent prerequisites; Burn reads each architecture's VC runtime registry
version when `Installed=1` and skips a runtime when that version is equal to or
newer than the bundled version. Removing Sembazuru does not remove a runtime
that may be shared by other applications.

The bundled runtimes are the Microsoft Visual C++ 2015–2022 Redistributable:

- [Microsoft supported downloads](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)
- [x64 installer](https://aka.ms/vc14/vc_redist.x64.exe)
- [x86 installer](https://aka.ms/vc14/vc_redist.x86.exe)

`prepare_redist.ps1` verifies each file's Authenticode signature, requires the
signer to be Microsoft Corporation, checks a numeric four-part product version,
and writes the verified paths and versions to
`target/installer/redist/Sembazuru.Redist.props`. With no arguments it downloads
the two official installers. An offline build can pass both local paths:

```powershell
pwsh -NoProfile -File installer/prepare_redist.ps1 `
  -X64Path 'C:\path\to\vc_redist.x64.exe' `
  -X86Path 'C:\path\to\vc_redist.x86.exe'
```

## Build

The build environment needs the .NET SDK, Rust, CMake, and both native hook
configurations. End users only need Windows 10/11 x64; they do not need the
development toolchain when using `Setup.exe`.

Build the release binaries and stage both hook DLLs as usual. The MSI also
requires the `sembazuru-config-store` package because it supplies the
`sembazuru-storectl.exe` helper embedded for machine-store custom actions:

```powershell
cargo build --release -p sembazuru-agent -p sembazuru-worker `
  -p sembazuru-gui -p sembazuru-config-store
cmake -S hooks -B hooks/build -A x64
cmake --build hooks/build --config Release
cmake -S hooks -B hooks/build32 -A Win32
cmake --build hooks/build32 --config Release
Copy-Item hooks/build32/Release/sbz_interceptor32.dll hooks/build/Release/ -Force
```

Build the MSI first, then prepare the runtimes and build the Bundle:

```powershell
dotnet build installer/Package.wixproj -c Release -p:Platform=x64 -p:SbzVersion=0.0.3
pwsh -NoProfile -File installer/prepare_redist.ps1
dotnet build installer/Bundle.wixproj -c Release -p:Platform=x64 -p:SbzVersion=0.0.3
```

The outputs are `installer/bin/x64/Release/Sembazuru.msi` and
`installer/bin/x64/Release/Sembazuru-Setup.exe`. Override the input paths for an
out-of-tree build with `-p:SbzMsi=...`, `-p:SbzVCRedistX64=...`, and
`-p:SbzVCRedistX86=...`; the corresponding four-part runtime versions can be
passed as `-p:SbzVCRedistX64Version=...` and `-p:SbzVCRedistX86Version=...`.
`SbzMsi` accepts a repository-relative or absolute path.

The checked-in defaults for Cargo, the MSI, and the Bundle must agree. Run the
version gate before packaging:

```powershell
pwsh -NoProfile -File installer/check_version_sync.ps1
```

## Upgrade and signing behavior

The MSI keeps its existing Windows Installer product family and
`MajorUpgrade` rule, but its launch condition blocks upgrades. Uninstall an
existing Sembazuru installation first, then run the new `Setup.exe`; an MSI
downgrade is rejected. The Burn Bundle has its own fixed upgrade family for
identifying Bundle registrations. Installing an MSI by itself does not
register a Bundle.

Unsigned builds are supported. For a signed release, sign the staged PE files
before building the MSI, sign the MSI, and build the Bundle with WiX's standard
Burn signing targets. The release workflow supplies the certificate only in the
process environment and signs both the detached Burn engine and the outer
`Setup.exe`:

```powershell
$env:SBZ_SIGNING_PFX_BASE64 = '<base64 PFX>'
$env:SBZ_SIGNING_PASSWORD = '<PFX password>'
$env:SBZ_TIMESTAMP_URL = 'http://timestamp.digicert.com'
dotnet build installer/Bundle.wixproj -c Release -p:Platform=x64 `
  -p:SbzVersion=0.0.3 -p:SignOutput=true
```

The release workflow names the assets
`Sembazuru-X.Y.Z-x64.msi` and `Sembazuru-X.Y.Z-x64-Setup.exe`. A build without a
release certificate remains unsigned and follows the existing draft-release
policy.
