# Sembazuru installer (WiX / MSI)

Builds the signed-capable Windows installer that bundles the daemon, worker,
build-system launcher, the resident GUI, and the C++ hook layer into one MSI
(ADR 0008 §1). The MSI only **packages** prebuilt binaries — it never participates
in the product's build path, so it stays compiler-agnostic (clang-cl is a
first-class target; MSVC is not assumed).

## Layout

- `sembazuru.wxs` — the package definition (binary placement, services, firewall,
  per-user GUI autostart, config init, uninstall).
- `Package.wixproj` — WiX v5 MSBuild SDK project. `dotnet build` restores the WiX
  SDK and extensions from NuGet; no global `wix` tool is required.

## Prerequisites

1. The product binaries must already be built (the MSI harvests, it does not build):
   - Rust: `cargo build --release` → `target/release/{sembazuru-daemon,sembazuru-worker,sembazuru,sembazuru-gui}.exe`
   - C++ hooks, both bitnesses, staged together (mirrors CI):
     ```
     cmake -S hooks -B hooks/build   -A x64   && cmake --build hooks/build   --config Release
     cmake -S hooks -B hooks/build32 -A Win32 && cmake --build hooks/build32 --config Release
     Copy-Item hooks/build32/Release/sbz_interceptor32.dll hooks/build/Release/ -Force
     ```
2. .NET SDK (provides `dotnet build`; the WiX v5 SDK is restored from NuGet).

## Build (unsigned)

From the repository root:

```
dotnet build installer/Package.wixproj -c Release -p:Platform=x64
```

The MSI is written to `installer/bin/x64/Release/Sembazuru.msi`.

Override sources/version for CI or out-of-tree builds:

```
dotnet build installer/Package.wixproj -c Release -p:Platform=x64 ^
  -p:SbzVersion=0.0.1 ^
  -p:SbzRustTarget=<dir with the Rust .exe set> ^
  -p:SbzHooks=<dir with launcher.exe + sbz_interceptor{64,32}.dll>
```

## Signing

The MSI is structured to be signed with `signtool` (Authenticode + RFC3161
timestamp): sign the individual `.exe`/`.dll` files **before** the build harvests
them, then sign the final `.msi`. A real OV/EV certificate is out of scope here
(M7 / release); CI produces an **unsigned** MSI as a green build gate. See
`hooks/test/sign_smoke.ps1` for the signing mechanism.
