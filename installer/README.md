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

## Runtime prerequisite on target machines (VC++ runtime)

The shipped Rust executables are **not** statically linked against the MSVC C runtime
(no `crt-static`; the workspace sets no `.cargo/config.toml` `target-feature`), so they
dynamically import `VCRUNTIME140.dll`. Verified with `dumpbin /dependents`:

```
> dumpbin /dependents target\release\sembazuru-gui.exe
    VCRUNTIME140.dll                     <-- part of the VC++ Redistributable
    api-ms-win-crt-runtime-l1-1-0.dll    <-- Universal CRT (ships with Windows 10+)
    api-ms-win-crt-{math,string,stdio,locale,heap}-l1-1-0.dll
```

The `api-ms-win-crt-*` (UCRT) forwarders are part of Windows 10/11, but `VCRUNTIME140.dll`
is **not guaranteed** on a clean machine — it comes with the **Microsoft Visual C++
2015–2022 Redistributable (x64)**. On a fresh target PC without it, the daemon/worker/GUI
fail to launch with a "VCRUNTIME140.dll was not found" error.

**Resolution (pick one — M12/A6 follow-up):**
1. **Bundle the redistributable in the MSI** (a WiX merge module / prerequisite), so a
   clean machine works out of the box. Recommended for a zero-friction installer.
2. **Statically link the CRT** via `.cargo/config.toml` `[target.x86_64-pc-windows-msvc] rustflags = ["-C", "target-feature=+crt-static"]`, removing the `VCRUNTIME140.dll`
   dependency entirely (slightly larger exes; validate all crates still build). Cleanest
   for a self-contained set.
3. **Document the prerequisite** and have users install the redistributable first (lowest
   effort, most friction — least preferred for a "zero-config" product).

Until one lands, note this in the release instructions so the first real-machine install
(M9.7) is not blocked by a missing runtime.

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
