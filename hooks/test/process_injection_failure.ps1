param(
    [string]$BuildDir = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$Launcher = (Join-Path $BuildDir 'launcher.exe'),
    [string]$Interceptor = (Join-Path $BuildDir 'sbz_interceptor64.dll'),
    [string]$ParentExe = (Join-Path $BuildDir 'process_injection_failure_probe.exe'),
    [string]$ChildExe = (Join-Path $PSScriptRoot '..\build32\Release\process_injection_failure_probe.exe'),
    [string]$WorkRoot = (Join-Path $PSScriptRoot '..\build\process-injection-failure')
)
$ErrorActionPreference = 'Stop'

foreach ($artifact in @($Launcher, $Interceptor, $ParentExe, $ChildExe)) {
    if (-not (Test-Path $artifact)) { throw "missing build artifact: $artifact" }
}

$WorkRoot = [System.IO.Path]::GetFullPath($WorkRoot)
if (Test-Path $WorkRoot) { Remove-Item -LiteralPath $WorkRoot -Recurse -Force }
New-Item -ItemType Directory -Path $WorkRoot | Out-Null

$saved = @{}
foreach ($name in @('SEMBAZURU_MODE', 'SEMBAZURU_VFS_ROOT', 'SEMBAZURU_VFS_PIPE',
                     'SEMBAZURU_VFS_SCRATCH', 'SEMBAZURU_TRACE_DIR',
                     'SEMBAZURU_VFS_MAPPING_HANDLE', 'SEMBAZURU_VFS_SEMAPHORE_HANDLE',
                     'SEMBAZURU_VFS_ATTESTATION_GENERATION')) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SbzAttestationNative {
  [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFileMapping(IntPtr file, IntPtr attributes,
      uint protect, uint high, uint low, string name);
  [DllImport("kernel32", SetLastError=true)]
  public static extern IntPtr MapViewOfFile(IntPtr mapping, uint access,
      uint high, uint low, UIntPtr bytes);
  [DllImport("kernel32", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateSemaphore(IntPtr attributes, int initial,
      int maximum, string name);
  [DllImport("kernel32", SetLastError=true)] public static extern bool UnmapViewOfFile(IntPtr view);
  [DllImport("kernel32", SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32", SetLastError=true)] public static extern bool SetHandleInformation(
      IntPtr handle, uint mask, uint flags);
}
'@

$script:attestation = $null
function Set-VfsAttestation([string]$tag) {
    if ($script:attestation) {
        [SbzAttestationNative]::UnmapViewOfFile($script:attestation.view) | Out-Null
        [SbzAttestationNative]::CloseHandle($script:attestation.mapping) | Out-Null
        [SbzAttestationNative]::CloseHandle($script:attestation.semaphore) | Out-Null
    }
    $suffix = ([Guid]::NewGuid().ToString('N'))
    $mappingName = "Local\Sembazuru.VfsAttestation.$suffix"
    $semaphoreName = "Local\Sembazuru.VfsFailure.$suffix"
    $bytes = 24 + 1024 * 12
    $mapping = [SbzAttestationNative]::CreateFileMapping([IntPtr](-1), [IntPtr]::Zero,
        0x04, 0, $bytes, $mappingName)
    $view = [SbzAttestationNative]::MapViewOfFile(
        $mapping, 0x06, 0, 0, [UIntPtr]::new([uint64]$bytes))
    $semaphore = [SbzAttestationNative]::CreateSemaphore([IntPtr]::Zero, 0, 1024, $semaphoreName)
    if ($mapping -eq [IntPtr]::Zero -or $view -eq [IntPtr]::Zero -or $semaphore -eq [IntPtr]::Zero) {
        throw "cannot create $tag VFS attestation objects"
    }
    if (-not [SbzAttestationNative]::SetHandleInformation($mapping, 1, 1) -or
        -not [SbzAttestationNative]::SetHandleInformation($semaphore, 1, 1)) {
        throw "cannot make $tag VFS bootstrap handles inheritable"
    }
    $generation = Get-Random -Minimum 1 -Maximum 2147483647
    [Runtime.InteropServices.Marshal]::WriteInt32($view, 0, 0x53425A41)
    [Runtime.InteropServices.Marshal]::WriteInt32($view, 4, 1)
    [Runtime.InteropServices.Marshal]::WriteInt32($view, 8, 1024)
    [Runtime.InteropServices.Marshal]::WriteInt32($view, 16, $generation)
    $env:SEMBAZURU_VFS_MAPPING_HANDLE = "$($mapping.ToInt64())"
    $env:SEMBAZURU_VFS_SEMAPHORE_HANDLE = "$($semaphore.ToInt64())"
    $env:SEMBAZURU_VFS_ATTESTATION_GENERATION = "$generation"
    $script:attestation = @{ mapping = $mapping; view = $view; semaphore = $semaphore }
}

function Test-VfsAttachments([int]$minimum, [string]$label) {
    $count = [Runtime.InteropServices.Marshal]::ReadInt32($script:attestation.view, 12)
    $corrupt = [Runtime.InteropServices.Marshal]::ReadInt32($script:attestation.view, 20)
    if ($corrupt -ne 0 -or $count -lt $minimum -or $count -gt 1024) {
        $script:failures += "$label attestation registry invalid (count=$count corrupt=$corrupt)"
        return
    }
    for ($i = 0; $i -lt $count; ++$i) {
        $offset = 24 + 12 * $i
        $slotProcessId = [Runtime.InteropServices.Marshal]::ReadInt32($script:attestation.view, $offset + 4)
        $attached = [Runtime.InteropServices.Marshal]::ReadInt32($script:attestation.view, $offset + 8)
        if ($slotProcessId -le 0 -or $attached -ne 1) {
            $script:failures += "$label missing VFS attachment at slot $i (pid=$slotProcessId attached=$attached)"
        }
    }
}

$failures = @()
$failClosedExit = 0x534249
$oldNativeEap = $null
$hasNativeEap = Get-Variable PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue
if ($hasNativeEap) {
    $oldNativeEap = $PSNativeCommandUseErrorActionPreference
    $PSNativeCommandUseErrorActionPreference = $false
}
try {
    foreach ($api in @('w', 'a')) {
        $case = Join-Path $WorkRoot $api
        $scratch = Join-Path $case 'scratch'
        $logical = Join-Path $case 'logical'
        New-Item -ItemType Directory -Force $scratch, $logical | Out-Null
        $dllCopy = Join-Path $case 'sbz_interceptor64.dll'
        Copy-Item -LiteralPath $Interceptor -Destination $dllCopy
        $sentinel = Join-Path $case 'child-ran.sentinel'

        $env:SEMBAZURU_MODE = 'vfs'
        $env:SEMBAZURU_VFS_ROOT = $logical
        $env:SEMBAZURU_VFS_PIPE = "sbz-missing-injection-test-$api"
        $env:SEMBAZURU_VFS_SCRATCH = $scratch
        Set-VfsAttestation "missing-$api"
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue

        # The parent is x64 and the child is x86. Keeping only the temporary
        # sbz_interceptor64.dll beside the parent forces Detours' real
        # cross-bitness sibling lookup to fail without modifying any artifact.
        & $Launcher $dllCopy $ParentExe "--parent-$api" $ChildExe $sentinel
        $exit = $LASTEXITCODE
        $marker = Join-Path $scratch '.sbz-unvirtualized'
        if ($exit -ne $failClosedExit) {
            $failures += "CreateProcess$($api.ToUpperInvariant()) did not terminate the action after injection failure (exit=$exit)"
        }
        if (Test-Path $sentinel) {
            $failures += "CreateProcess$($api.ToUpperInvariant()) ran the uninstrumented child after injection failure"
        }
        if (-not (Test-Path $marker)) {
            $failures += "CreateProcess$($api.ToUpperInvariant()) injection failure did not leave .sbz-unvirtualized"
        }
        Test-VfsAttachments 1 "CreateProcess$($api.ToUpperInvariant()) failure"
    }

    foreach ($api in @('w', 'a')) {
        $case = Join-Path $WorkRoot "success-$api"
        $scratch = Join-Path $case 'scratch'
        $logical = Join-Path $case 'logical'
        New-Item -ItemType Directory -Force $scratch, $logical | Out-Null
        $dllCopy = Join-Path $case 'sbz_interceptor64.dll'
        Copy-Item -LiteralPath $Interceptor -Destination $dllCopy
        $sentinel = Join-Path $case 'child-ran-with-hook.sentinel'

        $env:SEMBAZURU_MODE = 'vfs'
        $env:SEMBAZURU_VFS_ROOT = $logical
        $env:SEMBAZURU_VFS_PIPE = "sbz-unused-injection-success-$api"
        $env:SEMBAZURU_VFS_SCRATCH = $scratch
        Set-VfsAttestation "success-$api"
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue

        & $Launcher $dllCopy $ParentExe "--parent-success-$api" $ParentExe $sentinel
        $exit = $LASTEXITCODE
        if ($exit -ne 20) {
            $failures += "same-bitness CreateProcess$($api.ToUpperInvariant()) did not run a child with the hook module loaded (exit=$exit)"
        }
        if (-not (Test-Path $sentinel)) {
            $failures += "same-bitness CreateProcess$($api.ToUpperInvariant()) did not prove module-loaded child execution"
        }
        if (Test-Path (Join-Path $scratch '.sbz-unvirtualized')) {
            $failures += "same-bitness CreateProcess$($api.ToUpperInvariant()) left an unexpected fallback marker"
        }
        Test-VfsAttachments 2 "CreateProcess$($api.ToUpperInvariant()) success"
    }

    foreach ($api in @('w', 'a')) {
        $case = Join-Path $WorkRoot "custom-env-$api"
        $scratch = Join-Path $case 'scratch'
        $logical = Join-Path $case 'logical'
        New-Item -ItemType Directory -Force $scratch, $logical | Out-Null
        $dllCopy = Join-Path $case 'sbz_interceptor64.dll'
        Copy-Item -LiteralPath $Interceptor -Destination $dllCopy
        $sentinel = Join-Path $case 'child-must-not-run.sentinel'

        $env:SEMBAZURU_MODE = 'vfs'
        $env:SEMBAZURU_VFS_ROOT = $logical
        $env:SEMBAZURU_VFS_PIPE = "sbz-unused-custom-env-$api"
        $env:SEMBAZURU_VFS_SCRATCH = $scratch
        Set-VfsAttestation "custom-$api"
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue

        & $Launcher $dllCopy $ParentExe "--parent-custom-$api" $ParentExe $sentinel
        $exit = $LASTEXITCODE
        if ($exit -ne 20) {
            $failures += "custom-environment CreateProcess$($api.ToUpperInvariant()) did not preserve VFS payload propagation (exit=$exit)"
        }
        if (-not (Test-Path $sentinel)) {
            $failures += "custom-environment CreateProcess$($api.ToUpperInvariant()) did not run the payload-attested child"
        }
        if (Test-Path (Join-Path $scratch '.sbz-unvirtualized')) {
            $failures += "custom-environment CreateProcess$($api.ToUpperInvariant()) unexpectedly left a fallback marker"
        }
    }

    foreach ($api in @('w', 'a')) {
        $case = Join-Path $WorkRoot "marker-failure-$api"
        $logical = Join-Path $case 'logical'
        New-Item -ItemType Directory -Force $case, $logical | Out-Null
        $scratchFile = Join-Path $case 'scratch-is-a-file'
        Set-Content -LiteralPath $scratchFile -Value 'not a directory' -NoNewline
        $dllCopy = Join-Path $case 'sbz_interceptor64.dll'
        Copy-Item -LiteralPath $Interceptor -Destination $dllCopy
        $sentinel = Join-Path $case 'child-must-not-run.sentinel'

        $env:SEMBAZURU_MODE = 'vfs'
        $env:SEMBAZURU_VFS_ROOT = $logical
        $env:SEMBAZURU_VFS_PIPE = "sbz-missing-marker-failure-$api"
        $env:SEMBAZURU_VFS_SCRATCH = $scratchFile
        Set-VfsAttestation "marker-$api"
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue

        & $Launcher $dllCopy $ParentExe "--parent-$api" $ChildExe $sentinel
        $exit = $LASTEXITCODE
        if ($exit -ne $failClosedExit) {
            $failures += "marker-unwritable CreateProcess$($api.ToUpperInvariant()) did not terminate with fail-closed exit (exit=$exit)"
        }
        if (Test-Path $sentinel) {
            $failures += "marker-unwritable CreateProcess$($api.ToUpperInvariant()) ran the child"
        }
    }

    foreach ($api in @('w', 'a')) {
        $case = Join-Path $WorkRoot "observe-$api"
        $trace = Join-Path $case 'trace'
        New-Item -ItemType Directory -Force $case, $trace | Out-Null
        $dllCopy = Join-Path $case 'sbz_interceptor64.dll'
        Copy-Item -LiteralPath $Interceptor -Destination $dllCopy
        $sentinel = Join-Path $case 'child-ran.sentinel'

        Remove-Item Env:\SEMBAZURU_MODE, Env:\SEMBAZURU_VFS_ROOT, `
            Env:\SEMBAZURU_VFS_PIPE, Env:\SEMBAZURU_VFS_SCRATCH `
            -ErrorAction SilentlyContinue
        $env:SEMBAZURU_TRACE_DIR = $trace

        & $Launcher $dllCopy $ParentExe "--parent-$api" $ChildExe $sentinel
        $exit = $LASTEXITCODE
        if ($exit -ne 20) {
            $failures += "observe-only CreateProcess$($api.ToUpperInvariant()) did not preserve uninstrumented retry (exit=$exit)"
        }
        if (-not (Test-Path $sentinel)) {
            $failures += "observe-only CreateProcess$($api.ToUpperInvariant()) did not run the fallback child"
        }
    }

    foreach ($api in @('w', 'a')) {
        $case = Join-Path $WorkRoot "observe-custom-env-$api"
        $trace = Join-Path $case 'trace'
        New-Item -ItemType Directory -Force $case, $trace | Out-Null
        $dllCopy = Join-Path $case 'sbz_interceptor64.dll'
        Copy-Item -LiteralPath $Interceptor -Destination $dllCopy
        $sentinel = Join-Path $case 'child-ran-with-hook.sentinel'

        Remove-Item Env:\SEMBAZURU_MODE, Env:\SEMBAZURU_VFS_ROOT, `
            Env:\SEMBAZURU_VFS_PIPE, Env:\SEMBAZURU_VFS_SCRATCH `
            -ErrorAction SilentlyContinue
        $env:SEMBAZURU_TRACE_DIR = $trace

        & $Launcher $dllCopy $ParentExe "--parent-custom-$api" $ParentExe $sentinel
        $exit = $LASTEXITCODE
        if ($exit -ne 20) {
            $failures += "observe-only custom-environment CreateProcess$($api.ToUpperInvariant()) did not preserve injection (exit=$exit)"
        }
        if (-not (Test-Path $sentinel)) {
            $failures += "observe-only custom-environment CreateProcess$($api.ToUpperInvariant()) did not run the injected child"
        }
    }
} finally {
    if ($script:attestation) {
        [SbzAttestationNative]::UnmapViewOfFile($script:attestation.view) | Out-Null
        [SbzAttestationNative]::CloseHandle($script:attestation.mapping) | Out-Null
        [SbzAttestationNative]::CloseHandle($script:attestation.semaphore) | Out-Null
    }
    if ($hasNativeEap) { $PSNativeCommandUseErrorActionPreference = $oldNativeEap }
    foreach ($entry in $saved.GetEnumerator()) {
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
    }
}

if ($failures.Count -gt 0) {
    Write-Host 'PROCESS INJECTION FAILURE GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'PROCESS INJECTION FAILURE GATE PASS (same-bit payload injection loaded; VFS W/A fail closed on cross-bitness failure; custom environments preserve payload propagation; observe-only retry and custom environment preserved)'
