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
                     'SEMBAZURU_VFS_SCRATCH', 'SEMBAZURU_TRACE_DIR')) {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
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
        Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue

        & $Launcher $dllCopy $ParentExe "--parent-custom-$api" $ParentExe $sentinel
        $exit = $LASTEXITCODE
        if ($exit -ne $failClosedExit) {
            $failures += "custom-environment CreateProcess$($api.ToUpperInvariant()) did not terminate the VFS action (exit=$exit)"
        }
        if (Test-Path $sentinel) {
            $failures += "custom-environment CreateProcess$($api.ToUpperInvariant()) ran the child"
        }
        if (-not (Test-Path (Join-Path $scratch '.sbz-unvirtualized'))) {
            $failures += "custom-environment CreateProcess$($api.ToUpperInvariant()) did not leave .sbz-unvirtualized"
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
Write-Host 'PROCESS INJECTION FAILURE GATE PASS (same-bit injection loaded; VFS W/A and custom environment fail closed; marker failure terminated; observe-only retry and custom environment preserved)'
