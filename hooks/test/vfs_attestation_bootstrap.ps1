# Shared VFS attestation bootstrap for the hook gates.
#
# A process started with SEMBAZURU_MODE=vfs refuses to run unless it can open
# the per-action attestation objects (hooks/src/vfs_attestation.*). That is the
# fail-closed rule that stops an uninstrumented child from reporting a remote
# success: the loader-attestation slot is what proves the hook actually loaded.
# In production the worker creates those objects; a gate that drives
# launcher.exe directly has to play the worker's part, or the launcher exits
# with "VFS bootstrap handles unavailable" before it injects anything.
#
# Dot-source this file, then wrap each VFS launch:
#
#     . (Join-Path $PSScriptRoot 'vfs_attestation_bootstrap.ps1')
#     $att = New-SbzVfsAttestation 'my-case'
#     try   { & $launcher $dll $target ... }
#     finally { Remove-SbzVfsAttestation $att }
#
# Layout must match `Header` and `Slot` in hooks/src/vfs_attestation.h:
#   Header: magic, version, maxSlots, slotCount, generation, corrupt (LONG each)
#   Slot:   generation, pid, attached (LONG each)

$script:SbzAttestationMagic = 0x53425A41   # "SBZA", vfs_attestation.h kMagic
$script:SbzAttestationVersion = 1
$script:SbzAttestationMaxSlots = 1024
$script:SbzAttestationBytes = 24 + $script:SbzAttestationMaxSlots * 12

if (-not ('SbzAttestationNative' -as [type])) {
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
}

function New-SbzVfsAttestation {
    <#
      .SYNOPSIS
      Creates one action's attestation objects and publishes them to the
      environment the launcher reads. Returns a handle to pass to
      Remove-SbzVfsAttestation.
    #>
    param([string]$Tag = 'gate')

    $suffix = [Guid]::NewGuid().ToString('N')
    $mappingName = "Local\Sembazuru.VfsAttestation.$suffix"
    $semaphoreName = "Local\Sembazuru.VfsFailure.$suffix"

    $mapping = [IntPtr]::Zero
    $view = [IntPtr]::Zero
    $semaphore = [IntPtr]::Zero
    try {
        $mapping = [SbzAttestationNative]::CreateFileMapping(
            [IntPtr](-1), [IntPtr]::Zero, 0x04, 0, $script:SbzAttestationBytes, $mappingName)
        $view = [SbzAttestationNative]::MapViewOfFile(
            $mapping, 0x06, 0, 0, [UIntPtr]::new([uint64]$script:SbzAttestationBytes))
        $semaphore = [SbzAttestationNative]::CreateSemaphore([IntPtr]::Zero, 0, $script:SbzAttestationMaxSlots, $semaphoreName)
        if ($mapping -eq [IntPtr]::Zero -or $view -eq [IntPtr]::Zero -or $semaphore -eq [IntPtr]::Zero) {
            throw "cannot create $Tag VFS attestation objects"
        }

        # The launcher opens these by value out of the environment, so the child
        # must inherit them.
        if (-not [SbzAttestationNative]::SetHandleInformation($mapping, 1, 1) -or
            -not [SbzAttestationNative]::SetHandleInformation($semaphore, 1, 1)) {
            throw "cannot make $Tag VFS bootstrap handles inheritable"
        }

        $generation = Get-Random -Minimum 1 -Maximum 2147483647
        [Runtime.InteropServices.Marshal]::WriteInt32($view, 0, $script:SbzAttestationMagic)
        [Runtime.InteropServices.Marshal]::WriteInt32($view, 4, $script:SbzAttestationVersion)
        [Runtime.InteropServices.Marshal]::WriteInt32($view, 8, $script:SbzAttestationMaxSlots)
        [Runtime.InteropServices.Marshal]::WriteInt32($view, 16, $generation)

        $env:SEMBAZURU_VFS_MAPPING_HANDLE = "$($mapping.ToInt64())"
        $env:SEMBAZURU_VFS_SEMAPHORE_HANDLE = "$($semaphore.ToInt64())"
        $env:SEMBAZURU_VFS_ATTESTATION_GENERATION = "$generation"

        return [pscustomobject]@{
            Tag        = $Tag
            Mapping    = $mapping
            View       = $view
            Semaphore  = $semaphore
            Generation = $generation
        }
    } catch {
        # Nothing was handed back, so the caller has no cleanup block covering
        # these yet. Release whatever was acquired before re-throwing.
        if ($view -ne [IntPtr]::Zero) { [SbzAttestationNative]::UnmapViewOfFile($view) | Out-Null }
        if ($mapping -ne [IntPtr]::Zero) { [SbzAttestationNative]::CloseHandle($mapping) | Out-Null }
        if ($semaphore -ne [IntPtr]::Zero) { [SbzAttestationNative]::CloseHandle($semaphore) | Out-Null }
        throw
    }
}

function Remove-SbzVfsAttestation {
    <#
      .SYNOPSIS
      Releases one action's attestation objects and unpublishes them. Safe to
      call with $null so it can sit in a finally block.
    #>
    param($Attestation)

    if (-not $Attestation) { return }
    [SbzAttestationNative]::UnmapViewOfFile($Attestation.View) | Out-Null
    [SbzAttestationNative]::CloseHandle($Attestation.Mapping) | Out-Null
    [SbzAttestationNative]::CloseHandle($Attestation.Semaphore) | Out-Null
    Remove-Item Env:\SEMBAZURU_VFS_MAPPING_HANDLE, Env:\SEMBAZURU_VFS_SEMAPHORE_HANDLE, `
        Env:\SEMBAZURU_VFS_ATTESTATION_GENERATION -ErrorAction SilentlyContinue
}

function Test-SbzVfsAttachments {
    <#
      .SYNOPSIS
      Returns a list of problems with the registry an action left behind, or an
      empty list when at least $Minimum processes registered as attached.
    #>
    param($Attestation, [int]$Minimum, [string]$Label)

    $problems = @()
    $count = [Runtime.InteropServices.Marshal]::ReadInt32($Attestation.View, 12)
    $corrupt = [Runtime.InteropServices.Marshal]::ReadInt32($Attestation.View, 20)
    if ($corrupt -ne 0 -or $count -lt $Minimum -or $count -gt $script:SbzAttestationMaxSlots) {
        return @("$Label attestation registry invalid (count=$count corrupt=$corrupt)")
    }
    for ($i = 0; $i -lt $count; ++$i) {
        $offset = 24 + 12 * $i
        $slotProcessId = [Runtime.InteropServices.Marshal]::ReadInt32($Attestation.View, $offset + 4)
        $attached = [Runtime.InteropServices.Marshal]::ReadInt32($Attestation.View, $offset + 8)
        if ($slotProcessId -le 0 -or $attached -ne 1) {
            $problems += "$Label missing VFS attachment at slot $i (pid=$slotProcessId attached=$attached)"
        }
    }
    return $problems
}
