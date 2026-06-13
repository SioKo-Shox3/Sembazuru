# M3.1.5 NT-rename observability gate.
#
# Proves the NtSetInformationFile hook closes the docs/trace-format.md §8 gap:
# clang-cl/lld write each output to a run-varying temp and rename it onto the
# final name via NtSetInformationFile(FileRenameInformation), which bypasses the
# Win32 MoveFile family. Without the NT hook the trace saw only the transient
# temp; with it, the surviving final artifact is discovered and the temp is
# excluded.
#
# This is a focused, compiler-independent check: a tiny probe reproduces lld's
# exact pattern (write-only temp handle, then the NT rename) so the mechanism is
# validated locally with only cl.exe available. The real clang-cl integration is
# gated by determinism.ps1 (no --output) in CI. The probe opens the temp
# WRITE-ONLY on purpose, to prove the source-path capture works on the same
# access shape lld uses.
#
# Requires cl.exe on PATH (a VS dev shell or msvc-dev-cmd in CI).
param(
    [string]$BuildDir  = (Join-Path $PSScriptRoot '..\build\Release'),
    [string]$TracerExe = (Join-Path $PSScriptRoot '..\..\target\release\sembazuru-trace.exe'),
    # Work area must NOT be under %TEMP%: the reader tags temp paths as
    # intermediates, which would hide the very artifacts this test inspects.
    [string]$WorkRoot  = (Join-Path $PSScriptRoot '..\build\nt-rename-work')
)
$ErrorActionPreference = 'Stop'

$launcher = Join-Path $BuildDir 'launcher.exe'
$dll      = Join-Path $BuildDir 'sbz_interceptor64.dll'
foreach ($f in @($launcher, $dll, $TracerExe)) {
    if (-not (Test-Path $f)) { throw "missing build artifact: $f" }
}
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
    throw 'cl.exe not on PATH (run from a VS dev shell or after msvc-dev-cmd)'
}

if (Test-Path $WorkRoot) { Remove-Item -Recurse -Force $WorkRoot }
New-Item -ItemType Directory -Force $WorkRoot | Out-Null

# A probe that mirrors lld's atomic-write: open a WRITE-ONLY temp, write bytes,
# then rename it onto the final name with NtSetInformationFile, exactly the path
# the Win32 hooks cannot see.
$probeSrc = @'
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

// SetFileInformationByHandle(FileRenameInfo, ...) is the documented Win32 entry
// that kernelbase forwards to NtSetInformationFile(FileRenameInformation) -- the
// same NT call lld issues directly. Either way our NT hook fires and sees the
// (NT-form) destination path. Using the documented struct keeps the probe
// honest and avoids hand-rolling an NT path.
int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        fwprintf(stderr, L"usage: rename_probe <temp> <final>\n");
        return 2;
    }
    const wchar_t* temp = argv[1];
    const wchar_t* finalDos = argv[2];

    // READ + WRITE + DELETE, like lld (it memory-maps the output buffer, so the
    // temp open carries read intent too). This exercises the path where the temp
    // lands in BOTH the input and output sets and the rename must clear both.
    HANDLE h = CreateFileW(temp, GENERIC_READ | GENERIC_WRITE | DELETE, 0,
                           nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                           nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"open fail %lu\n", GetLastError());
        return 1;
    }
    const char* data = "hello-nt-rename";
    DWORD wrote = 0;
    WriteFile(h, data, (DWORD)strlen(data), &wrote, nullptr);

    size_t nameBytes = wcslen(finalDos) * sizeof(wchar_t);
    size_t sz = sizeof(FILE_RENAME_INFO) + nameBytes;
    FILE_RENAME_INFO* ri = (FILE_RENAME_INFO*)calloc(1, sz);
    ri->ReplaceIfExists = TRUE;
    ri->RootDirectory = nullptr;
    ri->FileNameLength = (DWORD)nameBytes;  // bytes, excluding the NUL
    memcpy(ri->FileName, finalDos, nameBytes);

    BOOL ok = SetFileInformationByHandle(h, FileRenameInfo, ri, (DWORD)sz);
    DWORD err = GetLastError();
    CloseHandle(h);
    free(ri);
    if (!ok) {
        fwprintf(stderr, L"rename fail %lu\n", err);
        return 4;
    }
    wprintf(L"renamed ok\n");
    return 0;
}
'@
Set-Content (Join-Path $WorkRoot 'rename_probe.cpp') $probeSrc -Encoding ascii

Push-Location $WorkRoot
try {
    $out = & cl /nologo /EHsc 'rename_probe.cpp' 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $out; throw 'probe compile failed' }
} finally { Pop-Location }
$probe = Join-Path $WorkRoot 'rename_probe.exe'

$traceDir = Join-Path $WorkRoot 'trace'
New-Item -ItemType Directory -Force $traceDir | Out-Null
$temp  = Join-Path $WorkRoot 'out-915f50da.tmp'
$final = Join-Path $WorkRoot 'out.bin'

$env:SEMBAZURU_TRACE_DIR = $traceDir
try {
    $out = & $launcher $dll $probe $temp $final 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { Write-Host $out; throw "probe run exited $LASTEXITCODE" }
} finally {
    Remove-Item Env:\SEMBAZURU_TRACE_DIR -ErrorAction SilentlyContinue
}

if (-not (Test-Path $final)) {
    throw "the rename did not produce $final (probe or NT call failed)"
}

$g = (& $TracerExe export --trace-dir $traceDir --json | ConvertFrom-Json)
if ($LASTEXITCODE -ne 0) { throw 'tracer export failed' }

# Canonicalize the same way the reader does (resolve '..', etc.) before
# comparing: $WorkRoot may carry a '..' segment that the tracer has resolved.
$finalNorm = [System.IO.Path]::GetFullPath($final).ToLowerInvariant()
$tempNorm  = [System.IO.Path]::GetFullPath($temp).ToLowerInvariant()
# Wrap in @() before projecting: after the fix the input set can be empty, and
# piping a null .path projection would run the block once with $null.
$outs = @(@($g.outputs)   | ForEach-Object { $_.path.ToLowerInvariant() })
$ins  = @(@($g.inputs)    | ForEach-Object { $_.path.ToLowerInvariant() })
$dels = @(@($g.deletions) | ForEach-Object { $_.path.ToLowerInvariant() })

$failures = @()
if (-not ($outs -contains $finalNorm)) {
    $failures += "final artifact not discovered as an output: $finalNorm (outputs: $($outs -join ', '))"
}
if ($outs -contains $tempNorm) {
    $failures += "run-varying temp leaked into outputs: $tempNorm"
}
# The read+write temp open puts the temp in inputs too; the rename must clear it,
# or the run-varying name poisons the input hash (a cache key from M4 on).
if ($ins -contains $tempNorm) {
    $failures += "run-varying temp leaked into inputs: $tempNorm"
}
if (-not ($dels -contains $tempNorm)) {
    $failures += "renamed-away temp not recorded as a deletion: $tempNorm (deletions: $($dels -join ', '))"
}

if ($failures.Count -gt 0) {
    Write-Host ''
    Write-Host 'NT-RENAME GATE FAIL:'
    $failures | ForEach-Object { Write-Host "  - $_" }
    exit 1
}
Write-Host 'NT-RENAME GATE PASS (NtSetInformationFile rename observed; final discovered as output, temp excluded)'
