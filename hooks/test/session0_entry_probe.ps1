#requires -Version 7.0
<#
.SYNOPSIS
固定終了値だけを返す x64 診断 EXE をビルドし、PE と通常ローカル子を検査する。
.DESCRIPTION
成果物は .harness/T-011-entry-probe/ に限定する。-BuildOnly はビルドと PE 検査を行う。
-Verify は独立2ビルドと BuildOnly の全バイト一致、15秒以内の終了と空出力を検査する。
0x53425a45 の観測だけをこの EXE の entry 到達の肯定証拠とする。
未観測は entry 前と終了処理の失敗を区別しない。Session 0 や cmd の成功を意味しない。
#>
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Verify')][switch]$Verify,
    [Parameter(Mandatory, ParameterSetName = 'BuildOnly')][switch]$BuildOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$root = Join-Path $repo '.harness/T-011-entry-probe'
$source = Join-Path $PSScriptRoot 'session0_entry_probe.cpp'
$executable = Join-Path $root 'session0_entry_probe.exe'

function Invoke-BuildTool([string]$File, [string[]]$Arguments, [string]$Log) {
    $output = & $File @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    [IO.File]::WriteAllText($Log, $output + "EXIT_CODE=$code`n")
    Write-Host $output.TrimEnd()
    if ($code -ne 0) { throw "ビルド用ツールが失敗しました: $File (exit=$code)" }
    return $output
}

function Build-Probe([string]$Directory) {
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $obj = Join-Path $Directory 'session0_entry_probe.obj'
    $exe = Join-Path $Directory 'session0_entry_probe.exe'
    # 入力もバッファもない専用 entry に CRT cookie 初期化を持ち込まない。
    $compile = @('/nologo', '/c', '/O1', '/W4', '/WX', '/utf-8', '/GS-', '/GR-', '/Zl', '/Brepro',
        "/Fo$obj", $source)
    $null = Invoke-BuildTool $script:compiler $compile (Join-Path $Directory 'compile.txt')
    $link = @('/nologo', '/MACHINE:X64', '/SUBSYSTEM:CONSOLE', '/ENTRY:ProbeEntry', '/NODEFAULTLIB',
        '/INCREMENTAL:NO', '/Brepro', '/DYNAMICBASE', '/HIGHENTROPYVA', '/NXCOMPAT',
        "/OUT:$exe", $obj, 'kernel32.lib')
    $null = Invoke-BuildTool $script:linker $link (Join-Path $Directory 'link.txt')
    return $exe
}

function Test-ProbePe([string]$Exe, [string]$Directory) {
    $headers = Invoke-BuildTool $script:dumpbin @('/nologo', '/headers', $Exe) (Join-Path $Directory 'headers.txt')
    $imports = Invoke-BuildTool $script:dumpbin @('/nologo', '/imports', $Exe) (Join-Path $Directory 'imports.txt')
    $null = Invoke-BuildTool $script:dumpbin @('/nologo', '/disasm', $Exe) (Join-Path $Directory 'disasm.txt')
    if ($headers -notmatch '(?m)^\s*8664 machine \(x64\)\s*$' -or
        $headers -notmatch '(?m)^\s*20B magic # \(PE32\+\)\s*$' -or
        $headers -notmatch '(?m)^\s*[0-9A-F]*[1-9A-F][0-9A-F]* entry point ' -or
        $headers -notmatch '(?m)^\s*0 \[\s*0\] RVA \[size\] of Delay Import Directory\s*$' -or
        $headers -notmatch '(?m)^\s*0 \[\s*0\] RVA \[size\] of Thread Storage Directory\s*$' -or
        $headers -notmatch '(?m)^\s*[0-9A-F]+ \[\s*10\] RVA \[size\] of Import Address Table Directory\s*$') {
        throw 'PE の x64/entry/遅延 import/TLS/単一 import 条件が一致しません。'
    }
    $dlls = @([regex]::Matches($imports, '(?im)^\s*([^\s]+\.dll)\s*$') | ForEach-Object { $_.Groups[1].Value })
    $functions = @([regex]::Matches($imports, '(?m)^\s+[0-9A-F]+ ([A-Za-z_][A-Za-z_0-9]*)\s*$') |
        ForEach-Object { $_.Groups[1].Value })
    if ($dlls.Count -ne 1 -or $dlls[0] -cne 'KERNEL32.dll' -or
        $functions.Count -ne 1 -or $functions[0] -cne 'ExitProcess') {
        throw '静的 import は Kernel32 の ExitProcess だけである必要があります。'
    }
    Write-Host 'PE_IMPORTS=KERNEL32.dll!ExitProcess DELAY_IMPORTS=none TLS=none MACHINE=x64'
}

function Assert-SameBytes([string]$First, [string]$Second) {
    $a = [IO.File]::ReadAllBytes($First)
    $b = [IO.File]::ReadAllBytes($Second)
    if ($a.Length -ne $b.Length) { throw '比較する EXE のサイズが異なります。' }
    for ($i = 0; $i -lt $a.Length; ++$i) {
        if ($a[$i] -ne $b[$i]) { throw "EXE が位置 $i で異なります。" }
    }
    Write-Host "BYTE_IDENTICAL=True BYTES=$($a.Length) SHA256=$((Get-FileHash -LiteralPath $First -Algorithm SHA256).Hash)"
}

function Test-LocalProbe {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $executable
    $start.WorkingDirectory = $root
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    $watch = [Diagnostics.Stopwatch]::new()
    $streams = @()
    try {
        $watch.Start()
        $started = $process.Start()
        if (-not $started) { throw '診断プロセスを開始できませんでした。' }
        # 空出力が契約なので、両方を同時に1バイトだけ読み、1バイトでも出れば拒否する。
        foreach ($reader in @($process.StandardOutput, $process.StandardError)) {
            $buffer = [byte[]]::new(1)
            $streams += [pscustomobject]@{ Stream = $reader.BaseStream; Buffer = $buffer; Count = 0; Eof = $false
                Pending = $reader.BaseStream.ReadAsync($buffer, 0, 1) }
        }
        while ($true) {
            if ($watch.ElapsedMilliseconds -ge 15000) { throw '診断プロセスまたは出力回収が15秒の期限を超えました。' }
            foreach ($s in $streams) {
                if (-not $s.Eof -and $s.Pending.IsCompleted) {
                    $s.Count = $s.Pending.GetAwaiter().GetResult()
                    if ($s.Count -ne 0) { throw '診断プロセスの出力が空ではありません。' }
                    $s.Eof = $true
                }
            }
            if ($process.HasExited -and $streams[0].Eof -and $streams[1].Eof) { break }
            Start-Sleep -Milliseconds 10
        }
        $watch.Stop()
        # .NET の符号付き値を、観測した32bitのまま記録する。
        $exitCode = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$process.ExitCode), 0)
        $exitHex = '0x{0:x8}' -f $exitCode
        $result = "CHILD_EXIT=$exitCode CHILD_EXIT_HEX=$exitHex STDOUT_BYTES=0 STDERR_BYTES=0`n" +
            "DEADLINE_MS=15000 ELAPSED_MS=$($watch.ElapsedMilliseconds) STDOUT_EOF=True STDERR_EOF=True`n"
        [IO.File]::WriteAllBytes((Join-Path $root 'local-stdout.bin'), [byte[]]::new(0))
        [IO.File]::WriteAllBytes((Join-Path $root 'local-stderr.bin'), [byte[]]::new(0))
        [IO.File]::WriteAllText((Join-Path $root 'local-result.txt'), $result)
        Write-Host $result.TrimEnd()
        if ($exitCode -ne [uint32]0x53425a45) {
            throw '固定終了値を観測できませんでした。entry 前と終了処理の失敗は区別できません。'
        }
        Write-Host 'LOCAL_ENTRY_OBSERVED=True'
    } finally {
        try {
            if ($started -and -not $process.HasExited) {
                $process.Kill($true)
                if (-not $process.WaitForExit(5000)) { throw '診断プロセスの停止を確認できませんでした。' }
            }
            if ($started) { Write-Host "CHILD_REAPED=$($process.HasExited)" }
        } finally {
            foreach ($s in $streams) { $s.Stream.Dispose() }
            $process.Dispose()
        }
    }
}

$savedEnvironment = @{}
try {
    if (-not $IsWindows) { throw 'この診断は Windows x64 用です。' }
    [IO.Directory]::CreateDirectory($root) | Out-Null
    # インストール済み MSVC/SDK の固定ツールを使い、環境経由の追加オプションを除く。
    foreach ($name in @('INCLUDE', 'LIB', 'PATH', 'CL', '_CL_', 'LINK', '_LINK_', 'VSLANG')) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    foreach ($name in @('CL', '_CL_', 'LINK', '_LINK_')) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
    $env:VSLANG = '1033'
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'インストール済みの vswhere.exe が見つかりません。' }
    $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'x64 MSVC が見つかりません。' }
    $vsDevCmd = Join-Path $installation 'Common7/Tools/VsDevCmd.bat'
    $environmentLines = & "$env:SystemRoot/System32/cmd.exe" /d /s /c "`"$vsDevCmd`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0) { throw 'x64 の開発環境を取得できませんでした。' }
    $dev = @{}
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$') { $dev[$matches[1]] = $matches[2] }
    }
    foreach ($name in @('INCLUDE', 'LIB', 'PATH')) {
        if (-not $dev.ContainsKey($name)) { throw "開発環境に $name がありません。" }
        [Environment]::SetEnvironmentVariable($name, $dev[$name], 'Process')
    }
    $bin = Join-Path $dev['VCToolsInstallDir'] 'bin/Hostx64/x64'
    $script:compiler = Join-Path $bin 'cl.exe'
    $script:linker = Join-Path $bin 'link.exe'
    $script:dumpbin = Join-Path $bin 'dumpbin.exe'
    $firstDir = Join-Path $root $(if ($Verify) { 'build-a' } else { 'build-only' })
    $first = Build-Probe $firstDir
    Test-ProbePe $first $firstDir
    if ($Verify) {
        $secondDir = Join-Path $root 'build-b'
        $second = Build-Probe $secondDir
        Test-ProbePe $second $secondDir
        Assert-SameBytes $first $second
    }
    Copy-Item -LiteralPath $first -Destination $executable -Force
    Write-Host "EXE=$executable SHA256=$((Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash)"
    if ($Verify) {
        Test-LocalProbe
        # 同一スクリプトの実際の BuildOnly 入口を別スコープで通し、生成物を再比較する。
        & $PSCommandPath -BuildOnly
        Assert-SameBytes $first $executable
        Write-Host 'BUILD_ONLY_MATCHES_VERIFY=True'
    }
    Write-Host $(if ($Verify) { 'VERIFY=PASS' } else { 'BUILD_ONLY=PASS' })
} catch {
    Write-Error -ErrorAction Continue $_
    exit 1
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
