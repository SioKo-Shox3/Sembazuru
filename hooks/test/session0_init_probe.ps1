#requires -Version 7.0
<#
.SYNOPSIS
CRT を使わない x64 初期化診断 EXE をビルドし、PE と通常プロセスの到達点を検査する。
.DESCRIPTION
-BuildOnly は .harness/T-011-init-probe/session0_init_probe.exe を生成して PE を検査する。
-Verify は同じビルドに加え、独立した2ビルドの全バイト一致とローカルの正常列を検査する。
entry 未観測だけでは失敗 DLL を特定できない。ローカル成功は Session 0 や cmd の成功を意味しない。
終了値は 0=正常、11=ロード失敗、12=既ロード、13=書込み失敗。書込み失敗時は列が途切れ得る。
#>
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Verify')][switch]$Verify,
    [Parameter(Mandatory, ParameterSetName = 'BuildOnly')][switch]$BuildOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$root = Join-Path $repo '.harness/T-011-init-probe'
$source = Join-Path $PSScriptRoot 'session0_init_probe.cpp'
$executable = Join-Path $root 'session0_init_probe.exe'

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
    $obj = Join-Path $Directory 'session0_init_probe.obj'
    $exe = Join-Path $Directory 'session0_init_probe.exe'
    # CRT cookie の初期化も避けるため、この有界な診断だけを /GS- でビルドする。
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
    if ($headers -notmatch '(?m)^\s*8664 machine \(x64\)\s*$' -or
        $headers -notmatch '(?m)^\s*20B magic # \(PE32\+\)\s*$' -or
        $headers -notmatch '(?m)^\s*[0-9A-F]*[1-9A-F][0-9A-F]* entry point ' -or
        $headers -notmatch '(?m)^\s*0 \[\s*0\] RVA \[size\] of Delay Import Directory\s*$' -or
        $headers -notmatch '(?m)^\s*0 \[\s*0\] RVA \[size\] of Thread Storage Directory\s*$') {
        throw 'PE の x64/entry/遅延 import/TLS 条件が一致しません。'
    }
    $dlls = @([regex]::Matches($imports, '(?im)^\s*([^\s]+\.dll)\s*$') | ForEach-Object { $_.Groups[1].Value })
    if ($dlls.Count -ne 1 -or $dlls[0] -cne 'KERNEL32.dll') {
        throw "静的 import は Kernel32 だけである必要があります: $dlls"
    }
    $actual = @([regex]::Matches($imports, '(?m)^\s+[0-9A-F]+ ([A-Za-z_][A-Za-z_0-9]*)\s*$') |
        ForEach-Object { $_.Groups[1].Value } | Sort-Object)
    $expected = @('ExitProcess', 'GetLastError', 'GetModuleHandleW', 'GetStdHandle', 'LoadLibraryExW',
        'SetErrorMode', 'SetLastError', 'WriteFile') | Sort-Object
    if (($actual -join ',') -cne ($expected -join ',')) {
        throw "Kernel32 の関数 import が固定集合と一致しません: $actual"
    }
    Write-Host 'PE_IMPORTS=KERNEL32.dll DELAY_IMPORTS=none TLS=none MACHINE=x64'
}

function Assert-SameBytes([string]$First, [string]$Second) {
    $a = [IO.File]::ReadAllBytes($First)
    $b = [IO.File]::ReadAllBytes($Second)
    if ($a.Length -ne $b.Length) { throw '独立ビルドの EXE サイズが異なります。' }
    for ($i = 0; $i -lt $a.Length; ++$i) {
        if ($a[$i] -ne $b[$i]) { throw "独立ビルドの EXE が位置 $i で異なります。" }
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
        $started = $process.Start()
        if (-not $started) { throw '診断プロセスを開始できませんでした。' }
        $watch.Start()
        # 両ストリームを同時に読み、各1024バイトを越えた時点で拒否する。
        foreach ($reader in @($process.StandardOutput, $process.StandardError)) {
            $buffer = [byte[]]::new(1025)
            $streams += [pscustomobject]@{ Stream = $reader.BaseStream; Buffer = $buffer; Count = 0; Eof = $false
                Pending = $reader.BaseStream.ReadAsync($buffer, 0, $buffer.Length) }
        }
        while (-not ($process.HasExited -and $streams[0].Eof -and $streams[1].Eof)) {
            if ($watch.ElapsedMilliseconds -ge 15000) { throw '診断プロセスまたは出力回収が15秒の期限を超えました。' }
            foreach ($s in $streams) {
                if (-not $s.Eof -and $s.Pending.IsCompleted) {
                    $read = $s.Pending.GetAwaiter().GetResult()
                    $s.Count += $read
                    if ($s.Count -gt 1024) { throw '診断出力が1024バイトを超えました。' }
                    if ($read -eq 0) { $s.Eof = $true }
                    else { $s.Pending = $s.Stream.ReadAsync($s.Buffer, $s.Count, $s.Buffer.Length - $s.Count) }
                }
            }
            Start-Sleep -Milliseconds 10
        }
        $exitCode = $process.ExitCode
        $raw = [byte[]]::new($streams[0].Count)
        [Array]::Copy($streams[0].Buffer, $raw, $raw.Length)
        [IO.File]::WriteAllBytes((Join-Path $root 'local-stdout.bin'), $raw)
        $stdout = [Text.Encoding]::ASCII.GetString($streams[0].Buffer, 0, $streams[0].Count)
        $stderr = [Text.Encoding]::ASCII.GetString($streams[1].Buffer, 0, $streams[1].Count)
        [IO.File]::WriteAllText((Join-Path $root 'local-result.txt'), "CHILD_EXIT=$exitCode`nSTDOUT_BYTES=$($streams[0].Count)`nSTDERR_BYTES=$($streams[1].Count)`n$stdout$stderr")
        Write-Host "CHILD_EXIT=$exitCode STDOUT_BYTES=$($streams[0].Count) STDERR_BYTES=$($streams[1].Count)"
        Write-Host $stdout.TrimEnd()
        # 成功時の GLE は API 契約上未規定なので8桁の観測値を保存する。
        $pattern = '\ASBZ_INIT_PROBE_V1 entry\nSBZ_INIT_PROBE_V1 user32_preloaded=0\n' +
            'SBZ_INIT_PROBE_V1 user32_load_begin\nSBZ_INIT_PROBE_V1 user32_load_result=1 gle=0x[0-9a-f]{8}\n' +
            'SBZ_INIT_PROBE_V1 complete\n\z'
        if ($exitCode -ne 0 -or $streams[1].Count -ne 0 -or $stdout -cnotmatch $pattern) {
            throw '正常段階列と終了0が揃っていません。entry 未観測だけでは失敗 DLL を特定できません。'
        }
        Write-Host 'LOCAL_SEQUENCE=PASS'
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
    # インストール済みの MSVC/SDK だけを使い、外からの追加オプションを受け取らない。
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
    $firstDir = Join-Path $root 'build-a'
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
    if ($Verify) { Test-LocalProbe }
    Write-Host $(if ($Verify) { 'VERIFY=PASS' } else { 'BUILD_ONLY=PASS' })
} catch {
    Write-Error -ErrorAction Continue $_
    exit 1
} finally {
    foreach ($name in $savedEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process')
    }
}
