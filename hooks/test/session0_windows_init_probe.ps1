#requires -Version 7.0
<#
.SYNOPSIS
CRT を使わない固定 WINDOWS 初期化診断をビルドし、通常ローカルで検査する。
.DESCRIPTION
既存 session0_init_probe.cpp の到達点と USER32 明示ロード境界を記録する。
出力は .harness/T-011-windows-init-probe/。BuildOnly は固定 EXE の生成と PE 検査を行う。
Verify は独立2ビルドと実 BuildOnly の全 EXE バイト一致、通常子の固定列・期限・回収を検査する。
成功時の GLE は観測値として保存する。ローカル成功は Session 0 や cmd の成功を意味しない。
終了値は 0=ロード成功、11=ロード失敗、12=既ロード、13=書込み失敗。
#>
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Verify')][switch]$Verify,
    [Parameter(Mandatory, ParameterSetName = 'BuildOnly')][switch]$BuildOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$root = Join-Path $repo '.harness/T-011-windows-init-probe'
$source = Join-Path $PSScriptRoot 'session0_init_probe.cpp'
$leaf = 'session0_windows_init_probe.exe'
$executable = Join-Path $root $leaf

function Assert-OutputPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full -ine $root -and -not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw '出力先が固定 root の外です。'
    }
    # 固定配置をリンクで別の場所へ転送しない。既存ファイルも含めて確認する。
    for ($current = $full; $current; $current = Split-Path $current -Parent) {
        if (Test-Path -LiteralPath $current) {
            $item = Get-Item -LiteralPath $current -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.LinkType) {
                throw '出力先の経路に reparse point または hard link があります。'
            }
        }
    }
}

function Invoke-BuildTool([string]$File, [string[]]$Arguments, [string]$Log) {
    Assert-OutputPath $Log
    $output = & $File @Arguments 2>&1 | Out-String
    $code = $LASTEXITCODE
    [IO.File]::WriteAllText($Log, $output + "EXIT_CODE=$code`n")
    if ($code -ne 0) { throw "ビルド用ツールが失敗しました: $File (exit=$code)" }
    return $output
}

function Assert-Range([byte[]]$Bytes, [long]$Offset, [long]$Size) {
    if ($Offset -lt 0 -or $Size -lt 0 -or $Offset + $Size -gt $Bytes.Length) { throw 'PE の範囲がファイル外です。' }
}
function Read-U16([byte[]]$Bytes, [long]$Offset) {
    Assert-Range $Bytes $Offset 2
    return [BitConverter]::ToUInt16($Bytes, [int]$Offset)
}
function Read-U32([byte[]]$Bytes, [long]$Offset) {
    Assert-Range $Bytes $Offset 4
    return [BitConverter]::ToUInt32($Bytes, [int]$Offset)
}
function Read-U64([byte[]]$Bytes, [long]$Offset) {
    Assert-Range $Bytes $Offset 8
    return [BitConverter]::ToUInt64($Bytes, [int]$Offset)
}
function Get-RvaOffset($Pe, [long]$Rva, [long]$Size) {
    $found = @($Pe.Sections | Where-Object {
        $Rva -ge $_.Rva -and $Rva + $Size -le $_.Rva + [Math]::Min($_.VirtualSize, $_.RawSize)
    })
    if ($Size -le 0 -or $found.Count -ne 1) { throw 'PE の RVA が一意な section 内にありません。' }
    $offset = $found[0].Raw + $Rva - $found[0].Rva
    Assert-Range $Pe.Bytes $offset $Size
    return $offset
}
function Read-PeString($Pe, [long]$Rva) {
    $value = ''
    for ($i = 0; $i -lt 128; ++$i) {
        $b = $Pe.Bytes[(Get-RvaOffset $Pe ($Rva + $i) 1)]
        if ($b -eq 0) { return $value }
        if ($b -lt 32 -or $b -gt 126) { throw 'PE の名前が ASCII ではありません。' }
        $value += [char]$b
    }
    throw 'PE の名前が終端されていません。'
}

function Read-ProbePe([string]$Exe, [string]$Map) {
    $b = [IO.File]::ReadAllBytes($Exe)
    $p = [long](Read-U32 $b 0x3c)
    $o = $p + 24
    if ((Read-U16 $b 0) -ne 0x5a4d -or (Read-U32 $b $p) -ne 0x4550 -or
        (Read-U16 $b ($p + 4)) -ne 0x8664 -or (Read-U16 $b ($p + 6)) -ne 3 -or
        (Read-U16 $b ($p + 20)) -ne 240 -or (Read-U16 $b ($p + 22)) -ne 0x22 -or
        (Read-U16 $b $o) -ne 0x20b -or (Read-U32 $b ($o + 108)) -ne 16) {
        throw 'PE の x64/PE32+/実行形式が一致しません。'
    }
    $entry = Read-U32 $b ($o + 16)
    $subsystem = Read-U16 $b ($o + 68)
    if ($subsystem -ne 2) { throw 'PE の subsystem 数値が一致しません。' }
    # 固定 entry を map のシンボル・VA と数値の双方で照合する。
    $symbols = [regex]::Matches($Map, '(?m)^\s*0001:([0-9a-fA-F]{8})\s+ProbeEntry\s+([0-9a-fA-F]{16})\s+f\s+session0_init_probe\.obj\s*$')
    if ($entry -eq 0 -or $symbols.Count -ne 1 -or
        [Convert]::ToUInt64($symbols[0].Groups[2].Value, 16) -ne (Read-U64 $b ($o + 24)) + $entry) {
        throw 'PE の専用 ProbeEntry RVA が一致しません。'
    }
    $sections = @()
    for ($i = 0; $i -lt 3; ++$i) {
        $s = $o + 240 + 40 * $i
        Assert-Range $b $s 40
        $name = [Text.Encoding]::ASCII.GetString($b, $s, 8).TrimEnd([char]0)
        $flags = Read-U32 $b ($s + 36)
        if ($name -cne @('.text', '.rdata', '.pdata')[$i] -or
            $flags -ne @(0x60000020, 0x40000040, 0x40000040)[$i]) { throw '未知の PE section です。' }
        $sections += [pscustomobject]@{ Name = $name; Rva = [long](Read-U32 $b ($s + 12))
            VirtualSize = [long](Read-U32 $b ($s + 8)); RawSize = [long](Read-U32 $b ($s + 16)); Raw = [long](Read-U32 $b ($s + 20)) }
        Assert-Range $b $sections[-1].Raw $sections[-1].RawSize
    }
    $headerSize = Read-U32 $b ($o + 60)
    if ($headerSize -lt $o + 240 + 120) { throw 'PE section 表が header の外です。' }
    foreach ($s in $sections) {
        if ($s.Raw -lt $headerSize -or $s.VirtualSize -le 0 -or $s.VirtualSize -gt $s.RawSize) {
            throw 'PE section の生データ範囲が一致しません。'
        }
        foreach ($other in $sections | Where-Object Name -CNE $s.Name) {
            if (($s.Raw -lt $other.Raw + $other.RawSize -and $s.Raw + $s.RawSize -gt $other.Raw) -or
                ($s.Rva -lt $other.Rva + $other.VirtualSize -and $s.Rva + $s.VirtualSize -gt $other.Rva)) {
                throw 'PE section の範囲が重なっています。'
            }
        }
    }
    $pe = [pscustomobject]@{ Bytes = $b; Sections = $sections; Entry = $entry; Subsystem = $subsystem }
    if ($sections[0].Rva + [Convert]::ToUInt32($symbols[0].Groups[1].Value, 16) -ne $entry) { throw 'entry と実行 section の固定シンボルが一致しません。' }
    $null = Get-RvaOffset $pe $entry 1
    $directories = @()
    for ($i = 0; $i -lt 16; ++$i) {
        $d = $o + 112 + $i * 8
        $rva = Read-U32 $b $d
        $size = Read-U32 $b ($d + 4)
        if ($i -notin @(1, 3, 6, 12) -and ($rva -ne 0 -or $size -ne 0)) { throw '許可していない PE directory（TLS/遅延 import 等）があります。' }
        $directories += [pscustomobject]@{ Rva = [long]$rva; Size = [long]$size }
    }
    if ($directories[1].Size -ne 40 -or $directories[12].Size -notin @(72, 80)) { throw 'import の個数が一致しません。' }
    $imp = Get-RvaOffset $pe $directories[1].Rva 40
    if ((Read-U32 $b ($imp + 4)) -ne 0 -or (Read-U32 $b ($imp + 8)) -ne 0 -or
        (Read-PeString $pe (Read-U32 $b ($imp + 12))) -cne 'KERNEL32.dll' -or
        (Read-U32 $b ($imp + 16)) -ne $directories[12].Rva) { throw '固定 Kernel32 import descriptor と一致しません。' }
    for ($i = 20; $i -lt 40; ++$i) { if ($b[$imp + $i] -ne 0) { throw '追加 import descriptor があります。' } }
    $lookup = Get-RvaOffset $pe (Read-U32 $b $imp) 72
    $iat = Get-RvaOffset $pe $directories[12].Rva $directories[12].Size
    $names = @()
    for ($i = 0; $i -lt 9; ++$i) {
        $thunk = Read-U64 $b ($lookup + 8 * $i)
        if ($thunk -ne (Read-U64 $b ($iat + 8 * $i)) -or $thunk -gt [uint32]::MaxValue) { throw '未知の import thunk です。' }
        if ($i -eq 8) { if ($thunk -ne 0) { throw '追加 import 関数があります。' } }
        else { $names += Read-PeString $pe ($thunk + 2) }
    }
    if ((($names | Sort-Object) -join ',') -cne 'ExitProcess,GetLastError,GetModuleHandleW,GetStdHandle,LoadLibraryExW,SetErrorMode,SetLastError,WriteFile') { throw '固定の初期化診断 API 以外を import しています。' }
    # 8関数と終端の後は、次の領域の16バイト境界に合わせるゼロ埋めだけを許す。
    for ($i = 72; $i -lt $directories[12].Size; ++$i) {
        if ($b[$iat + $i] -ne 0) { throw 'IAT の整列用領域がゼロではありません。' }
    }
    Write-Host "PE_SUBSYSTEM=2 ENTRY=ProbeEntry ENTRY_RVA=0x$('{0:x8}' -f $entry) MACHINE=x64 IMPORTS=KERNEL32.dll!$($names -join ',') TLS=none DELAY_IMPORTS=none CRT=none"
    return $pe
}

function Build-Probe([string]$Directory) {
    Assert-OutputPath $Directory
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $obj = Join-Path $Directory 'session0_init_probe.obj'
    $exe = Join-Path $Directory $leaf
    foreach ($name in @('session0_init_probe.obj', $leaf, 'probe.map')) { Assert-OutputPath (Join-Path $Directory $name) }
    # CRT cookie の初期化も避けるため、この有界な診断だけを /GS- でビルドする。
    $compile = @('/nologo', '/c', '/O1', '/W4', '/WX', '/utf-8', '/GS-', '/GR-', '/Zl', '/Brepro',
        "/Fo$obj", $source)
    $null = Invoke-BuildTool $script:compiler $compile (Join-Path $Directory 'compile.txt')
    $link = @('/nologo', '/MACHINE:X64', '/SUBSYSTEM:WINDOWS,6.00', '/ENTRY:ProbeEntry', '/NODEFAULTLIB',
        '/INCREMENTAL:NO', '/Brepro', '/DYNAMICBASE', '/HIGHENTROPYVA', '/NXCOMPAT',
        "/OUT:$exe", "/MAP:$(Join-Path $Directory 'probe.map')", $obj, 'kernel32.lib')
    $null = Invoke-BuildTool $script:linker $link (Join-Path $Directory 'link.txt')
    $inputPath = Join-Path $Directory 'build-input.json'
    Assert-OutputPath $inputPath
    [pscustomobject]@{ SourceSha256 = (Get-FileHash -LiteralPath $source).Hash
        Compile = $compile; Link = $link; Compiler = $script:compiler; Linker = $script:linker } |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $inputPath -Encoding utf8
    foreach ($kind in @('headers', 'imports')) {
        $null = Invoke-BuildTool $script:dumpbin @('/nologo', "/$kind", $exe) (Join-Path $Directory "$kind.txt")
    }
    $pe = Read-ProbePe $exe (Get-Content (Join-Path $Directory 'probe.map') -Raw)
    return [pscustomobject]@{ Path = $exe; Bytes = $pe.Bytes }
}

function Assert-SameBytes([byte[]]$Expected, [string]$Second) {
    $a = $Expected
    $b = [IO.File]::ReadAllBytes($Second)
    if ($a.Length -ne $b.Length) { throw '独立ビルドの EXE サイズが異なります。' }
    for ($i = 0; $i -lt $a.Length; ++$i) {
        if ($a[$i] -ne $b[$i]) { throw "独立ビルドの EXE が位置 $i で異なります。" }
    }
    Write-Host "BYTE_IDENTICAL=True BYTES=$($a.Length) SHA256=$((Get-FileHash -LiteralPath $Second -Algorithm SHA256).Hash)"
}

function Read-LocalSequence([byte[]]$Bytes, [uint32]$ExitCode) {
    if (@($Bytes | Where-Object { $_ -gt 127 }).Count) { throw '固定列に ASCII 以外のバイトがあります。' }
    $text = [Text.Encoding]::ASCII.GetString($Bytes)
    $prefix = 'SBZ_INIT_PROBE_V1 '
    $loaded = '\A' + $prefix + 'entry\n' + $prefix + 'user32_preloaded=0\n' +
        $prefix + 'user32_load_begin\n' + $prefix + 'user32_load_result=([01]) gle=0x([0-9a-f]{8})\n' + $prefix + 'complete\n\z'
    if ($text -cmatch $loaded) {
        $result = [int]$matches[1]
        $gle = '0x' + $matches[2]
        if (($result -eq 1 -and $ExitCode -ne 0) -or ($result -eq 0 -and $ExitCode -ne 11)) { throw 'ロード結果と終了値が一致しません。' }
        return [pscustomobject]@{ Preloaded = 0; LoadResult = $result; Gle = $gle; Complete = $true }
    }
    if ($text -ceq ($prefix + "entry`n" + $prefix + "user32_preloaded=1`n" + $prefix + "complete`n") -and $ExitCode -eq 12) {
        return [pscustomobject]@{ Preloaded = 1; LoadResult = $null; Gle = $null; Complete = $true }
    }
    throw '固定段階列と対応する終了値が揃っていません。'
}

function Assert-LocalResult($Result, [byte[]]$Stdout) {
    if ($Result.Error) { throw "通常子の検査が失敗しました: $($Result.Error)" }
    if ($null -eq $Result.ExitCode -or $Result.ExitHex -cne ('0x{0:x8}' -f [uint32]$Result.ExitCode)) { throw '終了値の記録が一致しません。' }
    if ($Result.StdoutBytes -ne $Stdout.Length -or $Result.StderrBytes -ne 0 -or -not $Result.StdoutEof -or -not $Result.StderrEof) { throw '通常子の出力と両 EOF が一致しません。' }
    if ($Result.DeadlineMs -ne 15000 -or -not $Result.DeadlineMet -or $Result.ElapsedMs -lt 0 -or $Result.ElapsedMs -ge 15000) { throw '通常子の15秒期限が成立しません。' }
    if ($Result.CleanupDeadlineMs -ne 5000 -or -not $Result.Reaped -or $Result.CleanupMs -lt 0 -or $Result.CleanupMs -ge 5000) { throw '通常子の5秒回収が成立しません。' }
    return Read-LocalSequence $Stdout $Result.ExitCode
}

function Test-LocalProbe([string]$Exe, [string]$Directory) {
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Exe
    $start.WorkingDirectory = $Directory
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    $started = $false
    $watch = [Diagnostics.Stopwatch]::new()
    $streams = @()
    $result = [ordered]@{ ExitCode = $null; ExitHex = $null; StdoutBytes = 0; StderrBytes = 0
        StdoutEof = $false; StderrEof = $false; DeadlineMet = $false; DeadlineMs = 15000; ElapsedMs = 0
        Reaped = $false; CleanupDeadlineMs = 5000; CleanupMs = 0; Error = '' }
    try {
        $watch.Start()
        $started = $process.Start()
        if (-not $started) { throw '通常子を開始できませんでした。' }
        foreach ($reader in @($process.StandardOutput, $process.StandardError)) {
            $buffer = [byte[]]::new(1025)
            $streams += [pscustomobject]@{ Stream = $reader.BaseStream; Buffer = $buffer; Count = 0; Eof = $false
                Pending = $reader.BaseStream.ReadAsync($buffer, 0, $buffer.Length) }
        }
        while ($true) {
            if ($watch.ElapsedMilliseconds -ge 15000) { throw '通常子または出力回収が15秒の期限を超えました。' }
            foreach ($s in $streams) {
                if (-not $s.Eof -and $s.Pending.IsCompleted) {
                    $read = $s.Pending.GetAwaiter().GetResult()
                    $s.Count += $read
                    if ($s.Count -gt 1024) { throw '通常子の出力が1024バイトを超えました。' }
                    if ($read -eq 0) { $s.Eof = $true }
                    else { $s.Pending = $s.Stream.ReadAsync($s.Buffer, $s.Count, $s.Buffer.Length - $s.Count) }
                }
            }
            if ($process.HasExited -and $streams[0].Eof -and $streams[1].Eof) { break }
            Start-Sleep -Milliseconds 10
        }
        $result.ExitCode = [BitConverter]::ToUInt32([BitConverter]::GetBytes([int32]$process.ExitCode), 0)
        $result.ExitHex = '0x{0:x8}' -f $result.ExitCode
        $result.DeadlineMet = $watch.ElapsedMilliseconds -lt 15000
    } catch { $result.Error = $_.Exception.Message }
    finally {
        $watch.Stop()
        $result.ElapsedMs = $watch.ElapsedMilliseconds
        $cleanup = [Diagnostics.Stopwatch]::StartNew()
        try {
            if ($started) {
                # 子を作らない固定 EXE を、保持した Process だけから回収する。
                if (-not $process.HasExited) {
                    try { $process.Kill() } catch { if (-not $process.HasExited) { throw } }
                }
                $remaining = 5000 - $cleanup.ElapsedMilliseconds
                $result.Reaped = $remaining -gt 0 -and $process.WaitForExit([int][Math]::Max(0, $remaining))
            }
        } catch { $result.Error += " 回収: $($_.Exception.Message)" }
        finally {
            $cleanup.Stop()
            $result.CleanupMs = $cleanup.ElapsedMilliseconds
            for ($i = 0; $i -lt $streams.Count; ++$i) {
                $s = $streams[$i]
                $name = @('Stdout', 'Stderr')[$i]
                $result[$name + 'Bytes'] = $s.Count
                $result[$name + 'Eof'] = $s.Eof
                $path = Join-Path $Directory ("local-{0}.bin" -f $name.ToLowerInvariant())
                Assert-OutputPath $path
                if ($s.Count) { [IO.File]::WriteAllBytes($path, [byte[]]$s.Buffer[0..($s.Count - 1)]) }
                else { [IO.File]::WriteAllBytes($path, [byte[]]::new(0)) }
                $s.Stream.Dispose()
            }
            $process.Dispose()
            Assert-OutputPath (Join-Path $Directory 'local-result.json')
            $result | ConvertTo-Json | Set-Content (Join-Path $Directory 'local-result.json') -Encoding utf8
            Write-Host ($result | ConvertTo-Json -Compress)
        }
    }
    $stdout = [IO.File]::ReadAllBytes((Join-Path $Directory 'local-stdout.bin'))
    $sequence = Assert-LocalResult ([pscustomobject]$result) $stdout
    Assert-OutputPath (Join-Path $Directory 'local-sequence.json')
    $sequence | ConvertTo-Json | Set-Content (Join-Path $Directory 'local-sequence.json') -Encoding utf8
    Write-Host ([Text.Encoding]::ASCII.GetString($stdout).TrimEnd())
    Write-Host ($sequence | ConvertTo-Json -Compress)
    if ($sequence.Preloaded -ne 0 -or $sequence.LoadResult -ne 1 -or $result.ExitCode -ne 0) { throw '通常ローカルの明示ロード成功列が揃っていません。' }
    Write-Host 'LOCAL_SEQUENCE=PASS CHILD_REAPED=True'
}

$savedEnvironment = @{}
$sourceHold = $null
try {
    if (-not $Verify -and -not $BuildOnly) { throw 'Verify または BuildOnly を有効にしてください。' }
    if (-not $IsWindows) { throw 'この診断は Windows x64 用です。' }
    Assert-OutputPath $root
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $sourceHold = [IO.File]::Open($source, 'Open', 'Read', 'Read')
    Write-Host "SOURCE_SHA256=$((Get-FileHash -LiteralPath $source).Hash)"
    foreach ($name in @('INCLUDE', 'LIB', 'PATH', 'CL', '_CL_', 'LINK', '_LINK_', 'VSLANG')) {
        $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
    }
    foreach ($name in @('CL', '_CL_', 'LINK', '_LINK_')) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
    $env:VSLANG = '1033'
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    $installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'x64 MSVC が見つかりません。' }
    $vsDevCmd = Join-Path $installation 'Common7/Tools/VsDevCmd.bat'
    $environmentLines = & "$env:SystemRoot/System32/cmd.exe" /d /s /c "`"$vsDevCmd`" -no_logo -arch=x64 -host_arch=x64 >nul && set"
    if ($LASTEXITCODE -ne 0) { throw 'x64 の開発環境を取得できませんでした。' }
    $dev = @{}
    foreach ($line in $environmentLines) { if ($line -match '^([^=]+)=(.*)$') { $dev[$matches[1]] = $matches[2] } }
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
    if ($Verify) {
        $second = Build-Probe (Join-Path $root 'build-b')
        Assert-SameBytes $first.Bytes $second.Path
        $output = Invoke-BuildTool (Join-Path $PSHOME 'pwsh.exe') @('-NoProfile', '-File', $PSCommandPath, '-BuildOnly') (Join-Path $root 'build-only.txt')
        Write-Host $output.TrimEnd()
        Assert-SameBytes $first.Bytes (Join-Path $root "build-only/$leaf")
        # PE 検査時のバイト列を基準とし、配置 EXE は照合の前から回収完了まで保持する。
        $exeHold = [IO.File]::Open($executable, 'Open', 'Read', 'Read')
        try {
            Assert-SameBytes $first.Bytes $executable
            Test-LocalProbe $executable $root
        }
        finally { $exeHold.Dispose() }
    } else {
        Assert-OutputPath $executable
        Copy-Item -LiteralPath $first.Path -Destination $executable -Force
        $exeHold = [IO.File]::Open($executable, 'Open', 'Read', 'Read')
        try { Assert-SameBytes $first.Bytes $executable }
        finally { $exeHold.Dispose() }
    }
    Write-Host "EXE=$executable SHA256=$((Get-FileHash -LiteralPath $executable).Hash)"
    Write-Host $(if ($Verify) { 'BUILD_ONLY_MATCHES_VERIFY=True VERIFY=PASS' } else { 'BUILD_ONLY=PASS' })
} catch {
    Write-Error -ErrorAction Continue $_
    exit 1
} finally {
    if ($sourceHold) { $sourceHold.Dispose() }
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}
