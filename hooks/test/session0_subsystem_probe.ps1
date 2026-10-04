#requires -Version 7.0
<#
.SYNOPSIS
同じ自己終了コードの CONSOLE/WINDOWS 対照をビルドし、通常ローカルで検査する。
.DESCRIPTION
既存 session0_terminate_probe.cpp から同一 OBJ を二通りにリンクする。
出力は .harness/T-011-subsystem-probe/ に限定する。BuildOnly は PE と候補差分を検査する。
Verify は各候補の独立2ビルド・実 BuildOnly の全バイト一致と、通常子の終了・回収を検査する。
候補間では subsystem と再現リンクの派生メタデータが異なる。EXE 全体の一要素差とは扱わない。
0x53425a54 はこの EXE の entry 到達だけを肯定し、Session 0 や cmd の成功を意味しない。
#>
[CmdletBinding(DefaultParameterSetName = 'Verify')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Verify')][switch]$Verify,
    [Parameter(Mandatory, ParameterSetName = 'BuildOnly')][switch]$BuildOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$root = Join-Path $repo '.harness/T-011-subsystem-probe'
$source = Join-Path $PSScriptRoot 'session0_terminate_probe.cpp'
$leaf = 'session0_subsystem_probe.exe'

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

function Read-ProbePe([string]$Exe, [int]$ExpectedSubsystem, [string]$Map) {
    if ($ExpectedSubsystem -notin @(2, 3)) { throw '未知の subsystem です。' }
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
    if ($subsystem -ne $ExpectedSubsystem) { throw 'PE の subsystem 数値が一致しません。' }
    # 固定 entry を map のシンボル・VA と数値の双方で照合する。
    $symbols = [regex]::Matches($Map, '(?m)^\s*0001:00000000\s+ProbeEntry\s+([0-9a-fA-F]{16})\s+f\s+session0_terminate_probe\.obj\s*$')
    if ($entry -ne 0x1000 -or $symbols.Count -ne 1 -or
        [Convert]::ToUInt64($symbols[0].Groups[1].Value, 16) -ne (Read-U64 $b ($o + 24)) + $entry) {
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
    $pe = [pscustomobject]@{ Bytes = $b; Sections = $sections; Entry = $entry; Subsystem = $subsystem
        Differences = @([pscustomobject]@{ Name = 'subsystem'; Offset = $o + 68; Size = 2 }
            [pscustomobject]@{ Name = 'coff-repro-timestamp'; Offset = $p + 8; Size = 4 }) }
    if ($sections[0].Rva -ne $entry) { throw 'entry が実行 section の先頭ではありません。' }
    $directories = @()
    for ($i = 0; $i -lt 16; ++$i) {
        $d = $o + 112 + $i * 8
        $rva = Read-U32 $b $d
        $size = Read-U32 $b ($d + 4)
        if ($i -notin @(1, 3, 6, 12) -and ($rva -ne 0 -or $size -ne 0)) { throw '許可していない PE directory（TLS/遅延 import 等）があります。' }
        $directories += [pscustomobject]@{ Rva = [long]$rva; Size = [long]$size }
    }
    if ($directories[1].Size -ne 40 -or $directories[12].Size -ne 24) { throw 'import の個数が一致しません。' }
    $imp = Get-RvaOffset $pe $directories[1].Rva 40
    if ((Read-U32 $b ($imp + 4)) -ne 0 -or (Read-U32 $b ($imp + 8)) -ne 0 -or
        (Read-PeString $pe (Read-U32 $b ($imp + 12))) -cne 'KERNEL32.dll' -or
        (Read-U32 $b ($imp + 16)) -ne $directories[12].Rva) { throw '固定 Kernel32 import descriptor と一致しません。' }
    for ($i = 20; $i -lt 40; ++$i) { if ($b[$imp + $i] -ne 0) { throw '追加 import descriptor があります。' } }
    $lookup = Get-RvaOffset $pe (Read-U32 $b $imp) 24
    $iat = Get-RvaOffset $pe $directories[12].Rva 24
    $names = @()
    for ($i = 0; $i -lt 3; ++$i) {
        $thunk = Read-U64 $b ($lookup + 8 * $i)
        if ($thunk -ne (Read-U64 $b ($iat + 8 * $i)) -or $thunk -gt [uint32]::MaxValue) { throw '未知の import thunk です。' }
        if ($i -eq 2) { if ($thunk -ne 0) { throw '追加 import 関数があります。' } }
        else { $names += Read-PeString $pe ($thunk + 2) }
    }
    if ((($names | Sort-Object) -join ',') -cne 'GetCurrentProcess,TerminateProcess') { throw '固定の自己終了 API 以外を import しています。' }
    if ($directories[6].Size -ne 56) { throw '再現リンクの debug directory が一致しません。' }
    $debug = Get-RvaOffset $pe $directories[6].Rva 56
    for ($i = 0; $i -lt 2; ++$i) {
        $d = $debug + 28 * $i
        $type = Read-U32 $b ($d + 12)
        if ($type -ne @(13, 16)[$i] -or (Read-U32 $b ($d + 4)) -ne (Read-U32 $b ($p + 8))) {
            throw '未知の debug 種別または派生 timestamp です。'
        }
        $pe.Differences += [pscustomobject]@{ Name = "debug-$type-repro-timestamp"; Offset = $d + 4; Size = 4 }
        if ($type -eq 16) {
            $data = Get-RvaOffset $pe (Read-U32 $b ($d + 20)) 36
            if ((Read-U32 $b ($d + 16)) -ne 36 -or (Read-U32 $b ($d + 24)) -ne $data -or (Read-U32 $b $data) -ne 32) {
                throw '再現リンクの hash 領域が一致しません。'
            }
            $pe.Differences += [pscustomobject]@{ Name = 'repro-hash'; Offset = $data + 4; Size = 32 }
        }
    }
    # 差分を許す debug 領域がコードや import を覆うことを拒否する。
    foreach ($range in $pe.Differences | Select-Object -Skip 2) {
        if ($range.Offset -lt $sections[1].Raw -or $range.Offset + $range.Size -gt $sections[1].Raw + $sections[1].VirtualSize) {
            throw 'debug メタデータが読み取り専用 section 外です。'
        }
        foreach ($span in @(@($imp, 40), @($lookup, 24), @($iat, 24))) {
            if ($range.Offset -lt $span[0] + $span[1] -and $range.Offset + $range.Size -gt $span[0]) { throw 'debug と import の領域が重なっています。' }
        }
    }
    Write-Host "PE_SUBSYSTEM=$subsystem ENTRY_RVA=0x$('{0:x8}' -f $entry) MACHINE=x64 IMPORTS=KERNEL32.dll!GetCurrentProcess,TerminateProcess TLS=none DELAY_IMPORTS=none CRT=none"
    return $pe
}

function Assert-Pair($Console, $Windows, [string]$Directory) {
    if ($Console.Subsystem -ne 3 -or $Windows.Subsystem -ne 2 -or $Console.Entry -ne $Windows.Entry -or
        $Console.Bytes.Length -ne $Windows.Bytes.Length -or
        ($Console.Differences | ConvertTo-Json -Compress) -cne ($Windows.Differences | ConvertTo-Json -Compress)) {
        throw '候補の subsystem/entry/サイズ/メタデータ配置が一致しません。'
    }
    $changes = @()
    for ($i = 0; $i -lt $Console.Bytes.Length; ++$i) {
        if ($Console.Bytes[$i] -eq $Windows.Bytes[$i]) { continue }
        $ranges = @($Console.Differences | Where-Object { $i -ge $_.Offset -and $i -lt $_.Offset + $_.Size })
        if ($ranges.Count -ne 1) { throw "候補間に未説明の差分があります: offset=$i" }
        $changes += [pscustomobject]@{ Offset = $i; Field = $ranges[0].Name; Console = $Console.Bytes[$i]; Windows = $Windows.Bytes[$i] }
    }
    Assert-OutputPath (Join-Path $Directory 'candidate-differences.json')
    $changes | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Directory 'candidate-differences.json') -Encoding utf8
    # /Brepro は PE 全体由来の hash を持ち、COFF/debug の timestamp もそこから派生する。
    Write-Host "PAIR_CODE_IMPORTS_EQUAL=True PAIR_FULL_BYTES_IDENTICAL=False CHANGED_BYTES=$($changes.Count)"
    Write-Host 'PAIR_DIFFERENCE_FIELDS=subsystem,coff-repro-timestamp,debug-13-repro-timestamp,debug-16-repro-timestamp,repro-hash'
}

function Build-Pair([string]$Directory) {
    Assert-OutputPath $Directory
    [IO.Directory]::CreateDirectory($Directory) | Out-Null
    $obj = Join-Path $Directory 'session0_terminate_probe.obj'
    Assert-OutputPath $obj
    $compile = @('/nologo', '/c', '/O1', '/W4', '/WX', '/utf-8', '/GS-', '/GR-', '/Zl', '/Brepro', "/Fo$obj", $source)
    $null = Invoke-BuildTool $script:compiler $compile (Join-Path $Directory 'compile.txt')
    $objHash = (Get-FileHash -LiteralPath $obj).Hash
    $pair = @()
    foreach ($subsystem in @('CONSOLE', 'WINDOWS')) {
        $out = Join-Path $Directory $subsystem.ToLowerInvariant()
        Assert-OutputPath $out
        [IO.Directory]::CreateDirectory($out) | Out-Null
        foreach ($name in @($leaf, 'probe.map')) { Assert-OutputPath (Join-Path $out $name) }
        # 作業場所だけを変え、引数列の差を SUBSYSTEM に限定する。同じ OBJ を二度リンクする。
        $link = @('/nologo', '/MACHINE:X64', "/SUBSYSTEM:$subsystem,6.00", '/ENTRY:ProbeEntry', '/NODEFAULTLIB',
            '/INCREMENTAL:NO', '/Brepro', '/DYNAMICBASE', '/HIGHENTROPYVA', '/NXCOMPAT',
            "/OUT:$leaf", '/MAP:probe.map', $obj, 'kernel32.lib')
        Push-Location $out
        try { $null = Invoke-BuildTool $script:linker $link (Join-Path $out 'link.txt') }
        finally { Pop-Location }
        if ((Get-FileHash -LiteralPath $obj).Hash -cne $objHash) { throw 'リンク中に共通 OBJ が変化しました。' }
        $exe = Join-Path $out $leaf
        foreach ($kind in @('headers', 'imports', 'disasm')) {
            $null = Invoke-BuildTool $script:dumpbin @('/nologo', "/$kind", $exe) (Join-Path $out "$kind.txt")
        }
        $pair += Read-ProbePe $exe $(if ($subsystem -ceq 'CONSOLE') { 3 } else { 2 }) (Get-Content (Join-Path $out 'probe.map') -Raw)
        Assert-OutputPath (Join-Path $out 'link-input.json')
        [pscustomobject]@{ ObjSha256 = $objHash; Arguments = $link } | ConvertTo-Json | Set-Content (Join-Path $out 'link-input.json') -Encoding utf8
    }
    Assert-Pair $pair[0] $pair[1] $Directory
    Write-Host "SAME_OBJ=True OBJ_SHA256=$objHash"
}

function Assert-SameBytes([string]$First, [string]$Second) {
    $a = [IO.File]::ReadAllBytes($First)
    $b = [IO.File]::ReadAllBytes($Second)
    if ($a.Length -ne $b.Length) { throw '比較する EXE のサイズが異なります。' }
    for ($i = 0; $i -lt $a.Length; ++$i) { if ($a[$i] -ne $b[$i]) { throw "EXE が位置 $i で異なります。" } }
    Write-Host "BYTE_IDENTICAL=True BYTES=$($a.Length) SHA256=$((Get-FileHash -LiteralPath $First).Hash)"
}

function Assert-LocalResult($Result) {
    if ($Result.Error) { throw "通常子の検査が失敗しました: $($Result.Error)" }
    if ($Result.ExitCode -ne [uint32]0x53425a54 -or $Result.ExitHex -cne '0x53425a54') { throw '固定自己終了値を観測できませんでした。' }
    if ($Result.StdoutBytes -ne 0 -or $Result.StderrBytes -ne 0 -or -not $Result.StdoutEof -or -not $Result.StderrEof) {
        throw '通常子の空出力と両 EOF が一致しません。'
    }
    if ($Result.DeadlineMs -ne 15000 -or -not $Result.DeadlineMet -or $Result.ElapsedMs -lt 0 -or $Result.ElapsedMs -ge 15000) { throw '通常子の15秒期限が成立しません。' }
    if ($Result.CleanupDeadlineMs -ne 5000 -or -not $Result.Reaped -or $Result.CleanupMs -lt 0 -or $Result.CleanupMs -ge 5000) { throw '通常子の5秒回収が成立しません。' }
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
            $buffer = [byte[]]::new(1)
            $streams += [pscustomobject]@{ Stream = $reader.BaseStream; Buffer = $buffer; Count = 0; Eof = $false
                Pending = $reader.BaseStream.ReadAsync($buffer, 0, 1) }
        }
        while ($true) {
            if ($watch.ElapsedMilliseconds -ge 15000) { throw '通常子または出力回収が15秒の期限を超えました。' }
            foreach ($s in $streams) {
                if (-not $s.Eof -and $s.Pending.IsCompleted) {
                    $s.Count = $s.Pending.GetAwaiter().GetResult()
                    if ($s.Count -ne 0) { throw '通常子の出力が空ではありません。' }
                    $s.Eof = $true
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
                if ($s.Count) { [IO.File]::WriteAllBytes($path, $s.Buffer) }
                else { [IO.File]::WriteAllBytes($path, [byte[]]::new(0)) }
                $s.Stream.Dispose()
            }
            $process.Dispose()
            Assert-OutputPath (Join-Path $Directory 'local-result.json')
            $result | ConvertTo-Json | Set-Content (Join-Path $Directory 'local-result.json') -Encoding utf8
            Write-Host ($result | ConvertTo-Json -Compress)
        }
    }
    Assert-LocalResult ([pscustomobject]$result)
    Write-Host 'LOCAL_SELF_TERMINATE_OBSERVED=True CHILD_REAPED=True'
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
    $first = Join-Path $root $(if ($Verify) { 'build-a' } else { 'build-only' })
    Build-Pair $first
    if ($Verify) {
        $second = Join-Path $root 'build-b'
        Build-Pair $second
        $output = Invoke-BuildTool (Join-Path $PSHOME 'pwsh.exe') @('-NoProfile', '-File', $PSCommandPath, '-BuildOnly') (Join-Path $root 'build-only.txt')
        Write-Host $output.TrimEnd()
    }
    foreach ($candidate in @('console', 'windows')) {
        $a = Join-Path $first "$candidate/$leaf"
        $destination = Join-Path $root $candidate
        Assert-OutputPath $destination
        [IO.Directory]::CreateDirectory($destination) | Out-Null
        $exe = Join-Path $destination $leaf
        Assert-OutputPath $exe
        if ($Verify) {
            Write-Host "CANDIDATE=$candidate"
            Assert-SameBytes $a (Join-Path $second "$candidate/$leaf")
            Assert-SameBytes $a (Join-Path $root "build-only/$candidate/$leaf")
            Assert-SameBytes $a $exe
            Test-LocalProbe $exe $destination
        } else { Copy-Item -LiteralPath $a -Destination $exe -Force }
        Write-Host "EXE=$exe SHA256=$((Get-FileHash -LiteralPath $exe).Hash)"
    }
    Write-Host $(if ($Verify) { 'BUILD_ONLY_MATCHES_VERIFY=True VERIFY=PASS' } else { 'BUILD_ONLY=PASS' })
} catch {
    Write-Error -ErrorAction Continue $_
    exit 1
} finally {
    if ($sourceHold) { $sourceHold.Dispose() }
    foreach ($name in $savedEnvironment.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}
