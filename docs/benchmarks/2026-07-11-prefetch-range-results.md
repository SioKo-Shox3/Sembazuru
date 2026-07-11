# Prefetch / CAS range read 実測

## 測定対象

- 測定日: 2026-07-12 (Asia/Tokyo)
- Prefetch 再測定対象 commit: `63afb94290066dd000e8b80456a3550570b949b6`
- Native gate 再測定対象 commit: `00cb47f75b114b82c5ba760a5b5fe425e5b89782`
- CI: **not run**。この記録はローカル Windows host の実測であり、CI の結果ではない。

今回のreview-fixではStep 2をPrefetch再測定対象commit、Step 4とStep 5をNative gate再測定対象commitで実行した。Step 1とStep 3は既存の測定記録を保持しており、今回の再実行結果ではない。

## Host / CPU / storage

`Get-CimInstance Win32_ComputerSystem`:

- Manufacturer: `MouseComputer`
- Model: `Z790-S01`
- TotalPhysicalMemory: `68554309632` bytes

`Get-CimInstance Win32_Processor`:

- Name: `13th Gen Intel(R) Core(TM) i9-13900KF`
- NumberOfCores: `24`
- NumberOfLogicalProcessors: `32`
- MaxClockSpeed: `3000` MHz

`Get-CimInstance Win32_DiskDrive`（host が返した全 device）:

| Model | MediaType | InterfaceType | Size (bytes) |
|---|---|---:|---:|
| ST8000DM 004-2U9188 USB Device | External hard disk media | USB | 8001560609280 |
| SUNEAST SE900 SSD 1024GB | Fixed hard disk media | IDE | 1024203640320 |
| ST8000DM004-2CX188 | Fixed hard disk media | IDE | 8001560609280 |
| Lexar SSD NM790 4TB | Fixed hard disk media | SCSI | 4096798110720 |
| ST8000DM 004-2CX188 USB Device | External hard disk media | USB | 8001560609280 |
| addlink M.2 PCIE G4x4 NVMe | Fixed hard disk media | SCSI | 4096798110720 |
| SUNEAST SE900 SSD 1024GB | Fixed hard disk media | IDE | 1024203640320 |
| ST2000DM 005-2CW102 USB Device | External hard disk media | USB | 2000396321280 |
| WDC WD80 EAAZ-00BXBB0 USB Device | External hard disk media | USB | 8001560609280 |

OS は `Microsoft Windows 11 Home`、version `10.0.22631`、64 bit。

## Toolchain

`rustc -Vv`:

```text
rustc 1.96.0 (ac68faa20 2026-05-25)
binary: rustc
commit-hash: ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96
commit-date: 2026-05-25
host: x86_64-pc-windows-msvc
release: 1.96.0
LLVM version: 22.1.2
```

Native gateでは`C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat -arch=x64 -host_arch=x64`を読み込み、LLVM binをPATHの先頭へ追加した。

- `cl.exe`: `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\HostX64\x64\cl.exe`、MSVC `19.44.35215` for x64
- `clang-cl.exe`: `C:\Program Files\LLVM\bin\clang-cl.exe`、clang `22.1.7`、target `x86_64-pc-windows-msvc`
- `ninja.exe`: `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe`、version `1.12.1`

### Native Release artifact prerequisites

最初に次のVisual Studio generatorを試したが、CompilerId中に604秒でtimeoutした。残ったowned process treeはcmake → MSBuild `CompilerIdCXX.vcxproj` → HostX86/x64 `cl.exe`であり、PIDとcommand lineを確認してから停止した。

```powershell
cmake -S hooks -B hooks/build -G 'Visual Studio 17 2022' -A x64
```

分離した`msbuild CompilerIdCXX.vcxproj /p:Configuration=Debug /p:Platform=x64 /v:minimal /nologo`も64秒でtimeoutした一方、同じresponse fileをHostX86 `cl.exe`へ直接渡したcompileは2.4秒、exit `0`だった。このためcompilerやargumentの失敗ではなく、このhostのMSBuild経路停止と切り分けた。これらのtimeoutはPASSとして扱わない。

成功したartifact生成はNinjaへ方式変更した次のcommandである。

```powershell
cmake -S hooks -B hooks/build/Release -G Ninja "-DCMAKE_MAKE_PROGRAM=C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=cl.exe
cmake --build hooks/build/Release --config Release
cargo build --locked -p sembazuru-tracer --release
```

configureは1.5秒、MSVC `19.44`を検出してexit `0`。Ninja buildは13/13 targetを生成してexit `0`、tracer buildも1.54秒でexit `0`だった。生成物は`launcher.exe` 36864 bytes、`sbz_interceptor64.dll` 77312 bytes、`sembazuru-trace.exe` 487424 bytes。

## 実行 command と結果

### Step 1: Rust workspace gate

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

既存記録では3 commandともexit `0`。format差分なし、clippy warning `0`、test failure `0`。このreview-fixではStep 1を再実行しておらず、Step 2の再測定とは区別する。

### Step 2: Prefetch concurrency

```powershell
powershell -NoProfile -File hooks/test/prefetch_bench.ps1
```

条件は各 concurrency 40 sample、512 path x 64 KiB、simulated RTT 2 ms。production `for_each_prefetch_bounded` と generic `hydrate` を通し、prefetch 中に末尾の未warm pathを foreground hydrate した。parser は大文字小文字を区別する固定7 property・固定順序・固定delimiterのcanonical schemaへ4行をanchored matchし、named captureから整数3指標の正の十進整数tokenとu64 range、latency 4指標のJSON number grammar・有限正数、concurrency集合、`peak_tasks <= concurrency`、全case同一transfer bytesを検証してexit `0`。Unicode escapeによるkey、重複、case-only key、nested/extra propertyはschema不一致として拒否する。外部依存のないself-testは`powershell.exe`と`pwsh`の両方で通過した。

`peak_tasks`は同時に実行中だったprefetch callback数の最大値である。`transfer_bytes`はbenchmarkが`ServerStats::content_bytes()`へ加算したsimulated content bytesであり、OSやnetwork I/Oの実測値ではない。

```text
PREFETCH_BENCH {"concurrency":8,"prefetch_p50_ms":246.039,"prefetch_p95_ms":249.226,"foreground_p50_ms":3.563,"foreground_p95_ms":4.607,"peak_tasks":8,"transfer_bytes":33554432}
PREFETCH_BENCH {"concurrency":16,"prefetch_p50_ms":122.302,"prefetch_p95_ms":124.770,"foreground_p50_ms":3.419,"foreground_p95_ms":4.519,"peak_tasks":16,"transfer_bytes":33554432}
PREFETCH_BENCH {"concurrency":32,"prefetch_p50_ms":61.219,"prefetch_p95_ms":62.513,"foreground_p50_ms":3.534,"foreground_p95_ms":4.378,"peak_tasks":32,"transfer_bytes":33554432}
PREFETCH_BENCH {"concurrency":64,"prefetch_p50_ms":30.404,"prefetch_p95_ms":31.987,"foreground_p50_ms":3.232,"foreground_p95_ms":3.999,"peak_tasks":64,"transfer_bytes":33554432}
```

production 採用値は `32`。本 workload ではprefetch p50/p95が`61.219 / 62.513 ms`、foreground p50/p95が`3.534 / 4.378 ms`、peak taskが`32`、simulated transferが`33554432` bytesだった。

### Step 3: CAS range / production file server

```powershell
cargo run -p sembazuru-cas --example range_bench --release
cargo run -p sembazuru-agent --example fileserver_range_bench --release
```

既存記録では両commandともexit `0`。このreview-fixではStep 3を再実行していない。

| Size | Whole-per-chunk median | Range median | Old ReadTransferCount | New ReadTransferCount | Old peak working set | New peak working set |
|---:|---:|---:|---:|---:|---:|---:|
| 1 MiB | 1.54 ms | 0.45 ms | 4194304 | 1048576 | 5144576 | 4898816 |
| 16 MiB | 406.88 ms | 6.61 ms | 1073741824 | 16777216 | 20881408 | 4898816 |
| 64 MiB | 6555.36 ms | 32.08 ms | 17179869184 | 67108864 | 71221248 | 4898816 |

production `serve_files_with_stats_token` + bound `FileClient` の warm 後2回目 fetch:

```text
size_mib=64 mode=fileserver-fetch elapsed_ms=227.50 read_transfer_bytes=67108864 peak_working_set_bytes=208044032
```

exact bytes と digest、および Windows の `read_transfer_bytes <= blob_size * 2` assertion は通過した。

### Step 4: VFS speed gate

```powershell
powershell -NoProfile -File hooks/test/vfs_bench.ps1 -Runs 5
```

修正前の`09c5d2d5d5cd10fe57a60e12fbe2b88c1df48a89`では、VS2022 x64環境、LLVM PATH、Release artifactsを用意してもWindows PowerShell 5でexit `1`となり、gate数値へ到達しなかった。代表raw:

```text
cargo.exe :     Compiling sembazuru-worker v0.0.3 (...)
At ...\hooks\test\vfs_bench.ps1:34 char:5
+     & cargo build -p sembazuru-worker --example vfs_host 2>&1 | Out-S...
CategoryInfo          : NotSpecified: (...) [cargo.exe], RemoteException
FullyQualifiedErrorId : NativeCommandError
```

Cargoが非zeroで失敗したのではなく、Windows PowerShell 5が`$ErrorActionPreference = 'Stop'`下で正常なCargo進捗stderrをterminating errorとして扱ったのが原因である。Cargo build区間だけpreferenceを保存・緩和し、出力と直後のexit codeを捕捉し、`finally`で復元する修正後、Native gate再測定対象commitでexit `0`:

```text
local           :    53.4 ms
vfs  (0 ms RTT) :    97.6 ms
vfs  (1 ms RTT) :   104.9 ms
RTT delta       :     7.3 ms
VFS BENCH GATE PASS (round-trip latency does not break the compile; speed within bounds)
```

したがってRTT deltaとcatastrophic slowdown assertionはともにPASS。PowerShell 7回帰もexit `0`で、`local 70.6 ms`、`vfs 0 ms 92.2 ms`、`vfs 1 ms 103.4 ms`、RTT delta `11.2 ms`、`VFS BENCH GATE PASS`だった。

### Step 5: clang-cl byte determinism gate

```powershell
powershell -NoProfile -File hooks/test/vfs_compile.ps1 -RequireClangCl
powershell -NoProfile -File hooks/test/determinism.ps1 -RequireClangCl
```

Native gate再測定対象commit上のWindows PowerShell 5で両commandともexit `0`。

```text
=== cl under VFS (mechanism) ===
GATE PASS  cl: object produced under VFS and source hydrated via the agent
=== clang-cl under VFS (byte-identity) ===
GATE PASS  clang-cl: remote .obj is byte-identical to local (7B0BB4B7B92D8760090F250BE4CCD6D4D9A1EAABC2452CC038FF262C31607A7D)
VFS COMPILE GATE PASS (remote compile under the read VFS; clang-cl byte-identical to local)
```

PowerShell 7の`vfs_compile.ps1 -RequireClangCl`回帰もexit `0`で、同じobject hashと`VFS COMPILE GATE PASS`を確認した。

Windows PowerShell 5実測では、determinismはMSVCの2 outputがbyte-for-byteで再現し、clang-clも異なるbuild directory間でbyte-identicalとなった。clang-clではbuild root差によるinput-set warningを明示したが、gate対象のoutput bytesは一致した。

```text
DETERMINISM OK: 2 output(s) reproduce (no unexplained differences)
GATE PASS  msvc: corpus reproduces byte-for-byte (or normalized-equal)
DETERMINISM OK: 2 output(s) reproduce (no unexplained differences) (input-set differed — see warning above)
GATE PASS  clang-cl: byte-identical across different build directories
DETERMINISM HARNESS PASS (M2: representative C++ TUs reproduce output bytes)
```
