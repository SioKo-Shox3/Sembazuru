# Prefetch / CAS range read 実測

## 測定対象

- 測定日: 2026-07-12 (Asia/Tokyo)
- Prefetch 再測定対象 commit: `63afb94290066dd000e8b80456a3550570b949b6`
- CI: **not run**。この記録はローカル Windows host の実測であり、CI の結果ではない。

今回のreview-fixではStep 2だけを上記commitで再測定した。Step 1とStep 3は既存の測定記録を保持し、Step 4とStep 5は次フェーズでnative artifactを用意して再実行するため、現在のblockerをそのまま記録する。

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

- `Get-Command cl`: **NOT FOUND ON PATH**
- `Get-Command clang-cl`: **NOT FOUND ON PATH**

したがって、この shell は VS developer shell ではなく、clang-cl 必須 gate を実行できる toolchain 条件を満たしていない。

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

exit `1`、**未確認**。blocker:

```text
missing: C:\Users\<user>\Documents\Sembazuru-speed-monitor\hooks\test\..\build\Release\launcher.exe
```

このため RTT delta と catastrophic slowdown assertion は実行されておらず、PASS として扱わない。

### Step 5: clang-cl byte determinism gate

```powershell
powershell -NoProfile -File hooks/test/vfs_compile.ps1 -RequireClangCl
powershell -NoProfile -File hooks/test/determinism.ps1 -RequireClangCl
```

両 command とも exit `1`、**未確認**。どちらも最初の blocker は次の CMake artifact 不足だった。

```text
missing build artifact: C:\Users\<user>\Documents\Sembazuru-speed-monitor\hooks\test\..\build\Release\launcher.exe
```

加えて `cl` と `clang-cl` はこの shell の PATH 上に無い。したがって byte-identical output gate は実行されておらず、determinism は PASS ではない。VS developer shell で Release の `launcher.exe` と `sbz_interceptor64.dll` を生成した後、上記3 command（Step 4の1本とStep 5の2本）を再実行する必要がある。
