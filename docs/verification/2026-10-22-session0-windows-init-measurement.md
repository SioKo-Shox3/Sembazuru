# Session 0 の WINDOWS 初期化診断

両ステーション権限候補で、固定WINDOWS形式の初期化診断はentryからcompleteまで到達した。USER32は既ロードではなく、明示ロードがresult=0、GLE=`0x0000045a`で失敗し、対応する終了値`11`を取得した。空stderr・両EOF・期限・隔離・回収は別ゲートで通過した。cmd両armは引き続き`0xc0000142`であり、この明示ロード失敗をcmdの原因と断定できない。

## 測定の識別

- ソースSHA: `0dece8744d734160208ce28908f3cc66704c6b95`。既存ブランチ: `chore/two-pc-preparation`。診断workflow blob: `0f5c7adb2c13540701c5f96eff4ba38d9d765902`。
- [Release run 39799787013](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39799787013)、attempt `1`、終端`success`。公開Release作成stepは`skipped`。
- 同一head SHAの[CI run 39799790283](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39799790283)は`failure`。PR checkoutは`d677797eb876959bd71064d4291b42d5bcbf2996`。親SHAと同一treeを保存metadataで確認した。
- 固定runの正本: `.harness/T-011-N21-run.json`。個別job・終端metadata・全ログとSHA-256一覧: `.harness/T-011-N21-evidence-hashes.json`。固定測定manifest: `.harness/T-011-N21-measurement-manifest.json`。
- 保存SHA・workflow blob・477入力の固定manifestを照合した。manifest SHA-256は`d50769b6a33fc1d5310181cf4cee08cf223f646ee7efa431aa3183abd487c3a7`。

## 両mask各8runの終了値

| 要求mask | job | cmd Baseline | cmd NO_WINDOW | Init | Entry | Terminate | CONSOLE | WINDOWS | WINDOWS初期化 |
|---|---|---|---|---|---|---|---|---|---|
| `0x0002` | [119896893393](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39799787013/job/119896893393) | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0x53425a54` | `0x0000000b` |
| `0x0022` | [119896893028](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39799787013/job/119896893028) | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0x53425a54` | `0x0000000b` |

WINDOWS自己終了候補の`0x53425a54`はそのEXE自身のentry到達を示す。新診断の終了値と混同しない。既存Initのentry未観測からUSER32原因を推定しない。

## WINDOWS初期化の段階・出力・取得終了値

| mask | 最終段階 | 既ロード | ロード結果 | GLE | u32取得 | u32値 | 列と対応exit | 空stderr | 両EOF | 期限 |
|---|---|---|---|---|---|---|---|---|---|---|
| `0x0002` | `5` | `0` | `0` | `0x0000045a` | `True` | `11` | `True` | `True` | `True` | `True` |
| `0x0022` | `5` | `0` | `0` | `0x0000045a` | `True` | `11` | `True` | `True` | `True` | `True` |

### `0x0002` のraw bytesと観測

stdoutは次の固定列だった。stderrは空（0 bytes）だった。

```text
SBZ_INIT_PROBE_V1 entry
SBZ_INIT_PROBE_V1 user32_preloaded=0
SBZ_INIT_PROBE_V1 user32_load_begin
SBZ_INIT_PROBE_V1 user32_load_result=0 gle=0x0000045a
SBZ_INIT_PROBE_V1 complete
```

保存観測（raw hexを含む）:

```json
{"bothEof": true, "deadlineMet": true, "exitAcquired": true, "exitU32": 11, "gle": "0x0000045a", "isolationAndCleanup": true, "loadResult": 0, "outcome": 2, "preloaded": 0, "sequenceVerified": true, "stage": 5, "stderrEmpty": true, "stderrHex": "", "stdoutHex": "53425a5f494e49545f50524f42455f563120656e7472790a53425a5f494e49545f50524f42455f5631207573657233325f7072656c6f616465643d300a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f626567696e0a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f726573756c743d3020676c653d307830303030303435610a53425a5f494e49545f50524f42455f563120636f6d706c6574650a"}
```

### `0x0022` のraw bytesと観測

stdoutは次の固定列だった。stderrは空（0 bytes）だった。

```text
SBZ_INIT_PROBE_V1 entry
SBZ_INIT_PROBE_V1 user32_preloaded=0
SBZ_INIT_PROBE_V1 user32_load_begin
SBZ_INIT_PROBE_V1 user32_load_result=0 gle=0x0000045a
SBZ_INIT_PROBE_V1 complete
```

保存観測（raw hexを含む）:

```json
{"bothEof": true, "deadlineMet": true, "exitAcquired": true, "exitU32": 11, "gle": "0x0000045a", "isolationAndCleanup": true, "loadResult": 0, "outcome": 2, "preloaded": 0, "sequenceVerified": true, "stage": 5, "stderrEmpty": true, "stderrHex": "", "stdoutHex": "53425a5f494e49545f50524f42455f563120656e7472790a53425a5f494e49545f50524f42455f5631207573657233325f7072656c6f616465643d300a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f626567696e0a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f726573756c743d3020676c653d307830303030303435610a53425a5f494e49545f50524f42455f563120636f6d706c6574650a"}
```

段階5はcompleteまでの記録を意味する。result=0とexit11は明示ロード失敗の列であり、診断自体が正常な失敗列を返したことと、USER32ロード成功を区別する。成功時GLEは未規定であり0を要求しない。未観測・途中列からロード原因を断定しない。

## 独立した隔離・回収ゲート

- 要求mask、単一非継承Station ACE、全runのTargetAccess action-maskはそれぞれ`0x00000002` / `0x00000022`で一致した。各maskの8runは異なる専用desktopを使用した。
- 全16runでJob UI制限`0x000000fe`、Baseline/追加EXEのcreation flags`0x00080404`、NO_WINDOWの`0x08080404`を確認した。own許可、他action/Default/WRITE_DAC/WRITE_OWNER拒否、DefaultDacl安全、Tcb不在、隔離、全子孫終了、desktop削除、StationCleanup=`removed`を確認した。
- 自己終了候補は空stdout/stderr・EOF・期限を個別フラグで確認した。新WindowsInitには空stdoutを要求せず、段階列のraw bytesと空stderr・両EOF・期限を個別照合した。cmd/旧Init/EntryのEOF・期限は個別フラグ非出力で、評価済み親の終了・分類ゲート通過と区別する。
- caller期待nonce/mask/役割別path/hashは評価済み親のfail-closed照合を通過した。nonceとworker前後snapshotの個別値は非出力であり、個別値の独立照合はできない。worker比較はfinallyの検査を通過し、CLEANUP ERRORはなかった。
- 全EXE/rootのhold・lease、終了未確認時の保持、SCM停止・不在確認後のidentity付き回収は固定した親の契約である。診断列/exitの成功から隔離・回収を推定せず、全ログの各値と終了状態を照合した。

## 各jobの7EXE個別path/hash

各jobの実ビルド値を使用した。ローカルhash、runner間・候補間のバイト一致を期待値にしていない。追加6候補の保護配置先は`C:\Program Files\Sembazuru Test Fixtures\SbzSession0*Probe.exe`で、役割別path/hashをレコードと個別照合した。workerの保護配置先とhashは評価済み親の入口ゲートで確認した。

### `0x0002` / job `119896893393`

| 役割 | 実ビルドパス | SHA-256 |
|---|---|---|
| `executable` | `D:\a\Sembazuru\Sembazuru\target\debug\deps\sembazuru_worker-f00087a01756abbc.exe` | `8bfe37ee1e37d18ebec7acefce105ec97d5746ca58d93d798178e2ff441a0500` |
| `init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-init-probe\session0_init_probe.exe` | `e3a7c549b8ec263e1f50d04f4a9c4b669ff90750c715d8b483e236cb07655344` |
| `entry_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-entry-probe\session0_entry_probe.exe` | `41d7180509d16bcc91aea1957acbbc6f093bff859940072ecc8444cde772807c` |
| `terminate_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-terminate-probe\session0_terminate_probe.exe` | `4dc48a6594d089cfa51078d9c6a35cabb497e025597e5b6a2577594fb99128a4` |
| `console_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\console\session0_subsystem_probe.exe` | `4dc48a6594d089cfa51078d9c6a35cabb497e025597e5b6a2577594fb99128a4` |
| `windows_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\windows\session0_subsystem_probe.exe` | `31a4bcb6a4fbb2d9e32a8b3722d223b5e154baddeb2abe4938c169dfafd74397` |
| `windows_init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-windows-init-probe\session0_windows_init_probe.exe` | `e7695b56fdc7da647031446401663b6c81e76d05220623559e07f60da2b978fe` |

### `0x0022` / job `119896893028`

| 役割 | 実ビルドパス | SHA-256 |
|---|---|---|
| `executable` | `D:\a\Sembazuru\Sembazuru\target\debug\deps\sembazuru_worker-f00087a01756abbc.exe` | `a46b0ec0fa54fabea9e459fef1767e4dbf352214cdb6d7ee55a03064475807b7` |
| `init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-init-probe\session0_init_probe.exe` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| `entry_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-entry-probe\session0_entry_probe.exe` | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |
| `terminate_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-terminate-probe\session0_terminate_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `console_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\console\session0_subsystem_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `windows_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\windows\session0_subsystem_probe.exe` | `a16778d37ac7e03c944260b4e4370dc8f86a040e0bd9e5922d589dc3fe7b8d15` |
| `windows_init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-windows-init-probe\session0_windows_init_probe.exe` | `fc3f9b2cfd9521239b7aeb3bab7bd265fa01485abe201671eaf0e55ce3ceb3b8` |

## 入力9sourceのSHA-256

保存SHAのWindows checkoutバイト列と両jobの保持入力hashを照合した。共有Init C++をWINDOWS初期化にも使用する。

| 入力path | SHA-256 |
|---|---|
| `hooks/test/m6_worker_window_station_probe.ps1` | `b08045243c152788aaa552ebb2ce3265594a49caa3666f558da1ef3ce54c395d` |
| `hooks/test/session0_init_probe.ps1` | `a3f4526a88b0ed1c907ffd577b5409b6431a2fc838f2c9c36d8ba4808cb4b46b` |
| `hooks/test/session0_init_probe.cpp` | `899acfa1eede704a299d0ba00cb13355887c5a07c247b3d78a11fe4b7612a734` |
| `hooks/test/session0_entry_probe.ps1` | `08083b26b107c15c55a52b6fc17c1a017b2e96128685d48b23aef1851aee924e` |
| `hooks/test/session0_entry_probe.cpp` | `15819e62b76f68d8f236fe6e542b7abc11b8c2a669b38929d6964320982457ef` |
| `hooks/test/session0_terminate_probe.ps1` | `e12cfbda3d910cc0207f58bd52d83bc8145452bfd70b9b1ef82cc6708f06714c` |
| `hooks/test/session0_terminate_probe.cpp` | `edfbfe10176fedb41d0e3744693312a514d4987a47ae5b7aac337333c8b71166` |
| `hooks/test/session0_subsystem_probe.ps1` | `c0ce51f9a61eec1467ce08aa2c4db872dbcd709021c611c75b8962a1a1fd5c7b` |
| `hooks/test/session0_windows_init_probe.ps1` | `ddbbe9c2bd3e97f28ca5a010200340859c02225237c71abf2d849b0084cb1ec1` |

## 同一SHAのCIとinstalled worker

[M9.6 installer job 119896893328](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39799790283/job/119896893328)はplain controlが`exit=-1073741502`（`0xc0000142`）、`states-ok=True`、`traces=0`で失敗した。plain control失敗行と、MSI install/repair/uninstall、directory/config/child ACL、uninstall cleanupの計8本文は個別生ログとCI全ログで一致した。

| CI job | 終端 |
|---|---|
| C++ hooks + tracer (MSVC) (windows-2022) | `failure` |
| Supply chain (cargo-deny) | `success` |
| M9.6 installer (MSI + Burn Bundle + version sync + signing structure) | `failure` |
| Rust (fmt, clippy, test) | `failure` |
| C++ hooks + tracer (MSVC) (windows-2025) | `failure` |
| LocalIntake caller isolation (LocalSystem service) | `success` |

Rustのclippyは生成protoに対するdouble_must_useが9件、両C++ jobはM6.1b worker VFS executionで失敗した。これらも全ログに保持した。WINDOWS診断のentryやcomplete到達はinstalled worker正常起動の証明にはならない。

## 解釈の範囲

新診断はWINDOWS形式のentry以後で明示したUSER32ロードの結果を観測する。ロード失敗のGLEと対応exitが得られても、cmdの起動時に同じDLL・依存関係・初期化経路が原因だったとは確定しない。権限を緩める根拠にもならない。

cmd正常起動、成功maskと最小性、installed worker正常起動、実EDR/AV、clang-clとworker経由の決定性は未実証である。R1/F1/M1および全体完了の前提は満たしていない。
