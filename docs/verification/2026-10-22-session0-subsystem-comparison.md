# Session 0 の CONSOLE / WINDOWS 自己終了対照

2026-10-22の同一ソースによる対照では、両ステーション権限候補ともWINDOWS形式のEXEだけが固定終了値`0x53425a54`を返した。CONSOLE形式、cmd両arm、既存のInit/Entry/Terminate診断はすべて`0xc0000142`だった。WINDOWS形式の自己終了コードへの到達を確認できたが、cmdの正常起動と初期化失敗の原因は未実証である。

## 測定の識別

- ソースSHA: `e655d125aad9b5b8975e09e8d1080c8a02fedc1d`。ブランチ: `chore/two-pc-preparation`。
- [Release run 39745889829](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39745889829)、attempt `1`、終端`success`。公開Release作成stepは`skipped`。
- 同一head SHAの[CI run 39745896172](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39745896172)は`failure`。PR checkoutは`21c8552fb24566028abaee4083fd108798654697`で、親に上記SHAを含みtreeは一致した。
- 診断workflow blob: `0350649624928500dfbe937b455f29378fc383a3`。各jobのWindows buildは`10.0.26100.0`。
- 固定runの正本: `.harness/T-011-N15-run.json`。全ログ・終端metadata・固定測定行と保存hash: `.harness/T-011-N15-evidence-hashes.json`。個別観測: `.harness/T-011-N15-observations.json`。

## 両maskの7run

| 要求mask | job | cmd Baseline | cmd NO_WINDOW | Init | Entry | Terminate | CONSOLE | WINDOWS |
|---|---|---|---|---|---|---|---|---|
| `0x0002` | [119714112447](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39745889829/job/119714112447) | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0x53425a54` |
| `0x0022` | [119714112379](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39745889829/job/119714112379) | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0x53425a54` |

cmdの分類は両maskとも`NO_WINDOW_NOT_SUFFICIENT`。Initは`entry-unobserved`、preloaded/load-result/GLEは`none`、outcomeは`indeterminate`。Entryの`0x53425a45`とTerminateの`0x53425a54`は未観測だった。

| 要求mask | subsystem候補 | u32取得 | u32値 | `0x53425a54`肯定bit | 空stdout/stderr | 両EOF | 期限 |
|---|---|---|---|---|---|---|---|
| `0x0002` | `ConsoleProbe` | `True` | `3221225794` | `False` | `True` | `True` | `True` |
| `0x0002` | `WindowsProbe` | `True` | `1396857428` | `True` | `True` | `True` | `True` |
| `0x0022` | `ConsoleProbe` | `True` | `3221225794` | `False` | `True` | `True` | `True` |
| `0x0022` | `WindowsProbe` | `True` | `1396857428` | `True` | `True` | `True` | `True` |

肯定bitは固定自己終了EXE自身のentry到達だけを示す。空出力・両EOF・期限・隔離・回収は独立したゲートであり、肯定bitの代用にはしない。CONSOLEのnegative結果も終了値取得の失敗ではなく、取得したu32値`3221225794`だった。

## 隔離と後始末

- 要求mask、単一非継承Station ACE、各runのTargetAccess action-maskがそれぞれ`0x00000002` / `0x00000022`で一致した。
- 全14runでJob UI制限`0x000000fe`、Baseline/各追加EXEのcreation flags`0x00080404`、NO_WINDOWの`0x08080404`を確認した。
- 各jobの7runはそれぞれ異なる専用desktopを使用した。own許可、他action/Default/WRITE_DAC/WRITE_OWNER拒否、DefaultDacl安全、Tcb不在、隔離確認、全子孫終了、desktop削除を確認した。station ACEは`removed`。
- 追加自己終了3候補の空stdout/stderr・両EOF・10秒期限は個別フラグで確認した。cmd/Init/Entryの空出力・EOF・期限は、保存されたrun結果と評価済み親の終了・分類ゲート通過を確認したもので、追加候補の個別フラグと区別する。
- caller期待nonce/mask/役割別path/hashの照合とworker前後snapshot比較は、評価済み親のfail-closedゲート通過を確認した。nonceとsnapshotの個別値は非出力であり、ログからの個別値の独立照合はできない。
- 全EXE/rootのhold・lease、終了未確認時の保持、SCM停止・不在確認後のidentity付き回収は固定された親の契約で、両jobにPRIMARY/CLEANUP errorはなかった。

## 各jobのEXE実パスとSHA-256

以下は各jobが生成し記録した実値である。ローカル生成物や候補間・runner間のバイト一致を期待値にしていない。保護配置先はworkerが`SbzWindowStationScmSmoke.exe`、追加候補が役割別の`SbzSession0*Probe.exe`となる。workerの保護配置先は評価済み親の入口ゲートで確認され、下表の実ビルドパスと区別する。

### `0x0002` / job `119714112447`

| 役割 | 実ビルドパス | SHA-256 |
|---|---|---|
| `executable` | `D:\a\Sembazuru\Sembazuru\target\debug\deps\sembazuru_worker-f00087a01756abbc.exe` | `703f806e705b03656eb1f955600d19dd5c9ea04494c15e438023e9f9ebfa1b98` |
| `init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-init-probe\session0_init_probe.exe` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| `entry_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-entry-probe\session0_entry_probe.exe` | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |
| `terminate_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-terminate-probe\session0_terminate_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `console_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\console\session0_subsystem_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `windows_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\windows\session0_subsystem_probe.exe` | `a16778d37ac7e03c944260b4e4370dc8f86a040e0bd9e5922d589dc3fe7b8d15` |

### `0x0022` / job `119714112379`

| 役割 | 実ビルドパス | SHA-256 |
|---|---|---|
| `executable` | `D:\a\Sembazuru\Sembazuru\target\debug\deps\sembazuru_worker-f00087a01756abbc.exe` | `ee31785cdbb02ff26367fc5c59930fd12737b114b2bb97eaa6aa9f290868f7c8` |
| `init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-init-probe\session0_init_probe.exe` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| `entry_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-entry-probe\session0_entry_probe.exe` | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |
| `terminate_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-terminate-probe\session0_terminate_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `console_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\console\session0_subsystem_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `windows_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\windows\session0_subsystem_probe.exe` | `a16778d37ac7e03c944260b4e4370dc8f86a040e0bd9e5922d589dc3fe7b8d15` |

追加5候補の保護配置先path/hashは測定レコードと上記の各実hashを照合した。候補の役割を入れ替えて解釈していない。

## 入力8sourceのSHA-256

各jobの検証済み入力hashは全8件で一致し、対象SHAのWindows checkoutバイト列と照合した。共有C++はTerminate/CONSOLE/WINDOWSのビルドに共用する。

| 入力 | SHA-256 |
|---|---|
| `hooks/test/m6_worker_window_station_probe.ps1` | `92f7a1326d75a2b31438efbb1c4ab6d42d68d0ef9cceb30e6753a27083c5ed24` |
| `hooks/test/session0_init_probe.ps1` | `a3f4526a88b0ed1c907ffd577b5409b6431a2fc838f2c9c36d8ba4808cb4b46b` |
| `hooks/test/session0_init_probe.cpp` | `899acfa1eede704a299d0ba00cb13355887c5a07c247b3d78a11fe4b7612a734` |
| `hooks/test/session0_entry_probe.ps1` | `08083b26b107c15c55a52b6fc17c1a017b2e96128685d48b23aef1851aee924e` |
| `hooks/test/session0_entry_probe.cpp` | `15819e62b76f68d8f236fe6e542b7abc11b8c2a669b38929d6964320982457ef` |
| `hooks/test/session0_terminate_probe.ps1` | `e12cfbda3d910cc0207f58bd52d83bc8145452bfd70b9b1ef82cc6708f06714c` |
| `hooks/test/session0_terminate_probe.cpp` | `edfbfe10176fedb41d0e3744693312a514d4987a47ae5b7aac337333c8b71166` |
| `hooks/test/session0_subsystem_probe.ps1` | `c0ce51f9a61eec1467ce08aa2c4db872dbcd709021c611c75b8962a1a1fd5c7b` |

## 同一SHAのCIとinstalled worker

installed workerの[M9.6 installer job 119714128748](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39745896172/job/119714128748)では、plain controlが`exit=-1073741502`（`0xc0000142`）、`states-ok=True`、`traces=0`で失敗した。MSI install/repair/uninstall、directory/config/child ACL、uninstall cleanupの成功行は、個別生ログとCI全ログの本文で一致した。WINDOWS診断の肯定bitはinstalled worker成功の証拠にはならない。

| CI job | 終端 |
|---|---|
| Rust (fmt, clippy, test) | `failure` |
| LocalIntake caller isolation (LocalSystem service) | `success` |
| M9.6 installer (MSI + Burn Bundle + version sync + signing structure) | `failure` |
| Supply chain (cargo-deny) | `success` |
| C++ hooks + tracer (MSVC) (windows-2025) | `failure` |
| C++ hooks + tracer (MSVC) (windows-2022) | `failure` |

Rustの失敗stepはclippyで、生成protoの`double_must_use`が9件記録された。両C++ jobの失敗stepは`M6.1b worker VFS execution`だった。これらの失敗もCI全ログに保持している。

## 解釈の範囲

両maskでWINDOWS候補自身のentry到達が観測され、同じ自己終了コードを使うCONSOLE候補との差が得られた。これはsubsystemに対応した初期化境界の差であり、console接続のどの処理が失敗したか、USER32が原因か、cmdを正常起動するための必要十分条件かは確定しない。

cmd正常起動、権限の最小性、installed worker正常起動、実EDR/AVとの互換性、clang-clとworker経由の決定性は未実証である。R1/F1/M1および全体完了の前提は満たしていない。
