# Session 0 の WINDOWS 起動情報診断

両ステーション権限候補で、新WINDOWS起動情報診断はcompleteまで到達した。lpDesktopはロード前後とも56 UTF-16単位の終端付き文字列で専用desktopと一致し、user32/gdi32/win32uは前後の照会で不在だった。USER32の明示ロードはresult=0、GLE `0x0000045a`、対応exit11だった。cmd両armは `0xc0000142` であり、cmd失敗の原因、権限の最小性、installed worker正常起動は未実証である。

## 測定の識別

- ソースSHA: `eeab82dc4c0b86e35452c6f9beab7593033b30b4`。ブランチ: `chore/two-pc-preparation`。診断workflow blob: `c4f1c12e78c71e1688a2a1801a8a9207c75802f4`。
- [Release run 39878545283](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39878545283)、attempt `1`、開始 `2026-10-23T00:30:40.067218+00:00`、終端 `success`。公開Release作成stepは `skipped`。
- 同一head SHAの[CI run 39878547890](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39878547890)は `failure`。PR checkoutは `7077760dd276679914c8131c2589927a080b5ca0`。保存した親関係とtreeは測定SHAに一致する。
- 固定run: `.harness/T-011-N27-run.json`。固定測定manifest: `.harness/T-011-N27-measurement-manifest.json`。全ログ・個別path/hash・観測行: `.harness/T-011-N27-evidence-hashes.json`。
- 入力固定manifestは1091件、SHA-256 `c5d0e44034795df59c66dd6e1830abeb7941d7c519efde4daec05b3eeceb2346`。保存workflow blobと固定写しのhashを照合した。

## 各maskの9run

| 要求mask | job | cmd Baseline | cmd NO_WINDOW | Init | Entry | Terminate | CONSOLE | WINDOWS | WINDOWS初期化 | WINDOWS起動情報 |
|---|---|---|---|---|---|---|---|---|---|---|
| `0x0002` | [120170052927](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39878545283/job/120170052927) | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0x53425a54` | `0x0000000b` | `0x0000000b` |
| `0x0022` | [120170052976](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39878545283/job/120170052976) | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0x53425a54` | `0x0000000b` | `0x0000000b` |

自己終了候補の `0x53425a54` はそのEXEのentry到達だけを示す。既存Init・Entry・Terminate・CONSOLEの `0xc0000142`、WINDOWS初期化と新WINDOWS起動情報の対応exitをそれぞれ保持し、cmdの起動結果へ置換しない。

## WINDOWS起動情報の到達段階と独立ゲート

| mask | 段階 | 既ロード | ロード結果 | GLE | exit取得 | u32 | 列と対応exit | 空stderr | 両EOF | 期限 |
|---|---|---|---|---|---|---|---|---|---|---|
| `0x0002` | `7` | `0` | `0` | `0x0000045a` | `True` | `11` | `True` | `True` | `True` | `True` |
| `0x0022` | `7` | `0` | `0` | `0x0000045a` | `True` | `11` | `True` | `True` | `True` | `True` |

段階は0未観測、1entry、2既ロード観測、3before、4load-begin、5load-result、6after、7complete。途中行・不正行・exit不整合の有無を別々に保持した。今回lpDesktopのNULLは観測していない。NULLや未観測を含むstartup状態だけから、USER32やcmd失敗の原因は確定できない。成功時GLEは未規定で、0を要求していない。

### `0x0002` のロード前後

| 時点 | desktop状態 | UTF16単位数 | UTF16コード単位hex | user32 | gdi32 | win32u |
|---|---|---|---|---|---|---|
| `before` | `terminated` | `56` | `0053006500720076006900630065002d003000780030002d0033006600380039003500320024005c00730062007a002d00610037006200300064006600370034003700650034006400650038006500640066006600300032006400370061003000300037006600350033003400340066` | `0` | `0` | `0` |
| `after` | `terminated` | `56` | `0053006500720076006900630065002d003000780030002d0033006600380039003500320024005c00730062007a002d00610037006200300064006600370034003700650034006400650038006500640066006600300032006400370061003000300037006600350033003400340066` | `0` | `0` | `0` |

前後のUTF-16コード単位は、診断runの専用TargetDesktopと一致した。

stdout（保持したraw bytesのASCII表示）:

```text
SBZ_WINDOWS_STARTUP_PROBE_V1 entry
SBZ_WINDOWS_STARTUP_PROBE_V1 user32_preloaded=0
SBZ_WINDOWS_STARTUP_PROBE_V1 before desktop=terminated units=56 hex=0053006500720076006900630065002d003000780030002d0033006600380039003500320024005c00730062007a002d00610037006200300064006600370034003700650034006400650038006500640066006600300032006400370061003000300037006600350033003400340066 user32=0 gdi32=0 win32u=0
SBZ_WINDOWS_STARTUP_PROBE_V1 user32_load_begin
SBZ_WINDOWS_STARTUP_PROBE_V1 user32_load_result=0 gle=0x0000045a
SBZ_WINDOWS_STARTUP_PROBE_V1 after desktop=terminated units=56 hex=0053006500720076006900630065002d003000780030002d0033006600380039003500320024005c00730062007a002d00610037006200300064006600370034003700650034006400650038006500640066006600300032006400370061003000300037006600350033003400340066 user32=0 gdi32=0 win32u=0
SBZ_WINDOWS_STARTUP_PROBE_V1 complete
```

観測値（raw hex、段階、各negative、exit取得を含む）:

```json
{"after": {"gdi32": 0, "hex": "0053006500720076006900630065002d003000780030002d0033006600380039003500320024005c00730062007a002d00610037006200300064006600370034003700650034006400650038006500640066006600300032006400370061003000300037006600350033003400340066", "state": "terminated", "units": 56, "user32": 0, "win32u": 0}, "before": {"gdi32": 0, "hex": "0053006500720076006900630065002d003000780030002d0033006600380039003500320024005c00730062007a002d00610037006200300064006600370034003700650034006400650038006500640066006600300032006400370061003000300037006600350033003400340066", "state": "terminated", "units": 56, "user32": 0, "win32u": 0}, "bothEof": true, "complete": true, "deadlineMet": true, "exitAcquired": true, "exitU32": 11, "gle": "0x0000045a", "isolationAndCleanup": true, "loadResult": 0, "negative": {"deadlineMissed": false, "eofMissing": false, "exitMismatch": false, "incomplete": false, "invalid": false, "stderrNonempty": false, "unobserved": false}, "outcome": 2, "partial": false, "preloaded": 0, "sequenceVerified": true, "stage": 7, "stderrEmpty": true, "stderrHex": "", "stdoutHex": "53425a5f57494e444f57535f535441525455505f50524f42455f563120656e7472790a53425a5f57494e444f57535f535441525455505f50524f42455f5631207573657233325f7072656c6f616465643d300a53425a5f57494e444f57535f535441525455505f50524f42455f5631206265666f7265206465736b746f703d7465726d696e6174656420756e6974733d3536206865783d3030353330303635303037323030373630303639303036333030363530303264303033303030373830303330303032643030333330303636303033383030333930303335303033323030323430303563303037333030363230303761303032643030363130303337303036323030333030303634303036363030333730303334303033373030363530303334303036343030363530303338303036353030363430303636303036363030333030303332303036343030333730303631303033303030333030303337303036363030333530303333303033343030333430303636207573657233323d302067646933323d302077696e3332753d300a53425a5f57494e444f57535f535441525455505f50524f42455f5631207573657233325f6c6f61645f626567696e0a53425a5f57494e444f57535f535441525455505f50524f42455f5631207573657233325f6c6f61645f726573756c743d3020676c653d307830303030303435610a53425a5f57494e444f57535f535441525455505f50524f42455f5631206166746572206465736b746f703d7465726d696e6174656420756e6974733d3536206865783d3030353330303635303037323030373630303639303036333030363530303264303033303030373830303330303032643030333330303636303033383030333930303335303033323030323430303563303037333030363230303761303032643030363130303337303036323030333030303634303036363030333730303334303033373030363530303334303036343030363530303338303036353030363430303636303036363030333030303332303036343030333730303631303033303030333030303337303036363030333530303333303033343030333430303636207573657233323d302067646933323d302077696e3332753d300a53425a5f57494e444f57535f535441525455505f50524f42455f563120636f6d706c6574650a", "valid": true}
```

### `0x0022` のロード前後

| 時点 | desktop状態 | UTF16単位数 | UTF16コード単位hex | user32 | gdi32 | win32u |
|---|---|---|---|---|---|---|
| `before` | `terminated` | `56` | `0053006500720076006900630065002d003000780030002d0032003900620039006200390024005c00730062007a002d00300062003500360035006100620033006400640038006400360062003700320061006300310033006600660032003200630031003200320061003800380039` | `0` | `0` | `0` |
| `after` | `terminated` | `56` | `0053006500720076006900630065002d003000780030002d0032003900620039006200390024005c00730062007a002d00300062003500360035006100620033006400640038006400360062003700320061006300310033006600660032003200630031003200320061003800380039` | `0` | `0` | `0` |

前後のUTF-16コード単位は、診断runの専用TargetDesktopと一致した。

stdout（保持したraw bytesのASCII表示）:

```text
SBZ_WINDOWS_STARTUP_PROBE_V1 entry
SBZ_WINDOWS_STARTUP_PROBE_V1 user32_preloaded=0
SBZ_WINDOWS_STARTUP_PROBE_V1 before desktop=terminated units=56 hex=0053006500720076006900630065002d003000780030002d0032003900620039006200390024005c00730062007a002d00300062003500360035006100620033006400640038006400360062003700320061006300310033006600660032003200630031003200320061003800380039 user32=0 gdi32=0 win32u=0
SBZ_WINDOWS_STARTUP_PROBE_V1 user32_load_begin
SBZ_WINDOWS_STARTUP_PROBE_V1 user32_load_result=0 gle=0x0000045a
SBZ_WINDOWS_STARTUP_PROBE_V1 after desktop=terminated units=56 hex=0053006500720076006900630065002d003000780030002d0032003900620039006200390024005c00730062007a002d00300062003500360035006100620033006400640038006400360062003700320061006300310033006600660032003200630031003200320061003800380039 user32=0 gdi32=0 win32u=0
SBZ_WINDOWS_STARTUP_PROBE_V1 complete
```

観測値（raw hex、段階、各negative、exit取得を含む）:

```json
{"after": {"gdi32": 0, "hex": "0053006500720076006900630065002d003000780030002d0032003900620039006200390024005c00730062007a002d00300062003500360035006100620033006400640038006400360062003700320061006300310033006600660032003200630031003200320061003800380039", "state": "terminated", "units": 56, "user32": 0, "win32u": 0}, "before": {"gdi32": 0, "hex": "0053006500720076006900630065002d003000780030002d0032003900620039006200390024005c00730062007a002d00300062003500360035006100620033006400640038006400360062003700320061006300310033006600660032003200630031003200320061003800380039", "state": "terminated", "units": 56, "user32": 0, "win32u": 0}, "bothEof": true, "complete": true, "deadlineMet": true, "exitAcquired": true, "exitU32": 11, "gle": "0x0000045a", "isolationAndCleanup": true, "loadResult": 0, "negative": {"deadlineMissed": false, "eofMissing": false, "exitMismatch": false, "incomplete": false, "invalid": false, "stderrNonempty": false, "unobserved": false}, "outcome": 2, "partial": false, "preloaded": 0, "sequenceVerified": true, "stage": 7, "stderrEmpty": true, "stderrHex": "", "stdoutHex": "53425a5f57494e444f57535f535441525455505f50524f42455f563120656e7472790a53425a5f57494e444f57535f535441525455505f50524f42455f5631207573657233325f7072656c6f616465643d300a53425a5f57494e444f57535f535441525455505f50524f42455f5631206265666f7265206465736b746f703d7465726d696e6174656420756e6974733d3536206865783d3030353330303635303037323030373630303639303036333030363530303264303033303030373830303330303032643030333230303339303036323030333930303632303033393030323430303563303037333030363230303761303032643030333030303632303033353030333630303335303036313030363230303333303036343030363430303338303036343030333630303632303033373030333230303631303036333030333130303333303036363030363630303332303033323030363330303331303033323030333230303631303033383030333830303339207573657233323d302067646933323d302077696e3332753d300a53425a5f57494e444f57535f535441525455505f50524f42455f5631207573657233325f6c6f61645f626567696e0a53425a5f57494e444f57535f535441525455505f50524f42455f5631207573657233325f6c6f61645f726573756c743d3020676c653d307830303030303435610a53425a5f57494e444f57535f535441525455505f50524f42455f5631206166746572206465736b746f703d7465726d696e6174656420756e6974733d3536206865783d3030353330303635303037323030373630303639303036333030363530303264303033303030373830303330303032643030333230303339303036323030333930303632303033393030323430303563303037333030363230303761303032643030333030303632303033353030333630303335303036313030363230303333303036343030363430303338303036343030333630303632303033373030333230303631303036333030333130303333303036363030363630303332303033323030363330303331303033323030333230303631303033383030333830303339207573657233323d302067646933323d302077696e3332753d300a53425a5f57494e444f57535f535441525455505f50524f42455f563120636f6d706c6574650a", "valid": true}
```

## 既存WINDOWS初期化の観測

`0x0002`:

```json
{"bothEof": true, "deadlineMet": true, "exitAcquired": true, "exitU32": 11, "gle": "0x0000045a", "isolationAndCleanup": true, "loadResult": 0, "outcome": 2, "preloaded": 0, "sequenceVerified": true, "stage": 5, "stderrEmpty": true, "stderrHex": "", "stdoutHex": "53425a5f494e49545f50524f42455f563120656e7472790a53425a5f494e49545f50524f42455f5631207573657233325f7072656c6f616465643d300a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f626567696e0a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f726573756c743d3020676c653d307830303030303435610a53425a5f494e49545f50524f42455f563120636f6d706c6574650a"}
```

`0x0022`:

```json
{"bothEof": true, "deadlineMet": true, "exitAcquired": true, "exitU32": 11, "gle": "0x0000045a", "isolationAndCleanup": true, "loadResult": 0, "outcome": 2, "preloaded": 0, "sequenceVerified": true, "stage": 5, "stderrEmpty": true, "stderrHex": "", "stdoutHex": "53425a5f494e49545f50524f42455f563120656e7472790a53425a5f494e49545f50524f42455f5631207573657233325f7072656c6f616465643d300a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f626567696e0a53425a5f494e49545f50524f42455f5631207573657233325f6c6f61645f726573756c743d3020676c653d307830303030303435610a53425a5f494e49545f50524f42455f563120636f6d706c6574650a"}
```

## 隔離・回収とcaller照合

- 要求mask、単一非継承Station ACE、全runのTargetAccess action-maskはそれぞれ `0x00000002` / `0x00000022` で一致した。各maskの9runは異なる専用desktopを使用した。
- 全18runでJob UI制限 `0x000000fe`、通常のcreation flags `0x00080404`、NO_WINDOWの `0x08080404` を確認した。own許可、他action/Default/WRITE_DAC/WRITE_OWNER拒否、DefaultDacl安全、Tcb不在、隔離、全子孫終了、desktop削除、StationCleanup=`removed` を照合した。
- 自己終了候補は空stdout/stderr・EOF・期限を個別確認した。新旧WINDOWS情報診断はraw・対応exitと、空stderr・両EOF・期限を別々に照合した。cmd/旧Init/EntryのEOF・期限は個別フラグ非出力のため、親の終了・分類ゲート通過と区別する。
- caller期待nonce/mask/役割別path/hashは固定した親のfail-closed照合を通過した。nonceとworker前後snapshotの個別値は非出力であり、個別値の独立観測とは扱わない。worker比較のfinally検査を通過し、CLEANUP ERRORはなかった。
- 全EXE/rootのread holdとlease、終了未確認時の保持、SCM停止・不在確認後のidentity付き回収は固定した親の契約である。段階列の成否から隔離や回収を推定していない。

## 各jobの8EXE個別path/hash

各jobの実ビルド値を期待値に使用した。ローカルhash、runner間・候補間のバイト一致は期待していない。追加7候補の保護配置先は役割別の `C:\Program Files\Sembazuru Test Fixtures\SbzSession0*Probe.exe` であり、記録のpath/hashと個別照合した。

### `0x0002` / job `120170052927`

| 役割 | 実ビルドpath | SHA-256 |
|---|---|---|
| `executable` | `D:\a\Sembazuru\Sembazuru\target\debug\deps\sembazuru_worker-f00087a01756abbc.exe` | `2e5aa316a38ebc03f89db53727eaac51da5a958b87ca9615635f0d95bba87de6` |
| `init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-init-probe\session0_init_probe.exe` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| `entry_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-entry-probe\session0_entry_probe.exe` | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |
| `terminate_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-terminate-probe\session0_terminate_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `console_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\console\session0_subsystem_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `windows_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\windows\session0_subsystem_probe.exe` | `a16778d37ac7e03c944260b4e4370dc8f86a040e0bd9e5922d589dc3fe7b8d15` |
| `windows_init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-windows-init-probe\session0_windows_init_probe.exe` | `fc3f9b2cfd9521239b7aeb3bab7bd265fa01485abe201671eaf0e55ce3ceb3b8` |
| `windows_startup_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-windows-startup-probe\session0_windows_startup_probe.exe` | `05a24ebeed69d9f836fcc7f724eced0f83bb22f1f4d30edda3946d218906c692` |

### `0x0022` / job `120170052976`

| 役割 | 実ビルドpath | SHA-256 |
|---|---|---|
| `executable` | `D:\a\Sembazuru\Sembazuru\target\debug\deps\sembazuru_worker-f00087a01756abbc.exe` | `0337167c0a3320253a167d6c86b3ccffdc42fde27ca212f186384375cf0623cf` |
| `init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-init-probe\session0_init_probe.exe` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| `entry_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-entry-probe\session0_entry_probe.exe` | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |
| `terminate_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-terminate-probe\session0_terminate_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `console_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\console\session0_subsystem_probe.exe` | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| `windows_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-subsystem-probe\windows\session0_subsystem_probe.exe` | `a16778d37ac7e03c944260b4e4370dc8f86a040e0bd9e5922d589dc3fe7b8d15` |
| `windows_init_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-windows-init-probe\session0_windows_init_probe.exe` | `fc3f9b2cfd9521239b7aeb3bab7bd265fa01485abe201671eaf0e55ce3ceb3b8` |
| `windows_startup_probe` | `D:\a\Sembazuru\Sembazuru\.harness\T-011-windows-startup-probe\session0_windows_startup_probe.exe` | `05a24ebeed69d9f836fcc7f724eced0f83bb22f1f4d30edda3946d218906c692` |

## 入力11sourceのSHA-256

保存SHAのWindows checkoutバイト列と両jobの保持入力hashを照合した。WINDOWS初期化は共有Init C++を使用する。

| 入力path | SHA-256 |
|---|---|
| `hooks/test/m6_worker_window_station_probe.ps1` | `40c9c637b9f1cd2626deb32aeeb1354eb7a3176a15b0bf32c12f263e6852bd09` |
| `hooks/test/session0_init_probe.ps1` | `a3f4526a88b0ed1c907ffd577b5409b6431a2fc838f2c9c36d8ba4808cb4b46b` |
| `hooks/test/session0_init_probe.cpp` | `899acfa1eede704a299d0ba00cb13355887c5a07c247b3d78a11fe4b7612a734` |
| `hooks/test/session0_entry_probe.ps1` | `08083b26b107c15c55a52b6fc17c1a017b2e96128685d48b23aef1851aee924e` |
| `hooks/test/session0_entry_probe.cpp` | `15819e62b76f68d8f236fe6e542b7abc11b8c2a669b38929d6964320982457ef` |
| `hooks/test/session0_terminate_probe.ps1` | `e12cfbda3d910cc0207f58bd52d83bc8145452bfd70b9b1ef82cc6708f06714c` |
| `hooks/test/session0_terminate_probe.cpp` | `edfbfe10176fedb41d0e3744693312a514d4987a47ae5b7aac337333c8b71166` |
| `hooks/test/session0_subsystem_probe.ps1` | `c0ce51f9a61eec1467ce08aa2c4db872dbcd709021c611c75b8962a1a1fd5c7b` |
| `hooks/test/session0_windows_init_probe.ps1` | `ddbbe9c2bd3e97f28ca5a010200340859c02225237c71abf2d849b0084cb1ec1` |
| `hooks/test/session0_windows_startup_probe.ps1` | `e99fa03071afdd5bd75065d4c165322fcbcd5aca015ae8ede04d5e2088164aca` |
| `hooks/test/session0_windows_startup_probe.cpp` | `50caddd8f9810006f941c78acdfbdbbc3db6f76fab8fc4108551d169a3ddf63a` |

## CIとinstalled worker

[M9.6 installer job 120170056194](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/39878547890/job/120170056194)のplain controlは `exit=-1073741502`（`0xc0000142`）、`states-ok=True`、`traces=0` で失敗した。plain controlとMSI install/repair/uninstall、directory/config/child ACL、uninstall cleanupの計8本文は個別生ログとCI全ログで一致した。

| CI job | 終端 |
|---|---|
| Supply chain (cargo-deny) | `success` |
| LocalIntake caller isolation (LocalSystem service) | `success` |
| Rust (fmt, clippy, test) | `failure` |
| M9.6 installer (MSI + Burn Bundle + version sync + signing structure) | `failure` |
| C++ hooks + tracer (MSVC) (windows-2022) | `failure` |
| C++ hooks + tracer (MSVC) (windows-2025) | `failure` |

Rust clippyは生成protoのdouble_must_useを9件報告し、両C++ jobはM6.1b worker VFS executionで失敗した。個別ログと全ログを保存し、後続skipも保持した。WINDOWS診断のentryやcomplete到達はinstalled workerの正常起動を証明しない。

## 保存証拠のSHA-256

測定manifestと保存hash一覧を固定し、run/SHA/job/path/hash/全観測行を個別ログとRelease/CI全ログへ照合した。

| 保存path | SHA-256 |
|---|---|
| `.harness/T-011-N27-run.json` | `f3e5722cdf0ab8bb7d42c0f82ab3be017645897e48387ff4aaffe8b1ea432e0a` |
| `.harness/T-011-N27-identity.json` | `3fbc6616e923d4c92e492980637d3aed0e3c15f0c70626fd2a961f238c1d3b2c` |
| `.harness/T-011-N27-authorization.json` | `ab8c7662536e1e44f8a41f786118ee028eeaaa0f6aa369ed0bf0bab77c862671` |
| `.harness/T-011-N27-release-initial.json` | `b8cd414f909af74bd161e22f430704215488b0c36f37f1f6627d2dfb0affa43c` |
| `.harness/T-011-N27-initial-runs.json` | `9735f550f4418cd8ee556329ef9d3da7ebefbeeb53651b72599330fe43e6afd6` |
| `.harness/T-011-N27-merge-ref.json` | `abff64656fe7ddf8243975d0f0d0ffdb42f87505a7bc2bc8ecfb11a26929dd6e` |
| `.harness/T-011-N27-before-measurement-hashes.json` | `eeed031b2bc82d98f2b5d20c45ef656bee0ffa06250b961baaa6b224eba60c51` |
| `.harness/T-011-N27-contract.md` | `fae7eb0b23cfa4eabd961fa0680ef7957aeafa01b76748870b1c3737afe1d4ce` |
| `.harness/T-011-N27-approval.md` | `6703c69ffcb2f726c8a8a060acb545707eed532cf48f3ba3c849e213c27d7f45` |
| `.harness/T-011-N27-old-evidence-hashes.json` | `41984aadbce3a353ebbc1339b563d117cbae0af119c462ecb72be01510ffc8fe` |
| `.harness/T-011-N27-collector-fixed-hashes.json` | `0ef2140a62e314d7a61323b43f34355c80f565d91de5f28dbc087b58a6499535` |
| `.harness/T-011-N27-run-39878545283-final.json` | `f40c6b52b258f9c1a571b6f564d6916c556183f8d6816e783b44dd77d3b0603c` |
| `.harness/T-011-N27-run-39878547890-final.json` | `4292d20a1222d3e65aeb81983364b9761b00fa4f70521ebe2289a075cc663d97` |
| `.harness/T-011-N27-raw/run-39878545283-full.log` | `3032f4cf0de1b3235f99fedac52f1dd81134b785d628e434bd3de02c63599924` |
| `.harness/T-011-N27-raw/run-39878547890-full.log` | `cf97fe9402adad1dfd470ee18e1476e095f15f17fa66feeb11890d468e30d40d` |
| `.harness/T-011-N27-raw/release-api.json` | `b203493107207d9e617e5d52ee668c7a41e0720aa4d626042a9c1064801f4021` |
| `.harness/T-011-N27-raw/job-120170052927.log` | `d2a557114553655402208f426d8d9d82b351aa63d80a7d8b4bc8fc04b2c288f7` |
| `.harness/T-011-N27-raw/job-120170052976.log` | `cd42462cfe0e55c0f51ab3660bbe2267e92bac2cc17c9b9f3aca62739d0cc70f` |
| `.harness/T-011-N27-raw/job-120170056194.log` | `99e4632df89e74ed984955710344025b7171f3e61ffe890896b9c37bd06025eb` |
| `.harness/T-011-N27-raw/ci-merge-commit.json` | `d72cde04a66f904d4162e69fc6591156a43623fd9cb076f4d9206e39d2351c8a` |
| `.harness/T-011-N27-measurement-manifest.json` | `8395008f1a91beb1bba0158e92297458c361d6441250431ac01e647505cad1f6` |
| `.harness/T-011-N27-acquisition-hashes.json` | `732bd4a26c5fb69af6eb5235d49f069c759be43f9f5a6efb16105891b354c616` |
| `.harness/T-011-N27-check.ps1` | `5011b4ec7dcaf298e563f9671e67cd96357f63e783df0e33348483529f4e6af1` |
| `.harness/T-011-N27-check.py` | `944ba1b02342504912f809540ae65481aa8cf49f0efba5a642a799c9eb7494e8` |
| `.harness/T-011-N27-startup.py` | `6f11019f0270f830c560a6f8c25170af84d0c8b36543cabd0c51e3d90adde925` |
| `.harness/T-011-N27-preflight.py` | `0da8e00d8279f4b77f80d28dc9d358b03a926938e8378acc57e79b9f73d662eb` |
| `.harness/T-011-N27-dispatch.py` | `73c5433945a3d586b399673a2f9d63113e45af73d0732030dd653c6170b6a32d` |
| `.harness/T-011-N27-collect.py` | `2e3cc9871ae0f345ad5b126282c5079b344489b5e7b079cc4e69a41ed83f02b3` |
| `.harness/T-011-N27-integrity.py` | `09558e20b3a2a78b7ef3f35db544696f73dcb6923b2f9614d29f082cf319b9e9` |
| `.harness/T-011-N27-early-observations.txt` | `e9f8dccedcbe910c5a976bf504d23bf814f21ee3d7d245a6fd0502cf70e42069` |
| `.harness/T-011-N27-startup-early-check.txt` | `2a175f9763e55498f3a67e79a56f3912efd98566083709890de3ca2db47ead29` |
| `.harness/T-011-N27-release-watch.txt` | `b7a3e0c234c04e52e5f1261f1fcf868af6c30803e8bb1dd8625b61ef1faef4c1` |
| `.harness/T-011-N27-ci-watch.txt` | `ed907b0e24b5f4bdbe2ae6f923a9b851f1227568b35f9f3e8c9f8eda47a484c9` |
| `.harness/runs/20261023-092648/verify-T-011-N27-0.txt` | `b9f31aa4309e1c6d8505171363c7e4ae1aebc3f66520e75e5283fbeb140cef15` |
| `.harness/runs/20261023-092648/verify-T-011-N27-1.txt` | `608afa5cb0d2395c1716d3edfe652f8728ee9cefaf4e4df31f326393ce74183c` |
| `.harness/runs/20261023-092648/verify-T-011-N27-2.txt` | `74c78175b8ce5ccc065e8f417f581e06f94a49263c9d7e06a9aa6284cdebbed7` |
| `.harness/runs/20261023-092648/verify-T-011-N27-3.txt` | `b09f30b54f817fa74951efc3038474cab1235c69456ed79072b1a018c899b1a8` |
| `.harness/runs/20261023-092648/verify-T-011-N27-4.txt` | `6e2979b7fb2ee29f558900dac010db20657b8032c35a53bfef0950d42d5e7b9d` |
| `.harness/T-011-N27-ci-early-errors.txt` | `0e319b7b3c2b3693edae9145208b0b7d7664c279e781eb71d3acd793cdb2c4e5` |
| `.harness/T-011-N27-ci-terminal-inspection.txt` | `4abeb9f83d4362729bf6ef5858824130a3e57c73facc0df0d94bf48b96ec3da5` |
| `.harness/T-011-N27-installer-comparison.txt` | `0db711f29dea6145abef0cc5724db746b0e7848a34e86f18b23ce9a823d40301` |
| `.harness/T-011-N27-collection-result.txt` | `25c308d389564f7a3d5cb84c0a3f1fc5b9d9ba237757023d7bf178f6b63f6dfb` |
| `.harness/T-011-N27-observations.json` | `11c30a6fbb8ab77b508b355a049358613431d0702215937948a8d5a77180b37c` |
| `.harness/T-011-N27-next-boundary.md` | `da7453d981ec6edba8eeecbb899abfc2fbe5ec13b50912d6a190b0193547ffda` |
| `.harness/T-011-N27-document.py` | `1a8f1e520fe3e9afb9a40036c7a355be2017d245c2f374b45ef97e41f70274c4` |
| `.harness/T-011-N27-freeze-hashes.py` | `6a3b33c43fafb82f4b9741fcbc0409d0ae6e7222574aabec038597a2169c7751` |
| `.harness/T-011-N27-raw/job-120170056181.log` | `548fb7557cebf974f96e675650dc224d2afda6fe316ef8dea9cefa69d1450cac` |
| `.harness/T-011-N27-raw/job-120170056213.log` | `9c27ea35c4624828354b027a73db759d21a73b9f409037c4ba123128cd7ca195` |
| `.harness/T-011-N27-raw/job-120170056343.log` | `b6824c034a5ed06c6997b307e5f09fc6afacd692c2861c149b99d85062e8c0bc` |

保存hash一覧自身のSHA-256: `c07b4196326e6c0c277a9fc67d731dbad256ee730af4092a3b41e8423ea6b21d`。

## 解釈の範囲

新診断の明示ロード結果、ロード前後のlpDesktopや既ロードモジュールは、このEXEの当該時点の観測である。NULL状態、特定のGLE、ロード失敗の前後差だけからcmd失敗のDLL原因を断定できず、隔離や権限を緩める根拠にもならない。

cmd正常起動、成功maskと最小性、installed worker正常起動、実EDR/AV、clang-clとworker経由の決定性は未実証である。R1/F1/M1および全体完了の前提は満たしていない。
