# Session 0 の固定自己終了診断の実測

対象は `87027ea5b80ad1b3783c7611872e2750f7019ba5`、ブランチは `chore/two-pc-preparation`。
Release [run 37194784976](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37194784976) の `workflow_dispatch / run_attempt=1` で、
0x0002 と 0x0022 を別 runner で測定した。起動要求時刻は `2026-10-04T10:15:30.6565039Z`。

両maskとも cmd Baseline、cmd NO_WINDOW、InitProbe、EntryProbe、TerminateProbe の5実行すべてが
`0xc0000142` で終了した。TerminateProbe の終了値は取得できたが、肯定値 `0x53425a54` は未観測だった。
空出力・EOF・期限・隔離・回収の各ゲートは通過している。正常起動と最小権限は未実証である。

TerminateProbe は専用entryから `GetCurrentProcess` と `TerminateProcess(self, 0x53425a54)` を呼ぶ。
`TerminateProcess` はDLLの終了通知を行わないため、DLL終了通知を使うEntryProbeとは異なる観測点になる。
ただし今回の未観測だけでは、entry前とAPI内部の失敗を区別できず、旧EXEの原因や特定DLLの失敗は確定できない。
[TerminateProcessの契約](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)、
[ExitProcessとの終了通知の違い](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)

## 実行識別と実hash

両jobは OS build `10.0.26100.0`、runner image `windows-2025-vs2026 / 20260925.250.1`。

| mask | 診断job | 測定行の時刻（UTC） |
|---|---|---|
| 0x0002 | [111414287862](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37194784976/job/111414287862) | 2026-10-04T10:18:13.3008637Z |
| 0x0022 | [111414287794](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37194784976/job/111414287794) | 2026-10-04T10:18:26.1073969Z |

各jobがビルドした4EXEのSHA-256は次のとおり。候補間の一致を前提にせず、個別の期待hashと照合した。

| mask | EXE | SHA-256 |
|---|---|---|
| 0x0002 | worker fixture | `908cddf1f486d1e8c554bad3fe1cfabbff276fef0d2f7df8d4296306afd3399f` |
| 0x0002 | InitProbe | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| 0x0002 | EntryProbe | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |
| 0x0002 | TerminateProbe | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |
| 0x0022 | worker fixture | `f3f76bab0e16e96428d47292e13f9cd9d429de6bcf28e5fbd98fb0193c582151` |
| 0x0022 | InitProbe | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| 0x0022 | EntryProbe | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |
| 0x0022 | TerminateProbe | `6df1c3d9cedc37dc022e91609341a35ecbe49d99244421fbaf9f263378512ba7` |

追加EXEの保護配置先は `C:\Program Files\Sembazuru Test Fixtures\` 内の
`SbzSession0InitProbe.exe`、`SbzSession0EntryProbe.exe`、`SbzSession0TerminateProbe.exe`。
各測定recordのpath/hashはこの固定配置と一致する。worker fixtureは親の固定配置・実hash照合を通過した。
追加3EXEのhashは両jobで一致したが、worker fixtureのhashは異なる。
同一ソースの独立ビルドによる比較であり、候補間の全バイナリ同一性やworker経由のビルド出力決定性を示さない。

保持・検証済み7入力のhashは両jobで一致し、対象コミットのCRLF展開とも一致した。

| 入力ソース | SHA-256 |
|---|---|
| `m6_worker_window_station_probe.ps1` | `e1f61316ff7c09714123124a37d3643dc3fbcc3a490a91e3522bb09bacb23c28` |
| `session0_init_probe.ps1` | `a3f4526a88b0ed1c907ffd577b5409b6431a2fc838f2c9c36d8ba4808cb4b46b` |
| `session0_init_probe.cpp` | `899acfa1eede704a299d0ba00cb13355887c5a07c247b3d78a11fe4b7612a734` |
| `session0_entry_probe.ps1` | `08083b26b107c15c55a52b6fc17c1a017b2e96128685d48b23aef1851aee924e` |
| `session0_entry_probe.cpp` | `15819e62b76f68d8f236fe6e542b7abc11b8c2a669b38929d6964320982457ef` |
| `session0_terminate_probe.ps1` | `e12cfbda3d910cc0207f58bd52d83bc8145452bfd70b9b1ef82cc6708f06714c` |
| `session0_terminate_probe.cpp` | `edfbfe10176fedb41d0e3744693312a514d4987a47ae5b7aac337333c8b71166` |

## 5実行の結果

次の値は両maskで共通だった。

| 観測 | cmd Baseline | cmd NO_WINDOW | InitProbe | EntryProbe | TerminateProbe |
|---|---|---|---|---|---|
| CreationFlags | 0x00080404 | 0x08080404 | 0x00080404 | 0x00080404 | 0x00080404 |
| JobUi | 0x000000fe | 0x000000fe | 0x000000fe | 0x000000fe | 0x000000fe |
| SpawnSucceeded | True | True | True | True | True |
| ChildExit | 0xc0000142 | 0xc0000142 | 0xc0000142 | 0xc0000142 | 0xc0000142 |
| stdout / stderr / SpawnError | 空 / 空 / 空 | 空 / 空 / 空 | 空 / 空 / 空 | 空 / 空 / 空 | 空 / 空 / 空 |
| DesktopCreated / IsolationVerified | True / True | True / True | True / True | True / True | True / True |
| TreeFinished / DesktopRemoved | True / True | True / True | True / True | True / True | True / True |

cmdの分類は両maskとも `NO_WINDOW_NOT_SUFFICIENT`、SCMは `service=0x53425b32 / session=0 / markers=0x07`。
SCMの終了値と各子の終了値は別の値である。`Initialization=dll-init-failed` は終了値の分類であり、失敗したDLL名の観測ではない。

- InitProbe: `0,none,none,none,0`、entry未観測。USER32既ロード・ロード開始・結果・GLE・completeは未観測で、Outcomeは `indeterminate`。
- EntryProbe: `EntryObserved=False`、`0x53425a45` は未観測、Outcomeは `indeterminate`。独立した `EntryProbeGatesVerified=True`。
- TerminateProbe: 終了値取得あり、u32は `3221225794`（`0xc0000142`）。`TerminateEntryObserved=False`、`0x53425a54`（`1396857428`）は未観測、Outcomeは `indeterminate`。

TerminateProbeの独立ゲートは両maskとも `GatesVerified=True / OutputEof=True / DeadlineMet=True`。
stdout/stderrは空、両方のEOFと10秒以内の終了を確認した。ログはEOFを統合bitで記録しており、個別のEOF時刻や経過時間は出力していない。
これらのゲート通過はentry肯定と別の事実である。

## 権限・隔離・回収

要求mask、非継承station ACE、5実行のTargetAccess内の要求maskは、0x0002では `0x00000002`、
0x0022では `0x00000022` で一致した。ACEは `count=1 / flags=0`。
brokerによるaction tokenのimpersonation下の6アクセス観測はすべて `allowed=true / gle=0 / first_failure=none`。
このアクセス観測は実子プロセスの初期化完了を示さない。

各jobの5実行はサービスstation内の異なる専用 `sbz-*` desktopを使用した。
DACLは `control=0x9004`、broker ACE `0x000f01ff` とaction SID ACE `0x000201ff`、flagsはいずれも0。
SACLは `label=absent;implied_integrity=8192`。brokerの整合性レベルは12288、actionは8192だった。

全10実行の隔離値は次のとおり。

```text
own=Ok(true);other_maximum=Err(5);default_maximum=Err(5);
write_dac=Err(5);write_owner=Err(5);default_dacl_safe=true;tcb_absent=true
```

Job UIは `handles=0`、clipboard読書き・systemparameters・displaysettings・globalatoms・desktop・exitwindowsは1、未知bitは0。
各実行の全子孫終了と専用desktop削除を確認し、station ACEは両jobとも `StationCleanup=removed`。

親の最終分類は、期待nonce/mask/path/hash照合、throwawayサービスの停止・削除・不在確認、
保護ファイル回収、保持handle解放、`SembazuruWorker` の前後snapshot一致の各ゲートを通過した後に出力された。
両jobに実際の `PRIMARY ERROR` / `CLEANUP ERROR` は無かった。
nonceとworker snapshotの個別値、およびバイナリrecord自体はログへ出力されないため、
この範囲は保存ソースの照合ゲート通過の確認であり、それら個別値の独立照合ではない。

## 同一SHAのCI

Releaseは終端 `success`。installer生成と両診断jobは成功し、公開用の `Create GitHub Release` はskippedだった。
同一head SHAのCI [run 37194786196](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37194786196) は `pull_request / failure`。

| CI job | 結果 |
|---|---|
| M9.6 installer (MSI + Burn Bundle + version sync + signing structure) | failure |
| C++ hooks + tracer (MSVC) (windows-2022) | failure |
| C++ hooks + tracer (MSVC) (windows-2025) | failure |
| Rust (fmt, clippy, test) | success |
| Supply chain (cargo-deny) | success |
| LocalIntake caller isolation (LocalSystem service) | success |

installed workerのplain controlは `exit=-1073741502`（u32 `3221225794` / `0xc0000142`）、
`states-ok=True / traces=0` で失敗した。MSI install/repair/uninstall、uninstall cleanup、
directory/config/child ACLの個別検査は成功した。
これは診断fixtureとは別の製品worker実行の結果であり、診断jobのsuccessで置き換えられない。

PRのcheckoutはmerge commit `fa8c84b1534004f4f09ea3287ac897e81193286d`。対象head SHAを親に持ち、
Git tree `6dbfa1822e7f9cdfd2e369def620a9f6b8a489cc` は測定SHAと一致した。

## 証拠と確認範囲

固定識別は `.harness/T-011-N10-run.json` と `.harness/T-011-N10-identity.json`。
両maskの全ログ、Release全ログ、同一SHA CI全ログ・installer生ログ、終端metadataを保存し、
`.harness/T-011-N10-evidence-hashes.json` の12ファイルhashで照合した。
各jobの6識別・測定行はRelease全ログと、installerの8観測本文はCI全ログと一致した。
個別観測は `.harness/T-011-N10-observations.json`、再検証コマンドは
`pwsh -NoProfile -File .harness/T-011-N10-check.ps1`。

正常起動、必要最小mask、失敗したDLL/API、実EDRでの挙動、clang-clのworker経由決定性はこの測定から確定できない。
今回の自己終了値未観測を、旧EXEのentry未到達やDLL終了処理の失敗へ読み替えない。
