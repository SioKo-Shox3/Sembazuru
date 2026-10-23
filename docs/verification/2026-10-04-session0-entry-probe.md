# Session 0 の固定終了値による entry 到達点の実測

対象は `c1686bdd4127f5832ae38049bc64e092c88d1c90`、ブランチは `chore/two-pc-preparation`。
Release [run 37187979681](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37187979681) の
`workflow_dispatch` / `run_attempt=1` で、0x0002 と 0x0022 を別 runner で測定した。

両 mask とも cmd Baseline、cmd NO_WINDOW、InitProbe、EntryProbe の4実行すべてが
`0xc0000142` で終了した。EntryProbe の固定終了値 `0x53425a45` は未観測で、
`EntryObserved=False / EntryProbeOutcome=indeterminate`。正常起動と最小権限は未実証である。

EntryProbe は専用 entry から `ExitProcess(0x53425a45)` を呼ぶ別の EXE である。
この実測は entry 前と終了処理の失敗を区別せず、旧 InitProbe の出力不全や特定 DLL の失敗を同定しない。
`ExitProcess` は DLL の終了処理を呼んだ後に終了値を確定するため、固定値未観測だけで
entry 未到達とは断定できない。[ExitProcess の契約](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)

## 実行識別と hash

| mask | 診断 job | 実測時刻（UTC） | worker fixture SHA-256 |
|---|---|---|---|
| 0x0002 | [111393936490](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37187979681/job/111393936490) | 2026-10-04 08:11:43 | `046672eb73547a6bfa5145d140a548ad115e30e7cebec94a5c53ed1ada254839` |
| 0x0022 | [111393936492](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37187979681/job/111393936492) | 2026-10-04 08:11:15 | `e660efc2f7e5082e06b6e748bdb7916a09a50e9891688001312df0bafba76d0c` |

両 job は Windows Server 2025 / OS build `10.0.26100.0`、image
`windows-2025-vs2026` / `20260925.250.1`。以下の追加 EXE の hash は両 job で一致した。

| EXE | 保護配置先 | SHA-256 |
|---|---|---|
| InitProbe | `C:\Program Files\Sembazuru Test Fixtures\SbzSession0InitProbe.exe` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| EntryProbe | `C:\Program Files\Sembazuru Test Fixtures\SbzSession0EntryProbe.exe` | `9e3668992de9d8a3efabbb546f7f9e1a9d25fdff093d47bf3dc7e41c31b661fe` |

各 job の期待 EXE hash と実測 record の個別 hash は一致する。EntryProbe の CI hash は
ローカル検証時の `cae9d812ad168260098f243262fe6a586dddef8b8d393a231b08e9debee09fa4` と異なる。
worker fixture も候補間で異なる。比較は同一ソースに基づく独立ビルドの比較であり、
候補間の全バイナリ同一性や worker 経由のビルド出力決定性を証明していない。

両 job の保持・検証済みソース hash は同一で、対象コミットを CRLF へ展開した内容と一致する。

| ソース | SHA-256 |
|---|---|
| `m6_worker_window_station_probe.ps1` | `690759d315ba0828b1c87508d6ca77fcd3e260177e762d6584d7f76a90d49ea6` |
| `session0_init_probe.ps1` | `a3f4526a88b0ed1c907ffd577b5409b6431a2fc838f2c9c36d8ba4808cb4b46b` |
| `session0_init_probe.cpp` | `899acfa1eede704a299d0ba00cb13355887c5a07c247b3d78a11fe4b7612a734` |
| `session0_entry_probe.ps1` | `08083b26b107c15c55a52b6fc17c1a017b2e96128685d48b23aef1851aee924e` |
| `session0_entry_probe.cpp` | `15819e62b76f68d8f236fe6e542b7abc11b8c2a669b38929d6964320982457ef` |

## 4実行の結果

次の値は両 mask で共通だった。

| 観測 | cmd Baseline | cmd NO_WINDOW | InitProbe | EntryProbe |
|---|---|---|---|---|
| CreationFlags | `0x00080404` | `0x08080404` | `0x00080404` | `0x00080404` |
| JobUi | `0x000000fe` | `0x000000fe` | `0x000000fe` | `0x000000fe` |
| SpawnSucceeded | True | True | True | True |
| ChildExit | `0xc0000142` | `0xc0000142` | `0xc0000142` | `0xc0000142` |
| Stdout / Stderr / SpawnError | 空 / 空 / 空 | 空 / 空 / 空 | 空 / 空 / 空 | 空 / 空 / 空 |
| DesktopCreated / IsolationVerified | True / True | True / True | True / True | True / True |
| TreeFinished / DesktopRemoved | True / True | True / True | True / True | True / True |

SCM の終了値は `service=0x53425b32`、`session=0 / markers=0x07`、cmd の分類は
`NO_WINDOW_NOT_SUFFICIENT`。このサービス終了値と、各子プロセスの `ChildExit` は別の値である。
`Initialization=dll-init-failed` は終了値の分類であり、DLL 名や失敗 API の観測ではない。

InitProbe の段階列は両 mask とも `0,none,none,none,0`、entry は未観測。
USER32 の既ロード有無・ロード開始・結果・GLE・complete は未観測、Outcome は `indeterminate`。
EntryProbe は出力を使わないが、今回その肯定値も得られなかった。空出力自体は肯定証拠ではない。

## 権限・隔離・後始末

0x0002 では要求値、非継承 station ACE、4実行の `TargetAccess` の要求 mask が
`0x00000002` で一致し、0x0022 では同じ箇所が `0x00000022` で一致した。
各 ACE は `count=1 / flags=0`。`TargetAccess` は broker が action token を impersonate した観測で、
6段階すべて `allowed=true / gle=0`、`first_failure=none` だった。
これは実子プロセスの初期化完了とは別の証拠である。

4実行は各 job の `Service-0x0-<LUID>$` 内の異なる `sbz-*` desktop を使用した。
各 DACL は `control=0x9004`、broker ACE `0x000f01ff`、action SID ACE `0x000201ff`、
各 `flags=0`。SACL は `label=absent;implied_integrity=8192`。
broker の整合性レベルは12288、action は8192だった。

8実行すべてで次の隔離値を確認した。

```text
own=Ok(true);other_maximum=Err(5);default_maximum=Err(5);
write_dac=Err(5);write_owner=Err(5);default_dacl_safe=true;tcb_absent=true
```

自分の専用 desktop への接続は許可され、別 action、Default、ACL・所有者変更は拒否された。
全子孫終了と専用 desktop 削除を確認し、station ACE は `StationCleanup=removed`。
EntryProbe の空出力・隔離・終了・回収を検査する独立ゲートも `EntryProbeGatesVerified=True` だった。

親スクリプトは期待 nonce・mask・path・hash の一致、throwaway サービス停止・削除・不在、
保護ファイル回収、保持 handle 解放、`SembazuruWorker` の前後 snapshot 一致を確認した後に最終分類を出力する。
両 job はこの最終分類を出力して成功し、実際の `PRIMARY ERROR` / `CLEANUP ERROR` は無かった。
nonce と worker snapshot の個別値・バイナリ record 自体はログに出ないため、確認範囲は
当該ソースの照合ゲート通過であり、それらの値の独立照合ではない。

## 同一 SHA の CI と証拠

Release run は終端 success。installer 生成と両診断 job は成功し、公開用の
Create GitHub Release step は skipped だった。これは診断の完走とビルドの成功であり、
上記の子プロセスの正常起動を示すものではない。

同一 head SHA の CI [run 37187982205](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37187982205)
は `pull_request` / 終端 `failure` だった。

| CI job | 結果 |
|---|---|
| Rust（fmt / clippy / test） | success |
| Supply chain（cargo-deny） | success |
| LocalIntake caller isolation | success |
| M9.6 installer | failure |
| C++ hooks + tracer（windows-2025 / windows-2022） | 両方 failure、M6.1b |

installer [job 111393940649](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37187982205/job/111393940649)
の plain control は `exit=-1073741502`（`0xc0000142`）、`states-ok=True / traces=0`。
ProgramData の directory/config/child ACL 個別検査、MSI install / repair / uninstall、
uninstall cleanup は PASS だった。installer の生ログと CI 全ログで実エラー本文・個別成功行が一致した。
サービスの状態遷移やインストール成功を実アクションの正常起動へ読み替えない。

固定 run の正本は `.harness/T-011-N5-run.json`。保存 hash 一覧は
`.harness/T-011-N5-D-evidence-hashes.json`、両 mask の抽出値は
`.harness/T-011-N5-D-observations.json` に保存した。
保存10ファイルの hash、固定 SHA/run/job、各 job の識別・source hash・EXE hash・実測行と
Release 全ログを `.harness/T-011-N5-D-check.ps1` で照合した。
観測はこの run に限定され、実 EDR/AV、clang-cl、worker 経由決定性、installed worker の正常起動を含む全体の成立を示さない。
