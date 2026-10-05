# Session 0 のステーション権限候補の実測

## 対象

- 対象 SHA: `e834c4ab6849c9764c1f7e739e2b707e0e25e28b`（`chore/two-pc-preparation`）。
- Release: [run 37172192286](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37172192286)、イベントは `workflow_dispatch`、終端は `success`（更新時刻 02:58:32 UTC）。
- 0x0002: [job 111347254543](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37172192286/job/111347254543)、終端は `success`。
- 0x0022: [job 111347254337](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37172192286/job/111347254337)、終端は `success`。
- 同じ head SHA の PR CI: [run 37172179258](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37172179258)、イベントは `pull_request`、終端は `failure`（更新時刻 03:00:56 UTC）。

両候補の診断 job は `success` だが、実子プロセスは計4 arm すべて `0xc0000142` で終了した。分類はどちらも `NO_WINDOW_NOT_SUFFICIENT`。`0x0020` の追加による正常起動は観測されず、権限の最小性も実証されていない。

## 0x0002 の観測

実測時刻は 2026-10-04 02:51:17 UTC。runner は Windows Server 2025、イメージ `windows-2025-vs2026` / `20260925.250.1`、OS build `10.0.26100.0`。ログの commit は対象 SHA と一致し、`run_attempt=1`、`session=0`、`markers=0x07`、SCM の分類値は `0x53425b32` だった。

要求値 `RequestedStationMask=0x00000002` に対し、共有 SID の ACE は `count=1;flags=0;mask=0x00000002`。両 arm の `TargetAccess` も `station:action_mask:mask=0x00000002;allowed=true;gle=0` で一致した。これは broker が action token を impersonate して測ったアクセスであり、子プロセスの初期化成功を意味しない。

| 観測 | Baseline | NO_WINDOW |
|---|---|---|
| Creation flags | `0x00080404` | `0x08080404` |
| Job UI | `0x000000fe` | `0x000000fe` |
| SpawnSucceeded | `True` | `True` |
| ChildExit | `0xc0000142` | `0xc0000142` |
| Initialization | `dll-init-failed` | `dll-init-failed` |
| DesktopCreated / IsolationVerified | `True / True` | `True / True` |
| TreeFinished / DesktopRemoved | `True / True` | `True / True` |
| TargetAccess first_failure | `none` | `none` |
| stdout / stderr / SpawnError | 空 | 空 |

各 arm の起動先は `Service-0x0-291e2e$` 内の別々の `sbz-*` desktop。保護 DACL は `control=0x9004`、broker の ACE が `0x000f01ff`、個別 action SID の ACE が `0x000201ff`、どちらも `flags=0`。SACL は `label=absent;implied_integrity=8192` だった。broker の整合性レベルは `12288`、action は Medium の `8192`。

両 arm の隔離記録は次のとおり。

```text
own=Ok(true);other_maximum=Err(5);default_maximum=Err(5);
write_dac=Err(5);write_owner=Err(5);default_dacl_safe=true;tcb_absent=true
```

自分の desktop は許可され、別 action token から当該 desktop を開く試行は拒否された。当該 action token による Default のオープンと、自分の desktop への `WRITE_DAC` / `WRITE_OWNER` もアクセス拒否となった。`TargetAccess` の station と専用 desktop の全6段は許可。一方、broker の Default に対する `BrokerUiProbe` は `desktop:maximum_allowed` で `gle=5` となった。この拒否と専用 desktop のアクセス結果は区別されている。

両 arm で tree の終了と desktop の除去が記録され、共有 station の追加 ACE は `StationCleanup=removed`。診断 script はサービス・fixture の後始末と `SembazuruWorker` の前後 snapshot 一致を確認してから分類を出力しており、今回その検査を通過した。snapshot の比較対象はサービスの存在・削除待ち、設定、依存関係、状態、PID等。個々の前後値はログに出ないため、具体的な PID やサービス状態そのものは未確認である。

実行した script の SHA-256 は `82659E66E3A5AC08271CA1ACE1D750D4AA00DA854BDF977BBEECE8A745655838`、fixture の期待 SHA-256 は `D2A52ED487AF567BA9042F300E9F2CBE6018021C45058A0BB37B0644BC78F4F6`。実ログは `.harness/T-011-D4-job-111347254543.log`（識別情報は200行、hashは506行、測定値は508行）。

## 0x0022 の観測

実測時刻は 2026-10-04 02:51:28 UTC。0x0002 と同じ run / SHA / `run_attempt=1` で、別の Windows Server 2025 runner による測定である。イメージは `windows-2025-vs2026` / `20260925.250.1`、OS build は `10.0.26100.0`。`session=0`、`markers=0x07`、SCM の分類値は `0x53425b32` だった。

job の期待値 `0x0022`、`RequestedStationMask=0x00000022`、共有 SID の `StationAce=count=1;flags=0;mask=0x00000022`、両 arm の `TargetAccess` 内の `station:action_mask:mask=0x00000022;allowed=true;gle=0` はすべて一致した。

| 観測 | Baseline | NO_WINDOW |
|---|---|---|
| Creation flags | `0x00080404` | `0x08080404` |
| Job UI | `0x000000fe` | `0x000000fe` |
| SpawnSucceeded | `True` | `True` |
| ChildExit | `0xc0000142` | `0xc0000142` |
| Initialization | `dll-init-failed` | `dll-init-failed` |
| DesktopCreated / IsolationVerified | `True / True` | `True / True` |
| TreeFinished / DesktopRemoved | `True / True` | `True / True` |
| TargetAccess first_failure | `none` | `none` |
| stdout / stderr / SpawnError | 空 | 空 |

起動先は `Service-0x0-2b3bc4$` 内の `sbz-c2231de9fc48572a39071cf0942f9087` と `sbz-1568433dfe709dfedfca21678e89536b`。両 desktop の保護 DACL は `control=0x9004`、broker の ACE は `0x000f01ff`、個別 action SID の ACE は `0x000201ff`、どちらも `flags=0`。SACL は `label=absent;implied_integrity=8192`。broker の整合性レベルは `12288`、action は `8192` である。

両 arm の隔離記録は `own=Ok(true);other_maximum=Err(5);default_maximum=Err(5);write_dac=Err(5);write_owner=Err(5);default_dacl_safe=true;tcb_absent=true`。自分の desktop は許可され、別 action token から当該 desktop を開く試行、当該 action token から Default を開く試行、自分の desktop の ACL / 所有者変更は拒否された。

専用 desktop に対する `TargetAccess` は全6段が許可された。一方、broker の Default を対象とする `BrokerUiProbe` は `desktop:maximum_allowed;gle=5`。広い station mask `0x0000006e` の `StationAccess` と、Default に対する `BrokerDesktopAccess=mask=0x000000cf` も拒否されている。これらは broker の impersonation による測定であり、実子プロセスの到達点や、その権限を初期化が要求した証拠ではない。

両 arm の tree 終了・desktop 除去と、`StationCleanup=removed` を確認した。サービス・fixture の cleanup と worker snapshot 比較は、script の分類出力前のゲートを通過した。0x0002 と同様に snapshot 個別値は非出力であり、具体的な前後 PID 等の実値は未確認である。

script の SHA-256 は `82659E66E3A5AC08271CA1ACE1D750D4AA00DA854BDF977BBEECE8A745655838`、fixture の期待 SHA-256 は `AE8F61857C81E0715B0C434F23040608FCDD5B7184CD8F116BCF060890FEB0A6`。実ログ `.harness/T-011-D4-job-111347254337.log` の識別情報は200行、hashは506行、測定値は508行にある。

## 候補の比較と観測の限界

| 比較項目 | 0x0002 | 0x0022 |
|---|---|---|
| job ID | `111347254543` | `111347254337` |
| 要求 / ACE / TargetAccess の mask | `0x00000002` で一致 | `0x00000022` で一致 |
| Baseline / NO_WINDOW の実 exit | ともに `0xc0000142` | ともに `0xc0000142` |
| 分類 | `NO_WINDOW_NOT_SUFFICIENT` | `NO_WINDOW_NOT_SUFFICIENT` |
| own 許可、other / Default / ACL 制御権拒否 | 通過 | 通過 |
| tree / desktop / station ACE cleanup | 確認済み | 確認済み |
| worker snapshot 比較 | 通過、個別値は非出力 | 通過、個別値は非出力 |

子のコマンドは両候補とも `System32\cmd.exe /d /c "exit /b 0"`。`SpawnSucceeded=True` はプロセス作成が返ったことを示すが、正常終了には至っていない。`WINSTA_ACCESSGLOBALATOMS` の追加だけでこの条件の初期化失敗が解消するという仮説は、この測定では支持されない。必要な権限が確定したことや、最小性を示す結果ではない。

同じソース SHA、OS イメージ、script hash での比較だが、fixture EXE は各 runner で独立にビルドされ、記録された hash は異なる。同一バイナリを使った比較や決定性の証明ではない。ログオンセッション、SID、desktop 名も各 job で異なる。

両候補で専用 desktop の作成とアクセス検査は通過したが、子の stdout / stderr は空で、失敗した DLL / API や entry 到達の有無は観測されていない。Default・別 action・ACL 制御権が初期化に必要という証拠もない。権限追加の根拠と、実子プロセス内の失敗点は未確定である。

## CI と installer

PR CI の head SHA は対象 SHA と一致する。実際の checkout は GitHub が生成した merge commit `dde589bdde29eaf5595f6303c74fbd07fce2cdbe` で、両 commit の tree SHA は `d987a6726d74645b6edc17e051c46276b91d13b4` と一致した。ソース内容の同一性は GitHub Git API の commit 情報でも確認した。

| 検査 | 結果 |
|---|---|
| Release installer job `111347254102` | `success`。MSI と unsigned Bundle の生成・artifact保存に成功 |
| Release の署名・公開 | 実証明書による署名と `Create GitHub Release` は `skipped` |
| PR CI Rust `111347211505` | `success`。Rust 1.98.1 の fmt / clippy `-D warnings` / workspace test。worker は `176 passed; 0 failed; 11 ignored` |
| PR CI LocalIntake / supply chain | 両 job とも `success` |
| PR CI C++ `111347211506` / `111347211523` | Windows 2022 / 2025 とも M6.1b で `failure` |
| PR CI installer `111347211383` | MSI / Bundle 生成は成功。installed worker plain control で `failure` |

Release の保存物は次の2件。SHA-256 は GitHub が返した **artifact ZIP** の値であり、MSI / EXE 単体のハッシュや署名の検証結果ではない。

| artifact | ID | ZIP bytes | ZIP SHA-256 |
|---|---|---|---|
| `Sembazuru-0.0.3-msi` | `11292101637` | `10756900` | `84f5310c1698e92296d4a117fdddd8b58b7b1c0a4467e4d433d4471c66b2c6fe` |
| `Sembazuru-0.0.3-bundle` | `11292161172` | `36321567` | `9202d26983a1c82bb6f917507276f75a93cbbd5b5b084d140a974b17d95ee6e2` |

PR installer の実ログでは、ディレクトリ・設定・子ファイル・cluster token の ACL、標準ユーザーのアクセス拒否、store/config/ACL の不変性を確認した。MSI install / repair / uninstall はすべて `exit=0`。uninstall 後はサービス、データ、Program Files、HKLM、uninstall登録の除去も `UNINSTALL CLEANUP PASS` だった。

一方、フックなしの installed worker plain control は次の実出力で失敗した。

```text
installed worker plain control failed: exit=-1073741502 states-ok=True traces=0
exec_vfs: states=[1, 2, 3, 4] exit=-1073741502
```

終了値は `0xC0000142`。Application event の限定収集は `no-allowlisted-event` であり、失敗箇所を特定する追加根拠は得られていない。plain control の後に行う VFS action は到達せず、後続のpre-positioning・rollback・署名構造の各 step も `skipped`。ProgramData ACL step 全体の合格や、導入後の正常実行とは扱えない。

C++ の M6.1b では、両 OS で hosted `/GL` が `exit=-1`、plain direct `/GL` が `exit=72`、CreateFile 診断が `target-trace-missing`、worker の `attestation-failed` を記録した。未完の T-023 を含む C++ ゲートを免除して CI 全体の成功とはしない。

## 証拠と判定範囲

終端 metadata と全ログを次へ保存した。

- `.harness/T-011-access-comparison-run.json`：固定 run / SHA / event / 両候補の job ID。
- `.harness/T-011-D4-run-37172192286-final.json` と `T-011-D4-run-37172192286-full.log`：Release。
- `.harness/T-011-D4-run-37172179258-final.json` と `T-011-D4-run-37172179258-full.log`：PR CI。
- `.harness/T-011-D4-job-111347254543.log`：0x0002 の実ログ。
- `.harness/T-011-D4-job-111347254337.log`：0x0022 の実ログ。
- `.harness/T-011-D4-job-111347211383.log`：PR installer。ACL等は1196〜1227行、plain control / uninstallは1228〜1237行。
- `.harness/T-011-D4-job-111347254102.log` と `T-011-D4-release-artifacts.json`：生成と保存物。
- `.harness/T-011-D4-job-111347211505.log`、`T-011-D4-job-111347211506.log`、`T-011-D4-job-111347211523.log`：Rust と C++。
- `.harness/T-011-D4-commit-<SHA>.json`：対象 HEAD と PR merge commit の tree 同一性。
- `.harness/T-011-D5-observations.json` と `T-011-D5-comparison.txt`：両候補の照合結果と元の測定行。

両 job ログ、Release metadata、全ログの SHA-256 は D4 保存時の一覧と一致し、両 job の測定行は Release 全ログにも一致した。0x0022 job ログの SHA-256 は `E1828C70B349B7BCC7EB3008F876A517AD23B44F0570996A6524EABF494CD4F0`。

0x0002 / 0x0022 の負の比較測定は完了したが、T-011 の正常起動条件は未達。権限の最小性、installed worker の正常終了、worker 経路の決定性は、この診断や Release 成功からは結論できない。
