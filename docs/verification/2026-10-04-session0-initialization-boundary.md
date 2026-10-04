# Session 0 の初期化到達点の実測

## 対象と結論

対象は `a540987cbe93103b6b632f89166e584870a5399e`、ブランチは `chore/two-pc-preparation`。Release [run 37180347955](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37180347955) の `workflow_dispatch` / `run_attempt=1` で測定した。[ステーション権限候補の実測](2026-10-04-session0-station-access-comparison.md)とは別の、到達点診断EXEを含むソースによる測定である。

Release runは終端 `success`。installer生成jobと両診断jobが成功し、タグ用の `Create GitHub Release` stepは `skipped` だった。

0x0002の診断 [job 111371484983](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37180347955/job/111371484983) は `success` だが、cmdのBaseline / NO_WINDOWと追加EXEはすべて `0xc0000142` で終了した。追加EXEの標準出力・標準エラーは空で、entryは未観測。初期化前の失敗または出力不全が残るため、USER32ロードの失敗とは確定できない。アクションの正常起動も権限の最小性も未達である。

## 実行識別とバイナリ

0x0002の測定出力は2026-10-04 05:38:02 UTC。Windows Server 2025、イメージ `windows-2025-vs2026` / `20260925.250.1`、OS build `10.0.26100.0`。SCMの値は `service=0x53425b32 session=0 markers=0x07`、分類は `NO_WINDOW_NOT_SUFFICIENT`。

| mask | job | worker診断fixtureのSHA-256 | 追加EXEのSHA-256 |
|---|---|---|---|
| 0x0002 | 111371484983 | `9018129EBB16E9928F3226836D85919AB94527A4EFE01D7212F73C15F0B219FF` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |
| 0x0022 | 111371484954 | `CD26A2243B5AE088FABD939F0B049F8FF753D5FE51E99821A2F3F05E94C2DC36` | `ce81e37c930b90d1804613414405b496eb0fd81fb31d989d0e7a2238775ea4ff` |

両jobは同じソースSHAを独立runnerでビルドしている。追加EXEの記録hashは一致するが、worker fixtureのhashは異なる。バイナリそのものの回収・直接バイト比較や、worker経由のビルド出力の決定性検証を意味しない。0x0022のログは保存済みで、この文書の到達点分析は0x0002を対象とする。

0x0002で実行されたPowerShellのSHA-256は `1E4FAB475B9644448A7613A643A4A8919DE9AA9FDBA387F5AC78B1BC1839ED27`。追加ビルドscriptは `A3F4526A88B0ED1C907FFD577B5409B6431A2FC838F2C9C36D8BA4808CB4B46B`、追加C++ソースは `899ACFA1EEDE704A299D0BA00CB13355887C5A07C247B3D78A11FE4B7612A734`。いずれも対象コミットの内容をCRLFへ展開したバイト列から計算したhashと一致した。

## cmd両armと追加EXEの区別

| 観測 | cmd Baseline | cmd NO_WINDOW | 追加EXE |
|---|---|---|---|
| Creation flags | `0x00080404` | `0x08080404` | `0x00080404` |
| Job UI | `0x000000fe` | `0x000000fe` | `0x000000fe` |
| SpawnSucceeded | `True` | `True` | `True` |
| ChildExit | `0xc0000142` | `0xc0000142` | `0xc0000142` |
| Initialization | `dll-init-failed` | `dll-init-failed` | `dll-init-failed` |
| Stdout / Stderr / SpawnError | 空 / 空 / 空 | 空 / 空 / 空 | 空 / 空 / 空 |
| DesktopCreated / IsolationVerified | `True / True` | `True / True` | `True / True` |
| TreeFinished / DesktopRemoved | `True / True` | `True / True` | `True / True` |

`Initialization=dll-init-failed` は終了値による分類であり、特定のDLL名や内部APIを同定した記録ではない。

追加EXEの固定pathは `C:\Program Files\Sembazuru Test Fixtures\SbzSession0InitProbe.exe`。record内のhashは同jobの期待hashと一致した。到達点は次のとおり。

| 到達点・観測値 | 結果 |
|---|---|
| entry | 未観測 (`entry-unobserved`) |
| USER32既ロード有無 | 未観測 (`none`) |
| USER32ロード開始 | 未観測 |
| USER32ロード結果 | 未観測 (`none`) |
| GLE | 未観測 (`none`) |
| complete | 未観測 |
| 段階列 / Outcome | `0,none,none,none,0` / `indeterminate` |

今回、`load_begin` 後の中断も、明示的なロード失敗とWin32エラーも、`complete` と正常終了の組も観測していない。entry未観測を、entry未到達やUSER32内部の失敗と断定しない。追加EXEが成功した場合でも、それだけではcmdの成功や失敗点の説明にはならない。

## 権限・隔離・後始末

要求 `RequestedStationMask=0x00000002`、共有SIDの `StationAce=count=1;flags=0;mask=0x00000002`、3runすべての `TargetAccess` 内の `station:action_mask:mask=0x00000002;allowed=true;gle=0` が一致した。`TargetAccess` はbrokerがaction tokenをimpersonateして測った6段階で、すべて許可、`first_failure=none`。実子プロセスの初期化到達点とは別の観測である。

3runの起動先は `Service-0x0-2e1b42$` 内の異なる `sbz-*` desktopだった。各専用desktopのDACLは `control=0x9004`、broker ACE `0x000f01ff`、個別action SID ACE `0x000201ff`、各 `flags=0`。SACLは `label=absent;implied_integrity=8192`。brokerの整合性レベルは12288、actionは8192。

3runで同じ隔離記録を確認した。

```text
own=Ok(true);other_maximum=Err(5);default_maximum=Err(5);
write_dac=Err(5);write_owner=Err(5);default_dacl_safe=true;tcb_absent=true
```

自分の専用desktopは開け、別action tokenから当該desktopを開く試行、当該actionからDefaultを開く試行、`WRITE_DAC` / `WRITE_OWNER` は拒否された。broker側Defaultへの `BrokerUiProbe` は `desktop:maximum_allowed;gle=5` で失敗しており、専用desktopの許可と混同しない。より広いmaskを要求する `StationAccess=mask=0x0000006e;allowed=false;gle=5` も、要求0x0002のアクセス成功とは別の結果である。

3runでtree終了・専用desktop削除が確認され、追加したstation ACEは `StationCleanup=removed`。診断scriptはthrowawayサービスの停止・削除・不在、保護fixtureと追加EXEの回収、保持handleの解放、`SembazuruWorker` の前後snapshot一致を確認した後に最終分類を出力する。今回、最終分類を出力してjobが成功し、`PRIMARY ERROR` / `CLEANUP ERROR` の実エラー出力は無かったため、このcleanup・比較ゲートを通過したと判断する。snapshotの個別値はログに出ないので、前後の具体的なPIDや設定値まで確認したとは扱わない。

## 同じhead SHAのinstalled worker

PR CI [run 37180330614](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37180330614) は同じhead SHAで終端 `failure`。Rust jobは成功したが、installer [job 111371432606](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37180330614/job/111371432606) のplain controlは `exit=-1073741502 states-ok=True traces=0` で失敗した。MSI install / repair / uninstallとuninstall後の回収が成功したことと、導入したworkerの正常実行は分けて扱う。この終了値の一致だけでは、追加EXEと同じ内部原因とは確定できない。

## 証拠と限界

- `.harness/T-011-N2-run.json`：固定run / SHA / 両job / 期待mask / 各EXE hash / jobログhash。
- `.harness/T-011-N2-run-37180347955-final.json` と `T-011-N2-run-37180347955-full.log`：Releaseの終端metadataと全ログ。両jobの識別情報・hash・測定行が全ログと一致した。
- `.harness/T-011-N2-job-111371484983.log`：0x0002の生ログ。SHA-256 `BDC00378F858519F9C7F7A10AFCFB4F72929F467ADD46A1135166376A9F47EC3`。
- `.harness/T-011-N2-job-111371484954.log`：同runの0x0022保存ログ。SHA-256 `476742D80DA78C589CB5A880C84E710B2706C7B26EFC1A8FA121F7EA8E60B790`。
- `.harness/T-011-N2-0002-measurement.txt`：0x0002の測定行を項目ごとに改行したもの。
- `.harness/T-011-N2-run-37180330614-final.json` と `T-011-N2-run-37180330614-full.log`：PR CIの終端metadataと全ログ。
- `.harness/T-011-N2-job-111371432606.log`：installed workerのplain controlとMSI回収の実ログ。
- `.harness/T-011-N2-observations.json` と `T-011-N2-evidence-hashes.json`：0x0002の照合結果と保存ファイルのSHA-256一覧。PR installerのエラー行はAPI生ログと全ログでANSI表現と時刻の下位桁が異なり、装飾・時刻・job接頭辞を除いた本文全体の一致を確認した。

この測定は追加EXEのentry出力まで観測できなかったという結果であり、製品maskを変更する根拠にはならない。正常起動、必要権限の最小性、installed workerのplain control、worker経由決定性は未実証。Releaseの生成物や別のC++ゲートの結果は、これらの成功の代用にならない。
