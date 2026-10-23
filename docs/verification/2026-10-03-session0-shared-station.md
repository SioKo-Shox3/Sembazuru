# 共有ウィンドウステーション経路の Session 0 実測

本記録の対象は 2026-10-03 の固定 run `37105578000` と SHA `2590e08777c24fbe4573fb33372f1cd1008d8540`。未測定の記述はこの run の範囲を示す。

2026-10-04 の SHA `e834c4ab6849c9764c1f7e739e2b707e0e25e28b` では、`0x0002` と `0x0022` の比較測定が完了した。両候補の Baseline / NO_WINDOW はすべて `0xc0000142`、分類は `NO_WINDOW_NOT_SUFFICIENT` で、正常起動と最小性は未達。同じ head SHA の installed worker も plain control が `0xC0000142` で失敗した。対象 run / job、隔離・後始末、観測の限界は[ステーション権限候補の実測](2026-10-04-session0-station-access-comparison.md)を参照。

到達点診断EXEを追加した SHA `a540987cbe93103b6b632f89166e584870a5399e` の Release run `37180347955` でも、`0x0002` の cmd 両 arm と追加EXEはすべて `0xc0000142` だった。追加EXEは出力が空で entry 未観測のため、USER32 のロード失敗とは確定できない。同じ head SHA の installed worker も plain control が失敗した。正常起動・最小性・worker経由決定性は未実証。対象ログ、隔離・後始末、installer ACL の結果は[初期化到達点の実測](2026-10-04-session0-initialization-boundary.md)を参照。

## 対象

- 対象 SHA: `2590e08777c24fbe4573fb33372f1cd1008d8540`（`chore/two-pc-preparation`）
- Release run: [37105578000](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37105578000) — `workflow_dispatch`、終端 `success`
- Session 0 job: [111153308288](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37105578000/job/111153308288) — `success`
- installer job: [111153308080](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37105578000/job/111153308080) — `success`
- 同じ SHA の PR CI [37105571297](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37105571297) は `failure`。CodeQL [37105571317](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/37105571317) は `success`。
- Session 0 runner は Windows Server 2025。診断ログは `session=0`、broker と action のユーザー SID はともに `S-1-5-80-1970768882-1784875830-2469753724-3049475639-218607474`。Action の整合性レベルは Medium (`8192`)、Broker は `12288`。

開いた実ログは `.harness/T-011-M1-run-37105578000-{final.json,watch.txt,full.log,session0.log,installer.log}`、`.harness/T-011-M1-run-37105571297-{final.json,watch.txt,full.log,installer.log}`、`.harness/T-011-M1-run-37105571317-final.json`。Session 0 の観測照合は `.harness/runs/20261003-161723/verify-T-011-M1-2.txt` に保存した。

## Session 0 の結果

診断分類は `NO_WINDOW_NOT_SUFFICIENT`。Baseline と `CREATE_NO_WINDOW` の両方で子の生成は成功したが、初期化結果は `dll-init-failed`、終了値は `0xc0000142` だった。`ACTION_STARTS` にはならなかった。

| 項目 | 実測 |
|---|---|
| Session / worker-actions SID | Session `0`。`WorkerActionsSid=S-1-9-1651336531-1920301665-1870081653-1919249266-2617622895-2555344629-1974502065-3972078236` |
| 共有ステーション | `Service-0x0-297b30$` |
| station の追加 ACE | action SID に `count=1;flags=0;mask=0x00000002`。後始末後は `StationCleanup=removed` |
| action desktop | 同じ station 上に run ごとの desktop を作成。Baseline は `sbz-e65d064a5f0ab2f13b4622db91322042`、NO_WINDOW は `sbz-e738ab3edf7bc854f2965622bdd8dc34` |
| desktop DACL | 両 arm とも非継承 ACE。サービス SID は `0x000f01ff`、action SID は `0x000201ff`。DACL control は `0x9004` |
| 対象アクセス | station の `MAXIMUM_ALLOWED` / `0x00000002` と desktop の `MAXIMUM_ALLOWED` / `0x00000001` / `0x000201ff` が全て許可された (`gle=0`) |
| Job UI / 起動 flags | 両 arm の Job UI は `0x000000fe`。Baseline は `0x00080404`、NO_WINDOW は `0x08080404` |
| action 隔離 | 自 action は許可。別 action と broker の `Default` は `ERROR_ACCESS_DENIED` (`5`)。`WRITE_DAC` / `WRITE_OWNER` も拒否。`default_dacl_safe=true`、`tcb_absent=true` |
| tree と後始末 | 両 arm とも desktop 作成・隔離確認・tree 終了・desktop 削除が `true`。station の追加 ACE も削除された |
| SACL | 対象 desktop は `label=absent;implied_integrity=8192` |

診断ハーネスは canonical `SembazuruWorker` の前後 snapshot を比較し、不一致なら後始末エラーとして失敗する。Session 0 job は分類を出力して成功終了し、primary / cleanup error は記録されていないため、snapshot比較とfixture・一時serviceの後始末は通過した。前後の個別 snapshot 値とfixtureの識別値自体はログに出力されていない。

`StationAce` の `0x00000002` では station と action desktop のアクセス確認が通ったが、子の初期化は両 arm で失敗した。この実測では `0x0002` の最小性は判定できない。`0x0022` との比較および成功 mask の各ビットを除く測定も行っていない。

## MSI / Bundle と installer 検査

Release installer job は MSI と Bundle を生成して artifact をアップロードした。署名証明書は設定されておらず (`HAS_SIGNING_CERT=false`)、両 artifact は未署名。MSI artifact は 10,755,078 bytes、SHA-256 `420a65eb6c8973d10971f356515ef09c09c75713459ef79bc61cffa891702a1e`。Bundle artifact は 36,320,542 bytes、SHA-256 `aeafcf6a58082809bbfc1a90664db9c28301c9149d3df5b1524943f9a9e8391b`。タグ条件は成立せず、GitHub Release 作成は実行されていない。

同 SHA の PR CI `M9.6 installer` 実ログでは MSI install / repair / uninstall、ProgramData の directory / config / child ACL、uninstall cleanup が成功した。サービスは `SembazuruWorker` / `NT SERVICE\SembazuruWorker` として起動・接続を確認した。一方、installed worker の plain control は `exit=-1073741502` (`0xC0000142`)、`states-ok=True traces=0` で失敗し、外側の ProgramData ACL job は failure となった。ログの installed worker event 診断は `no-allowlisted-event`。これは Release の Session 0 診断分類とは別の検査である。

PR CI ではこのほか Rust Clippy と Windows 2022 / 2025 の C++ M6.1b job も失敗した。CodeQL は成功した。

## 判定

I1 / I2 を含む同一 SHA の Session 0 実測は得られたが、制限付き Medium action が `0xc0000142` にならず正常終了する条件を満たさなかった。実測分類は `NO_WINDOW_NOT_SUFFICIENT` であり、T-011-M1 は未完了。installer の plain control も同じ SHA で失敗した。この run では最小 mask、`0x0022`、成功 mask のビット除去は未測定だった。
