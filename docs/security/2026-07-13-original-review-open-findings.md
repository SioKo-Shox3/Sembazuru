# 初回コードレビュー未解決事項（2026-07-13）

この文書は、速度改善差分が新規に生んだ問題の一覧ではない。初回レビュー時点から存在する既存課題を含み、
速度改善とライブモニターを `main` の `25dede1` へマージした後に再監査した結果である。
次セッションは下記の `OPEN` だけを対象とし、末尾の解決済み項目を再修正しないこと。

## Critical

### RESOLVED: LocalSystem LocalIntakeの呼出元認証

- 対応: `68e5422`（DACL付きnamed pipe、caller SID、impersonation／restricted primary token、管理API分離）、
  `e284940`（LocalSystem server PIDのread-only SCM照合）、`a35bf9f`（2標準ユーザーのnative SID A/B）。
  設計同期と失敗証拠の保全は `b2ebb17`、`9ff8390`、`e8b7372`、`82cb16e`、`c0fc0f7`。
- 境界: production pipeはfirst-instance／remote reject／protected DACLを維持し、clientはserver SIDを送信前に検証する。
  daemonはfirst authenticated readでcaller tokenを捕捉し、callerのrestricted tokenでsuspended起動→Job割当て→resumeする。
  token／process起動失敗時にLocalSystem tokenへretryせず、Status/Admin RPCは別listenerのまま。
- ローカル検証: `cargo test -p sembazuru-agent --lib` は `258 passed; 0 failed; 2 ignored`、
  `rustup run 1.97.0 cargo clippy -p sembazuru-agent --all-targets -- -D warnings`、fmt、scope、差分検査が成功。
- clean Windows A/B: [CI run 29394437184](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29394437184)／
  [LocalIntake job 87284613248](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29394437184/job/87284613248) が成功。
  `DAEMON FALLBACK: A=...-1003 B=...-1004 SYSTEM=false crossed=false`、
  `DAEMON DOWN FALLBACK: caller=...-1003 note=verified`、最終PASSを確認した。
- Done: 標準ユーザーA/Bのdaemon-side childは各caller SIDで動き、SYSTEMにも相互callerにもならない。
  daemon停止後も正規launcherのlocal fallbackが同じ標準ユーザーSID・exit 0で完走する。

## High

### RESOLVED (2026-07-16): ProgramData ACL・平文トークン・安全な設定保存

- 対応（安全なstore／秘密）: `22b71f2`（handle相対・原子的な設定保存）、`b29b832`（canonical machine-store結線）、
  `53d15da`（DPAPI LocalMachineと固定identity）、`73331a1`・`6724bcf`・`6449e34`（前進回復journal、原子的削除、平文token移行）。
- 対応（競合／consumer）: `d598c3a`・`b4e521a`・`a53bff4`・`6ed779a`（service shared leaseとtoken-update exclusive lease、
  provision／commit両立、guard下secret read）、`3f48f57`（agent／worker canonical起動のguard→legacy全型拒否→DPAPI strict UTF-8→env適用）、
  `fefc745`（storectl認可、認可前stdin禁止、bounded／zeroized入力）、`e6f88e2`（Statusはpresenceのみ、Set／Clearはoffline保守、Keepは非secretのみ）。
- 統合追補: `941dcad`（cache成立後にworker停止）、`8e6ac87`・`df620f3`・`f60cbfe`（production境界を弱めず、直接起動testを明示Override identityへ移行）。
- 境界: `%ProgramData%\Sembazuru`は継承を遮断し、SYSTEM／Administrators／必要なservice SIDだけに限定する。
  store操作は保持handle相対、no-follow、owner／DACL／lifecycle／identity再検証、ランダム`create_new` tempと原子的replace／deleteを用いる。
  canonical tokenはDPAPI blobだけで、TOMLの全`cluster_token`型を移行案内付きで拒否する。
- ローカル検証: config-storeのmachine config／secret／token-update fault・collision・reparse・wrong-owner・resume tests、storectl認可7件、
  agent／worker canonical consumer tests、canonical Status `6 passed; 0 failed`、Override `config_rpc` `8 passed; 0 failed`、workspace、fmt、clippy、scopeが成功。
- clean CI: [run 29487785441](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29487785441) の
  [Rust](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29487785441/job/87586296817)、
  [installer ACL](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29487785441/job/87586296828)、
  [Windows 2022](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29487785441/job/87586296854)、
  [Windows 2025](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29487785441/job/87586296882) が成功し、
  [CodeQL run 29487785427](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29487785427) も成功。
- レビュー: orchestratorの統合行レビューは完了。direct Codex／Claude read-only統合レビューは各304秒でtimeoutし出力なしだったため、
  同一儀式を再実行せず、上記ローカル反証testとclean CIを出口証拠とした。
- Done: 標準Usersは設定・CAS・scratchのprivate ACLを通れず、秘密は平文保存されない。先置き、hardlink／reparse、wrong owner／DACL、
  root／journal置換、途中faultはfail closedまたはjournalから前進回復し、canonical serviceとtoken保守は同時に成立しない。

### RESOLVED: workerのプロセス・scratch分離

- 対応: `73026ce`（action固有restricted primary token、private scratch/runtime、plain／VFS production結線、
  `CREATE_SUSPENDED`→restricted token確認→exact Job割当て確認→`ResumeThread`）、`0c84462`（restricted token判定を正式APIで固定）、
  `2a9bb72`（productionと同じrestricted processによるbroker秘密／別action scratch拒否のnative E2E証拠）。
- 境界: action leafはbroker full＋action SIDのread/write/execute/deleteだけを持つprotected DACLとし、scratch root名の列挙は
  秘密境界に含めない。失敗時はsuspended guardianがchildをterminate/reapし、Jobはkill-on-closeかつbreakawayなしを維持する。
- ローカル検証: isolation evidence `1 passed; 0 failed`、restricted process群 `7 passed; 0 failed; 3 ignored`、
  `process_isolation` `2 passed; 0 failed`、`env_isolation` `1 passed; 0 failed`、worker lib `142 passed; 0 failed; 8 ignored`。
  `cargo fmt --all -- --check`、worker all-targets clippy `-D warnings`、scope、差分／行末検査も成功。
- レビュー: Codex round 1の既存file write拒否・失敗時fixture cleanup指摘を修正し、round 2 APPROVE。Claude統合二次確認もAPPROVE。
- Done: restricted primary childはbroker-onlyなconfig／machine token／CAS相当fileと別action scratchをread・既存write・新規createできず、
  exact kill-on-close Jobへの割当て確認後にだけresumeされ、setup失敗時は最初の命令を実行しない。

## P0 correctness

### RESOLVED: `non_deterministic`でも既存cacheをresolveする

- 対応: `e72174d`でnon-deterministic actionのweak key／tool identity生成を止め、resolve／prefetch／recordの全cache利用を遮断した。
  `fc0e3d3`で既存hit、非空の予測入力、record可能なverified tool／trace／declared outputを用意したproduction経路の回帰証拠を追加した。
- ローカル検証: 既存hitでもworkerへ到達してpredicted pathsが空、cache hit／miss counterがともに0となるexact testと、
  record条件を満たすremote成功後もfresh weak keyがmissのままであるexact testが各`1 passed; 0 failed`。
  `prefetch_scope`全体は`3 passed; 0 failed`、agent libは`280 passed; 0 failed; 2 ignored`。fmt、agent all-targets clippy
  `-D warnings`、scope、差分／行末検査も成功。
- レビュー: 独立Codex実装レビューは、事前条件・record gate・手書きtrace・cleanupを確認してAPPROVE（blocking／non-blocking所見なし）。
- Done: 既存entryの有無にかかわらずnon-deterministic actionは必ずworkerで実行され、cache hit／prefetch／recordを行わない。

### RESOLVED: build root内のabsent probeをcache keyから落とす

- 対応: `c1e10d0`で場所による分類を廃止し、traceの`ProbeMiss`はroot内外を問わず`InputKind::Absent`へ残し、
  probe根拠のないunreadable観測はuncacheableへ倒した。自己生成tempはgraphの成功したwrite→delete／rename event sequenceでのみ除外する。
  `7ada953`でbuild root内`generated/gen.h`を使うproduction AgentCacheのrecord→Hit→出現後MissをE2E固定した。
- ローカル検証: root内absent exact testは`1 passed; 0 failed`、agent libは`280 passed; 0 failed; 2 ignored`、
  tracer libは`79 passed; 0 failed`。fmt、agent／tracer all-targets clippy `-D warnings`、scope、差分／行末検査も成功。
- レビュー: LIGHT path。orchestrator差分レビューでcache storeとbuild fixtureの独立を維持するよう最小化し、再検証後に着地した。
- Done: `__has_include`等のroot内absent headerはcache keyへ保持され、後の生成でresolveがmissする。場所名だけでinputを落とさず、
  run-varyingな自己生成tempだけをevent sequenceにより除外し、不明なvanished readはcache記録を拒否する。

### OPEN: VFS子process注入がtrace依存かつfail-open

- 根拠: `crates/agent/src/intake.rs:638-653`、`crates/worker/src/lib.rs:839-840,911-912`、`hooks/src/interceptor.cpp:1649-1703`。
- 修正方向: `VFS mode || trace enabled`で子processへDLLを注入し、VFS中の注入失敗は未注入spawnへ再試行せずremote action失敗としてlocal fallbackへ返す。
- Done: cache無効のVFS実行でも子孫が必ずvirtualizeされ、注入失敗時にworker-local入力を使った成功結果が返らない統合テストが通る。

## P1

### RESOLVED (2026-07-20): cancel済みqueued actionがpermit取得後にspawnする

- 根拠: `crates/worker/src/lib.rs:516-520,572-617`。
- 修正方向: QUEUED送信失敗／receiver closeとpermit待ちを同時監視し、取消しをspawnより前に確定する。
- Done: capacity待ち中にclientを切断したactionが、permit解放後もprocess・scratch・Jobを作成しない競合テストが通る。
- 対応commit: `d354a05` (`P1: queued actionの切断をadmission前に取消す`)。`QUEUED`送信失敗を即時終了し、`tx.closed()`とpermit待ちを`biased`に同時監視したうえで、permit取得直後にもreceiver closeを再確認する。
- 検証証拠: `cargo test -p sembazuru-worker --test admission -- --nocapture` は `3 passed; 0 failed`。`dropping_a_queued_stream_cancels_before_admission`がpermit解放後も`served=1`、`running=0`、scratch空を維持し、取消済みactionがadmission・process/scratch/Job作成へ進まないことを固定する。

### OPEN: FileClient reader taskの自己保持リーク

- 根拠: `crates/worker/src/fileclient.rs:56-80,268-278`。
- 修正方向: readerが`Arc<Mux>`を永久保持しない所有権構造、または明示shutdown/Dropを導入し、最後のclient dropでsocketとreaderを終了させる。
- Done: peerがEOFを返さなくても最後の`FileClient` drop後にreader taskと接続が回収され、pending waiterも解放されるテストが通る。

## Performance

### OPEN: hook→worker named pipeをoperationごとに再接続する

- 根拠: `hooks/src/interceptor.cpp:482-542`（`CreateFileW`は`502-508`、`CloseHandle`は`541`）。
- 修正方向: 測定を追加したうえで、再入・終了処理を安全にしたper-thread接続再利用または小規模poolを導入する。
- Done: production相当benchmarkで接続回数とopen latencyが低下し、切断時の再接続・fallback回帰テストが通る。

### OPEN: metadata probeがfull hydrateする

- 根拠: `hooks/src/interceptor.cpp:760-794,1300-1403`。
- 修正方向: stat/batch-stat応答だけで属性probeを処理し、content open時だけhydrateする。
- Done: `GetFileAttributes*`主体のbenchmarkでcontent転送が発生せず、属性・absent結果が通常openと一致する。

### OPEN: trace recordごとに複数の同期`WriteFile`を行う

- 根拠: `hooks/src/trace_writer.cpp:112-129,255-278`。
- 修正方向: production条件の計測後、thread-local bufferまたは一括frameで同期write回数を削減し、process終了時のflushを保証する。
- Done: trace完全性とdeterminism gateを維持したまま、record当たりの`WriteFile`回数とwall timeが測定上減る。

## 解決済み（再修正しない）

- **同一パスhydrate競合**: single-flightと一時ファイルからのatomic renameで解決済み。
- **prefetch production結線**: absoluteな`InputKind::Content`だけを送り、件数・並列数を制限済み。
- **CAS range readのO(N²) I/O**: bounded range readへ移行済み。

これらは新しい失敗証拠が出ない限りscopeへ戻さず、次セッションはCriticalから順に独立した変更として進める。
