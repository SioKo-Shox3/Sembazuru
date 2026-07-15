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

### OPEN: ProgramData ACL・平文トークン・安全な設定保存

- 根拠: `installer/sembazuru.wxs:215-241`、`crates/agent/src/config.rs:52,260-284`、`crates/worker/src/config.rs:137,418-444`。
- 現状: `%ProgramData%\Sembazuru`の継承ACLを閉じず、`cluster_token`を平文TOMLへ保存する。PID固定名の一時ファイルを`write`しており、先置きやreparse pointへの防御がない。
- 修正方向: SYSTEM／Administrators／必要なservice SIDだけのprivate DACL、DPAPI等による秘密保護、ランダム名＋`create_new`、所有者とreparse point検証、既存トークンのローテーションを実装する。
- Done: 標準Usersが設定・CAS・scratchを読めず作れず、秘密が平文保存されず、先置き／reparse回帰テストがfail closedする。

### OPEN: workerのプロセス・scratch分離の残部

- 根拠: `crates/worker/src/lib.rs:803-815,819-838,933-958`。
- 現状: actionはbrokerと同じservice tokenで動き、scratchにaction固有private ACLがない。processをspawnした後でJob Objectへ割り当てる短い逃走窓も残る。
- 修正方向: action固有SID/private ACL、restricted tokenまたはAppContainer executorを導入し、`CREATE_SUSPENDED`または`PROC_THREAD_ATTRIBUTE_JOB_LIST`で起動時からJobへ所属させる。
- Done: actionからbroker秘密・他action scratchへアクセスできず、最初の命令実行前から全子孫がkill-on-close Jobに拘束されるテストが通る。

## P0 correctness

### OPEN: `non_deterministic`でも既存cacheをresolveする

- 根拠: `crates/agent/src/intake.rs:573-578,711-720`。
- 修正方向: resolveとprefetchも`!non_deterministic`で囲み、recordだけでなく全cache利用を無効化する。
- Done: 既存entryがあってもnon-deterministic actionは必ず実行され、cache hit/prefetch/recordが発生しない回帰テストが通る。

### OPEN: build root内のabsent probeをcache keyから落とす

- 根拠: `crates/tracer/src/action_key.rs:418-453`（特に`447-448`）。
- 修正方向: build root内外ではなくtrace event種別で一時ファイルを分類し、通常のprobe missは`InputKind::Absent`に残す。不明な観測はuncacheableへ倒す。
- Done: `__has_include`等で初回absentだったheaderを後から生成するとcache missになり、run-varying一時ファイルは誤ってkeyを不安定化しない。

### OPEN: VFS子process注入がtrace依存かつfail-open

- 根拠: `crates/agent/src/intake.rs:638-653`、`crates/worker/src/lib.rs:839-840,911-912`、`hooks/src/interceptor.cpp:1649-1703`。
- 修正方向: `VFS mode || trace enabled`で子processへDLLを注入し、VFS中の注入失敗は未注入spawnへ再試行せずremote action失敗としてlocal fallbackへ返す。
- Done: cache無効のVFS実行でも子孫が必ずvirtualizeされ、注入失敗時にworker-local入力を使った成功結果が返らない統合テストが通る。

## P1

### OPEN: cancel済みqueued actionがpermit取得後にspawnする

- 根拠: `crates/worker/src/lib.rs:516-520,572-617`。
- 修正方向: QUEUED送信失敗／receiver closeとpermit待ちを同時監視し、取消しをspawnより前に確定する。
- Done: capacity待ち中にclientを切断したactionが、permit解放後もprocess・scratch・Jobを作成しない競合テストが通る。

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
