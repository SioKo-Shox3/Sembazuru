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
