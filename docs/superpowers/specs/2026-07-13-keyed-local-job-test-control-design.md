# Local Job テスト制御の guardian 単位化 設計

## 背景と決定

Windows Local Job guardian の failpoint は、現在 process-global な単一 `AtomicU8` である。failpoint を install するテスト同士は `LOCAL_JOB_TEST_LOCK` で直列化されているが、failpoint を持たない並列 guardian も全ての `take_failpoint(point)` を試す。このため、無関係な guardian が対象テストの failpoint 4 を先に消費し、対象 guardian が fast-disarm して natural Exit を公開した。

実機 RED では次を同時に観測した。

- `run_local` は submission deadline 付きで実行された。
- 親・grandchild はどちらも対象 guardian Job の exact member だった。
- grandchild は生存していた。
- failpoint 4 は process-global には消費済みだった。
- 対象 guardian は failpoint 4 を見ず、fast-disarm natural branch を通った。

採用方針は、ユーザー承認済みの A 案、すなわち **全 failpoint と付随同期状態を対象 guardian 固有の test-only context に束縛する**方式とする。

## 目標

1. 無関係な guardian が別テストの failpoint を消費できない。
2. setup、monitor、audit、stop/join の全 failpoint を同一方式で対象指定できる。
3. DELAY_NEW と terminate pause の同期状態も guardian ごとに分離する。
4. Job handle、child handle、audit counts、Job-owner close count のテスト観測値も guardian ごとに分離する。
5. test marker は実行対象の子プロセス環境へ渡さない。
6. production build、protocol、公開 API、Job/IOCP 所有権、terminal/EOF 意味論を変更しない。
7. 調査用の一時 breadcrumb・temp-file logging は最終差分から除去する。

## 非目標

- production 用 fault injection の追加。
- Job/IOCP guardian アルゴリズムの変更。
- `SubmissionDeadline` や transport reconciliation の変更。
- Wave 6 の `action_lease_id` / transport-break reconciliation。
- GUI build monitor の実装。

## 選択肢

### A. Guardian 固有の test control（採用）

各対象 command に opaque な test ID を付け、test-only registry の `Weak<TestGuardianState>` を exact `Arc<TestGuardianState>` に解決する。guardian は entry 時に一度だけ state を取得し、以後の injection はその state だけを見る。

利点は、並列テストと将来の guardian 追加に対して構造的に安全で、setup 前から monitor thread まで同じ identity を使えることである。変更量は他案より大きいが、根因そのものを除去する。

### B. 全 guardian テストを共有 lock 配下に置く（不採用）

変更量は小さいが、新しいテストが lock を取り忘れるだけで再発する。failpoint を install しない guardian も consumer になるという構造を残す。

### C. Failpoint 4 だけ command 特例にする（不採用）

今回のテストだけは直るが、points 1–3、5–22 と DELAY_NEW/terminate pause に同じ横取り可能性を残す。根因修正にならない。

## 構造

### `TestGuardianControl`

`crates/agent/src/lib.rs` の `local_job` module 内、`#[cfg(test)]` に限定して定義する。`TestGuardianState` は crate-root `run_local` から型とinternal methodだけを利用できる `pub(super)`、fieldsはprivateとする。テスト側の `TestGuardianControl` handle は opaque ID と `Arc<TestGuardianState>` を保持し、guardian 側には state の `Arc` だけを渡す。

保持する状態:

- opaque `u64` ID;
- consume-once failpoint slot;
- DELAY_NEW の flag + condition variable;
- terminate pause の `(enabled, reached)` + condition variable;
- observed Job duplicate handle;
- setup failure時のretained child handle;
- last audit `(raw, unique, total)`;
- 当該 guardian のJob-owner close count;
- last natural-publish branch (`2=fast disarm`, `3=audit natural`);
- `run_local` entry で観測した submission deadline state (`1=None`, `2=Some`);
- last consumed failpoint number。

テスト側 handle は control の `Arc` を保持し、次の操作を提供する。

- `TestGuardianControl::bind(command: &mut Command) -> std::io::Result<Self>`;
- `install(&self, point: u8)`;
- `observe_job(&self)`;
- `release_delayed_new(&self)`;
- `wait_before_terminate_reached(&self)`;
- `release_before_terminate(&self)`;
- `take_observed_job_handle(&self) -> usize`;
- `take_last_child_handle(&self) -> usize`;
- `take_last_audit_counts(&self) -> (u64, u64, u64)`;
- `job_owner_close_count(&self) -> u64`;
- `take_natural_publish_branch(&self) -> u8`;
- `take_run_local_deadline_state(&self) -> u8`;
- `take_last_consumed_failpoint(&self) -> u8`。

`TestGuardianControl` とこれらの method は全て `pub(super)` か `pub(crate)` の `#[cfg(test)]` に限定し、production API にはならない。

`TestGuardianState` はcrate-root routing用に `pub(super) fn record_run_local_deadline(&self, present: bool)` を提供する。crate-rootはprivate fieldへ直接アクセスしない。

failpoint state は `is_armed(point) -> bool`（非消費）と `take_failpoint(point) -> bool`（consume成功時にlast consumed pointを記録）を分ける。point 22のprecheckとpoints 1–3のretained-handle precheckは`is_armed`、既存の注入位置だけが`take_failpoint`を使う。

### Registry と lifetime

test-only registry は `ID -> Weak<TestGuardianState>` を保持する。

1. テストが control を作り、command に予約 marker を付ける。
2. crate-root の `run_local` が `current_submission_deadline()` を判定する前に marker を読み、`local_job` の test-only resolver で exact control を解決する。解決した control に deadline state を記録する。
3. deadline が存在する場合、`run_local` は同じ control を `local_job::run` へ渡す。marker 付きなのに deadline が存在しない場合は、テスト setup error として silent plain-spawn を拒否する。
4. 解決した `Arc` は setup owner、`MonitorShared`、drop/cleanup owner が共有する。
5. monitor thread を含む全 `take_failpoint` は、この instance context の slot だけを参照し、consume 成功時は同じ context に point number を記録する。
6. control handle の `Drop` が、自分と同じ allocation を指す registry entry だけを除去する。guardian が既に取得した `Arc` の lifetime は変えない。

ID は process-lifetime `AtomicU64::fetch_update` + `checked_add` で単調採番し、0とwrapを拒否する。`bind` はcase-insensitiveな既存marker衝突を拒否する。resolverはcase-insensitiveにexactly-one markerを要求し、不正decimal、zero、別casing重複、registry miss、Weak upgrade failureをsilent fallbackせずerrorにする。ID のない command は failpoint/observer無しの context を使い、他 control を参照しない。

observed Job handle と retained child handle の所有権は、`take_*` で受け取ったテスト側に移り、テストが close する。control の `Drop` は未取得の raw handle を close しない。これは既存の「取得されない観測 handle は test process lifetime まで保持する」意味論を維持し、guardian 側との二重 close を避ける。

### Marker の隔離

予約 marker は test harness 内部だけの routing metadata とする。

- crate-root `run_local` だけが command から marker をexactly onceで読み、resolved stateを `local_job::run` へ渡す。`local_job::run` はmarkerを再parseしない。
- `tokio::process::Command` に environment を転送する単一 chokepoint で、先に `cmd.env_remove(marker)` を呼び、command map の loop でも marker を case-insensitive に skip する。loop の skip だけでは親process環境の同名変数を継承し得るため不可。
- production build には registry/control routing を含めない。
- marker 名は `SEMBAZURU_INTERNAL_TEST_*` prefix とし、外向け設定として文書化しない。
- control-bound command は live worker に dispatch しない NoWorker/local guardian テストに限定する。remote transport でのmarker除去は今回のscopeに含めず、対象テストは local route を明示的に成立させる。

## データフロー

```text
test
  -> control = TestGuardianControl::bind(&mut command)?
  -> control.install(point)
  -> run_local(command)
       -> marker ID lookup exactly once before deadline check
       -> deadline Some/None recorded on the same control
       -> per-guardian Arc<TestGuardianState>
       -> setup / monitor / audit / cleanup consume only this control
       -> ownership/audit observations return only to this control
       -> marker is not forwarded to spawned process
```

無関係 guardian は ID を持たないか別 ID を持つため、対象 slot を読み取れない。

## 移行範囲

実装 source の write path は次の3ファイルに限定する。

- `crates/agent/src/lib.rs`: context、registry、guardian wiring、既存 unit tests。
- `crates/agent/src/run.rs`: daemon deadline テストの対象 control 付与。
- `crates/agent/src/intake.rs`: 既存 failpoint 5 テストの対象 control 付与。

既存の `install_failpoint(point)`、global DELAY_NEW、global terminate pause、global Job/child observer、global audit counts、global Job-owner close count、global natural-publish branch、global failpoint4-consumed、crate-root のglobal run_local-deadline observerに依存する全 callsiteを機械的に列挙し、control handle APIへ移行する。`run_local` entryのtest-only観測もmarkerから解決した同じcontrolへroutingする。process-globalのinjection/対象別observer slotは残さない。production運用値である quarantine ID/count はglobalのまま維持する。

## TDD と回帰試験

### 決定的 RED

対象 guardian に failpoint 4 を設定した後、無関係な guardian を先に natural completion させる。その後、対象 guardian の top を終了させる。

旧 global 実装では無関係 guardian が point 4 を消費し、対象が fast-disarm natural になるため RED。新実装では無関係 guardian は対象 slot を参照できず、対象だけが disarm-failure path に入る。

テストは次を確認する。

- 無関係 guardian は natural completion。
- 対象 guardian は point 4 を自分で消費。
- live grandchild がいる間、natural Exit を公開しない。
- force 後は対象 tree を reap し、安全な terminal/EOF 契約を維持する。

### 全 failpoint 移行回帰

- points 1–22 の既存 focused tests を維持する。
- monitor-thread points も exact context を使用する。
- DELAY_NEW と terminate pause の release/wait は同じ control に対してのみ作用する。
- marker が fixture child 環境に存在しないことを検証する。
- control-bound command が NoWorker/local guardian route を通ったことを検証する。
- control のない並列 guardian が対象 point を消費できないことを追加で検証する。
- control のない並列 guardian が対象の Job/child/audit observer を奪えないことを検証する。
- control のない並列 guardian が対象の natural-publish branch、run_local deadline state、consumed failpoint number を上書きできないことを検証する。
- zero/invalid/別casing重複/stale markerがresolver errorになることを検証する。
- `take_observed_job_handle()`後にcontrolをdropしてもraw handleが有効で、callerが一度だけcloseできることを検証する。
- setup points 1–3のretained child handleが同じcontrolへ返ることを検証する。

### 最終 gates

- focused deterministic theft RED/ GREEN。
- `cargo test --locked -p sembazuru-agent local_job_ -- --test-threads=1`
- `cargo test --locked -p sembazuru-agent --all-targets` を標準並列で反復。
- `cargo test --locked -p sembazuru-cas --all-targets`
- `cargo test --locked -p sembazuru-worker --all-targets`
- `cargo clippy --locked --workspace --all-targets -- -D warnings`
- `cargo fmt --all -- --check`
- `git diff --check`
- native VFS、速度、determinism gates。
- integrated scope check。
- fresh Codex implementation/security review と fresh Claude Opus review。

## Stop conditions

次のいずれかで実装を停止し、orchestrator へ証拠を返す。

- control の無い guardian が対象 slot を消費できる。
- marker が spawned process に渡る。
- setup/monitor/cleanup のどこかで global failpoint 参照が残る。
- natural branch、deadline state、consumed point を含む対象別global observerが残る。
- success/retry terminal、retained-handle signal、KILL_ON_CLOSE、EOF 契約が変わる。
- 同じ実装アプローチが2回失敗する。
