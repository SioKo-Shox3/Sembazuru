# Guardian単位 Local Job テスト制御 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Windows Local Job の全 test injection/対象別observerを guardian 固有 context に束縛し、無関係な並列 guardian による failpoint/observer 横取りを構造的に不可能にする。

**Architecture:** test command に opaque ID marker を付け、test-only registry の `Weak<TestGuardianState>` を `run_local` entry で一度だけ解決する。setup owner、`MonitorShared`、`Handles`、monitor thread、cleanup owner は同じ `Arc<TestGuardianState>` を共有し、production build には routing/state を含めない。

**Tech Stack:** Rust、Tokio、Windows Job Objects/IOCP、`std::sync::{Arc, Weak, LazyLock, Mutex, Condvar}`。

## Global Constraints

- HEAVY path。implementation source は implementer が書き、main thread は書かない。
- Source write paths は `crates/agent/src/lib.rs`、`crates/agent/src/run.rs`、`crates/agent/src/intake.rs` の3ファイルだけ。
- sourceのtextual editは既存internal function/typeへ `#[cfg(test)]` field/parameter/branchを追加し得るが、`cfg(not(test))`でcompileされるinternal signature、code path、protocol、public API、production Job/IOCP/terminal/EOF semanticsは不変。
- marker は `SEMBAZURU_INTERNAL_TEST_LOCAL_JOB_CONTROL`。spawned child へ渡さない。
- control-bound command は NoWorker/local guardian test に限定し、live worker へ dispatch しない。
- production-global `QUARANTINE_COUNT` は維持する。target-specific global injection/observer は全廃する。
- raw observed Job/child handle は `take_*` caller が closeする。control/state Drop は closeしない。
- temporary broken-stderr stage/temp-file/panic-hook と daemon diagnostic breadcrumb は最終差分から除去する。
- implementer は commit/stage/pushしない。同一アプローチ2回失敗で証拠を返して停止する。

---

### Task 1: 無関係 guardian が failpoint 4 を盗む決定的 RED を固定する

**Files:**
- Modify/Test: `crates/agent/src/lib.rs` の Windows unit-test module と fixture helpers

**Interfaces:**
- Consumes: `fixture_command`、`accept_local_job_fixture`、`with_submission_deadline`、現行 `local_job::install_failpoint(4)`。
- Produces: `tests::local_job_failpoint_is_bound_to_target_guardian`。旧global実装で必ずREDになる。

- [ ] **Step 1: target A と decoy B の順序を決定化するテストを書く**

最初のREDではtarget Aへ現行global point 4をinstallする。AはDETACH付きで2 peers接続まで開始する。次にfailpoint無しのdecoy Bを開始し、両peersをreleaseして`NaturalReaped`/exit 0まで完了させる。その後Aのparentだけをreleaseする。

```rust
local_job::install_failpoint(4);
let mut target_run = tokio::spawn(with_submission_deadline(
    Arc::clone(&target_deadline),
    async move { run_local(&target_command).await },
));
let mut target_peers = accept_local_job_fixture(target_listener).await;

let decoy_run = tokio::spawn(with_submission_deadline(
    Arc::clone(&decoy_deadline),
    async move { run_local(&decoy_command).await },
));
let mut decoy_peers = accept_local_job_fixture(decoy_listener).await;
for peer in &mut decoy_peers {
    peer.socket.write_all(&[1]).unwrap();
}
assert_eq!(decoy_run.await.unwrap().unwrap(), 0);
assert_eq!(decoy_deadline.phase(), SubmissionPhase::NaturalReaped);

target_peers.iter_mut().find(|p| p.role == 1).unwrap()
    .socket.write_all(&[1]).unwrap();
assert!(
    tokio::time::timeout(Duration::from_millis(100), &mut target_run)
        .await.is_err(),
    "unrelated guardian consumed the targeted disarm failpoint",
);
assert!(!target_peers.iter().find(|p| p.role == 0).unwrap().is_signaled());
```

unexpected early completion時はchild peerをreleaseしてprocessを回収してからpanicする。正常なpending確認後は`target_deadline.request_force()`し、targetが`Interrupted`/`ForcedReaped`、全peers signaledになることをassertする。output pathsは次のhelperを使う。

```rust
fn unique_job_output(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "sembazuru-job-{label}-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
```

- [ ] **Step 2: RED を実行する**

```powershell
cargo test --locked -p sembazuru-agent tests::local_job_failpoint_is_bound_to_target_guardian -- --exact --nocapture
```

Expected: `unrelated guardian consumed the targeted disarm failpoint` でFAIL。decoy Bがpoint 4を消費しtarget Aがfast-disarmする。異なるsignatureまたは不安定なら実装へ進まず停止する。

---

### Task 2: `TestGuardianControl` と instance routing を実装する

**Files:**
- Modify: `crates/agent/src/lib.rs:30-55, 500-520, 543-2100`
- Test: Task 1 test

**Interfaces:**
- Consumes: `Command.env`、`current_submission_deadline()`、setup/monitor/audit/cleanup paths。
- Produces: `local_job::TestGuardianControl` と per-guardian `Arc<TestGuardianState>`。

- [ ] **Step 1: test-only state、handle、registry を追加する**

```rust
#[cfg(test)]
pub(super) const TEST_CONTROL_MARKER: &str =
    "SEMBAZURU_INTERNAL_TEST_LOCAL_JOB_CONTROL";

#[cfg(test)]
pub(super) struct TestGuardianState {
    failpoint: std::sync::atomic::AtomicU8,
    delayed_new: Mutex<bool>,
    delayed_new_changed: Condvar,
    terminate_pause: Mutex<(bool, bool)>,
    terminate_pause_changed: Condvar,
    observe_job: AtomicBool,
    observed_job_handle: AtomicUsize,
    last_child_handle: AtomicUsize,
    last_audit_raw: AtomicU64,
    last_audit_unique: AtomicU64,
    last_audit_total: AtomicU64,
    job_owner_close_count: AtomicU64,
    natural_publish_branch: std::sync::atomic::AtomicU8,
    run_local_deadline_state: std::sync::atomic::AtomicU8,
    last_consumed_failpoint: std::sync::atomic::AtomicU8,
}

#[cfg(test)]
pub(crate) struct TestGuardianControl {
    id: u64,
    state: Arc<TestGuardianState>,
}

#[cfg(test)]
static NEXT_TEST_CONTROL_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
static TEST_CONTROLS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<u64, std::sync::Weak<TestGuardianState>>>,
> = std::sync::LazyLock::new(|| Mutex::new(std::collections::HashMap::new()));
```

`TestGuardianState::new()`は全atomic=0、`delayed_new=false`、`terminate_pause=(false,false)`。

- [ ] **Step 2: control API と resolver を実装する**

```rust
#[cfg(test)]
impl TestGuardianControl {
    pub(crate) fn bind(command: &mut Command) -> std::io::Result<Self>;
    pub(crate) fn install(&self, point: u8);
    pub(crate) fn observe_job(&self);
    pub(crate) fn release_delayed_new(&self);
    pub(crate) fn wait_before_terminate_reached(&self);
    pub(crate) fn release_before_terminate(&self);
    pub(crate) fn take_observed_job_handle(&self) -> usize;
    pub(crate) fn take_last_child_handle(&self) -> usize;
    pub(crate) fn take_last_audit_counts(&self) -> (u64, u64, u64);
    pub(crate) fn job_owner_close_count(&self) -> u64;
    pub(crate) fn take_natural_publish_branch(&self) -> u8;
    pub(crate) fn take_run_local_deadline_state(&self) -> u8;
    pub(crate) fn take_last_consumed_failpoint(&self) -> u8;
}

#[cfg(test)]
pub(super) fn resolve_test_control(
    command: &Command,
) -> std::io::Result<Option<Arc<TestGuardianState>>>;
```

`bind`は`AtomicU64::fetch_update` + `checked_add`でmonotonic nonzero IDを採番し、`ID -> Weak<State>`を登録し、decimal IDをmarker valueに挿入する。case-insensitiveな既存markerは`AlreadyExists`。resolverはmarker 0件なら`Ok(None)`、exactly 1件だけparseし、zero/non-decimal/registry miss/Weak upgrade failureをerror、別casingを含む2件以上を`InvalidInput`にする。silent fallback禁止。`Drop`はregistry Weakが自身のallocationと一致する場合だけentryを除去し、raw handlesはcloseしない。

`install(11)`はそのstateの`delayed_new=true`、`install(20)`はpauseを`(true,false)`にしてからslotをstoreする。consume成功時は同じstateの`last_consumed_failpoint=point`。

`TestGuardianState` はcrate-root専用internal methodを持つ。

```rust
#[cfg(test)]
impl TestGuardianState {
    pub(super) fn record_run_local_deadline(&self, present: bool) {
        self.run_local_deadline_state
            .store(if present { 2 } else { 1 }, Ordering::SeqCst);
    }

    fn is_armed(&self, point: u8) -> bool {
        self.failpoint.load(Ordering::SeqCst) == point
    }

    fn take_failpoint(&self, point: u8) -> bool {
        let consumed = self.failpoint
            .compare_exchange(point, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if consumed {
            self.last_consumed_failpoint.store(point, Ordering::SeqCst);
        }
        consumed
    }
}
```

- [ ] **Step 3: `run_local` entry で一度だけresolveする**

Windows test buildだけdeadline判定前にresolverを呼び、同じstateへ`1=None/2=Some`を記録する。marker付きでdeadline Noneなら`io::Error`にしてplain spawnを拒否する。production用zero-size controlは追加せず、`#[cfg(test)]`/`#[cfg(not(test))]` call branchを分ける。

```rust
#[cfg(all(test, windows))]
let test_control = local_job::resolve_test_control(command)?;
let submission_deadline = current_submission_deadline();
#[cfg(all(test, windows))]
if let Some(state) = &test_control {
    state.record_run_local_deadline(submission_deadline.is_some());
    if submission_deadline.is_none() {
        return Err(std::io::Error::other(
            "test guardian control requires a submission deadline",
        ));
    }
}
```

- [ ] **Step 4: setup、monitor、audit、cleanupへ同じstateを伝播する**

- test buildの`local_job::run`へ`Option<Arc<TestGuardianState>>`を渡す。
- `MonitorShared`にtest-only control fieldを追加し、`Handles -> MonitorShared`でcleanup ownerまで維持する。
- Job owner `OwnedHandle`だけtest state cloneを持ち、Drop時にそのstateのclose countを増やす。
- setup points 1–8はrun local state、monitor points 9–12/17–19/21は`MonitorShared`、audit/cleanup points 13–16/20/22は`Handles.shared`だけを見る。
- point 4 consume後のpoint 22確認と、points 1–3のretained-child observer precheckは`is_armed`を使いslotを消費しない。
- `query_accounting(job: HANDLE, #[cfg(test)] test_control: Option<&TestGuardianState>)`とし、top seedとauditが`handles.shared`の同じcontrolでpoints 14/22を消費する。production compiled signatureは従来どおり`query_accounting(job)`。
- `create_job(#[cfg(test)] test_control: Option<Arc<TestGuardianState>>)`、`OwnedHandle::new_job(handle, #[cfg(test)] test_control)`、`MonitorShared::new(#[cfg(test)] test_control)`とし、各production compiled signatureは従来どおりに保つ。classifierはtest buildで`create_job(None)`、通常setupは同じstateを渡す。
- `MonitorShared::new(None)`はclassifier helpersだけに許可し、global fallback禁止。

- [ ] **Step 5: child env chokepointでmarkerを二重に除外する**

```rust
#[cfg(test)]
cmd.env_remove(TEST_CONTROL_MARKER);
for (key, value) in &command.env {
    #[cfg(test)]
    if key.eq_ignore_ascii_case(TEST_CONTROL_MARKER) {
        continue;
    }
    cmd.env(key, value);
}
```

fixture child entryでmarker absentをassertする。control-bound testsはNoWorker/local routeをassertする。

- [ ] **Step 6: Task 1をtarget controlへ切替えてGREENにする**

```rust
let target_control = local_job::TestGuardianControl::bind(&mut target_command).unwrap();
target_control.install(4);
```

decoy Bはunbound。pending確認後に`target_control.take_last_consumed_failpoint() == 4`をassertする。

```powershell
cargo test --locked -p sembazuru-agent tests::local_job_failpoint_is_bound_to_target_guardian -- --exact --nocapture
cargo check --locked -p sembazuru-agent
```

Expected: focused `1 passed; 0 failed`、production check exit 0。

---

### Task 3: 全callsite移行とtemporary diagnostic除去

**Files:**
- Modify/Test: `crates/agent/src/lib.rs`
- Modify/Test: `crates/agent/src/run.rs` の daemon deadline test
- Modify/Test: `crates/agent/src/intake.rs` の setup point 5 test

**Interfaces:**
- Consumes: Task 2 control API。
- Produces: process-global target-specific injection/observer 0件。

- [ ] **Step 1: injection/synchronization callsitesをcontrolへ移行する**

| Path | 現行用途 | 置換 |
|---|---|---|
| `intake.rs:1181` | point 5 | commandを変数化、bind、`control.install(5)` |
| `run.rs:1351` | point 4 | target commandへbind、`control.install(4)` |
| `lib.rs:2476` | broken-stderr natural point 16 | child fixture commandへbind/install |
| `lib.rs:2713,2740` | `force_fixture_with_failpoint` | helper内bind/install、controlも返す |
| `lib.rs:2816,2830` | point 11/release | 同じcontrol |
| `lib.rs:2865,2878` | point 20/release | 同じcontrol |
| `lib.rs:2992` | point 22 | control |
| `lib.rs:3115` | points 5–8 | iterationごとにcontrol |
| `lib.rs:3393` | point 16 | control |
| `lib.rs:3508` | points 1–3 | iterationごとにcontrol |
| `lib.rs:3556,3607` | point 4 | control |

`force_fixture_with_failpoint`は`(io::Result<i32>, SubmissionPhase, Vec<LocalJobFixturePeer>, TestGuardianControl)`を返す。

- [ ] **Step 2: observer callsitesをcontrolへ移行する**

Job observerは`control.observe_job()`後に`take_observed_job_handle()`、owner close/audit/child/natural branch/deadline/consumed pointも同じcontrolから読む。raw handlesは既存callerだけが一度closeする。`QUARANTINE_COUNT`だけglobal維持。

- [ ] **Step 3: globalsとtemporary diagnosticsを削除する**

削除対象はcrate-root run-local observer、`NEXT_FAILPOINT`、global DELAY_NEW/terminate pause、Job/child/audit/owner globals、natural branch/failpoint4 globals、broken-stderr stage/temp-file/env dump/panic hook/elapsed、run.rs一時membership/global diagnostic print。broken-stderr本体、OS broken pipe、captured stdout/stderr、forced/natural ownership assertionsは残す。

- [ ] **Step 4: registry/observer/raw-handle回帰を追加する**

個別testで次を固定する。

1. target/decoy testでtarget controlのobserved Job handle、deadline state=2、consumed point=4、audit counts、natural branchがdecoyに上書きされない。
2. marker zero、non-decimal、別casing2件、drop済みcontrol IDがresolver error。既存marker付きcommandへの`bind`もerror。
3. `take_observed_job_handle()`後にcontrolをdropし、`GetHandleInformation`成功後にcallerが一度だけ`CloseHandle`。
4. setup points 1–3でretained child handleが同じcontrolから取得できる。
5. fixture child内でmarker absent。
6. valid controlをbindしたcommandをsubmission deadline無しで`run_local`し、processをspawnせずerror、`take_run_local_deadline_state()==1`。nonblocking listenerへ接続が無いことも確認する。

- [ ] **Step 5: 旧global語彙とtemporary diagnostic語彙をsweepする**

```powershell
rg -n "NEXT_FAILPOINT|OBSERVE_NEXT_JOB|OBSERVED_JOB_HANDLE|LAST_CHILD_HANDLE|LAST_AUDIT_|JOB_OWNER_CLOSE_COUNT|DELAY_NEW|TERMINATE_PAUSE|OBSERVE_NEXT_RUN_LOCAL|LAST_RUN_LOCAL_DEADLINE_STATE|LAST_NATURAL_PUBLISH_BRANCH|LAST_FAILPOINT4_CONSUMED|install_failpoint\(" crates/agent/src/lib.rs crates/agent/src/run.rs crates/agent/src/intake.rs
```

Expected: global declarations/accessors/calls 0件。instance fields/methodsだけなら行単位確認する。

```powershell
rg -n "BROKEN_STDERR_DIAG_STAGE|broken_stderr_diag_path|broken_stderr_record|broken_stderr_env_snapshot|install_broken_stderr_diagnostics|BROKEN_STDERR_DIAG|BROKEN_STDERR_PANIC|sembazuru-forced-diag|DAEMON_DEADLINE_DIAG|started\.elapsed\(\)" crates/agent/src/lib.rs crates/agent/src/run.rs
```

Expected: 0件。`break_process_stderr`、scenario env、captured stdout/stderrは残す。

- [ ] **Step 6: focused testsを実行する**

```powershell
cargo test --locked -p sembazuru-agent tests::local_job_failpoint_is_bound_to_target_guardian -- --exact --nocapture
cargo test --locked -p sembazuru-agent tests::local_job_broken_stderr_cannot_interrupt_quarantine -- --exact --nocapture
cargo test --locked -p sembazuru-agent run::tests::daemon_deadline_forces_disarm_wait_before_retry_eof -- --exact --nocapture
```

Expected: 各`1 passed; 0 failed`。

---

### Task 4: parallel回帰と統合gate

**Files:** repository-wide verify only。

- [ ] **Step 1: local_jobとagent libのparallel反復**

```powershell
cargo test --locked -p sembazuru-agent local_job_ -- --test-threads=1
1..10 | ForEach-Object {
    cargo test --locked -p sembazuru-agent tests::local_job_broken_stderr_cannot_interrupt_quarantine -- --exact --quiet
    if ($LASTEXITCODE -ne 0) { throw "broken-stderr repetition $_ failed" }
}
1..10 | ForEach-Object {
    cargo test --locked -p sembazuru-agent --lib --quiet
    if ($LASTEXITCODE -ne 0) { throw "agent lib parallel repetition $_ failed" }
}
```

Expected: focused、broken-stderr 10/10、agent lib 10/10の全て0 failed。test数は実装後の実数を報告する。

- [ ] **Step 2: package/workspace gates**

```powershell
1..3 | ForEach-Object {
    cargo test --locked -p sembazuru-agent --all-targets
    if ($LASTEXITCODE -ne 0) { throw "agent all-targets repetition $_ failed" }
}
cargo test --locked -p sembazuru-cas --all-targets
cargo test --locked -p sembazuru-worker --all-targets
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
cargo doc --locked -p sembazuru-agent --no-deps
```

Expected: tests 0 failed、clippy/fmt/diff exit 0、既知rustdoc 10 warnings以外の新規warning 0。

- [ ] **Step 3: scope/mirror**

```powershell
node C:\Users\<user>\.agent-workflow\check-scope.mjs .superpowers\sdd\cas-revocation-wave3-declaration.md --base a5d2e27c509d151e11e6e25d14c43d833a30ee22
git diff --no-index -- AGENTS.md CLAUDE.md
```

Expected: scope OK、mirror diff出力なし。

- [ ] **Step 4: implementer handoff**

RED、focused GREEN、10反復、all-targets、clippy/fmt/diff、production check、変更pathsを返す。commit/stage/pushしない。

---

## Orchestrator-only completion gates

1. `git diff --stat` と全target-specific globalのmechanical sweep。
2. native VFS、速度、determinism gates再実行。
3. integrated diffへfresh Codex implementation/security review。
4. `$prompt = Get-Content -Raw .superpowers\sdd\fresh-claude-final-integrated-review.md; claude -p $prompt --model opus --permission-mode plan`のfresh Claude review。
5. 全review CLEAN後だけ単一purposeの日本語commit。
6. Wave 6 transport-break reconciliationへ進む。GUI build monitorとgoal completeには進まない。
