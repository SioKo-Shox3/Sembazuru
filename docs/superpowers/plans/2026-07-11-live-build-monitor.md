# ライブビルドモニタ Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** worker別execution slotで現在と直近60秒のsource build activityをタイムライン表示する。

**Architecture:** daemonの有界`ActionTracker`がschedulerとworker streamの状態遷移をattempt単位で記録し、Status snapshotがbasenameだけをGUIへ投影する。GUIは既存1.5秒pollを直列化し、eguiだけでworker×slotの60秒timelineを描く。物理CPU affinityやserver-streamingは導入しない。

**Tech Stack:** Rust 1.96、Tokio、tonic/prost、eframe/egui 0.34、既存Status loopback gRPC。

## Global Constraints

- 参照仕様: `docs/superpowers/specs/2026-07-11-speed-and-build-monitor-design.md`。
- 速度改善計画 `docs/superpowers/plans/2026-07-11-speed-improvements.md` の完了後に開始する。
- execution slotは可視化laneであり、物理CPU core番号と表現しない。
- activity retentionはterminal後60秒、全体最大4096 attempt、表示名最大128文字。
- Statusへfull path、argv、env、response-file content、tokenを追加しない。
- 現行loopback Statusはcaller SIDを認証しない。basename開示をREADMEへ明記する。
- monitor observer failureはbuild execution・scheduler・fallbackを失敗させない。
- 新しいGUI描画dependencyは追加しない。
- production codeを書く前に対応testをREDで確認する。
- 各Taskを個別commitし、author以外のreviewを通してから次へ進む。
- 同一手法2回失敗で停止し、証拠をmainへ返す。
- code/commentは英語、commit messageと判断資料は日本語。

---

### Task 1: 有界ActionTrackerと表示名redactionを追加する

**Files:**

- Create: `crates/agent/src/action_tracker.rs`
- Modify: `crates/agent/src/lib.rs:15-29`
- Test: `crates/agent/src/action_tracker.rs`

**Interfaces:**

- Produces: `ActionTracker`, `AttemptKey`, `ExecutionKind`, `ActivityState`, `ActivitySnapshot`。
- Produces: `display_name(command: &sembazuru_proto::v0::Command) -> String`。
- Produces: production `SystemClock`とretention test用injectable `TrackerClock`。
- Consumed by: Tasks 2-3のscheduler observerとStatus projection。

- [ ] **Step 1: moduleとRED testsを先に作る**

`lib.rs`へ次を追加する。

```rust
pub mod action_tracker;
```

`action_tracker.rs`に公開型とtestsだけを先に置く。

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const ACTIVITY_TTL: Duration = Duration::from_secs(60);
pub const MAX_ACTIVITY_ATTEMPTS: usize = 4096;
pub const MAX_DISPLAY_CHARS: usize = 128;
pub const MAX_ID_CHARS: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AttemptKey {
    pub action_id: String,
    pub attempt_no: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionKind { Remote, Local, Fallback }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityState {
    Created, Queued, Preparing, Running, Completed, Failed, Interrupted,
}

impl ActivityState {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Interrupted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivitySnapshot {
    pub key: AttemptKey,
    pub worker_id: String,
    pub execution_kind: ExecutionKind,
    pub display_name: String,
    pub state: ActivityState,
    pub lane_index: u32,
    pub started_age: Duration,
    pub finished_age: Option<Duration>,
    pub duration: Duration,
}
```

testsは次のobservable behaviorを固定する。

```rust
#[test]
fn tracker_reuses_lane_only_after_terminal() {
    let tracker = ActionTracker::default();
    let a = tracker.begin_attempt("a", 0, "w1", ExecutionKind::Remote, "a.cpp").unwrap();
    let b = tracker.begin_attempt("b", 0, "w1", ExecutionKind::Remote, "b.cpp").unwrap();
    tracker.transition(&a, ActivityState::Running);
    tracker.transition(&b, ActivityState::Running);
    assert_eq!(tracker.snapshot().iter().find(|x| x.key == a).unwrap().lane_index, 1);
    assert_eq!(tracker.snapshot().iter().find(|x| x.key == b).unwrap().lane_index, 2);
    tracker.finish(&a, ActivityState::Completed);
    let c = tracker.begin_attempt("c", 0, "w1", ExecutionKind::Remote, "c.cpp").unwrap();
    tracker.transition(&c, ActivityState::Running);
    assert_eq!(tracker.snapshot().iter().find(|x| x.key == c).unwrap().lane_index, 1);
}

#[test]
fn retry_gets_distinct_attempt_key() {
    let tracker = ActionTracker::default();
    let first = tracker.begin_attempt("compile", 0, "w1", ExecutionKind::Remote, "a.cpp").unwrap();
    tracker.finish(&first, ActivityState::Failed);
    let retry = tracker.begin_attempt("compile", 1, "w2", ExecutionKind::Remote, "a.cpp").unwrap();
    assert_ne!(first, retry);
    assert_eq!(tracker.snapshot().len(), 2);
}

#[test]
fn display_name_never_contains_parent_path() {
    let command = Command {
        argv: vec!["clang-cl.exe".into(), "/c".into(), "C:\\secret\\src\\main.cpp".into()],
        env: [("TOKEN".into(), "secret".into())].into_iter().collect(),
        cwd: "C:\\secret".into(),
    };
    assert_eq!(display_name(&command), "main.cpp");
    let unix = Command { argv: vec!["clang".into(), "-c".into(), "/secret/src/unix.cc".into()], ..Default::default() };
    assert_eq!(display_name(&unix), "unix.cc");
}
```

TTL/cap testはsleepせずprivate`prune_at(now)`を使い、4096 activeを削除しないことをassertする。

- [ ] **Step 2: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-agent action_tracker::tests -- --nocapture
```

Expected: `ActionTracker`、method、`display_name`未定義でcompile FAIL。

- [ ] **Step 3: state containerとAPIを実装する**

```rust
#[derive(Clone)]
pub struct ActionTracker {
    inner: Arc<Mutex<TrackerState>>,
    clock: Arc<dyn TrackerClock>,
}

pub trait TrackerClock: Send + Sync { fn now(&self) -> Instant; }
struct SystemClock;
impl TrackerClock for SystemClock { fn now(&self) -> Instant { Instant::now() } }

#[derive(Default)]
struct TrackerState {
    attempts: HashMap<AttemptKey, AttemptRecord>,
    rejected_transitions: u64,
}

impl Default for ActionTracker {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackerState::default())),
            clock: Arc::new(SystemClock),
        }
    }
}

impl ActionTracker {
    pub fn begin_attempt(
        &self,
        action_id: &str,
        attempt_no: u32,
        worker_id: &str,
        execution_kind: ExecutionKind,
        display_name: &str,
    ) -> Option<AttemptKey>;

    pub fn transition(&self, key: &AttemptKey, next: ActivityState);
    pub fn finish(&self, key: &AttemptKey, terminal: ActivityState);
    pub fn snapshot(&self) -> Vec<ActivitySnapshot>;
    pub fn with_clock(clock: Arc<dyn TrackerClock>) -> Self;
}
```

method bodyは次の規則を1箇所で実装する。

- forward state skipを許可、state後退を拒否してcounter加算。
- terminal同値更新はno-op、terminal上書きは拒否。
- `Running`遷移時に同workerのactive laneから最小未使用1-based laneを選ぶ。
- terminal時にlaneを解放するがrecordはTTLまで残す。
- cap到達時はoldest terminalを先に削除し、activeだけで4096なら`None`を返す。
- `snapshot_at(Instant::now())`でage/durationを作り、古いterminalをpruneする。
- snapshotは`started_at`、`action_id`、`attempt_no`でstable sortして返し、HashMap iteration順をwire/testへ漏らさない。
- `attempt_no`は承認済み仕様どおりcallerが渡す。Trackerは補助採番Mapを持たず、全保持状態を`attempts`最大4096件へ閉じ込める。重複keyの`begin_attempt`は既存recordを上書きせず`None`を返す。
- `action_id`、`worker_id`、displayは保持memoryを入力長から切り離す。IDは128文字以下なら保持し、超過時は先頭96文字+`#`+`sembazuru_cas::Digest::of(value.as_bytes()).hex()`先頭16文字へ縮約する。単純truncateによるlane/action衝突は作らない。displayは128文字でtruncateする。
- `Mutex`取得は`lock().unwrap_or_else(|error| error.into_inner())`へ1箇所に集約し、observer側panicをbuild executionへ伝播させない。

追加testは8192個のunique actionをterminal化・`prune_at`し、`attempts.len() <= MAX_ACTIVITY_ATTEMPTS`かつ補助ID mapが存在しないことを確認する。別testはthread内で意図的にtracker mutexをpoisonし、その後の`begin_attempt`、`transition`、`snapshot`がpanicせず、build側の戻り値に影響しないことを固定する。

- [ ] **Step 4: 表示名helperを実装する**

```rust
pub fn display_name(command: &Command) -> String {
    const SOURCE_EXTENSIONS: &[&str] = &["c", "cc", "cpp", "cxx", "m", "mm", "rs"];
    let mut sources = command.argv.iter().filter_map(|arg| {
        let basename = arg.rsplit(|ch| ch == '\\' || ch == '/').next()?;
        let path = std::path::Path::new(basename);
        let ext = path.extension()?.to_str()?;
        SOURCE_EXTENSIONS.iter().any(|known| ext.eq_ignore_ascii_case(known))
            .then(|| path.file_name()?.to_string_lossy().into_owned())
            .flatten()
    });
    let first = sources.next().or_else(|| {
        command.argv.first().and_then(|arg| {
            arg.rsplit(|ch| ch == '\\' || ch == '/').next().map(str::to_owned)
        })
    }).unwrap_or_else(|| "process".to_string());
    let extra = sources.count();
    let label = if extra == 0 { first } else { format!("{first} +{extra}") };
    label.chars().take(MAX_DISPLAY_CHARS).collect()
}
```

- [ ] **Step 5: GREENを確認する**

Run:

```powershell
cargo test -p sembazuru-agent action_tracker::tests -- --nocapture
```

Expected: lane、retry、TTL/cap、redaction、state transition testsがPASS。

- [ ] **Step 6: commitする**

```powershell
git add crates/agent/src/action_tracker.rs crates/agent/src/lib.rs
git commit -m "M15: 有界ActionTrackerを追加する"
```

---

### Task 2: Schedulerとworker event streamをTrackerへ接続する

**Files:**

- Modify: `crates/agent/src/lib.rs:207-296`
- Modify: `crates/agent/src/scheduler.rs:115-225,445-529`
- Modify: `crates/agent/src/run.rs:236-245`
- Modify: `crates/agent/src/intake.rs:135-175,285-300,488-500`
- Test: `crates/agent/tests/scheduler_dispatch.rs`
- Test: `crates/agent/tests/intake.rs`

**Interfaces:**

- Consumes: Task 1の`ActionTracker`と`AttemptKey`。
- Produces: `ActionObserver`と`execute_on_channel_with_observer`。
- Produces: trackerを共有する`Scheduler::with_remote_budget_and_cluster_token_and_tracker`。
- Produces: `pub(crate) dispatch_observed(..., display: String) -> ObservedExecution { execution, next_attempt_no }`。既存`dispatch`はdisplayを生成してexecutionだけ返すwrapper。
- Existing `execute_on_channel_with`と`Scheduler::dispatch`はwrapperとして維持する。

- [ ] **Step 1: retry/fallback lifecycleのRED testsを書く**

```rust
#[tokio::test]
async fn scheduler_records_retry_and_fallback_as_distinct_attempts() {
    let tracker = ActionTracker::default();
    let w1 = start_scripted_worker(WorkerScript::RpcError).await;
    let w2 = start_scripted_worker(WorkerScript::StreamEnds).await;
    let table = table_with(&[("w1", &w1, 1), ("w2", &w2, 1)]);
    let scheduler = Scheduler::with_remote_budget_and_cluster_token_and_tracker(
        table, Duration::from_secs(1), None, tracker.clone(),
    );
    let result = scheduler.dispatch(
        cmd(&["cmd", "/c", "exit", "0"]),
        "a".into(),
        "session".into(),
        ExecOptions::default(),
    ).await;
    assert!(matches!(result, Execution::LocalFallback { .. }));
    let mut attempts = tracker.snapshot();
    attempts.sort_by_key(|attempt| attempt.key.attempt_no);
    assert_eq!(attempts.len(), 3);
    assert_eq!(attempts[0].execution_kind, ExecutionKind::Remote);
    assert_eq!(attempts[1].execution_kind, ExecutionKind::Remote);
    assert_eq!(attempts[2].execution_kind, ExecutionKind::Fallback);
    assert!(attempts.iter().all(|attempt| attempt.state.is_terminal()));
}

#[tokio::test]
async fn remote_nonzero_exit_is_failed_not_completed() {
    let tracker = ActionTracker::default();
    let (worker, _) = start_worker().await;
    let scheduler = Scheduler::with_remote_budget_and_cluster_token_and_tracker(
        table_with(&[("w1", &worker, 1)]), Duration::from_secs(1), None, tracker.clone(),
    );
    let result = scheduler.dispatch(
        cmd(&["cmd", "/c", "exit", "4"]),
        "nonzero".into(), "session".into(), ExecOptions::default(),
    ).await;
    assert!(matches!(result, Execution::Remote(_)));
    let attempt = tracker.snapshot().into_iter()
        .find(|attempt| attempt.key.action_id == "nonzero").unwrap();
    assert_eq!(attempt.state, ActivityState::Failed);
}
```

`WorkerScript` fixtureはin-process tonic `Execution` serviceで、`RpcError`は`Status::unavailable`、`StreamEnds`はterminalなしでstream close、`WorkerFailed`はFailed state後にstream close、`Exit(i32)`はRunning→Completed→Exit、`Hang`はRunning後にrelease channel待ちを返す。固定portは使わない。`Hang`は短い`remote_budget`でtimeoutさせ、旧attemptがInterrupted・lane解放された後に次worker attemptが始まることをassertする。承認仕様どおりheartbeatはaction identity/stateの情報源に使わない。

- [ ] **Step 2: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-agent --test scheduler_dispatch scheduler_records_retry_and_fallback_as_distinct_attempts -- --nocapture
```

Expected: tracker-aware constructor/API未定義でcompile FAIL。

- [ ] **Step 3: observerを追加する**

```rust
#[derive(Clone)]
pub struct ActionObserver {
    tracker: ActionTracker,
    key: AttemptKey,
}

impl ActionObserver {
    pub fn new(tracker: ActionTracker, key: AttemptKey) -> Self { Self { tracker, key } }
    fn worker_state(&self, state: i32) {
        let mapped = match ActionState::try_from(state).ok() {
            Some(ActionState::Queued) => Some(ActivityState::Queued),
            Some(ActionState::Preparing) => Some(ActivityState::Preparing),
            Some(ActionState::Running) => Some(ActivityState::Running),
            _ => None,
        };
        if let Some(next) = mapped { self.tracker.transition(&self.key, next); }
    }
}
```

`drive_execute`は`Option<ActionObserver>`を受け、`Event::State`のQueued/Preparing/Runningだけを即時通知する。workerのCompleted/Failed/Abortedはterminal確定に使わない。既存public functionは`None`を渡すwrapperとする。

- [ ] **Step 4: Schedulerへ共有trackerを追加する**

```rust
#[derive(Clone)]
pub struct Scheduler {
    table: WorkerTable,
    in_flight: Arc<Mutex<HashMap<String, u32>>>,
    channels: Arc<Mutex<HashMap<String, tonic::transport::Channel>>>,
    remote_budget: Duration,
    cluster_token: Option<String>,
    tracker: ActionTracker,
}

```

signatureは次へ統一する。

```rust
pub fn with_remote_budget_and_cluster_token_and_tracker(
    table: WorkerTable,
    remote_budget: Duration,
    cluster_token: Option<String>,
    tracker: ActionTracker,
) -> Self;

pub(crate) struct ObservedExecution {
    pub execution: Execution,
    pub next_attempt_no: u32,
}
```

既存`new`、`with_cluster_token`、`with_remote_budget`、`with_remote_budget_and_cluster_token`は`ActionTracker::default()`を渡すwrapperとして後方互換を保ち、`run.rs`だけ共有trackerを渡す。

- [ ] **Step 5: dispatch attempt境界を実装する**

`dispatch_observed`は引数`display: String`を受け取る。`run_submission`はcommandをmoveする前に`let display = display_name(&command);`を一度だけ計算し、`display.clone()`を`dispatch_observed`、元の`display`をpublish fallbackへ渡す。既存public `dispatch` wrapperはmonitor付きintake以外のcaller向けに同じhelperでdisplayを1回生成して`dispatch_observed`へ渡す。remote、route-away local、scheduler fallback、publish fallbackへ渡す表示文字列はこのredacted値だけとする。worker選択後・RPC前にその番号で`begin_attempt`し、全terminal branchで`finish`して番号を増やしてから次workerへ進む。terminal分類は次へ固定する。

- `exit_code == Some(0)` → `Completed`。
- `exit_code == Some(nonzero)` → `Failed`。
- exitなしでworker stateに`Failed`あり → `Failed`。
- clean stream end、RPC transport error、remote budget timeout → `Interrupted`。

heartbeatは約5秒遅延しaction identityを持たないため、承認仕様どおりmonitor stateを生成しない。worker disconnectはRPC error/stream end、hung streamはremote budget timeoutとしてInterruptedへ閉じる。全worker失敗後の`run_local`は現在番号でFallback attemptを作り、実行直前にRunning、exit後にCompleted/Failedへ閉じる。route-away localはExecutionKind::Localを使う。戻り値の`next_attempt_no`は最後に使用した番号+1。`WorkerScript`各branchでstateをassertする。

```rust
let key = self.tracker.begin_attempt(
    &action_id,
    attempt_no,
    &worker.worker_id,
    ExecutionKind::Remote,
    &display,
);
let observer = key.clone().map(|key| ActionObserver::new(self.tracker.clone(), key));
let result = execute_on_channel_with_observer(
    channel, command.clone(), action_id.clone(), session_id.clone(), opts.clone(), capability, observer,
).await;
```

`IntakeService`にも同じtrackerを保持させ、既存constructorはdefault trackerを使うwrapper、production `run.rs`は共有trackerを渡すconstructorを使う。`run_submission`は次の順で値を保持する。

```rust
let display = display_name(&command);
let observed = scheduler.dispatch_observed(
    command,
    action_id.clone(),
    session_id.clone(),
    opts,
    display.clone(),
).await;
let outcome = publish_remote_or_fallback(
    observed.execution,
    &cap,
    &fallback_command,
    &tracker,
    &action_id,
    observed.next_attempt_no,
    &display,
).await;
```

`publish_remote_or_fallback`はpublish失敗でlocal再実行する直前に指定番号の`ExecutionKind::Fallback` attemptを開始し、そのlocal exitで閉じる。`intake.rs` unit testは既存のinvalid staged publish fixtureを使い、Remote CompletedとFallback Completed/Failedの2 attemptが番号0/1でterminal、両方のdisplayが同一basenameになること、tracker capでbeginが`None`でも最終Executionが同じことをassertする。

- [ ] **Step 6: GREENとexecution非干渉を確認する**

Run:

```powershell
cargo test -p sembazuru-agent scheduler::tests -- --nocapture
cargo test -p sembazuru-agent execute -- --nocapture
cargo test -p sembazuru-agent --test intake -- --nocapture
```

Expected: retry/fallback、timeout、既存scheduler testsがPASS。tracker capで`begin_attempt=None`でもexecution結果は同一。

- [ ] **Step 7: commitする**

```powershell
git add crates/agent/src/lib.rs crates/agent/src/scheduler.rs crates/agent/src/run.rs crates/agent/src/intake.rs crates/agent/tests/scheduler_dispatch.rs crates/agent/tests/intake.rs
git commit -m "M15: 実行ライフサイクルをTrackerへ接続する"
```

---

### Task 3: ActionActivityをStatusへ安全に投影する

**Files:**

- Modify: `crates/proto/proto/sembazuru/v0/control.proto:410-479`
- Modify: `crates/agent/src/status.rs:125-228`
- Modify: `crates/agent/src/run.rs:239-360`
- Create/Test: `crates/agent/tests/status_activity.rs`
- Modify: `crates/agent/tests/config_rpc.rs`
- Modify: `crates/agent/tests/eviction.rs`
- Modify: `crates/agent/tests/status.rs`
- Modify: `crates/gui/tests/status_client.rs`
- Modify: `README.md:171-200`

**Interfaces:**

- Consumes: Task 1-2の`ActivitySnapshot`。
- Produces: proto `ActivityExecutionKind`、`ActivityState`、`ActionActivity`。
- Produces: `GetStatusResponse.activities = 7`。

- [ ] **Step 1: protoを先に変更しprojection RED testを書く**

```proto
enum ActivityExecutionKind {
  ACTIVITY_EXECUTION_KIND_UNSPECIFIED = 0;
  ACTIVITY_EXECUTION_KIND_REMOTE = 1;
  ACTIVITY_EXECUTION_KIND_LOCAL = 2;
  ACTIVITY_EXECUTION_KIND_FALLBACK = 3;
}

enum ActivityState {
  ACTIVITY_STATE_UNKNOWN = 0;
  ACTIVITY_STATE_QUEUED = 1;
  ACTIVITY_STATE_PREPARING = 2;
  ACTIVITY_STATE_RUNNING = 3;
  ACTIVITY_STATE_COMPLETED = 4;
  ACTIVITY_STATE_FAILED = 5;
  ACTIVITY_STATE_INTERRUPTED = 6;
}

message ActionActivity {
  string activity_id = 1;
  uint32 attempt_no = 2;
  string worker_id = 3;
  ActivityExecutionKind execution_kind = 4;
  string display_name = 5;
  ActivityState state = 6;
  uint32 lane_index = 7;
  uint64 started_age_ms = 8;
  optional uint64 finished_age_ms = 9;
  uint64 duration_us = 10;
}
```

`GetStatusResponse`へ追加する。

```proto
repeated ActionActivity activities = 7;
```

integration testはactive→recent→expired、retry/fallback分離、redactionを確認する。

```rust
#[tokio::test]
async fn status_exposes_active_then_recent_activity_without_command_material() {
    let (endpoint, tracker) = start_status_with_tracker().await;
    let command = Command {
        argv: vec![
            "clang-cl.exe".into(), "/c".into(), "C:\\secret\\src\\main.cpp".into(),
            "@C:\\secret\\args.rsp".into(),
        ],
        env: [("TOKEN".into(), "secret-value".into())].into_iter().collect(),
        cwd: "C:\\secret".into(),
    };
    let raw_action_id = "C:\\secret\\action-id.cpp";
    let key = tracker.begin_attempt(
        raw_action_id, 0, "w1", ExecutionKind::Remote, &display_name(&command),
    ).unwrap();
    tracker.transition(&key, ActivityState::Running);
    let mut client = StatusClient::connect(endpoint).await.unwrap();
    let active = client.get_status(GetStatusRequest {}).await.unwrap().into_inner();
    assert_eq!(active.activities[0].display_name, "main.cpp");
    assert_ne!(active.activities[0].activity_id, raw_action_id);
    let encoded = active.encode_to_vec();
    let wire = String::from_utf8_lossy(&encoded);
    for secret in ["C:\\secret", "action-id.cpp", "args.rsp", "TOKEN", "secret-value"] {
        assert!(!wire.contains(secret), "wire leaked {secret}");
    }
}
```

`start_status_with_tracker`は既存`crates/gui/tests/status_client.rs`のephemeral loopback fixtureと同じ形で、`StatusState`、`serve_status_service`、共有trackerを返すtest helperとして同じtest file内に実装する。retention期限は`ActionTracker::with_clock(Arc<dyn TrackerClock>)`へtest `ManualClock`を注入し、60秒sleepなしで61秒進めた後のStatusから消えることをassertする。production Defaultは`Instant::now()`を返す`SystemClock`を使う。

- [ ] **Step 2: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-agent --test status_activity -- --nocapture
```

Expected: `activities` fieldとtracker field未定義でcompile FAIL。

- [ ] **Step 3: StatusStateへtrackerを追加しprojectionする**

```rust
#[derive(Clone)]
pub struct StatusState {
    pub table: WorkerTable,
    pub server_stats: Arc<ServerStats>,
    pub cache: Option<Arc<AgentCache>>,
    pub cache_max_bytes: Option<u64>,
    pub metrics: Arc<Metrics>,
    pub tracker: ActionTracker,
    pub auth_enabled: bool,
    pub config_path: PathBuf,
    pub admin_enabled: bool,
}
```

`snapshot`で`tracker.snapshot()`をprotoへmapし、ageはsaturating millisecond、durationはmicrosecondへchecked clampする。raw `action_id`はwireへ出さず、`activity_id = Digest::of(format!("{}:{}", key.action_id, key.attempt_no).as_bytes()).hex()[..16].to_string()`だけを投影する。`run.rs`で1つのtrackerをSchedulerとStatusStateへcloneする。既存StatusState test fixtureへ`ActionTracker::default()`を追加する。

- [ ] **Step 4: READMEへ暫定リスクを英語で明記する**

`What's not done yet`のResident GUI bullet末尾へ追加する。

```markdown
  The live monitor exposes source basenames and recent outcomes over the current
  loopback Status endpoint. Until Status moves to a caller-authenticated named pipe,
  any local process can read that short-lived metadata; full paths, arguments,
  environment values, and tokens are never exposed.
```

- [ ] **Step 5: GREENを確認する**

Run:

```powershell
cargo test -p sembazuru-agent --test status_activity -- --nocapture
cargo test -p sembazuru-agent status -- --nocapture
cargo test -p sembazuru-agent --tests --no-run
cargo test -p sembazuru-gui --tests --no-run
```

Expected: lifecycle projection、expiry、retry、redaction、既存Status testsがPASS。

- [ ] **Step 6: commitする**

```powershell
git add crates/proto/proto/sembazuru/v0/control.proto crates/agent/src/status.rs crates/agent/src/run.rs crates/agent/tests/status_activity.rs crates/agent/tests/config_rpc.rs crates/agent/tests/eviction.rs crates/agent/tests/status.rs crates/gui/tests/status_client.rs README.md
git commit -m "M15: Statusへredacted activityを追加する"
```

---

### Task 4: GUI activity modelとStatus pollを直列化する

**Files:**

- Modify: `crates/gui/Cargo.toml`
- Modify: `crates/gui/src/model.rs:15-120,243-303`
- Modify: `crates/gui/src/client.rs:87-119,212-263`
- Modify/Test: `crates/gui/tests/status_client.rs`

**Interfaces:**

- Consumes: Task 3のproto `ActionActivity`。
- Produces: `ActivityRow`、`ActivityKind`、`ActivityStatus`。
- Existing `run_client` public signatureとcommand channelは維持する。

- [ ] **Step 1: model mappingのRED testを書く**

```rust
#[test]
fn maps_activity_without_command_material() {
    let response = GetStatusResponse {
        activities: vec![ActionActivity {
            activity_id: "9f02a1b3c4d5e6f7".into(), attempt_no: 1, worker_id: "w1".into(),
            execution_kind: ActivityExecutionKind::Remote as i32,
            display_name: "main.cpp".into(),
            state: ProtoActivityState::Running as i32,
            lane_index: 2, started_age_ms: 250, finished_age_ms: None,
            duration_us: 250_000,
        }],
        ..Default::default()
    };
    let model = map_dashboard(response);
    assert_eq!(model.activities[0].display_name, "main.cpp");
    assert_eq!(model.activities[0].lane_index, 2);
}
```

- [ ] **Step 2: poll重複のRED testを書く**

test Status serviceへ`active_status_requests`、`peak_status_requests`、`entered_tx`、`release_rx: Mutex<Option<oneshot::Receiver<()>>>`を持たせる。`get_status`はcounterを増やし、release receiverを先にtakeしてからentered通知し、receiver await中は必ずpendingとなる。drop guardでactiveを減らす。Config RPCはdelayなしで返す。fakeの最初のStatusがpendingのまま2 tick分進め、`UiCommand::GetConfig`を送る。

```rust
entered_rx.await.unwrap();
tokio::time::advance(POLL_INTERVAL * 2).await;
let (reply_tx, reply_rx) = oneshot::channel();
commands.send(UiCommand::GetConfig(reply_tx)).await.unwrap();
let command_reply = tokio::time::timeout(Duration::from_millis(250), reply_rx).await.unwrap();
assert!(matches!(command_reply.unwrap(), Ok(_)));
assert_eq!(peak_status_requests.load(Ordering::SeqCst), 1);
release_tx.send(()).unwrap();
```

testは`#[tokio::test(start_paused = true)]`を使い、wall-clock sleepをしない。このためGUIのTokio featureへ`test-util`を追加する。

- [ ] **Step 3: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-gui --test status_client maps_activity_without_command_material -- --nocapture
cargo test -p sembazuru-gui --test status_client poller_never_overlaps_status_requests -- --nocapture
```

Expected: model field未定義、現行pollerのoverlapでFAIL。

- [ ] **Step 4: model typesとmappingを実装する**

```rust
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivityRow {
    pub activity_id: String,
    pub attempt_no: u32,
    pub worker_id: String,
    pub kind: ActivityKind,
    pub display_name: String,
    pub status: ActivityStatus,
    pub lane_index: u32,
    pub started_age_ms: u64,
    pub finished_age_ms: Option<u64>,
    pub duration_us: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityKind { Remote, Local, Fallback, Unknown }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActivityStatus { Queued, Preparing, Running, Completed, Failed, Interrupted, Unknown }
```

`DashboardModel`へ`pub activities: Vec<ActivityRow>`を追加し、unknown enum valueは`Unknown`へmapする。

- [ ] **Step 5: poll loopを1 request直列へ変更する**

poll tickごとにunbounded spawnせず、`Option<JoinHandle<ConnectionState>>`を1つだけ保持する。command receiverは`tokio::select!`の別branchで既存`spawn_command`へ送り続ける。

```rust
let mut pending_poll: Option<tokio::task::JoinHandle<ConnectionState>> = None;
loop {
    tokio::select! {
        _ = tick.tick(), if pending_poll.is_none() => {
            let endpoint = endpoint.clone();
            pending_poll = Some(tokio::spawn(async move { fetch_status(&endpoint).await }));
        }
        result = async { pending_poll.as_mut().expect("guarded").await }, if pending_poll.is_some() => {
            let state = result.unwrap_or_else(|error| ConnectionState::Error(error.to_string()));
            pending_poll = None;
            shared.set(state);
            wake();
        }
        command = commands.recv() => match command {
            Some(command) => spawn_command(endpoint.clone(), command),
            None => {
                if let Some(handle) = pending_poll.take() {
                    handle.abort();
                    let _ = handle.await;
                }
                break;
            }
        }
    }
}
```

responseにgeneration counterを付けずとも、同時requestが1なら古いresponse逆転は起きない。channel close testはpending Status中に全senderをdropし、`run_client` return後にserver active countが0、wake counterとshared snapshotが以後変化しないことをassertする。

- [ ] **Step 6: GREENを確認する**

Run:

```powershell
cargo test -p sembazuru-gui --test status_client -- --nocapture
cargo test -p sembazuru-gui model -- --nocapture
```

Expected: activity mapping、peak=1、command responsiveness、daemon-down recoveryがPASS。

- [ ] **Step 7: commitする**

```powershell
git add crates/gui/Cargo.toml crates/gui/src/model.rs crates/gui/src/client.rs crates/gui/tests/status_client.rs Cargo.lock
git commit -m "M15: activity modelと直列Status pollを追加する"
```

---

### Task 5: worker別60秒Monitorタイムラインを描画する

**Files:**

- Create: `crates/gui/src/app/monitor.rs`
- Create/Test: `crates/gui/tests/monitor.rs`
- Modify: `crates/gui/src/app/mod.rs:20-33,129-162`
- Visual target: `docs/superpowers/specs/assets/2026-07-11-build-monitor-timeline-target.png`

**Interfaces:**

- Consumes: Task 4の`WorkerRow`と`ActivityRow`。
- Produces: `Monitor` tab、`group_lanes`、`bar_geometry`、`ellipsize`。

- [ ] **Step 1: pure geometry/groupingのRED testsを書く**

```rust
#[test]
fn geometry_clamps_to_sixty_seconds() {
    assert_eq!(bar_geometry(75_000, Some(65_000), 10_000_000, 600.0), None);
    let (left, width) = bar_geometry(30_000, Some(10_000), 20_000_000, 600.0).unwrap();
    assert_eq!((left, width), (300.0, 200.0));
    assert_eq!(bar_geometry(75_000, None, 75_000_000, 600.0), Some((0.0, 600.0)));
    assert_eq!(bar_geometry(0, Some(0), 999, 600.0), Some((599.0, 1.0)));
    assert_eq!(bar_geometry(60_000, Some(60_000), 0, 600.0), Some((0.0, 1.0)));
}

#[test]
fn lane_order_is_stable_and_disconnected_history_remains_visible() {
    let workers = vec![WorkerRow { id: "w1".into(), cpu: 4, ..Default::default() }];
    let activities = vec![
        activity("a", "w1", 1, ActivityKind::Remote),
        activity("b", "w1", 4, ActivityKind::Remote),
        activity("c", "w2-gone", 1, ActivityKind::Remote),
    ];
    let groups = group_lanes(&workers, &activities);
    assert_eq!(groups.iter().map(|g| g.worker_id.as_str()).collect::<Vec<_>>(), vec!["w1", "w2-gone"]);
    assert_eq!(groups[0].lanes.iter().map(|l| l.index).collect::<Vec<_>>(), vec![1, 2, 3, 4]);
    let zero_cpu = vec![WorkerRow { id: "w0".into(), cpu: 0, ..Default::default() }];
    let overflow = vec![activity("overflow", "w0", 3, ActivityKind::Remote)];
    assert_eq!(group_lanes(&zero_cpu, &overflow)[0].lanes.len(), 3);

    let mixed = vec![
        activity("remote", "w1", 1, ActivityKind::Remote),
        activity("local", "", 0, ActivityKind::Local),
        activity("fallback", "", 0, ActivityKind::Fallback),
    ];
    let mixed_groups = group_lanes(&workers, &mixed);
    let synthetic = mixed_groups.iter().find(|group| group.worker_id == "Local / Fallback").unwrap();
    assert_eq!(synthetic.capacity, 0);
    assert!(synthetic.lanes.is_empty());
    assert_eq!(synthetic.activities.len(), 2);
}

#[test]
fn narrow_bar_ellipsizes() {
    assert_eq!(ellipsize("very_long_translation_unit.cpp", 10), "very_long…");
}

fn activity(
    activity_id: &str,
    worker_id: &str,
    lane_index: u32,
    kind: ActivityKind,
) -> ActivityRow {
    ActivityRow {
        activity_id: activity_id.into(),
        attempt_no: 0,
        worker_id: worker_id.into(),
        kind,
        display_name: format!("{activity_id}.cpp"),
        status: ActivityStatus::Running,
        lane_index,
        started_age_ms: 1_000,
        finished_age_ms: None,
        duration_us: 1_000_000,
    }
}
```

- [ ] **Step 2: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-gui --test monitor -- --nocapture
```

Expected: module/helper未定義でcompile FAIL。

- [ ] **Step 3: pure layout modelを実装する**

```rust
pub const WINDOW_MS: u64 = 60_000;

pub struct WorkerLanes {
    pub worker_id: String,
    pub capacity: u32,
    pub lanes: Vec<Lane>,
    pub activities: Vec<ActivityRow>, // populated only by Local / Fallback band
}

pub struct Lane {
    pub index: u32,
    pub activities: Vec<ActivityRow>,
}

pub fn bar_geometry(
    started_age_ms: u64,
    finished_age_ms: Option<u64>,
    _duration_us: u64,
    width: f32,
) -> Option<(f32, f32)> {
    if started_age_ms > WINDOW_MS && finished_age_ms.is_some_and(|age| age >= WINDOW_MS) {
        return None;
    }
    let start = started_age_ms.min(WINDOW_MS);
    let finish = finished_age_ms.unwrap_or(0).min(start);
    let mut left = width * (WINDOW_MS - start) as f32 / WINDOW_MS as f32;
    let right = width * (WINDOW_MS - finish) as f32 / WINDOW_MS as f32;
    let bar_width = (right - left).max(1.0);
    left = left.min((width - bar_width).max(0.0));
    Some((left, bar_width.min(width)))
}
```

`group_lanes`はworker一覧順を保ち、一覧にない履歴workerをworker_id sortで後置する。各workerのlane数は`max(reported cpu_count, observed max lane_index)`とし、cpu=0や一時overflowでも観測済みbarを捨てない。Local/Fallbackは`Local / Fallback` synthetic groupへ入れ、物理slot数は表示しない。`app/mod.rs`へ`pub mod monitor;`を追加し、integration testからpure helperを参照可能にする。
`ellipsize(text, max_chars)`はellipsisを上限内の1文字として数え、`max_chars - 1`文字+`…`を返す。

- [ ] **Step 4: `Monitor` tabを追加する**

`Tab` enumへ`Monitor`を追加し、navigation順を`Dashboard, Monitor, Services, Join, Settings`にする。`monitor::render`は次を描く。

- top: connected workers、total slots、in-flight、completed/failed 60s。
- center: seconds ruler、Now line、worker header、Slot lane、activity bars。
- bottom: newest-first recent history table。
- active=blue、success=green→muted、failed/interrupted=red、state text併記。
- bar hover: worker、slot、basename、state、duration。
- horizontal/vertical ScrollAreaで既存最小window 560×360を壊さない。

- [ ] **Step 5: GREENを確認する**

Run:

```powershell
cargo test -p sembazuru-gui --test monitor -- --nocapture
cargo test -p sembazuru-gui --test dashboard_badge -- --nocapture
```

Expected: geometry/grouping/text testsと既存tab/dashboard testがPASS。

- [ ] **Step 6: commitする**

```powershell
git add crates/gui/src/app/monitor.rs crates/gui/src/app/mod.rs crates/gui/tests/monitor.rs
git commit -m "M15: worker別60秒Monitorタイムラインを追加する"
```

---

### Task 6: 性能・privacy・視覚・workspace gateを通す

**Files:**

- Create: `docs/benchmarks/2026-07-11-live-monitor-results.md`
- Verify only: implementation files from Tasks 1-5

**Interfaces:**

- Consumes: tracker/proto/model/UIの統合結果。
- Produces: build throughput比較、privacy review、同viewport screenshot比較の証拠。

- [ ] **Step 1: Rust gateを実行する**

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: exit 0、warning 0、test failure 0。

- [ ] **Step 2: GUI未起動/起動のbuild throughputを比較する**

同じ100 action corpusをGUI未起動とMonitor表示中で各5回実行し、中央値を記録する。Monitor表示中が2%以上遅ければ完了せず、tracker lock、snapshot copy、egui repaintをprofileする。

- [ ] **Step 3: privacy sweepを実行する**

```powershell
rg -n "argv|env|cwd|response|token|full.path" crates/proto/proto/sembazuru/v0/control.proto crates/agent/src/action_tracker.rs crates/agent/src/status.rs crates/gui/src
cargo test -p sembazuru-agent --test status_activity activity_projection_contains_no_path_argv_or_env -- --nocapture
```

Expected: proto activity messageに禁止fieldなし、redaction test PASS。意図した既存config/status参照はreviewで分類する。

- [ ] **Step 4: visual smokeを実行する**

```powershell
cargo run -p sembazuru-gui
```

900×600と1440×1024でMonitorを撮影し、選択画像とside-by-sideで比較する。確認項目はnavigation順、worker grouping、Slot label、60秒ruler、Now line、色+状態文字、history、overflow/clipping。差分はlayoutだけ修正し、backend仕様を変えない。

- [ ] **Step 5: benchmark記録を作る**

`docs/benchmarks/2026-07-11-live-monitor-results.md`へ、commit hash、commands、5回のraw values/median、privacy result、screenshot path、CI状態を書く。未実行項目は理由を記載し、PASSと書かない。

- [ ] **Step 6: 二重reviewを通す**

Codex reviewerへstate machine、retry/fallback ordering、bounded memory、privacy、poll overlap、visual targetを渡す。Claude verifierへ同じ証拠を渡す。Claude unavailable時は独立Codex二次reviewで代替し、skipped gateを記録する。

- [ ] **Step 7: 証拠commitを作る**

```powershell
git add docs/benchmarks/2026-07-11-live-monitor-results.md
git commit -m "M15: ライブモニタの性能とprivacy証拠を記録する"
```

Task 6まで通過するまで、ライブモニタフェーズを完了扱いにしない。
