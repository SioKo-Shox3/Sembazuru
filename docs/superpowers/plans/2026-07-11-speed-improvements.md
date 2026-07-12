# Production VFS速度改善 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** production prefetchを有効かつforeground-safeにし、CAS range readを要求byte比例のI/Oへ変える。

**Architecture:** agentはcache manifestからscope内のabsolute Content pathだけをhint化し、workerは最大32件だけを並行warmする。同一pathのprefetchとforeground hydrateはsingle-flight化する。CASはWindowsのdelete sharingを明示的に外した短命handleでrangeだけを読み、file serverのblocking I/Oは`spawn_blocking`へ送る。

**Tech Stack:** Rust 1.96、Tokio、tonic、windows-sys 0.59、PowerShell VFS/determinism harness。

## Global Constraints

- 参照仕様: `docs/superpowers/specs/2026-07-11-speed-and-build-monitor-design.md`。
- correctnessを速度より優先し、失敗は既存local fallbackへ戻す。
- clang-clをfirst-class gateとして維持する。
- protocol、GUI、hook C++の挙動はこの計画で変更しない。
- `MAX_PREDICTED_PATHS = 4096`、`PREFETCH_CONCURRENCY = 32`、FileClient in-flight 128を維持する。
- prefetch failureはadvisoryでありaction failureへ昇格しない。
- production codeを書く前に対応testをREDで確認する。
- 実装担当は各Taskで同一手法2回失敗したら停止し、mainへ証拠を返す。
- 各Taskを個別commitし、author以外のreviewを通してから次へ進む。
- コメント、code、branch名は英語、commit messageと判断資料は日本語。

---

### Task 1: Agent側prefetch hintをscope内absolute Contentへ限定する

**Files:**

- Modify: `crates/agent/src/action_cache.rs:421-445`
- Modify: `crates/agent/src/fileserver.rs:403-535`
- Modify: `crates/agent/src/intake.rs:418-475`
- Test: `crates/agent/src/action_cache.rs:1849-1925`
- Create/Test: `crates/agent/tests/prefetch_scope.rs`

**Interfaces:**

- Consumes: `InputManifest.inputs`, `InputEntry.absolute`, `InputKind::Content`, `normalize_requested`, `path_in_scope`。
- Produces: `AgentCache::predicted_paths(&Digest, Option<&str>) -> io::Result<Vec<String>>`。
- Produces: `pub(crate) fn path_in_scope(requested: &str, root: Option<&str>) -> bool`。
- Later tasks receive lowercase・backslash統一済みabsolute pathだけをworkerへ渡す。

- [ ] **Step 1: filter順序を固定するRED testを書く**

`action_cache.rs`の既存`tests` moduleへ追加する。

```rust
fn assert_tail_content_survives(prefix_kind: InputKind, tag: &str) {
    let root = tmp("predict-filter");
    let cache = AgentCache::open(&root).unwrap();
    let weak = cache.weak_key(&["clang-cl".into(), "/c".into(), tag.into()], &[], "");

    let mut inputs = (0..MAX_PREDICTED_PATHS).map(|i| {
        InputEntry {
            logical: format!("prefix\\h{i}.h"),
            absolute: format!("c:\\outside\\h{i}.h"),
            kind: prefix_kind,
        }
    }).collect::<Vec<_>>();
    inputs.push(InputEntry {
        logical: "src/a.cpp".into(),
        absolute: "C:/PROJ/src/./a.cpp".into(),
        kind: InputKind::Content,
    });
    inputs.push(InputEntry {
        logical: "src/a-duplicate.cpp".into(),
        absolute: "c:\\proj\\src\\a.cpp".into(),
        kind: InputKind::Content,
    });

    let manifest = InputManifest { inputs, cmds: vec![], cacheable: true };
    cache.cache.put_manifest(&weak, &encode_manifest(&manifest)).unwrap();

    let predicted = cache.predicted_paths(&weak, Some("c:\\proj")).unwrap();
    assert_eq!(predicted, vec!["c:\\proj\\src\\a.cpp"]);
}

#[test]
fn scope_filter_runs_before_quota() {
    assert_tail_content_survives(InputKind::Content, "scope.cpp");
}

#[test]
fn kind_filter_runs_before_quota() {
    assert_tail_content_survives(InputKind::Absent, "kind.cpp");
}
```

- [ ] **Step 2: production session wiringのRED integration testを書く**

`prefetch_scope.rs`に、受信した`ExecuteRequest`をchannelへ送りrelease通知までresponseを保留する最小tonic `Execution` fakeを置く。`AgentCache::record`でinside Content、outside Content、inside Absentを持つ実manifestをseedし、`IntakeService::with_vfs`、共有`SessionRegistry`、`serve_files_with_stats_token`、fake workerをproductionと同じ構成で起動する。submitはmanifestと同じcommand/cwdと`input_root`を使う。

fakeがrequestを捕捉してsessionがactiveな間に次をassertする。

```rust
assert_eq!(request.predicted_paths, vec![inside_normalized.clone()]);
let vfs = request.vfs.as_ref().expect("VFS request");
assert_eq!(vfs.vfs_root, root.to_string_lossy());
assert!(!request.session_id.is_empty());

let client = FileClient::connect_with_rtt_session(
    fileserver_addr,
    Duration::ZERO,
    String::new(),
    String::new(),
    request.session_id.clone(),
).await.unwrap();
assert!(client.probe_digest(&inside_normalized).await.unwrap().is_some());
assert!(client.probe_digest(&outside_normalized).await.unwrap().is_none());
release.send(()).unwrap();
```

fake `execute`は`Queued`→`Running`→release待ち→`Completed`→`ExitStatus(0)`を返す。これによりcache manifest→intake filtering→worker request→agent-authoritative session enforcementを1本で通す。

- [ ] **Step 3: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-agent scope_filter_runs_before_quota -- --nocapture
cargo test -p sembazuru-agent kind_filter_runs_before_quota -- --nocapture
cargo test -p sembazuru-agent --test prefetch_scope -- --nocapture
```

Expected: `predicted_paths`の引数数不一致、または現行実装がrelative/Absentを返してFAILする。

- [ ] **Step 4: scope helperをcrate内共有にする**

`fileserver.rs`のvisibilityだけを変更し、bodyは一字も変えない。

```rust
pub(crate) fn path_in_scope(requested: &str, root: Option<&str>) -> bool {
    let Some(root) = root else {
        return true;
    };
    let Some(norm) = normalize_requested_inner(requested, ShortAliasPolicy::Allow) else {
        return false;
    };
    if norm == root {
        return true;
    }
    let Some(rel) = norm
        .strip_prefix(root)
        .and_then(|rest| rest.strip_prefix('\\'))
    else {
        return false;
    };
    !rel.split('\\').any(is_short_name_alias_component)
}
```

- [ ] **Step 5: `predicted_paths`を最小実装する**

`action_cache.rs`へ`HashSet`をimportし、現行methodを置換する。

```rust
pub fn predicted_paths(
    &self,
    weak: &Digest,
    normalized_vfs_root: Option<&str>,
) -> io::Result<Vec<String>> {
    let Some(bytes) = self.cache.get_manifest(weak)? else {
        return Ok(Vec::new());
    };
    let Some(manifest) = decode_manifest(&bytes) else {
        return Ok(Vec::new());
    };

    let mut seen = std::collections::HashSet::new();
    Ok(manifest
        .inputs
        .into_iter()
        .filter(|entry| entry.kind == InputKind::Content)
        .filter_map(|entry| crate::fileserver::normalize_requested(&entry.absolute))
        .filter(|path| crate::fileserver::path_in_scope(path, normalized_vfs_root))
        .filter(|path| seen.insert(path.clone()))
        .take(MAX_PREDICTED_PATHS)
        .collect())
}
```

- [ ] **Step 6: intakeのroot算出順序を移動する**

`vfs_root`と`normalized_vfs_root`の既存blockをprefetch取得の前へ移し、closureへcloneを渡す。

```rust
let vfs_root = if input_root.is_empty() {
    command.cwd.clone()
} else {
    input_root.clone()
};
let normalized_vfs_root = crate::fileserver::normalize_root(&vfs_root);

let predicted_paths = match (&ctx.cache, &weak) {
    (Some(cache), Some(weak)) => {
        let cache = cache.clone();
        let weak = weak.clone();
        let root = normalized_vfs_root.clone();
        tokio::task::spawn_blocking(move || cache.predicted_paths(&weak, root.as_deref()))
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or_default()
    }
    _ => Vec::new(),
};
```

既存の`predicted_paths.truncate`はmethod内quotaと重複するため削除する。

- [ ] **Step 7: 既存test callerを新signatureへ更新してGREENを確認する**

Run:

```powershell
cargo test -p sembazuru-agent predicted_paths -- --nocapture
cargo test -p sembazuru-agent intake -- --nocapture
cargo test -p sembazuru-agent fileserver::tests::path_in_scope -- --nocapture
cargo test -p sembazuru-agent --test prefetch_scope -- --nocapture
```

Expected: 全test PASS。未知weak keyとmanifestなしは引き続き空vector。

- [ ] **Step 8: commitする**

```powershell
git add crates/agent/src/action_cache.rs crates/agent/src/fileserver.rs crates/agent/src/intake.rs crates/agent/tests/prefetch_scope.rs
git commit -m "M5: prefetch hintをscope内入力へ限定する"
```

---

### Task 2: Worker prefetch task数を32へ制限する

**Files:**

- Modify: `crates/worker/Cargo.toml`
- Modify/Test: `crates/worker/src/vfs_pipe.rs:37-122`
- Modify: `Cargo.lock`

**Interfaces:**

- Consumes: Task 1が生成した正規化absolute path。
- Produces: `const PREFETCH_CONCURRENCY: usize = 32`。
- Produces: private `for_each_prefetch_bounded`。全pathを処理するがin-flight hydrate futureは32以下。
- warm futureはpipe server future自身がpollし、detached Tokio taskを作らない。

- [ ] **Step 1: peak concurrencyのRED testを書く**

```rust
#[tokio::test]
async fn prefetch_peak_concurrency_never_exceeds_limit() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let completed = Arc::new(AtomicUsize::new(0));
    let paths = (0..200).map(|i| format!("c:\\proj\\h{i}.h"));

    for_each_prefetch_bounded(paths, 32, {
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        let completed = Arc::clone(&completed);
        move |_| {
            let active = Arc::clone(&active);
            let peak = Arc::clone(&peak);
            let completed = Arc::clone(&completed);
            async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                active.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
            }
        }
    }).await;

    assert_eq!(completed.load(Ordering::SeqCst), 200);
    assert!(peak.load(Ordering::SeqCst) <= 32);
}
```

- [ ] **Step 2: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-worker prefetch_peak_concurrency_never_exceeds_limit -- --nocapture
```

Expected: helper未定義でcompile FAIL。

- [ ] **Step 3: sliding-window helperを実装する**

```rust
use std::future::Future;
use futures_util::stream::{FuturesUnordered, StreamExt};

const PREFETCH_CONCURRENCY: usize = 32;

async fn for_each_prefetch_bounded<I, F, Fut>(paths: I, limit: usize, f: F)
where
    I: IntoIterator<Item = String>,
    F: Fn(String) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut paths = paths.into_iter();
    let mut tasks = FuturesUnordered::new();
    for _ in 0..limit.max(1) {
        let Some(path) = paths.next() else { break };
        let f = f.clone();
        tasks.push(f(path));
    }
    while tasks.next().await.is_some() {
        let Some(path) = paths.next() else { continue };
        let f = f.clone();
        tasks.push(f(path));
    }
}
```

- [ ] **Step 4: `prefetch_warm`をhelperへ接続する**

```rust
async fn prefetch_warm(self: &Arc<Self>, paths: &[String]) {
    let paths = bounded_prefetch_paths(paths).cloned().collect::<Vec<_>>();
    let state = Arc::clone(self);
    for_each_prefetch_bounded(paths, PREFETCH_CONCURRENCY, move |path| {
        let state = Arc::clone(&state);
        async move {
            let _ = hydrate(&path, &state).await;
        }
    }).await;
}

```

`crates/worker/Cargo.toml`へ`futures-util = "0.3"`を追加する。`serve_vfs_with_prefetch_ready`はwarmをspawnせずpinし、pipe accept loopと同じfuture内でpollする。

```rust
let mut warm_done = predicted_paths.is_empty();
let warm = state.prefetch_warm(&predicted_paths);
tokio::pin!(warm);
let mut clients = FuturesUnordered::new();
loop {
    tokio::select! {
        () = &mut warm, if !warm_done => warm_done = true,
        result = server.connect() => {
            result?;
            let connected = server;
            server = ServerOptions::new().create(&full)?;
            clients.push(handle_client(connected, Arc::clone(&state)));
        }
        Some(_result) = clients.next(), if !clients.is_empty() => {}
    }
}
```

既存のdetached `handle_client` spawnも同時に廃止し、client futureを同じ`FuturesUnordered`でpollする。pipe taskをabortしてawaitすると、pinned warm、prefetch hydrate、connected client hydrateの全futureが同じouter futureのdropで同期的に破棄される。unit test `dropping_pipe_future_drops_all_warm_futures_before_return`はoperation内にdropで`active`を減らすguardを置き、outer pipe taskの`abort(); await`直後（追加sleepなし）に`active=0`、以後scratch write counterが増えないことをassertする。

- [ ] **Step 5: GREENと既存prefetch testを確認する**

Run:

```powershell
cargo test -p sembazuru-worker prefetch_ -- --nocapture
cargo test -p sembazuru-worker dropping_pipe_future_drops_all_warm_futures_before_return -- --nocapture
```

Expected: peak test、quota test、warm testがPASS。4096個の待機taskは生成されない。

- [ ] **Step 6: commitする**

```powershell
git add crates/worker/Cargo.toml crates/worker/src/vfs_pipe.rs Cargo.lock
git commit -m "M5: prefetchの並列task数を制限する"
```

---

### Task 3: Prefetchとforeground hydrateをsingle-flight化する

**Files:**

- Modify/Test: `crates/worker/src/lib.rs:697-860,1060-1130`
- Modify: `crates/worker/src/vfs_pipe.rs:45-75,285-335`
- Test: `crates/agent/tests/vfs_pipe.rs`

**Interfaces:**

- Consumes: Task 2のbounded prefetch。
- Produces: case/separator正規化した`hydration_key(&str) -> String`。
- Produces: pathごとの`Arc<tokio::sync::Mutex<()>>` gateとtemp→rename publish。
- Produces: `build_child`が唯一使用する`start_action_vfs(...) -> Result<ActionVfsServer, String>` production helper。

- [ ] **Step 1: 同一path競合のRED integration testを書く**

test serverの`ServerStats`をcallerへ返すhelperを追加し、同じpathをcase/separator違いで同時hydrateする。helperは既存`start_file_server`を次のsignatureへ置換し、spawn側へcloneを渡す。

```rust
async fn start_file_server_with_stats() -> (std::net::SocketAddr, Arc<ServerStats>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(ServerStats::default());
    let served_stats = Arc::clone(&stats);
    tokio::spawn(async move {
        let _ = sembazuru_agent::fileserver::serve_files_with_stats(listener, served_stats).await;
    });
    (addr, stats)
}
```

```rust
#[tokio::test]
async fn concurrent_prefetch_and_open_share_one_hydration() {
    let source = TempDir::new("single-flight-source");
    let path = source.join("shared.h");
    let body = vec![0x5a; 700_000];
    std::fs::write(&path, &body).unwrap();
    let (addr, stats) = start_file_server_with_stats().await;
    let scratch = source.join("scratch");
    let pipe_name = format!("sbz-vfs-single-flight-{}", std::process::id());
    let full = format!(r"\\.\pipe\{pipe_name}");
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let predicted = path.to_string_lossy().to_uppercase();
    tokio::spawn(async move {
        let _ = sembazuru_worker::vfs_pipe::serve_vfs_with_prefetch_ready(
            &pipe_name,
            addr,
            scratch,
            source.join("cas"),
            Duration::ZERO,
            vec![predicted],
            ready_tx,
            String::new(),
            String::new(),
            String::new(),
        ).await;
    });
    ready_rx.await.unwrap();
    let logical = path.to_string_lossy().replace('\\', "/");
    let (first, second) = tokio::join!(
        pipe_hydrate(&full, &logical),
        pipe_hydrate(&full, &logical.to_uppercase()),
    );

    for hydrated in [first, second] {
        assert_eq!(hydrated.0, 0);
        assert_eq!(std::fs::read(hydrated.1).unwrap(), body);
    }
    assert_eq!(stats.content_bytes(), body.len() as u64);
    assert_eq!(stats.read_ops.load(Ordering::Relaxed), 3);
}
```

実際の競合をscheduler運に依存させないため、同じStepで`vfs_pipe.rs` unit testへbarrier testを追加する。全taskはbarrier通過後に同じ正規化keyのgateを取得し、critical sectionを通るたび`active`/`peak`を更新する。各処理は失敗を模してhydrated mapへinsertしない。

```rust
fn test_state() -> VfsState {
    VfsState {
        scratch_root: temp("gate-scratch"),
        hydrated: Mutex::new(HashMap::new()),
        hydrating: Mutex::new(HashMap::new()),
        cas: BlobStore::open(temp("gate-cas")).unwrap(),
        agent_addr: "127.0.0.1:0".parse().unwrap(), // gate-only test never connects
        rtt: Duration::ZERO,
        auth_token: String::new(),
        session_root: String::new(),
        session_id: String::new(),
        client: OnceCell::new(),
    }
}

#[tokio::test]
async fn same_key_gate_stays_single_flight_across_failed_waiters() {
    let state = Arc::new(test_state());
    let start = Arc::new(tokio::sync::Barrier::new(33));
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut tasks = Vec::new();
    for i in 0..32 {
        let state = Arc::clone(&state);
        let start = Arc::clone(&start);
        let active = Arc::clone(&active);
        let peak = Arc::clone(&peak);
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            let path = if i % 2 == 0 { "C:/SRC/Shared.H" } else { "c:\\src\\shared.h" };
            let active_for_op = Arc::clone(&active);
            let peak_for_op = Arc::clone(&peak);
            let result = hydrate(path, &state, || async move {
                let now = active_for_op.fetch_add(1, Ordering::SeqCst) + 1;
                peak_for_op.fetch_max(now, Ordering::SeqCst);
                tokio::task::yield_now().await;
                active_for_op.fetch_sub(1, Ordering::SeqCst);
                (STATUS_ERROR, String::new())
            }).await;
            assert_eq!(result.0, STATUS_ERROR);
        }));
    }
    start.wait().await;
    for task in tasks { task.await.unwrap(); }
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    assert_eq!(state.hydrating.lock().await.len(), 1);
}
```

さらに`lib.rs`のVFS start blockを`start_action_vfs`へ抽出し、production helperを直接通すtestを追加する。real agent file serverと`ServerStats`、real `serve_vfs_with_prefetch_ready`を使い、予測pathがwarmされた後のforeground pipe openで追加転送0をassertする。

```rust
struct ActionVfsServer {
    pipe_name: String,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
    scratch_root: PathBuf,
}

impl ActionVfsServer {
    fn full_pipe_name(&self) -> String { format!(r"\\.\pipe\{}", self.pipe_name) }
    async fn shutdown(self) {
        self.task.abort();
        let _ = self.task.await;
    }
}

async fn start_action_vfs(
    v: VfsExecution,
    cfg: Arc<WorkerVfsConfig>,
    predicted_paths: Vec<String>,
    session_id: String,
) -> Result<ActionVfsServer, String>;

async fn test_pipe_hydrate(full_pipe: &str, logical: &str) -> (u8, String) {
    let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(full_pipe)
        .unwrap();
    let payload = logical.as_bytes();
    client.write_all(&(payload.len() as u32).to_le_bytes()).await.unwrap();
    client.write_all(payload).await.unwrap();
    client.flush().await.unwrap();
    let mut len = [0u8; 4];
    client.read_exact(&mut len).await.unwrap();
    let mut response = vec![0u8; u32::from_le_bytes(len) as usize];
    client.read_exact(&mut response).await.unwrap();
    (response[0], String::from_utf8(response[1..].to_vec()).unwrap())
}

let server = start_action_vfs(vfs, cfg, vec![logical.clone()], session_id).await.unwrap();
tokio::time::timeout(Duration::from_secs(5), async {
    while stats.content_bytes() != body.len() as u64 { tokio::task::yield_now().await; }
}).await.unwrap();
let after_warm = stats.content_bytes();
let (status, local) = test_pipe_hydrate(&server.full_pipe_name(), &logical).await;
assert_eq!(status, STATUS_OK);
assert_eq!(std::fs::read(local).unwrap(), body);
assert_eq!(stats.content_bytes(), after_warm);
server.shutdown().await;
```

helper bodyは現行`build_child`のsuffix/pipe/scratch作成、address parse、directory作成、`serve_vfs_with_prefetch_ready` spawn、`ready_rx.await` fail-closeをそのまま移す。`build_child`は手書きのVFS起動blockを残さず、このhelperだけを呼び、返されたpipe名・task・scratch rootをlauncher setupへ渡す。action終了経路はpipe taskをabortしてawaitした後だけscratch cleanupへ進み、pipe outer futureが所有するwarm/client futureもその時点でdrop済みとする。これで`ExecuteRequest.predicted_paths`を受けるproduction入口とwarm処理の接続、およびaction終了時のtask ownershipを固定する。

- [ ] **Step 2: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-agent --test vfs_pipe concurrent_prefetch_and_open_share_one_hydration -- --nocapture
cargo test -p sembazuru-worker same_key_gate_stays_single_flight_across_failed_waiters -- --nocapture
cargo test -p sembazuru-worker action_vfs_warms_received_hint_before_foreground_open -- --nocapture
```

Expected: helper/gate未定義でcompile FAIL。production wiring testは現行`build_child`内に抽出可能な入口がないためcompile FAIL。

- [ ] **Step 3: gateと正規化keyを追加する**

```rust
struct VfsState {
    scratch_root: PathBuf,
    hydrated: Mutex<HashMap<String, String>>,
    hydrating: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    cas: BlobStore,
    agent_addr: SocketAddr,
    rtt: Duration,
    auth_token: String,
    session_root: String,
    session_id: String,
    client: OnceCell<FileClient>,
}

fn hydration_key(path: &str) -> String {
    path.replace('/', "\\").to_lowercase()
}

async fn hydration_gate(state: &VfsState, key: &str) -> Arc<Mutex<()>> {
    let mut gates = state.hydrating.lock().await;
    Arc::clone(gates.entry(key.to_string()).or_insert_with(|| Arc::new(Mutex::new(()))))
}
```

- [ ] **Step 4: `hydrate`をsingle-flight wrapperとuncached処理へ分ける**

```rust
async fn hydrate<F, Fut>(
    path: &str,
    state: &VfsState,
    operation: F,
) -> (u8, String)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = (u8, String)>,
{
    let key = hydration_key(path);
    if let Some(hit) = state.hydrated.lock().await.get(&key).cloned() {
        return (STATUS_OK, hit);
    }
    let gate = hydration_gate(state, &key).await;
    let _guard = gate.lock().await;
    if let Some(hit) = state.hydrated.lock().await.get(&key).cloned() {
        return (STATUS_OK, hit);
    }

    let result = operation().await;
    if result.0 == STATUS_OK {
        state.hydrated.lock().await.insert(key.clone(), result.1.clone());
    }
    result
}

```

`hydrate_uncached(path: &str, state: &VfsState) -> (u8, String)`へ既存fetch処理を移し、末尾の`hydrated` map insertはwrapperだけに残す。scratchへ直接writeせず同一directoryのunique tempを`create_new(true)`で作成し、`write_all`、`flush`、drop後に`tokio::fs::rename`する。write/flush/rename失敗時はtempを削除して`(STATUS_ERROR, String::new())`を返す。unique suffixはprocess idと`AtomicU64`で作る。

gate entryは削除せずaction-local `VfsState`の寿命まで保持する。これにより失敗直後に待機者が旧gate、第三者が新gateを掴む二重実行を防ぐ。unit test `same_key_gate_stays_single_flight_across_failed_waiters`はproductionと同じgeneric `hydrate(path, state, operation)`そのものを通す。pipe requestとprefetchの全callerは`hydrate(path, state, || hydrate_uncached(path, state))`を呼ぶため、gateを迂回する別wrapperは存在しない。

```rust
static HYDRATE_TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn hydrate_temp_path(final_path: &Path) -> PathBuf {
    let id = HYDRATE_TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let mut name = final_path.as_os_str().to_os_string();
    name.push(format!(".sbz-tmp-{}-{id}", std::process::id()));
    PathBuf::from(name)
}
```

- [ ] **Step 5: GREENとcleanupを確認する**

Run:

```powershell
cargo test -p sembazuru-agent --test vfs_pipe -- --nocapture
cargo test -p sembazuru-worker vfs_pipe::tests -- --nocapture
cargo test -p sembazuru-worker action_vfs_warms_received_hint_before_foreground_open -- --nocapture
```

Expected: concurrent test PASS、temp file残存なし、既存hydrate test PASS。

- [ ] **Step 6: commitする**

```powershell
git add crates/worker/src/lib.rs crates/worker/src/vfs_pipe.rs crates/agent/tests/vfs_pipe.rs
git commit -m "M5: hydrateをpath単位でsingle-flight化する"
```

---

### Task 4: CASにWindows-safeなrange APIを追加する

**Files:**

- Modify: `crates/cas/Cargo.toml`
- Modify/Test: `crates/cas/src/store.rs:68-165,310-430`
- Create: `crates/cas/examples/range_bench.rs`

**Interfaces:**

- Produces: clone可能な`BlobStore`。
- Produces: `BlobStore::get_range(&Digest, u64, usize) -> io::Result<Option<Vec<u8>>>`。
- Produces: private `open_blob_read`と`read_range_from<R: Read + Seek>`。

- [ ] **Step 1: range意味論のRED testsを書く**

```rust
#[test]
fn get_range_covers_zero_middle_eof_and_missing() {
    let root = tmp("range");
    let store = BlobStore::open(&root).unwrap();
    let digest = store.put(b"0123456789").unwrap();

    assert_eq!(store.get_range(&digest, 0, 0).unwrap(), Some(vec![]));
    assert_eq!(store.get_range(&digest, 3, 4).unwrap(), Some(b"3456".to_vec()));
    assert_eq!(store.get_range(&digest, 8, 8).unwrap(), Some(b"89".to_vec()));
    assert_eq!(store.get_range(&digest, 10, 1).unwrap(), Some(vec![]));
    assert_eq!(store.get_range(&Digest::of(b"missing"), 0, 4).unwrap(), None);
}

#[test]
fn counting_reader_never_reads_beyond_requested_range() {
    let mut reader = CountingReader::new(vec![0x11; 1024 * 1024]);
    let bytes = read_range_from(&mut reader, 128, 4096).unwrap();
    assert_eq!(bytes.len(), 4096);
    assert_eq!(reader.bytes_requested(), 4096);
    assert!(reader.max_request() <= 4096);
}
```

同じtest moduleへ、要求された`Read::read` buffer長と合計を記録するreaderを追加する。

```rust
struct CountingReader {
    inner: std::io::Cursor<Vec<u8>>,
    bytes_requested: usize,
    max_request: usize,
}

impl CountingReader {
    fn new(bytes: Vec<u8>) -> Self {
        Self { inner: std::io::Cursor::new(bytes), bytes_requested: 0, max_request: 0 }
    }
    fn bytes_requested(&self) -> usize { self.bytes_requested }
    fn max_request(&self) -> usize { self.max_request }
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.bytes_requested += buf.len();
        self.max_request = self.max_request.max(buf.len());
        self.inner.read(buf)
    }
}

impl Seek for CountingReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> { self.inner.seek(pos) }
}
```

Windows限定testも追加する。

```rust
#[cfg(windows)]
#[test]
fn open_reader_blocks_eviction_until_drop() {
    let root = tmp("share-mode");
    let store = BlobStore::open(&root).unwrap();
    let digest = store.put(b"pinned").unwrap();
    let path = store.blob_path(&digest);
    let file = store.open_blob_read(&digest).unwrap().unwrap();
    assert!(std::fs::remove_file(&path).is_err());
    drop(file);
    std::fs::remove_file(&path).unwrap();
}
```

- [ ] **Step 2: REDを確認する**

Run:

```powershell
cargo test -p sembazuru-cas get_range_ -- --nocapture
cargo test -p sembazuru-cas open_reader_blocks_eviction_until_drop -- --nocapture
```

Expected: API/helper未定義でcompile FAIL。

- [ ] **Step 3: Windows dependencyを追加する**

```toml
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "0.59", features = [
    "Win32_Storage_FileSystem",
    "Win32_System_ProcessStatus",
    "Win32_System_Threading",
] }
```

- [ ] **Step 4: share-safe openとrange readを実装する**

`BlobStore`へ`#[derive(Clone)]`を追加する。`store.rs`のimportは`File`、`Read`、`Seek`、`SeekFrom`を含める。

```rust
fn open_read_only(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};
        return std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path);
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

fn read_range_from<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    len: usize,
) -> io::Result<Vec<u8>> {
    if len == 0 { return Ok(Vec::new()); }
    reader.seek(SeekFrom::Start(offset))?;
    let mut bytes = Vec::with_capacity(len);
    reader.take(len as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn open_blob_read(&self, digest: &Digest) -> io::Result<Option<File>> {
    match open_read_only(&self.blob_path(digest)) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn get_range(
    &self,
    digest: &Digest,
    offset: u64,
    len: usize,
) -> io::Result<Option<Vec<u8>>> {
    let Some(mut file) = self.open_blob_read(digest)? else { return Ok(None) };
    read_range_from(&mut file, offset, len).map(Some)
}
```

既存`get`も`open_blob_read`後に`read_to_end`する形へ変更し、CAS commentを実装と一致させる。

- [ ] **Step 5: GREENを確認する**

Run:

```powershell
cargo test -p sembazuru-cas -- --nocapture
```

Expected: range、share-mode、eviction、tamper testsが全PASS。

- [ ] **Step 6: `range_bench`を追加する**

exampleは1/16/64 MiB blobを256 KiBずつ読み、5回の中央値を表示する。Windowsでは`GetCurrentProcess`と`GetProcessIoCounters`で`ReadTransferCount`差分、`GetProcessMemoryInfo`で`PeakWorkingSetSize`を表示する。peak値が先行modeに汚染されないようcontrollerが同じexampleを`--child-mode whole-per-chunk` / `--child-mode range`で別process起動し、各childが1 modeだけ計測する。出力形式を固定する。

```text
size_mib=16 mode=whole-per-chunk median_ms=125.50 read_transfer_bytes=1073741824 peak_working_set_bytes=201326592
size_mib=16 mode=range median_ms=8.25 read_transfer_bytes=16777216 peak_working_set_bytes=50331648
```

上の数値はoutput parserを固定するformat例であり、benchmark記録には実測値だけを書く。

- [ ] **Step 7: commitする**

```powershell
git add crates/cas/Cargo.toml crates/cas/src/store.rs crates/cas/examples/range_bench.rs Cargo.lock
git commit -m "M5: CASにWindows-safeなrange readを追加する"
```

---

### Task 5: File serverをrange APIと`spawn_blocking`へ切り替える

**Files:**

- Modify: `crates/agent/Cargo.toml`
- Modify: `crates/agent/src/fileserver.rs:1059-1132`
- Test: `crates/agent/tests/dataplane_fs.rs:181-235`
- Modify/Test: `crates/worker/src/fileclient.rs:390-460,468-end`
- Modify/Test: `crates/worker/src/vfs_pipe.rs:285-360,tests`
- Create: `crates/agent/examples/fileserver_range_bench.rs`

**Interfaces:**

- Consumes: Task 4のclone可能な`BlobStore::get_range`。
- Produces: private async `get_range_blocking`。
- Existing `open_read`、`read_range`、wire formatは変更しない。

- [ ] **Step 1: multi-rangeのRED testへ拡張する**

既存`start_server`を`(SocketAddr, String, Arc<ServerStats>)`返却へ変更し、全call siteで第3要素を`_stats`として受ける。server taskへは`Arc::clone(&stats)`を渡す。`fetch_returns_exact_bytes_and_verifies_digest`を700 KiB超へ変更し、inline 64 KiB、256 KiB×2、末尾端数を必ず通す。

```rust
let big: Vec<u8> = (0..700_123u32).map(|i| (i % 251) as u8).collect();
let (addr, session_id, stats) = start_server().await;
let client = connect_bound(addr, &session_id).await;
let before = stats.read_ops.load(Ordering::Relaxed);
let (bytes, digest) = client.fetch(&path).await.unwrap().unwrap();
assert_eq!(bytes, big);
assert_eq!(Digest::of(&bytes), digest);
let after = stats.read_ops.load(Ordering::Relaxed);
assert_eq!(after - before, 3);
```

`fileclient.rs` test moduleの既存`accept_test_handshake`を使い、range間でblobが消失・変化した応答を決定的に作る。

```rust
async fn start_scripted_read_server(responses: Vec<(u64, u32, Vec<u8>)>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut sock = accept_test_handshake(listener).await;
        for (expected_offset, expected_len, bytes) in responses {
            let (header, payload) = read_frame(&mut sock).await.unwrap();
            let request = ReadRequest::decode(&payload).unwrap();
            assert_eq!(header.op, OpCode::Read);
            assert_eq!(request.offset, expected_offset);
            assert_eq!(request.len, expected_len);
            let response = ReadResponse { bytes }.encode();
            write_frame(&mut sock, FrameHeader {
                request_id: header.request_id,
                op: OpCode::Read,
                is_response: true,
            }, &response).await.unwrap();
            sock.flush().await.unwrap();
        }
    });
    addr
}

#[tokio::test]
async fn fetch_by_digest_rejects_blob_removed_between_ranges() {
    let body = vec![0x41; READ_CHUNK as usize + 17];
    let digest = Digest::of(&body);
    let addr = start_scripted_read_server(vec![
        (0, READ_CHUNK, body[..READ_CHUNK as usize].to_vec()),
        (READ_CHUNK as u64, 17, Vec::new()),
    ]).await;
    let client = FileClient::connect(addr).await.unwrap();
    let error = client.fetch_by_digest(&digest, body.len() as u64).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn fetch_by_digest_rejects_blob_changed_between_ranges() {
    let body = vec![0x41; READ_CHUNK as usize + 17];
    let digest = Digest::of(&body);
    let addr = start_scripted_read_server(vec![
        (0, READ_CHUNK, body[..READ_CHUNK as usize].to_vec()),
        (READ_CHUNK as u64, 17, vec![0x42; 17]),
    ]).await;
    let client = FileClient::connect(addr).await.unwrap();
    let error = client.fetch_by_digest(&digest, body.len() as u64).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
```

`vfs_pipe.rs`にも同じscripted responseを使う`hydrate_does_not_publish_scratch_after_midstream_truncate`を追加し、`STATUS_ERROR`、final scratch path不存在、`.sbz-tmp-*`不存在をassertする。

- [ ] **Step 2: REDまたは旧I/O証拠を確認する**

Run:

```powershell
cargo test -p sembazuru-agent --test dataplane_fs fetch_returns_exact_bytes_and_verifies_digest -- --nocapture
cargo test -p sembazuru-worker fetch_by_digest_rejects_blob_ -- --nocapture
cargo test -p sembazuru-worker hydrate_does_not_publish_scratch_after_midstream_truncate -- --nocapture
cargo run -p sembazuru-cas --example range_bench --release
cargo run -p sembazuru-agent --example fileserver_range_bench --release
```

`fileserver_range_bench`は64 MiB source、共有`SessionRegistry`、production `serve_files_with_stats_token`、bound `FileClient`を起動する。1回目のfetchでsnapshot/CASをwarmした後、同じactive sessionで2回目のfetch前後の`GetProcessIoCounters.ReadTransferCount`とpeak working setを取得する。2回目のexact bytes/digestをassertし、固定形式で出す。

agentのWindows dependencyへbenchmark APIを明示する。

```toml
windows-sys = { version = "0.59", features = [
    "Win32_System_ProcessStatus",
    "Win32_System_Threading",
] }
```

```text
size_mib=64 mode=fileserver-fetch elapsed_ms=42.00 read_transfer_bytes=67108864 peak_working_set_bytes=134217728
```

Windowsで`read_transfer_bytes <= blob_size * 2`をassertするため、現行の全blob-per-chunk実装ではRED、range接続後だけGREENになる。非Windowsではexact bytes/digestだけをassertしI/O counter thresholdはskip理由付きで表示する。CAS単体benchはrange API自体、file-server benchはproduction接続を別々に反証する。

- [ ] **Step 3: blocking helperを追加する**

```rust
async fn get_range_blocking(
    store: &BlobStore,
    digest: &Digest,
    offset: u64,
    len: usize,
) -> io::Result<Option<Vec<u8>>> {
    let store = store.clone();
    let digest = digest.clone();
    tokio::task::spawn_blocking(move || store.get_range(&digest, offset, len))
        .await
        .map_err(io::Error::other)?
}
```

- [ ] **Step 4: inlineとReadをhelperへ置換する**

```rust
let first_chunk = if req.want_inline {
    get_range_blocking(store, &digest, 0, INLINE_CHUNK)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
} else {
    Vec::new()
};
```

`read_range`はwire値をchecked conversionし、quotaでclampしてから渡す。

```rust
const MAX_READ_CHUNK: usize = 256 * 1024;

let len = usize::try_from(req.len).unwrap_or(usize::MAX).min(MAX_READ_CHUNK);
let out = get_range_blocking(store, &digest, req.offset, len)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
```

`MAX_READ_CHUNK`はworkerの現行`READ_CHUNK`と同じ256 KiBに固定する。wire互換性は保ち、これを超す単発requestだけをclampする。

- [ ] **Step 5: integration GREENを確認する**

Run:

```powershell
cargo test -p sembazuru-agent --test dataplane_fs -- --nocapture
cargo test -p sembazuru-agent fileserver -- --nocapture
cargo test -p sembazuru-worker fetch_by_digest_rejects_blob_ -- --nocapture
cargo test -p sembazuru-worker hydrate_does_not_publish_scratch_after_midstream_truncate -- --nocapture
```

Expected: exact bytes、digest、snapshot pin、session ACL、write-back testsが全PASS。

- [ ] **Step 6: commitする**

```powershell
git add crates/agent/Cargo.toml crates/agent/src/fileserver.rs crates/agent/tests/dataplane_fs.rs crates/agent/examples/fileserver_range_bench.rs crates/worker/src/fileclient.rs crates/worker/src/vfs_pipe.rs Cargo.lock
git commit -m "M5: file serverの全blob読みをrange readへ置換する"
```

---

### Task 6: 性能・決定性・workspace gateの証拠を残す

**Files:**

- Create: `docs/benchmarks/2026-07-11-prefetch-range-results.md`
- Create: `hooks/test/prefetch_bench.ps1`
- Modify/Test: `crates/worker/src/vfs_pipe.rs`（ignored measurement test）
- Verify only: all implementation files from Tasks 1-5

**Interfaces:**

- Consumes: Task 2のbounded concurrency、Task 4のrange benchmark、Task 5のproduction path。
- Produces: before/after、command、toolchain、median、未実施理由を含む日本語benchmark記録。

- [ ] **Step 1: Rust gateを実行する**

Run:

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Expected: exit 0、warning 0、test failure 0。

- [ ] **Step 2: prefetch 8/16/32/64比較harnessを実行する**

`vfs_pipe.rs`へ`#[ignore] prefetch_concurrency_benchmark`を追加する。各limit `[8,16,32,64]`で40 sample、512 path×64 KiB、2ms simulated RTTを使い、production `for_each_prefetch_bounded`とgeneric `hydrate`を通す。各sampleではprefetch中に未warm pathのforeground hydrateを1回入れ、次を収集する。

- prefetch wall time p50/p95。
- foreground hydrate latency p50/p95。
- atomic peak live tasks。
- `ServerStats::content_bytes()` transfer bytes。

出力はlimitごとに1行へ固定する。

```text
PREFETCH_BENCH {"concurrency":32,"prefetch_p50_ms":84.2,"prefetch_p95_ms":91.7,"foreground_p50_ms":3.1,"foreground_p95_ms":4.8,"peak_tasks":32,"transfer_bytes":33554432}
```

`hooks/test/prefetch_bench.ps1`はrelease ignored testを実行し、`PREFETCH_BENCH `行を`ConvertFrom-Json`でparseする。concurrency集合が8/16/32/64と一致、各`peak_tasks <= concurrency`、全metricが正数、transfer bytesが全caseで同じであることをassertし、raw 4行をそのまま表示する。

```powershell
powershell -File hooks/test/prefetch_bench.ps1
```

Expected: 4 JSON rows、assertion PASS。32をproduction採用値とし、p50/p95・foreground latency・peak task・transfer byteをbenchmark記録へ転記する。

- [ ] **Step 3: range benchmarkを実行する**

Run:

```powershell
cargo run -p sembazuru-cas --example range_bench --release
cargo run -p sembazuru-agent --example fileserver_range_bench --release
```

Expected: 1/16/64 MiBのCAS rangeと64 MiB production file-server fetchで`read_transfer_bytes`がblob size比例になり、`peak_working_set_bytes`も固定列として記録される。

- [ ] **Step 4: VFS speed gateを実行する**

Run from VS developer shell:

```powershell
powershell -File hooks/test/vfs_bench.ps1 -Runs 5
```

Expected: script内のRTT deltaとcatastrophic slowdown assertionがPASS。commandがtoolchain不足なら、欠落commandと未実施をbenchmark記録へ書き、成功扱いしない。

- [ ] **Step 5: clang-cl決定性gateを実行する**

```powershell
powershell -File hooks/test/vfs_compile.ps1 -RequireClangCl
powershell -File hooks/test/determinism.ps1 -RequireClangCl
```

Expected: byte-identical output gate PASS。`cl`、`clang-cl`、CMake artifact不足は未確認として記録する。

- [ ] **Step 6: benchmark記録を作る**

`docs/benchmarks/2026-07-11-prefetch-range-results.md`へ次を実数で書く。

```markdown
# Prefetch / CAS range read 実測

- Commit: `git rev-parse HEAD` の実出力
- Host / CPU / storage: `Get-CimInstance Win32_Processor, Win32_DiskDrive` の実出力
- Toolchain: `rustc -Vv`、`cl`、`clang-cl --version` の実出力
- Commands: Task 6 Step 1-5で実行したcommandを省略せず記載
- Prefetch: concurrency / prefetch p50/p95 / foreground p50/p95 / peak tasks / transferred bytes
- Range: size / old median / new median / old ReadTransferCount / new ReadTransferCount
- Determinism: PASS or exact blocker
- CI: PASS / FAIL / not run
```

実測値を取得できないfieldは空欄にせず、実行できなかったcommandとblockerを書く。

- [ ] **Step 7: 独立reviewを通す**

Codex reviewerへTasks 1-5のdiffと実測を渡し、correctness、Windows handle、async blocking、prefetch starvationを確認する。次にClaude verifierへ同じ証拠を渡す。Claudeが利用不能なら独立Codex二次reviewを行い、skipped gateを記録する。

- [ ] **Step 8: 証拠commitを作る**

```powershell
git add crates/worker/src/vfs_pipe.rs hooks/test/prefetch_bench.ps1 docs/benchmarks/2026-07-11-prefetch-range-results.md
git commit -m "M5: prefetchとrange readの改善効果を記録する"
```

Task 6まで通過するまで、速度改善フェーズを完了扱いにしない。
