//! M9.2 gate: long-lived daemon disk eviction (deferred #8). The daemon must not
//! accumulate per-action trace dirs forever, and the GUI must be able to force a
//! CAS eviction down to the configured cap. (The byte-level eviction + its
//! correctness-safety + determinism are proven in the AgentCache unit test
//! `eviction_caps_the_cas_and_is_correctness_safe`; here we cover the daemon-path
//! behaviors: per-action trace cleanup and the TriggerEviction RPC wiring.)

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::action_cache::AgentCache;
use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::fileserver::ServerStats;
use sembazuru_agent::intake::{
    IntakeService, IntakeVfsContext, SubmitOptions, serve_intake_service,
    submit_to_loopback_fixture,
};
use sembazuru_agent::scheduler::Scheduler;
use sembazuru_agent::status::{Metrics, StatusState, serve_status_service};
use sembazuru_proto::v0::{Command, TriggerEvictionRequest, status_client::StatusClient};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp(tag: &str) -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("sbz-m92-{}-{tag}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    p
}

fn cmd(argv: &[&str]) -> Command {
    Command {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: Default::default(),
        cwd: String::new(),
    }
}

#[tokio::test]
async fn trace_dir_is_removed_after_a_submission() {
    // A cache is configured (so the daemon creates a per-action trace dir) but no
    // worker is live, so the action completes via local fallback. The trace dir it
    // created under scratch_root must be gone afterward — previously every traced
    // submission left a `trace-{n}` dir for the daemon's whole life (deferred #8).
    let cache_root = tmp("cache");
    let scratch_root = tmp("scratch");
    let cache = Arc::new(AgentCache::open(&cache_root).unwrap());
    let ctx = IntakeVfsContext {
        // No worker will run VFS here (empty table → local fallback), so this
        // address is never dialed; it only has to be syntactically valid.
        agent_fileserver: "127.0.0.1:1".to_string(),
        cache: Some(cache),
        scratch_root: scratch_root.clone(),
        registry: Arc::new(sembazuru_agent::session_registry::SessionRegistry::new().unwrap()),
    };
    let intake = IntakeService::with_vfs(
        Scheduler::new(WorkerTable::new(Duration::from_secs(60))),
        ctx,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_intake_service(listener, intake).await.unwrap();
    });

    let (code, _note) = submit_to_loopback_fixture(
        format!("http://{addr}"),
        cmd(&["cmd", "/c", "exit", "0"]),
        SubmitOptions::default(),
    )
    .await
    .expect("the action completes via local fallback");
    assert_eq!(code, 0);

    // scratch_root exists (the trace dir was created under it) but holds nothing:
    // the per-action trace dir was cleaned up.
    let leftovers: Vec<_> = std::fs::read_dir(&scratch_root)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    assert!(
        leftovers.is_empty(),
        "the per-action trace dir must be cleaned up, found: {leftovers:?}"
    );
}

fn status_state(cache: Option<Arc<AgentCache>>, cap: Option<u64>) -> StatusState {
    StatusState {
        table: WorkerTable::new(Duration::from_secs(60)),
        server_stats: Arc::new(ServerStats::default()),
        cache,
        cache_max_bytes: cap,
        metrics: Arc::new(Metrics::default()),
        tracker: sembazuru_agent::action_tracker::ActionTracker::default(),
        auth_enabled: false,
        config_path: std::env::temp_dir().join("sbz-eviction-test-unused.toml"),
        admin_enabled: true, // these tests exercise TriggerEviction (ADR 0016 gate)
    }
}

async fn start_status(state: StatusState) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_status_service(listener, state).await.unwrap();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn trigger_eviction_reports_a_configured_cap() {
    // Cache + cap configured: TriggerEviction reports cap_configured. The cache is
    // empty so there is nothing to free — the point here is the RPC wiring and the
    // cap_configured signal (actual byte-freeing is covered by the unit test).
    let cache = Arc::new(AgentCache::open(tmp("cap-cache")).unwrap());
    let endpoint = start_status(status_state(Some(cache), Some(1024))).await;
    let mut client = StatusClient::connect(endpoint).await.unwrap();
    let r = client
        .trigger_eviction(TriggerEvictionRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(r.cap_configured, "a configured cap is reported back");
    assert_eq!(r.freed_bytes, 0, "an empty cache has nothing to free");
    assert_eq!(r.size_bytes_after, 0);
}

#[tokio::test]
async fn trigger_eviction_without_a_cap_is_a_noop() {
    // Cache present but no cap: TriggerEviction is a no-op and says so, so the GUI
    // can explain that a cap must be set first.
    let cache = Arc::new(AgentCache::open(tmp("nocap-cache")).unwrap());
    let endpoint = start_status(status_state(Some(cache), None)).await;
    let mut client = StatusClient::connect(endpoint).await.unwrap();
    let r = client
        .trigger_eviction(TriggerEvictionRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(!r.cap_configured, "no cap configured is reported as such");
    assert_eq!(r.freed_bytes, 0);
}
