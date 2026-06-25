//! M9.4a gate: the resident GUI's loopback Status client and view-model, driven
//! end-to-end against the *real* Status service stood up in-process (the same
//! `StatusState` + `serve_status_service` harness `crates/agent/tests/status.rs`
//! and `config_rpc.rs` use). This is the headless half of M9.4's verification:
//! GetStatus mapping, the daemon-down path, and the GetConfig/SetConfig round-trip
//! including the cluster-token presence/clear/set semantics — none of which needs
//! egui or a display.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::fileserver::ServerStats;
use sembazuru_agent::status::{Metrics, StatusState, serve_status_service};
use sembazuru_proto::v0::Capabilities;

use sembazuru_gui::client::{apply_config, fetch_config, fetch_status};
use sembazuru_gui::model::{ConfigEdit, ConnectionState, TokenAction};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp_config() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sbz-gui-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("daemon.toml")
}

/// Stands up the loopback Status plane over `table` with `config_path`, returning
/// the `http://` endpoint the GUI client dials.
async fn start_status(table: WorkerTable, config_path: std::path::PathBuf) -> String {
    let state = StatusState {
        table,
        server_stats: Arc::new(ServerStats::default()),
        cache: None,
        cache_max_bytes: None,
        metrics: Arc::new(Metrics::default()),
        auth_enabled: false,
        config_path,
        admin_enabled: true, // the GUI round-trip test exercises SetConfig (ADR 0016)
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_status_service(listener, state).await.unwrap();
    });
    format!("http://{addr}")
}

fn table_with_one_worker() -> WorkerTable {
    let table = WorkerTable::new(Duration::from_secs(60));
    table.upsert_register(
        "w1".to_string(),
        "http://127.0.0.1:9".to_string(),
        Capabilities {
            cpu_count: 2,
            ..Default::default()
        },
    );
    table
}

/// Polls `pred` until it holds or `limit` elapses, yielding to the runtime between
/// checks so spawned tasks make progress on the current-thread test runtime.
async fn wait_until(limit: Duration, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    while tokio::time::Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    pred()
}

#[tokio::test]
async fn fetch_status_maps_a_registered_worker() {
    let endpoint = start_status(table_with_one_worker(), tmp_config()).await;

    let state = fetch_status(&endpoint).await;
    let ConnectionState::Connected(dash) = state else {
        panic!("expected Connected, got {state:?}");
    };

    assert_eq!(dash.workers.len(), 1, "the registered worker is listed");
    let w = &dash.workers[0];
    assert_eq!(w.id, "w1");
    assert_eq!(w.cpu, 2);
    assert!(w.healthy, "a freshly-registered worker is healthy");
    assert!(!w.last_ping.is_empty(), "the heartbeat age is humanized");

    // Nothing has run and no cache is configured.
    assert_eq!(
        (dash.exec.remote, dash.exec.local, dash.exec.fallback),
        (0, 0, 0)
    );
    assert!(!dash.cache.enabled, "no cache configured");
    assert_eq!(dash.cache.hit_rate_pct, None, "no lookups → no hit rate");
    assert!(!dash.auth_enabled, "auth disabled in this test");
}

#[tokio::test]
async fn fetch_status_reports_daemon_down_when_nothing_listens() {
    // A freed ephemeral port: connecting there is refused, which the client must
    // surface as DaemonDown (the "start the daemon" state), never a panic.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let dead = format!("http://{addr}");

    let state = fetch_status(&dead).await;
    assert!(
        matches!(state, ConnectionState::DaemonDown),
        "connection refused must map to DaemonDown, got {state:?}"
    );
}

#[tokio::test]
async fn config_round_trip_with_token_presence_clear_set() {
    let path = tmp_config();
    let endpoint = start_status(WorkerTable::new(Duration::from_secs(60)), path.clone()).await;

    // Fresh: no file yet → defaults, no token.
    let c0 = fetch_config(&endpoint).await.expect("get_config");
    assert!(!c0.file_exists, "no config file yet");
    assert!(!c0.cluster_token_set, "no token configured");
    assert_eq!(c0.coord_addr, "127.0.0.1:50070", "default address surfaced");

    // Set a token + cache_root; leave addresses empty (= keep).
    let outcome = apply_config(
        &endpoint,
        ConfigEdit {
            cache_root: "C:\\sbz-cache".into(),
            cache_max_bytes: 8192,
            token: TokenAction::Set("s3cret".into()),
            ..Default::default()
        },
    )
    .await
    .expect("set_config");
    assert!(outcome.ok);
    assert!(
        outcome.detail.contains("restart"),
        "the user is told a restart applies it: {}",
        outcome.detail
    );

    // Read back: persisted, address kept at its default, token reported SET but
    // its value is NOT present anywhere in the mapped model.
    let c1 = fetch_config(&endpoint).await.expect("get_config");
    assert!(c1.file_exists);
    assert_eq!(c1.cache_root, "C:\\sbz-cache");
    assert_eq!(c1.cache_max_bytes, 8192);
    assert_eq!(
        c1.coord_addr, "127.0.0.1:50070",
        "empty addr kept the default"
    );
    assert!(c1.cluster_token_set, "token presence is reported");
    let dbg = format!("{c1:?}");
    assert!(
        !dbg.contains("s3cret"),
        "the cluster token must never reach the GUI model: {dbg}"
    );

    // Keep: changing another field with token = Keep leaves the token set.
    apply_config(
        &endpoint,
        ConfigEdit {
            cache_max_bytes: 4096,
            token: TokenAction::Keep,
            ..Default::default()
        },
    )
    .await
    .expect("set_config keep");
    let c2 = fetch_config(&endpoint).await.expect("get_config");
    assert!(c2.cluster_token_set, "Keep leaves the token in place");
    assert_eq!(c2.cache_max_bytes, 4096, "the other field updated");
    assert!(
        !format!("{c2:?}").contains("s3cret"),
        "the token must not surface while it is still set"
    );

    // Clear: an empty token disables auth.
    apply_config(
        &endpoint,
        ConfigEdit {
            token: TokenAction::Clear,
            ..Default::default()
        },
    )
    .await
    .expect("set_config clear");
    let c3 = fetch_config(&endpoint).await.expect("get_config");
    assert!(!c3.cluster_token_set, "Clear removes the token");
    assert!(
        !format!("{c3:?}").contains("s3cret"),
        "the token must not surface across any config response"
    );
}

#[tokio::test]
async fn run_client_polls_serves_commands_and_stops_on_channel_close() {
    use std::sync::atomic::AtomicU64;

    use sembazuru_gui::client::{SharedState, UiCommand, Waker, run_client};
    use sembazuru_gui::model::ConfigModel;
    use tokio::sync::{mpsc, oneshot};

    let endpoint = start_status(table_with_one_worker(), tmp_config()).await;
    let shared = SharedState::new();
    let (tx, rx) = mpsc::channel::<UiCommand>(4);
    let woke = Arc::new(AtomicU64::new(0));
    let w = woke.clone();
    let wake: Waker = Arc::new(move || {
        w.fetch_add(1, Ordering::Relaxed);
    });

    let handle = tokio::spawn(run_client(endpoint.clone(), shared.clone(), rx, wake));

    // The first interval tick fires immediately: the dashboard becomes Connected
    // well under one POLL_INTERVAL (1.5s), not after a blank.
    let connected = wait_until(Duration::from_secs(2), || {
        matches!(shared.snapshot(), ConnectionState::Connected(_))
    })
    .await;
    assert!(connected, "run_client did not produce a snapshot promptly");
    assert!(
        woke.load(Ordering::Relaxed) >= 1,
        "the wake callback fired after a poll"
    );

    // A command routed through the loop round-trips off the poll path.
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(UiCommand::GetConfig(reply_tx)).await.unwrap();
    let cfg: ConfigModel = reply_rx.await.unwrap().expect("GetConfig via run_client");
    assert!(!cfg.cluster_token_set);

    // Dropping every sender closes the channel; the loop returns.
    drop(tx);
    let stopped = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(
        stopped.is_ok(),
        "run_client did not stop when the command channel closed"
    );
}
