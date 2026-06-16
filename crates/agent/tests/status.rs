//! M9.1 gate: the loopback Status surface end-to-end. The resident GUI (M9.4)
//! will poll this; here we drive real actions through the daemon's intake and
//! assert the `GetStatus` RPC reports them — the connected worker, the
//! remote/local/fallback breakdown, the in-flight gauge, and the cache/auth
//! posture. The point is that the counters the intake path increments are the
//! exact ones the Status service surfaces (they share one `Metrics` Arc).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::fileserver::ServerStats;
use sembazuru_agent::intake::{
    IntakeService, SubmitOptions, require_loopback, serve_intake_service, submit_to_daemon,
};
use sembazuru_agent::scheduler::Scheduler;
use sembazuru_agent::status::{StatusState, serve_status_service};
use sembazuru_proto::v0::{
    Capabilities, Command, GetStatusRequest, GetStatusResponse, status_client::StatusClient,
};
use sembazuru_worker::WorkerService;

/// An in-process Execution worker (capacity 2); returns its `http://` endpoint
/// and a handle to its cumulative served-action count.
async fn start_worker() -> (String, Arc<AtomicU64>) {
    let service = WorkerService::with_capacity(2);
    let served = service.served_handle();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });
    (format!("http://{addr}"), served)
}

fn table_with(workers: &[(&str, &str, u32)]) -> WorkerTable {
    let table = WorkerTable::new(Duration::from_secs(60));
    for (id, endpoint, cpu) in workers {
        table.upsert_register(
            (*id).to_string(),
            (*endpoint).to_string(),
            Capabilities {
                cpu_count: *cpu,
                ..Default::default()
            },
        );
    }
    table
}

fn cmd(argv: &[&str]) -> Command {
    Command {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: Default::default(),
        cwd: String::new(),
    }
}

/// Stands up the daemon's intake + Status planes over `table`, sharing one
/// `Metrics` Arc the way `sembazuru-daemon` does. Returns the intake endpoint a
/// launcher dials and the Status endpoint the GUI dials.
async fn start_intake_and_status(table: WorkerTable, auth_enabled: bool) -> (String, String) {
    let scheduler = Scheduler::new(table.clone());
    let intake = IntakeService::new(scheduler);
    let metrics = intake.metrics();

    let intake_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let intake_addr = intake_listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_intake_service(intake_listener, intake).await.unwrap();
    });

    let state = StatusState {
        table,
        server_stats: Arc::new(ServerStats::default()),
        cache: None,
        metrics,
        auth_enabled,
    };
    let status_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let status_addr = status_listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_status_service(status_listener, state).await.unwrap();
    });

    (
        format!("http://{intake_addr}"),
        format!("http://{status_addr}"),
    )
}

async fn get_status(status_endpoint: &str) -> GetStatusResponse {
    let mut client = StatusClient::connect(status_endpoint.to_string())
        .await
        .unwrap();
    client
        .get_status(GetStatusRequest {})
        .await
        .unwrap()
        .into_inner()
}

#[tokio::test]
async fn status_reports_a_remote_run_and_the_connected_worker() {
    let (w1, served) = start_worker().await;
    let (intake, status) = start_intake_and_status(table_with(&[("w1", &w1, 2)]), false).await;

    // A baseline snapshot: the worker is connected and healthy, nothing has run.
    let before = get_status(&status).await;
    assert_eq!(before.workers.len(), 1, "the registered worker is listed");
    let w = &before.workers[0];
    assert_eq!(w.worker_id, "w1");
    assert_eq!(w.cpu_count, 2);
    assert!(w.healthy, "a freshly-registered worker is healthy");
    let exec = before.exec.as_ref().unwrap();
    assert_eq!((exec.remote, exec.local, exec.fallback), (0, 0, 0));
    assert!(
        !before.cache.as_ref().unwrap().enabled,
        "no cache configured"
    );
    assert!(!before.auth_enabled, "auth disabled in this test");

    // Run one action remotely through intake.
    let (code, _note) = submit_to_daemon(
        intake,
        cmd(&["cmd", "/c", "exit", "0"]),
        SubmitOptions::default(),
    )
    .await
    .expect("intake mirrored an exit code");
    assert_eq!(code, 0);
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the action actually ran on the worker"
    );

    // The Status surface reflects exactly that one remote run.
    let after = get_status(&status).await;
    let exec = after.exec.as_ref().unwrap();
    assert_eq!(
        (exec.remote, exec.local, exec.fallback),
        (1, 0, 0),
        "one remote run shows up as remote, not local/fallback"
    );
}

#[tokio::test]
async fn status_counts_a_local_fallback_when_no_worker_is_live() {
    // No workers: the action completes via local fallback (DESIGN §2), and the
    // Status surface classifies it as a fallback (not a deliberate route-away).
    let (intake, status) =
        start_intake_and_status(WorkerTable::new(Duration::from_secs(60)), true).await;

    let before = get_status(&status).await;
    assert!(before.workers.is_empty(), "no workers connected");
    assert!(before.auth_enabled, "auth posture is surfaced");

    let (code, _note) = submit_to_daemon(
        intake,
        cmd(&["cmd", "/c", "exit", "0"]),
        SubmitOptions::default(),
    )
    .await
    .expect("local fallback completed the action");
    assert_eq!(code, 0);

    let after = get_status(&status).await;
    let exec = after.exec.as_ref().unwrap();
    assert_eq!(
        (exec.remote, exec.local, exec.fallback),
        (0, 0, 1),
        "with no live worker the run is a fallback"
    );
}

#[test]
fn status_plane_refuses_a_non_loopback_bind() {
    // The Status plane is loopback-only (ADR 0008 §4): a routable bind would
    // expose the daemon's operational state to the network.
    assert!(require_loopback("127.0.0.1:50073", "Status").is_ok());
    assert!(require_loopback("[::1]:50073", "Status").is_ok());
    assert!(require_loopback("0.0.0.0:50073", "Status").is_err());
    assert!(require_loopback("10.0.0.5:50073", "Status").is_err());
}
