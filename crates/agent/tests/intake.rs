//! M6.0 gate: the LocalIntake front door end-to-end. A build-system launcher
//! submits an action to the daemon over loopback; the daemon schedules it on a
//! worker (or falls back to local) and mirrors the exit code back so the
//! launcher can exit as the compiler would have.
//!
//! This wires the four daemon pieces the way `sembazuru-daemon` does, but
//! in-process: a worker registered in a `WorkerTable`, a `Scheduler` over it,
//! and `serve_intake` driven by the `submit_to_daemon` client (the launcher's
//! core call). The three cases are the M6.0 contract:
//!   1. with a live worker the action runs *remotely* and its exit is mirrored;
//!   2. with no workers the daemon completes it via *local fallback* (§2);
//!   3. a down daemon surfaces an error — exactly the launcher's fallback
//!      trigger (the launcher then runs the compiler locally).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::intake::{serve_intake, submit_to_daemon};
use sembazuru_agent::scheduler::Scheduler;
use sembazuru_proto::v0::{Capabilities, Command};
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

/// Stands up `serve_intake` over `scheduler` on an ephemeral loopback port and
/// returns the `http://` endpoint a launcher would dial.
async fn start_intake(scheduler: Scheduler) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_intake(listener, scheduler).await.unwrap();
    });
    format!("http://{addr}")
}

fn cmd(argv: &[&str]) -> Command {
    Command {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: Default::default(),
        cwd: String::new(),
    }
}

#[tokio::test]
async fn intake_runs_action_remotely_and_mirrors_exit() {
    let (w1, served) = start_worker().await;
    let scheduler = Scheduler::new(table_with(&[("w1", &w1, 2)]));
    let endpoint = start_intake(scheduler).await;

    // A launcher submitting `cmd /c exit 5` must get exit 5 back, and the action
    // must have actually run on the worker (not local fallback).
    let (code, _note) = submit_to_daemon(endpoint, cmd(&["cmd", "/c", "exit", "5"]), Vec::new())
        .await
        .expect("daemon mirrored an exit code");
    assert_eq!(
        code, 5,
        "the compiler's exit code is mirrored through intake"
    );
    assert_eq!(
        served.load(Ordering::SeqCst),
        1,
        "the action ran remotely on the worker"
    );
}

#[tokio::test]
async fn intake_completes_via_local_fallback_with_no_workers() {
    // No workers: the daemon's scheduler must still complete the action locally
    // (DESIGN.md §2) and mirror its exit code — the launcher sees a clean exit,
    // not an error.
    let scheduler = Scheduler::new(WorkerTable::new(Duration::from_secs(60)));
    let endpoint = start_intake(scheduler).await;

    let (code, _note) = submit_to_daemon(endpoint, cmd(&["cmd", "/c", "exit", "3"]), Vec::new())
        .await
        .expect("daemon completed via local fallback");
    assert_eq!(
        code, 3,
        "local fallback ran the command and mirrored its exit"
    );
}

#[tokio::test]
async fn submit_errors_when_daemon_is_down() {
    // A dead intake endpoint: submit_to_daemon must error. This is precisely the
    // signal the `sembazuru` launcher converts into a local compiler run, so the
    // build completes even with no daemon at all.
    let err = submit_to_daemon(
        "http://127.0.0.1:1".into(),
        cmd(&["cmd", "/c", "exit", "0"]),
        Vec::new(),
    )
    .await;
    assert!(
        err.is_err(),
        "an unreachable daemon must error so the launcher falls back to local"
    );
}
