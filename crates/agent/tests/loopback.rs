//! M3.1 loopback Execute end-to-end test: an in-process worker on an ephemeral
//! loopback port, driven by the real agent client over gRPC. This is the
//! automated evidence for the M3.1 increment — the agent commands a process
//! lifecycle on a worker and gets back the exit code and state sequence.
//!
//! It deliberately runs a trivial `cmd /c` (no DLL injection, no real compiler)
//! so the Rust CI job needs none of the C++ build artifacts: this gates the
//! control-plane lifecycle, not virtualization.

use sembazuru_proto::v0::{ActionState, Command};

/// Starts an in-process worker, returns its `http://` endpoint.
async fn start_worker() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener(listener).await.unwrap();
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
async fn loopback_execute_propagates_exit_code() {
    let endpoint = start_worker().await;

    let outcome = sembazuru_agent::execute_remote(
        endpoint,
        cmd(&["cmd", "/c", "exit", "7"]),
        "act-exit".to_string(),
        "sess".to_string(),
    )
    .await
    .expect("remote execution should succeed");

    assert_eq!(outcome.exit_code, Some(7), "remote exit code is propagated");
    assert!(
        outcome.states.contains(&(ActionState::Running as i32)),
        "lifecycle passed through RUNNING, got {:?}",
        outcome.states
    );
    assert_eq!(
        outcome.states.last().copied(),
        Some(ActionState::Completed as i32),
        "lifecycle ended in COMPLETED, got {:?}",
        outcome.states
    );
}

#[tokio::test]
async fn loopback_execute_reports_success() {
    let endpoint = start_worker().await;

    let outcome = sembazuru_agent::execute_remote(
        endpoint,
        cmd(&["cmd", "/c", "exit", "0"]),
        "act-ok".to_string(),
        "sess".to_string(),
    )
    .await
    .expect("remote execution should succeed");

    assert_eq!(outcome.exit_code, Some(0));
}
