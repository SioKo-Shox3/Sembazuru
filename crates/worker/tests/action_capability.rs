use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::scheduler::Scheduler;
use sembazuru_agent::{ExecOptions, ExecuteError, Execution};
use sembazuru_proto::capability::{self, ActionCapability, CAPABILITY_VERSION};
use sembazuru_proto::v0::execution_server::Execution as _;
use sembazuru_proto::v0::{AbortRequest, Capabilities, Command, ExecuteRequest};
use sembazuru_worker::WorkerService;
use tonic::Request;

const TOKEN: &str = "capability-test-token";
const WORKER_ID: &str = "worker-capability-test";

fn cmd(argv: &[&str]) -> Command {
    Command {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        env: Default::default(),
        cwd: String::new(),
    }
}

fn table_with(worker_id: &str, endpoint: &str) -> WorkerTable {
    let table = WorkerTable::new(Duration::from_secs(60));
    table.upsert_register(
        worker_id.to_string(),
        endpoint.to_string(),
        Capabilities {
            cpu_count: 1,
            worker_version: env!("CARGO_PKG_VERSION").to_string(),
            ..Default::default()
        },
    );
    table
}

async fn start_token_worker(worker_id: &str) -> (String, Arc<AtomicU64>) {
    let service = WorkerService::with_capacity(1)
        .with_action_capability_auth(Some(TOKEN.to_string()), worker_id.to_string());
    let served = service.served_handle();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });
    (endpoint, served)
}

fn capability_for(
    worker_id: &str,
    action_id: &str,
    session_id: &str,
    command: &Command,
    issued_at: u64,
    expires_at: u64,
) -> Vec<u8> {
    ActionCapability {
        version: CAPABILITY_VERSION,
        worker_id: worker_id.to_string(),
        action_id: action_id.to_string(),
        session_id: session_id.to_string(),
        command_digest: capability::command_digest(&command.argv, &command.env, &command.cwd),
        vfs_root: String::new(),
        issued_at,
        expires_at,
        nonce: [3; 16],
    }
    .encode(&capability::cap_key(TOKEN))
}

fn execute_request(
    action_id: &str,
    session_id: &str,
    command: Command,
    action_capability: Vec<u8>,
) -> ExecuteRequest {
    ExecuteRequest {
        action_id: action_id.to_string(),
        command: Some(command),
        session_id: session_id.to_string(),
        predicted_inputs: None,
        predicted_paths: Vec::new(),
        vfs: None,
        action_capability,
    }
}

#[tokio::test]
async fn execute_with_valid_capability_is_accepted() {
    let (endpoint, served) = start_token_worker(WORKER_ID).await;
    let scheduler =
        Scheduler::with_cluster_token(table_with(WORKER_ID, &endpoint), Some(TOKEN.to_string()));

    let exec = scheduler
        .dispatch(
            cmd(&["cmd", "/c", "exit", "0"]),
            "valid-action".into(),
            "valid-session".into(),
            ExecOptions::default(),
        )
        .await;

    match exec {
        Execution::Remote(outcome) => assert_eq!(outcome.exit_code, Some(0)),
        other => panic!("expected remote execution, got {other:?}"),
    }
    assert_eq!(served.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn execute_without_capability_is_rejected() {
    let (endpoint, served) = start_token_worker(WORKER_ID).await;

    let result = sembazuru_agent::execute_remote(
        endpoint,
        cmd(&["cmd", "/c", "exit", "0"]),
        "missing-cap".into(),
        "sess".into(),
    )
    .await;

    match result {
        Err(ExecuteError::Rpc(status)) => assert_eq!(status.code(), tonic::Code::PermissionDenied),
        other => panic!("expected permission_denied RPC error, got {other:?}"),
    }
    assert_eq!(served.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn execute_with_tampered_command_is_rejected() {
    let service = WorkerService::with_capacity(1)
        .with_action_capability_auth(Some(TOKEN.to_string()), WORKER_ID.to_string());
    let original = cmd(&["cmd", "/c", "exit", "0"]);
    let tampered = cmd(&["cmd", "/c", "exit", "9"]);
    let cap = capability_for(WORKER_ID, "act", "sess", &original, 1_000, u64::MAX);

    let result = service
        .execute(Request::new(execute_request("act", "sess", tampered, cap)))
        .await;

    let status = result.expect_err("tampered command must be rejected");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "command mismatch");
}

#[tokio::test]
async fn execute_with_tampered_action_id_is_rejected() {
    let service = WorkerService::with_capacity(1)
        .with_action_capability_auth(Some(TOKEN.to_string()), WORKER_ID.to_string());
    let command = cmd(&["cmd", "/c", "exit", "0"]);
    let cap = capability_for(WORKER_ID, "cap-action", "sess", &command, 1_000, u64::MAX);

    let result = service
        .execute(Request::new(execute_request(
            "request-action",
            "sess",
            command,
            cap,
        )))
        .await;

    let status = result.expect_err("tampered action_id must be rejected");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "action id mismatch");
}

#[tokio::test]
async fn execute_with_tampered_session_id_is_rejected() {
    let service = WorkerService::with_capacity(1)
        .with_action_capability_auth(Some(TOKEN.to_string()), WORKER_ID.to_string());
    let command = cmd(&["cmd", "/c", "exit", "0"]);
    let cap = capability_for(WORKER_ID, "act", "cap-session", &command, 1_000, u64::MAX);

    let result = service
        .execute(Request::new(execute_request(
            "act",
            "request-session",
            command,
            cap,
        )))
        .await;

    let status = result.expect_err("tampered session_id must be rejected");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "session id mismatch");
}

#[tokio::test]
async fn execute_with_expired_capability_is_rejected() {
    let service = WorkerService::with_capacity(1)
        .with_action_capability_auth(Some(TOKEN.to_string()), WORKER_ID.to_string());
    let command = cmd(&["cmd", "/c", "exit", "0"]);
    let cap = capability_for(WORKER_ID, "act", "sess", &command, 1_000, 1_001);

    let result = service
        .execute(Request::new(execute_request("act", "sess", command, cap)))
        .await;

    let status = result.expect_err("expired capability must be rejected");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "capability expired");
}

#[tokio::test]
async fn execute_with_wrong_worker_capability_is_rejected() {
    let service = WorkerService::with_capacity(1)
        .with_action_capability_auth(Some(TOKEN.to_string()), WORKER_ID.to_string());
    let command = cmd(&["cmd", "/c", "exit", "0"]);
    let cap = capability_for("other-worker", "act", "sess", &command, 1_000, u64::MAX);

    let result = service
        .execute(Request::new(execute_request("act", "sess", command, cap)))
        .await;

    let status = result.expect_err("wrong-worker capability must be rejected");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "capability not for this worker");
}

#[tokio::test]
async fn abort_without_capability_is_rejected() {
    let service = WorkerService::with_capacity(1)
        .with_action_capability_auth(Some(TOKEN.to_string()), WORKER_ID.to_string());

    let result = service
        .abort(Request::new(AbortRequest {
            action_id: "act".to_string(),
            reason: String::new(),
            action_capability: Vec::new(),
        }))
        .await;

    let status = result.expect_err("missing abort capability must be rejected");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "missing action capability");
}
