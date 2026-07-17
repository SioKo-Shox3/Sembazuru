//! M5.2 worker admission test: the `Execution` service bounds concurrent actions
//! to its capacity with an admission semaphore (a single un-virtualized worker
//! must not fork-bomb under a flood of `Execute`s — the DoS fix). Driven through
//! the real agent client (a dev-dependency) over loopback gRPC.
//!
//! The assertion is an *upper bound* on the in-flight gauge, which is robust to
//! timing: under a burst of slow actions the count must reach capacity (proving
//! admission lets work through) but never exceed it (proving the bound holds).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use sembazuru_agent::{ActionOutcome, ExecuteError};
use sembazuru_proto::v0::execute_event::Event;
use sembazuru_proto::v0::execution_server::Execution as _;
use sembazuru_proto::v0::{ActionState, Command, ExecuteRequest};
use sembazuru_worker::WorkerService;
use tokio::task::JoinSet;
use tokio_stream::StreamExt;
use tonic::Request;

type RpcOutcome = Result<ActionOutcome, ExecuteError>;

fn blocking_cmd() -> Command {
    // cmd creates the readiness marker inside this action's private %TEMP%; the
    // action cwd is the same private directory, so it can wait on a release
    // marker without accessing another action's synchronization files. WAITFOR
    // signal names accept alphanumerics here (no underscore): exit 0 means the
    // release event arrived, while exit 3 diagnoses exhausted backoff iterations.
    Command {
        argv: vec![
            "cmd.exe".into(),
            "/d".into(),
            "/q".into(),
            "/s".into(),
            "/c".into(),
            concat!(
                "type nul > ready & ",
                "(for /L %i in (1,1,600) do @if exist release (exit /b 0) else ",
                "(waitfor /t 1 SembazuruAdmissionNeverSignal7f6d29a4c31e >nul 2>nul)) ",
                "& exit /b 3"
            )
            .into(),
        ],
        env: Default::default(),
        cwd: String::new(),
    }
}

fn ready_scratch_dirs(root: &Path) -> HashSet<PathBuf> {
    std::fs::read_dir(root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.join("ready").is_file())
        .collect()
}

fn drain_finished(
    actions: &mut JoinSet<(usize, RpcOutcome)>,
    outcomes: &mut Vec<(usize, RpcOutcome)>,
) {
    while let Some(result) = actions.try_join_next() {
        match result {
            Ok(outcome) => outcomes.push(outcome),
            Err(error) => panic!("admission RPC task failed to join: {error}"),
        }
    }
}

fn execute_request(action_id: &str) -> ExecuteRequest {
    ExecuteRequest {
        action_id: action_id.to_string(),
        command: Some(blocking_cmd()),
        session_id: "sess".into(),
        predicted_inputs: None,
        predicted_paths: Vec::new(),
        vfs: None,
        action_capability: Vec::new(),
    }
}

async fn expect_state(
    stream: &mut <WorkerService as sembazuru_proto::v0::execution_server::Execution>::ExecuteStream,
    expected: ActionState,
) {
    let event = tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await
        .expect("worker did not emit the expected state")
        .expect("worker closed the execution stream early")
        .expect("worker returned a stream error");
    let Some(Event::State(state)) = event.event else {
        panic!("expected a state event, got {event:?}");
    };
    assert_eq!(state.state, expected as i32);
}

#[tokio::test]
async fn dropping_a_queued_stream_cancels_before_admission() {
    let scratch_root = std::env::temp_dir().join(format!(
        "sbz-admission-queued-cancel-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&scratch_root);
    std::fs::create_dir(&scratch_root).unwrap();

    let service = WorkerService::with_capacity(1).with_scratch_root(scratch_root.clone());
    let running = service.running_handle();
    let served = service.served_handle();

    let mut first = service
        .execute(Request::new(execute_request("first")))
        .await
        .unwrap()
        .into_inner();
    expect_state(&mut first, ActionState::Queued).await;

    let first_ready = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(path) = ready_scratch_dirs(&scratch_root).into_iter().next() {
                break path;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first action never acquired the sole permit");
    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(running.load(Ordering::SeqCst), 1);

    let mut second = service
        .execute(Request::new(execute_request("second")))
        .await
        .unwrap()
        .into_inner();
    expect_state(&mut second, ActionState::Queued).await;
    drop(second);

    std::fs::write(first_ready.join("release"), b"release").unwrap();
    while first.next().await.is_some() {}

    let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        assert_eq!(
            served.load(Ordering::SeqCst),
            1,
            "the cancelled queued action reached admission"
        );
        if running.load(Ordering::SeqCst) == 0
            && std::fs::read_dir(&scratch_root).unwrap().next().is_none()
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < cleanup_deadline,
            "cancelled queued action reached running or left private scratch: running={}, scratch={:?}",
            running.load(Ordering::SeqCst),
            ready_scratch_dirs(&scratch_root)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(served.load(Ordering::SeqCst), 1);
    assert_eq!(running.load(Ordering::SeqCst), 0);
    assert!(std::fs::read_dir(&scratch_root).unwrap().next().is_none());

    // Keep the runtime alive after the permit is released so the queued task
    // must observe cancellation rather than merely remaining unscheduled.
    let stable_until = tokio::time::Instant::now() + Duration::from_millis(250);
    while tokio::time::Instant::now() < stable_until {
        assert_eq!(served.load(Ordering::SeqCst), 1);
        assert_eq!(running.load(Ordering::SeqCst), 0);
        assert!(std::fs::read_dir(&scratch_root).unwrap().next().is_none());
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::fs::remove_dir(scratch_root).unwrap();
}

#[tokio::test]
async fn admission_caps_concurrent_actions_at_capacity() {
    const CAP: u32 = 2;
    const ACTIONS: usize = 4;
    let scratch_root =
        std::env::temp_dir().join(format!("sbz-admission-events-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch_root);
    std::fs::create_dir(&scratch_root).unwrap();

    let service = WorkerService::with_capacity(CAP).with_scratch_root(scratch_root.clone());
    let running = service.running_handle();
    let served = service.served_handle();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });

    // Fire four event-blocked actions at a capacity-2 worker. Keep every task so
    // an early RPC or child failure cannot be mistaken for an admission result.
    let mut actions = JoinSet::new();
    for i in 0..ACTIONS {
        let ep = endpoint.clone();
        actions.spawn(async move {
            let result = sembazuru_agent::execute_remote(
                ep,
                blocking_cmd(),
                format!("admit-{i}"),
                "sess".into(),
            )
            .await;
            (i, result)
        });
    }

    // Wait for exactly CAP private ready markers. This is an action event, not a
    // guess based on how long a particular executable usually runs.
    let mut max_seen = 0u32;
    let mut outcomes: Vec<(usize, RpcOutcome)> = Vec::new();
    let first_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let first_ready = loop {
        let ready = ready_scratch_dirs(&scratch_root);
        let now = running.load(Ordering::SeqCst);
        max_seen = max_seen.max(now);
        drain_finished(&mut actions, &mut outcomes);
        assert!(
            now <= CAP,
            "in-flight actions {now} exceeded capacity {CAP} — admission semaphore breached"
        );
        assert!(
            ready.len() <= CAP as usize,
            "more actions became ready than capacity permits: {ready:?}"
        );
        if ready.len() == CAP as usize {
            break ready;
        }
        assert!(
            outcomes.is_empty() && tokio::time::Instant::now() < first_deadline,
            "actions failed before capacity became ready: served={}, running={now}, ready={ready:?}, outcomes={outcomes:#?}",
            served.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    };

    // With neither ready action released, queued actions must remain unable to
    // create their own ready marker throughout a short stability window.
    let stable_until = tokio::time::Instant::now() + Duration::from_millis(200);
    while tokio::time::Instant::now() < stable_until {
        let ready = ready_scratch_dirs(&scratch_root);
        let now = running.load(Ordering::SeqCst);
        max_seen = max_seen.max(now);
        drain_finished(&mut actions, &mut outcomes);
        assert_eq!(
            ready,
            first_ready,
            "a queued action became ready before capacity was released: served={}, running={now}, outcomes={outcomes:#?}",
            served.load(Ordering::SeqCst)
        );
        assert!(
            outcomes.is_empty(),
            "a blocked action exited early: {outcomes:#?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(served.load(Ordering::SeqCst), u64::from(CAP));

    for path in &first_ready {
        std::fs::write(path.join("release"), b"release").unwrap();
    }

    // Releasing the first batch must allow the remaining actions to reach their
    // own private ready markers. Preserve paths already seen because completed
    // actions' scratch directories are removed promptly.
    let mut all_ready = first_ready.clone();
    let remaining_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while all_ready.len() < ACTIONS {
        all_ready.extend(ready_scratch_dirs(&scratch_root));
        let now = running.load(Ordering::SeqCst);
        max_seen = max_seen.max(now);
        drain_finished(&mut actions, &mut outcomes);
        assert!(
            now <= CAP,
            "in-flight actions {now} exceeded capacity {CAP} after release"
        );
        assert!(
            tokio::time::Instant::now() < remaining_deadline,
            "remaining actions never became ready: served={}, running={now}, ready={all_ready:?}, outcomes={outcomes:#?}",
            served.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let remaining_ready: Vec<_> = all_ready.difference(&first_ready).cloned().collect();
    assert_eq!(remaining_ready.len(), ACTIONS - CAP as usize);
    for path in &remaining_ready {
        std::fs::write(path.join("release"), b"release").unwrap();
    }

    let completion_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while outcomes.len() < ACTIONS {
        let result = tokio::time::timeout_at(completion_deadline, actions.join_next())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "RPC completion timed out: served={}, running={}, outcomes={outcomes:#?}",
                    served.load(Ordering::SeqCst),
                    running.load(Ordering::SeqCst)
                )
            })
            .expect("JoinSet ended before every RPC completed")
            .expect("admission RPC task failed to join");
        outcomes.push(result);
    }
    outcomes.sort_by_key(|(i, _)| *i);
    for (i, result) in &outcomes {
        let outcome = result
            .as_ref()
            .unwrap_or_else(|error| panic!("action {i} RPC failed: {error:?}"));
        assert_eq!(
            outcome.exit_code,
            Some(0),
            "action {i} did not complete successfully: {outcome:?}"
        );
    }
    eprintln!(
        "admission events: served={}, max_running={max_seen}, outcomes={outcomes:#?}",
        served.load(Ordering::SeqCst)
    );
    assert_eq!(served.load(Ordering::SeqCst), ACTIONS as u64);
    assert_eq!(max_seen, CAP);

    let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while std::fs::read_dir(&scratch_root).unwrap().next().is_some() {
        assert!(
            tokio::time::Instant::now() < cleanup_deadline,
            "private scratch was not cleaned after all actions completed"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    std::fs::remove_dir(scratch_root).unwrap();
}

#[tokio::test]
async fn flood_past_backlog_is_rejected_with_resource_exhausted() {
    // capacity 1 → accepted backlog cap = QUEUE_FACTOR(8) × 1 = 8. A flood of 12
    // concurrent blocked actions must see at least the overflow rejected with
    // RESOURCE_EXHAUSTED rather than pinning unbounded queued tasks (DoS: H1).
    let service = WorkerService::with_capacity(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });

    // Dropping the still-running RPC streams cancels their worker actions, so the
    // test does not need to release every accepted fixture action.
    let mut set = JoinSet::new();
    for i in 0..12 {
        let ep = endpoint.clone();
        set.spawn(async move {
            sembazuru_agent::execute_remote(ep, blocking_cmd(), format!("flood-{i}"), "sess".into())
                .await
        });
    }

    // Rejections come back immediately; collect for a short window.
    let mut rejected = 0;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while let Ok(Some(res)) = tokio::time::timeout_at(deadline, set.join_next()).await {
        if let Ok(Err(ExecuteError::Rpc(status))) = res
            && status.code() == tonic::Code::ResourceExhausted
        {
            rejected += 1;
        }
    }
    assert!(
        rejected >= 1,
        "flooding past the accepted-work backlog must reject with RESOURCE_EXHAUSTED, \
         got {rejected} rejections"
    );
}
