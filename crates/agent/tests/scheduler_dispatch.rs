//! M5.2 scheduler dispatch end-to-end test: the agent-side [`Scheduler`] places
//! actions on live workers from a [`WorkerTable`], reassigns past a dead worker,
//! and falls back to local execution when no remote path works. In-process
//! Execution workers (as in `loopback.rs`) stand in for worker processes.
//!
//! Together with the unit tests in `scheduler.rs` (affinity stability, ring
//! determinism, load-spread ordering) this is the M5.2 evidence: actions reach
//! workers, a worker death does not lose an action, and the build still
//! completes locally in the worst case (DESIGN.md §2).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::action_tracker::{ActionTracker, ActivityState, ExecutionKind};
use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::scheduler::{BuildAction, Scheduler};
use sembazuru_agent::{ExecOptions, Execution};
use sembazuru_proto::v0::{Capabilities, Command};
use sembazuru_worker::WorkerService;

/// Starts an in-process Execution worker (capacity 2), returning its `http://`
/// endpoint and a handle to its cumulative served-action count (so a test can
/// assert work actually landed on it).
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

/// A table with the given workers registered (endpoint + cpu_count), live for a
/// generous window so they stay schedulable through the test. Workers report this
/// build's version so they pass the ADR 0011 version gate (the agent admits only
/// version-matched workers); tests of the gate itself register a mismatch explicitly.
fn table_with(workers: &[(&str, &str, u32)]) -> WorkerTable {
    let table = WorkerTable::new(Duration::from_secs(60));
    for (id, endpoint, cpu) in workers {
        table.upsert_register(
            (*id).to_string(),
            (*endpoint).to_string(),
            Capabilities {
                cpu_count: *cpu,
                worker_version: env!("CARGO_PKG_VERSION").to_string(),
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

// Restricted worker startup can be slow under loaded CI. Tests that require a
// Remote outcome need enough budget to avoid mistaking fixture latency for fallback.
const GENEROUS_REMOTE_BUDGET: Duration = Duration::from_secs(30);

async fn unavailable_endpoint() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}")
}

#[tokio::test]
async fn scheduler_records_retry_and_fallback_as_distinct_attempts() {
    let tracker = ActionTracker::default();
    let w1 = unavailable_endpoint().await;
    let w2 = unavailable_endpoint().await;
    let table = table_with(&[("w1", &w1, 1), ("w2", &w2, 1)]);
    let scheduler = Scheduler::with_remote_budget_and_cluster_token_and_tracker(
        table,
        Duration::from_secs(1),
        None,
        tracker.clone(),
    );
    let result = scheduler
        .dispatch(
            cmd(&["cmd", "/c", "exit", "0"]),
            "a".into(),
            "session".into(),
            ExecOptions::default(),
        )
        .await;
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
        table_with(&[("w1", &worker, 1)]),
        GENEROUS_REMOTE_BUDGET,
        None,
        tracker.clone(),
    );
    let result = scheduler
        .dispatch(
            cmd(&["cmd", "/c", "exit", "4"]),
            "nonzero".into(),
            "session".into(),
            ExecOptions::default(),
        )
        .await;
    assert!(matches!(result, Execution::Remote(_)));
    let attempt = tracker
        .snapshot()
        .into_iter()
        .find(|attempt| attempt.key.action_id == "nonzero")
        .unwrap();
    assert_eq!(attempt.state, ActivityState::Failed);
}

#[tokio::test]
async fn worker_stream_exposes_running_before_remote_completion() {
    let tracker = ActionTracker::default();
    let (worker, _) = start_worker().await;
    let scheduler = Scheduler::with_remote_budget_and_cluster_token_and_tracker(
        table_with(&[("w1", &worker, 1)]),
        GENEROUS_REMOTE_BUDGET,
        None,
        tracker.clone(),
    );
    let run = tokio::spawn(async move {
        scheduler
            .dispatch(
                cmd(&[
                    "cmd",
                    "/c",
                    "waitfor /t 2 SembazuruSchedulerRunningNeverSignal4c8f21a7 >nul 2>nul & exit /b 0",
                ]),
                "running".into(),
                "session".into(),
                ExecOptions::default(),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if tracker
                .snapshot()
                .iter()
                .any(|attempt| attempt.state == ActivityState::Running)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker Running event was not observed before completion");
    match run.await.unwrap() {
        Execution::Remote(outcome) => assert_eq!(outcome.exit_code, Some(0)),
        other => panic!("expected remote execution, got {other:?}"),
    }
    assert_eq!(tracker.snapshot()[0].state, ActivityState::Completed);
}

#[tokio::test]
async fn tracker_capacity_never_changes_fallback_execution() {
    let tracker = ActionTracker::default();
    for index in 0..sembazuru_agent::action_tracker::MAX_ACTIVITY_ATTEMPTS {
        assert!(
            tracker
                .begin_attempt(
                    &format!("active-{index}"),
                    0,
                    "busy",
                    ExecutionKind::Remote,
                    "unit.cpp",
                )
                .is_some()
        );
    }
    let scheduler = Scheduler::with_remote_budget_and_cluster_token_and_tracker(
        WorkerTable::new(Duration::from_secs(60)),
        Duration::from_secs(1),
        None,
        tracker.clone(),
    );
    let result = scheduler
        .dispatch(
            cmd(&["cmd", "/c", "exit", "0"]),
            "overflow".into(),
            "session".into(),
            ExecOptions::default(),
        )
        .await;
    assert!(matches!(
        result,
        Execution::LocalFallback { exit_code: 0, .. }
    ));
    assert_eq!(
        tracker.snapshot().len(),
        sembazuru_agent::action_tracker::MAX_ACTIVITY_ATTEMPTS
    );
}

#[tokio::test]
async fn cancelled_dispatch_interrupts_its_tracked_attempt() {
    let tracker = ActionTracker::default();
    let scheduler = Scheduler::with_remote_budget_and_cluster_token_and_tracker(
        WorkerTable::new(Duration::from_secs(60)),
        Duration::from_secs(1),
        None,
        tracker.clone(),
    );
    let dispatch = tokio::spawn(async move {
        scheduler
            .dispatch(
                cmd(&["cmd", "/c", "ping -n 30 127.0.0.1 >nul"]),
                "cancelled".into(),
                "session".into(),
                ExecOptions::default(),
            )
            .await
    });

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if tracker
                .snapshot()
                .iter()
                .any(|attempt| attempt.state == ActivityState::Running)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("local fallback did not reach Running");

    dispatch.abort();
    assert!(dispatch.await.unwrap_err().is_cancelled());
    let snapshot = tracker.snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].state, ActivityState::Interrupted);
    assert!(snapshot[0].finished_age.is_some());
}

#[tokio::test]
async fn dispatch_runs_remotely_with_live_workers() {
    let (w1, _) = start_worker().await;
    let (w2, _) = start_worker().await;
    let table = table_with(&[("w1", &w1, 2), ("w2", &w2, 2)]);
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "4"]),
            "act-1".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::Remote(o) => assert_eq!(o.exit_code, Some(4), "ran on a worker"),
        other => panic!("expected remote execution, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_captures_remote_stdout() {
    // M6.1: the process runs on the worker, so its console output must be streamed
    // back (else a developer sees no compiler diagnostics). Assert a remote
    // action's stdout is captured in the outcome.
    let (w1, _) = start_worker().await;
    let table = table_with(&[("w1", &w1, 2)]);
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "echo", "hello-from-worker"]),
            "act-stdout".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::Remote(o) => {
            assert_eq!(o.exit_code, Some(0));
            let out = String::from_utf8_lossy(&o.stdout);
            assert!(
                out.contains("hello-from-worker"),
                "remote stdout must be captured, got {out:?}"
            );
        }
        other => panic!("expected remote execution, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_reassigns_past_a_dead_worker() {
    // One dead endpoint, one live worker. Whichever the ring prefers, dispatch
    // must try both and land the action on the live one — not fall back to local.
    let (live, _) = start_worker().await;
    let table = table_with(&[("dead", "http://127.0.0.1:1", 2), ("live", &live, 2)]);
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "7"]),
            "act-2".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::Remote(o) => assert_eq!(o.exit_code, Some(7), "reassigned to the live worker"),
        other => panic!("expected remote execution after reassignment, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_falls_back_to_local_when_all_workers_dead() {
    let table = table_with(&[
        ("dead1", "http://127.0.0.1:1", 2),
        ("dead2", "http://127.0.0.1:2", 2),
    ]);
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "9"]),
            "act-3".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::LocalFallback { exit_code, reason } => {
            assert_eq!(
                exit_code, 9,
                "local fallback ran the command; reason: {reason}"
            );
        }
        other => panic!("expected local fallback, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_falls_back_to_local_when_all_workers_cpu_busy() {
    // ADR 0010: live, reachable, capable workers — but every one reports 0% idle
    // CPU (its host is busy with the user's own work). The scheduler must not
    // burden them; it routes the action to local execution instead, and the build
    // still completes. This is the CPU-aware analogue of the all-dead fallback.
    let (w1, served1) = start_worker().await;
    let (w2, served2) = start_worker().await;
    let table = table_with(&[("w1", &w1, 2), ("w2", &w2, 2)]);
    // A heartbeat carrying idle_cpu_pct = 0 marks each host as busy.
    table.on_ping("w1", 0, 0, Some(0));
    table.on_ping("w2", 0, 0, Some(0));
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "5"]),
            "act-busy".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::LocalFallback { exit_code, reason } => {
            assert_eq!(exit_code, 5, "ran locally; reason: {reason}");
        }
        other => panic!("expected local fallback when all workers are CPU-busy, got {other:?}"),
    }
    // The busy workers were genuinely avoided, not merely out-raced.
    assert_eq!(
        served1.load(Ordering::SeqCst),
        0,
        "CPU-busy worker w1 must receive no action"
    );
    assert_eq!(
        served2.load(Ordering::SeqCst),
        0,
        "CPU-busy worker w2 must receive no action"
    );
}

#[tokio::test]
async fn dispatch_falls_back_to_local_when_all_workers_version_mismatched() {
    // ADR 0011: live, reachable, fully idle workers — but every one reports a build
    // version that differs from this agent's. The version gate excludes them all
    // from scheduling, so the action runs locally and the build still completes
    // (local fallback is always available, non-negotiable #2). A mixed-version
    // cluster never silently runs a build on a worker whose output could diverge.
    let (w1, served1) = start_worker().await;
    let (w2, served2) = start_worker().await;
    // Register with a deliberately mismatched version (not via table_with, which
    // reports this build's version and would be admitted).
    let table = WorkerTable::new(Duration::from_secs(60));
    for (id, endpoint) in [("w1", &w1), ("w2", &w2)] {
        table.upsert_register(
            id.to_string(),
            endpoint.to_string(),
            Capabilities {
                cpu_count: 2,
                worker_version: "0.0.0-mismatch".to_string(),
                ..Default::default()
            },
        );
    }
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "7"]),
            "act-ver".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::LocalFallback { exit_code, reason } => {
            assert_eq!(exit_code, 7, "ran locally; reason: {reason}");
        }
        other => {
            panic!("expected local fallback when all workers are version-mismatched, got {other:?}")
        }
    }
    // The mismatched workers were genuinely excluded, not merely out-raced.
    assert_eq!(
        served1.load(Ordering::SeqCst),
        0,
        "version-mismatched worker w1 must receive no action"
    );
    assert_eq!(
        served2.load(Ordering::SeqCst),
        0,
        "version-mismatched worker w2 must receive no action"
    );
}

#[tokio::test]
async fn dispatch_falls_back_to_local_when_all_workers_mode_off() {
    // ADR 0012: live, reachable, version-matched, idle workers — but every one is
    // configured `participation_mode = off`. The agent excludes opted-out workers
    // from scheduling, so the action runs locally and the build still completes.
    let (w1, served1) = start_worker().await;
    let (w2, served2) = start_worker().await;
    let table = WorkerTable::new(Duration::from_secs(60));
    for (id, endpoint) in [("w1", &w1), ("w2", &w2)] {
        table.upsert_register(
            id.to_string(),
            endpoint.to_string(),
            Capabilities {
                cpu_count: 2,
                // Version-matched (so only the mode excludes them), opted out.
                worker_version: env!("CARGO_PKG_VERSION").to_string(),
                participation_mode: "off".to_string(),
                ..Default::default()
            },
        );
    }
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "4"]),
            "act-off".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::LocalFallback { exit_code, reason } => {
            assert_eq!(exit_code, 4, "ran locally; reason: {reason}");
        }
        other => panic!("expected local fallback when all workers are mode=off, got {other:?}"),
    }
    assert_eq!(
        served1.load(Ordering::SeqCst),
        0,
        "opted-out worker w1 must receive no action"
    );
    assert_eq!(
        served2.load(Ordering::SeqCst),
        0,
        "opted-out worker w2 must receive no action"
    );
}

#[tokio::test]
async fn dispatch_runs_remotely_when_worker_reports_idle_cpu() {
    // The complement of the busy case: a worker reporting plenty of idle CPU is
    // still scheduled remotely — CPU-awareness must not block an idle worker.
    let (w1, served) = start_worker().await;
    let table = table_with(&[("w1", &w1, 2)]);
    table.on_ping("w1", 0, 2, Some(100)); // fully idle host
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "3"]),
            "act-idle".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::Remote(o) => assert_eq!(o.exit_code, Some(3), "idle worker ran the action"),
        other => panic!("an idle worker must still run remotely, got {other:?}"),
    }
    assert!(
        served.load(Ordering::SeqCst) >= 1,
        "the idle worker actually served the action"
    );
}

#[tokio::test]
async fn dispatch_falls_back_to_local_with_no_workers() {
    let table = WorkerTable::new(Duration::from_secs(60)); // empty
    let sched = Scheduler::new(table);

    let exec = sched
        .dispatch(
            cmd(&["cmd", "/c", "exit", "2"]),
            "act-4".into(),
            "sess".into(),
            ExecOptions::default(),
        )
        .await;
    match exec {
        Execution::LocalFallback { exit_code, reason } => {
            assert_eq!(exit_code, 2);
            assert_eq!(reason.to_string(), "no live workers");
        }
        other => panic!("expected local fallback with no workers, got {other:?}"),
    }
}

#[tokio::test]
async fn dispatch_spreads_distinct_actions_across_workers() {
    // A burst of *distinct* actions (different argv = different TUs) must both
    // complete remotely AND actually land on more than one worker — affinity
    // hashes distinct TUs to different workers, and load spill covers the rest.
    // (Identical argv would correctly pin to one worker, so the TUs differ here.)
    let (w1, served1) = start_worker().await;
    let (w2, served2) = start_worker().await;
    let table = table_with(&[("w1", &w1, 2), ("w2", &w2, 2)]);
    let sched = Scheduler::new(table);

    let mut handles = Vec::new();
    for i in 0..16 {
        let s = sched.clone();
        handles.push(tokio::spawn(async move {
            // `cmd /c set SBZ_TU=tuN` varies argv per action and exits 0.
            s.dispatch(
                cmd(&["cmd", "/c", "set", &format!("SBZ_TU=tu{i}")]),
                format!("act-burst-{i}"),
                "sess".into(),
                ExecOptions::default(),
            )
            .await
        }));
    }
    for h in handles {
        match h.await.unwrap() {
            Execution::Remote(o) => assert_eq!(o.exit_code, Some(0)),
            other => panic!("expected all remote, got {other:?}"),
        }
    }

    let s1 = served1.load(Ordering::SeqCst);
    let s2 = served2.load(Ordering::SeqCst);
    assert_eq!(
        s1 + s2,
        16,
        "every action ran exactly once across the workers"
    );
    assert!(
        s1 > 0 && s2 > 0,
        "work must spread across both workers, got w1={s1} w2={s2}"
    );
}

#[tokio::test]
async fn run_build_fans_out_a_whole_phase_across_workers() {
    // M5.5 CI correctness gate (non-flaky: no timing threshold). A full "build
    // phase" of many distinct actions, run via run_build across W workers, must:
    // every action completes remotely, work spreads across all workers, and the
    // exact set of actions is accounted for. This is the integration the parallel-
    // efficiency harness measures; here we assert correctness, not speed.
    let workers = [
        start_worker().await,
        start_worker().await,
        start_worker().await,
    ];
    let table = table_with(&[
        ("w1", &workers[0].0, 2),
        ("w2", &workers[1].0, 2),
        ("w3", &workers[2].0, 2),
    ]);
    let sched = Scheduler::new(table);

    let n = 60;
    let actions: Vec<BuildAction> = (0..n)
        .map(|i| BuildAction {
            // Distinct argv per TU so affinity spreads them across the ring.
            command: cmd(&["cmd", "/c", "set", &format!("SBZ_TU=tu{i}")]),
            action_id: format!("tu{i}"),
            session_id: "build".into(),
        })
        .collect();

    let outcomes = sched.run_build(actions).await;

    assert_eq!(outcomes.len(), n, "every action produced an outcome");
    for (i, o) in outcomes.iter().enumerate() {
        match o {
            Execution::Remote(out) => assert_eq!(out.exit_code, Some(0), "action {i} ok"),
            other => panic!("action {i} did not run remotely: {other:?}"),
        }
    }

    let served: Vec<u64> = workers
        .iter()
        .map(|(_, s)| s.load(Ordering::SeqCst))
        .collect();
    assert_eq!(
        served.iter().sum::<u64>(),
        n as u64,
        "all actions accounted for across workers, got {served:?}"
    );
    assert!(
        served.iter().all(|&s| s > 0),
        "every worker got a share of the build, got {served:?}"
    );
}
