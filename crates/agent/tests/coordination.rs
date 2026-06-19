//! M5.1 Coordination end-to-end test: the agent hosts the `Coordination` server
//! and real worker clients (`sembazuru_worker::coordination::register_and_heartbeat`)
//! register and heartbeat over gRPC, exactly as the worker daemon does. This is
//! the automated evidence for M5.1 — registration populates the worker table
//! with live capacity, and a worker that stops heartbeating ages out within the
//! dead-detection window (ADR 0004).
//!
//! Like `loopback.rs`, "workers" here are in-process client tasks rather than
//! spawned processes; they exercise the same client/server code paths. A short
//! `dead_timeout` keeps the death test fast instead of the production 15 s.
//!
//! Scope of the death tests (honest limits): "death" here is a graceful drain —
//! the worker ends its ping stream, so the agent handler exits via stream-end
//! (`Ok(None)`) and stops refreshing `last_ping`. An abrupt transport error
//! (process kill, socket RST) takes the *same* handler exit (`while let
//! Ok(Some(..))` treats `Err` and `Ok(None)` identically) and then the *same*
//! age-out timer fires — that logic is what these tests cover. What they do NOT
//! cover is the transport-error trigger itself: tonic drives the client's
//! outbound stream from its connection task, so aborting an in-process worker
//! task does not close the socket. True process-death is only reachable via the
//! real daemon; tracked in `docs/deferred.md` (M5 in-process test limits).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::Duration;

use sembazuru_agent::coordination::{
    WorkerTable, serve_coordination, serve_coordination_with_token,
};
use sembazuru_worker::coordination::register_and_heartbeat;

/// Starts the agent Coordination server on an ephemeral loopback port and
/// returns its `http://` endpoint plus the shared table. Auth disabled.
async fn start_agent(dead_timeout: Duration) -> (String, WorkerTable) {
    let table = WorkerTable::new(dead_timeout);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let t = table.clone();
    tokio::spawn(async move {
        serve_coordination(listener, t).await.unwrap();
    });
    (format!("http://{addr}"), table)
}

/// Like [`start_agent`] but the server requires `token` on `Register` (ADR
/// 0006). Used to exercise the accept/reject paths deterministically without
/// touching the process-global `SEMBAZURU_CLUSTER_TOKEN`.
async fn start_agent_with_token(dead_timeout: Duration, token: &str) -> (String, WorkerTable) {
    let table = WorkerTable::new(dead_timeout);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let t = table.clone();
    let token = token.to_string();
    tokio::spawn(async move {
        serve_coordination_with_token(listener, t, Some(token))
            .await
            .unwrap();
    });
    (format!("http://{addr}"), table)
}

/// Spawns a worker client that registers as `worker_id` and heartbeats on
/// `interval`, reporting `running` in-flight actions, presenting `token` for
/// auth (empty = no token). Returns a `stop` flag; setting it ends the ping
/// stream (graceful drain) — the in-process stand-in for worker death. See the
/// module docs for what this does and does not cover.
fn spawn_worker(
    agent: &str,
    worker_id: &str,
    running: u32,
    interval: Duration,
    token: &str,
) -> Arc<AtomicBool> {
    let agent = agent.to_string();
    let worker_id = worker_id.to_string();
    let token = token.to_string();
    let counter = Arc::new(AtomicU32::new(running));
    let stop = Arc::new(AtomicBool::new(false));
    let stop_ret = Arc::clone(&stop);
    tokio::spawn(async move {
        let _ = register_and_heartbeat(
            agent,
            worker_id,
            "http://127.0.0.1:50061".to_string(),
            4, // advertised capacity (cpu_count)
            counter,
            interval,
            stop,
            token,
            sembazuru_worker::config::ParticipationSettings::always(),
        )
        .await;
    });
    stop_ret
}

/// Polls `cond` until it returns true or `deadline` elapses; returns the result.
async fn wait_until<F: Fn() -> bool>(cond: F, deadline: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    cond()
}

#[tokio::test]
async fn register_and_heartbeat_makes_worker_live_with_capacity() {
    let (agent, table) = start_agent(Duration::from_secs(5)).await;
    let _stop = spawn_worker(&agent, "worker-a", 1, Duration::from_millis(100), "");

    assert!(
        wait_until(|| table.is_live("worker-a"), Duration::from_secs(3)).await,
        "worker should be live after registering + heartbeating"
    );

    // The heartbeat pushed real capacity: running_actions and idle_slots derived
    // from the worker's own cpu_count.
    let snap = table.live_snapshot();
    let e = snap
        .iter()
        .find(|e| e.worker_id == "worker-a")
        .expect("worker-a in live snapshot");
    assert_eq!(
        e.running_actions, 1,
        "running_actions reported over heartbeat"
    );
    assert_eq!(
        e.idle_slots,
        e.caps.cpu_count.saturating_sub(1),
        "idle_slots = cpu_count - running_actions"
    );
}

#[tokio::test]
async fn worker_ages_out_after_dead_timeout() {
    // 1 s dead window so the test is fast (production is 15 s, ADR 0004).
    let (agent, table) = start_agent(Duration::from_secs(1)).await;
    let stop = spawn_worker(&agent, "worker-b", 0, Duration::from_millis(100), "");

    assert!(
        wait_until(|| table.is_live("worker-b"), Duration::from_secs(3)).await,
        "worker should first come live"
    );

    // Simulate worker death: stop heartbeating. The entry must age out within
    // the dead window and disappear from the schedulable set.
    stop.store(true, Ordering::SeqCst);
    assert!(
        wait_until(|| !table.is_live("worker-b"), Duration::from_secs(3)).await,
        "worker should be marked dead after the timeout with no heartbeats"
    );
    assert_eq!(table.live_count(), 0, "no live workers remain");
}

#[tokio::test]
async fn one_worker_death_leaves_the_other_live() {
    let (agent, table) = start_agent(Duration::from_secs(1)).await;
    let stop1 = spawn_worker(&agent, "w1", 0, Duration::from_millis(100), "");
    let _stop2 = spawn_worker(&agent, "w2", 0, Duration::from_millis(100), "");

    assert!(
        wait_until(|| table.live_count() == 2, Duration::from_secs(3)).await,
        "both workers should register and go live"
    );

    // Kill one; the other keeps heartbeating and stays schedulable.
    stop1.store(true, Ordering::SeqCst);
    assert!(
        wait_until(
            || table.live_count() == 1 && table.is_live("w2"),
            Duration::from_secs(3)
        )
        .await,
        "the surviving worker stays live while the dead one ages out"
    );
    assert!(!table.is_live("w1"), "the killed worker is no longer live");
}

// ---- M7.0 shared-token auth (ADR 0006) -----------------------------------

#[tokio::test]
async fn right_token_registers_wrong_token_is_rejected() {
    // Agent requires the cluster token. The good worker presents it and becomes
    // schedulable; the bad worker presents the wrong one and never appears in
    // the table — the unauthenticated-Register injection path is closed.
    let (agent, table) = start_agent_with_token(Duration::from_secs(5), "s3cret").await;
    let _good = spawn_worker(&agent, "good", 0, Duration::from_millis(100), "s3cret");
    let _bad = spawn_worker(&agent, "bad", 0, Duration::from_millis(100), "nope");

    assert!(
        wait_until(|| table.is_live("good"), Duration::from_secs(3)).await,
        "worker with the correct token should register and go live"
    );
    // Give the rejected worker ample time to (fail to) appear.
    assert!(
        !wait_until(|| table.is_live("bad"), Duration::from_secs(1)).await,
        "worker with the wrong token must never become schedulable"
    );
    assert!(table.is_live("good") && !table.is_live("bad"));
}

#[tokio::test]
async fn rejected_registration_surfaces_a_safe_reason() {
    // The worker client turns a rejected Register into an Err carrying the
    // agent's reason. The reason is a fixed safe string (no secret, no path).
    let (agent, _table) = start_agent_with_token(Duration::from_secs(5), "s3cret").await;
    let err = register_and_heartbeat(
        agent,
        "bad".to_string(),
        "http://127.0.0.1:50061".to_string(),
        4,
        Arc::new(AtomicU32::new(0)),
        Duration::from_millis(100),
        Arc::new(AtomicBool::new(false)),
        "wrong".to_string(),
        sembazuru_worker::config::ParticipationSettings::always(),
    )
    .await
    .expect_err("registration with the wrong token must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("invalid cluster auth token"),
        "reason should be the safe rejection string, got: {msg}"
    );
}

#[tokio::test]
async fn missing_token_against_authed_agent_is_rejected() {
    // A pre-M7 worker (or one with no token configured) presents an empty token;
    // an agent that requires auth rejects it rather than silently accepting.
    let (agent, table) = start_agent_with_token(Duration::from_secs(5), "s3cret").await;
    let _none = spawn_worker(&agent, "tokenless", 0, Duration::from_millis(100), "");
    assert!(
        !wait_until(|| table.is_live("tokenless"), Duration::from_secs(1)).await,
        "a worker presenting no token must be rejected by an authed agent"
    );
}
