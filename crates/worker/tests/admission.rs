//! M5.2 worker admission test: the `Execution` service bounds concurrent actions
//! to its capacity with an admission semaphore (a single un-virtualized worker
//! must not fork-bomb under a flood of `Execute`s — the DoS fix). Driven through
//! the real agent client (a dev-dependency) over loopback gRPC.
//!
//! The assertion is an *upper bound* on the in-flight gauge, which is robust to
//! timing: under a burst of slow actions the count must reach capacity (proving
//! admission lets work through) but never exceed it (proving the bound holds).

use std::sync::atomic::Ordering;
use std::time::Duration;

use sembazuru_agent::ExecuteError;
use sembazuru_proto::v0::Command;
use sembazuru_worker::WorkerService;
use tokio::task::JoinSet;

fn slow_cmd() -> Command {
    // `ping -n 4 127.0.0.1` waits ~3 s without needing a console or extra tools.
    Command {
        argv: ["cmd", "/c", "ping", "-n", "4", "127.0.0.1"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        env: Default::default(),
        cwd: String::new(),
    }
}

#[tokio::test]
async fn admission_caps_concurrent_actions_at_capacity() {
    const CAP: u32 = 2;
    let service = WorkerService::with_capacity(CAP);
    let running = service.running_handle();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });

    // Fire a burst of 4 slow actions at a capacity-2 worker.
    for i in 0..4 {
        let ep = endpoint.clone();
        tokio::spawn(async move {
            let _ = sembazuru_agent::execute_remote(
                ep,
                slow_cmd(),
                format!("admit-{i}"),
                "sess".into(),
            )
            .await;
        });
    }

    // Sample the in-flight gauge while the actions run; it must reach CAP and
    // never exceed it.
    let mut max_seen = 0u32;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = running.load(Ordering::SeqCst);
        max_seen = max_seen.max(now);
        assert!(
            now <= CAP,
            "in-flight actions {now} exceeded capacity {CAP} — admission semaphore breached"
        );
    }
    assert_eq!(
        max_seen, CAP,
        "the burst should have saturated the worker to its capacity"
    );
}

#[tokio::test]
async fn flood_past_backlog_is_rejected_with_resource_exhausted() {
    // capacity 1 → accepted backlog cap = QUEUE_FACTOR(8) × 1 = 8. A flood of 12
    // concurrent slow actions must see at least the overflow rejected with
    // RESOURCE_EXHAUSTED rather than pinning unbounded queued tasks (DoS: H1).
    let service = WorkerService::with_capacity(1);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });

    // JoinSet aborts the still-running (accepted, slow) actions on drop, so the
    // test does not wait for 8 serial 3 s pings — and dropping their streams
    // kills the worker children (kill_on_drop), leaving no orphans.
    let mut set = JoinSet::new();
    for i in 0..12 {
        let ep = endpoint.clone();
        set.spawn(async move {
            sembazuru_agent::execute_remote(ep, slow_cmd(), format!("flood-{i}"), "sess".into())
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
