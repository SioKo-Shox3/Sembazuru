use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sembazuru_agent::action_tracker::{
    ActionTracker, ActivityState, ExecutionKind, TrackerClock, display_name,
};
use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::fileserver::ServerStats;
use sembazuru_agent::status::{Metrics, StatusState, serve_status_service};
use sembazuru_proto::v0::{
    ActivityExecutionKind, ActivityState as ProtoActivityState, Command, GetStatusRequest,
    status_client::StatusClient,
};

struct ManualClock(Mutex<Instant>);

impl ManualClock {
    fn new(now: Instant) -> Self {
        Self(Mutex::new(now))
    }

    fn advance(&self, duration: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += duration;
    }
}

impl TrackerClock for ManualClock {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}

async fn start_status_with_tracker() -> (String, ActionTracker, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(Instant::now()));
    let tracker = ActionTracker::with_clock(clock.clone());
    let state = StatusState {
        table: WorkerTable::new(Duration::from_secs(60)),
        server_stats: Arc::new(ServerStats::default()),
        cache: None,
        cache_max_bytes: None,
        metrics: Arc::new(Metrics::default()),
        tracker: tracker.clone(),
        auth_enabled: false,
        config_path: std::env::temp_dir().join("sbz-status-activity-unused.toml"),
        admin_enabled: false,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_status_service(listener, state).await.unwrap();
    });
    (format!("http://{addr}"), tracker, clock)
}

async fn get_status(endpoint: &str) -> sembazuru_proto::v0::GetStatusResponse {
    let mut client = StatusClient::connect(endpoint.to_owned()).await.unwrap();
    client
        .get_status(GetStatusRequest {})
        .await
        .unwrap()
        .into_inner()
}

#[tokio::test]
async fn status_exposes_active_then_recent_activity_without_command_material() {
    let (endpoint, tracker, clock) = start_status_with_tracker().await;
    let command = Command {
        argv: vec![
            "clang-cl.exe".into(),
            "/c".into(),
            "C:\\secret\\src\\main.cpp".into(),
            "@C:\\secret\\args.rsp".into(),
        ],
        env: [("TOKEN".into(), "secret-value".into())]
            .into_iter()
            .collect(),
        cwd: "C:\\secret".into(),
    };
    let raw_action_id = "C:\\secret\\action-id.cpp";
    let key = tracker
        .begin_attempt(
            raw_action_id,
            0,
            "w1",
            ExecutionKind::Remote,
            &display_name(&command),
        )
        .unwrap();
    tracker.transition(&key, ActivityState::Running);

    let active = get_status(&endpoint).await;
    assert_eq!(active.activities.len(), 1);
    assert_eq!(active.activities[0].display_name, "main.cpp");
    assert_ne!(active.activities[0].activity_id, raw_action_id);
    assert_eq!(active.activities[0].activity_id.len(), 16);
    assert_eq!(
        active.activities[0].execution_kind,
        ActivityExecutionKind::Remote as i32
    );
    assert_eq!(
        active.activities[0].state,
        ProtoActivityState::Running as i32
    );
    assert_eq!(active.activities[0].started_age_ms, 0);
    let response = format!("{active:?}");
    for secret in [
        "C:\\secret",
        "action-id.cpp",
        "args.rsp",
        "TOKEN",
        "secret-value",
    ] {
        assert!(!response.contains(secret), "status leaked {secret}");
    }

    clock.advance(Duration::from_secs(2));
    tracker.finish(&key, ActivityState::Completed);
    let recent = get_status(&endpoint).await;
    assert_eq!(recent.activities.len(), 1);
    assert_eq!(
        recent.activities[0].state,
        ProtoActivityState::Completed as i32
    );
    assert_eq!(recent.activities[0].started_age_ms, 2_000);
    assert_eq!(recent.activities[0].finished_age_ms, Some(0));
    assert_eq!(recent.activities[0].duration_us, 2_000_000);

    clock.advance(Duration::from_secs(61));
    assert!(get_status(&endpoint).await.activities.is_empty());
}

#[tokio::test]
async fn status_keeps_retry_and_fallback_attempts_distinct() {
    let (endpoint, tracker, _) = start_status_with_tracker().await;
    let remote = tracker
        .begin_attempt("compile", 0, "w1", ExecutionKind::Remote, "main.cpp")
        .unwrap();
    tracker.finish(&remote, ActivityState::Interrupted);
    let fallback = tracker
        .begin_attempt("compile", 1, "local", ExecutionKind::Fallback, "main.cpp")
        .unwrap();
    tracker.transition(&fallback, ActivityState::Running);
    tracker.finish(&fallback, ActivityState::Completed);

    let status = get_status(&endpoint).await;
    assert_eq!(status.activities.len(), 2);
    assert_eq!(status.activities[0].attempt_no, 0);
    assert_eq!(status.activities[1].attempt_no, 1);
    assert_eq!(
        status.activities[0].execution_kind,
        ActivityExecutionKind::Remote as i32
    );
    assert_eq!(
        status.activities[1].execution_kind,
        ActivityExecutionKind::Fallback as i32
    );
    assert_eq!(
        status.activities[0].state,
        ProtoActivityState::Interrupted as i32
    );
    assert_eq!(
        status.activities[1].state,
        ProtoActivityState::Completed as i32
    );
    assert_ne!(
        status.activities[0].activity_id,
        status.activities[1].activity_id
    );
}
