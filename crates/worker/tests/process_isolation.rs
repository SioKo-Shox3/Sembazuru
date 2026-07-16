use sembazuru_proto::v0::{ActionState, Command};
use sembazuru_worker::WorkerService;

async fn service(service: WorkerService) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });
    endpoint
}

#[tokio::test]
async fn restricted_process_plain_streams_large_output_from_private_scratch() {
    let root = std::env::temp_dir().join(format!("sbz-process-stream-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let endpoint = service(WorkerService::with_capacity(1).with_scratch_root(root.clone())).await;
    let line = "O".repeat(80);
    let err_line = "E".repeat(80);
    let command = Command {
        argv: vec![
            "cmd.exe".into(),
            "/d".into(),
            "/q".into(),
            "/c".into(),
            format!(
                "echo CWD=%CD%& echo TEMP=%TEMP%& (for /L %i in (1,1,2000) do @echo {line})& (for /L %i in (1,1,2000) do @echo {err_line} 1>&2)"
            ),
        ],
        env: Default::default(),
        cwd: String::new(),
    };
    let outcome =
        sembazuru_agent::execute_remote(endpoint, command, "large-output".into(), "session".into())
            .await
            .unwrap();
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(stdout.matches('O').count() >= 140_000);
    assert!(
        String::from_utf8_lossy(&outcome.stderr)
            .matches('E')
            .count()
            >= 140_000
    );
    let root_text = root.to_string_lossy().to_ascii_lowercase();
    assert!(
        stdout
            .to_ascii_lowercase()
            .contains(&format!("cwd={root_text}"))
    );
    assert!(
        stdout
            .to_ascii_lowercase()
            .contains(&format!("temp={root_text}"))
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    std::fs::remove_dir(root).unwrap();
}

#[tokio::test]
async fn restricted_process_setup_failure_does_not_retry_or_leak_scratch() {
    let root = std::env::temp_dir().join(format!("sbz-process-failure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let endpoint = service(WorkerService::with_capacity(1).with_scratch_root(root.clone())).await;
    let command = Command {
        argv: vec![root.join("missing.exe").display().to_string()],
        env: Default::default(),
        cwd: String::new(),
    };
    let outcome = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        sembazuru_agent::execute_remote(
            endpoint,
            command,
            "setup-failure".into(),
            "session".into(),
        ),
    )
    .await
    .expect("a setup failure must not trigger an ambient-path retry")
    .unwrap();
    assert_eq!(outcome.exit_code, None);
    assert_eq!(
        outcome.states.last().copied(),
        Some(ActionState::Failed as i32)
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    std::fs::remove_dir(root).unwrap();
}
