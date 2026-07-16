//! SEC-002 (Part 2): the plain-spawn path must not leak the worker's own secrets
//! into an agent-supplied command. The worker service process holds
//! SEMBAZURU_CLUSTER_TOKEN (its auth secret) and other SEMBAZURU_* internals in
//! its environment; a plain-spawned child inherits the worker env (it needs OS
//! basics like SystemRoot), and the child's stdout is streamed back to the
//! requesting agent. Without stripping, an `Execute` of `cmd /c set` would
//! exfiltrate the cluster token. This drives a real plain action end-to-end and
//! asserts the secret never reaches the child — while OS-essential env survives.
//!
//! This test mutates process-global environment, so it lives in its own test
//! binary (one test → no intra-binary thread races on the env).

use sembazuru_proto::v0::Command;
use sembazuru_worker::WorkerService;

#[tokio::test]
async fn plain_child_does_not_inherit_worker_secrets() {
    const SECRET: &str = "super-secret-cluster-token-DO-NOT-LEAK-42";
    const AMBIENT_SECRET: &str = "ambient-aws-secret-DO-NOT-LEAK-17";
    // Simulate the worker service environment holding its auth secret plus an
    // internal var. `build_child` reads the process env at spawn time.
    // SAFETY: this is the only test in this binary, so no other thread races on
    // the environment while we set/read/remove it.
    unsafe {
        std::env::set_var("SEMBAZURU_CLUSTER_TOKEN", SECRET);
        std::env::set_var("SEMBAZURU_AGENT", "http://10.0.0.1:50051");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", AMBIENT_SECRET);
    }

    let scratch_root =
        std::env::temp_dir().join(format!("sbz-env-isolation-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch_root);
    std::fs::create_dir(&scratch_root).unwrap();
    let service = WorkerService::with_capacity(2).with_scratch_root(scratch_root.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        sembazuru_worker::serve_on_listener_with(listener, service)
            .await
            .unwrap();
    });

    // `cmd /c set` dumps the child's entire environment to stdout, which the
    // worker streams back to us. Empty action env → the child runs with the
    // (secret-stripped) inherited worker env only.
    let cmd = Command {
        argv: ["cmd", "/c", "set"].iter().map(|s| s.to_string()).collect(),
        env: [("CALLER_EXPLICIT".to_string(), "preserved".to_string())]
            .into_iter()
            .collect(),
        cwd: String::new(),
    };
    let outcome =
        sembazuru_agent::execute_remote(endpoint, cmd, "leak-probe".into(), "sess".into())
            .await
            .expect("plain execute should run");

    let dumped = String::from_utf8_lossy(&outcome.stdout).into_owned();
    // Clean up the process env before asserting, so a failure cannot poison an
    // unrelated later run in the same process.
    unsafe {
        std::env::remove_var("SEMBAZURU_CLUSTER_TOKEN");
        std::env::remove_var("SEMBAZURU_AGENT");
        std::env::remove_var("AWS_SECRET_ACCESS_KEY");
    }

    assert!(
        !dumped.contains(SECRET),
        "the cluster token leaked into a plain child's environment (SEC-002):\n{dumped}"
    );
    assert!(
        !dumped.to_ascii_uppercase().contains("SEMBAZURU_"),
        "no SEMBAZURU_* internal var may reach a plain child (SEC-002):\n{dumped}"
    );
    assert!(
        !dumped.contains(AMBIENT_SECRET),
        "ambient secret leaked:\n{dumped}"
    );
    assert!(dumped.contains("CALLER_EXPLICIT=preserved"), "{dumped}");
    for name in ["TEMP", "TMP"] {
        let value = dumped
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .expect("authoritative private temp variable");
        assert!(
            value
                .to_ascii_lowercase()
                .starts_with(&scratch_root.to_string_lossy().to_ascii_lowercase()),
            "{name} escaped private scratch: {value}"
        );
    }
    // Sanity: the child still ran with a real environment (SystemRoot present),
    // proving we stripped only secrets, not the OS env the command needs — a full
    // env_clear here would break bare commands like this one.
    assert!(
        dumped.to_ascii_uppercase().contains("SYSTEMROOT="),
        "the plain child must still inherit OS-essential env (SystemRoot):\n{dumped}"
    );
    assert_eq!(std::fs::read_dir(&scratch_root).unwrap().count(), 0);
    std::fs::remove_dir(scratch_root).unwrap();
}
