//! M5.5 parallel-efficiency harness (driver side). Hosts the Coordination
//! server, waits for the expected number of workers to register, then runs a
//! whole "build phase" of `n` CPU-bound `burn` actions via the scheduler and
//! prints the makespan. `hooks/test/m5_scale.ps1` runs this twice — with 1 and
//! with W core-pinned worker processes — and computes E(W) = T(1)/(W·T(W)).
//!
//! Usage:
//!   scale_harness <coord_addr> <expected_workers> <n_actions> <burn_exe> <iters>

use std::time::{Duration, Instant};

use sembazuru_agent::Execution;
use sembazuru_agent::coordination::{
    DEFAULT_DEAD_TIMEOUT, WorkerTable, serve_coordination_with_token,
};
use sembazuru_agent::scheduler::{BuildAction, Scheduler};
use sembazuru_proto::v0::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let coord_addr = args
        .first()
        .cloned()
        .unwrap_or_else(|| "127.0.0.1:50070".into());
    let expected: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(1);
    let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(64);
    let burn = args
        .get(3)
        .cloned()
        .ok_or("usage: scale_harness <addr> <workers> <n> <burn_exe> <iters>")?;
    let iters = args.get(4).cloned().unwrap_or_else(|| "20000000".into());
    let coord_addr = coord_addr.parse::<std::net::SocketAddr>()?;
    let token = sembazuru_proto::auth::cluster_token_from_env();
    if !coord_addr.ip().is_loopback() && token.is_none() {
        return Err("SEMBAZURU_CLUSTER_TOKEN is required for non-loopback coordination".into());
    }

    let table = WorkerTable::new(DEFAULT_DEAD_TIMEOUT);
    let listener = tokio::net::TcpListener::bind(coord_addr).await?;
    eprintln!("scale_harness: Coordination on {}", listener.local_addr()?);
    {
        let t = table.clone();
        let coordination_token = token.clone();
        tokio::spawn(async move {
            let _ = serve_coordination_with_token(listener, t, coordination_token).await;
        });
    }

    // Wait for the workers to register before timing anything.
    let deadline = Instant::now() + Duration::from_secs(30);
    while table.live_count() < expected {
        if Instant::now() >= deadline {
            return Err(format!(
                "only {} of {expected} workers registered within 30s",
                table.live_count()
            )
            .into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!(
        "scale_harness: {} workers live; dispatching {n} actions",
        expected
    );

    let actions: Vec<BuildAction> = (0..n)
        .map(|i| BuildAction {
            command: Command {
                argv: vec![burn.clone(), iters.clone()],
                env: Default::default(),
                cwd: String::new(),
            },
            action_id: format!("burn-{i}"),
            session_id: "scale".into(),
        })
        .collect();

    let start = Instant::now();
    let outcomes = Scheduler::with_cluster_token(table, token)
        .run_build(actions)
        .await;
    let makespan = start.elapsed();

    let remote = outcomes
        .iter()
        .filter(|o| matches!(o, Execution::Remote(_)))
        .count();
    let local = outcomes.len() - remote;
    let ok = n > 0
        && expected > 0
        && outcomes.len() == n
        && local == 0
        && outcomes.iter().all(|o| match o {
            Execution::Remote(r) => r.exit_code == Some(0),
            Execution::LocalFallback { .. } => false,
        });

    // Machine-readable result line for the ps1 to parse.
    println!(
        "SCALE workers={expected} actions={n} makespan_ms={} remote={remote} local={local} ok={ok}",
        makespan.as_millis()
    );
    if !ok {
        return Err("some actions did not exit 0".into());
    }
    Ok(())
}
