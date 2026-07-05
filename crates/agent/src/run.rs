//! The daemon's runnable core (M9.3b). The setup that used to live in
//! `bin/sembazuru_daemon.rs` is here as [`run_daemon`] so it can be driven from
//! two entry points — the plain CLI (Ctrl-C → shutdown) and the Windows Service
//! wrapper (SCM Stop → shutdown) — and exercised by tests without an SCM.
//!
//! Shutdown is a [`CancellationToken`]: Coordination, file supply, Status, and
//! LocalIntake run as supervised server tasks. Cancelling the token is a clean
//! stop. Any supervised server task that returns `Err`, panics, or exits
//! unexpectedly with `Ok(())` before shutdown makes the daemon return an error
//! naming that server role. In-flight remote actions that get cut off are still
//! correct — the agent's local fallback completes the build (DESIGN §2) — so an
//! abrupt stop never breaks a build; a fuller per-server drain is a refinement
//! (M7.4 deferred note).

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::task::{Id, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::action_cache::AgentCache;
use crate::config::DaemonConfig;
use crate::coordination::{DEFAULT_DEAD_TIMEOUT, WorkerTable, serve_coordination_with_token};
use crate::fileserver::{ServerStats, serve_files_with_stats_token};
use crate::intake::{IntakeService, IntakeVfsContext, LocalIntakeTransport, require_loopback};
use crate::scheduler::Scheduler;
use crate::session_registry::SessionRegistry;
use crate::status::{StatusState, evict_cache_to_cap, serve_status_service};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ServerFuture = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ServerRole {
    Coordination,
    FileServer,
    Status,
    LocalIntake,
}

impl ServerRole {
    #[cfg(test)]
    const ALL: [Self; 4] = [
        Self::Coordination,
        Self::FileServer,
        Self::Status,
        Self::LocalIntake,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Coordination => "Coordination",
            Self::FileServer => "file server",
            Self::Status => "Status",
            Self::LocalIntake => "LocalIntake",
        }
    }
}

struct RequiredServerTasks {
    coordination: ServerFuture,
    file_server: ServerFuture,
    status: ServerFuture,
    local_intake: ServerFuture,
}

impl RequiredServerTasks {
    fn new(
        coordination: ServerFuture,
        file_server: ServerFuture,
        status: ServerFuture,
        local_intake: ServerFuture,
    ) -> Self {
        Self {
            coordination,
            file_server,
            status,
            local_intake,
        }
    }
}

struct SupervisedServers {
    tasks: JoinSet<Result<(), BoxError>>,
    roles: HashMap<Id, ServerRole>,
}

impl SupervisedServers {
    fn spawn(tasks: RequiredServerTasks) -> Self {
        let mut supervised = Self {
            tasks: JoinSet::new(),
            roles: HashMap::new(),
        };
        supervised.spawn_one(ServerRole::Coordination, tasks.coordination);
        supervised.spawn_one(ServerRole::FileServer, tasks.file_server);
        supervised.spawn_one(ServerRole::Status, tasks.status);
        supervised.spawn_one(ServerRole::LocalIntake, tasks.local_intake);
        supervised
    }

    fn spawn_one(&mut self, role: ServerRole, task: ServerFuture) {
        let handle = self.tasks.spawn(task);
        self.roles.insert(handle.id(), role);
    }

    fn abort_all(&mut self) {
        self.tasks.abort_all();
    }

    async fn next_exit(&mut self) -> Result<(), BoxError> {
        match self.tasks.join_next_with_id().await {
            Some(exit) => self.classify_exit(exit),
            None => Err("daemon has no supervised server tasks".into()),
        }
    }

    fn try_next_exit(&mut self) -> Option<Result<(), BoxError>> {
        self.tasks
            .try_join_next_with_id()
            .map(|exit| self.classify_exit(exit))
    }

    fn classify_exit(
        &mut self,
        exit: Result<(Id, Result<(), BoxError>), tokio::task::JoinError>,
    ) -> Result<(), BoxError> {
        match exit {
            Ok((id, Ok(()))) => {
                let role = self.role_label_for(id);
                Err(format!("{role} task unexpectedly exited successfully").into())
            }
            Ok((id, Err(e))) => {
                let role = self.role_label_for(id);
                Err(format!("{role} task exited with error: {e}").into())
            }
            Err(e) => {
                let role = self.role_label_for(e.id());
                if e.is_panic() {
                    Err(format!("{role} task panicked: {e}").into())
                } else if e.is_cancelled() {
                    Err(format!("{role} server task was cancelled before shutdown").into())
                } else {
                    Err(format!("{role} server task failed to join: {e}").into())
                }
            }
        }
    }

    fn role_label_for(&mut self, id: Id) -> String {
        self.roles
            .remove(&id)
            .map(|role| role.label().to_owned())
            .unwrap_or_else(|| format!("unknown task {id:?}"))
    }

    #[cfg(test)]
    fn registered_roles(&self) -> Vec<ServerRole> {
        self.roles.values().copied().collect()
    }
}

async fn supervise_server_tasks_until_shutdown(
    tasks: RequiredServerTasks,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    let mut servers = SupervisedServers::spawn(tasks);
    tokio::select! {
        biased;
        result = servers.next_exit() => {
            servers.abort_all();
            result
        }
        _ = shutdown.cancelled() => {
            tokio::task::yield_now().await;
            if let Some(result) = servers.try_next_exit() {
                servers.abort_all();
                return result;
            }
            eprintln!("sembazuru-daemon: shutdown requested; stopping");
            servers.abort_all();
            Ok(())
        }
    }
}

/// Refuses unauthenticated LAN-reachable Coordination/file-server binds by
/// default. Loopback, or auth enabled, is fine. The unsafe override exists only
/// for explicit transitional/test deployments and must never be used in
/// production.
fn refuse_unauthenticated_lan(
    role: &str,
    addr: std::net::SocketAddr,
    auth_enabled: bool,
    unsafe_allow_unauthenticated_lan: bool,
) -> Result<(), BoxError> {
    if auth_enabled || addr.ip().is_loopback() {
        return Ok(());
    }
    if unsafe_allow_unauthenticated_lan {
        eprintln!(
            "sembazuru-daemon: WARNING: {role} listens on {addr}; unauthenticated LAN bind \
             allowed by unsafe override; never in production."
        );
        return Ok(());
    }

    let risk = if role == "Coordination" {
        "register a rogue worker"
    } else {
        "read agent files"
    };
    Err(format!(
        "refusing to bind {role} to non-loopback address {addr} with worker auth DISABLED: any \
         host on this network could {risk}. Set a cluster token (config cluster_token or \
         SEMBAZURU_CLUSTER_TOKEN) on the daemon and every worker, or set \
         SEMBAZURU_UNSAFE_ALLOW_UNAUTHENTICATED_LAN=1 \
         (unsafe_allow_unauthenticated_lan=true) to override - never in production."
    )
    .into())
}

/// Runs the daemon — Coordination + file supply + Scheduler + LocalIntake + the
/// loopback Status surface — until `shutdown` is cancelled or the LocalIntake
/// server exits. `config` is the already-resolved effective config (file + env).
pub async fn run_daemon(config: DaemonConfig, shutdown: CancellationToken) -> Result<(), BoxError> {
    let cluster_token = config.cluster_token.clone();
    eprintln!(
        "sembazuru-daemon: worker auth {}",
        if cluster_token.is_some() {
            "ENABLED (shared token)"
        } else {
            "disabled (LAN-trusted)"
        }
    );

    let table = WorkerTable::new(DEFAULT_DEAD_TIMEOUT);
    let scheduler = Scheduler::with_cluster_token(table.clone(), cluster_token.clone());

    // The data-plane session registry (ADR 0013): one shared instance threaded
    // into BOTH the file server (which binds a worker's Hello session id to the
    // agent's authoritative capability) and intake (which creates a session right
    // before dispatch and finishes it after). This is the object the two planes
    // used to lack — the seam that makes the agent, not the worker, the authority.
    let registry = Arc::new(SessionRegistry::new()?);

    // Coordination: workers register + heartbeat in. Spawned; the table it fills
    // is shared with the scheduler.
    let coord_listener = tokio::net::TcpListener::bind(&config.coord_addr).await?;
    eprintln!(
        "sembazuru-daemon: Coordination on {}",
        coord_listener.local_addr()?
    );
    refuse_unauthenticated_lan(
        "Coordination",
        coord_listener.local_addr()?,
        cluster_token.is_some(),
        config.unsafe_allow_unauthenticated_lan,
    )?;
    let coordination_task = {
        let t = table.clone();
        let tok = cluster_token.clone();
        Box::pin(async move { serve_coordination_with_token(coord_listener, t, tok).await })
            as ServerFuture
    };

    // File supply: workers pull inputs on demand over the data plane. The bound
    // address is what VFS-mode workers dial, so capture it for VfsExecution. Stats
    // are shared with the Status surface (M9.1).
    let file_listener = tokio::net::TcpListener::bind(&config.fileserver_addr).await?;
    let fileserver_addr = file_listener.local_addr()?;
    eprintln!("sembazuru-daemon: file server on {fileserver_addr}");
    refuse_unauthenticated_lan(
        "file server",
        fileserver_addr,
        cluster_token.is_some(),
        config.unsafe_allow_unauthenticated_lan,
    )?;
    if config.unsafe_legacy_dataplane_sessions {
        eprintln!(
            "sembazuru-daemon: WARNING: UNSAFE legacy empty-session data-plane fallback is \
             ENABLED; it reopens the pre-ADR-0013 unscoped/any-path, worker-declared-root \
             capability for empty session ids. NEVER use this in production."
        );
    }
    let server_stats = Arc::new(ServerStats::default());
    let file_server_task = {
        let stats = server_stats.clone();
        let tok = cluster_token.clone();
        let reg = registry.clone();
        let legacy_sessions_enabled = config.unsafe_legacy_dataplane_sessions;
        Box::pin(async move {
            // Empty/unknown session ids are rejected by default (ADD-002); the
            // legacy empty-session compatibility path is wired from config and
            // defaults off.
            serve_files_with_stats_token(file_listener, stats, tok, reg, legacy_sessions_enabled)
                .await?;
            Ok(())
        }) as ServerFuture
    };

    // Action cache (M4): opt-in via config.cache_root. Per-action trace dirs go
    // under trace_root.
    let cache = match &config.cache_root {
        Some(root) => match AgentCache::open(root) {
            Ok(c) => {
                eprintln!("sembazuru-daemon: action cache at {root}");
                Some(Arc::new(c))
            }
            Err(e) => {
                eprintln!("sembazuru-daemon: action cache disabled (open failed: {e})");
                None
            }
        },
        None => None,
    };
    let cache_max_bytes = config.cache_max_bytes;
    if let Some(max) = cache_max_bytes {
        eprintln!("sembazuru-daemon: action cache size cap {max} bytes");
    }
    let trace_root = config.trace_root.clone().unwrap_or_else(|| {
        std::env::temp_dir()
            .join("sembazuru-trace")
            .to_string_lossy()
            .into_owned()
    });

    let intake = IntakeService::with_vfs(
        scheduler,
        IntakeVfsContext {
            agent_fileserver: fileserver_addr.to_string(),
            cache: cache.clone(),
            scratch_root: std::path::PathBuf::from(trace_root),
            registry: registry.clone(),
        },
    );

    // Status surface (M9.1, ADR 0008 §4): loopback-only read-only plane for the
    // GUI; refuses any non-loopback bind.
    let status_sockaddr = require_loopback(&config.status_addr, "Status")?;
    let status_listener = tokio::net::TcpListener::bind(status_sockaddr).await?;
    eprintln!(
        "sembazuru-daemon: Status on {}",
        status_listener.local_addr()?
    );
    let status_task = {
        let state = StatusState {
            table: table.clone(),
            server_stats: server_stats.clone(),
            cache: cache.clone(),
            cache_max_bytes,
            metrics: intake.metrics(),
            auth_enabled: cluster_token.is_some(),
            config_path: DaemonConfig::path_from_env(),
            // SEC-001 interim (ADR 0016): the mutating Status RPCs are opt-in
            // (default off) because the loopback Status plane has no caller auth.
            admin_enabled: config.status_admin,
        };
        Box::pin(async move { serve_status_service(status_listener, state).await }) as ServerFuture
    };

    // Periodic CAS eviction sweep (M9.2 / deferred #8): bounds the cache when a cap
    // is configured. Correctness-safe (only ever a miss).
    if let (Some(c), Some(max)) = (cache.clone(), cache_max_bytes) {
        const EVICTION_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(EVICTION_INTERVAL);
            loop {
                tick.tick().await;
                match evict_cache_to_cap(c.clone(), max).await {
                    Ok((freed, after)) if freed > 0 => eprintln!(
                        "sembazuru-daemon: cache eviction freed {freed} bytes (now {after} / cap {max})"
                    ),
                    Ok(_) => {}
                    Err(e) => eprintln!("sembazuru-daemon: cache eviction failed: {e}"),
                }
            }
        });
    }

    // Backstop reaper for the session registry (ADR 0013): the common path is the
    // explicit `finish` intake runs after dispatch, but an intake task that
    // panicked before that would leak its session. Periodically reap sessions with
    // NO live connection that are older than a generous TTL (far longer than any
    // action runs, and a live connection holds a ConnGuard regardless), mirroring
    // the WorkerTable opportunistic reaper.
    {
        const SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);
        const SESSION_TTL: std::time::Duration = std::time::Duration::from_secs(900);
        let reg = registry.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tick.tick().await;
                let reaped = reg.sweep_idle(SESSION_TTL).await;
                if reaped > 0 {
                    eprintln!("sembazuru-daemon: reaped {reaped} stale data-plane session(s)");
                }
            }
        });
    }

    // LocalIntake: the build front door (loopback-only). This is the blocking
    // server; the daemon runs until the LocalIntake server exits OR `shutdown` is
    // cancelled (Ctrl-C in CLI mode, SCM Stop in service mode).
    let intake_transport = LocalIntakeTransport::loopback_tcp(&config.intake_addr)?;
    match &intake_transport {
        LocalIntakeTransport::LoopbackTcp(addr) => {
            eprintln!("sembazuru-daemon: LocalIntake on {addr}");
        }
    }
    let local_intake_task = Box::pin(async move { intake_transport.serve(intake).await });
    supervise_server_tasks_until_shutdown(
        RequiredServerTasks::new(
            coordination_task,
            file_server_task,
            status_task,
            local_intake_task,
        ),
        shutdown,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::future;
    use std::time::Duration;

    /// `run_daemon` must return promptly when the shutdown token is cancelled —
    /// the property the Windows Service Stop handler and Ctrl-C both rely on. Uses
    /// ephemeral loopback ports (cache disabled) so no admin/SCM is involved.
    #[tokio::test]
    async fn run_daemon_returns_when_shutdown_is_cancelled() {
        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            intake_addr: "127.0.0.1:0".into(),
            fileserver_addr: "127.0.0.1:0".into(),
            status_addr: "127.0.0.1:0".into(),
            ..DaemonConfig::default()
        };
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run_daemon(config, shutdown.clone()));

        // Let the servers bind, then request shutdown.
        tokio::time::sleep(Duration::from_millis(150)).await;
        shutdown.cancel();

        // It must finish quickly (well under the test's patience) and cleanly.
        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("run_daemon did not return within 5s of shutdown")
            .expect("run_daemon task panicked");
        assert!(res.is_ok(), "run_daemon returned an error: {res:?}");
    }

    #[tokio::test]
    async fn daemon_refuses_coord_lan_without_token() {
        let config = DaemonConfig {
            coord_addr: "0.0.0.0:0".into(),
            cluster_token: None,
            ..DaemonConfig::default()
        };

        let err = tokio::time::timeout(
            Duration::from_secs(5),
            run_daemon(config, CancellationToken::new()),
        )
        .await
        .expect("run_daemon did not return within 5s")
        .expect_err("daemon must refuse unauthenticated Coordination LAN bind");
        let message = err.to_string();
        assert!(message.contains("Coordination"), "{message}");
        assert!(message.contains("non-loopback"), "{message}");
    }

    #[tokio::test]
    async fn daemon_refuses_fileserver_lan_without_token() {
        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            fileserver_addr: "0.0.0.0:0".into(),
            cluster_token: None,
            ..DaemonConfig::default()
        };

        let err = tokio::time::timeout(
            Duration::from_secs(5),
            run_daemon(config, CancellationToken::new()),
        )
        .await
        .expect("run_daemon did not return within 5s")
        .expect_err("daemon must refuse unauthenticated file server LAN bind");
        let message = err.to_string();
        assert!(message.contains("file server"), "{message}");
    }

    #[test]
    fn daemon_allows_lan_with_cluster_token() {
        assert!(
            refuse_unauthenticated_lan("Coordination", "0.0.0.0:1".parse().unwrap(), true, false)
                .is_ok()
        );
    }

    #[test]
    fn daemon_allows_loopback_without_token() {
        assert!(
            refuse_unauthenticated_lan(
                "Coordination",
                "127.0.0.1:1".parse().unwrap(),
                false,
                false,
            )
            .is_ok()
        );
    }

    #[test]
    fn unsafe_override_allows_but_warns() {
        assert!(
            refuse_unauthenticated_lan("file server", "0.0.0.0:1".parse().unwrap(), false, true)
                .is_ok()
        );
    }

    fn pending_server_tasks() -> RequiredServerTasks {
        RequiredServerTasks::new(
            Box::pin(future::pending()),
            Box::pin(future::pending()),
            Box::pin(future::pending()),
            Box::pin(future::pending()),
        )
    }

    fn one_error_server_task(failing_role: ServerRole, message: String) -> RequiredServerTasks {
        let task = move |role| -> ServerFuture {
            if role == failing_role {
                let message = message.clone();
                Box::pin(async move { Err(message.into()) })
            } else {
                Box::pin(future::pending())
            }
        };
        RequiredServerTasks::new(
            task(ServerRole::Coordination),
            task(ServerRole::FileServer),
            task(ServerRole::Status),
            task(ServerRole::LocalIntake),
        )
    }

    fn one_ok_server_task(finishing_role: ServerRole) -> RequiredServerTasks {
        let task = move |role| -> ServerFuture {
            if role == finishing_role {
                Box::pin(future::ready(Ok(())))
            } else {
                Box::pin(future::pending())
            }
        };
        RequiredServerTasks::new(
            task(ServerRole::Coordination),
            task(ServerRole::FileServer),
            task(ServerRole::Status),
            task(ServerRole::LocalIntake),
        )
    }

    fn one_panicking_server_task(panicking_role: ServerRole) -> RequiredServerTasks {
        let task = move |role| -> ServerFuture {
            if role == panicking_role {
                Box::pin(async {
                    panic!("synthetic supervisor panic");
                    #[allow(unreachable_code)]
                    Ok(())
                })
            } else {
                Box::pin(future::pending())
            }
        };
        RequiredServerTasks::new(
            task(ServerRole::Coordination),
            task(ServerRole::FileServer),
            task(ServerRole::Status),
            task(ServerRole::LocalIntake),
        )
    }

    #[tokio::test]
    async fn supervisor_pending_servers_shutdown_returns_ok() {
        let shutdown = CancellationToken::new();
        let run = tokio::spawn(supervise_server_tasks_until_shutdown(
            pending_server_tasks(),
            shutdown.clone(),
        ));

        shutdown.cancel();

        let result = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .expect("supervisor did not return within 5s")
            .expect("supervisor task panicked");
        assert!(result.is_ok(), "supervisor returned error: {result:?}");
    }

    #[tokio::test]
    async fn supervisor_server_failure_wins_when_shutdown_is_already_cancelled() {
        let shutdown = CancellationToken::new();
        shutdown.cancel();

        let message = "injected failure during shutdown race".to_owned();
        let result = supervise_server_tasks_until_shutdown(
            one_error_server_task(ServerRole::Coordination, message.clone()),
            shutdown,
        )
        .await;

        let err = result.expect_err("server error must win over already-cancelled shutdown");
        let text = err.to_string();
        assert!(text.contains(ServerRole::Coordination.label()), "{text}");
        assert!(text.contains(&message), "{text}");
    }

    #[tokio::test]
    async fn supervisor_each_role_error_reports_role_and_source_error() {
        for role in ServerRole::ALL {
            let message = format!("injected failure for {}", role.label());
            let result = supervise_server_tasks_until_shutdown(
                one_error_server_task(role, message.clone()),
                CancellationToken::new(),
            )
            .await;
            let err = result.expect_err("server error must fail daemon");
            let text = err.to_string();
            assert!(text.contains(role.label()), "{text}");
            assert!(text.contains(&message), "{text}");
            assert!(!text.contains("server server"), "{text}");
        }
    }

    #[tokio::test]
    async fn supervisor_each_role_panic_reports_role_and_panic() {
        for role in ServerRole::ALL {
            let result = supervise_server_tasks_until_shutdown(
                one_panicking_server_task(role),
                CancellationToken::new(),
            )
            .await;
            let err = result.expect_err("server panic must fail daemon");
            let text = err.to_string();
            assert!(text.contains(role.label()), "{text}");
            assert!(text.contains("panicked"), "{text}");
            assert!(!text.contains("server server"), "{text}");
        }
    }

    #[tokio::test]
    async fn supervisor_each_role_unexpected_ok_reports_role_and_exit() {
        for role in ServerRole::ALL {
            let result = supervise_server_tasks_until_shutdown(
                one_ok_server_task(role),
                CancellationToken::new(),
            )
            .await;
            let err = result.expect_err("unexpected server success must fail daemon");
            let text = err.to_string();
            assert!(text.contains(role.label()), "{text}");
            assert!(text.contains("unexpected"), "{text}");
            assert!(text.contains("exited"), "{text}");
            assert!(!text.contains("server server"), "{text}");
        }
    }

    #[tokio::test]
    async fn supervisor_registers_fixed_four_server_roles() {
        let supervised = SupervisedServers::spawn(pending_server_tasks());
        let actual: BTreeSet<_> = supervised.registered_roles().into_iter().collect();
        let expected: BTreeSet<_> = ServerRole::ALL.into_iter().collect();

        assert_eq!(ServerRole::ALL.len(), 4);
        assert_eq!(actual, expected);
    }
}
