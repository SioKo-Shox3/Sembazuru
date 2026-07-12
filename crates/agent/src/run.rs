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
use std::time::Duration;

use tokio::task::{Id, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::action_cache::AgentCache;
use crate::config::DaemonConfig;
use crate::coordination::{DEFAULT_DEAD_TIMEOUT, WorkerTable, serve_coordination_with_token};
use crate::fileserver::{ServerStats, serve_files_with_stats_token_tracked};
use crate::intake::{
    IntakeService, IntakeVfsContext, LocalIntakeTransport, require_loopback,
    serve_intake_service_with_shutdown,
};
use crate::scheduler::Scheduler;
use crate::session_registry::{DaemonTaskScope, SessionRegistry};
use crate::status::{StatusState, evict_cache_to_cap, serve_status_service};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ServerFuture = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>;

#[cfg(test)]
type DaemonReadySender = tokio::sync::oneshot::Sender<(
    std::net::SocketAddr,
    std::net::SocketAddr,
    Arc<SessionRegistry>,
)>;

#[cfg(test)]
std::thread_local! {
    static NEXT_SERVER_FAILURE: std::cell::Cell<Option<ServerRole>> = const {
        std::cell::Cell::new(None)
    };
    static NEXT_GATED_SERVER_FAILURE: std::cell::RefCell<
        Option<(ServerRole, tokio::sync::oneshot::Receiver<()>)>
    > = const { std::cell::RefCell::new(None) };
    static NEXT_DAEMON_READY: std::cell::RefCell<Option<DaemonReadySender>> =
        const { std::cell::RefCell::new(None) };
    static NEXT_AFTER_SESSION_DRAIN: std::cell::RefCell<
        Option<(tokio::sync::oneshot::Sender<()>, tokio::sync::oneshot::Receiver<()>)>
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
static SUBMISSION_DEADLINES: std::sync::LazyLock<std::sync::Mutex<HashMap<String, Duration>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ServerRole {
    Coordination,
    FileServer,
    Status,
    #[cfg_attr(not(test), allow(dead_code))]
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

#[cfg(test)]
fn inject_server_failure(role: ServerRole, task: ServerFuture) -> ServerFuture {
    if NEXT_SERVER_FAILURE.with(|failure| failure.take()) == Some(role) {
        Box::pin(async move { Err(format!("injected {} failure", role.label()).into()) })
    } else if let Some(trigger) = NEXT_GATED_SERVER_FAILURE.with(|slot| {
        let mut slot = slot.borrow_mut();
        match slot.take() {
            Some((injected_role, trigger)) if injected_role == role => Some(trigger),
            other => {
                *slot = other;
                None
            }
        }
    }) {
        Box::pin(async move {
            let _ = trigger.await;
            Err(format!("injected {} failure", role.label()).into())
        })
    } else {
        task
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
    #[cfg(test)]
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

    async fn abort_and_drain(&mut self) {
        self.abort_all();
        while self.tasks.join_next().await.is_some() {}
        self.roles.clear();
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

#[cfg(test)]
async fn supervise_server_tasks_until_shutdown(
    tasks: RequiredServerTasks,
    shutdown: CancellationToken,
) -> Result<(), BoxError> {
    let mut servers = SupervisedServers::spawn(tasks);
    let result = tokio::select! {
        biased;
        result = servers.next_exit() => result,
        _ = shutdown.cancelled() => {
            tokio::task::yield_now().await;
            if let Some(result) = servers.try_next_exit() {
                result
            } else {
                eprintln!("sembazuru-daemon: shutdown requested; stopping");
                Ok(())
            }
        }
    };
    servers.abort_and_drain().await;
    result
}

const SUBMISSION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(120);

async fn supervise_daemon_servers_until_shutdown(
    tasks: RequiredServerTasks,
    shutdown: CancellationToken,
    intake_shutdown: CancellationToken,
    child_tasks: &DaemonTaskScope,
    submission_deadline: Duration,
) -> Result<(), BoxError> {
    let RequiredServerTasks {
        coordination,
        file_server,
        status,
        local_intake,
    } = tasks;
    let mut servers = SupervisedServers {
        tasks: JoinSet::new(),
        roles: HashMap::new(),
    };
    servers.spawn_one(ServerRole::Coordination, coordination);
    servers.spawn_one(ServerRole::FileServer, file_server);
    servers.spawn_one(ServerRole::Status, status);
    let mut local_intake = tokio::spawn(local_intake);

    let (result, local_intake_done) = tokio::select! {
        biased;
        result = servers.next_exit() => (result, false),
        joined = &mut local_intake => (
            match joined {
                Ok(Ok(())) => Err("LocalIntake task unexpectedly exited successfully".into()),
                Ok(Err(error)) => Err(format!("LocalIntake task exited with error: {error}").into()),
                Err(error) if error.is_panic() => {
                    Err(format!("LocalIntake task panicked: {error}").into())
                }
                Err(error) => Err(format!("LocalIntake task failed to join: {error}").into()),
            },
            true,
        ),
        _ = shutdown.cancelled() => {
            tokio::task::yield_now().await;
            if let Some(result) = servers.try_next_exit() {
                (result, false)
            } else {
                eprintln!("sembazuru-daemon: shutdown requested; stopping");
                (Ok(()), false)
            }
        }
    };

    child_tasks.begin_shutdown();
    intake_shutdown.cancel();
    servers.abort_and_drain().await;
    child_tasks.wait_cancel().await;
    child_tasks.drain_until(submission_deadline).await;

    if !local_intake_done {
        match local_intake.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(format!("{result:?}; LocalIntake shutdown failed: {error}").into());
            }
            Err(error) => {
                return Err(
                    format!("{result:?}; LocalIntake shutdown join failed: {error}").into(),
                );
            }
        }
    }
    result
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
    #[cfg(test)]
    let submission_deadline = SUBMISSION_DEADLINES
        .lock()
        .expect("submission deadline mutex poisoned")
        .remove(&config.intake_addr)
        .unwrap_or(SUBMISSION_SHUTDOWN_DEADLINE);
    #[cfg(not(test))]
    let submission_deadline = SUBMISSION_SHUTDOWN_DEADLINE;
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
    let tracker = crate::action_tracker::ActionTracker::default();
    let scheduler = Scheduler::with_remote_budget_and_cluster_token_and_tracker(
        table.clone(),
        crate::scheduler::DEFAULT_REMOTE_BUDGET,
        cluster_token.clone(),
        tracker.clone(),
    );

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
    #[cfg(test)]
    let coordination_task = inject_server_failure(ServerRole::Coordination, coordination_task);

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

    // Status surface (M9.1, ADR 0008 §4): loopback-only read-only plane for the
    // GUI; refuses any non-loopback bind.
    let status_sockaddr = require_loopback(&config.status_addr, "Status")?;
    let status_listener = tokio::net::TcpListener::bind(status_sockaddr).await?;
    eprintln!(
        "sembazuru-daemon: Status on {}",
        status_listener.local_addr()?
    );

    // Complete every fallible listener/transport setup before creating the
    // ephemeral registry. After this point all exits use the cleanup funnel.
    let intake_transport = LocalIntakeTransport::loopback_tcp(&config.intake_addr)?;
    let intake_listener = match intake_transport {
        LocalIntakeTransport::LoopbackTcp(addr) => tokio::net::TcpListener::bind(addr).await?,
    };
    let intake_addr = intake_listener.local_addr()?;
    eprintln!("sembazuru-daemon: LocalIntake on {intake_addr}");

    // The data-plane session registry (ADR 0013): one shared instance threaded
    // into both the file server and intake.
    let registry = Arc::new(SessionRegistry::new()?);
    let child_tasks = DaemonTaskScope::new();
    #[cfg(test)]
    if let Some(ready) = NEXT_DAEMON_READY.with(|slot| slot.borrow_mut().take()) {
        let _ = ready.send((fileserver_addr, intake_addr, Arc::clone(&registry)));
    }
    let file_server_task = {
        let stats = server_stats.clone();
        let tok = cluster_token.clone();
        let reg = registry.clone();
        let scope = child_tasks.clone();
        let legacy_sessions_enabled = config.unsafe_legacy_dataplane_sessions;
        Box::pin(async move {
            serve_files_with_stats_token_tracked(
                file_listener,
                stats,
                tok,
                reg,
                legacy_sessions_enabled,
                scope,
            )
            .await?;
            Ok(())
        }) as ServerFuture
    };
    let intake = IntakeService::with_vfs_tracked_and_tracker(
        scheduler,
        IntakeVfsContext {
            agent_fileserver: fileserver_addr.to_string(),
            cache: cache.clone(),
            scratch_root: std::path::PathBuf::from(trace_root),
            registry: registry.clone(),
        },
        child_tasks.clone(),
        tracker.clone(),
    );
    let status_task = {
        let state = StatusState {
            table: table.clone(),
            server_stats: server_stats.clone(),
            cache: cache.clone(),
            cache_max_bytes,
            metrics: intake.metrics(),
            tracker,
            auth_enabled: cluster_token.is_some(),
            config_path: DaemonConfig::path_from_env(),
            // SEC-001 interim (ADR 0016): mutating Status RPCs are opt-in.
            admin_enabled: config.status_admin,
        };
        Box::pin(async move { serve_status_service(status_listener, state).await }) as ServerFuture
    };

    // Periodic CAS eviction is detached but does not retain the session registry.
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
    let session_sweeper = {
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
        })
    };

    // LocalIntake is the build front door. Its root is stopped gracefully so
    // accepted RPCs retain their response stream until their submission is safe.
    let intake_shutdown = CancellationToken::new();
    let local_intake_task = {
        let graceful = intake_shutdown.clone();
        Box::pin(async move {
            serve_intake_service_with_shutdown(intake_listener, intake, graceful).await
        }) as ServerFuture
    };
    #[cfg(test)]
    let local_intake_task = inject_server_failure(ServerRole::LocalIntake, local_intake_task);
    let server_result = supervise_daemon_servers_until_shutdown(
        RequiredServerTasks::new(
            coordination_task,
            file_server_task,
            status_task,
            local_intake_task,
        ),
        shutdown,
        intake_shutdown,
        &child_tasks,
        submission_deadline,
    )
    .await;
    session_sweeper.abort();
    let _ = session_sweeper.await;
    registry.shutdown_sessions().await;
    #[cfg(test)]
    if let Some((reached, release)) = NEXT_AFTER_SESSION_DRAIN.with(|slot| slot.borrow_mut().take())
    {
        let _ = reached.send(());
        let _ = release.await;
    }
    let cleanup = tokio::task::spawn_blocking(move || registry.shutdown_cleanup_blocking()).await;
    let cleanup_result: Result<(), BoxError> = match cleanup {
        Ok(result) => result.map_err(|error| Box::new(error) as BoxError),
        Err(error) => Err(format!("registry cleanup task failed to join: {error}").into()),
    };
    match (server_result, cleanup_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(server), Ok(())) => Err(server),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(server), Err(cleanup)) => {
            Err(format!("{server}; registry cleanup also failed: {cleanup}").into())
        }
    }
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

    async fn exercise_daemon_cleanup(failing_server: bool) -> (bool, Result<(), BoxError>) {
        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            intake_addr: "127.0.0.1:0".into(),
            fileserver_addr: "127.0.0.1:0".into(),
            status_addr: "127.0.0.1:0".into(),
            ..DaemonConfig::default()
        };
        let shutdown = CancellationToken::new();
        let (root_tx, root_rx) = tokio::sync::oneshot::channel();
        let (reached_tx, reached_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        SessionRegistry::observe_next_cleanup(root_tx, reached_tx, release_rx);
        if failing_server {
            NEXT_SERVER_FAILURE.with(|failure| failure.set(Some(ServerRole::Coordination)));
        }
        let mut daemon = tokio::spawn(run_daemon(config, shutdown.clone()));
        let root = root_rx
            .await
            .expect("daemon registry root was not observed");
        if !failing_server {
            tokio::time::sleep(Duration::from_millis(150)).await;
            shutdown.cancel();
        }
        tokio::task::spawn_blocking(move || reached_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .unwrap()
            .expect("daemon cleanup did not reach its barrier");
        let early = tokio::time::timeout(Duration::from_millis(100), &mut daemon).await;
        let returned_early = early.is_ok();
        release_tx.send(()).unwrap();
        let joined = match early {
            Ok(joined) => joined,
            Err(_) => daemon.await,
        }
        .expect("run_daemon task panicked");
        for _ in 0..100 {
            if !root.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!root.exists(), "daemon cleanup did not remove its CAS root");
        (returned_early, joined)
    }

    #[tokio::test]
    async fn normal_shutdown_waits_for_registry_cleanup_completion() {
        let (returned_early, result) = exercise_daemon_cleanup(false).await;
        assert!(
            !returned_early,
            "normal shutdown returned before cleanup completion"
        );
        assert!(result.is_ok(), "normal shutdown failed: {result:?}");
    }

    #[tokio::test]
    async fn server_failure_waits_for_registry_cleanup_completion() {
        let (returned_early, result) = exercise_daemon_cleanup(true).await;
        assert!(
            !returned_early,
            "server failure returned before cleanup completion"
        );
        assert!(result.is_err(), "injected server failure was lost");
    }

    async fn exercise_descendant_drain_during_pin_barrier(
        failing_server: bool,
    ) -> Result<(), BoxError> {
        use sembazuru_dataplane::async_io::{read_frame, write_frame};
        use sembazuru_dataplane::ops::{
            HelloRequest, HelloResponse, OpenReadRequest, OpenReadResponse,
        };
        use sembazuru_dataplane::wire::{FrameHeader, OpCode};
        use tokio::io::AsyncWriteExt;

        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            intake_addr: "127.0.0.1:0".into(),
            fileserver_addr: "127.0.0.1:0".into(),
            status_addr: "127.0.0.1:0".into(),
            ..DaemonConfig::default()
        };
        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        NEXT_DAEMON_READY.with(|slot| {
            assert!(slot.borrow_mut().replace(ready_tx).is_none());
        });
        let (drained_tx, drained_rx) = tokio::sync::oneshot::channel();
        let (release_drain_tx, release_drain_rx) = tokio::sync::oneshot::channel();
        NEXT_AFTER_SESSION_DRAIN.with(|slot| {
            assert!(
                slot.borrow_mut()
                    .replace((drained_tx, release_drain_rx))
                    .is_none()
            );
        });
        let failure_trigger = if failing_server {
            let (trigger_tx, trigger_rx) = tokio::sync::oneshot::channel();
            NEXT_GATED_SERVER_FAILURE.with(|slot| {
                assert!(
                    slot.borrow_mut()
                        .replace((ServerRole::Coordination, trigger_rx))
                        .is_none()
                );
            });
            Some(trigger_tx)
        } else {
            None
        };
        let (root_tx, root_rx) = tokio::sync::oneshot::channel();
        let (cleanup_reached_tx, cleanup_reached_rx) = std::sync::mpsc::channel();
        let (cleanup_release_tx, cleanup_release_rx) = std::sync::mpsc::channel();
        SessionRegistry::observe_next_cleanup(root_tx, cleanup_reached_tx, cleanup_release_rx);
        let mut daemon = tokio::spawn(run_daemon(config, shutdown.clone()));
        let (fileserver_addr, _intake_addr, registry) =
            ready_rx.await.expect("daemon did not publish readiness");
        let store_root = root_rx
            .await
            .expect("daemon registry root was not observed");

        let fixture = std::env::temp_dir().join(format!(
            "sbz-daemon-child-race-{}-{}",
            std::process::id(),
            u8::from(failing_server)
        ));
        let _ = std::fs::remove_dir_all(&fixture);
        std::fs::create_dir(&fixture).unwrap();
        let input = fixture.join("input.h");
        std::fs::write(&input, b"tracked child race").unwrap();
        let requested = input.to_string_lossy().into_owned();
        let session_id = format!("tracked-child-{}", u8::from(failing_server));
        let capability = registry.create(session_id.clone(), None, Vec::new()).await;

        let mut socket = loop {
            match tokio::net::TcpStream::connect(fileserver_addr).await {
                Ok(socket) => break socket,
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        };
        write_frame(
            &mut socket,
            FrameHeader {
                request_id: 0,
                op: OpCode::Hello,
                is_response: false,
            },
            &HelloRequest {
                token: String::new(),
                root: String::new(),
                session_id,
            }
            .encode(),
        )
        .await
        .unwrap();
        socket.flush().await.unwrap();
        let (_, hello) = read_frame(&mut socket).await.unwrap();
        assert!(HelloResponse::decode(&hello).unwrap().ok);

        let (pin_reached_tx, pin_reached_rx) = tokio::sync::oneshot::channel();
        let (pin_release_tx, pin_release_rx) = tokio::sync::oneshot::channel();
        capability.install_before_pin_insert_hook(pin_reached_tx, pin_release_rx);
        let request = tokio::spawn(async move {
            let write = write_frame(
                &mut socket,
                FrameHeader {
                    request_id: 1,
                    op: OpCode::OpenRead,
                    is_response: false,
                },
                &OpenReadRequest {
                    path: requested,
                    want_inline: true,
                }
                .encode(),
            )
            .await;
            let response = match write {
                Ok(()) => match socket.flush().await {
                    Ok(()) => read_frame(&mut socket).await.and_then(|(_, payload)| {
                        OpenReadResponse::decode(&payload)
                            .map_err(|error| std::io::Error::other(error.to_string()))
                    }),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            };
            (socket, response)
        });
        pin_reached_rx
            .await
            .expect("request did not reach the pre-pin barrier");

        if let Some(trigger) = failure_trigger {
            trigger.send(()).unwrap();
        } else {
            shutdown.cancel();
        }
        drained_rx
            .await
            .expect("daemon did not finish its session drain");
        let descendant_was_drained = pin_release_tx.send(()).is_err();
        let (socket, response) = tokio::time::timeout(Duration::from_secs(5), request)
            .await
            .expect("OpenRead did not terminate during daemon shutdown")
            .unwrap();
        let pinned_after_shutdown = capability.pinned_count().await;
        drop((socket, capability));
        for _ in 0..200 {
            if registry.active_pin_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            registry.active_pin_count(),
            0,
            "test cleanup retained a pin"
        );
        release_drain_tx.send(()).unwrap();
        tokio::task::spawn_blocking(move || {
            cleanup_reached_rx.recv_timeout(Duration::from_secs(5))
        })
        .await
        .unwrap()
        .expect("daemon cleanup did not reach its barrier");
        let early = tokio::time::timeout(Duration::from_millis(100), &mut daemon).await;
        assert!(
            early.is_err(),
            "daemon returned before CAS cleanup completion"
        );
        cleanup_release_tx.send(()).unwrap();
        let daemon_result = daemon.await.expect("run_daemon task panicked");
        assert_eq!(failing_server, daemon_result.is_err());
        assert!(!store_root.exists(), "daemon CAS root survived cleanup");
        std::fs::remove_dir_all(fixture).ok();

        assert!(
            !matches!(response, Ok(open) if open.exists),
            "a descendant request crossed session shutdown and published a pin"
        );
        assert!(
            descendant_was_drained,
            "the request future remained alive until after session shutdown"
        );
        assert_eq!(
            pinned_after_shutdown, 0,
            "shutdown clear was followed by a descendant pin insertion"
        );
        Ok(())
    }

    #[tokio::test]
    async fn normal_shutdown_drains_descendant_request_before_session_cleanup() {
        exercise_descendant_drain_during_pin_barrier(false)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn server_failure_drains_descendant_request_before_session_cleanup() {
        exercise_descendant_drain_during_pin_barrier(true)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn daemon_refuses_coord_lan_without_token() {
        let registry_count = SessionRegistry::current_thread_creation_count();
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
        assert_eq!(
            SessionRegistry::current_thread_creation_count(),
            registry_count,
            "fallible daemon setup must finish before registry creation"
        );
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

    #[cfg(windows)]
    fn local_fixture_command(
        addr: std::net::SocketAddr,
        output: &std::path::Path,
    ) -> sembazuru_proto::v0::Command {
        let executable = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        // This synthetic fixture is the test executable itself, which embeds the
        // production runtime constants and test needle strings without importing
        // those DLLs. Isolate that exact metadata key from the production scan.
        crate::scheduler::prime_bypass_runtime_none(&executable).unwrap();
        sembazuru_proto::v0::Command {
            argv: vec![
                executable,
                "--ignored".into(),
                "--exact".into(),
                "tests::local_job_child_fixture".into(),
                "--nocapture".into(),
            ],
            env: [
                ("SEMBAZURU_JOB_FIXTURE_MODE".into(), "parent".into()),
                ("SEMBAZURU_JOB_FIXTURE_ADDR".into(), addr.to_string()),
                (
                    "SEMBAZURU_JOB_FIXTURE_OUTPUT".into(),
                    output.to_string_lossy().into_owned(),
                ),
            ]
            .into_iter()
            .collect(),
            cwd: std::env::temp_dir().to_string_lossy().into_owned(),
        }
    }

    #[cfg(windows)]
    async fn exercise_daemon_submission_drain(failing_server: bool) {
        use std::io::Write;

        let _guard = crate::LOCAL_JOB_TEST_LOCK.lock().await;

        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            intake_addr: "127.0.0.1:0".into(),
            fileserver_addr: "127.0.0.1:0".into(),
            status_addr: "127.0.0.1:0".into(),
            ..DaemonConfig::default()
        };
        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        NEXT_DAEMON_READY.with(|slot| {
            assert!(slot.borrow_mut().replace(ready_tx).is_none());
        });
        let failure = if failing_server {
            let (tx, rx) = tokio::sync::oneshot::channel();
            NEXT_GATED_SERVER_FAILURE.with(|slot| {
                assert!(
                    slot.borrow_mut()
                        .replace((ServerRole::Coordination, rx))
                        .is_none()
                );
            });
            Some(tx)
        } else {
            None
        };
        let daemon = tokio::spawn(run_daemon(config, shutdown.clone()));
        let (_, intake_addr, _) = ready_rx.await.expect("daemon did not publish readiness");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-daemon-drain-{}-{}-{}.txt",
            std::process::id(),
            u8::from(failing_server),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = local_fixture_command(listener.local_addr().unwrap(), &output);
        let mut client = tokio::spawn(crate::intake::submit_to_daemon(
            format!("http://{intake_addr}"),
            command,
            crate::intake::SubmitOptions::default(),
        ));
        let mut peers = crate::accept_local_job_fixture(listener).await;

        if let Some(failure) = failure {
            failure.send(()).unwrap();
        } else {
            shutdown.cancel();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut client)
                .await
                .is_err(),
            "accepted LocalIntake RPC closed before the local child completed"
        );
        for peer in &mut peers {
            peer.socket.write_all(&[1]).unwrap();
        }
        let (exit, _) = tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("client did not receive the natural Exit")
            .unwrap()
            .unwrap();
        assert_eq!(exit, 0);
        let daemon_result = tokio::time::timeout(Duration::from_secs(5), daemon)
            .await
            .expect("daemon did not finish cleanup")
            .unwrap();
        assert_eq!(daemon_result.is_err(), failing_server);
        assert_eq!(std::fs::read(&output).unwrap(), b"completed\n");
        for peer in &peers {
            peer.assert_signaled();
        }
        let _ = std::fs::remove_file(output);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn daemon_normal_shutdown_drains_local_submission_to_real_exit() {
        exercise_daemon_submission_drain(false).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn daemon_non_intake_failure_drains_local_submission_to_real_exit() {
        exercise_daemon_submission_drain(true).await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn daemon_deadline_reaps_old_tree_before_retry_eof() {
        let _guard = crate::LOCAL_JOB_TEST_LOCK.lock().await;
        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            intake_addr: "127.0.0.2:0".into(),
            fileserver_addr: "127.0.0.1:0".into(),
            status_addr: "127.0.0.1:0".into(),
            ..DaemonConfig::default()
        };
        SUBMISSION_DEADLINES
            .lock()
            .unwrap()
            .insert(config.intake_addr.clone(), Duration::from_millis(10));
        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        NEXT_DAEMON_READY.with(|slot| {
            assert!(slot.borrow_mut().replace(ready_tx).is_none());
        });
        let daemon = tokio::spawn(run_daemon(config, shutdown.clone()));
        let (_, intake_addr, _) = ready_rx.await.expect("daemon did not publish readiness");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-daemon-deadline-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let command = local_fixture_command(listener.local_addr().unwrap(), &output);
        let client = tokio::spawn(crate::intake::submit_to_daemon(
            format!("http://{intake_addr}"),
            command,
            crate::intake::SubmitOptions::default(),
        ));
        let peers = crate::accept_local_job_fixture(listener).await;
        shutdown.cancel();

        let client_error = tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("client did not receive retry-safe EOF")
            .unwrap()
            .expect_err("forced submission must not publish a fake Exit");
        assert!(
            client_error.to_string().contains("exit status"),
            "{client_error}"
        );
        for peer in &peers {
            peer.assert_signaled();
        }
        assert!(!output.exists(), "old tree wrote output before force reap");
        drop(peers);
        tokio::time::timeout(Duration::from_secs(5), daemon)
            .await
            .expect("daemon did not finish after forced reap")
            .unwrap()
            .unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn daemon_deadline_forces_disarm_wait_before_retry_eof() {
        use std::io::Write;

        let _guard = crate::LOCAL_JOB_TEST_LOCK.lock().await;
        let config = DaemonConfig {
            coord_addr: "127.0.0.1:0".into(),
            intake_addr: "127.0.0.3:0".into(),
            fileserver_addr: "127.0.0.1:0".into(),
            status_addr: "127.0.0.1:0".into(),
            ..DaemonConfig::default()
        };
        SUBMISSION_DEADLINES
            .lock()
            .unwrap()
            .insert(config.intake_addr.clone(), Duration::from_millis(10));
        let shutdown = CancellationToken::new();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        NEXT_DAEMON_READY.with(|slot| {
            assert!(slot.borrow_mut().replace(ready_tx).is_none());
        });
        let daemon = tokio::spawn(run_daemon(config, shutdown.clone()));
        let (_, intake_addr, _) = ready_rx.await.expect("daemon did not publish readiness");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let output = std::env::temp_dir().join(format!(
            "sembazuru-daemon-disarm-force-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut command = local_fixture_command(listener.local_addr().unwrap(), &output);
        command
            .env
            .insert("SEMBAZURU_JOB_FIXTURE_DETACH".into(), "1".into());
        let control = crate::local_job::TestGuardianControl::bind(&mut command).unwrap();
        control.install(4);
        control.observe_job();
        let client = tokio::spawn(crate::intake::submit_to_daemon(
            format!("http://{intake_addr}"),
            command,
            crate::intake::SubmitOptions::default(),
        ));
        let mut peers = crate::accept_local_job_fixture(listener).await;
        let observed_job = control.take_observed_job_handle();
        let membership = if observed_job == 0 {
            Vec::new()
        } else {
            peers
                .iter()
                .map(|peer| {
                    (
                        peer.role,
                        peer.pid,
                        peer.is_in_job(observed_job)
                            .map_err(|error| error.to_string()),
                    )
                })
                .collect::<Vec<_>>()
        };
        if observed_job != 0 {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(observed_job as _);
            }
        }
        peers
            .iter_mut()
            .find(|peer| peer.role == 1)
            .unwrap()
            .socket
            .write_all(&[1])
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), async {
            while !peers
                .iter()
                .find(|peer| peer.role == 1)
                .unwrap()
                .is_signaled()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("top process did not exit into the disarm wait");
        assert!(
            !peers
                .iter()
                .find(|peer| peer.role == 0)
                .unwrap()
                .is_signaled(),
            "detached descendant exited before force"
        );
        shutdown.cancel();

        let client_result = tokio::time::timeout(Duration::from_secs(5), client)
            .await
            .expect("client did not receive safe EOF after disarm force")
            .unwrap();
        let branch = control.take_natural_publish_branch();
        let failpoint4_consumed = control.take_last_consumed_failpoint();
        let audit = control.take_last_audit_counts();
        let run_local_deadline_state = control.take_run_local_deadline_state();
        let peer_signals = peers
            .iter()
            .map(|peer| (peer.role, peer.pid, peer.is_signaled()))
            .collect::<Vec<_>>();
        let diagnostic = format!(
            "observed_job={observed_job} membership={membership:?} audit={audit:?} natural_branch={branch} failpoint4_consumed={failpoint4_consumed} run_local_deadline_state={run_local_deadline_state} peer_signals={peer_signals:?}"
        );
        let client_error = client_result.expect_err(&format!(
            "forced disarm wait must not publish the natural Exit; {diagnostic}"
        ));
        assert!(
            client_error.to_string().contains("exit status"),
            "{client_error}; {diagnostic}"
        );
        for peer in &peers {
            peer.assert_signaled();
        }
        tokio::time::timeout(Duration::from_secs(5), daemon)
            .await
            .expect("daemon did not finish after disarm force")
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"completed\n");
        let _ = std::fs::remove_file(output);
    }
}
