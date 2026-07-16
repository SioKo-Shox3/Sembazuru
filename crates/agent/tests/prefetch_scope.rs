use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::action_cache::AgentCache;
use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::fileserver::{ServerStats, normalize_requested, serve_files_with_stats_token};
use sembazuru_agent::intake::{
    IntakeService, IntakeVfsContext, SubmitOptions, serve_intake_service,
    submit_to_loopback_fixture,
};
use sembazuru_agent::scheduler::Scheduler;
use sembazuru_agent::session_registry::SessionRegistry;
use sembazuru_proto::v0::execute_event::Event;
use sembazuru_proto::v0::execution_server::{Execution, ExecutionServer};
use sembazuru_proto::v0::{
    AbortRequest, AbortResponse, ActionState, Capabilities, Command, ExecuteEvent, ExecuteRequest,
    ExitStatus, StateChange,
};
use sembazuru_tracer::action_key::{InputEntry, InputKind, InputManifest};
use sembazuru_worker::fileclient::FileClient;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::{Request, Response, Status};

static SEQ: AtomicU64 = AtomicU64::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::current_dir()
            .unwrap()
            .join("target")
            .join("prefetch-scope-tests")
            .join(format!(
                "sbz-prefetch-scope-{}-{tag}-{seq}",
                std::process::id()
            ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn cleanup(self) {
        let path = self.path.clone();
        std::fs::remove_dir_all(&path).unwrap_or_else(|e| {
            panic!("failed to remove fixture directory {}: {e}", path.display())
        });
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[derive(Clone)]
struct HoldingExecution {
    requests: mpsc::Sender<ExecuteRequest>,
    release: Arc<Mutex<Option<oneshot::Receiver<()>>>>,
}

fn state_event(state: ActionState) -> ExecuteEvent {
    ExecuteEvent {
        event: Some(Event::State(StateChange {
            state: state as i32,
            detail: String::new(),
        })),
    }
}

#[tonic::async_trait]
impl Execution for HoldingExecution {
    type ExecuteStream = ReceiverStream<Result<ExecuteEvent, Status>>;

    async fn execute(
        &self,
        request: Request<ExecuteRequest>,
    ) -> Result<Response<Self::ExecuteStream>, Status> {
        self.requests
            .send(request.into_inner())
            .await
            .map_err(|_| Status::internal("request receiver closed"))?;
        let release = self
            .release
            .lock()
            .await
            .take()
            .ok_or_else(|| Status::resource_exhausted("release already consumed"))?;
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            for state in [ActionState::Queued, ActionState::Running] {
                if tx.send(Ok(state_event(state))).await.is_err() {
                    return;
                }
            }
            let _ = release.await;
            if tx
                .send(Ok(state_event(ActionState::Completed)))
                .await
                .is_err()
            {
                return;
            }
            let _ = tx
                .send(Ok(ExecuteEvent {
                    event: Some(Event::Exit(ExitStatus {
                        exit_code: 0,
                        wall_time_us: 0,
                        user_time_us: 0,
                        kernel_time_us: 0,
                        resolved_tool_digest: String::new(),
                    })),
                }))
                .await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn abort(
        &self,
        _request: Request<AbortRequest>,
    ) -> Result<Response<AbortResponse>, Status> {
        Ok(Response::new(AbortResponse { acknowledged: true }))
    }
}

async fn start_worker(
    requests: mpsc::Sender<ExecuteRequest>,
    release: oneshot::Receiver<()>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = HoldingExecution {
        requests,
        release: Arc::new(Mutex::new(Some(release))),
    };
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(ExecutionServer::new(service))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let endpoint = format!("http://{addr}");
    tonic::transport::Endpoint::from_shared(endpoint.clone())
        .unwrap()
        .connect()
        .await
        .unwrap();
    (endpoint, task)
}

fn command(root: &Path) -> Command {
    Command {
        argv: vec![
            root.join("clang-cl.exe").to_string_lossy().into_owned(),
            "--prefetch-scope-test".into(),
        ],
        env: Default::default(),
        cwd: root.to_string_lossy().into_owned(),
    }
}

#[test]
fn production_prefetch_only_exposes_scope_content_inputs() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (dirs, paths) = runtime.block_on(async {
        let root = TempDir::new("root");
        let outside = TempDir::new("outside");
        let cache_dir = TempDir::new("cache");
        let scratch = TempDir::new("scratch");
        let inside = root.write("src/in.h", b"inside-v1");
        let outside_path = outside.write("secret.h", b"outside");
        let absent = root.path.join("include/absent.h");
        let inside_normalized = normalize_requested(&inside.to_string_lossy()).unwrap();
        let outside_normalized = normalize_requested(&outside_path.to_string_lossy()).unwrap();

        let cache = Arc::new(AgentCache::open(&cache_dir.path).unwrap());
        let command = command(&root.path);
        let weak = cache.weak_key(&command.argv, &[], &command.cwd);
        let manifest = InputManifest {
            inputs: vec![
                InputEntry {
                    logical: "src\\in.h".into(),
                    absolute: inside.to_string_lossy().into_owned(),
                    kind: InputKind::Content,
                },
                InputEntry {
                    logical: "..\\outside\\secret.h".into(),
                    absolute: outside_path.to_string_lossy().into_owned(),
                    kind: InputKind::Content,
                },
                InputEntry {
                    logical: "include\\absent.h".into(),
                    absolute: absent.to_string_lossy().into_owned(),
                    kind: InputKind::Absent,
                },
            ],
            cmds: vec![],
            cacheable: true,
        };
        cache
            .record(&weak, &manifest, &root.path, &[], 0, &[], &[])
            .unwrap();
        std::fs::write(&inside, b"inside-v2").unwrap();

        let (request_tx, mut request_rx) = mpsc::channel(1);
        let (release_tx, release_rx) = oneshot::channel();
        let (worker_endpoint, worker_task) = start_worker(request_tx, release_rx).await;
        let table = WorkerTable::new(Duration::from_secs(60));
        table.upsert_register(
            "prefetch-worker".into(),
            worker_endpoint,
            Capabilities {
                cpu_count: 1,
                worker_version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
        );

        let registry = Arc::new(SessionRegistry::new().unwrap());
        let fileserver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fileserver_addr = fileserver_listener.local_addr().unwrap();
        let fileserver_registry = Arc::clone(&registry);
        let fileserver_task = tokio::spawn(async move {
            serve_files_with_stats_token(
                fileserver_listener,
                Arc::new(ServerStats::default()),
                None,
                fileserver_registry,
                false,
            )
            .await
            .unwrap();
        });

        let intake = IntakeService::with_vfs(
            Scheduler::new(table),
            IntakeVfsContext {
                agent_fileserver: fileserver_addr.to_string(),
                cache: Some(cache),
                scratch_root: scratch.path.clone(),
                registry,
            },
        );
        let intake_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let intake_addr = intake_listener.local_addr().unwrap();
        let intake_task = tokio::spawn(async move {
            serve_intake_service(intake_listener, intake).await.unwrap();
        });

        let input_root = root.path.to_string_lossy().into_owned();
        let submit = tokio::spawn(submit_to_loopback_fixture(
            format!("http://{intake_addr}"),
            command,
            SubmitOptions {
                input_root: input_root.clone(),
                ..Default::default()
            },
        ));
        let request = tokio::time::timeout(Duration::from_secs(5), request_rx.recv())
            .await
            .expect("worker receives ExecuteRequest")
            .expect("request channel remains open");

        assert_eq!(request.predicted_paths, vec![inside_normalized.clone()]);
        let vfs = request.vfs.as_ref().expect("VFS request");
        assert_eq!(vfs.vfs_root, input_root);
        assert!(!request.session_id.is_empty());

        let client = FileClient::connect_with_rtt_session(
            fileserver_addr,
            Duration::ZERO,
            String::new(),
            String::new(),
            request.session_id.clone(),
        )
        .await
        .unwrap();
        assert!(
            client
                .probe_digest(&inside_normalized)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            client
                .probe_digest(&outside_normalized)
                .await
                .unwrap()
                .is_none()
        );
        release_tx.send(()).unwrap();

        let (exit_code, _) = submit.await.unwrap().unwrap();
        assert_eq!(exit_code, 0);

        drop(client);
        for task in [intake_task, worker_task, fileserver_task] {
            task.abort();
            let result = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("server task stops within timeout");
            assert!(
                result.unwrap_err().is_cancelled(),
                "server task was not cancelled"
            );
        }

        let paths = [
            root.path.clone(),
            outside.path.clone(),
            cache_dir.path.clone(),
            scratch.path.clone(),
        ];
        ([root, outside, cache_dir, scratch], paths)
    });
    runtime.shutdown_timeout(Duration::from_secs(5));

    for dir in dirs {
        dir.cleanup();
    }
    for path in paths {
        assert!(
            !path.exists(),
            "fixture directory was not removed: {}",
            path.display()
        );
    }
}

#[test]
fn non_deterministic_submission_bypasses_cache_and_prefetch() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let dirs = runtime.block_on(async {
        let root = TempDir::new("non-deterministic-root");
        let cache_dir = TempDir::new("non-deterministic-cache");
        let scratch = TempDir::new("non-deterministic-scratch");
        let input = root.write("src/in.h", b"stable-input");

        let cache = Arc::new(AgentCache::open(&cache_dir.path).unwrap());
        let command = command(&root.path);
        let weak = cache.weak_key(&command.argv, &[], &command.cwd);
        let manifest = InputManifest {
            inputs: vec![InputEntry {
                logical: "src\\in.h".into(),
                absolute: input.to_string_lossy().into_owned(),
                kind: InputKind::Content,
            }],
            cmds: vec![],
            cacheable: true,
        };
        cache
            .record(&weak, &manifest, &root.path, &[], 0, &[], &[])
            .unwrap();
        assert!(
            matches!(
                cache.resolve(&weak, &root.path),
                Ok(sembazuru_agent::action_cache::CacheLookup::Hit { .. })
            ),
            "test precondition: the matching cache entry resolves"
        );

        let (request_tx, mut request_rx) = mpsc::channel(1);
        let (release_tx, release_rx) = oneshot::channel();
        let (worker_endpoint, worker_task) = start_worker(request_tx, release_rx).await;
        let table = WorkerTable::new(Duration::from_secs(60));
        table.upsert_register(
            "non-deterministic-worker".into(),
            worker_endpoint,
            Capabilities {
                cpu_count: 1,
                worker_version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
        );

        let registry = Arc::new(SessionRegistry::new().unwrap());
        let fileserver_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let fileserver_addr = fileserver_listener.local_addr().unwrap();
        let fileserver_registry = Arc::clone(&registry);
        let fileserver_task = tokio::spawn(async move {
            serve_files_with_stats_token(
                fileserver_listener,
                Arc::new(ServerStats::default()),
                None,
                fileserver_registry,
                false,
            )
            .await
            .unwrap();
        });

        let intake = IntakeService::with_vfs(
            Scheduler::new(table),
            IntakeVfsContext {
                agent_fileserver: fileserver_addr.to_string(),
                cache: Some(Arc::clone(&cache)),
                scratch_root: scratch.path.clone(),
                registry,
            },
        );
        let metrics = intake.metrics();
        let intake_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let intake_addr = intake_listener.local_addr().unwrap();
        let intake_task = tokio::spawn(async move {
            serve_intake_service(intake_listener, intake).await.unwrap();
        });

        let submit = tokio::spawn(submit_to_loopback_fixture(
            format!("http://{intake_addr}"),
            command,
            SubmitOptions {
                input_root: root.path.to_string_lossy().into_owned(),
                non_deterministic: true,
                ..Default::default()
            },
        ));
        let request = tokio::time::timeout(Duration::from_secs(2), request_rx.recv())
            .await
            .expect("non-deterministic action reaches the worker instead of a cache hit")
            .expect("request channel remains open");

        assert!(
            request.predicted_paths.is_empty(),
            "non-deterministic actions must not inherit cached predictions"
        );
        assert_eq!(metrics.cache_hits.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.cache_misses.load(Ordering::Relaxed), 0);

        release_tx.send(()).unwrap();
        let (exit_code, _) = submit.await.unwrap().unwrap();
        assert_eq!(exit_code, 0);
        assert!(
            matches!(
                cache.resolve(&weak, &root.path),
                Ok(sembazuru_agent::action_cache::CacheLookup::Hit { .. })
            ),
            "the pre-existing cache entry remains usable"
        );

        for task in [intake_task, worker_task, fileserver_task] {
            task.abort();
            let result = tokio::time::timeout(Duration::from_secs(5), task)
                .await
                .expect("server task stops within timeout");
            assert!(
                result.unwrap_err().is_cancelled(),
                "server task was not cancelled"
            );
        }

        [root, cache_dir, scratch]
    });
    runtime.shutdown_timeout(Duration::from_secs(5));

    for dir in dirs {
        dir.cleanup();
    }
}
