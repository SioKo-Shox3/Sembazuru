//! M9.3a gate: the Status GetConfig/SetConfig RPCs over the wire. The GUI (M9.4)
//! uses these to read and persist the daemon's SEMBAZURU_* settings without
//! touching env vars. The key invariants: SetConfig persists to the TOML file
//! that the daemon reads on next start; GetConfig never echoes the cluster token
//! (only its presence); empty addresses are kept, empty optionals are cleared.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sembazuru_agent::config::DaemonConfig;
use sembazuru_agent::coordination::WorkerTable;
use sembazuru_agent::fileserver::ServerStats;
use sembazuru_agent::status::{Metrics, StatusState, serve_status_service};
use sembazuru_proto::v0::{GetConfigRequest, SetConfigRequest, status_client::StatusClient};

static SEQ: AtomicU64 = AtomicU64::new(0);

fn tmp_config() -> std::path::PathBuf {
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sbz-cfgrpc-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir.join("daemon.toml")
}

async fn start_status_with_config(config_path: std::path::PathBuf) -> String {
    let state = StatusState {
        table: WorkerTable::new(Duration::from_secs(60)),
        server_stats: Arc::new(ServerStats::default()),
        cache: None,
        cache_max_bytes: None,
        metrics: Arc::new(Metrics::default()),
        auth_enabled: false,
        config_path,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_status_service(listener, state).await.unwrap();
    });
    format!("http://{addr}")
}

fn blank_set() -> SetConfigRequest {
    SetConfigRequest {
        coord_addr: String::new(),
        intake_addr: String::new(),
        fileserver_addr: String::new(),
        status_addr: String::new(),
        cache_root: String::new(),
        trace_root: String::new(),
        cache_max_bytes: 0,
        cluster_token: None,
    }
}

#[tokio::test]
async fn set_config_persists_and_get_config_reads_back_without_echoing_the_token() {
    let path = tmp_config();
    let endpoint = start_status_with_config(path.clone()).await;
    let mut client = StatusClient::connect(endpoint).await.unwrap();

    // Fresh: no file yet → defaults, no token, nothing cached.
    let g0 = client
        .get_config(GetConfigRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(!g0.file_exists, "no config file yet");
    assert_eq!(g0.coord_addr, "127.0.0.1:50070", "default address");
    assert!(g0.cache_root.is_empty());
    assert!(!g0.cluster_token_set, "no token configured");

    // Set cache_root, a cap, and a token; leave addresses empty (= keep).
    let resp = client
        .set_config(SetConfigRequest {
            cache_root: "C:\\sbz-cache".into(),
            cache_max_bytes: 8192,
            cluster_token: Some("s3cret".into()),
            ..blank_set()
        })
        .await
        .unwrap()
        .into_inner();
    assert!(resp.ok);
    assert!(
        resp.detail.contains("restart"),
        "the response tells the user a restart applies it"
    );

    // Read back: the values are persisted; the address was kept at its default;
    // the token is reported as SET but its value is NOT in the response.
    let g1 = client
        .get_config(GetConfigRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(g1.file_exists);
    assert_eq!(g1.cache_root, "C:\\sbz-cache");
    assert_eq!(g1.cache_max_bytes, 8192);
    assert_eq!(
        g1.coord_addr, "127.0.0.1:50070",
        "empty addr kept the default"
    );
    assert!(g1.cluster_token_set, "token presence is reported");
    // Defensive: the secret must not appear anywhere in the GetConfig response.
    let dbg = format!("{g1:?}");
    assert!(
        !dbg.contains("s3cret"),
        "GetConfig must never echo the cluster token, got: {dbg}"
    );

    // But the token IS persisted to the file the daemon will read on next start.
    assert_eq!(
        DaemonConfig::load_from(&path).cluster_token.as_deref(),
        Some("s3cret"),
        "the token is stored on disk, just not returned over the wire"
    );
}

#[tokio::test]
async fn set_config_token_semantics_unchanged_then_cleared() {
    let path = tmp_config();
    let endpoint = start_status_with_config(path.clone()).await;
    let mut client = StatusClient::connect(endpoint).await.unwrap();

    // Establish a token.
    client
        .set_config(SetConfigRequest {
            cluster_token: Some("keepme".into()),
            ..blank_set()
        })
        .await
        .unwrap();

    // A SetConfig with cluster_token = None (absent) must NOT touch the token,
    // even while changing another field.
    client
        .set_config(SetConfigRequest {
            cache_max_bytes: 4096,
            cluster_token: None,
            ..blank_set()
        })
        .await
        .unwrap();
    assert_eq!(
        DaemonConfig::load_from(&path).cluster_token.as_deref(),
        Some("keepme"),
        "absent cluster_token leaves the stored token unchanged"
    );
    assert_eq!(
        DaemonConfig::load_from(&path).cache_max_bytes,
        Some(4096),
        "the other field was updated"
    );

    // A present-but-empty cluster_token clears it (disables auth).
    client
        .set_config(SetConfigRequest {
            cluster_token: Some(String::new()),
            ..blank_set()
        })
        .await
        .unwrap();
    assert!(
        DaemonConfig::load_from(&path).cluster_token.is_none(),
        "an empty cluster_token clears the stored token"
    );
    let g = client
        .get_config(GetConfigRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(!g.cluster_token_set, "GetConfig reflects the cleared token");
}
