use sembazuru_gui::join::worker_toml::{JoinError, JoinInput, render_worker_toml, validate};

fn base() -> JoinInput {
    JoinInput {
        agent: "http://192.168.1.10:50070".into(),
        cluster_token: "shared-secret".into(),
        listen_addr: "0.0.0.0:50061".into(),
        advertise: "".into(), // empty → auto-filled from detected LAN IP
        detected_lan_ip: Some("192.168.1.11".into()),
        participation_mode: "adaptive".into(),
        allow_insecure_lan: true,
    }
}

#[test]
fn autofills_advertise_when_listen_is_unspecified() {
    let out = validate(base()).expect("valid");
    assert_eq!(
        out.advertise, "http://192.168.1.11:50061",
        "0.0.0.0 listen → advertise auto-filled from detected LAN IP + listen port"
    );
}

#[test]
fn rejects_unspecified_listen_without_lan_ip() {
    let mut i = base();
    i.detected_lan_ip = None;
    i.advertise = "".into();
    assert!(
        matches!(validate(i), Err(JoinError::AdvertiseUnresolved)),
        "0.0.0.0 listen + no advertise + no detected IP must fail (worker/src/run.rs:93 trap)"
    );
}

#[test]
fn rejects_bad_agent_url() {
    let mut i = base();
    i.agent = "192.168.1.10:50070".into(); // missing scheme
    assert!(matches!(validate(i), Err(JoinError::AgentUrl)));
}

#[test]
fn rejects_empty_token() {
    let mut i = base();
    i.cluster_token = "".into();
    assert!(
        matches!(validate(i), Err(JoinError::TokenRequired)),
        "LAN join requires a shared token (agent/src/run.rs:39-62 refuses LAN bind without one)"
    );
}

#[test]
fn renders_expected_toml_keys() {
    let out = validate(base()).expect("valid");
    let toml = render_worker_toml(&out);
    assert!(toml.contains("agent = \"http://192.168.1.10:50070\""));
    assert!(toml.contains("cluster_token = \"shared-secret\""));
    assert!(toml.contains("listen_addr = \"0.0.0.0:50061\""));
    assert!(toml.contains("advertise = \"http://192.168.1.11:50061\""));
    assert!(toml.contains("participation_mode = \"adaptive\""));
    assert!(toml.contains("unsafe_allow_insecure_execution_lan = true"));
    // round-trips through the real worker config parser (dev-dep):
    let parsed: sembazuru_worker::config::WorkerConfig = toml::from_str(&toml).expect("parse");
    assert_eq!(parsed.agent.as_deref(), Some("http://192.168.1.10:50070"));
    assert_eq!(
        parsed.advertise.as_deref(),
        Some("http://192.168.1.11:50061")
    );
}
