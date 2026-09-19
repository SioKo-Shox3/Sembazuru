use std::sync::{Arc, Mutex};

use sembazuru_config_store::JoinPayload;
use sembazuru_gui::app::join_panel::JoinPanel;
use sembazuru_gui::join::submit::JoinSubmitter;
use sembazuru_gui::join::transport::TransportError;

/// Stands in for the elevated helper, which a test cannot summon: it records what it was handed
/// and returns the outcome the case is about.
struct Recorder {
    handed: Arc<Mutex<Vec<Vec<u8>>>>,
    outcome: Result<(), TransportError>,
}

impl JoinSubmitter for Recorder {
    fn submit(&self, payload: &JoinPayload) -> Result<(), TransportError> {
        let encoded = payload.encode().expect("the panel builds a valid payload");
        self.handed.lock().expect("lock").push(encoded.to_vec());
        self.outcome.clone()
    }
}

fn panel_with(outcome: Result<(), TransportError>) -> (JoinPanel, Arc<Mutex<Vec<Vec<u8>>>>) {
    let handed = Arc::new(Mutex::new(Vec::new()));
    let mut panel = JoinPanel::default();
    panel.set_fields_for_test(
        "http://192.168.1.10:50070",
        "cluster-token-sentinel",
        "0.0.0.0:50061",
        "",
        "adaptive",
        true,
    );
    panel.set_detected_lan_ip_for_test(Some("192.168.1.11".into()));
    panel.set_submitter_for_test(Box::new(Recorder {
        handed: Arc::clone(&handed),
        outcome,
    }));
    (panel, handed)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn panel_builds_validated_input_from_fields() {
    let (panel, _) = panel_with(Ok(()));
    let toml = panel.preview_toml().expect("valid input renders toml");
    assert!(toml.contains("advertise = \"http://192.168.1.11:50061\""));
}

#[test]
fn applying_hands_the_token_to_the_helper_and_keeps_it_out_of_the_preview() {
    let (mut panel, handed) = panel_with(Ok(()));
    let toml = panel.preview_toml().expect("valid input renders toml");
    assert!(
        !toml.contains("cluster-token-sentinel"),
        "the previewed configuration must not carry the token: {toml}"
    );

    panel.apply();

    let handed = handed.lock().expect("lock");
    assert_eq!(handed.len(), 1, "one join is one transaction");
    assert!(
        contains(&handed[0], b"cluster-token-sentinel"),
        "the token reaches the helper through the payload"
    );
    assert!(
        contains(&handed[0], b"advertise = \"http://192.168.1.11:50061\""),
        "so does the worker configuration"
    );
    assert!(panel.notice_for_test().starts_with("Joined."));
}

#[test]
fn a_saved_but_unreflected_join_is_reported_as_such() {
    // 12 is storectl's exit code for a transaction that was written while the services stayed down.
    let (mut panel, _) = panel_with(Err(TransportError::Helper(12)));
    panel.apply();
    let notice = panel.notice_for_test();
    assert!(notice.contains("saved"), "{notice}");
    assert!(notice.contains("Services"), "{notice}");
}

#[test]
fn declined_elevation_is_reported_without_claiming_a_save() {
    let (mut panel, _) = panel_with(Err(TransportError::Elevation(
        "elevation was declined".into(),
    )));
    panel.apply();
    let notice = panel.notice_for_test();
    assert!(notice.contains("declined"), "{notice}");
    assert!(!notice.contains("saved"), "{notice}");
}

#[test]
fn invalid_settings_never_reach_the_helper() {
    let handed = Arc::new(Mutex::new(Vec::new()));
    let mut panel = JoinPanel::default();
    // No token, which validation refuses before anything is built.
    panel.set_fields_for_test(
        "http://192.168.1.10:50070",
        "",
        "0.0.0.0:50061",
        "",
        "adaptive",
        true,
    );
    panel.set_detected_lan_ip_for_test(Some("192.168.1.11".into()));
    panel.set_submitter_for_test(Box::new(Recorder {
        handed: Arc::clone(&handed),
        outcome: Ok(()),
    }));

    panel.apply();

    assert!(
        handed.lock().expect("lock").is_empty(),
        "an unvalidated join must not be handed over"
    );
    assert!(panel.notice_for_test().starts_with("Invalid join settings"));
}
