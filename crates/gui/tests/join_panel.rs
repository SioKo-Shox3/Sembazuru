use std::sync::{Arc, Mutex};

use sembazuru_config_store::{JoinPayload, MAX_MACHINE_CLUSTER_TOKEN_BYTES};
use sembazuru_gui::app::join_panel::JoinPanel;
use sembazuru_gui::join::submit::JoinSubmitter;
use sembazuru_gui::join::transport::TransportError;

/// Stands in for the elevated helper, which a test cannot summon: it records what it was handed
/// and returns the outcome the case is about.
struct Recorder {
    handed: Arc<Mutex<Vec<Vec<u8>>>>,
    outcome: Arc<Mutex<Result<(), TransportError>>>,
}

impl JoinSubmitter for Recorder {
    fn submit(&self, payload: &JoinPayload) -> Result<(), TransportError> {
        let encoded = payload.encode().expect("the panel builds a valid payload");
        self.handed.lock().expect("lock").push(encoded.to_vec());
        self.outcome.lock().expect("lock").clone()
    }
}

struct Harness {
    panel: JoinPanel,
    handed: Arc<Mutex<Vec<Vec<u8>>>>,
    outcome: Arc<Mutex<Result<(), TransportError>>>,
}

impl Harness {
    fn with_token(token: &str) -> Self {
        let handed = Arc::new(Mutex::new(Vec::new()));
        let outcome = Arc::new(Mutex::new(Ok(())));
        let mut panel = JoinPanel::default();
        panel.set_fields_for_test(
            "http://192.168.1.10:50070",
            token,
            "0.0.0.0:50061",
            "",
            "adaptive",
            true,
        );
        panel.set_detected_lan_ip_for_test(Some("192.168.1.11".into()));
        panel.set_submitter_for_test(Arc::new(Recorder {
            handed: Arc::clone(&handed),
            outcome: Arc::clone(&outcome),
        }));
        Self {
            panel,
            handed,
            outcome,
        }
    }

    fn new() -> Self {
        Self::with_token("cluster-token-sentinel")
    }

    /// Starts a join and waits for the worker thread, the way the panel's poll eventually would.
    fn join(&mut self) {
        self.panel.apply(|| {});
        self.panel.wait_for_result_for_test();
    }

    fn handed(&self) -> Vec<Vec<u8>> {
        self.handed.lock().expect("lock").clone()
    }

    fn set_outcome(&self, outcome: Result<(), TransportError>) {
        *self.outcome.lock().expect("lock") = outcome;
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn panel_builds_validated_input_from_fields() {
    let harness = Harness::new();
    let toml = harness
        .panel
        .preview_toml()
        .expect("valid input renders toml");
    assert!(toml.contains("advertise = \"http://192.168.1.11:50061\""));
}

#[test]
fn applying_hands_the_token_to_the_helper_and_keeps_it_out_of_the_preview() {
    let mut harness = Harness::new();
    let toml = harness
        .panel
        .preview_toml()
        .expect("valid input renders toml");
    assert!(
        !toml.contains("cluster-token-sentinel"),
        "the previewed configuration must not carry the token: {toml}"
    );

    harness.join();

    let handed = harness.handed();
    assert_eq!(handed.len(), 1, "one join is one transaction");
    assert!(
        contains(&handed[0], b"cluster-token-sentinel"),
        "the token reaches the helper through the payload"
    );
    assert!(
        contains(&handed[0], b"advertise = \"http://192.168.1.11:50061\""),
        "so does the worker configuration"
    );
    assert!(harness.panel.notice_for_test().starts_with("Joined."));
}

#[test]
fn a_saved_but_unreflected_join_is_reported_as_such() {
    // 12 is storectl's exit code for a transaction that was written while the services stayed down.
    let mut harness = Harness::new();
    harness.set_outcome(Err(TransportError::Helper(12)));
    harness.join();
    let notice = harness.panel.notice_for_test();
    assert!(notice.contains("saved"), "{notice}");
    assert!(notice.contains("Services"), "{notice}");
}

#[test]
fn declined_elevation_is_reported_without_claiming_a_save() {
    let mut harness = Harness::new();
    harness.set_outcome(Err(TransportError::Elevation(
        "elevation was declined".into(),
    )));
    harness.join();
    let notice = harness.panel.notice_for_test();
    assert!(notice.contains("declined"), "{notice}");
    assert!(!notice.contains("saved"), "{notice}");
}

#[test]
fn a_later_failure_replaces_an_earlier_success() {
    // The notice is the only thing the operator reads, so a stale success is a lie about the
    // machine's current state.
    let mut harness = Harness::new();
    harness.join();
    assert!(harness.panel.notice_for_test().starts_with("Joined."));

    harness.set_outcome(Err(TransportError::Timeout));
    harness.join();
    let notice = harness.panel.notice_for_test();
    assert!(notice.starts_with("Join failed"), "{notice}");
    assert!(!notice.contains("Joined."), "{notice}");
    assert_eq!(harness.handed().len(), 2, "both joins were handed over");
}

#[test]
fn a_token_the_store_would_refuse_never_reaches_the_helper() {
    // Each of these is refused somewhere between the wizard and the envelope. Which one does not
    // matter here; that none of them is handed to an elevated process does.
    let oversized = "x".repeat(MAX_MACHINE_CLUSTER_TOKEN_BYTES + 1);
    for token in [
        "",
        "   ",
        "line\nbreak",
        "carriage\rreturn",
        "nul\0byte",
        oversized.as_str(),
    ] {
        let mut harness = Harness::with_token(token);
        harness.join();
        assert!(
            harness.handed().is_empty(),
            "a token of {} bytes was handed over",
            token.len()
        );
        assert!(
            harness
                .panel
                .notice_for_test()
                .starts_with("Invalid join settings"),
            "unexpected notice for {token:?}: {}",
            harness.panel.notice_for_test()
        );
    }
}
