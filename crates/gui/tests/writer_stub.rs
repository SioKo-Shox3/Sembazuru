use sembazuru_gui::join::writer::{ConfigWriter, StubConfigWriter, WriteError, WriteTarget};

#[test]
fn stub_reports_mechanism_unconfigured() {
    let w = StubConfigWriter;
    let err = w
        .write(WriteTarget::WorkerToml, "agent = \"http://x:1\"\n")
        .unwrap_err();
    assert!(matches!(err, WriteError::MechanismUnconfigured));
    assert!(
        err.to_string().contains("§2.0"),
        "error points the operator at the pending decision"
    );
}
