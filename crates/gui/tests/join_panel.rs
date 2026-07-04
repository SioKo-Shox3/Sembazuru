use sembazuru_gui::app::join_panel::JoinPanel;

#[test]
fn panel_builds_validated_input_from_fields() {
    let mut p = JoinPanel::default();
    p.set_fields_for_test(
        "http://192.168.1.10:50070",
        "tok",
        "0.0.0.0:50061",
        "",
        "adaptive",
        true,
    );
    p.set_detected_lan_ip_for_test(Some("192.168.1.11".into()));
    let toml = p.preview_toml().expect("valid input renders toml");
    assert!(toml.contains("advertise = \"http://192.168.1.11:50061\""));
}
