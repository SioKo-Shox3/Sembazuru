use sembazuru_gui::app::config::{SizeUnit, bytes_to_unit, unit_to_bytes};

#[test]
fn round_trips_and_picks_readable_unit() {
    assert_eq!(unit_to_bytes(8.0, SizeUnit::Gib), 8 * 1024 * 1024 * 1024);
    assert_eq!(unit_to_bytes(0.0, SizeUnit::Gib), 0); // 0 = uncapped
    let (val, unit) = bytes_to_unit(8 * 1024 * 1024 * 1024);
    assert_eq!(unit, SizeUnit::Gib);
    assert!((val - 8.0).abs() < 1e-9);
    let (val, unit) = bytes_to_unit(512 * 1024 * 1024);
    assert_eq!(unit, SizeUnit::Mib);
    assert!((val - 512.0).abs() < 1e-9);
    assert_eq!(bytes_to_unit(0), (0.0, SizeUnit::Gib)); // uncapped shows as 0 GiB
}
