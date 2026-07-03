use sembazuru_gui::app::dashboard::worker_badge_text;

#[test]
fn badge_reads_zero_one_many() {
    assert_eq!(worker_badge_text(0), "No workers connected");
    assert_eq!(worker_badge_text(1), "1 worker connected ✓");
    assert_eq!(worker_badge_text(3), "3 workers connected ✓");
}
