use sembazuru_gui::app::monitor::{bar_geometry, ellipsize, group_lanes};
use sembazuru_gui::model::{ActivityKind, ActivityRow, ActivityStatus, WorkerRow};

#[test]
fn geometry_clamps_to_sixty_seconds() {
    assert_eq!(bar_geometry(75_000, Some(65_000), 10_000_000, 600.0), None);
    let (left, width) = bar_geometry(30_000, Some(10_000), 20_000_000, 600.0).unwrap();
    assert_eq!((left, width), (300.0, 200.0));
    assert_eq!(
        bar_geometry(75_000, None, 75_000_000, 600.0),
        Some((0.0, 600.0))
    );
    assert_eq!(bar_geometry(0, Some(0), 999, 600.0), Some((599.0, 1.0)));
    assert_eq!(
        bar_geometry(60_000, Some(60_000), 0, 600.0),
        Some((0.0, 1.0))
    );
}

#[test]
fn lane_order_is_stable_and_disconnected_history_remains_visible() {
    let workers = vec![WorkerRow {
        id: "w1".into(),
        cpu: 4,
        ..Default::default()
    }];
    let activities = vec![
        activity("a", "w1", 1, ActivityKind::Remote),
        activity("b", "w1", 4, ActivityKind::Remote),
        activity("c", "w2-gone", 1, ActivityKind::Remote),
    ];
    let groups = group_lanes(&workers, &activities);
    assert_eq!(
        groups
            .iter()
            .map(|group| group.worker_id.as_str())
            .collect::<Vec<_>>(),
        vec!["w1", "w2-gone"]
    );
    assert_eq!(
        groups[0]
            .lanes
            .iter()
            .map(|lane| lane.index)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );

    let zero_cpu = vec![WorkerRow {
        id: "w0".into(),
        cpu: 0,
        ..Default::default()
    }];
    let overflow = vec![activity("overflow", "w0", 3, ActivityKind::Remote)];
    assert_eq!(group_lanes(&zero_cpu, &overflow)[0].lanes.len(), 3);

    let mixed = vec![
        activity("remote", "w1", 1, ActivityKind::Remote),
        activity("local", "", 0, ActivityKind::Local),
        activity("fallback", "", 0, ActivityKind::Fallback),
    ];
    let mixed_groups = group_lanes(&workers, &mixed);
    let synthetic = mixed_groups
        .iter()
        .find(|group| group.worker_id == "Local / Fallback")
        .unwrap();
    assert_eq!(synthetic.capacity, 0);
    assert!(synthetic.lanes.is_empty());
    assert_eq!(synthetic.activities.len(), 2);
}

#[test]
fn narrow_bar_ellipsizes() {
    assert_eq!(
        ellipsize("very_long_translation_unit.cpp", 10),
        "very_long…"
    );
}

fn activity(
    activity_id: &str,
    worker_id: &str,
    lane_index: u32,
    kind: ActivityKind,
) -> ActivityRow {
    ActivityRow {
        activity_id: activity_id.into(),
        attempt_no: 0,
        worker_id: worker_id.into(),
        kind,
        display_name: format!("{activity_id}.cpp"),
        status: ActivityStatus::Running,
        lane_index,
        started_age_ms: 1_000,
        finished_age_ms: None,
        duration_us: 1_000_000,
    }
}
