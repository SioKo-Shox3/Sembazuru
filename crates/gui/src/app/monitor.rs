//! Live build monitor: a redacted, worker/lane-oriented view of the last minute.

use std::collections::{BTreeMap, BTreeSet};

use eframe::egui::{self, Align2, Color32, FontId, RichText, Sense, Vec2};

use crate::model::{
    ActivityKind, ActivityRow, ActivityStatus, ConnectionState, DashboardModel, WorkerRow,
};

pub const WINDOW_MS: u64 = 60_000;

const TIMELINE_WIDTH: f32 = 600.0;
const LANE_HEIGHT: f32 = 28.0;
const LABEL_WIDTH: f32 = 110.0;
const ACTIVE: Color32 = Color32::from_rgb(0x2f, 0x6f, 0xc5);
const SUCCESS: Color32 = Color32::from_rgb(0x38, 0x8e, 0x4b);
const FAILED: Color32 = Color32::from_rgb(0xb4, 0x32, 0x32);
const MUTED: Color32 = Color32::from_rgb(0x70, 0x75, 0x7c);

#[derive(Clone, Debug)]
pub struct WorkerLanes {
    pub worker_id: String,
    pub capacity: u32,
    pub lanes: Vec<Lane>,
    pub activities: Vec<ActivityRow>,
}

#[derive(Clone, Debug)]
pub struct Lane {
    pub index: u32,
    pub activities: Vec<ActivityRow>,
}

pub fn bar_geometry(
    started_age_ms: u64,
    finished_age_ms: Option<u64>,
    _duration_us: u64,
    width: f32,
) -> Option<(f32, f32)> {
    if started_age_ms > WINDOW_MS && finished_age_ms.is_some_and(|age| age >= WINDOW_MS) {
        return None;
    }
    let start = started_age_ms.min(WINDOW_MS);
    let finish = finished_age_ms.unwrap_or(0).min(start);
    let mut left = width * (WINDOW_MS - start) as f32 / WINDOW_MS as f32;
    let right = width * (WINDOW_MS - finish) as f32 / WINDOW_MS as f32;
    let bar_width = (right - left).max(1.0);
    left = left.min((width - bar_width).max(0.0));
    Some((left, bar_width.min(width)))
}

pub fn ellipsize(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    match max_chars {
        0 => String::new(),
        1 => "…".to_owned(),
        n => format!("{}…", text.chars().take(n - 1).collect::<String>()),
    }
}

pub fn group_lanes(workers: &[WorkerRow], activities: &[ActivityRow]) -> Vec<WorkerLanes> {
    let connected_ids = workers
        .iter()
        .map(|worker| worker.id.as_str())
        .collect::<BTreeSet<_>>();
    let disconnected = activities
        .iter()
        .filter(|activity| activity.kind == ActivityKind::Remote)
        .map(|activity| activity.worker_id.as_str())
        .filter(|id| !id.is_empty() && !connected_ids.contains(id))
        .collect::<BTreeSet<_>>();
    let mut order = workers
        .iter()
        .map(|worker| worker.id.as_str())
        .collect::<Vec<_>>();
    order.extend(disconnected.iter().copied());

    let remote_by_worker = activities
        .iter()
        .filter(|activity| activity.kind == ActivityKind::Remote)
        .fold(
            BTreeMap::<&str, Vec<ActivityRow>>::new(),
            |mut map, activity| {
                let worker_id = if activity.worker_id.is_empty() {
                    "Unknown worker"
                } else {
                    activity.worker_id.as_str()
                };
                map.entry(worker_id).or_default().push(activity.clone());
                map
            },
        );
    if remote_by_worker.contains_key("Unknown worker") && !order.contains(&"Unknown worker") {
        order.push("Unknown worker");
    }

    let mut groups = Vec::new();
    for worker_id in order {
        let worker_activities = remote_by_worker.get(worker_id).cloned().unwrap_or_default();
        let reported = workers
            .iter()
            .find(|worker| worker.id == worker_id)
            .map_or(0, |worker| worker.cpu);
        let observed = worker_activities
            .iter()
            .map(|activity| activity.lane_index)
            .max()
            .unwrap_or(0);
        let capacity = reported.max(observed);
        let lanes = (1..=capacity)
            .map(|index| Lane {
                index,
                activities: worker_activities
                    .iter()
                    .filter(|activity| activity.lane_index == index)
                    .cloned()
                    .collect(),
            })
            .collect();
        groups.push(WorkerLanes {
            worker_id: worker_id.to_owned(),
            capacity,
            lanes,
            activities: Vec::new(),
        });
    }

    let local = activities
        .iter()
        .filter(|activity| matches!(activity.kind, ActivityKind::Local | ActivityKind::Fallback))
        .cloned()
        .collect::<Vec<_>>();
    if !local.is_empty() {
        groups.push(WorkerLanes {
            worker_id: "Local / Fallback".to_owned(),
            capacity: 0,
            lanes: Vec::new(),
            activities: local,
        });
    }
    groups
}

pub fn render(ui: &mut egui::Ui, state: &ConnectionState) {
    ui.heading("Monitor");
    ui.separator();
    match state {
        ConnectionState::Connecting => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Connecting to the local daemon…");
            });
        }
        ConnectionState::DaemonDown => {
            ui.colored_label(FAILED, "The local daemon is not running.");
        }
        ConnectionState::Error(message) => {
            ui.colored_label(FAILED, format!("Status error: {message}"));
        }
        ConnectionState::Connected(dashboard) => render_monitor(ui, dashboard),
    }
}

fn render_monitor(ui: &mut egui::Ui, dashboard: &DashboardModel) {
    let completed = dashboard
        .activities
        .iter()
        .filter(|activity| activity.status == ActivityStatus::Completed)
        .count();
    let failed = dashboard
        .activities
        .iter()
        .filter(|activity| {
            matches!(
                activity.status,
                ActivityStatus::Failed | ActivityStatus::Interrupted
            )
        })
        .count();
    let slots = dashboard
        .workers
        .iter()
        .map(|worker| worker.cpu as u64)
        .sum::<u64>();
    ui.horizontal_wrapped(|ui| {
        metric(ui, "Connected workers", dashboard.workers.len());
        metric(ui, "Total slots", slots);
        metric(ui, "In flight", dashboard.in_flight);
        metric(ui, "Completed (60s)", completed);
        metric(ui, "Failed (60s)", failed);
    });
    ui.add_space(6.0);

    let groups = group_lanes(&dashboard.workers, &dashboard.activities);
    egui::ScrollArea::both()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_min_width(LABEL_WIDTH + TIMELINE_WIDTH + 20.0);
            render_ruler(ui);
            for group in &groups {
                ui.separator();
                if group.capacity == 0 {
                    ui.label(RichText::new(&group.worker_id).strong());
                    render_activity_band(ui, "Local", &group.activities);
                } else {
                    ui.label(
                        RichText::new(format!("{}  ({} slots)", group.worker_id, group.capacity))
                            .strong(),
                    );
                    for lane in &group.lanes {
                        render_activity_band(ui, &format!("Slot {}", lane.index), &lane.activities);
                    }
                }
            }
            ui.add_space(8.0);
            render_history(ui, &dashboard.activities);
        });
}

fn metric(ui: &mut egui::Ui, label: &str, value: impl std::fmt::Display) {
    ui.group(|ui| {
        ui.label(RichText::new(label).small().color(MUTED));
        ui.label(RichText::new(value.to_string()).strong().size(18.0));
    });
}

fn render_ruler(ui: &mut egui::Ui) {
    ui.horizontal(|ui| {
        ui.add_sized([LABEL_WIDTH, LANE_HEIGHT], egui::Label::new("Seconds"));
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(TIMELINE_WIDTH, LANE_HEIGHT), Sense::hover());
        let painter = ui.painter();
        for age in (0..=60).step_by(10) {
            let x = rect.right() - rect.width() * age as f32 / 60.0;
            painter.line_segment(
                [egui::pos2(x, rect.center().y), egui::pos2(x, rect.bottom())],
                egui::Stroke::new(1.0, MUTED),
            );
            let label = if age == 0 {
                "Now".to_owned()
            } else {
                format!("-{age}")
            };
            painter.text(
                egui::pos2(x, rect.top()),
                Align2::CENTER_TOP,
                label,
                FontId::proportional(11.0),
                MUTED,
            );
        }
    });
}

fn render_activity_band(ui: &mut egui::Ui, label: &str, activities: &[ActivityRow]) {
    ui.horizontal(|ui| {
        ui.add_sized([LABEL_WIDTH, LANE_HEIGHT], egui::Label::new(label));
        let (rect, _) =
            ui.allocate_exact_size(Vec2::new(TIMELINE_WIDTH, LANE_HEIGHT), Sense::hover());
        ui.painter().line_segment(
            [rect.right_top(), rect.right_bottom()],
            egui::Stroke::new(1.0, MUTED),
        );
        for activity in activities {
            let Some((left, width)) = bar_geometry(
                activity.started_age_ms,
                activity.finished_age_ms,
                activity.duration_us,
                rect.width(),
            ) else {
                continue;
            };
            let bar = egui::Rect::from_min_size(
                egui::pos2(rect.left() + left, rect.top() + 3.0),
                Vec2::new(width, rect.height() - 6.0),
            );
            ui.painter()
                .rect_filled(bar, 2.0, activity_color(activity.status));
            let max_chars = (bar.width() / 7.0).floor() as usize;
            if max_chars > 1 {
                let text = ellipsize(
                    &format!(
                        "{} · {}",
                        activity.display_name,
                        status_text(activity.status)
                    ),
                    max_chars,
                );
                ui.painter().text(
                    egui::pos2(bar.left() + 4.0, bar.center().y),
                    Align2::LEFT_CENTER,
                    text,
                    FontId::proportional(11.0),
                    Color32::WHITE,
                );
            }
            ui.interact(
                bar,
                ui.id()
                    .with(("activity", &activity.activity_id, activity.attempt_no)),
                Sense::hover(),
            )
            .on_hover_text(format!(
                "Worker: {}\nSlot: {}\nFile: {}\nState: {}\nDuration: {:.3}s",
                visible_worker(activity),
                activity.lane_index,
                activity.display_name,
                status_text(activity.status),
                activity.duration_us as f64 / 1_000_000.0
            ));
        }
    });
}

fn render_history(ui: &mut egui::Ui, activities: &[ActivityRow]) {
    ui.label(RichText::new("Recent history (newest first)").strong());
    let mut recent = activities
        .iter()
        .filter(|activity| activity.finished_age_ms.is_some())
        .collect::<Vec<_>>();
    recent.sort_by_key(|activity| activity.finished_age_ms.unwrap_or(u64::MAX));
    egui::Grid::new("monitor_recent_history")
        .striped(true)
        .num_columns(6)
        .show(ui, |ui| {
            for heading in ["Age", "Worker", "Slot", "File", "Status", "Duration"] {
                ui.label(RichText::new(heading).strong());
            }
            ui.end_row();
            for activity in recent {
                ui.label(format!(
                    "{:.1}s",
                    activity.finished_age_ms.unwrap_or(0) as f64 / 1_000.0
                ));
                ui.label(visible_worker(activity));
                ui.label(activity.lane_index.to_string());
                ui.label(&activity.display_name);
                ui.colored_label(
                    activity_color(activity.status),
                    status_text(activity.status),
                );
                ui.label(format!("{:.3}s", activity.duration_us as f64 / 1_000_000.0));
                ui.end_row();
            }
        });
}

fn visible_worker(activity: &ActivityRow) -> &str {
    if activity.worker_id.is_empty() {
        match activity.kind {
            ActivityKind::Fallback => "Local fallback",
            _ => "Local",
        }
    } else {
        &activity.worker_id
    }
}

fn activity_color(status: ActivityStatus) -> Color32 {
    match status {
        ActivityStatus::Queued | ActivityStatus::Preparing | ActivityStatus::Running => ACTIVE,
        ActivityStatus::Completed => SUCCESS,
        ActivityStatus::Failed | ActivityStatus::Interrupted => FAILED,
        ActivityStatus::Unknown => MUTED,
    }
}

fn status_text(status: ActivityStatus) -> &'static str {
    match status {
        ActivityStatus::Queued => "Queued",
        ActivityStatus::Preparing => "Preparing",
        ActivityStatus::Running => "Running",
        ActivityStatus::Completed => "Completed",
        ActivityStatus::Failed => "Failed",
        ActivityStatus::Interrupted => "Interrupted",
        ActivityStatus::Unknown => "Unknown",
    }
}
