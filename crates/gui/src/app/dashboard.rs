//! Dashboard rendering (M9.4b): turns a [`ConnectionState`] into the egui widgets
//! a non-developer reads — the connected workers and their health, the cache hit
//! rate / size / cap, in-flight actions, the remote/local/fallback breakdown, the
//! file-server counters, and the auth posture. Pure presentation: it reads the
//! already-mapped view-model and draws, doing no I/O.

use eframe::egui::{self, Color32, RichText};

use crate::model::{CacheModel, ConnectionState, DashboardModel, ExecModel, format_bytes};

const HEALTHY: Color32 = Color32::from_rgb(0x4c, 0xaf, 0x50);
const UNHEALTHY: Color32 = Color32::from_rgb(0xd9, 0x53, 0x4f);
const MUTED: Color32 = Color32::from_rgb(0x9e, 0x9e, 0x9e);

/// Renders the dashboard for the current connection state into `ui`.
pub fn render(ui: &mut egui::Ui, state: &ConnectionState) {
    ui.horizontal(|ui| {
        ui.heading("Sembazuru");
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            connection_badge(ui, state);
        });
    });
    ui.separator();

    egui::ScrollArea::vertical().show(ui, |ui| match state {
        ConnectionState::Connecting => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Connecting to the local daemon…");
            });
        }
        ConnectionState::DaemonDown => render_daemon_down(ui),
        ConnectionState::Error(message) => {
            ui.colored_label(UNHEALTHY, format!("Status error: {message}"));
        }
        ConnectionState::Connected(dash) => render_dashboard(ui, dash),
    });
}

fn connection_badge(ui: &mut egui::Ui, state: &ConnectionState) {
    let (color, text) = match state {
        ConnectionState::Connecting => (MUTED, "connecting"),
        ConnectionState::Connected(_) => (HEALTHY, "connected"),
        ConnectionState::DaemonDown => (UNHEALTHY, "daemon down"),
        ConnectionState::Error(_) => (UNHEALTHY, "error"),
    };
    ui.colored_label(color, RichText::new(format!("● {text}")).small());
}

fn render_daemon_down(ui: &mut egui::Ui) {
    ui.add_space(8.0);
    ui.label(RichText::new("The local daemon is not running.").strong());
    ui.label(
        RichText::new(
            "Nothing is listening on the loopback Status port. Start the daemon to \
             see cluster and cache state.",
        )
        .color(MUTED),
    );
    // The "Start daemon" control (Windows Service start, with elevation) arrives
    // in M9.4e; for now this is an informational state.
}

fn render_dashboard(ui: &mut egui::Ui, dash: &DashboardModel) {
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(RichText::new("In-flight:").color(MUTED));
        ui.label(RichText::new(dash.in_flight.to_string()).strong());
        ui.separator();
        ui.label(RichText::new("Auth:").color(MUTED));
        if dash.auth_enabled {
            ui.colored_label(HEALTHY, "enabled");
        } else {
            ui.colored_label(MUTED, "disabled");
        }
    });

    section(ui, "Workers", |ui| render_workers(ui, dash));
    section(ui, "Cache", |ui| render_cache(ui, &dash.cache));
    section(ui, "Execution", |ui| render_exec(ui, &dash.exec));
    section(ui, "File server", |ui| {
        egui::Grid::new("fileserver").num_columns(2).show(ui, |ui| {
            kv(ui, "Read ops", dash.fileserver.read_ops.to_string());
            kv(ui, "Read bytes", format_bytes(dash.fileserver.read_bytes));
            kv(
                ui,
                "Inline bytes",
                format_bytes(dash.fileserver.inline_bytes),
            );
        });
    });
}

fn render_workers(ui: &mut egui::Ui, dash: &DashboardModel) {
    if dash.workers.is_empty() {
        ui.colored_label(MUTED, "No workers connected.");
        return;
    }
    egui::Grid::new("workers")
        .striped(true)
        .num_columns(7)
        .show(ui, |ui| {
            for h in [
                "",
                "Worker",
                "Endpoint",
                "CPU",
                "Running",
                "Idle",
                "Last ping",
            ] {
                ui.label(RichText::new(h).strong());
            }
            ui.end_row();

            for w in &dash.workers {
                let color = if w.healthy { HEALTHY } else { UNHEALTHY };
                ui.colored_label(color, "●").on_hover_text(if w.healthy {
                    "healthy"
                } else {
                    "unhealthy"
                });
                ui.label(&w.id);
                ui.label(&w.endpoint);
                ui.label(w.cpu.to_string());
                ui.label(w.running.to_string());
                ui.label(w.idle.to_string());
                ui.label(&w.last_ping);
                ui.end_row();
            }
        });
}

fn render_cache(ui: &mut egui::Ui, cache: &CacheModel) {
    if !cache.enabled {
        ui.colored_label(MUTED, "Caching disabled (no cache root configured).");
        return;
    }
    egui::Grid::new("cache").num_columns(2).show(ui, |ui| {
        let hit_rate = cache
            .hit_rate_pct
            .map(|p| format!("{p:.1}%"))
            .unwrap_or_else(|| "—".to_string());
        kv(ui, "Hit rate", hit_rate);
        kv(
            ui,
            "Hits / misses",
            format!("{} / {}", cache.hits, cache.misses),
        );
        kv(ui, "Size", format_bytes(cache.size_bytes));
        let cap = if cache.max_bytes == 0 {
            "uncapped".to_string()
        } else {
            format_bytes(cache.max_bytes)
        };
        kv(ui, "Cap", cap);
    });
}

fn render_exec(ui: &mut egui::Ui, exec: &ExecModel) {
    let total = exec.remote + exec.local + exec.fallback;
    egui::Grid::new("exec").num_columns(2).show(ui, |ui| {
        kv(ui, "Remote", share(exec.remote, total));
        kv(ui, "Local", share(exec.local, total));
        kv(ui, "Fallback", share(exec.fallback, total));
    });
}

fn share(count: u64, total: u64) -> String {
    if total == 0 {
        format!("{count}")
    } else {
        format!("{count} ({:.0}%)", count as f64 / total as f64 * 100.0)
    }
}

/// A titled section with an indented body.
fn section(ui: &mut egui::Ui, title: &str, body: impl FnOnce(&mut egui::Ui)) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).heading());
    ui.separator();
    body(ui);
}

/// One "key: value" grid row (key muted, value plain), ending the row.
fn kv(ui: &mut egui::Ui, key: &str, value: String) {
    ui.label(RichText::new(key).color(MUTED));
    ui.label(value);
    ui.end_row();
}
