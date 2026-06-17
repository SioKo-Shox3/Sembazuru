//! Service controls (M9.4e): live Running/Stopped/Not-installed badges for the
//! local daemon and worker (queried non-elevated) and Start/Stop buttons. A click
//! runs the elevation (`runas`) on a background thread so the UAC prompt and the
//! SCM wait never block the UI thread; the result refreshes the badges.

use eframe::egui::{self, Color32};

use crate::svcctl::{self, Action, Service, ServiceState};

const RUNNING: Color32 = Color32::from_rgb(0x4c, 0xaf, 0x50);
const STOPPED: Color32 = Color32::from_rgb(0xd9, 0x53, 0x4f);
const MUTED: Color32 = Color32::from_rgb(0x9e, 0x9e, 0x9e);

type ActionResult = (Service, Action, Result<i32, String>);

#[derive(Default)]
pub struct ServicesPanel {
    last_query: f64,
    daemon: Option<ServiceState>,
    worker: Option<ServiceState>,
    busy: bool,
    notice: String,
    result_rx: Option<std::sync::mpsc::Receiver<ActionResult>>,
}

impl ServicesPanel {
    pub fn render(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.poll_result();
        self.refresh_states(ui);

        ui.add_space(4.0);
        ui.label("Start or stop the local Sembazuru services. Remote workers run on");
        ui.label("other machines and are not controlled from here.");
        ui.add_space(8.0);

        let daemon = self.daemon.unwrap_or(ServiceState::Unknown);
        let worker = self.worker.unwrap_or(ServiceState::Unknown);
        self.row(ui, ctx, Service::Daemon, daemon);
        ui.add_space(4.0);
        self.row(ui, ctx, Service::Worker, worker);

        ui.add_space(10.0);
        ui.separator();
        if self.busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Waiting for elevation…");
            });
        }
        if !self.notice.is_empty() {
            ui.label(&self.notice);
        }
        ui.add_space(4.0);
        ui.colored_label(
            MUTED,
            "Start/Stop needs Administrator; Windows will prompt for elevation.",
        );
    }

    /// Lets the dashboard's "daemon down" affordance trigger a daemon start.
    pub fn start_daemon(&mut self, ctx: &egui::Context) {
        self.trigger(Service::Daemon, Action::Start, ctx);
    }

    fn row(
        &mut self,
        ui: &mut egui::Ui,
        ctx: &egui::Context,
        service: Service,
        state: ServiceState,
    ) {
        let mut do_start = false;
        let mut do_stop = false;
        ui.horizontal(|ui| {
            ui.colored_label(badge_color(state), "●");
            ui.label(format!("{} ({})", service.label(), state.label()));
            let can_start = matches!(state, ServiceState::Stopped) && !self.busy;
            let can_stop = matches!(state, ServiceState::Running) && !self.busy;
            if ui
                .add_enabled(can_start, egui::Button::new("Start"))
                .clicked()
            {
                do_start = true;
            }
            if ui
                .add_enabled(can_stop, egui::Button::new("Stop"))
                .clicked()
            {
                do_stop = true;
            }
        });
        if do_start {
            self.trigger(service, Action::Start, ctx);
        }
        if do_stop {
            self.trigger(service, Action::Stop, ctx);
        }
    }

    fn trigger(&mut self, service: Service, action: Action, ctx: &egui::Context) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.notice = format!("{} {}…", action.progressive(), service.label());

        let (tx, rx) = std::sync::mpsc::channel();
        self.result_rx = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = svcctl::request_action(service, action);
            let _ = tx.send((service, action, result));
            // Wake the UI so the result and refreshed badges show immediately.
            ctx.request_repaint();
        });
    }

    fn poll_result(&mut self) {
        let received = self.result_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some((service, action, result)) = received {
            self.busy = false;
            self.result_rx = None;
            self.notice = match result {
                Ok(0) => format!("{} {}: done.", action.progressive(), service.label()),
                Ok(code) => {
                    format!(
                        "{} {} failed (exit {code}).",
                        action.progressive(),
                        service.label()
                    )
                }
                Err(message) => format!("{} {}: {message}", action.progressive(), service.label()),
            };
            // Force an immediate state re-query on the next refresh.
            self.last_query = 0.0;
        }
    }

    fn refresh_states(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        if self.daemon.is_none() || now - self.last_query > 1.0 {
            self.last_query = now;
            self.daemon = Some(svcctl::query_state(Service::Daemon));
            self.worker = Some(svcctl::query_state(Service::Worker));
        }
    }
}

fn badge_color(state: ServiceState) -> Color32 {
    match state {
        ServiceState::Running => RUNNING,
        ServiceState::Stopped => STOPPED,
        ServiceState::NotInstalled | ServiceState::Unknown => MUTED,
    }
}
