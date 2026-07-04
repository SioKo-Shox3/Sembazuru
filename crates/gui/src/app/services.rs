//! Service controls (M9.4e): live Running/Stopped/Not-installed badges for the
//! local daemon and worker (queried non-elevated) and Start/Stop buttons. A click
//! runs the elevation (`runas`) on a background thread so the UAC prompt and the
//! SCM wait never block the UI thread; the result refreshes the badges.

use std::time::Duration;

use eframe::egui::{self, Color32};

use crate::svcctl::{self, Action, Service, ServiceState};

const RUNNING: Color32 = Color32::from_rgb(0x4c, 0xaf, 0x50);
const STOPPED: Color32 = Color32::from_rgb(0xd9, 0x53, 0x4f);
const MUTED: Color32 = Color32::from_rgb(0x9e, 0x9e, 0x9e);

type ActionResult = (Service, &'static str, Result<i32, String>);

pub enum RestartOutcome {
    Started,
    Busy,
    NoAction,
}

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

    pub fn restart(&mut self, service: Service, ctx: &egui::Context) -> RestartOutcome {
        if self.busy {
            self.notice = format!(
                "Cannot restart {}: another service action is already running.",
                service.label()
            );
            ctx.request_repaint();
            return RestartOutcome::Busy;
        }
        let current = svcctl::query_state(service);
        let plan = svcctl::restart_plan(current);
        if plan.is_empty() {
            self.notice = format!(
                "Restarting {}: no action for {} service.",
                service.label(),
                current.label()
            );
            self.last_query = 0.0;
            ctx.request_repaint();
            return RestartOutcome::NoAction;
        }
        self.trigger_actions(service, plan, "Restarting", ctx);
        RestartOutcome::Started
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
        self.trigger_actions(service, vec![action], action.progressive(), ctx);
    }

    fn trigger_actions(
        &mut self,
        service: Service,
        actions: Vec<Action>,
        operation: &'static str,
        ctx: &egui::Context,
    ) {
        if self.busy {
            return;
        }
        self.busy = true;
        self.notice = format!("{} {}…", operation, service.label());

        let (tx, rx) = std::sync::mpsc::channel();
        self.result_rx = Some(rx);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let result = run_actions(service, actions);
            let _ = tx.send((service, operation, result));
            // Wake the UI so the result and refreshed badges show immediately.
            ctx.request_repaint();
        });
    }

    fn poll_result(&mut self) {
        let received = self.result_rx.as_ref().and_then(|rx| rx.try_recv().ok());
        if let Some((service, operation, result)) = received {
            self.busy = false;
            self.result_rx = None;
            self.notice = match result {
                Ok(0) => format!("{} {}: done.", operation, service.label()),
                Ok(code) => {
                    format!("{} {} failed (exit {code}).", operation, service.label())
                }
                Err(message) => format!("{} {}: {message}", operation, service.label()),
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

const STOP_SETTLE_TIMEOUT: Duration = Duration::from_secs(8);
const STOP_SETTLE_POLL: Duration = Duration::from_millis(200);

fn run_actions(service: Service, actions: Vec<Action>) -> Result<i32, String> {
    run_actions_with(
        service,
        actions,
        svcctl::request_action,
        svcctl::query_state,
        std::thread::sleep,
        STOP_SETTLE_TIMEOUT,
        STOP_SETTLE_POLL,
    )
}

fn run_actions_with(
    service: Service,
    actions: Vec<Action>,
    mut request_action: impl FnMut(Service, Action) -> Result<i32, String>,
    mut query_state: impl FnMut(Service) -> ServiceState,
    mut sleep: impl FnMut(Duration),
    stop_timeout: Duration,
    stop_poll: Duration,
) -> Result<i32, String> {
    let mut last = Ok(0);
    let mut actions = actions.into_iter().peekable();
    while let Some(action) = actions.next() {
        last = request_action(service, action);
        if !matches!(last, Ok(0)) {
            break;
        }
        if action == Action::Stop
            && actions.peek().is_some_and(|next| *next == Action::Start)
            && !wait_until_stopped(
                service,
                &mut query_state,
                &mut sleep,
                stop_timeout,
                stop_poll,
            )
        {
            return Err("service did not stop before restart".to_string());
        }
    }
    last
}

fn wait_until_stopped(
    service: Service,
    query_state: &mut impl FnMut(Service) -> ServiceState,
    sleep: &mut impl FnMut(Duration),
    stop_timeout: Duration,
    stop_poll: Duration,
) -> bool {
    let mut waited = Duration::ZERO;
    loop {
        if query_state(service) == ServiceState::Stopped {
            return true;
        }
        if waited >= stop_timeout {
            return false;
        }
        sleep(stop_poll);
        waited += stop_poll;
    }
}

fn badge_color(state: ServiceState) -> Color32 {
    match state {
        ServiceState::Running => RUNNING,
        ServiceState::Stopped => STOPPED,
        ServiceState::NotInstalled | ServiceState::Unknown => MUTED,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use super::*;

    #[test]
    fn restart_waits_for_stopped_before_starting() {
        let calls = RefCell::new(Vec::new());
        let states = RefCell::new(VecDeque::from([
            ServiceState::Running,
            ServiceState::Stopped,
        ]));

        let result = run_actions_with(
            Service::Worker,
            vec![Action::Stop, Action::Start],
            |_, action| {
                calls.borrow_mut().push(match action {
                    Action::Stop => "request stop",
                    Action::Start => "request start",
                });
                Ok(0)
            },
            |_| {
                calls.borrow_mut().push("query");
                states
                    .borrow_mut()
                    .pop_front()
                    .unwrap_or(ServiceState::Stopped)
            },
            |_| calls.borrow_mut().push("sleep"),
            Duration::from_millis(400),
            Duration::from_millis(200),
        );

        assert_eq!(result, Ok(0));
        assert_eq!(
            calls.into_inner(),
            vec!["request stop", "query", "sleep", "query", "request start"]
        );
    }

    #[test]
    fn restart_does_not_start_when_stop_never_settles() {
        let calls = RefCell::new(Vec::new());

        let result = run_actions_with(
            Service::Worker,
            vec![Action::Stop, Action::Start],
            |_, action| {
                calls.borrow_mut().push(match action {
                    Action::Stop => "request stop",
                    Action::Start => "request start",
                });
                Ok(0)
            },
            |_| {
                calls.borrow_mut().push("query");
                ServiceState::Running
            },
            |_| calls.borrow_mut().push("sleep"),
            Duration::from_millis(400),
            Duration::from_millis(200),
        );

        assert_eq!(
            result,
            Err("service did not stop before restart".to_string())
        );
        assert!(!calls.into_inner().contains(&"request start"));
    }
}
