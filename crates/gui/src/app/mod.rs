//! The egui application shell (M9.4b).
//!
//! `SembazuruApp` owns the background tokio runtime and the Status poll loop, and
//! renders the dashboard each frame from the latest [`SharedState`] snapshot. The
//! UI thread never does I/O: it only reads the shared snapshot and (later) sends
//! [`UiCommand`]s. The poll loop's wake callback is wired to `egui` repaints so a
//! fresh snapshot shows up promptly without busy-looping.

use std::sync::Arc;

use eframe::egui;
use tokio::sync::mpsc;

use crate::client::{POLL_INTERVAL, SharedState, UiCommand, Waker, run_client};
use crate::tray::{Tray, TrayMessage};

mod config;
pub mod dashboard;
mod services;

/// Which view the window is showing.
#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum Tab {
    #[default]
    Dashboard,
    Services,
    Settings,
}

pub struct SembazuruApp {
    // The background runtime must outlive the app; dropping it cancels the poll.
    _runtime: tokio::runtime::Runtime,
    shared: SharedState,
    // Keeps the command channel open (so the poll loop keeps running) and carries
    // the config / service-control requests.
    commands: mpsc::Sender<UiCommand>,
    // The tray icon (`None` if the platform tray could not be created); polled each
    // frame for Show / Quit.
    tray: Option<Tray>,
    // Set when the user picks "Quit" so the close handler stops minimizing-to-tray.
    quitting: bool,
    tab: Tab,
    config: config::ConfigPanel,
    services: services::ServicesPanel,
}

impl SembazuruApp {
    /// Builds the app: starts the background runtime, wires the poll loop's wake to
    /// egui repaints, installs the tray, and begins polling the loopback Status
    /// service at `endpoint`.
    pub fn new(cc: &eframe::CreationContext<'_>, endpoint: String) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build the GUI's background tokio runtime");
        let shared = SharedState::new();
        let (commands, rx) = mpsc::channel(8);

        let ctx = cc.egui_ctx.clone();
        let wake: Waker = Arc::new(move || ctx.request_repaint());
        runtime.spawn(run_client(endpoint, shared.clone(), rx, wake));

        let tray = Tray::new(&cc.egui_ctx);

        Self {
            _runtime: runtime,
            shared,
            commands,
            tray,
            quitting: false,
            tab: Tab::default(),
            config: config::ConfigPanel::default(),
            services: services::ServicesPanel::default(),
        }
    }

    /// Drains tray interactions and applies the minimize-to-tray policy: closing
    /// the window hides it to the tray instead of quitting, unless "Quit" was
    /// chosen (or there is no tray to hide into).
    fn handle_tray(&mut self, ctx: &egui::Context) {
        if let Some(tray) = &mut self.tray {
            while let Some(message) = tray.poll() {
                match message {
                    TrayMessage::Show => {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                    }
                    TrayMessage::Quit => {
                        self.quitting = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                }
            }
        }

        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested && self.tray.is_some() && !self.quitting {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
    }
}

impl eframe::App for SembazuruApp {
    // eframe 0.34's `App::ui` hands us the root central `Ui` directly (no margin);
    // `update` is deprecated. We read the latest snapshot and render it.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.handle_tray(&ctx);

        egui::Panel::top("nav").show_inside(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Dashboard, "Dashboard");
                ui.selectable_value(&mut self.tab, Tab::Services, "Services");
                ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
            });
            ui.add_space(2.0);
        });

        match self.tab {
            Tab::Dashboard => {
                let state = self.shared.snapshot();
                if let Some(dashboard::DashAction::OpenServices) = dashboard::render(ui, &state) {
                    self.tab = Tab::Services;
                    self.services.start_daemon(&ctx);
                }
            }
            Tab::Services => self.services.render(ui, &ctx),
            Tab::Settings => self.config.render(ui, &self.commands),
        }

        // Keep heartbeat ages ticking even if a repaint signal is ever missed.
        ctx.request_repaint_after(POLL_INTERVAL);
    }
}
