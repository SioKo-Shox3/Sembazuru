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

mod dashboard;

pub struct SembazuruApp {
    // The background runtime must outlive the app; dropping it cancels the poll.
    _runtime: tokio::runtime::Runtime,
    shared: SharedState,
    // Held to keep the command channel open (so the poll loop keeps running) and
    // wired to the config / service controls in M9.4d–e.
    #[allow(dead_code)]
    commands: mpsc::Sender<UiCommand>,
}

impl SembazuruApp {
    /// Builds the app: starts the background runtime, wires the poll loop's wake to
    /// egui repaints, and begins polling the loopback Status service at `endpoint`.
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

        Self {
            _runtime: runtime,
            shared,
            commands,
        }
    }
}

impl eframe::App for SembazuruApp {
    // eframe 0.34's `App::ui` hands us the root central `Ui` directly (no margin);
    // `update` is deprecated. We read the latest snapshot and render it.
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let state = self.shared.snapshot();
        dashboard::render(ui, &state);
        // Keep heartbeat ages ticking even if a repaint signal is ever missed.
        ui.ctx().request_repaint_after(POLL_INTERVAL);
    }
}
