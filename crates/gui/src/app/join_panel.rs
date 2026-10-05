//! Join-a-cluster wizard panel (M11): collects worker settings, previews the validated
//! worker.toml, and hands the whole join to an elevated helper as one transaction.
//!
//! The panel does not restart anything itself. Stopping the services, writing the three targets,
//! and starting them again all belong to the one transaction the helper runs (ADR 0018), because
//! the store refuses a write while the services hold their own lease on it.

use eframe::egui;

use std::sync::Arc;
use std::sync::mpsc::Receiver;

use crate::join::submit::{JoinSubmitter, PipeJoinSubmitter, outcome_notice, payload_for};
use crate::join::transport::TransportError;
use crate::join::worker_toml::{JoinError, JoinInput, render_worker_toml, validate};

pub struct JoinPanel {
    agent: String,
    cluster_token: String,
    listen_addr: String,
    advertise: String,
    participation_mode: String,
    allow_insecure_lan: bool,
    detected: bool,
    lan_ips: Vec<String>,
    detected_lan_ip: Option<String>,
    submitter: Arc<dyn JoinSubmitter>,
    notice: String,
    /// Set while a join runs on its own thread. The panel keeps drawing meanwhile.
    busy: bool,
    result_rx: Option<Receiver<Result<(), TransportError>>>,
}

impl Default for JoinPanel {
    fn default() -> Self {
        Self {
            agent: "http://127.0.0.1:50070".to_string(),
            cluster_token: String::new(),
            listen_addr: "0.0.0.0:50061".to_string(),
            advertise: String::new(),
            participation_mode: "adaptive".to_string(),
            allow_insecure_lan: false,
            detected: false,
            lan_ips: Vec::new(),
            detected_lan_ip: None,
            submitter: Arc::new(PipeJoinSubmitter),
            notice: String::new(),
            busy: false,
            result_rx: None,
        }
    }
}

impl JoinPanel {
    pub fn set_fields_for_test(
        &mut self,
        agent: &str,
        cluster_token: &str,
        listen_addr: &str,
        advertise: &str,
        participation_mode: &str,
        allow_insecure_lan: bool,
    ) {
        self.agent = agent.to_string();
        self.cluster_token = cluster_token.to_string();
        self.listen_addr = listen_addr.to_string();
        self.advertise = advertise.to_string();
        self.participation_mode = participation_mode.to_string();
        self.allow_insecure_lan = allow_insecure_lan;
    }

    pub fn set_detected_lan_ip_for_test(&mut self, ip: Option<String>) {
        self.detected = true;
        self.detected_lan_ip = ip.clone();
        self.lan_ips = ip.into_iter().collect();
    }

    /// The wizard's current answers, in the shape validation accepts.
    fn input(&self) -> JoinInput {
        JoinInput {
            agent: self.agent.clone(),
            cluster_token: self.cluster_token.clone(),
            listen_addr: self.listen_addr.clone(),
            advertise: self.advertise.clone(),
            detected_lan_ip: self.detected_lan_ip_for_input(),
            participation_mode: self.participation_mode.clone(),
            allow_insecure_lan: self.allow_insecure_lan,
        }
    }

    pub fn preview_toml(&self) -> Result<String, JoinError> {
        validate(self.input()).map(|join| render_worker_toml(&join))
    }

    pub fn render(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        self.poll_result();
        self.detect_lan_ips_once();

        ui.heading("Join a cluster as a worker");
        ui.add_space(8.0);
        egui::Grid::new("join-fields")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                field_hint(
                    ui,
                    "Agent URL",
                    &mut self.agent,
                    "Coordinator URL of the machine running the daemon, including http://.",
                );
                ui.label("Cluster token").on_hover_text(
                    "Shared token configured on the daemon before LAN workers are allowed.",
                );
                ui.add(
                    egui::TextEdit::singleline(&mut self.cluster_token)
                        .password(true)
                        .desired_width(320.0),
                )
                .on_hover_text(
                    "Write-only local buffer; saved into worker.toml when Apply succeeds.",
                );
                ui.end_row();
                field_hint(
                    ui,
                    "Listen addr",
                    &mut self.listen_addr,
                    "Worker execution listener. Use 0.0.0.0:50061 for LAN workers.",
                );
                field_hint(
                    ui,
                    "Advertise URL",
                    &mut self.advertise,
                    "Optional. Leave empty to derive http://<selected LAN IP>:<listen port>.",
                );
                ui.label("Detected LAN IP").on_hover_text(
                    "Used to auto-fill advertise when the listen address is unspecified.",
                );
                egui::ComboBox::from_id_salt("join-lan-ip")
                    .selected_text(
                        self.detected_lan_ip
                            .as_deref()
                            .unwrap_or("No LAN IP detected"),
                    )
                    .show_ui(ui, |ui| {
                        for ip in &self.lan_ips {
                            ui.selectable_value(&mut self.detected_lan_ip, Some(ip.clone()), ip);
                        }
                    });
                ui.end_row();
                ui.label("Participation")
                    .on_hover_text("How the worker participates in remote execution scheduling.");
                egui::ComboBox::from_id_salt("join-participation")
                    .selected_text(self.participation_mode.as_str())
                    .show_ui(ui, |ui| {
                        ui.selectable_value(
                            &mut self.participation_mode,
                            "always".to_string(),
                            "always",
                        );
                        ui.selectable_value(
                            &mut self.participation_mode,
                            "adaptive".to_string(),
                            "adaptive",
                        );
                        ui.selectable_value(&mut self.participation_mode, "off".to_string(), "off");
                    });
                ui.end_row();
            });

        ui.checkbox(&mut self.allow_insecure_lan, "Allow insecure LAN execution")
            .on_hover_text(
                "Required for the current LAN worker flow; only use on a trusted network.",
            );

        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Preview worker.toml").clicked() {
                self.notice = self
                    .preview_toml()
                    .unwrap_or_else(|e| format!("Invalid join settings: {e:?}"));
            }
            let join = ui
                .add_enabled(!self.busy, egui::Button::new("Join (asks for elevation)"))
                .on_hover_text(
                    "Saves the token and the worker configuration together, then restarts the \
                     daemon and the worker on them. Windows asks for administrator approval.",
                );
            if join.clicked() {
                let ctx = ctx.clone();
                self.apply(move || ctx.request_repaint());
            }
        });

        if self.busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("The join is running. The services restart as part of it.");
            });
        }
        if !self.notice.is_empty() {
            ui.separator();
            ui.label(&self.notice);
        }
    }

    fn detect_lan_ips_once(&mut self) {
        if self.detected {
            return;
        }
        self.lan_ips = crate::net::lan_ipv4_candidates()
            .into_iter()
            .map(|ip| ip.to_string())
            .collect();
        if self.detected_lan_ip.is_none() {
            self.detected_lan_ip = self.lan_ips.first().cloned();
        }
        self.detected = true;
    }

    fn detected_lan_ip_for_input(&self) -> Option<String> {
        self.detected_lan_ip
            .clone()
            .or_else(|| self.lan_ips.first().cloned())
    }

    /// Validates, builds the one transaction, and starts handing it over.
    ///
    /// The hand-over runs on its own thread. A join waits for a person to answer an elevation
    /// prompt and then for two services to stop and start, which is minutes in the worst case; on
    /// the drawing thread that would be a frozen window. `repaint` wakes the UI when the result
    /// lands — a closure rather than the egui context, so this logic stays testable without one.
    pub fn apply(&mut self, repaint: impl Fn() + Send + 'static) {
        if self.busy {
            return;
        }
        let join = match validate(self.input()) {
            Ok(join) => join,
            Err(err) => {
                self.notice = format!("Invalid join settings: {err:?}");
                return;
            }
        };
        let payload = match payload_for(&join) {
            Ok(payload) => payload,
            Err(err) => {
                // The envelope refuses what the store would refuse anyway, so say which field.
                self.notice = format!("Invalid join settings: {err}");
                return;
            }
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let submitter = Arc::clone(&self.submitter);
        self.busy = true;
        self.result_rx = Some(rx);
        self.notice = "Joining. Windows will ask for administrator approval…".to_owned();
        std::thread::spawn(move || {
            let result = submitter.submit(&payload);
            // The receiver is gone only if the panel itself is gone, and then nobody is waiting.
            let _ = tx.send(result);
            repaint();
        });
    }

    /// Takes the result of a finished join, if one has landed. Never blocks.
    fn poll_result(&mut self) {
        if let Some(result) = self.result_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.busy = false;
            self.result_rx = None;
            self.notice = outcome_notice(result);
        }
    }

    /// Replaces the elevation-backed submitter. Only tests stand in for the helper.
    pub fn set_submitter_for_test(&mut self, submitter: Arc<dyn JoinSubmitter>) {
        self.submitter = submitter;
    }

    /// Blocks until a started join reports back. Tests only; the panel polls instead.
    pub fn wait_for_result_for_test(&mut self) {
        if let Some(rx) = self.result_rx.take() {
            let result = rx.recv().expect("the join thread reports its result");
            self.busy = false;
            self.notice = outcome_notice(result);
        }
    }

    /// The line the operator is currently shown.
    pub fn notice_for_test(&self) -> &str {
        &self.notice
    }
}

fn field_hint(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(label).on_hover_text(hint);
    ui.add(egui::TextEdit::singleline(value).desired_width(320.0))
        .on_hover_text(hint);
    ui.end_row();
}
