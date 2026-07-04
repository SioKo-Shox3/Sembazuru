//! Join-a-cluster wizard panel (M11): collects worker settings, previews the
//! validated worker.toml, and asks the configured writer to persist it before
//! restarting the local worker service.

use eframe::egui;

use crate::join::worker_toml::{JoinError, JoinInput, render_worker_toml, validate};
use crate::join::writer::{ConfigWriter, StubConfigWriter, WriteError, WriteTarget};
use crate::svcctl::Service;

use super::services::RestartOutcome;

const CONFIG_WRITE_UNCONFIGURED: &str = "config-write mechanism not configured (roadmap §2.0, owner-managed); cannot persist config from the GUI yet";
const CONFIG_WRITE_DOC_LABEL: &str = "docs/superpowers/plans/2026-07-02-gui-completion.md §2.0";

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
    writer: Box<dyn ConfigWriter>,
    notice: String,
    show_write_docs_link: bool,
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
            writer: Box::new(StubConfigWriter),
            notice: String::new(),
            show_write_docs_link: false,
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

    pub fn preview_toml(&self) -> Result<String, JoinError> {
        let input = JoinInput {
            agent: self.agent.clone(),
            cluster_token: self.cluster_token.clone(),
            listen_addr: self.listen_addr.clone(),
            advertise: self.advertise.clone(),
            detected_lan_ip: self.detected_lan_ip_for_input(),
            participation_mode: self.participation_mode.clone(),
            allow_insecure_lan: self.allow_insecure_lan,
        };
        validate(input).map(|join| render_worker_toml(&join))
    }

    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        services: &mut super::services::ServicesPanel,
        ctx: &egui::Context,
    ) {
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
                self.show_write_docs_link = false;
                self.notice = self
                    .preview_toml()
                    .unwrap_or_else(|e| format!("Invalid join settings: {e:?}"));
            }
            if ui.button("Apply & restart worker").clicked() {
                self.apply(services, ctx);
            }
        });

        if !self.notice.is_empty() {
            ui.separator();
            ui.label(&self.notice);
            if self.show_write_docs_link {
                ui.hyperlink_to(CONFIG_WRITE_DOC_LABEL, CONFIG_WRITE_DOC_LABEL);
            }
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

    fn apply(&mut self, services: &mut super::services::ServicesPanel, ctx: &egui::Context) {
        self.show_write_docs_link = false;
        let toml = match self.preview_toml() {
            Ok(toml) => toml,
            Err(err) => {
                self.notice = format!("Invalid join settings: {err:?}");
                return;
            }
        };

        match self.writer.write(WriteTarget::WorkerToml, &toml) {
            Ok(()) => match services.restart(Service::Worker, ctx) {
                RestartOutcome::Started => {
                    self.notice = "worker.toml saved; restarting Worker service…".to_string();
                }
                RestartOutcome::Busy => {
                    self.notice = "worker.toml saved; Worker restart did not start because another service action is running. Use the Services tab to retry.".to_string();
                }
                RestartOutcome::NoAction => {
                    self.notice = "worker.toml saved; Worker restart did not start because the service is not installed or its state is unknown. Use the Services tab to inspect it.".to_string();
                }
            },
            Err(WriteError::MechanismUnconfigured) => {
                self.notice = CONFIG_WRITE_UNCONFIGURED.to_string();
                self.show_write_docs_link = true;
            }
            Err(err) => {
                self.notice = format!("Write failed: {err}");
            }
        }
    }
}

fn field_hint(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(label).on_hover_text(hint);
    ui.add(egui::TextEdit::singleline(value).desired_width(320.0))
        .on_hover_text(hint);
    ui.end_row();
}
