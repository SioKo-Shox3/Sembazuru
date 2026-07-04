//! Settings panel (M9.4d): reads and edits the daemon's persisted config through
//! the Status `GetConfig`/`SetConfig` RPCs, hiding the `SEMBAZURU_*` env behind a
//! form. Changes apply on the next daemon restart (no live reload, ADR 0008 §3).
//!
//! Secret discipline: the cluster token is presence-only on read (the form shows
//! "set" / "not set", never a value) and write-only on input. The text box buffer
//! is zeroized as soon as the edit is lowered to a request.

use std::net::Ipv4Addr;

use eframe::egui;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroize;

use crate::client::{ClientError, UiCommand};
use crate::model::{
    ConfigEdit, ConfigModel, EvictionOutcome, SecretString, SetConfigOutcome, TokenAction,
};
use crate::svcctl::Service;

use super::services::RestartOutcome;

const LAN_COORD_PORT: u16 = 50070;
const LAN_FILESERVER_PORT: u16 = 50072;
const STATUS_ADMIN_NOTICE: &str = "Daemon config mutation is disabled (§2.0 / ADR 0016). Enable status_admin (SEMBAZURU_STATUS_ADMIN=1 or status_admin = true), or use the owner-chosen config-write mechanism.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SizeUnit {
    Bytes,
    Mib,
    #[default]
    Gib,
}

impl SizeUnit {
    pub fn label(self) -> &'static str {
        match self {
            SizeUnit::Bytes => "bytes",
            SizeUnit::Mib => "MiB",
            SizeUnit::Gib => "GiB",
        }
    }

    fn factor(self) -> u64 {
        match self {
            SizeUnit::Bytes => 1,
            SizeUnit::Mib => 1024 * 1024,
            SizeUnit::Gib => 1024 * 1024 * 1024,
        }
    }
}

/// Convert a UI value+unit to bytes (0 stays 0 = uncapped).
pub fn unit_to_bytes(value: f64, unit: SizeUnit) -> u64 {
    if value <= 0.0 {
        return 0;
    }
    (value * unit.factor() as f64).round() as u64
}

/// Pick the most readable unit for a byte count (0 -> 0 GiB).
pub fn bytes_to_unit(bytes: u64) -> (f64, SizeUnit) {
    if bytes == 0 {
        return (0.0, SizeUnit::Gib);
    }
    if bytes.is_multiple_of(1024 * 1024 * 1024) {
        return (bytes as f64 / (1024.0 * 1024.0 * 1024.0), SizeUnit::Gib);
    }
    if bytes >= 1024 * 1024 {
        return (bytes as f64 / (1024.0 * 1024.0), SizeUnit::Mib);
    }
    (bytes as f64, SizeUnit::Bytes)
}

/// Daemon coord/fileserver addresses for LAN worker acceptance. Use a concrete
/// LAN IP so `local_addr()`-derived file-server URLs are routable by workers.
pub fn lan_daemon_addrs(lan_ip: &str, coord_port: u16, fileserver_port: u16) -> (String, String) {
    let lan_ip = lan_ip.trim();
    if let Ok(ip) = lan_ip.parse::<Ipv4Addr>() {
        assert!(
            !ip.is_unspecified(),
            "LAN worker daemon addresses must use a concrete LAN IP"
        );
    }
    (
        format!("{lan_ip}:{coord_port}"),
        format!("{lan_ip}:{fileserver_port}"),
    )
}

fn lan_daemon_edit_from_fields(
    lan_ip: &str,
    intake_addr: &str,
    status_addr: &str,
    cache_root: &str,
    trace_root: &str,
    cache_max_bytes: u64,
) -> ConfigEdit {
    let (coord_addr, fileserver_addr) =
        lan_daemon_addrs(lan_ip, LAN_COORD_PORT, LAN_FILESERVER_PORT);
    ConfigEdit {
        coord_addr,
        intake_addr: intake_addr.trim().to_string(),
        fileserver_addr,
        status_addr: status_addr.trim().to_string(),
        cache_root: cache_root.trim().to_string(),
        trace_root: trace_root.trim().to_string(),
        cache_max_bytes,
        token: TokenAction::Keep,
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum TokenMode {
    /// Leave the stored token untouched.
    #[default]
    Keep,
    /// Clear the token (disable auth).
    Clear,
    /// Set a new token (from the password box).
    Set,
}

#[derive(Default)]
pub struct ConfigPanel {
    requested: bool,
    loaded: Option<ConfigModel>,
    coord: String,
    intake: String,
    fileserver: String,
    status: String,
    cache_root: String,
    trace_root: String,
    cache_size_value: String,
    cache_size_unit: SizeUnit,
    token_mode: TokenMode,
    token_input: String,
    allow_lan_workers: bool,
    lan_detected: bool,
    lan_ips: Vec<String>,
    selected_lan_ip: Option<String>,
    notice: String,
    pending_config: Option<oneshot::Receiver<Result<ConfigModel, ClientError>>>,
    pending_save: Option<oneshot::Receiver<Result<SetConfigOutcome, ClientError>>>,
    pending_lan_daemon_restart: bool,
    pending_evict: Option<oneshot::Receiver<Result<EvictionOutcome, ClientError>>>,
}

impl ConfigPanel {
    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        commands: &mpsc::Sender<UiCommand>,
        services: &mut super::services::ServicesPanel,
        ctx: &egui::Context,
    ) {
        self.poll_replies(services, ctx);
        if !self.requested {
            self.request_config(commands);
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.request_config(commands);
            }
            if ui
                .add_enabled(self.pending_save.is_none(), egui::Button::new("Save"))
                .clicked()
            {
                self.save(commands);
            }
            if ui.button("Evict cache now").clicked() {
                self.evict(commands);
            }
        });

        if let Some(cfg) = &self.loaded {
            ui.add_space(6.0);
            ui.label(format!("Config file: {}", cfg.config_path));
            ui.label(if cfg.file_exists {
                "A daemon.toml exists on disk."
            } else {
                "No daemon.toml yet — saving will create it."
            });
        }

        ui.add_space(8.0);
        egui::Grid::new("config-fields")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                field_hint(
                    ui,
                    "Coordination addr",
                    &mut self.coord,
                    "ワーカーが登録/heartbeat する待受アドレス。1台運用は 127.0.0.1:50070。LAN 参加はこの画面の Allow LAN workers で設定。",
                );
                field_hint(
                    ui,
                    "Intake addr",
                    &mut self.intake,
                    "ローカル実行クライアントからの要求を受ける待受アドレス。通常は 127.0.0.1 のまま。",
                );
                field_hint(
                    ui,
                    "File-server addr",
                    &mut self.fileserver,
                    "ワーカーがファイル供給を受ける待受アドレス。LAN では 0.0.0.0 ではなく実 IP を使う（Allow LAN workers が自動設定）。",
                );
                field_hint(
                    ui,
                    "Status addr",
                    &mut self.status,
                    "GUI が daemon 状態を読む loopback Status RPC の待受アドレス。通常は 127.0.0.1:50073。",
                );
                field_hint(
                    ui,
                    "Cache root",
                    &mut self.cache_root,
                    "CAS とファイル供給キャッシュを置くディレクトリ。空ならキャッシュは無効。",
                );
                field_hint(
                    ui,
                    "Trace root",
                    &mut self.trace_root,
                    "診断トレースを書き出すディレクトリ。空なら既定の場所を使う。",
                );
                let cache_hint = "ディスクキャッシュの上限。0 は無制限。単位を GiB/MiB/bytes から選べます。";
                ui.label("Cache max (0 = uncapped)")
                    .on_hover_text(cache_hint);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.cache_size_value)
                            .desired_width(120.0),
                    )
                    .on_hover_text(cache_hint);
                    let combo = egui::ComboBox::from_id_salt("cache-unit")
                        .selected_text(self.cache_size_unit.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.cache_size_unit, SizeUnit::Gib, "GiB");
                            ui.selectable_value(&mut self.cache_size_unit, SizeUnit::Mib, "MiB");
                            ui.selectable_value(
                                &mut self.cache_size_unit,
                                SizeUnit::Bytes,
                                "bytes",
                            );
                        });
                    combo.response.on_hover_text(cache_hint);
                });
                ui.end_row();
            });

        ui.add_space(8.0);
        self.render_token(ui);

        ui.add_space(10.0);
        self.render_lan_workers(ui, commands);

        ui.add_space(10.0);
        ui.separator();
        ui.label("Changes apply when the daemon restarts (no live reload).");
        if !self.notice.is_empty() {
            ui.add_space(4.0);
            ui.label(&self.notice);
        }
    }

    fn render_lan_workers(&mut self, ui: &mut egui::Ui, commands: &mpsc::Sender<UiCommand>) {
        self.detect_lan_ips_once();

        let token_ready = self
            .loaded
            .as_ref()
            .map(|c| c.cluster_token_set)
            .unwrap_or(false);
        if !token_ready {
            self.allow_lan_workers = false;
        }

        ui.separator();
        ui.label(egui::RichText::new("Allow LAN workers").strong());
        let checkbox = ui.add_enabled(
            token_ready,
            egui::Checkbox::new(&mut self.allow_lan_workers, "Allow LAN workers"),
        );
        if token_ready {
            checkbox.on_hover_text(
                "Bind daemon coordination and file-server endpoints to a concrete LAN IP.",
            );
        } else {
            checkbox.on_hover_text(
                "Set a cluster token first; the daemon refuses unauthenticated LAN binds.",
            );
        }

        if self.allow_lan_workers && token_ready {
            ui.horizontal(|ui| {
                ui.label("LAN IP").on_hover_text(
                    "Concrete local IPv4 address workers can route to; never 0.0.0.0.",
                );
                egui::ComboBox::from_id_salt("daemon-lan-ip")
                    .selected_text(
                        self.selected_lan_ip
                            .as_deref()
                            .unwrap_or("No LAN IP detected"),
                    )
                    .show_ui(ui, |ui| {
                        for ip in &self.lan_ips {
                            ui.selectable_value(&mut self.selected_lan_ip, Some(ip.clone()), ip);
                        }
                    })
                    .response
                    .on_hover_text(
                        "Concrete local IPv4 address workers can route to; never 0.0.0.0.",
                    );
            });
        }

        let can_apply = token_ready
            && self.allow_lan_workers
            && self.selected_lan_ip.is_some()
            && self.pending_save.is_none();
        if ui
            .add_enabled(can_apply, egui::Button::new("Apply LAN settings"))
            .on_hover_text(
                "Persist LAN daemon addresses through Status SetConfig, then restart the daemon.",
            )
            .clicked()
        {
            self.apply_lan_settings(commands);
        }

        if self.allow_lan_workers && token_ready && self.selected_lan_ip.is_none() {
            ui.label("No usable LAN IPv4 address detected.");
        }
    }

    fn render_token(&mut self, ui: &mut egui::Ui) {
        let presence = self
            .loaded
            .as_ref()
            .map(|c| c.cluster_token_set)
            .unwrap_or(false);
        ui.label(egui::RichText::new("Cluster token").strong());
        ui.label(if presence {
            "Currently: set"
        } else {
            "Currently: not set"
        });
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.token_mode, TokenMode::Keep, "Keep");
            ui.radio_value(&mut self.token_mode, TokenMode::Clear, "Clear");
            ui.radio_value(&mut self.token_mode, TokenMode::Set, "Set");
        });
        if self.token_mode == TokenMode::Set {
            ui.add(
                egui::TextEdit::singleline(&mut self.token_input)
                    .password(true)
                    .hint_text("new token (write-only)"),
            );
        }
    }

    /// Polls the in-flight RPC replies (non-blocking) and updates the form.
    fn poll_replies(&mut self, services: &mut super::services::ServicesPanel, ctx: &egui::Context) {
        if let Some(rx) = &mut self.pending_config {
            match rx.try_recv() {
                Ok(Ok(cfg)) => {
                    self.apply_loaded(cfg);
                    self.pending_config = None;
                }
                Ok(Err(e)) => {
                    self.notice = format!("Load failed: {e}");
                    self.pending_config = None;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.notice = "Load failed: daemon unreachable".to_string();
                    self.pending_config = None;
                }
            }
        }
        if let Some(rx) = &mut self.pending_save {
            match rx.try_recv() {
                Ok(Ok(outcome)) => {
                    let restart_daemon = self.pending_lan_daemon_restart && outcome.ok;
                    let detail = outcome.detail;
                    self.pending_save = None;
                    self.pending_lan_daemon_restart = false;
                    // Re-read so the presence flag reflects the just-saved token.
                    self.requested = false;
                    if restart_daemon {
                        match services.restart(Service::Daemon, ctx) {
                            RestartOutcome::Started => {
                                self.notice = format!("{detail} Restarting daemon…");
                            }
                            RestartOutcome::Busy => {
                                self.notice = format!(
                                    "{detail} Daemon restart did not start because another service action is running. Use the Services tab to retry."
                                );
                            }
                            RestartOutcome::NoAction => {
                                self.notice = format!(
                                    "{detail} Daemon restart did not start because the service is not installed or its state is unknown. Use the Services tab to inspect it."
                                );
                            }
                        }
                    } else {
                        self.notice = detail;
                    }
                }
                Ok(Err(e)) => {
                    self.notice = set_config_error_notice(&e);
                    self.pending_save = None;
                    self.pending_lan_daemon_restart = false;
                    self.requested = false;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.notice = "Save failed: daemon unreachable".to_string();
                    self.pending_save = None;
                    self.pending_lan_daemon_restart = false;
                }
            }
        }
        if let Some(rx) = &mut self.pending_evict {
            match rx.try_recv() {
                Ok(Ok(ev)) => {
                    self.notice = format!(
                        "Evicted {} bytes; cache now {} bytes{}",
                        ev.freed_bytes,
                        ev.size_bytes_after,
                        if ev.cap_configured {
                            ""
                        } else {
                            " (no cap configured)"
                        }
                    );
                    self.pending_evict = None;
                }
                Ok(Err(e)) => {
                    self.notice = format!("Eviction failed: {e}");
                    self.pending_evict = None;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.notice = "Eviction failed: daemon unreachable".to_string();
                    self.pending_evict = None;
                }
            }
        }
    }

    fn apply_loaded(&mut self, cfg: ConfigModel) {
        self.coord = cfg.coord_addr.clone();
        self.intake = cfg.intake_addr.clone();
        self.fileserver = cfg.fileserver_addr.clone();
        self.status = cfg.status_addr.clone();
        self.cache_root = cfg.cache_root.clone();
        self.trace_root = cfg.trace_root.clone();
        let (cache_size_value, cache_size_unit) = bytes_to_unit(cfg.cache_max_bytes);
        self.cache_size_value = cache_size_value.to_string();
        self.cache_size_unit = cache_size_unit;
        self.allow_lan_workers = cfg.cluster_token_set && config_uses_lan_addr(&cfg);
        if let Some(ip) = config_lan_ip(&cfg) {
            self.selected_lan_ip = Some(ip);
        }
        self.loaded = Some(cfg);
    }

    fn request_config(&mut self, commands: &mpsc::Sender<UiCommand>) {
        let (tx, rx) = oneshot::channel();
        // Only mark "requested" once the send actually lands, so a transiently full
        // channel self-heals on the next frame instead of wedging the auto-load.
        if commands.try_send(UiCommand::GetConfig(tx)).is_ok() {
            self.requested = true;
            self.pending_config = Some(rx);
        }
    }

    fn save(&mut self, commands: &mpsc::Sender<UiCommand>) {
        let token = match self.token_mode {
            TokenMode::Keep => TokenAction::Keep,
            TokenMode::Clear => TokenAction::Clear,
            TokenMode::Set => TokenAction::Set(SecretString::from(self.token_input.as_str())),
        };
        // The token has been handed to the request; wipe the UI buffer.
        self.token_input.zeroize();
        self.token_input.clear();
        self.token_mode = TokenMode::Keep;

        let cache_max_bytes = self.current_cache_max_bytes();
        let edit = ConfigEdit {
            coord_addr: self.coord.trim().to_string(),
            intake_addr: self.intake.trim().to_string(),
            fileserver_addr: self.fileserver.trim().to_string(),
            status_addr: self.status.trim().to_string(),
            cache_root: self.cache_root.trim().to_string(),
            trace_root: self.trace_root.trim().to_string(),
            cache_max_bytes,
            token,
        };

        let _ = self.submit_config_edit(commands, edit, false, "Saving…");
    }

    fn apply_lan_settings(&mut self, commands: &mpsc::Sender<UiCommand>) {
        let token_ready = self
            .loaded
            .as_ref()
            .map(|c| c.cluster_token_set)
            .unwrap_or(false);
        if !token_ready {
            self.notice =
                "Set a cluster token before allowing LAN workers; unauthenticated LAN binds are refused.".to_string();
            return;
        }

        let Some(ip) = self
            .selected_lan_ip
            .clone()
            .or_else(|| self.lan_ips.first().cloned())
        else {
            self.notice = "No usable LAN IPv4 address detected.".to_string();
            return;
        };

        let edit = lan_daemon_edit_from_fields(
            &ip,
            &self.intake,
            &self.status,
            &self.cache_root,
            &self.trace_root,
            self.current_cache_max_bytes(),
        );
        let coord_addr = edit.coord_addr.clone();
        let fileserver_addr = edit.fileserver_addr.clone();

        if self.submit_config_edit(commands, edit, true, "Applying LAN settings…") {
            self.coord = coord_addr;
            self.fileserver = fileserver_addr;
        }
    }

    fn submit_config_edit(
        &mut self,
        commands: &mpsc::Sender<UiCommand>,
        edit: ConfigEdit,
        restart_daemon_after_save: bool,
        pending_notice: &str,
    ) -> bool {
        if self.pending_save.is_some() {
            self.notice = "Config save already in progress.".to_string();
            return false;
        }
        let (tx, rx) = oneshot::channel();
        if commands.try_send(UiCommand::SetConfig(edit, tx)).is_ok() {
            self.notice = pending_notice.to_string();
            self.pending_save = Some(rx);
            self.pending_lan_daemon_restart = restart_daemon_after_save;
            true
        } else {
            self.notice = "Busy — try again".to_string();
            self.pending_lan_daemon_restart = false;
            false
        }
    }

    fn evict(&mut self, commands: &mpsc::Sender<UiCommand>) {
        let (tx, rx) = oneshot::channel();
        if commands.try_send(UiCommand::TriggerEviction(tx)).is_ok() {
            self.notice = "Evicting…".to_string();
            self.pending_evict = Some(rx);
        }
    }

    fn current_cache_max_bytes(&self) -> u64 {
        unit_to_bytes(
            self.cache_size_value.trim().parse::<f64>().unwrap_or(0.0),
            self.cache_size_unit,
        )
    }

    fn detect_lan_ips_once(&mut self) {
        if self.lan_detected {
            return;
        }
        self.lan_ips = crate::net::lan_ipv4_candidates()
            .into_iter()
            .map(|ip| ip.to_string())
            .collect();
        if self.selected_lan_ip.is_none() {
            self.selected_lan_ip = self.lan_ips.first().cloned();
        }
        self.lan_detected = true;
    }
}

impl Drop for ConfigPanel {
    // Wipe the token text box if the panel is dropped (e.g. app exit) before a save
    // already zeroized it.
    fn drop(&mut self) {
        self.token_input.zeroize();
    }
}

/// One labelled single-line field row in the config grid, with a shared hover hint.
fn field_hint(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(label).on_hover_text(hint);
    ui.add(egui::TextEdit::singleline(value).desired_width(320.0))
        .on_hover_text(hint);
    ui.end_row();
}

fn set_config_error_notice(error: &ClientError) -> String {
    if status_admin_disabled(error) {
        format!("Save failed: {STATUS_ADMIN_NOTICE}")
    } else {
        format!("Save failed: {error}")
    }
}

fn status_admin_disabled(error: &ClientError) -> bool {
    error.0.contains("Status admin RPCs are disabled")
        || error.0.contains("SEMBAZURU_STATUS_ADMIN")
        || error.0.contains("config-mutation is opt-in")
}

fn config_uses_lan_addr(cfg: &ConfigModel) -> bool {
    config_lan_ip(cfg).is_some()
}

fn config_lan_ip(cfg: &ConfigModel) -> Option<String> {
    addr_lan_ip(&cfg.coord_addr).or_else(|| addr_lan_ip(&cfg.fileserver_addr))
}

fn addr_lan_ip(addr: &str) -> Option<String> {
    let host = addr.rsplit_once(':')?.0;
    let ip = host.parse::<Ipv4Addr>().ok()?;
    (!ip.is_loopback() && !ip.is_unspecified()).then(|| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::{lan_daemon_addrs, lan_daemon_edit_from_fields};

    #[test]
    fn lan_daemon_addrs_uses_selected_concrete_ip() {
        let (coord, fileserver) = lan_daemon_addrs("192.168.1.10", 50070, 50072);

        assert_eq!(coord, "192.168.1.10:50070");
        assert_eq!(fileserver, "192.168.1.10:50072");
        assert!(!coord.starts_with("0.0.0.0:"));
        assert!(!fileserver.starts_with("0.0.0.0:"));
    }

    #[test]
    fn lan_daemon_edit_preserves_non_lan_fields() {
        let req = lan_daemon_edit_from_fields(
            "192.168.1.10",
            "127.0.0.1:50071",
            "127.0.0.1:50073",
            "C:\\sbz-cache",
            "C:\\sbz-trace",
            8192,
        )
        .into_request();

        assert_eq!(req.coord_addr, "192.168.1.10:50070");
        assert_eq!(req.fileserver_addr, "192.168.1.10:50072");
        assert_eq!(req.intake_addr, "127.0.0.1:50071");
        assert_eq!(req.status_addr, "127.0.0.1:50073");
        assert_eq!(req.cache_root, "C:\\sbz-cache");
        assert_eq!(req.trace_root, "C:\\sbz-trace");
        assert_eq!(req.cache_max_bytes, 8192);
        assert_eq!(req.cluster_token, None);
    }
}
