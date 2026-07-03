//! Settings panel (M9.4d): reads and edits the daemon's persisted config through
//! the Status `GetConfig`/`SetConfig` RPCs, hiding the `SEMBAZURU_*` env behind a
//! form. Changes apply on the next daemon restart (no live reload, ADR 0008 §3).
//!
//! Secret discipline: the cluster token is presence-only on read (the form shows
//! "set" / "not set", never a value) and write-only on input. The text box buffer
//! is zeroized as soon as the edit is lowered to a request.

use eframe::egui;
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroize;

use crate::client::{ClientError, UiCommand};
use crate::model::{
    ConfigEdit, ConfigModel, EvictionOutcome, SecretString, SetConfigOutcome, TokenAction,
};

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
    notice: String,
    pending_config: Option<oneshot::Receiver<Result<ConfigModel, ClientError>>>,
    pending_save: Option<oneshot::Receiver<Result<SetConfigOutcome, ClientError>>>,
    pending_evict: Option<oneshot::Receiver<Result<EvictionOutcome, ClientError>>>,
}

impl ConfigPanel {
    pub fn render(&mut self, ui: &mut egui::Ui, commands: &mpsc::Sender<UiCommand>) {
        self.poll_replies();
        if !self.requested {
            self.request_config(commands);
        }

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.request_config(commands);
            }
            if ui.button("Save").clicked() {
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
                    "ワーカーが登録/heartbeat する待受アドレス。1台運用は 127.0.0.1:50070。LAN 参加は Join タブのトグルで設定。",
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
                    "ワーカーがファイル供給を受ける待受アドレス。LAN では 0.0.0.0 ではなく実 IP を使う（Join タブが自動設定）。",
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
        ui.separator();
        ui.label("Changes apply when the daemon restarts (no live reload).");
        if !self.notice.is_empty() {
            ui.add_space(4.0);
            ui.label(&self.notice);
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
    fn poll_replies(&mut self) {
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
                    self.notice = outcome.detail;
                    self.pending_save = None;
                    // Re-read so the presence flag reflects the just-saved token.
                    self.requested = false;
                }
                Ok(Err(e)) => {
                    self.notice = format!("Save failed: {e}");
                    self.pending_save = None;
                }
                Err(oneshot::error::TryRecvError::Empty) => {}
                Err(oneshot::error::TryRecvError::Closed) => {
                    self.notice = "Save failed: daemon unreachable".to_string();
                    self.pending_save = None;
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

        let cache_max_bytes = unit_to_bytes(
            self.cache_size_value.trim().parse::<f64>().unwrap_or(0.0),
            self.cache_size_unit,
        );
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

        let (tx, rx) = oneshot::channel();
        if commands.try_send(UiCommand::SetConfig(edit, tx)).is_ok() {
            self.notice = "Saving…".to_string();
            self.pending_save = Some(rx);
        } else {
            self.notice = "Busy — try again".to_string();
        }
    }

    fn evict(&mut self, commands: &mpsc::Sender<UiCommand>) {
        let (tx, rx) = oneshot::channel();
        if commands.try_send(UiCommand::TriggerEviction(tx)).is_ok() {
            self.notice = "Evicting…".to_string();
            self.pending_evict = Some(rx);
        }
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
