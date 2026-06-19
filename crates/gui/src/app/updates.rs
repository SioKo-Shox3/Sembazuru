//! The GUI-side controller for self-update (ADR 0009): a small state machine driven
//! by user actions, plus the modal "Software update" dialog.
//!
//! The detection/download/verify/apply *steps* live in [`crate::update`],
//! [`crate::verify`], and [`crate::svcctl`]; this module sequences them and surfaces
//! progress. The flow is strictly: **check → (user) download → verify → (user)
//! install**. Nothing is fetched without a click, nothing is run before its
//! signature and publisher are verified, and there is no background polling — a
//! check happens only from the tray "Check for updates…" or one silent check at
//! launch (which surfaces a dialog *only* if an update is actually available).
//!
//! Async steps run on the app's tokio runtime and publish their result into a
//! shared [`Phase`]; the UI thread renders whatever phase it finds each frame and a
//! repaint is requested when the phase changes.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use eframe::egui;
use tokio::runtime::Handle;

use crate::update::{self, AvailableUpdate, UpdateCheck};
use crate::{svcctl, verify};

/// Where the update flow currently is. `Idle` draws no dialog; every other phase
/// draws the modal.
#[derive(Clone)]
enum Phase {
    Idle,
    Checking,
    UpToDate(String),
    Available(AvailableUpdate),
    Downloading(AvailableUpdate),
    Verifying(AvailableUpdate),
    ReadyToInstall {
        update: AvailableUpdate,
        msi: PathBuf,
    },
    Installing,
    Installed,
    Error(String),
}

/// Owns the shared phase and the runtime handle used to drive the async steps.
pub struct Updates {
    phase: Arc<Mutex<Phase>>,
    rt: Handle,
    /// An egui context clone so a finished async step can wake the UI to repaint.
    ctx: egui::Context,
    /// Bumped by every user action (and `dismiss`). An async step stamps the
    /// generation it started under and only writes its result back if it is still
    /// current — so a result that finishes after the user moved on (e.g. the silent
    /// launch check completing after the user dismissed a manual one) is dropped
    /// instead of resurrecting a stale dialog.
    generation: Arc<AtomicU64>,
}

fn set(phase: &Arc<Mutex<Phase>>, next: Phase) {
    *phase.lock().unwrap_or_else(|e| e.into_inner()) = next;
}

fn get(phase: &Arc<Mutex<Phase>>) -> Phase {
    phase.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Writes `next` (and wakes the UI) only if `my_gen` is still the current
/// generation — i.e. no newer user action has superseded this async step.
fn set_if_current(
    phase: &Arc<Mutex<Phase>>,
    generation: &Arc<AtomicU64>,
    my_gen: u64,
    ctx: &egui::Context,
    next: Phase,
) {
    if generation.load(Ordering::SeqCst) == my_gen {
        set(phase, next);
        ctx.request_repaint();
    }
}

impl Updates {
    pub fn new(rt: Handle, ctx: egui::Context) -> Self {
        Self {
            phase: Arc::new(Mutex::new(Phase::Idle)),
            rt,
            ctx,
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Bumps and returns the new generation, invalidating any in-flight async step.
    fn next_gen(&self) -> u64 {
        self.generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1)
    }

    /// Starts a release check. `manual` = the user asked (tray menu): then even an
    /// "up to date" / error result is shown. A non-manual (at-launch) check stays
    /// silent unless it finds an available update.
    pub fn start_check(&self, manual: bool) {
        let my_gen = self.next_gen();
        if manual {
            set(&self.phase, Phase::Checking);
            self.ctx.request_repaint();
        }
        let phase = self.phase.clone();
        let ctx = self.ctx.clone();
        let generation = self.generation.clone();
        self.rt.spawn(async move {
            let next = match update::check_for_update().await {
                Ok(UpdateCheck::Available(u)) => Phase::Available(u),
                Ok(UpdateCheck::UpToDate { current }) if manual => {
                    Phase::UpToDate(current.to_string())
                }
                Ok(UpdateCheck::UpToDate { .. }) => Phase::Idle,
                Err(e) if manual => Phase::Error(e.to_string()),
                Err(_) => Phase::Idle,
            };
            set_if_current(&phase, &generation, my_gen, &ctx, next);
        });
    }

    /// Downloads the update's MSI to a temp file, then verifies its signature and
    /// publisher. Only a verified file reaches `ReadyToInstall`; a failed download or
    /// verification ends in `Error` and the (unverified) file is removed.
    fn start_download(&self, update: AvailableUpdate) {
        let my_gen = self.next_gen();
        set(&self.phase, Phase::Downloading(update.clone()));
        self.ctx.request_repaint();
        let phase = self.phase.clone();
        let ctx = self.ctx.clone();
        let generation = self.generation.clone();
        self.rt.spawn(async move {
            let next = match update::download_msi(&update, &std::env::temp_dir()).await {
                Ok(msi) => {
                    set_if_current(
                        &phase,
                        &generation,
                        my_gen,
                        &ctx,
                        Phase::Verifying(update.clone()),
                    );
                    let to_verify = msi.clone();
                    match tokio::task::spawn_blocking(move || verify::verify_msi(&to_verify)).await
                    {
                        Ok(Ok(())) => Phase::ReadyToInstall { update, msi },
                        Ok(Err(e)) => {
                            // Never leave an unverified installer on disk.
                            let _ = std::fs::remove_file(&msi);
                            Phase::Error(format!("signature check failed: {e}"))
                        }
                        Err(_) => {
                            let _ = std::fs::remove_file(&msi);
                            Phase::Error("the verification task did not complete".into())
                        }
                    }
                }
                Err(e) => Phase::Error(e.to_string()),
            };
            set_if_current(&phase, &generation, my_gen, &ctx, next);
        });
    }

    /// Applies a verified MSI via an elevated, UAC-prompted `msiexec /i … /passive`
    /// (the same elevation path as service control). `MajorUpgrade` does the in-place
    /// upgrade; the GUI stays non-elevated and prompts a restart on success.
    fn start_install(&self, msi: PathBuf) {
        let my_gen = self.next_gen();
        set(&self.phase, Phase::Installing);
        self.ctx.request_repaint();
        let phase = self.phase.clone();
        let ctx = self.ctx.clone();
        let generation = self.generation.clone();
        self.rt.spawn(async move {
            // Re-verify immediately before running, closing the TOCTOU window between
            // the earlier check and now: the file we hand to an elevated msiexec must
            // *still* be validly signed and publisher-pinned, even if something tried
            // to swap the temp file in the meantime.
            let to_verify = msi.clone();
            let reverify =
                tokio::task::spawn_blocking(move || verify::verify_msi(&to_verify)).await;
            if !matches!(reverify, Ok(Ok(()))) {
                let _ = std::fs::remove_file(&msi);
                let why = match reverify {
                    Ok(Err(e)) => format!("re-check before install failed: {e}"),
                    _ => "the verification task did not complete".to_string(),
                };
                set_if_current(&phase, &generation, my_gen, &ctx, Phase::Error(why));
                return;
            }

            let program = msiexec_path();
            // The only interpolated value is our own sanitized temp-file path.
            let params = format!("/i \"{}\" /passive", msi.display());
            let next = match tokio::task::spawn_blocking(move || {
                svcctl::elevate_and_run(&program, &params)
            })
            .await
            {
                Ok(Ok(0)) => Phase::Installed,
                Ok(Ok(code)) => Phase::Error(format!("the installer exited with code {code}")),
                Ok(Err(e)) => Phase::Error(e),
                Err(_) => Phase::Error("the install task did not complete".into()),
            };
            set_if_current(&phase, &generation, my_gen, &ctx, next);
        });
    }

    fn dismiss(&self) {
        // Bump the generation so any in-flight step's result is dropped rather than
        // reopening the dialog after the user closed it.
        self.next_gen();
        set(&self.phase, Phase::Idle);
    }

    /// Draws the modal dialog for the current phase (nothing when `Idle`). Button
    /// clicks drive the next async step.
    pub fn render(&self, ctx: &egui::Context) {
        let phase = get(&self.phase);
        if matches!(phase, Phase::Idle) {
            return;
        }
        egui::Window::new("Software update")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| self.render_body(ui, phase));
    }

    fn render_body(&self, ui: &mut egui::Ui, phase: Phase) {
        ui.set_min_width(320.0);
        match phase {
            Phase::Idle => {}
            Phase::Checking => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Checking for updates…");
                });
            }
            Phase::UpToDate(current) => {
                ui.label(format!("Sembazuru {current} is up to date."));
                if ui.button("Close").clicked() {
                    self.dismiss();
                }
            }
            Phase::Available(update) => {
                ui.label(format!(
                    "Version {} is available (you have {}).",
                    update.tag,
                    update::current_version()
                ));
                ui.hyperlink_to("Release notes", &update.notes_url);
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Download & verify").clicked() {
                        self.start_download(update.clone());
                    }
                    if ui.button("Later").clicked() {
                        self.dismiss();
                    }
                });
            }
            Phase::Downloading(update) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!("Downloading {}…", update.asset_name));
                });
            }
            Phase::Verifying(update) => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!("Verifying {}'s signature…", update.tag));
                });
            }
            Phase::ReadyToInstall { update, msi } => {
                ui.label(format!(
                    "Version {} is verified and ready to install.",
                    update.tag
                ));
                ui.colored_label(
                    egui::Color32::from_rgb(0x4c, 0xaf, 0x50),
                    "✔ signature and publisher verified",
                );
                ui.label("Installing will prompt for administrator approval (UAC).");
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button("Install").clicked() {
                        self.start_install(msi.clone());
                    }
                    if ui.button("Cancel").clicked() {
                        let _ = std::fs::remove_file(&msi);
                        self.dismiss();
                    }
                });
            }
            Phase::Installing => {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label("Installing… approve the administrator prompt to continue.");
                });
            }
            Phase::Installed => {
                ui.label("Update installed. Restart Sembazuru to finish applying it.");
                if ui.button("Close").clicked() {
                    self.dismiss();
                }
            }
            Phase::Error(message) => {
                ui.colored_label(egui::Color32::from_rgb(0xd3, 0x2f, 0x2f), "Update failed");
                ui.label(message);
                if ui.button("Close").clicked() {
                    self.dismiss();
                }
            }
        }
    }
}

/// The full path to `msiexec.exe` under the system directory, so the elevated launch
/// resolves no PATH/CWD search (a planted `msiexec.exe` cannot hijack the update).
fn msiexec_path() -> std::ffi::OsString {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let mut path = PathBuf::from(root);
    path.push("System32");
    path.push("msiexec.exe");
    path.into_os_string()
}
