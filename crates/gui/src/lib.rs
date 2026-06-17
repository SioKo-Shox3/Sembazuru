//! `sembazuru-gui`: the resident, user-session GUI for Sembazuru (M9.4).
//!
//! A non-elevated process that lives in the tray, polls the daemon's loopback
//! Status service to show cluster/cache state, hides the `SEMBAZURU_*` settings
//! behind a config panel, and starts/stops the local daemon and worker Windows
//! Services (ADR 0008 §2–4). The daemon and worker themselves stay as services
//! (session 0); this is the user-session companion that talks to them.
//!
//! The crate is split so the load-bearing logic is testable without a display:
//!
//! - [`model`]: pure proto → view-model mapping (no I/O, no egui) — unit-tested.
//! - [`client`]: the async loopback Status client — integration-tested headless
//!   against an in-process `serve_status_service`.
//!
//! The tray residency and the (elevation-gated) service controls land in later
//! sub-commits and depend only on these.

pub mod app;
pub mod client;
pub mod model;
