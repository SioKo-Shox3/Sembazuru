//! Embeds a Windows application manifest declaring
//! `requestedExecutionLevel = asInvoker`, so the resident GUI runs NON-elevated
//! (ADR 0008 §4). Elevation happens only per-action, when the GUI re-launches
//! itself with the "runas" verb to start/stop a Windows Service. Pure Rust via
//! `embed-manifest`; a no-op on non-Windows targets.

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        use embed_manifest::manifest::ExecutionLevel;
        use embed_manifest::{embed_manifest, new_manifest};

        embed_manifest(
            new_manifest("Sembazuru.Gui").requested_execution_level(ExecutionLevel::AsInvoker),
        )
        .expect("embed application manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
