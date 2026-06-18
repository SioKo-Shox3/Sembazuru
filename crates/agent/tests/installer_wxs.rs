//! Anti-drift guard (M9.5b): the WiX MSI declares the two Windows services
//! natively via `ServiceInstall`/`ServiceControl`, so the service identity in
//! `installer/sembazuru.wxs` must stay in lockstep with the Rust definitions in
//! `crates/{agent,worker}/src/service.rs`. The MSI is the single registrar in the
//! installed product; the exes' own `install`/`uninstall` subcommands stay
//! dev-only (so there is no double registration). If a service constant changes
//! without the .wxs being updated, this test fails — catching the drift in CI
//! rather than on a user's machine.
//!
//! It reads the .wxs as text (no XML/WiX dependency) and asserts the *live* Rust
//! constants appear in it. `sembazuru-worker` is an `sembazuru-agent`
//! dev-dependency, so both services' constants are in scope here. Windows-only:
//! the `service` modules are `#[cfg(windows)]`.
#![cfg(windows)]

use std::path::PathBuf;

fn wxs_text() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../installer/sembazuru.wxs");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

#[test]
fn wxs_service_definitions_match_rust_constants() {
    use sembazuru_agent::service as daemon;
    use sembazuru_worker::service as worker;

    let wxs = wxs_text();

    // Daemon: SembazuruDaemon, LocalSystem (reads the developer source tree).
    assert!(
        wxs.contains(&format!("Name=\"{}\"", daemon::SERVICE_NAME)),
        "daemon ServiceInstall Name must be {}",
        daemon::SERVICE_NAME
    );
    assert!(
        wxs.contains(&format!("DisplayName=\"{}\"", daemon::DISPLAY_NAME)),
        "daemon DisplayName must be {}",
        daemon::DISPLAY_NAME
    );
    assert!(
        wxs.contains("Account=\"LocalSystem\""),
        "daemon service runs as LocalSystem (service.rs default account)"
    );

    // Worker: SembazuruWorker under its least-privilege virtual account.
    assert!(
        wxs.contains(&format!("Name=\"{}\"", worker::SERVICE_NAME)),
        "worker ServiceInstall Name must be {}",
        worker::SERVICE_NAME
    );
    assert!(
        wxs.contains(&format!("DisplayName=\"{}\"", worker::DISPLAY_NAME)),
        "worker DisplayName must be {}",
        worker::DISPLAY_NAME
    );
    let virtual_account = format!("NT SERVICE\\{}", worker::SERVICE_NAME);
    assert!(
        wxs.contains(&format!("Account=\"{virtual_account}\"")),
        "worker service runs under the virtual account {virtual_account} (service.rs default)"
    );

    // Both services are launched by the SCM with the `--service` argument.
    assert_eq!(daemon::SERVICE_ARG, worker::SERVICE_ARG);
    assert!(
        wxs.contains(&format!("Arguments=\"{}\"", daemon::SERVICE_ARG)),
        "ServiceInstall Arguments must register the SCM arg {}",
        daemon::SERVICE_ARG
    );
}
