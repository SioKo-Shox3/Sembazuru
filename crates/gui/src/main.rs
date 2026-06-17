//! `sembazuru-gui` entry point (M9.4b–c).
//!
//! Enforces a single resident instance, resolves the loopback Status endpoint
//! (refusing a non-loopback override), then launches the resident, tray-backed
//! dashboard window. The config editor (M9.4d) and the `--svcctl` elevation
//! dispatch + service controls (M9.4e) build on this.

use sembazuru_gui::app::SembazuruApp;
use sembazuru_gui::client::status_endpoint;

fn main() -> eframe::Result<()> {
    // The hidden elevated helper path: when re-launched with `--svcctl <action>
    // <service>` (via "runas"), do the SCM op and exit — no window, no single-
    // instance lock. Dispatched before anything else, mirroring the daemon's
    // thin-bin arg handling.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--svcctl") {
        std::process::exit(sembazuru_gui::svcctl::run_cli(&args));
    }

    if !acquire_single_instance() {
        eprintln!("sembazuru-gui: another instance is already running");
        return Ok(());
    }

    let endpoint = match status_endpoint() {
        Ok(endpoint) => endpoint,
        Err(message) => {
            eprintln!("sembazuru-gui: {message}");
            std::process::exit(2);
        }
    };

    let native_options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([900.0, 600.0])
            .with_min_inner_size([560.0, 360.0])
            .with_title("Sembazuru"),
        ..Default::default()
    };

    eframe::run_native(
        "Sembazuru",
        native_options,
        Box::new(move |cc| Ok(Box::new(SembazuruApp::new(cc, endpoint)))),
    )
}

/// Returns `true` if this is the only running instance (and registers us as such).
///
/// On Windows this is a session-local named mutex held open for the process
/// lifetime: a second launch sees `ERROR_ALREADY_EXISTS` and bows out, so there is
/// never a second tray icon. The handle is deliberately never closed — closing it
/// would release the lock.
#[cfg(windows)]
fn acquire_single_instance() -> bool {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    let name: Vec<u16> = "Sembazuru-GUI-single-instance\0".encode_utf16().collect();
    // SAFETY: `name` is a valid NUL-terminated UTF-16 string; null security attrs
    // and a non-owning initial state are the documented defaults.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
    let already_running = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if handle.is_null() {
        // Could not create the mutex at all; do not block startup over it.
        return true;
    }
    !already_running
}

#[cfg(not(windows))]
fn acquire_single_instance() -> bool {
    true
}
