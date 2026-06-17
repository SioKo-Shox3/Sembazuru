//! `sembazuru-gui` entry point.
//!
//! For M9.4a this is a headless smoke utility: it dials the daemon's loopback
//! Status service once and prints the mapped snapshot, exercising the client and
//! view-model end-to-end before the UI exists. The egui window, tray residency,
//! and service controls land in the following sub-commits (M9.4b–e), at which
//! point this `main` grows the `--svcctl` arg dispatch and launches the app.

use sembazuru_gui::client::{fetch_status, status_endpoint};

fn main() {
    let endpoint = match status_endpoint() {
        Ok(endpoint) => endpoint,
        Err(message) => {
            eprintln!("sembazuru-gui: {message}");
            std::process::exit(2);
        }
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    let state = runtime.block_on(fetch_status(&endpoint));
    println!("sembazuru-gui: status @ {endpoint}\n{state:#?}");
}
