//! `sembazuru-gui` entry point (M9.4b).
//!
//! Resolves the loopback Status endpoint (refusing a non-loopback override), then
//! launches the resident dashboard window. Tray residency (M9.4c), the config
//! editor (M9.4d), and the `--svcctl` elevation dispatch + service controls
//! (M9.4e) build on this.

use sembazuru_gui::app::SembazuruApp;
use sembazuru_gui::client::status_endpoint;

fn main() -> eframe::Result<()> {
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
