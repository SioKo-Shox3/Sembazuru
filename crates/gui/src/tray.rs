//! Tray residency (M9.4c, ADR 0008 §2/§4).
//!
//! The resident GUI lives in the system tray: the window minimizes to the tray
//! instead of quitting, and a tray menu offers Show / Quit. tray-icon delivers
//! menu and icon events through global handlers; we classify them into a
//! [`TrayMessage`] and forward them over a channel the egui app drains each frame,
//! waking a repaint so a click is acted on immediately even while hidden.
//!
//! The forwarding channel is `tokio`'s unbounded channel because tray-icon's
//! handler bound is `Fn + Send + Sync` and `std::sync::mpsc::Sender` is not `Sync`.

use eframe::egui;
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder, TrayIconEvent};

/// A high-level tray interaction the app acts on.
pub enum TrayMessage {
    /// Restore and focus the window.
    Show,
    /// Quit the application for real (not minimize-to-tray).
    Quit,
}

/// The tray icon plus the receiver the app drains. Dropping it removes the icon.
pub struct Tray {
    _icon: TrayIcon,
    rx: tokio::sync::mpsc::UnboundedReceiver<TrayMessage>,
}

impl Tray {
    /// Installs the tray icon and its Show/Quit menu, wiring tray events to wake
    /// `ctx`. Returns `None` if the platform tray could not be created (the window
    /// then simply behaves as an ordinary window).
    pub fn new(ctx: &egui::Context) -> Option<Self> {
        let menu = Menu::new();
        let show = MenuItem::new("Show Sembazuru", true, None);
        let quit = MenuItem::new("Quit", true, None);
        menu.append(&show).ok()?;
        menu.append(&quit).ok()?;
        let show_id = show.id().clone();
        let quit_id = quit.id().clone();

        let icon = TrayIconBuilder::new()
            .with_tooltip("Sembazuru")
            .with_menu(Box::new(menu))
            .with_icon(brand_icon())
            .build()
            .ok()?;

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        let menu_tx = tx.clone();
        let menu_ctx = ctx.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            let message = if event.id == show_id {
                Some(TrayMessage::Show)
            } else if event.id == quit_id {
                Some(TrayMessage::Quit)
            } else {
                None
            };
            if let Some(message) = message {
                let _ = menu_tx.send(message);
                menu_ctx.request_repaint();
            }
        }));

        let icon_ctx = ctx.clone();
        TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
            // A double-click on the icon restores the window (Windows-only event).
            if let TrayIconEvent::DoubleClick { .. } = event {
                let _ = tx.send(TrayMessage::Show);
                icon_ctx.request_repaint();
            }
        }));

        Some(Self { _icon: icon, rx })
    }

    /// Returns the next pending tray interaction, if any (non-blocking).
    pub fn poll(&mut self) -> Option<TrayMessage> {
        self.rx.try_recv().ok()
    }
}

/// A simple generated 32×32 tray glyph: a filled disc in the brand green on a
/// transparent field. A bespoke icon asset can replace this later without code
/// changes elsewhere.
fn brand_icon() -> Icon {
    const SIZE: i32 = 32;
    const COLOR: [u8; 3] = [0x4c, 0xaf, 0x50];
    let center = (SIZE as f32 - 1.0) / 2.0;
    let radius_sq = center * center;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - center;
            let dy = y as f32 - center;
            if dx * dx + dy * dy <= radius_sq {
                rgba.extend_from_slice(&[COLOR[0], COLOR[1], COLOR[2], 0xff]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    Icon::from_rgba(rgba, SIZE as u32, SIZE as u32).expect("generated tray icon is valid RGBA")
}
