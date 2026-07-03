# GUI Completion (M11 + M12) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **PROJECT MODEL POLICY (CLAUDE.md, harness-enforced):** implementation source (`.rs`) is written by **Codex**, not the main thread. Each code task below is handed to Codex; the main thread reviews line-by-line (Codex + Claude double review) before the task is "Done". egui rendering snippets in this plan are **representative** — Codex compiles and iterates them against `eframe 0.34`. Pure-logic and test code blocks are **literal** (correctness-critical; written against the verified type signatures in `docs/superpowers/specs/2026-07-02-sembazuru-roadmap.md` §M11 and the crate).

**Goal:** Complete the resident GUI so a non-developer can (M12) read cluster state at a glance and (M11) bring a 2nd machine online as a worker through the GUI, with the security-gated config-write backend isolated behind an abstraction so everything else ships now.

**Architecture:** Two independent parts. **Part A (M12)** is pure UI polish on the existing panels (`dashboard.rs`, `config.rs`, `app/mod.rs`) — no new backend, ships immediately. **Part B (M11)** adds a "Join a cluster" wizard and a daemon "Allow LAN workers" toggle; its load-bearing logic (LAN-IP detection, `worker.toml` generation, validation, advertise auto-fill, service-restart orchestration) is buildable now, while the actual privileged config **write** goes through a `ConfigWriter` trait whose concrete backend is deferred to the §2.0 decision (owner-managed, external — see roadmap spec §2.0).

**Tech Stack:** Rust, `eframe = "0.34"` (egui), `tokio`, `tonic` (loopback Status RPC), `windows-sys 0.59` (service control + — new — `Win32_NetworkManagement_IpHelper` for LAN IP), `zeroize`. New GUI deps: `toml` + `serde` (for `worker.toml` generation) — see Task B2.

---

## Prerequisites & constraints

1. **§2.0 config-write backend is externally gated.** Non-elevated config mutation is blocked by design (SetConfig admin-gated OFF — `crates/agent/src/status.rs:148-176`; `%ProgramData%` ACL). Part B builds against a `ConfigWriter` trait; the concrete backend (enable `status_admin` / installer ACL grant / elevated helper) is the owner's external security decision. Until chosen, the stub backend returns a clear "not configured" error, so the GUI compiles, is testable, and degrades gracefully.
2. **Toolchain:** build/test the GUI with `cargo test -p sembazuru-gui`. clang-cl is not needed for GUI code. On non-Windows, `svcctl` and LAN-IP are `cfg(windows)`-stubbed (mirror the existing `svcctl` non-windows stub at `crates/gui/src/svcctl/mod.rs:277-292`).
3. **Test harness pattern:** headless tests stand up the real in-process `StatusState` + `serve_status_service` on an ephemeral loopback port and drive the GUI's async client fns — template at `crates/gui/tests/status_client.rs:23-49,119-201`. Pure logic is tested without egui.
4. **Commit rules (CLAUDE.md):** small, single-purpose commits; **commit messages in Japanese**, referencing the milestone (`M11:` / `M12:`) and the evidence (test names).

---

## File structure

**Part A (M12) — modify only:**
- `crates/gui/src/app/dashboard.rs` — add the "N workers connected" badge in `render_dashboard`.
- `crates/gui/src/app/config.rs` — cache-size unit picker; field tooltips.
- `crates/gui/src/app/mod.rs` — tray-minimize one-time hint.
- `README.md`, `docs/quickstart.md` — M9 status sync + end-user install steps.

**Part B (M11) — create + modify:**
- Create `crates/gui/src/net.rs` — LAN IPv4 enumeration (`lan_ipv4_candidates()`), `cfg(windows)` via `GetAdaptersAddresses`, non-windows stub.
- Create `crates/gui/src/join/mod.rs` — the join-flow module root (re-exports below).
- Create `crates/gui/src/join/worker_toml.rs` — pure `WorkerJoinConfig` model + validation + TOML text generation (unit-tested).
- Create `crates/gui/src/join/writer.rs` — `ConfigWriter` trait + `StubConfigWriter` (§2.0-gated backend).
- Create `crates/gui/src/app/join_panel.rs` — the "Join a cluster" wizard panel (egui).
- Modify `crates/gui/src/svcctl/mod.rs` — add a `restart` orchestration (Stop→wait-Stopped→Start) reusing existing Start/Stop.
- Modify `crates/gui/src/app/services.rs` — expose a `restart(service, ctx)` trigger.
- Modify `crates/gui/src/app/mod.rs` — add `Tab::Join` + render dispatch; register `join_panel`.
- Modify `crates/gui/src/lib.rs` — `pub mod net; pub mod join;`.
- Modify `crates/gui/Cargo.toml` — add `serde`, `toml`; add `Win32_NetworkManagement_IpHelper` to `windows-sys` features.

---

# Part A — M12 UI polish (independent, ships now)

## Task A1: Dashboard "N workers connected" badge

**Files:**
- Modify: `crates/gui/src/app/dashboard.rs` (insert into `render_dashboard`, dashboard.rs:82-94)
- Test: `crates/gui/tests/dashboard_badge.rs` (new — pure helper test)

- [ ] **Step 1: Write the failing test** for a pure badge-text helper (keep logic out of egui so it is testable).

Create `crates/gui/tests/dashboard_badge.rs`:
```rust
use sembazuru_gui::app::dashboard::worker_badge_text;

#[test]
fn badge_reads_zero_one_many() {
    assert_eq!(worker_badge_text(0), "No workers connected");
    assert_eq!(worker_badge_text(1), "1 worker connected ✓");
    assert_eq!(worker_badge_text(3), "3 workers connected ✓");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sembazuru-gui --test dashboard_badge`
Expected: FAIL — `worker_badge_text` not found / `dashboard` not public.

- [ ] **Step 3: Implement the pure helper and render the badge.**

In `crates/gui/src/app/mod.rs`, make the module public so tests can reach the helper: change `mod dashboard;` → `pub mod dashboard;` (dashboard.rs already only exposes `render`/`DashAction`; add the helper as `pub`).

In `crates/gui/src/app/dashboard.rs` add the pure helper:
```rust
/// Human badge text for the connected-worker count. Pure (no egui) so it is unit-tested.
pub fn worker_badge_text(count: usize) -> String {
    match count {
        0 => "No workers connected".to_string(),
        1 => "1 worker connected ✓".to_string(),
        n => format!("{n} workers connected ✓"),
    }
}
```
Then render it at the top of `render_dashboard` (dashboard.rs:82, before the existing summary), colored by count (representative egui):
```rust
fn render_dashboard(ui: &mut egui::Ui, dash: &DashboardModel) {
    let n = dash.workers.len();
    let color = if n == 0 { MUTED } else { HEALTHY };
    ui.label(egui::RichText::new(worker_badge_text(n)).size(18.0).strong().color(color));
    ui.add_space(6.0);
    // …existing in-flight / auth summary and sections unchanged…
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sembazuru-gui --test dashboard_badge`
Expected: PASS (3 assertions).

- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/app/dashboard.rs crates/gui/src/app/mod.rs crates/gui/tests/dashboard_badge.rs
git commit -m "M12: ダッシュボードにワーカー接続数の大バッジを追加"
```

## Task A2: Cache-size unit picker (GB/MB/bytes)

**Files:**
- Modify: `crates/gui/src/app/config.rs` (fields at config.rs:39,89-94,207,232)
- Test: `crates/gui/tests/cache_unit.rs` (new)

- [ ] **Step 1: Write the failing test** for the pure unit↔bytes conversion.

Create `crates/gui/tests/cache_unit.rs`:
```rust
use sembazuru_gui::app::config::{bytes_to_unit, unit_to_bytes, SizeUnit};

#[test]
fn round_trips_and_picks_readable_unit() {
    assert_eq!(unit_to_bytes(8.0, SizeUnit::Gib), 8 * 1024 * 1024 * 1024);
    assert_eq!(unit_to_bytes(0.0, SizeUnit::Gib), 0); // 0 = uncapped
    let (val, unit) = bytes_to_unit(8 * 1024 * 1024 * 1024);
    assert_eq!(unit, SizeUnit::Gib);
    assert!((val - 8.0).abs() < 1e-9);
    let (val, unit) = bytes_to_unit(512 * 1024 * 1024);
    assert_eq!(unit, SizeUnit::Mib);
    assert!((val - 512.0).abs() < 1e-9);
    assert_eq!(bytes_to_unit(0), (0.0, SizeUnit::Gib)); // uncapped shows as 0 GiB
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sembazuru-gui --test cache_unit`
Expected: FAIL — symbols not found / `config` not public.

- [ ] **Step 3: Implement.** Make `pub mod config;` in `app/mod.rs`. Add to `config.rs`:
```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SizeUnit { Bytes, Mib, Gib }

impl SizeUnit {
    pub fn label(self) -> &'static str {
        match self { SizeUnit::Bytes => "bytes", SizeUnit::Mib => "MiB", SizeUnit::Gib => "GiB" }
    }
    fn factor(self) -> u64 {
        match self { SizeUnit::Bytes => 1, SizeUnit::Mib => 1024 * 1024, SizeUnit::Gib => 1024 * 1024 * 1024 }
    }
}

/// Convert a UI value+unit to bytes (0 stays 0 = uncapped).
pub fn unit_to_bytes(value: f64, unit: SizeUnit) -> u64 {
    if value <= 0.0 { return 0; }
    (value * unit.factor() as f64).round() as u64
}

/// Pick the most readable unit for a byte count (0 → 0 GiB).
pub fn bytes_to_unit(bytes: u64) -> (f64, SizeUnit) {
    if bytes == 0 { return (0.0, SizeUnit::Gib); }
    if bytes % (1024 * 1024 * 1024) == 0 { return (bytes as f64 / (1024.0*1024.0*1024.0), SizeUnit::Gib); }
    if bytes >= 1024 * 1024 { return (bytes as f64 / (1024.0*1024.0), SizeUnit::Mib); }
    (bytes as f64, SizeUnit::Bytes)
}
```
Replace the raw `cache_max_bytes: String` field usage: keep a `cache_size_value: String` + `cache_size_unit: SizeUnit` in `ConfigPanel`; in `apply_loaded` set them via `bytes_to_unit(cfg.cache_max_bytes)`; in `save` compute `let cache_max_bytes = unit_to_bytes(self.cache_size_value.trim().parse().unwrap_or(0.0), self.cache_size_unit);`. Render a `ComboBox` next to the value field (representative egui):
```rust
ui.horizontal(|ui| {
    ui.add(egui::TextEdit::singleline(&mut self.cache_size_value).desired_width(120.0));
    egui::ComboBox::from_id_salt("cache-unit")
        .selected_text(self.cache_size_unit.label())
        .show_ui(ui, |ui| {
            ui.selectable_value(&mut self.cache_size_unit, SizeUnit::Gib, "GiB");
            ui.selectable_value(&mut self.cache_size_unit, SizeUnit::Mib, "MiB");
            ui.selectable_value(&mut self.cache_size_unit, SizeUnit::Bytes, "bytes");
        });
});
```

- [ ] **Step 4: Run test** — `cargo test -p sembazuru-gui --test cache_unit` → PASS.
- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/app/config.rs crates/gui/src/app/mod.rs crates/gui/tests/cache_unit.rs
git commit -m "M12: キャッシュ上限に GiB/MiB/bytes 単位ピッカーを追加"
```

## Task A3: Config field tooltips

**Files:** Modify `crates/gui/src/app/config.rs` (the `field` fn, config.rs:271-275, and the grid calls config.rs:83-88).

- [ ] **Step 1:** No new logic test (pure egui hover text). Add a `field_with_hint` variant.
- [ ] **Step 2: Implement.** Extend `field` to accept a hint and attach `.on_hover_text`:
```rust
fn field_hint(ui: &mut egui::Ui, label: &str, value: &mut String, hint: &str) {
    ui.label(label).on_hover_text(hint);
    ui.add(egui::TextEdit::singleline(value).desired_width(320.0)).on_hover_text(hint);
    ui.end_row();
}
```
Wire hints for each field, e.g. `"Coordination addr"` → `"ワーカーが登録/heartbeat する待受アドレス。1台運用は 127.0.0.1:50070。LAN 参加は Join タブのトグルで設定。"`, `"File-server addr"` → `"ワーカーがファイル供給を受ける待受アドレス。LAN では 0.0.0.0 ではなく実 IP を使う（Join タブが自動設定）。"`, etc.
- [ ] **Step 3: Run** the existing suite to confirm no regression: `cargo test -p sembazuru-gui`.
- [ ] **Step 4: Commit**
```bash
git add crates/gui/src/app/config.rs
git commit -m "M12: 設定フィールドに説明ツールチップを追加"
```

## Task A4: Tray-minimize one-time hint

**Files:** Modify `crates/gui/src/app/mod.rs` (tray handling; `SembazuruApp` at app/mod.rs:30-45, `handle_tray`).

- [ ] **Step 1: Implement.** Add `hint_shown: bool` to `SembazuruApp` (default false). When the window is closed-to-tray (the existing close-to-tray path in `handle_tray`/the close handling), if `!self.hint_shown`, set a `notice`/toast string "トレイに常駐します。終了はトレイメニューから。" and `self.hint_shown = true`. Render the toast as a transient `egui::Area` or a label in the nav bar for a few frames. (Representative — Codex wires to the actual close-to-tray branch.)
- [ ] **Step 2: Run** `cargo test -p sembazuru-gui` (no logic test; ensure it compiles and existing tests pass).
- [ ] **Step 3: Commit**
```bash
git add crates/gui/src/app/mod.rs
git commit -m "M12: トレイ最小化時に常駐を知らせる初回ヒントを表示"
```

## Task A5: README / quickstart sync + end-user install steps

**Files:** Modify `README.md`, `docs/quickstart.md`.

- [ ] **Step 1:** Update `README.md` status badge (currently `status-pre--alpha (single--box M1--M8)`) to reflect M9 code-complete, and the roadmap table's `M9` row from `⬜ planned` to done-pending-real-machine (match `docs/deferred.md`).
- [ ] **Step 2:** Add an **end-user install section** (new) to `README.md` and `docs/quickstart.md`: "Download the MSI from GitHub Releases → double-click → (unsigned: SmartScreen「詳細情報」→「実行」) → the GUI starts in the tray." Include the note that a real signed release is pending, and that single-machine works out of the box while 2nd-machine join uses the GUI Join tab (Part B).
- [ ] **Step 3: Commit**
```bash
git add README.md docs/quickstart.md
git commit -m "M12: README/quickstart を M9 現状に同期し MSI 導入手順を追加"
```

## Task A6: VC++ runtime dependency determination (investigation + note)

**Files:** Modify `installer/README.md` (or `docs/quickstart.md` prerequisites).

- [ ] **Step 1:** Determine CRT linkage of the shipped exes: run `dumpbin /dependents target/release/sembazuru-gui.exe` (and daemon/worker) in a VS dev shell; check for `VCRUNTIME140.dll` / `MSVCP140.dll` (dynamic) vs none (static `/MT`).
- [ ] **Step 2:** If dynamic, add a prerequisite note (VC++ 2015–2022 x64 Redistributable) to the install docs and open a follow-up to bundle VCRedist in the MSI; if static, note "no runtime prerequisite." Record the `dumpbin` output as evidence in the commit body.
- [ ] **Step 3: Commit**
```bash
git add installer/README.md docs/quickstart.md
git commit -m "M12: 配布 exe の CRT 依存を確定し前提条件を明記（dumpbin 証跡）"
```

---

# Part B — M11 onboarding (logic + UI now; config-write backend §2.0-gated)

## Task B1: LAN IPv4 enumeration helper

**Files:**
- Create: `crates/gui/src/net.rs`
- Modify: `crates/gui/src/lib.rs` (`pub mod net;`), `crates/gui/Cargo.toml` (add `Win32_NetworkManagement_IpHelper` feature)
- Test: `crates/gui/tests/net.rs`

- [ ] **Step 1: Write the failing test** (behavioral, platform-tolerant — the machine's own enumeration is environment-specific, so assert the shape/filtering contract, not a specific IP).
```rust
use sembazuru_gui::net::{is_usable_lan_ipv4, lan_ipv4_candidates};
use std::net::Ipv4Addr;

#[test]
fn filters_loopback_and_linklocal() {
    assert!(!is_usable_lan_ipv4(Ipv4Addr::LOCALHOST));
    assert!(!is_usable_lan_ipv4(Ipv4Addr::new(169, 254, 1, 5)));   // APIPA link-local
    assert!(!is_usable_lan_ipv4(Ipv4Addr::UNSPECIFIED));            // 0.0.0.0
    assert!(is_usable_lan_ipv4(Ipv4Addr::new(192, 168, 1, 10)));
    assert!(is_usable_lan_ipv4(Ipv4Addr::new(10, 0, 0, 4)));
}

#[test]
fn candidates_never_include_loopback() {
    for ip in lan_ipv4_candidates() {
        assert!(is_usable_lan_ipv4(ip), "candidate {ip} must pass the usable filter");
    }
}
```

- [ ] **Step 2: Run** `cargo test -p sembazuru-gui --test net` → FAIL (module missing).

- [ ] **Step 3: Implement.** Add to `crates/gui/Cargo.toml` `windows-sys` features: `"Win32_NetworkManagement_IpHelper"`, `"Win32_Networking_WinSock"`. Create `crates/gui/src/net.rs`:
```rust
//! LAN IPv4 discovery for the join flow (M11). The GUI never auto-detected its own
//! address before; this offers candidate LAN IPs so the operator does not run `ipconfig`.
use std::net::Ipv4Addr;

/// A LAN IPv4 usable as an advertise / coordinator address: not loopback,
/// not link-local (APIPA 169.254/16), not unspecified, not broadcast.
pub fn is_usable_lan_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified() && !ip.is_broadcast()
}

/// Enumerate usable LAN IPv4 addresses of this machine (best-effort; empty on failure).
#[cfg(windows)]
pub fn lan_ipv4_candidates() -> Vec<Ipv4Addr> {
    imp::enumerate().into_iter().filter(|ip| is_usable_lan_ipv4(*ip)).collect()
}
#[cfg(not(windows))]
pub fn lan_ipv4_candidates() -> Vec<Ipv4Addr> { Vec::new() }

#[cfg(windows)]
mod imp {
    use std::net::Ipv4Addr;
    // Uses GetAdaptersAddresses (Win32_NetworkManagement_IpHelper). Codex implements the
    // unsafe FFI: call with AF_INET, iterate IP_ADAPTER_ADDRESSES → FirstUnicastAddress,
    // read each SOCKADDR_IN, skip adapters that are not IfOperStatusUp. Return Vec<Ipv4Addr>.
    pub fn enumerate() -> Vec<Ipv4Addr> { /* Codex: GetAdaptersAddresses FFI */ Vec::new() }
}
```
Note for Codex: the FFI is **the only `unsafe` in this plan**; keep it minimal, one call + one linked-list walk, and route-away to an empty Vec on any error (the UI treats "no candidates" as "type it manually").

- [ ] **Step 4: Run** `cargo test -p sembazuru-gui --test net` → PASS (filter test is deterministic; candidates test passes trivially on non-windows/empty).
- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/net.rs crates/gui/src/lib.rs crates/gui/Cargo.toml crates/gui/tests/net.rs
git commit -m "M11: LAN IPv4 候補列挙ヘルパを追加（GetAdaptersAddresses）"
```

## Task B2: `worker.toml` generation + validation (pure logic)

**Files:**
- Create: `crates/gui/src/join/mod.rs`, `crates/gui/src/join/worker_toml.rs`
- Modify: `crates/gui/src/lib.rs` (`pub mod join;`), `crates/gui/Cargo.toml` (add `serde = { version = "1", features=["derive"] }`, `toml = "0.8"`)
- Test: `crates/gui/tests/worker_toml.rs`

- [ ] **Step 1: Write the failing tests** for the pure model → TOML + validation. These are the correctness core of M11.
```rust
use sembazuru_gui::join::worker_toml::{JoinInput, JoinError, render_worker_toml, validate};

fn base() -> JoinInput {
    JoinInput {
        agent: "http://192.168.1.10:50070".into(),
        cluster_token: "shared-secret".into(),
        listen_addr: "0.0.0.0:50061".into(),
        advertise: "".into(),           // empty → auto-filled from detected LAN IP
        detected_lan_ip: Some("192.168.1.11".into()),
        participation_mode: "adaptive".into(),
        allow_insecure_lan: true,
    }
}

#[test]
fn autofills_advertise_when_listen_is_unspecified() {
    let out = validate(base()).expect("valid");
    assert_eq!(out.advertise, "http://192.168.1.11:50061",
        "0.0.0.0 listen → advertise auto-filled from detected LAN IP + listen port");
}

#[test]
fn rejects_unspecified_listen_without_lan_ip() {
    let mut i = base();
    i.detected_lan_ip = None;
    i.advertise = "".into();
    assert!(matches!(validate(i), Err(JoinError::AdvertiseUnresolved)),
        "0.0.0.0 listen + no advertise + no detected IP must fail (worker/src/run.rs:93 trap)");
}

#[test]
fn rejects_bad_agent_url() {
    let mut i = base();
    i.agent = "192.168.1.10:50070".into(); // missing scheme
    assert!(matches!(validate(i), Err(JoinError::AgentUrl)));
}

#[test]
fn rejects_empty_token() {
    let mut i = base();
    i.cluster_token = "".into();
    assert!(matches!(validate(i), Err(JoinError::TokenRequired)),
        "LAN join requires a shared token (agent/src/run.rs:39-62 refuses LAN bind without one)");
}

#[test]
fn renders_expected_toml_keys() {
    let out = validate(base()).expect("valid");
    let toml = render_worker_toml(&out);
    assert!(toml.contains("agent = \"http://192.168.1.10:50070\""));
    assert!(toml.contains("cluster_token = \"shared-secret\""));
    assert!(toml.contains("listen_addr = \"0.0.0.0:50061\""));
    assert!(toml.contains("advertise = \"http://192.168.1.11:50061\""));
    assert!(toml.contains("participation_mode = \"adaptive\""));
    assert!(toml.contains("unsafe_allow_insecure_execution_lan = true"));
    // round-trips through the real worker config parser (dev-dep):
    let parsed: sembazuru_worker::config::WorkerConfig = toml::from_str(&toml).expect("parse");
    assert_eq!(parsed.agent.as_deref(), Some("http://192.168.1.10:50070"));
    assert_eq!(parsed.advertise.as_deref(), Some("http://192.168.1.11:50061"));
}
```

- [ ] **Step 2: Run** `cargo test -p sembazuru-gui --test worker_toml` → FAIL (module missing). (Add `toml` to `[dev-dependencies]` too for the round-trip parse.)

- [ ] **Step 3: Implement** the pure module. `crates/gui/src/join/mod.rs`:
```rust
pub mod worker_toml;
pub mod writer;
```
`crates/gui/src/join/worker_toml.rs`:
```rust
//! Pure logic for the "join a cluster" flow (M11): turn wizard input into a validated
//! worker.toml. No egui, no I/O — unit-tested. Only the subset of worker fields the
//! wizard sets is emitted; the rest fall back to WorkerConfig defaults on the worker side.
use serde::Serialize;

#[derive(Clone, Debug, Default)]
pub struct JoinInput {
    pub agent: String,
    pub cluster_token: String,
    pub listen_addr: String,
    pub advertise: String,          // empty = auto-fill
    pub detected_lan_ip: Option<String>,
    pub participation_mode: String, // "always" | "adaptive" | "off"
    pub allow_insecure_lan: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinError { AgentUrl, TokenRequired, ListenAddr, AdvertiseUnresolved, ParticipationMode }

/// The validated, ready-to-serialize subset of worker.toml.
#[derive(Clone, Debug, Serialize)]
pub struct WorkerJoin {
    pub agent: String,
    pub cluster_token: String,
    pub listen_addr: String,
    pub advertise: String,
    pub participation_mode: String,
    pub unsafe_allow_insecure_execution_lan: bool,
}

fn parse_socket(addr: &str) -> Option<(std::net::IpAddr, u16)> {
    addr.parse::<std::net::SocketAddr>().ok().map(|s| (s.ip(), s.port()))
}

pub fn validate(i: JoinInput) -> Result<WorkerJoin, JoinError> {
    if !(i.agent.starts_with("http://") || i.agent.starts_with("https://")) {
        return Err(JoinError::AgentUrl);
    }
    if i.cluster_token.trim().is_empty() { return Err(JoinError::TokenRequired); }
    let (ip, port) = parse_socket(&i.listen_addr).ok_or(JoinError::ListenAddr)?;
    if !matches!(i.participation_mode.as_str(), "always" | "adaptive" | "off") {
        return Err(JoinError::ParticipationMode);
    }
    // Advertise: explicit wins; else if listen is 0.0.0.0/unspecified, derive from detected LAN IP.
    let advertise = if !i.advertise.trim().is_empty() {
        i.advertise.trim().to_string()
    } else if ip.is_unspecified() {
        let lan = i.detected_lan_ip.as_deref().ok_or(JoinError::AdvertiseUnresolved)?;
        format!("http://{lan}:{port}")
    } else {
        format!("http://{ip}:{port}")
    };
    Ok(WorkerJoin {
        agent: i.agent.trim().to_string(),
        cluster_token: i.cluster_token.clone(),
        listen_addr: i.listen_addr.trim().to_string(),
        advertise,
        participation_mode: i.participation_mode,
        unsafe_allow_insecure_execution_lan: i.allow_insecure_lan,
    })
}

/// Serialize to TOML text (via `toml`), the exact bytes the writer persists.
pub fn render_worker_toml(w: &WorkerJoin) -> String {
    toml::to_string_pretty(w).expect("WorkerJoin is a fixed, always-serializable struct")
}
```
Add `serde`, `toml` to `[dependencies]` and `toml` to `[dev-dependencies]` in `crates/gui/Cargo.toml`.

- [ ] **Step 4: Run** `cargo test -p sembazuru-gui --test worker_toml` → PASS (6 tests incl. the WorkerConfig round-trip).
- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/join crates/gui/src/lib.rs crates/gui/Cargo.toml crates/gui/tests/worker_toml.rs
git commit -m "M11: worker.toml 生成とバリデーションの純粋ロジックを追加（advertise 自動補完・token 必須）"
```

## Task B3: `ConfigWriter` trait + stub backend (§2.0-gated)

**Files:** Create `crates/gui/src/join/writer.rs`; Test: `crates/gui/tests/writer_stub.rs`.

- [ ] **Step 1: Write the failing test.**
```rust
use sembazuru_gui::join::writer::{ConfigWriter, StubConfigWriter, WriteError, WriteTarget};

#[test]
fn stub_reports_mechanism_unconfigured() {
    let w = StubConfigWriter;
    let err = w.write(WriteTarget::WorkerToml, "agent = \"http://x:1\"\n").unwrap_err();
    assert!(matches!(err, WriteError::MechanismUnconfigured));
    assert!(err.to_string().contains("§2.0"), "error points the operator at the pending decision");
}
```

- [ ] **Step 2: Run** `cargo test -p sembazuru-gui --test writer_stub` → FAIL.

- [ ] **Step 3: Implement** the abstraction. `crates/gui/src/join/writer.rs`:
```rust
//! Config-write abstraction (M11). The privileged write of daemon.toml/worker.toml is
//! blocked by design (SetConfig admin-gated OFF; %ProgramData% ACL) — see roadmap §2.0.
//! Everything upstream (wizard, validation, restart orchestration) builds against this
//! trait; the CONCRETE backend (enable status_admin / installer ACL grant / elevated
//! helper) is the owner's external security decision and lands as a real impl later.
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteTarget { WorkerToml, DaemonToml }

#[derive(Debug, PartialEq, Eq)]
pub enum WriteError {
    /// No config-write backend has been chosen/installed yet (roadmap §2.0).
    MechanismUnconfigured,
    /// The chosen backend failed at runtime (permission denied, path, elevation declined…).
    Backend(String),
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WriteError::MechanismUnconfigured => write!(f,
                "config-write mechanism not configured (roadmap §2.0, owner-managed); \
                 cannot persist config from the GUI yet"),
            WriteError::Backend(m) => write!(f, "config write failed: {m}"),
        }
    }
}
impl std::error::Error for WriteError {}

pub trait ConfigWriter: Send + Sync {
    /// Persist `contents` to the given config target, atomically. Returns after the bytes
    /// are on disk (the caller then restarts the service to apply).
    fn write(&self, target: WriteTarget, contents: &str) -> Result<(), WriteError>;
}

/// Default backend until §2.0 is decided: refuses, with a clear message.
pub struct StubConfigWriter;
impl ConfigWriter for StubConfigWriter {
    fn write(&self, _t: WriteTarget, _c: &str) -> Result<(), WriteError> {
        Err(WriteError::MechanismUnconfigured)
    }
}
```

- [ ] **Step 4: Run** `cargo test -p sembazuru-gui --test writer_stub` → PASS.
- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/join/writer.rs crates/gui/tests/writer_stub.rs
git commit -m "M11: ConfigWriter 抽象とスタブ実装を追加（§2.0 の外部決定まで書込は保留）"
```

## Task B4: Service restart orchestration (Stop → wait → Start)

**Files:** Modify `crates/gui/src/svcctl/mod.rs`, `crates/gui/src/app/services.rs`; Test: extend `crates/gui/src/svcctl/mod.rs` `#[cfg(test)]`.

- [ ] **Step 1: Write the failing test** for a pure state-transition planner (so the sequencing is testable without a real SCM).
```rust
// in svcctl/mod.rs #[cfg(test)] mod tests
use super::{restart_plan, Action, ServiceState};
#[test]
fn restart_plan_stops_then_starts_when_running() {
    assert_eq!(restart_plan(ServiceState::Running), vec![Action::Stop, Action::Start]);
}
#[test]
fn restart_plan_just_starts_when_stopped() {
    assert_eq!(restart_plan(ServiceState::Stopped), vec![Action::Start]);
}
#[test]
fn restart_plan_noop_when_not_installed() {
    assert!(restart_plan(ServiceState::NotInstalled).is_empty());
}
```

- [ ] **Step 2: Run** `cargo test -p sembazuru-gui svcctl` → FAIL (`restart_plan` missing).

- [ ] **Step 3: Implement** the planner (pure) in `svcctl/mod.rs`:
```rust
/// The action sequence to reach a freshly-(re)started service from `current`. Pure.
pub fn restart_plan(current: ServiceState) -> Vec<Action> {
    match current {
        ServiceState::Running => vec![Action::Stop, Action::Start],
        ServiceState::Stopped => vec![Action::Start],
        ServiceState::NotInstalled | ServiceState::Unknown => vec![],
    }
}
```
Then in `crates/gui/src/app/services.rs` add a `restart(service, ctx)` that: queries `svcctl::query_state(service)`, computes `restart_plan`, and runs the actions **sequentially** off the UI thread (extend the existing `trigger` thread-spawn to accept a `Vec<Action>` and call `svcctl::request_action` for each in order, re-checking Stopped between Stop and Start with a bounded wait). Representative:
```rust
pub fn restart(&mut self, service: Service, ctx: &egui::Context) {
    if self.busy { return; }
    self.busy = true;
    self.notice = format!("Restarting {}…", service.label());
    let plan = svcctl::restart_plan(svcctl::query_state(service));
    let (tx, rx) = std::sync::mpsc::channel();
    self.result_rx = Some(rx);
    let ctx = ctx.clone();
    std::thread::spawn(move || {
        let mut last = Ok(0);
        for action in plan {
            last = svcctl::request_action(service, action); // each Start/Stop already elevates once
            if last.is_err() { break; }
        }
        let _ = tx.send((service, Action::Start, last));
        ctx.request_repaint();
    });
}
```
(Note the UX cost surfaced in roadmap §2.4: Stop and Start each raise their own UAC prompt, since `request_action` elevates per call. Acceptable for v1; a single-elevation `--svcctl restart` CLI is a possible follow-up but out of this task.)

- [ ] **Step 4: Run** `cargo test -p sembazuru-gui svcctl` → PASS (3 planner tests + existing svcctl tests).
- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/svcctl/mod.rs crates/gui/src/app/services.rs
git commit -m "M11: サービス再起動オーケストレーション（Stop→Start）を追加"
```

## Task B5: "Join a cluster" wizard panel

**Files:** Create `crates/gui/src/app/join_panel.rs`; Modify `crates/gui/src/app/mod.rs` (`Tab::Join`, dispatch, `mod join_panel;`).

- [ ] **Step 1: Write the failing test** for the panel's pure "collect input → validated result" step (keep the decision logic out of egui).
```rust
use sembazuru_gui::app::join_panel::JoinPanel;
#[test]
fn panel_builds_validated_input_from_fields() {
    let mut p = JoinPanel::default();
    p.set_fields_for_test("http://192.168.1.10:50070", "tok", "0.0.0.0:50061", "", "adaptive", true);
    p.set_detected_lan_ip_for_test(Some("192.168.1.11".into()));
    let toml = p.preview_toml().expect("valid input renders toml");
    assert!(toml.contains("advertise = \"http://192.168.1.11:50061\""));
}
```

- [ ] **Step 2: Run** `cargo test -p sembazuru-gui join_panel` → FAIL.

- [ ] **Step 3: Implement** `crates/gui/src/app/join_panel.rs`. Struct holds the field buffers, the detected LAN IP list (from `crate::net::lan_ipv4_candidates()` on first render), a `Box<dyn ConfigWriter>` (defaults to `StubConfigWriter`), and pending state. Provide test hooks (`set_fields_for_test`, `set_detected_lan_ip_for_test`, `preview_toml`) that build a `JoinInput`, run `validate`, and `render_worker_toml`. `render(ui, services)` draws the wizard, a **Preview** of the worker.toml, and an **Apply** button that: `writer.write(WriteTarget::WorkerToml, &toml)` then, on Ok, `services.restart(Service::Worker, ctx)`. On `WriteError::MechanismUnconfigured`, show the §2.0 message and a link to the docs. Make `pub mod join_panel;` in `app/mod.rs`. Representative egui body:
```rust
pub fn render(&mut self, ui: &mut egui::Ui, services: &mut super::services::ServicesPanel, ctx: &egui::Context) {
    if !self.detected { self.lan_ips = crate::net::lan_ipv4_candidates(); self.detected = true; }
    ui.heading("Join a cluster as a worker");
    // fields: agent, token(password), listen_addr, advertise(+auto), participation combo,
    //         allow_insecure_lan checkbox; a ComboBox to pick from self.lan_ips.
    if ui.button("Preview worker.toml").clicked() { self.notice = self.preview_toml().map_or_else(|e| format!("{e:?}"), |t| t); }
    if ui.button("Apply & restart worker").clicked() { self.apply(services, ctx); }
    if !self.notice.is_empty() { ui.separator(); ui.label(&self.notice); }
}
```

- [ ] **Step 4:** Wire the tab in `app/mod.rs`: add `Join` to `Tab`, `ui.selectable_value(&mut self.tab, Tab::Join, "Join")` in the nav, `Tab::Join => self.join_panel.render(ui, &mut self.services, &ctx)` in the match, and a `join_panel: join_panel::JoinPanel` field (default). Run `cargo test -p sembazuru-gui join_panel` → PASS.
- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/app/join_panel.rs crates/gui/src/app/mod.rs crates/gui/tests
git commit -m "M11: 「Join a cluster」ワーカー参加ウィザードパネルを追加"
```

## Task B6: Daemon "Allow LAN workers" toggle

**Files:** Modify `crates/gui/src/app/config.rs` (or a small new section in the Settings panel); reuse the existing `SetConfig` path + graceful admin-gated handling; use `crate::net` for the LAN IP and `services.restart(Service::Daemon, ctx)`.

- [ ] **Step 1: Write the failing test** for the pure "compute daemon LAN edit" helper (given a chosen LAN IP + ports, produce the coord/fileserver addresses — never `0.0.0.0`).
```rust
use sembazuru_gui::app::config::lan_daemon_addrs;
#[test]
fn lan_addrs_use_concrete_ip_never_unspecified() {
    let (coord, fileserver) = lan_daemon_addrs("192.168.1.10", 50070, 50072);
    assert_eq!(coord, "192.168.1.10:50070");
    assert_eq!(fileserver, "192.168.1.10:50072");   // routable — NOT 0.0.0.0 (roadmap §2.4)
}
```

- [ ] **Step 2: Run** `cargo test -p sembazuru-gui config` → FAIL.

- [ ] **Step 3: Implement.** Add to `config.rs`:
```rust
/// Daemon coord/fileserver addresses for LAN worker acceptance: bind on the concrete
/// LAN IP so `local_addr()`-derived `agent_fileserver` is routable (roadmap §2.4).
pub fn lan_daemon_addrs(lan_ip: &str, coord_port: u16, fileserver_port: u16) -> (String, String) {
    (format!("{lan_ip}:{coord_port}"), format!("{lan_ip}:{fileserver_port}"))
}
```
Add an "Allow LAN workers" section to the Settings panel: a checkbox; when enabled it (1) requires a cluster token to be set (disable the toggle + tooltip if `!cluster_token_set`, mirroring `agent/src/run.rs:39-62`), (2) picks a LAN IP via `crate::net::lan_ipv4_candidates()` (ComboBox), (3) on "Apply", sends a `ConfigEdit` with `coord_addr`/`fileserver_addr` = `lan_daemon_addrs(...)` through the **existing** `UiCommand::SetConfig` path, then calls `services.restart(Service::Daemon, ctx)`. If `SetConfig` returns `permission_denied` (admin-gated, ADR 0016), surface: "daemon config mutation is disabled (§2.0). Enable status_admin or use the chosen config-write mechanism." (This reuses the existing wired SetConfig; only the daemon side can use it, because worker has no RPC — hence Task B2/B5 for worker.)

- [ ] **Step 4: Run** `cargo test -p sembazuru-gui config` → PASS (unit + existing config tests). Add an integration test in `crates/gui/tests/status_client.rs` style: with `admin_enabled: true`, a `lan_daemon_addrs`-built `ConfigEdit` round-trips and read-back shows the concrete-IP addresses (never `0.0.0.0`).
- [ ] **Step 5: Commit**
```bash
git add crates/gui/src/app/config.rs crates/gui/tests/status_client.rs
git commit -m "M11: daemon「Allow LAN workers」トグル（具体 LAN IP・token 前提・再起動）"
```

---

## Self-review

**Spec coverage (roadmap §M11 + §M12):**
- §M11 §2.0 config-write gate → Task B3 (`ConfigWriter`/stub) + B6 admin-gated handling. ✓
- §M11 §2.2 wizard fields → Task B2 (`JoinInput`) + B5 (panel). ✓
- §M11 §2.3 validation (agent URL, advertise auto-fill on 0.0.0.0, token required) → Task B2 tests. ✓
- §M11 §2.4 daemon toggle: concrete LAN IP (not 0.0.0.0), token precondition, restart → Task B6 + B4. ✓
- §M11 worker.toml write + Worker restart → B2 (content), B3 (write), B4 (restart), B5 (wire). ✓
- §M11 LAN IP detection (was absent) → Task B1. ✓
- §M12 badge → A1; unit picker → A2; tooltips → A3; tray hint → A4; README/quickstart → A5; VC++ dep → A6. ✓

**Placeholder scan:** the only intentionally-deferred code is the `GetAdaptersAddresses` FFI body (B1, Codex FFI) and the concrete `ConfigWriter` backend (B3, §2.0-gated) — both explicitly flagged, not silent TODOs. Pure-logic and tests are complete literal code.

**Type consistency:** `JoinInput`/`WorkerJoin`/`validate`/`render_worker_toml` names are used identically across B2 and B5; `ConfigWriter`/`WriteTarget`/`WriteError` identical across B3/B5/B6; `restart_plan`/`Action`/`ServiceState` match `svcctl` verbatim; `ConfigEdit`/`SetConfigOutcome`/`ConfigModel` match `model.rs`; `WorkerConfig` fields match `crates/worker/src/config.rs` verbatim. ✓

**Ordering:** Part A tasks are independent (any order). Part B order is B1→B2→B3→B4 (all independent-ish, buildable now) → B5 (wires B1/B2/B3/B4) → B6 (reuses B4 + net). B5/B6 depend on their predecessors compiling.

**Externally-gated:** B3's concrete backend and B6's live daemon-mutation both depend on the §2.0 decision; until then the stub/admin-gated paths keep the GUI compiling and honest. Real 2-machine acceptance of B5/B6 is verified in **M10** (needs the 2nd physical machine), not here.
