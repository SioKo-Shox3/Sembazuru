# 0016 — local 特権分離（named pipe＋impersonation・read/admin 分離・非 LocalSystem 既定）

- ステータス: **一部実装（PARTIAL）。** 起案: 2026-06-24。決定者承認: 保留（プロジェクトリード）。
  出所: コードレビュー（SEC-001・最も危険な P0＝local EoP→SYSTEM）。
  **実装済み**: (1) 暫定緩和のうち **Status 書込み RPC のゲート**（`set_config`/`trigger_eviction`
  を `status_admin`/`SEMBAZURU_STATUS_ADMIN` の opt-in・既定 deny。無認証 loopback から cluster
  token をクリアして LAN auth を無効化する経路を閉鎖。`config_rpc.rs` で deny を実証）。
  **未実装（本格策・lead/実機ゲート）**: LocalIntake→`run_local`→SYSTEM の主経路（= (2)named-pipe
  transport＋DACL／(3)caller impersonation／(5)非 LocalSystem 既定＋installer ACL）。これらは Windows
  サービス/2 ユーザー/SID assertion の実機検証（M9.5/M10）が要るため当環境では未着手。
- 決めること: local IPC を**どの境界で守るか**。**(1) 暫定緩和（先行）**、**(2) named-pipe transport＋DACL**、
  **(3) caller impersonation で local fallback**、**(4) Status の read/admin 分離**、**(5) 非 LocalSystem 既定**。
- 判定基準: 非交渉（**正しさ>速度**／**ローカルフォールバック常時**）。署名/EDR は [ADR 0009 撤回](0009-app-self-update-github-releases.md)で任意降格だが、
  named pipe＋impersonation は EDR シグナル化しうる＝`security-reviewer`(opus) 必須。
- 関連: [ADR 0006](0006-trust-and-auth.md)（LAN auth・local は対象外だった）、[ADR 0008](0008-productization-installer-gui-residency.md)（常駐/installer）、
  `crates/agent/src/{intake,status,lib,service}.rs`、`crates/agent/src/bin/sembazuru_daemon.rs`、
  `installer/sembazuru.wxs`、`crates/agent/src/bin/sembazuru_launcher.rs`、`crates/gui/src/client.rs`。

## 背景

local IPC が「同一マシン」境界しか持たず「同一ユーザー」境界を持たないため、**標準ユーザーが SYSTEM 実行に到達**できる（SEC-001）:

- **LocalIntake**(`127.0.0.1:50071`)/**Status**(`:50073`) は loopback-TCP・**無認証**。`require_loopback`(`intake.rs:417-439`) は **bind アドレス制限のみ**で caller identity を見ない。loopback TCP は「同一マシン」境界＝任意の local プロセスが connect 可。
- `run_local`(`lib.rs:275-292`) は **daemon プロセスのトークン**で `tokio::process::Command` を spawn・**impersonation なし**。daemon は installer で **LocalSystem**（`sembazuru.wxs:121`、`daemon.rs:81` 既定 `System`）。⇒ 標準ユーザーが submit→無 worker/route-away で local fallback→**SYSTEM 実行**。
- Status `set_config`(`status.rs:282-318`) が **cluster token クリア・listen addr 書換**を無認証で永続化（次回起動で外部公開しうる）。`trigger_eviction` も無認証。

[ADR 0006](0006-trust-and-auth.md) の共有トークン auth は worker→agent の **LAN プレーン専用**で、LocalIntake/Status は対象外（`status.rs:17-21`）。

### 実装前提（現状調査で確定）
- worker は既に最小権限 Virtual(`NT SERVICE\SembazuruWorker`)＝**daemon の既定だけが問題**。
- `windows-sys` は依存済（svcctl で `Win32::Foundation`/`Threading`/`Shell` を使用）＝pipe DACL/`ImpersonateNamedPipeClient` の Win32 面は新 crate 不要。
- 既存 named pipe は worker VFS pipe(`vfs_pipe.rs`)のみで **DACL/impersonation なし**（再利用は framing のみ、security は net-new）。
- クライアント: launcher→intake `50071`、GUI Status→`50073`（pipe 移行で動作維持要）。GUI svcctl は SCM 直＝無関係。

## 決定

### (1) 暫定緩和（先行・安価）
daemon 既定を `System` から外す（`daemon.rs:81`＋`sembazuru.wxs:121`）。Status write RPC（`set_config`/`trigger_eviction`）を **build feature か Administrators SID** で gate。本格策完了まで service install を開発者 opt-in。

### (2) named-pipe transport＋DACL
`LocalIntakeTransport` 抽象を作り TCP を **test-only** へ。**Windows named-pipe transport** を追加（pipe 名に user SID、**明示 DACL** で現ユーザー/Administrators 限定）。Status も pipe 化。

### (3) caller impersonation で local fallback
`run_local` を **`ImpersonateNamedPipeClient`/複製トークンで caller として実行**（`run_local_as_caller`）＝daemon が SYSTEM でも submitted process は **caller SID**。caller token を `SubmissionContext` に保持。

### (4) Status の read/admin 分離
Status を `StatusRead`（get_status/get_config）と `StatusAdmin`（set_config/trigger_eviction）に分離。admin pipe は **Administrators SID 限定**の DACL。

### (5) 非 LocalSystem 既定 + installer
service 既定アカウント再決定（user-session agent ＋ machine service の分離が目標形）。installer ACL/service account 更新。

## 影響

- `crates/agent/src/intake.rs`（LocalIntakeTransport・pipe）、`status.rs`（read/admin 分離・SID gate）、`lib.rs`（run_local_as_caller・impersonation）、`service.rs`＋`bin/sembazuru_daemon.rs`（既定アカウント）、`installer/sembazuru.wxs`（Account/ACL）、`gui/src/client.rs`＋`bin/sembazuru_launcher.rs`（pipe クライアント）。
- 検証: 標準ユーザー A の daemon へ B が submit 不可／非管理者が `SetConfig`/`TriggerEviction` 不可／local fallback の process token SID が caller と一致／daemon が SYSTEM でも submitted process は SYSTEM でない／production build で TCP loopback が listen しない／2 ユーザー pipe access 拒否の Windows 統合テスト。**`security-reviewer`(opus) 必須**（impersonation/EDR 光学）。

## 繰延・未決

- user-session agent と machine service の完全分離（目標形）の段階導入。
- pipe SDDL の正確な DACL 設計（現ユーザー/Administrators/SYSTEM の許可セット）。
- Windows 実機統合テスト（2 ユーザー・SID assertion・impersonation 失敗系）は実機ゲート（[ADR 0008](0008-productization-installer-gui-residency.md) 系）と同枠。
