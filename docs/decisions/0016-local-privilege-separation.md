# 0016 — LocalIntake 特権分離（authenticated named pipe＋caller restricted token）

- ステータス: **実装済み・clean Windows CI 確認済み。** 起案: 2026-06-24、解決: 2026-07-15。
  中核実装は `68e5422`、LocalSystem server照合は `e284940`、clean A/B証拠は `a35bf9f`。
  SEC-001 は初回レビューバックログで `RESOLVED`。
- 出所: コードレビュー（SEC-001・最も危険な P0＝local EoP→SYSTEM）。
- 決めたこと: Windows production LocalIntake を **machine-wide authenticated named pipe** とし、DACL、server
  SID 検証、caller impersonation、restricted primary token、管理 API 分離を一つの境界として維持する。
- 判定基準: **標準ユーザーから SYSTEM 権限の任意コマンドを実行できないこと**、かつ正規 launcher の local
  fallback が caller 権限で完走すること。認証／token 準備に失敗した場合は daemon token へ retry せず fail closed。
- 関連: [ADR 0006](0006-trust-and-auth.md)（LAN auth）、
  [ADR 0008](0008-productization-installer-gui-residency.md)（Status/Admin と installer）、
  `crates/agent/src/{intake_pipe,intake,lib,service}.rs`、`crates/agent/src/bin/sembazuru_launcher.rs`、
  `hooks/test/m6_local_intake_security.ps1`。

## 背景

commit `68e5422` より前は LocalIntake (`127.0.0.1:50071`) が無認証 loopback TCP で、caller identity を確認せず、
local fallback を daemon の token で spawn していた。installer の daemon は LocalSystem なので、標準ユーザーが
任意コマンドを submit して SYSTEM 実行へ到達できた。loopback は「同一マシン」しか保証せず、権限境界にならない。

Status (`127.0.0.1:50073`) は別サービスである。書込み RPC は既に `status_admin`／
`SEMBAZURU_STATUS_ADMIN` の opt-in・既定 deny とし、LocalIntake のコマンド実行面と分離している。

## 決定

### (1) production transport と DACL

Windows production endpoint は `\\.\pipe\Sembazuru.LocalIntake.v1` に固定する。first-instance と remote-client reject
を有効にし、再 arm する全 instance に protected DACL を適用する。SYSTEM／Administrators は GA、Authenticated
Users は `0x00120083`（read/write data と接続に必要な標準権限。`FILE_CREATE_PIPE_INSTANCE` `0x4` は含めない）、
daemon の具体的 process SID だけは再 arm に必要な `0x0012019f` を得る。production TCP は廃止し、明示 endpoint の
test fixture だけに残す。

### (2) client からの server 認証

launcher は HTTP/2 bytes を送る前に pipe server PID の process token SID を検証し、LocalSystem または launcher
自身の SID だけを許可する。具体的 read/write data access と `SecurityImpersonation` を要求し、偽 server、低い
impersonation level、remote pipe は拒否する。

### (3) caller 認証と local fallback

server は最初の request bytes を読む前に専用 OS thread で `ImpersonateNamedPipeClient` を実行し、impersonation
level と caller SID を取得する。primary token を複製して `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` を適用後、
必ず `RevertToSelf` する。この caller context を intake→scheduler→local fallback へ明示的に渡す。

fallback は caller の環境と実行ファイル解決結果を使い、`CreateProcessAsUserW` で suspended 起動する。既存 Job
Object へ割り当てて guardian を seed した後に resume する。token、環境、Job 割当て、process 起動のどれかが失敗
した場合も daemon の ambient token では再試行しない。これにより正規 launcher の fallback とプロセスツリー kill
を保ちながら、LocalSystem への昇格を遮断する。

### (4) Status/Admin 分離

Status は read-only loopback `127.0.0.1:50073`、変更操作は opt-in `StatusAdmin` のまま維持する。LocalIntake pipe
には Status/Admin RPC を載せない。caller 実行認証を管理 API の認可代わりに使わない。

### (5) service identity

installer の daemon は現時点で LocalSystem を維持する。安全性は「service が非 LocalSystem」という弱い前提では
なく、DACL＋双方向 SID 検証＋caller restricted token＋fail-closed 起動で担保する。user-session agent と machine
service の完全分離は別設計とし、この境界を弱める理由にはしない。

## 検証状況

- ローカル: `cargo test -p sembazuru-agent --lib` は `258 passed; 0 failed; 2 ignored`。
  `intake_pipe::tests` 9件、Rust 1.97 clippy／fmt／scope／差分検査も成功し、HEAVY統合reviewはblockingなし。
- clean Windows CI: [run 29394437184](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29394437184) の
  [LocalIntake job 87284613248](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/29394437184/job/87284613248) が成功。
  2標準ユーザーのdaemon-side childは別々のcaller SIDで、`SYSTEM=false crossed=false`。daemon停止後も
  launcher fallbackがcaller SID・exit 0で完走し、最終PASSを出した。
- 現ローカル機には既存の canonical `SembazuruDaemon` service があるため、ゲートは service/config/account を変更せず
  exit 1 で拒否する。このfail-fastは既存serviceを変更しない安全条件として維持する。

## 繰延・未決

- LocalSystem service側fallbackは現在stdout/stderrをlauncherへstreamしない。clean CIでWindows PowerShellを直接
  payloadにするとhost初期化が `0xFFFF0000` で失敗したため、SEC-001のSID証拠はOS一次情報の`whoami.exe`へ固定した。
  console process互換性と出力転送は別correctness残課題であり、解消のためにrestricted token境界を弱めない。
- user-session agent と machine service の完全分離、ProgramData の最小権限化（別 OPEN 項目）。
- signing／EDR allowlist の実運用確認。
