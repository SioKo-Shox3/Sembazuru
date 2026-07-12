# Sembazuru 直接コミット運用版 修正計画書

- 対象リポジトリ: `SioKo-Shox3/Sembazuru`
- 方針: リポジトリ所有者が `main` へ直接コミットする前提
- 想定基準コミット: `a19c125b4393a4cda804b881ea334f2cf39bfabe`
- 目的: フェーズ1から順に完了すれば、既知のP0/P1問題をすべて閉じられる作業計画にする
- レビュー種別: 静的敵対的レビューに基づく修正計画
- 注意: Windows実機での動的検証、multi-user権限境界テスト、2台LANテストは各フェーズ内で追加する

---

## 0. 運用方針

PRは使わず、**小さな直接コミットを積む**。ただし、PRを使わない分、各コミットの粒度と検証ログを厳密にする。

### 0.1 直接コミットの基本ルール

1. 1コミット = 1つのsecurity invariant、または1つの明確なmechanical refactor。
2. `main`へ直接積むが、各フェーズ完了ごとにタグを切る。
3. コミットメッセージに必ず以下を入れる。
   - Fix ID
   - 閉じる攻撃経路またはcorrectness bug
   - 追加テスト名
   - 実行した検証コマンド
4. フェーズ途中で失敗したら、最後のフェーズタグへ戻す。
5. 互換fallbackを残す場合は、production defaultでは必ず無効にする。
6. 「warningで済ませる」はP0では不可。既定はhard fail。
7. cache関連は「missが増える」は許容、「false hit」は不可。
8. auth関連は「LAN-trustedなのでOK」で止めない。最低限secure defaultを入れる。

### 0.2 推奨タグ

```text
review-fix/start-a19c125
review-fix/phase-01-session-boundary
review-fix/phase-02-secure-defaults
review-fix/phase-03-writeback-authority
review-fix/phase-04-local-privilege
review-fix/phase-05-worker-auth
review-fix/phase-06-cache-correctness
review-fix/phase-07-path-hardening
review-fix/phase-08-runtime-resilience
review-fix/phase-09-ci-docs-release-gates
```

### 0.3 各コミット後の最低検証

```powershell
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
```

C++ hookやinstallerに触れた場合は追加で以下。

```powershell
cmake -S hooks -B hooks/build -A x64
cmake --build hooks/build --config Release
cmake -S hooks -B hooks/build32 -A Win32
cmake --build hooks/build32 --config Release
```

該当フェーズの終わりには `.github/workflows/ci.yml` と同等の主要PowerShell gateを実行する。

---

## 1. 追加で見つかった要修正点

前回指摘点以外、または前回計画では十分に強調していなかった追加修正点は以下。

| ID | 優先度 | 追加指摘 | 理由 |
|---|---:|---|---|
| ADD-001 | P0 | session `finish()` 後も既存data-plane connectionがcapabilityを保持し続け、late operation可能 | `ConnGuard`が`Arc<SessionCapability>`を保持する設計だと、registryから削除後もOpenRead/Read/WriteBackが通り得る。action完了後のlate WriteBackは危険 |
| ADD-002 | P0/P1 | unknown non-empty `session_id` がlegacy/unscopedへfallback | これは前回再レビューで新たに確定した重大穴。ADR 0013の効果を無効化する |
| ADD-003 | P1 | Coordination / file server がauthなしで非loopback bindされた場合にwarning止まり | token未設定 + LAN bindはrogue worker登録 / file supply露出につながる。secure defaultはhard failが望ましい |
| ADD-004 | P1 | `Status admin` opt-in後もcaller認証はない | 暫定緩和としてdefault-denyは良いが、opt-in後は同一ホスト低権限ユーザーからconfig mutation可能 |
| ADD-005 | P1 | Worker Executionのplain pathが環境denylist | `SEMBAZURU_*`以外のsecretがservice envにあればchildへ漏れる。allowlistへ移行すべき |
| ADD-006 | P1 | cache publish / WriteBack / file supplyがreparse pointをhandle-basedに防げていない | lexical checkだけではjunction/symlink/ADS等に弱い |
| ADD-007 | P2 | cargo-deny/SBOMは入ったが、権限境界・session spoof・path corpus CIがまだ不足 | direct commit運用ではCI gateがより重要 |

これらは下記フェーズに統合済み。

---

# 2. 全フェーズ概要

| フェーズ | 目的 | 完了時に閉じる主問題 |
|---:|---|---|
| Phase 1 | data-plane session境界を安全化 | unknown session fallback、late operation、session theft被害拡大 |
| Phase 2 | secure defaultを強制 | Worker LAN RCE、authなしLAN bind、verified tool name-only record |
| Phase 3 | WriteBackをagent-authoritativeにする | root内任意書込み、worker指定path、late WriteBack |
| Phase 4 | LocalIntakeの権限境界を修正 | LocalSystem local fallback RCE |
| Phase 5 | Worker Execution本認証 | Execute/Abort未認証RCE |
| Phase 6 | cache correctnessの残差を閉じる | unresolved tool、temp heuristic、registry/dir/RMW policy |
| Phase 7 | Windows path hardening | reparse/ADS/junction/symlink escape |
| Phase 8 | runtime resilience/resource control | server task死、heartbeat再接続、DoS、partial publish |
| Phase 9 | adversarial CI/docs/release gate | 再発防止と配布準備 |

---

# Phase 1: data-plane session境界を安全化する

## Phase 1のゴール

ADR 0013で導入したsession registryを、攻撃者がlegacy fallbackやlate connectionで迂回できない状態にする。

## 1.1 Commit: `phase1: reject unknown data-plane session ids`

### 対象

- `crates/agent/src/fileserver.rs`
- `crates/agent/src/session_registry.rs`
- `crates/agent/tests/dataplane_fs.rs`
- `crates/dataplane/src/ops.rs`

### 修正内容

現在の挙動:

```rust
let cap = match registry.get(&session_id).await {
    Some(c) => c,
    None => SessionRegistry::legacy_capability(worker_root),
};
```

これを次へ変更する。

```rust
let cap = if session_id.is_empty() {
    if legacy_sessions_enabled {
        SessionRegistry::legacy_capability(worker_root)
    } else {
        reject("session id required")
    }
} else {
    registry
        .get(&session_id)
        .await
        .ok_or_reject("unknown or expired session id")
};
```

### 実装要件

- production daemonでは `legacy_sessions_enabled = false`。
- test helperだけlegacyを有効化可能。
- unknown non-empty IDは必ずreject。
- expired IDもreject。
- rejectはHelloResponseで明示し、その後close。

### テスト

- `hello_unknown_nonempty_session_id_is_rejected`
- `hello_expired_session_id_is_rejected`
- `hello_empty_session_id_rejected_in_production_mode`
- `legacy_empty_session_id_allowed_only_in_test_compat_mode`
- `unknown_session_cannot_open_any_file`
- `unknown_session_cannot_writeback_any_path`

### 完了条件

unknown session IDでOpenRead/Read/Has/WriteBackへ到達できない。

---

## 1.2 Commit: `phase1: close capabilities when action session finishes`

### 追加指摘 ADD-001 対応

### 問題

`SessionRegistry::finish(session_id)`がmapからentryを削除しても、既存connectionが`Arc<SessionCapability>`を保持している場合、そのconnectionはcapabilityを使ってoperationを続行できる。action完了後のlate WriteBackやlate Readが可能になる。

### 対象

- `crates/agent/src/session_registry.rs`
- `crates/agent/src/fileserver.rs`
- `crates/agent/src/intake.rs`

### 実装方針

`SessionCapability`にterminal stateを追加する。

```rust
pub enum SessionState {
    Open,
    Closing,
    Closed,
}
```

簡易には以下でもよい。

```rust
closed: AtomicBool
```

`finish()`はmapからremoveするだけでなく、capabilityを`closed=true`にする。file server側の各operationは先頭でclosedを確認する。

```rust
if cap.closed() {
    return protocol_error_or_empty_response;
}
```

WriteBackだけは特にhard rejectにする。

### 受入条件

- action完了後、同じconnectionでOpenReadできない。
- action完了後、同じconnectionでRead/Hasできない。
- action完了後、同じconnectionでWriteBackできない。
- finish後にconnectionが残ってもidle sweeperやdropでリークしない。
- normal action中のreadは壊れない。

### テスト

- `late_open_read_after_finish_is_rejected`
- `late_read_after_finish_is_rejected`
- `late_writeback_after_finish_is_rejected`
- `finish_marks_live_connection_capability_closed`
- `closed_session_cleanup_does_not_panic`

---

## 1.3 Commit: `phase1: make legacy data-plane compatibility explicit unsafe`

### 目的

旧worker互換を残す場合でも、名前と設定で危険性を明確にする。

### 実装

- config/env例:
  - `SEMBAZURU_UNSAFE_LEGACY_DATAPLANE_SESSIONS=1`
  - `unsafe_legacy_dataplane_sessions = true`
- docsに「production禁止」と明記。
- defaultはfalse。

### 完了条件

grepで`legacy_capability(`の呼び出し箇所が明示unsafe flag配下だけになる。

---

## Phase 1 完了時の検証

```powershell
cargo test -p sembazuru-agent dataplane
cargo test -p sembazuru-agent session
cargo test --workspace
```

### Phase 1 完了タグ

```bash
git tag review-fix/phase-01-session-boundary
```

---

# Phase 2: secure defaultを強制する

## Phase 2のゴール

mTLSやnamed pipeの本実装前でも、既定設定でRCEやauth無効LAN公開が起きないようにする。

---

## 2.1 Commit: `phase2: refuse insecure non-loopback Worker Execution binds`

### 対象

- `crates/worker/src/run.rs`
- `crates/worker/src/config.rs`
- `crates/worker/src/bin/sembazuru_worker.rs`
- docs

### 修正内容

Worker Execution RPCは未認証なので、loopback以外へのbindを既定拒否する。

```rust
if !addr.ip().is_loopback() && !config.unsafe_allow_insecure_execution_lan {
    return Err("refusing unauthenticated Worker Execution on non-loopback".into());
}
```

### 設定名

危険性が分かる名前にする。

```toml
unsafe_allow_insecure_execution_lan = false
```

env:

```text
SEMBAZURU_UNSAFE_ALLOW_INSECURE_EXECUTION_LAN=1
```

### テスト

- `worker_refuses_0_0_0_0_without_unsafe_flag`
- `worker_refuses_lan_ip_without_unsafe_flag`
- `worker_accepts_loopback`
- `worker_allows_lan_only_with_unsafe_flag`

### 完了条件

未認証Executionを既定でLAN公開できない。

---

## 2.2 Commit: `phase2: hard-fail unauthenticated Coordination/file-server LAN binds`

### 追加指摘 ADD-003 対応

### 対象

- `crates/agent/src/run.rs`
- `crates/agent/src/config.rs`
- docs

### 修正内容

現在の`warn_if_exposed`を、authなし非loopbackではhard errorにする。

```rust
if !auth_enabled && !addr.ip().is_loopback() && !unsafe_allow_unauthenticated_lan {
    return Err("refusing unauthenticated LAN bind".into());
}
```

### 対象plane

- Coordination
- file server

LocalIntake/Statusは既にloopback-onlyなので別。

### 例外flag

```text
SEMBAZURU_UNSAFE_ALLOW_UNAUTHENTICATED_LAN=1
```

### テスト

- `daemon_refuses_coord_lan_without_token`
- `daemon_refuses_fileserver_lan_without_token`
- `daemon_allows_lan_with_cluster_token`
- `daemon_allows_loopback_without_token`
- `unsafe_override_allows_but_warns`

---

## 2.3 Commit: `phase2: propagate worker.toml cluster token to VFS data-plane`

### 対象

- `crates/worker/src/config.rs`
- `crates/worker/src/run.rs`
- `crates/worker/src/lib.rs`
- `crates/worker/src/vfs_pipe.rs`
- `crates/worker/src/fileclient.rs`

### 修正内容

`vfs_pipe`が`cluster_token_from_env()`を直接読む設計を廃止。解決済み`WorkerConfig`から`WorkerVfsConfig`へtokenを注入する。

### テスト

- `worker_file_token_used_for_register_and_dataplane`
- `env_token_overrides_file_token`
- `vfs_pipe_no_direct_env_token_read`
- auth E2E: token only in worker.toml

---

## 2.4 Commit: `phase2: do not record cache entries for unresolved verified tools`

### 対象

- `crates/cas/src/toolchain.rs`
- `crates/agent/src/action_cache.rs`
- `crates/agent/src/intake.rs`
- `crates/worker/src/lib.rs`

### 修正内容

`toolchain_digest`を分類付きidentityへ変更する。

```rust
pub enum ToolchainIdentity {
    Content { digest: Digest, path: PathBuf },
    NameOnly { digest: Digest, argv0: String },
}
```

record条件:

```rust
tool_verified && matches!(tool_identity, ToolchainIdentity::Content { .. })
```

### テスト

- `verified_tool_unresolved_is_not_recorded`
- `verified_tool_resolved_file_is_recorded`
- `worker_nameonly_identity_skips_record`
- `agent_worker_tool_identity_mismatch_skips_record`

---

## 2.5 Commit: `phase2: use checked config load in Status get/set`

### 対象

- `crates/agent/src/status.rs`
- `crates/agent/src/config.rs`
- GUI error handling

### 修正内容

- `get_config`: `DaemonConfig::load_or_refuse`
- `set_config`: `DaemonConfig::load_or_refuse`
- invalid configをdefaultからpatch保存しない

### テスト

- `get_config_refuses_invalid_existing_config`
- `set_config_does_not_overwrite_invalid_existing_config`
- `get_config_defaults_when_absent`
- `set_config_preserves_valid_existing_values`

---

## Phase 2 完了条件

- LAN RCEの既定公開ができない。
- authなしCoord/file-server LAN bindができない。
- config-only tokenでVFS auth成功。
- name-only tool identityでrecordされない。
- invalid configがStatus経由でdefault上書きされない。

### Phase 2 完了タグ

```bash
git tag review-fix/phase-02-secure-defaults
```

---

# Phase 3: WriteBackをagent-authoritativeにする

## Phase 3のゴール

workerがagent-side pathを指定できない、またはdeclared output以外に書けない状態にする。

---

## 3.1 Commit: `phase3: pass declared_outputs into SessionCapability`

### 対象

- `crates/agent/src/intake.rs`
- `crates/agent/src/session_registry.rs`
- `crates/agent/src/fileserver.rs`

### 修正内容

`registry.create(..., Default::default())`を廃止し、`declared_outputs`を正規化して渡す。

### 重要方針

- declared outputが空の場合、WriteBackは禁止。
- `within_root` fallbackは削除。
- trace-discovered outputsはWriteBack権威に使わない。

### テスト

- `writeback_to_declared_output_succeeds`
- `writeback_to_root_but_undeclared_path_fails`
- `writeback_empty_declared_outputs_fails`
- `writeback_dotdot_declared_output_rejected`
- `writeback_absolute_outside_root_rejected`

---

## 3.2 Commit: `phase3: replace WriteBack path authority with output_id`

### 対象

- `crates/dataplane/src/ops.rs`
- `crates/dataplane/src/wire.rs`
- `crates/agent/src/fileserver.rs`
- `crates/agent/src/session_registry.rs`
- `crates/worker/src/fileclient.rs`

### 仕様

```rust
pub struct WriteBackRequest {
    pub output_id: u32,
    pub digest_hex: String,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub last: bool,
}
```

session側:

```rust
struct OutputSpec {
    id: u32,
    final_path: PathBuf,
    max_size: u64,
}
```

### 互換

旧path-based WriteBackはproductionでは拒否。test compatだけ残すならunsafe flag必須。

### テスト

- `writeback_unknown_output_id_rejected`
- `writeback_other_session_output_id_rejected`
- `writeback_path_field_not_accepted_in_v2`
- `writeback_size_limit_enforced`
- `writeback_digest_mismatch_rejected`

---

## 3.3 Commit: `phase3: agent-owned staging and commit only after action success`

### 対象

- `crates/agent/src/fileserver.rs`
- `crates/agent/src/session_registry.rs`
- `crates/agent/src/intake.rs`

### 修正内容

- WriteBackはfinal pathへ直接書かない。
- agent-owned staging rootへ保存。
- action success後にagentがpublish。
- action failure/timeout/abort/closed sessionではstaging削除。
- temp名はCSPRNG + `create_new`。

### テスト

- `failed_action_does_not_publish_writeback`
- `late_writeback_after_exit_rejected`
- `digest_mismatch_removes_staging`
- `crash_like_disconnect_leaves_no_final_output`
- `staging_temp_is_unique_and_create_new`

---

## Phase 3 完了条件

- workerは任意pathをwireで指定できない。
- declared output以外へのWriteBackはできない。
- action完了後のlate WriteBackはできない。
- final publishはagentだけが行う。
- partial final outputが残らない。

### Phase 3 完了タグ

```bash
git tag review-fix/phase-03-writeback-authority
```

---

# Phase 4: LocalIntakeの権限境界を修正する

## Phase 4のゴール

同一ホスト低権限ユーザーがLocalSystem daemonへ任意commandを投げ、SYSTEMとしてlocal fallbackさせる経路を閉じる。

---

## 4.1 Commit: `phase4: change daemon service default account away from LocalSystem`

### 対象

- `crates/agent/src/bin/sembazuru_daemon.rs`
- `crates/agent/src/service.rs`
- installer
- docs

### 修正内容

- self-install defaultを`Virtual`へ変更。
- `--account system`は明示opt-in。
- system指定時は強いwarning。
- docsにACL grant手順を追加。

### テスト

- `parse_account_defaults_to_virtual`
- `explicit_system_account_still_supported_with_warning`

---

## 4.2 Commit: `phase4: introduce LocalIntake transport abstraction`

### 対象

- `crates/agent/src/intake.rs`
- `crates/agent/src/bin/sembazuru_launcher.rs`

### 修正内容

- TCP LocalIntake実装をtrait背後へ移動。
- Windows named pipe実装を追加する前段階。
- testはTCPを使えるがproduction pathは切替可能にする。

---

## 4.3 Commit: `phase4: implement Windows named-pipe LocalIntake`

### 対象

- `crates/agent/src/intake_pipe.rs` 新規
- `crates/agent/src/bin/sembazuru_launcher.rs`
- `crates/agent/src/run.rs`

### 仕様

Pipe名:

```text
\\.\pipe\Sembazuru\Intake\<UserSID>
```

DACL:

- current user
- Administrators
- SYSTEM

### テスト

- same user connect succeeds
- different user connect denied
- non-admin cannot connect to admin pipe

---

## 4.4 Commit: `phase4: run local fallback as caller token`

### 対象

- `crates/agent/src/lib.rs`
- `crates/agent/src/intake.rs`
- Windows token helper module

### 修正内容

- LocalIntake request contextへcaller token/SIDを保持。
- `run_local`を`run_local_as_caller`へ置換。
- token取得失敗時はdaemon-side fallbackせず、launcher-side fallbackへ返す。

### テスト

- local fallback child SID == caller SID
- daemon running as System still does not spawn System child
- token acquisition failure does not run as daemon token

---

## Phase 4 完了条件

- LocalIntake TCPはproductionで無効、またはunsafe明示flag必須。
- named pipeがcaller SIDを検証する。
- local fallbackはcaller tokenで実行。
- daemon default accountがSystemではない。
- multi-user権限境界テストが通る。

### Phase 4 完了タグ

```bash
git tag review-fix/phase-04-local-privilege
```

---

# Phase 5: Worker Executionの本認証

## Phase 5のゴール

agent以外がworkerへExecute/Abortできないようにする。

---

## 5.1 Commit: `phase5: add action capability fields to proto`

### 対象

- `crates/proto/proto/sembazuru/v0/control.proto`
- generated code
- docs/protocol

### 追加field

```proto
message ExecuteRequest {
  ...
  bytes action_capability = 20;
}

message AbortRequest {
  ...
  bytes action_capability = 20;
}
```

---

## 5.2 Commit: `phase5: implement signed action capability`

### 仕様

Capability payload:

```text
version
cluster_id
agent_id
worker_id
action_id
session_id
command_digest
vfs_root
declared_outputs_digest
issued_at
expires_at
nonce
```

署名/HMAC keyは当面cluster tokenから派生してもよいが、将来mTLSへ移す前提でtype分離する。

### 対象

- `crates/proto/src/auth.rs` または新規 `capability.rs`
- `crates/agent/src/scheduler.rs`
- `crates/worker/src/lib.rs`

### テスト

- missing capability rejected
- tampered command rejected
- tampered action_id rejected
- tampered session_id rejected
- expired capability rejected
- wrong worker rejected
- Abort without capability rejected

---

## 5.3 Commit: `phase5: bind capabilities to registered worker identity`

### 対象

- `crates/agent/src/coordination.rs`
- `crates/agent/src/scheduler.rs`
- `crates/worker/src/coordination.rs`

### 修正内容

- worker registrationにagent-side worker identityを保持。
- schedulerがそのidentityをcapabilityへ入れる。
- workerは自分宛capabilityだけ受理する。

---

## 5.4 Commit: `phase5: plan mTLS migration but keep capability as immediate enforcement`

### 成果物

- ADR更新
- protocol docs更新
- installer certificate provisioning backlog追加

---

## Phase 5 完了条件

- unauthenticated Execute/Abortが拒否される。
- session_id theftだけではworker executeできない。
- wrong worker capabilityが拒否される。
- nonloopback worker bindがsafeになる。

### Phase 5 完了タグ

```bash
git tag review-fix/phase-05-worker-auth
```

---

# Phase 6: cache correctnessの残差を閉じる

## 6.1 Commit: `phase6: remove temp path substring heuristic from cacheable input decisions`

### 対象

- `crates/tracer/src/graph.rs`
- `crates/tracer/src/action_key.rs`

### 問題

`\temp\` を含む実project pathがintermediate扱いされる可能性がある。

### 修正

- path locationだけでinput/outputをdropしない。
- transient判定はevent sequenceで行う。
- 判定不能ならcache不可。

### テスト

- project root under `C:\temp\project`
- source under `%TEMP%`
- compiler temp create/write/rename/delete
- read temp file is included as input

---

## 6.2 Commit: `phase6: classify registry/env/dir enumeration as cache policy blockers unless profiled`

### 目的

verified profile外、またはprofileが許可していないregistry/env/dir依存をcache不可にする。

### 方針

- clang-cl/cl/dxc profileに必要な許容範囲を明示。
- unknown registry readはcache blocking。
- directory enumerationはmembership fingerprintへ入れるかcache blocking。

---

## 6.3 Commit: `phase6: make manifest/action-result codecs versioned and bounded`

### 対象

- `crates/agent/src/action_cache.rs`
- `crates/cas/src/action_cache.rs`

### 修正

- magic
- version
- max inputs
- max cmds
- max string length
- checksum

### テスト

- malformed corpus
- huge count
- huge string length
- trailing junk
- version mismatch -> miss

---

## Phase 6 完了タグ

```bash
git tag review-fix/phase-06-cache-correctness
```

---

# Phase 7: Windows path hardening

## 7.1 Commit: `phase7: introduce Windows handle-based path containment utility`

### 対象

- 新規 `crates/windows_path` または `crates/agent/src/winpath.rs`
- agent/worker path users

### API案

```rust
struct RootHandle;
fn open_root(path: &Path) -> io::Result<RootHandle>;
fn open_child_no_reparse(root: &RootHandle, rel: &str) -> io::Result<OwnedHandle>;
fn verify_under_root(root: &RootHandle, handle: &OwnedHandle) -> io::Result<bool>;
```

---

## 7.2 Commit: `phase7: apply handle containment to WriteBack/cache publish`

### 対象

- `crates/agent/src/fileserver.rs`
- `crates/agent/src/action_cache.rs`

### 拒否

- ADS
- device path
- UNC
- trailing dot/space
- reserved names
- reparse escape
- parent swap race

---

## 7.3 Commit: `phase7: apply path corpus tests`

### テストケース

- junction
- symlink
- hardlink
- ADS
- `\\?\`
- `\??\`
- UNC
- drive-relative
- current-drive-rooted
- trailing dot/space
- reserved name
- 8.3 short name
- `temp` segment project root

### Phase 7 完了タグ

```bash
git tag review-fix/phase-07-path-hardening
```

---

# Phase 8: runtime resilience / resource control

## 8.1 Commit: `phase8: supervise daemon server tasks`

### 修正

- `tokio::spawn` detachedを`JoinSet`へ。
- Coordination/file server/Status/Intakeが落ちたらdaemon全体を終了。
- SCMへ非zero exitを伝播。

---

## 8.2 Commit: `phase8: add worker coordination reconnect loop`

### 修正

- `register_and_heartbeat`失敗後にexponential backoffで再登録。
- auth failure / version mismatch / network failureを分類。

---

## 8.3 Commit: `phase8: add per-layer quotas`

### 対象

- data-plane frames
- StatBatch path count
- Has digest count
- DirList entries
- WriteBack total bytes
- stdout/stderr cap
- predicted_paths count
- in-flight request count
- unauthenticated handshakes

---

## 8.4 Commit: `phase8: make cache publish failure non-success and rollback-aware`

### 修正

- partial renameをsuccessにしない。
- rollback journal。
- rollback不能時はhard error。
- dependent actionを進めない。

### Phase 8 完了タグ

```bash
git tag review-fix/phase-08-runtime-resilience
```

---

# Phase 9: CI / docs / release gates

## 9.1 Commit: `phase9: add adversarial security tests`

### 追加CI

- unknown/expired session
- unauthenticated Execute/Abort
- LocalIntake multi-user
- WriteBack undeclared output
- config invalid get/set
- worker config token-only

---

## 9.2 Commit: `phase9: add Windows path corpus tests to CI`

Phase 7のpath corpusをCI化。

---

## 9.3 Commit: `phase9: update docs and threat model`

### 対象

- README
- docs/quickstart.md
- docs/protocol/v0.md
- docs/deferred.md
- docs/security/*
- ADR 0013/0016 update
- 新ADR:
  - LocalIntake named pipe / caller token
  - Worker capability auth
  - WriteBack output authority
  - Windows path containment

---

## 9.4 Commit: `phase9: release gate checklist`

### 内容

- secure defaults
- auth enabled
- no unsafe legacy flags
- service account
- config ACL
- cert/token provisioning
- SBOM
- signing
- CI green
- adversarial tests green

### Phase 9 完了タグ

```bash
git tag review-fix/phase-09-ci-docs-release-gates
```

---

# 3. フェーズ順に実行するコマンド例

## 開始

```bash
git checkout main
git pull
git tag review-fix/start-a19c125 a19c125b4393a4cda804b881ea334f2cf39bfabe
```

## 各コミット前

```bash
git status
```

## 各コミット後

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
git add .
git commit -m "phase1: reject unknown data-plane session ids

Fix: SEC-004-A / ADD-002

Security invariant:
- unknown non-empty Hello.session_id is rejected
- production no longer falls back to legacy/unscoped capability

Tests:
- hello_unknown_nonempty_session_id_is_rejected
- hello_expired_session_id_is_rejected
- legacy_empty_session_id_allowed_only_in_test_compat_mode

Validation:
- cargo fmt --all --check
- cargo clippy --all-targets -- -D warnings
- cargo test --workspace"
```

## フェーズ完了時

```bash
git tag review-fix/phase-01-session-boundary
```

---

# 4. 完了判定

## 全P0完了条件

- [ ] unknown non-empty session IDが拒否される
- [ ] productionでempty session legacy fallbackが無効
- [ ] action finish後の既存connection操作が拒否される
- [ ] Worker Executionが未認証LAN clientを拒否する
- [ ] Worker Execution nonloopback bindが認証なしでは起動拒否
- [ ] LocalIntakeがnamed pipe + caller SIDで保護される
- [ ] local fallbackがcaller tokenで実行される
- [ ] daemon service defaultがSystemではない
- [ ] WriteBackがdeclared output setだけに可能
- [ ] workerがwireでarbitrary pathを指定できない
- [ ] worker.toml tokenだけでRegisterとVFS authが成功
- [ ] verified tool unresolved時にcache recordされない
- [ ] invalid configをStatus経由でdefault上書きできない

## 全P1完了条件

- [ ] authなしCoord/file-server LAN bindが既定拒否
- [ ] path containmentがhandle-based
- [ ] reparse/ADS/junction corpusがCIにある
- [ ] registry/env/dir/RMW cache policyが明確
- [ ] cache codecがversioned/bounded
- [ ] server task failureがsupervisorへ伝播
- [ ] heartbeat reconnectあり
- [ ] resource quotaあり
- [ ] partial cache publishがsuccessにならない
- [ ] docs/threat modelが実装と一致

---

# 5. 最短安全化ルート

時間が限られる場合も、最低限この順で進める。

1. Phase 1.1: unknown session reject
2. Phase 1.2: action finish closes live caps
3. Phase 2.1: worker nonloopback insecure reject
4. Phase 2.2: unauth Coord/file server LAN reject
5. Phase 2.3: worker.toml token propagation
6. Phase 2.4: unresolved verified tool no-record
7. Phase 3.1: declared_outputs binding
8. Phase 4.1: daemon default non-System

この8コミットで、現在の最も危険な穴はかなり閉じる。

---

# 6. 最終コメント

直接コミット運用は問題ない。ただし、PRレビューがない分、**コミットを小さくし、各コミットにsecurity invariantとテストを必ず紐づける**ことが必須。

今回追加で見つかった最重要点は、`finish()`後のlive connection capabilityと、unknown `session_id` のlegacy fallbackである。これらはADR 0013の安全性を根元から弱めるため、Phase 1で最初に閉じる。
