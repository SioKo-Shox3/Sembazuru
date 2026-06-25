# 0013 — agent 権威の per-action session capability（データプレーンの scope/pin/writeback を session に束縛）

- ステータス: **起案（PROPOSED）。** 起案: 2026-06-24。決定者承認: 保留（プロジェクトリード）。
  出所: コードレビュー `docs/Sembazuru_code_review_action_guide.md`（COR-001 / SEC-004 / SEC-003 / PROTO-001）、
  Plan エージェント(opus)検証済み。
- 決めること: データプレーンの file 供給/書き戻しを **どの単位の権威に束縛するか**。**(1) session_id の生成**、
  **(2) agent 権威 SessionRegistry**、**(3) session_id を Hello へ運ぶ**、**(4) fileserver の scope/pin/digest/writeback ゲート**、
  **(5) session ライフサイクル**、**(6) wire 互換**。
- 判定基準: 非交渉（**正しさ>速度**＝action 跨ぎの stale 入力を出さない／**ローカルフォールバック常時**／出力バイト不変）。
  LAN-trusted＋共有トークン（[ADR 0006](0006-trust-and-auth.md)）が現脅威モデル。mTLS/per-worker 暗号 identity は後続 zero-trust（reserved field 11）。
- 関連: [ADR 0006](0006-trust-and-auth.md)（auth・§6 capability flag・wire 互換）、
  [ADR 0001](0001-vfs-approach.md)（VFS）、[ADR 0007](0007-arbitrary-process-distribution.md)（ローカルフォールバック）、
  `crates/agent/src/{fileserver,intake,run,scheduler}.rs`、`crates/agent/src/session_registry.rs`(新)、
  `crates/dataplane/src/ops.rs`、`crates/worker/src/{lib,vfs_pipe,fileclient,coordination}.rs`、
  `crates/proto/.../control.proto`、`docs/protocol/v0.md §4.1/§5`。

## 背景

レビューが指摘する4件は**単一の構造欠陥**に帰着する: データプレーンの file 供給が **agent 権威の per-action session に束縛されていない**。

- **COR-001**: `fileserver.rs::Session` は `serve_with_map`(`:225`) で**プロセス全体に1つ**生成され全接続で共有。`pinned` map がプロセス寿命で固定され、action A が pin した v1 を、A 完了後に編集された後でも action B に返す＝stale。`ingest`(`:144-159`) は pin 判定と disk read の間で lock を落とす first-touch race も持つ。
- **SEC-004**: scope root は worker が Hello で**自己申告**（`handshake`→`normalize_root(&h.root)` `:392`）。共有トークンを持つ worker は root を `c:\`/空に広げ自スコープを無効化できる。
- **SEC-003**: `write_back`(`:507`) は `PathBuf::from(&req.path)` を**スコープ検査なし**で使い、worker が名指す任意絶対パスへ agent 権限で書く。
- **PROTO-001(予測可能性)**: `session_id`/`action_id` は `intake.rs:160-161` で `intake-{n}` 連番（かつ `session_id==action_id`）。

`session_id` は制御プレーンで `ExecuteRequest.session_id` まで届くが **worker `execute`(`lib.rs:715`) で破棄**され、データプレーン Hello には乗らない。`v0.md §4.1` は「snapshot は **per session**」と記すが実装は **per process** で pin する＝仕様との乖離。

### 実装前提（現状調査で確定）

- `fileserver.rs::Session.cas` は **M9.2 で evict される `AgentCache` とは別物**（fileserver 専用の一時 `BlobStore`、Drop で消去）。allowed-digest gate は永続 action cache に**無影響**。
- action-cache strong key は session pin と**独立**（`AgentCache::resolve` は dispatch 前に disk から直接再読込）。順序ハザードなし。
- `scheduler.rs::pick_and_reserve` は worker 間で**再割当て**＝session は worker と 1:1 でない。
- agent 権威の素材は既存: `SubmitActionRequest.input_root`/`declared_outputs`（`control.proto:256-288`）が intake の手元（`:227-230/312-316/169`）。
- scheduler と fileserver は**アドレス文字列以外を共有しない**＝`SessionRegistry` を `run.rs` で生成し両者へ注入するのが自然な唯一の seam。

## 決定

### (1) session_id を 128bit 乱数化
`intake.rs:159-161` で `session_id` を `action_id`(=`intake-{n}`) から分離し、**OS CSPRNG(getrandom) 128bit→32hex**。`action_id` は trace dir 名/abort key なので連番のまま。`session_id: String` は既に opaque passenger ＝**型変更なし**、mint 値だけ変更。

### (2) agent 権威 SessionRegistry（新規 `session_registry.rs`）
session ごとに保持: `root`（agent 正規化済 input root・**worker 申告は使わない**）／`declared_outputs`／`pinned: HashMap<path, Arc<OnceCell<Digest>>>`（**per-path single-flight**＝race 解消）／`allowed_digests`（OpenRead pin で増える**共有 CAS への ACL overlay**）／`writebacks`／`created`＋`conns`。registry が **daemon 全体で1つの共有 `BlobStore`** を所有（per-server `Session.cas` を置換）。`run.rs::run_daemon` で1つ生成し intake と fileserver の**両方**へ注入。
（`dispatched_workers` テレメトリは**当初設計に含めたが実装では見送り**：データプレーン Hello に per-worker 秘密がなく、提示された session_id の peer が dispatch 先 worker か照合できないため、記録しても比較対象がない。下記「残存」の per-session capability token と同時に入れる。）

### (3) session_id をデータプレーン Hello へ
`worker/lib.rs execute`→`run_action`→`build_child`(VFS分岐 `:602`)→`serve_vfs_with_prefetch_ready`→`VfsState`→`FileClient::connect_with_rtt_session`→`HelloRequest` に session_id を配線。`HelloRequest`(`ops.rs:433-463`)は手書き構造体ゆえ**3つ目 field を追記＋寛容 decode**（旧2 field frame は `session_id=""`、strict trailing 検査を呼ばない）。

### (4) fileserver の4ゲート
`handshake` で token 検証後 `h.session_id` で registry を引き、**見つかれば `h.root` を完全無視**して `cap.root` を使う:
- **SEC-004**: `path_in_scope` の root 源を `cap.root` に（`normalize_requested`/`path_in_scope` `:321-360` は不変）。
- **COR-001**: `open_read` を `cap.pin`(single-flight) 経由に。pin は session 破棄で drop。action B は新 cap で新内容を pin。
- **Read/Has gate**: `read_range`/`has` を `cap.allowed_digests.contains(&digest)` で gate（cross-session digest oracle を閉じる）。
- **SEC-003**: `write_back` 冒頭で `req.path`(normalize 済) を `cap.declared_outputs` に照合。**空集合時は `cap.root` 内にフォールバック**（現状の任意絶対パスより厳密に良い）。

### (5) session ライフサイクル
dispatch 直前に `registry.create`、dispatch 戻り後（cache-hit 含む）`registry.finish` で overlay drop（共有 CAS blob は消さない）。**接続 close でなく完了＋expiry で破棄**（`conns` refcount）。バックストップに `run_daemon` の idle sweeper（M9.2 ループの兄弟・`WorkerTable` reaper と同思想）。**prefetch(M5.4) は同 session 接続で OpenRead を出す＝同 cap に warm＋authorize されるので無改修。M9.2 eviction は別ストアゆえ無影響。**

### (6) wire 互換
`Capabilities.supports_session_capability`(field 10、`supports_auth` field 7 と同型)を追加。新 worker は `local_capabilities` で true。旧 worker は `h.session_id==""`→**legacy unscoped 経路**（per-connection ephemeral cap）で既存テスト＆未更新 worker が動く。テスト entry point（`serve_files*`）も legacy default session を内部生成し diff 爆発を防ぐ。

## 影響

- 新規 `crates/agent/src/session_registry.rs`。`fileserver.rs`（handshake bind-by-session、per-op `&cap`、4ゲート、`Session` 退役、legacy fallback）。`intake.rs`（乱数 mint、create/finish）。`run.rs`（registry 生成＋両注入、idle sweeper）。`dataplane/src/ops.rs`（HelloRequest 3rd field＋寛容 decode）。`worker/src/{lib,vfs_pipe,fileclient}.rs`（session_id 配線）。`control.proto`＋`worker/coordination.rs`（capability flag）。`docs/protocol/v0.md`（§5 caveat を「agent 権威・session_id keyed」、WriteBack を「declared-output/root scoped」へ）。
- 検証（**実装済み・緑**）: SEC-004（`c:\`申告無視）UT＋cross-session digest isolation UT、COR-001 二 session UT（A の編集を B が観測）、single-flight race UT、absent-pin 非キャッシュ UT、declared 外 WriteBack 拒否 UT、idle sweeper UT、旧 worker(空 id) legacy 経路で既存テスト緑、fmt/clippy/test 緑（workspace 268 passed）。author 以外で `verifier`(opus)＝CONFIRMED、データプレーン/scope ゆえ `security-reviewer`(opus)＝PASS（バイパスなし）。determinism harness は本作業が supply/scope のみ＝出力バイト不変ゆえ CI ゲートに委譲。

## 残存・繰延（LAN-trusted・後続 zero-trust）

- **cross-worker session theft（bounded・not closed）**: 共有トークン保持 worker が他 session_id を**捕捉**できれば（予測は 128bit 乱数で不可）その scope を読める。到達範囲は権威 root＋declared_outputs のみ（`c:\`/任意書込み不可＝現状より厳密に良い）。データプレーン Hello は共有トークン認証で per-worker 秘密がなく、提示された id の peer が dispatch 先 worker か照合する手段がない（検知シグナルも置けない）。**完全閉鎖**は per-session capability token（agent が当該 worker の `ExecuteRequest` だけに渡す第2乱数を Hello で提示・registry 照合、reserved field 11・**mTLS 不要の additive**）＝小さな後続。本 registry seam が受け皿で、dispatch↔worker 束縛（旧 `dispatched_workers`）はこの token と同時に入れる。
- TLS（機密性）・per-worker mTLS identity は [ADR 0006](0006-trust-and-auth.md) のまま実 2 台 LAN 判断へ繰延。
- WriteBack の declared-output 粒度（どの output か）は content-addressed＋digest 検証で担保（誤バイト不可）。
