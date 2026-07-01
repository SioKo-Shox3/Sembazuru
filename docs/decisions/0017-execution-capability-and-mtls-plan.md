# 0017 — Worker Execution 認証（signed action capability）と mTLS 移行計画

- ステータス: **決定済み（ACCEPTED）。** 起案: review-fix Phase 5、2026-07-02。
  決定者承認: プロジェクトリード（review-fix Phase 5 の進行を通じて）。
- 決めること: ADR 0006 は Coordination（`Register`）とデータプレーン（`Hello`）の認証を
  決定したが、**Worker Execution（`Execute`/`Abort`）は対象外**のまま残り、無認証で
  任意コード実行が可能だった（review-fix Phase 5 の起点）。本 ADR は
  **(1) Execution plane の直近の認証機構**（signed action capability）と
  **(2) mTLS への移行計画**（ADR 0006 §将来余地の予約フィールド 11 を Execution にも
  適用する道筋）を決定する。
- 判定基準: ADR 0006 と同じ非交渉事項（正確性 > 速度／ローカルフォールバック常時／
  clang-cl ファーストクラス）。Execution は RCE 面（任意コマンド実行）を持つため、
  ADR 0006 の Coordination/データプレーンより一段重い扱いを要する。

## 背景

review-fix Phase 5 着手時点の状態（`crates/worker/src/lib.rs` の `Execution` サービス）:
worker の `Execute`/`Abort` RPC は **一切の呼び出し元認証を持たず**、`command.argv`/`env`/
`cwd` をそのまま子プロセスとして起動していた。唯一の防御は Phase 2（ADR は無し、
review-fix Phase 2）で追加した **loopback-only bind gate**（`unsafe_allow_insecure_execution_lan`
既定 false）——非 loopback bind を拒否するのみで、loopback に到達できる主体は誰でも
無認証で任意コマンドを実行できた。ADR 0006 の共有トークンは `Register` とデータプレーン
`Hello` のみを対象とし、Execution には**そもそも運ばれていなかった**（`ExecuteRequest`/
`AbortRequest` にトークンや capability を運ぶ field 自体が存在しなかった）。

## 決定

**ADR 0006 の LAN-trusted モデルを Execution plane にも拡張し、認証機構として
署名付き action capability（対称鍵 MAC）を即時導入する。** 将来の mTLS 移行は
ADR 0006 と同じく「wire 非破壊の移行口を残す」形で計画するに留め、今回は実装しない
（決定者承認済みの繰延方針を踏襲）。

### 1. 直近の認証機構＝signed action capability（ADR 0006 共有トークンから鍵導出）

- **鍵:** 新規の別鍵を配布・運用するコストを避けるため、ADR 0006 の
  `SEMBAZURU_CLUSTER_TOKEN`（Coordination/データプレーンと共通）から
  `blake3::derive_key("sembazuru action-capability v1", cluster_token)` で
  Execution 専用の 256-bit 鍵を KDF 導出する（トークンそのものを MAC 鍵に流用しない）。
  クラスタ全体でトークン 1 本の配布のみという運用コストは変えない。
- **capability の中身と署名:** `ActionCapability{version, worker_id, action_id, session_id,
  command_digest, vfs_digest, issued_at, expires_at, nonce}` を
  `blake3::keyed_hash(key, signing_bytes)` で MAC する。`command_digest` は argv/env
  (sorted)/cwd の決定的 BLAKE3、`vfs_digest` は `VfsExecution` 全体（有無を含む）の
  決定的 BLAKE3。scheduler が dispatch 時に選択した worker の `worker_id` を bind して
  mint し、`ExecuteRequest`/`AbortRequest` の `action_capability`（field 20）に載せる。
- **検証（worker 側）:** `verify_execute_capability`/`verify_abort_capability`
  （`crates/worker/src/lib.rs`）が spawn/abort の**前に** MAC・有効期限・
  worker_id/action_id/session_id/command_digest/vfs_digest の全 binding を検証し、
  いずれか不一致なら `permission_denied`（spawn しない・カウンタも増やさない）。
- **有効/無効の切り替え:** ADR 0006 と同じ back-compat 原則——
  **cluster token が未設定なら Execution も無認証のまま**（M5/M6 LAN 既定を壊さない）。
  トークンを設定したときのみ enforce する。
- **なぜ mTLS を今回選ばなかったか（ADR 0006 §比較を踏襲）:** 証明書 CA 運用・
  worker への配布・ローテーション・失効管理は恒常運用コストであり、現段階
  （社内/開発 LAN・単一クラスタ）ではその投資に見合う脅威（経路上の能動的中間者・
  任意網からの攻撃者）が現実的でない。共有鍵 MAC で「トークンを持たない第三者は
  任意コード実行できない」という Execution の Done-when を最小コストで満たせる。

### 2. worker identity 統合性（routing table 側の残存穴を閉じる）

capability が `worker_id` 文字列を bind しても、agent 側 `WorkerTable` の
`worker_id → execution_endpoint` mapping 自体が同一 worker_id の再登録で
乗っ取られれば、capability の暗号は正しくても誤った宛先へ配送される。
review-fix Phase 5.3 でこれを閉じた: `upsert_register` は同一 worker_id への
**live**（`last_ping_age < dead_timeout`）な既存 entry と異なる `execution_endpoint`
での再登録を reject する（first-registrant-wins-while-live）。owner が dead に
なった後の reclaim・同一 endpoint での再登録は引き続き許可。

### 3. wire 非破壊（ADR 0006 予約フィールド 11 との関係）

- `ExecuteRequest`/`AbortRequest` の `action_capability`（新規 field 20）は
  ADR 0006 の `RegisterRequest.auth_token`（field 10）とは**独立**した新規追加であり、
  既存 field の意味は一切変更していない（`docs/protocol/v0.md` §6 versioning 準拠）。
- ADR 0006 が Coordination/データプレーン向けに予約した field 11
  （将来のクライアント証明書/attestation 用）は、Execution plane にも
  **同じ移行口として転用できる**——mTLS 移行時は Execution の capability を
  「クライアント証明書＋短命トークン」の組み合わせに置き換える設計とし、
  `action_capability` field 自体は（署名フォーマットが変わっても）同じ opaque
  bytes 運搬 field として存続できる。

## 将来余地（mTLS 移行計画・採らなかった選択肢）

ADR 0006 §将来余地と同じ扱いとする——**外部公開・マルチテナント・非信頼網が要件化した
時点で再評価**。移行時の設計方針（今回は実装しない）:

- **per-worker クライアント証明書:** worker ごとに CA 発行のクライアント証明書を持たせ、
  tonic `ServerTlsConfig.client_ca_root` で相互 TLS を要求する。証明書の Common Name/SAN を
  `worker_id` に対応させることで、Phase 5.3 で閉じた「worker_id 文字列は正しいが
  routing table が乗っ取られる」問題を **TLS 層で証明可能な worker identity**に
  格上げできる（現状は共有トークン保持者なら誰でも任意の worker_id を名乗れる）。
- **installer での証明書配布バックログ（本 ADR で新規に積む項目）:**
  - mTLS 移行時、worker 側インストーラー（WiX/MSI）は (a) worker 固有の秘密鍵生成、
    (b) CA への証明書署名要求（CSR）提出、(c) 発行された証明書のインストール、
    (d) 失効/ローテーション時の再配布、を担う必要がある。これは ADR 0006 §繰延の
    **Authenticode コード署名証明書**（バイナリ署名・EDR/SmartScreen 対策）とは
    **別系統の PKI**（mTLS クライアント認証用）であり、混同しないこと。
  - 現段階では**着手しない**（実 2 台以上のクラスタ運用・外部公開が要件化してから）。
    `docs/deferred.md` にバックログとして追記する（本 ADR 参照）。
- **capability フォーマットの互換性:** `ActionCapability`（`crates/proto/src/capability.rs`）
  は `version: u8` を持つため、mTLS 移行時に署名方式が変わっても version bump で
  wire 非破壊に切り替えられる。

## 繰延（本 ADR の射程外・別承認）

- **mTLS 実装そのもの**（CA 運用・証明書発行・installer 配布）は上記のとおり
  外部公開/マルチテナント要件化まで繰延。
- **capability の replay 防止（server 側 nonce cache）:** 現状 300 秒 TTL 内の
  replay は防げない（worker_id/action_id/session_id/command/vfs すべて bind
  済みのため payload 差し替えは不可、同一 action の再実行のみ）。mTLS 移行
  （per-接続の相互認証）で本質的に解消される見込みのため、bounded な
  seen-nonce LRU の先行実装は行わない（`docs/deferred.md` 参照）。
- **非-loopback Execution bind gate の緩和:** capability enforce 時は
  非-loopback bind も認証済みで安全なはずだが、`unsafe_allow_insecure_execution_lan`
  の既定は変更していない（bind gate と capability enforce は独立したレイヤーとして
  維持し、緩和は実 LAN 運用が要件化してから再評価）。

## 影響

- `crates/proto/proto/sembazuru/v0/control.proto`: `ExecuteRequest`/`AbortRequest` に
  `action_capability`（field 20, bytes）を追加（review-fix Phase 5.1）。
- `crates/proto/src/capability.rs`（新規）: `ActionCapability` の署名/検証/
  `command_digest`/`vfs_digest`（review-fix Phase 5.2, F3）。
- `crates/agent/src/scheduler.rs`: dispatch 時に capability を mint（Phase 5.2）。
- `crates/worker/src/lib.rs`: `execute`/`abort` ハンドラでの verify-before-spawn
  （Phase 5.2, F3）。
- `crates/agent/src/coordination.rs`: `upsert_register` の worker_id squatting 防止
  （Phase 5.3）。
- `docs/protocol/v0.md` §5（Security）に Execution plane の認証を追記（本 ADR と
  同時に反映）。
- `docs/deferred.md`: mTLS/installer 証明書配布バックログ・replay 防止・
  非-loopback bind gate 緩和の 3 項目を追記。
