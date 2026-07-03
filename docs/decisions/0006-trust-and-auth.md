# 0006 — ワーカー信頼モデルと認証方式（M7）

- ステータス: **決定済み（ACCEPTED）。** 起案: M7.0、2026-06-14。
  決定者承認: プロジェクトリード、2026-06-14
  （信頼モデル＝LAN-trusted の堅牢化／認証＝共有トークン＋サーバ TLS／実証明書購入と
  実 2 台 LAN 実測は繰延、で承認）。
- 決めること: `docs/DESIGN.md` §9 と `docs/protocol/v0.md` §5・§3.1 が **M7 判断**として
  委ねた、**(1) ワーカー信頼モデル**（社内 LAN 前提か、ゼロトラスト前提か）、
  **(2) 制御プレーン／データプレーンの認証機構**、
  **(3) `RegisterRequest` 予約フィールド 10–11 の使い方と wire 非破壊の担保**。
- 判定基準: M7 Done-when＝「実プロジェクトで日常的に使い続けられる信頼性に到達」
  （DESIGN §7 M7）。非交渉事項（正確性 > 速度／ローカルフォールバック常時／clang-cl
  ファーストクラス）を満たすこと。

## 背景

M5 は LAN 前提・無認証 start で確定し（ADR `0004-scheduler-and-fanout.md` §6）、
ゼロトラスト可否を本 ADR（M7）へ送った。現状は **control/data plane・VFS パイプ・
agent fileserver のすべてが無認証**で、悪意/誤設定の worker が (1) 誤った出力を返す、
(2) アクションを吸引してブラックホール化する、(3) action cache の trace を過少申告して
stale 命中を招く、といった経路が開いている（`docs/deferred.md` M5.2/M5.5/M6.1 所見）。
M7 はこの信頼境界を閉じる。

## 問い

リモートワーカーをどこまで信頼するか。候補は 2 つ:

- **A. LAN-trusted の堅牢化** — 社内/開発 LAN・相互信頼ネットワークを前提に維持し、
  その上で「無認証 accept の閉鎖・誤結果注入の緩和・パススコープ・サンドボックス・
  運用堅牢化」を固める。認証は軽量（共有シークレット）で足りる。
- **B. ゼロトラスト** — 任意ネットワーク（非信頼網・外部公開）を前提に、全 RPC と
  データプレーンに強固な相互認証＋暗号化を必須化し、worker attestation を要求する。

## 比較

| 軸 | A. LAN-trusted の堅牢化 | B. ゼロトラスト |
|---|---|---|
| 認証の重さ | 共有トークン（per-RPC）＋必要時サーバ TLS。証明書配布不要 | mTLS（CA 発行・クライアント証明書を全 worker へ配布・ローテーション・失効管理）＋attestation |
| 運用負荷 | トークン 1 本を agent/worker に環境変数で配布するのみ | CA 運用・証明書ライフサイクル管理が恒常コスト |
| 守れる脅威 | LAN 内の偶発的誤接続・誤設定 worker・トークン非保持の第三者。**daily 使用の信頼性に十分** | 上記＋経路上の能動的中間者・任意網からの攻撃者 |
| 整合 | DESIGN §10 の目標（置き換えでなく信頼性＋daily 使用）／ADR 0004 §6 の M5 確定と地続き | 現段階では過剰。外部公開・マルチテナント化が生じてから価値が出る |
| 採用例 | **sccache-dist**（scheduler↔builder は JWT HS256 共有シークレット、IP:port バインド）。BuildXL は Azure 内部網の信頼境界前提で明示的トークン記述なし | REAPI 系のマネージド RBE（証明書/IAM 前提）|

主な出典:
- sccache 分散認証（JWT HS256・`server_auth`/`client_auth`）: github.com/mozilla/sccache `docs/Distributed.md`
- BuildXL 分散（orchestrator/worker・Attach、認証はネットワーク信頼前提）: github.com/microsoft/BuildXL `Documentation/Wiki/Distributed-Builds.md`
- tonic TLS/mTLS（`ServerTlsConfig`/`ClientTlsConfig`・rustls）: docs.rs/tonic `transport`
- per-RPC トークン（interceptor で metadata 検証）: tokio.rs/blog/2021-07-tonic-0-5

## 決定

**案 A（LAN-trusted の堅牢化）を採用する。** 認証は **共有トークン＋（設定可能な）
サーバ TLS** とする。決定者: プロジェクトリード、2026-06-14。

### 1. 信頼モデル＝LAN-trusted の堅牢化
社内/開発 LAN・相互信頼ネットワークを前提に維持する。ゼロトラストは現段階では過剰であり、
外部公開・マルチテナント化が要件化した時点で再評価する（下記「将来余地」）。

根拠: DESIGN §10 の現実的な目標は「既存製品の置き換えそのものでなく、無料・OSS の特定セグメントで
確実な代替＝daily 使用に耐える信頼性」。LAN-trusted の堅牢化で Done-when に最小コストで到達でき、
ゼロトラストの恒常運用コストは daily 使用の障害になりこそすれ信頼性を直接は上げない。

### 2. 認証機構＝共有トークン（per-RPC）＋設定可能なサーバ TLS
- **共有トークン:** クラスタ単位の共有シークレットを **環境変数**（例 `SEMBAZURU_CLUSTER_TOKEN`）で
  agent と全 worker に配布する。worker は Register（および後続のデータプレーン session 確立）で
  トークンを提示し、agent が照合する。一致で `accepted=true`、不一致は `accepted=false`＋
  **sanitize 済み** detail（内部パス等を露出しない）。sccache-dist の共有シークレット型と同型。
- **トークンが未設定なら従来どおり無条件 accept（back-compat）。** agent がトークンを設定したときのみ
  強制する。これにより M5/M6 の単機・既存テストを壊さず、段階導入できる。
- **データプレーンのトークン gate:** データプレーンは protobuf を載せないハンドメイドのバイナリ
  フレーミング（v0 §4.2）。session 確立ハンドシェイクに同トークンを載せ、agent fileserver が
  per-connection で検証する。VFS パイプ（フック→worker のローカル名前付きパイプ）はプロセス境界内の
  ローカル経路のため、本トークンの対象は **worker→agent のデータプレーン接続**とする。
- **サーバ TLS（設定可能・LAN 既定 off）:** v0 §5 の「localhost/LAN-trusted スコープを出る通信は
  暗号化必須」を満たすため、tonic `ServerTlsConfig`/`ClientTlsConfig`（rustls）で TLS を**設定により
  有効化**できるようにする。LAN-trusted 既定ではトークンのみで足り TLS は off。スコープを出る運用では
  TLS を on（サーバ認証＝worker が agent 証明書を検証）。なお digest 検証は v0 §5 のとおり TLS の
  有無に関わらず常時（CAS 整合性は無料）。

### 3. wire 非破壊（`RegisterRequest` 予約 10–11・capability flag）
- `RegisterRequest` の予約フィールド（現状 `reserved 10, 11`、コメントは「zero-trust」想定）を
  **本 ADR の LAN-trusted 共有トークン**へ転用する。**フィールド 10 = `auth_token`（共有トークン）**、
  **フィールド 11 は将来のクライアント証明書/attestation 用に予約継続**（mTLS/ゼロトラスト移行の余地）。
- 認証の要否は **capability flag**（v0 §6「capability flag でオプション機能を gate」）で表現し、
  バージョン sniffing はしない。旧フィールドは触らず、新フィールドの追加のみ（§6 versioning 準拠）。

## 将来余地（採らなかった選択肢）

- **B（ゼロトラスト／mTLS）:** 外部公開・マルチテナント・非信頼網が要件化したら再評価。
  フィールド 11（client-cert/attestation）を予約継続することで、本決定から **wire 非破壊で**
  mTLS へ移行できる。tonic は `ServerTlsConfig.client_ca_root`＋クライアント証明書で mTLS を
  サポートする（調査済み）。
- ミニフィルタ案 B（ADR 0001）と同じく、プロジェクトが法人格・運用体制を得た段階での再評価対象。

## 繰延（本 ADR の射程外・別承認）

- **実証明書（OV Authenticode）の購入と Microsoft Defender への false-positive 提出**は、
  署名機構（CI 署名パイプライン）を placeholder/self-signed で先行検証したうえで、証明書入手後に
  決定者が実施（M7.2、ADR/署名計画）。2024 年以降 EV でも SmartScreen 即時評判は付与されず OV と
  等価・HW トークン必須化のため、機構先行・現金支出後行とする。
- **実 2 台 LAN 実測**は引き続き決定者承認の繰延（実機なし）。M7 は単機ハーネス＋RTT
  エミュレーションで完了させる。ただし **env allowlist は「LAN 分割前に必須」**として M7.1 で
  先行実装する（`docs/deferred.md` M6.1 security 所見）。

## 影響

- `docs/protocol/v0.md` §3.1（`RegisterRequest`）に `auth_token`（フィールド 10）と認証 capability flag を追加、
  §5（Security）を「LAN-trusted・共有トークン＋設定可能サーバ TLS」で具体化（プレースホルダの解消）。
- `crates/proto/.../control.proto` の `RegisterRequest` 予約 10 を `auth_token` へ、capability flag を追加。
- `crates/worker/src/coordination.rs` の無条件 accept をトークン照合へ。
- agent fileserver（`crates/agent/src/fileserver.rs`）のデータプレーン session 確立にトークン検証を追加。
- `docs/deferred.md` の M7「無認証 control/data plane」「無認証 Register」「action cache trace 過少申告」を
  本 ADR の実装で回収（解消時に当該行へ追記）。
- DESIGN §9 の「ワーカー信頼モデル（LAN vs ゼロトラスト）」を **LAN-trusted で確定**、ゼロトラストは
  将来余地として wire 非破壊の移行口（予約 11）を残す。
