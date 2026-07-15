# 0008 — 配布物と常駐 UX（M9）: インストーラ・GUI・常駐方式・GUI↔daemon 通信・disk eviction 方針

- ステータス: **決定済み（ACCEPTED）。** 起案: M9.0、2026-06-16。
  決定者承認: プロジェクトリード、2026-06-16
  （installer=WiX(MSI)＋winget配布 ／ GUI=egui(eframe)＋tray-icon ／ 常駐=Windows Service（daemon/worker）＋GUIは別プロセスのトレイ ／ GUI↔daemon=新規 loopback 限定 Status/Admin gRPC サービス、で承認）。
- 決めること: `docs/DESIGN.md` §7 M9（配布物と常駐 UX）と Done-when が委ねた、
  **(1) インストーラ技術**（WiX(MSI) / winget / MSIX）、**(2) 常駐 GUI の実装技術**
  （Tauri / egui(eframe) / windows-rs ネイティブトレイ）、**(3) daemon/worker の常駐方式**
  （Windows Service / ログオン時トレイ常駐）、**(4) GUI↔daemon の通信面**
  （既存 Coordination の read-only 拡張 / 新規ローカル IPC）、および
  **(5) 長寿命 daemon の disk eviction（deferred #8）の方針**。
- 判定基準: M9 Done-when＝「非開発者が署名済みインストーラから導入し、GUI から daemon／worker を
  起動して既存プロジェクトを分散ビルドでき、クラスタ／キャッシュの状態を目視確認でき、2 台目 PC も
  同じインストーラ＋設定だけで worker 参加できる（M10 前提）」。非交渉事項（正確性 > 速度／
  ローカルフォールバック常時／UBA 非取り込み／clang-cl ファーストクラス）と、§2 設計原則 1
  「無設定（ゼロコンフィグ）」を UX として守ること。
- 関連: ADR `0006-trust-and-auth.md`（`SEMBAZURU_CLUSTER_TOKEN`・LAN-trusted・実 OV 証明書購入は繰延）、
  `0007-arbitrary-process-distribution.md`（ローカルフォールバック二段機構・EDR steady-state に新 TTP を足さない）、
  `0003-cas-hash-and-chunking.md`（CAS eviction の O(N) 簡易版）、`docs/DESIGN.md` §2/§7 M9/§8、
  `docs/deferred.md` #8（disk eviction）/ M10（実 2 台 LAN）、`docs/security/edr-allowlist.md`、
  `hooks/test/sign_smoke.ps1`（M7.2 署名機構）、`docs/quickstart.md`／`docs/integrations/README.md`
  （隠蔽対象の `SEMBAZURU_*` と既定ポート）。

## 背景

M0–M8 は「無設定 clang-cl 分散ビルド」を機構として確立したが、導入は依然 **開発者専用の手動手順**に依存する
（`docs/quickstart.md`: VS dev shell で C++ フックを CMake ビルド → Rust を `cargo build` → 複数ターミナルで
`SEMBAZURU_*` env を手で並べて daemon/worker 起動 → `Directory.Build.targets` を手コピー）。M9 はこれを
**署名済みインストーラ＋常駐サービス＋GUI** に引き上げ、非開発者でも導入・運用・目視確認できる状態にする。
これは M10「実 2 台 LAN 実測」の前提（入れて設定するだけで worker 参加できる）でもある。

### 実装前提（M9.0 調査で確定した現状）

- **GUI 用ステータス面はゼロ。** `WorkerTable`（worker 一覧/health, `crates/agent/src/coordination.rs`）、
  worker の in-flight（`running: AtomicU32`, `crates/worker/src/lib.rs`）、`ServerStats`（転送バイト,
  `crates/agent/src/fileserver.rs`）、CAS `total_size()`/`evict_to()`（`crates/cas/src/store.rs`）は
  **内部に存在するがどの RPC にも露出していない**。cache ヒット率・remote/local/fallback 内訳は
  **計測すらしていない**（カウンタ新設が必要）。
- **Windows サービス統合・トレイ・GUI コードは皆無。** daemon/worker は env 駆動の CLI 手動起動のみ。
- **パッケージング雛形は皆無**（`.wxs`/`.msix`/`.nsi` 一切なし）。
- **disk eviction は自動化されていない**（deferred #8）。`evict_to()`（LRU）は手動呼び出しのみ、
  `Session::drop`（`fileserver.rs`）はプロセス終了時のみ発火 → サービス常駐で trace/scratch/CAS が単調増加。
- **署名（M7.2）の穴**: `hooks/test/sign_smoke.ps1` は C++ PE（`launcher.exe`/`sbz_interceptor{64,32}.dll`）
  のみ署名。Rust バイナリ・GUI・MSI 自体・RFC3161 タイムスタンプは未対応。

## 決定

### (1) インストーラ＝WiX (MSI)、winget は MSI 配布チャネル

**WiX で MSI を作る。** winget は独自インストーラではなく配布チャネルであり、完成した MSI をそのまま配布する
（DESIGN の「署名済み MSI ＋ winget」想定と一致）。

根拠 / 比較:

| 軸 | WiX (MSI)（採用） | MSIX | winget のみ |
|---|---|---|---|
| Windows Service 登録 | ServiceInstall/ServiceControl で正攻法 | サンドボックスモデルで任意サービス登録が困難 | 不可（配布のみ） |
| PATH 変更・FW 規則・system レベル導入 | 標準機能＋WiX firewall ext で可能 | コンテナ前提で制約大 | 不可 |
| DLL 注入（`launcher.exe`＋hook DLL）との相性 | 制約なし | サンドボックスが本件の中核要件と衝突 | — |
| 配布 | winget が MSI を配布 | winget 可だが上記制約が残る | インストーラ本体が別途必要 |

MSIX のコンテナ化は本件が必要とする「任意の Windows Service 登録・PATH・FW 規則・DLL 注入」と構造的に衝突する。
winget 単独はインストーラ本体になり得ない。よって WiX(MSI) が唯一現実的。

### (2) 常駐 GUI＝egui (eframe) ＋ tray-icon

**純 Rust の egui(eframe) でダッシュボード窓を作り、`tray-icon` でトレイ常駐する。** tonic gRPC クライアントを
直結し、(4) の Status/Admin サービスを叩く（CLAUDE.md「Rust GUI で既存 gRPC を叩く」方針・スタック整合）。

根拠 / 比較:

| 軸 | egui(eframe)＋tray-icon（採用） | Tauri | windows-rs ネイティブトレイ |
|---|---|---|---|
| 言語・配布 | 純 Rust 単一 exe | Rust＋WebView、web ビルド系(JS/CSS)同梱 | 純 Rust |
| 要求 UI（worker 一覧・health・cache ヒット率・in-flight・fallback 内訳の表/指標） | 即時モードで表・指標を素直に描ける | 可能だが過剰 | トレイ＋メニュー止まり、ダッシュボードは手書き Win32 で低レベルすぎ |
| 署名対象・EDR 表面積 | 最小（単一 exe） | WebView2 依存＋バンドル肥大で増える | 最小だが UI が作れない |
| gRPC 結線 | tonic を直接 await | 可能 | 可能 |

要求は「ダッシュボード＋トレイ」。egui は単一 exe で表・指標を軽量に描け、署名/EDR 表面積が最小で、tonic を
直結できる。Tauri は WebView 依存とバンドル肥大が本用途に不釣り合い。ネイティブトレイは UI を作れない。

### (3) 常駐方式＝Windows Service（daemon/worker、自動起動）、GUI は別プロセスのトレイ

**daemon と worker は Windows Service として自動起動する。** GUI は session 0 のサービスからは描けないため、
**ユーザーセッションの別プロセス**として常駐し、(4) の loopback gRPC でサービスに接続する（service↔GUI 分離は
常套構成）。**CLI モードは維持**する（開発・ローカルフォールバック・dev 用）。

根拠: ログオン時トレイ常駐のみだとログオフで daemon が落ち、ログオン前は worker 不在になる。M10「2 台目 PC が
常時 worker 参加」を満たすには、ログオン状態に依存しない Windows Service が必須。誤検知の安全側として、
サービスが落ちても (非交渉 #2) ビルドはローカルで完走しなければならない＝サービスはビルドの可用性に対して
add-on であり、single point of failure にしない。

**EDR 整合（重要）:** Windows Service 登録は `docs/security/edr-allowlist.md` の「No persistence」開示に対する
**追加の persistence** なので、許可リスト申請に**サービス 1 つを明示開示**する。Run キー／スケジュールタスク／
WMI 購読など**開示外の persistence 機構は一切足さない**（ADR 0007 ④「EDR steady-state に新 TTP を足さない」と整合）。

**改訂（2026-06-18, M9.5）:** 上の「persistence はサービスのみ」に、**per-user の GUI 自動起動を 1 つだけ
開示付きで許可**する例外を加える。常駐 GUI（`sembazuru-gui.exe`）は session 0 のサービスからは描けずユーザー
セッションに常駐する必要があるが、ログオン時の起動導線が無いと「常駐」が成立しない（M9.4 のトレイは起動後に
のみ常駐）。導線は**全ユーザー共通 Startup フォルダの署名済みショートカット**（非昇格 asInvoker・非注入・
loopback Status 面のみ・UAC プロンプト付きの svcctl 経由でのみ SCM を叩く）とする。これは Run キー／スケジュール
タスク／WMI のような昇格・隠蔽的 TTP とは異なり、最小・可視・アンインストールで完全除去できる。よって持続化は
**「2 サービス＋この Startup ショートカット 1 つ」**に限定し、`docs/security/edr-allowlist.md` に 3 つすべてを開示、
同梱バイナリ集合＝署名/開示集合を保つ。HKCU/HKLM Run キー・スケジュールタスクは引き続き不採用。
（リード決定 2026-06-18：選択肢「Startup ショートカット＋ADR 改訂」を採用。）

**設定ソース:** サービスは per-shell env を持てないため、設定は `%ProgramData%\Sembazuru\config.toml` から読む。
既存の `SEMBAZURU_*` env は **dev/CLI override** として後方互換で残す（env > config.toml の優先）。GUI と (4) の
Admin RPC はこの config.toml を書く。反映は単純化のため**サービス再起動で適用**（live-reload は当面しない）。

### (4) GUI↔daemon＝新規 loopback 限定 Status/Admin gRPC サービス

> **後続決定との境界:** 本節の loopback transport は `Status`／opt-in `StatusAdmin` に限って現行である。
> LocalIntake は [ADR 0016](0016-local-privilege-separation.md) と commit `68e5422` により authenticated named pipe
> へ移行した。Status/Admin を同じ pipe へ統合せず、管理 API 分離を維持する。

**daemon に loopback 限定の新 gRPC サービス `Status`（read-only）＋ admin 操作を追加する**（既定
`127.0.0.1:50073`、env `SEMBAZURU_STATUS`、loopback バインドを強制）。tonic 既存スタックを流用し、GUI は生成
クライアントで接続する。

**既存 Coordination を拡張しない理由:** Coordination は worker 向けで、ネット公開され `SEMBAZURU_CLUSTER_TOKEN`
認証が掛かる（ADR 0006）。ここに status/admin を相乗りさせると責務が混ざり、ローカル GUI に cluster token を
要求してしまう。loopback 限定の別サービスに分離することで、admin 面をネット公開ポートから外し、ローカル GUI は
無認証（loopback 信頼）で読める。named pipe を採らない判断は Status/Admin 面に限る。任意コマンドを受ける
LocalIntake には同じ信頼仮定を適用しない。

最小 RPC:
- `GetStatus() → { workers[]{id, caps, running, idle, last_ping_age, healthy}, cache{size_bytes, hits, misses, hit_rate}, in_flight, fallback{remote, local, fallback}, fileserver{read_ops, read_bytes} }`（read-only）
- admin 足場: `GetConfig()/SetConfig()`（config.toml の読み書き）、`TriggerEviction()`（(5) を駆動）。
  worker の start/stop は Service 制御（GUI 側）と組み合わせる。

cache ヒット率・remote/local/fallback 内訳は現状未計測のため、本サービス実装と同時に **カウンタを新設**する
（hit/miss は action_cache ルックアップ地点、fallback 内訳は `scheduler.rs` の実行経路分岐）。

### (5) disk eviction＝総量上限（LRU）＋セッション境界クリーンアップ（deferred #8）

サービス常駐で daemon プロセスが事実上無限寿命になるため、「プロセス終了時に消えていた」もの
（per-action trace/scratch、agent セッション CAS の temp blob と pinned マップ、worker scratch）が溜まり続ける。
これを M9 で解消する:

- **総量上限（LRU）:** 既存 `BlobStore::evict_to(max_bytes)` を自動駆動する。上限は env
  `SEMBAZURU_CACHE_MAX_BYTES`（config.toml にも）。CAS eviction の O(N) フルスキャンは ADR 0003 の簡易版を
  据え置くが、**上限で律速**し、**何を evict したかを必ず log**（silent cap 禁止）。
- **セッション境界クリーンアップ:** `Session` をプロセス終了時だけでなくビルド境界で破棄できるようにし、
  trace/scratch と worker の hydrated scratch をアクション後に始末する。
- **可視化/操作:** 現サイズと evict 実績を (4) の Status に露出し、`TriggerEviction` で手動起動も可能にする。

**正確性ガード:** eviction はビルド出力キャッシュに触れるため、**eviction 後の再ビルドが byte-identical**
であること（determinism harness 通過）を M9.2 の Done-when に含める（非交渉 #1・M2 品質ゲート）。

## 影響

- `docs/DESIGN.md` §7 M9 を本決定（WiX(MSI)／egui＋tray／Windows Service＋GUI 別プロセス／loopback Status 面／
  総量上限＋セッション境界 eviction）で具体化。Done-when は不変。
- `crates/proto/.../control.proto`: loopback 限定 `Status` サービス（GetStatus／GetConfig／SetConfig／
  TriggerEviction）を非破壊追加（v0 §6 versioning 準拠）。
- `crates/agent/`: cache hit/miss・fallback 内訳カウンタ新設、status アグリゲータ、Status リスナ（loopback 強制）、
  config.toml ローダ（env override）、eviction 自動駆動とセッション境界クリーンアップ。
- `crates/worker/`: scratch 後始末、Service ラッパ。新 crate `crates/gui`（`sembazuru-gui.exe`）。
- 署名/配布: `hooks/test/sign_smoke.ps1`（および release 署名）に Rust バイナリ＋GUI を追加、RFC3161
  タイムスタンプ、MSI 自体の署名を追加。WiX プロジェクトと winget manifest を新設。
- `docs/security/edr-allowlist.md`: Windows Service 登録を persistence として開示追記、同梱バイナリ集合 ==
  署名/開示集合を保証。
- `docs/deferred.md`: #8（disk eviction）を本 ADR の (5) で回収する旨を着手時に更新。M10 前提が整う旨を明記。

## 繰延・未決（本 ADR の射程外）

- **実 OV 証明書（HSM）の購入と EDR 許可リスト提出**は ADR 0006 のとおり決定者所有・長納期。M9 は M7.2 同様
  **placeholder 自己署名で機構を実証**し、実証明書はリリース時に差し替える（実証は placeholder ベースで満たす）。
- **config.toml スキーマ**の詳細（フィールド名と env の 1:1 対応・override 規則）は M9.3 実装時に確定。
- **CAS eviction の O(N) スキャン最適化**は簡易版据え置き（ADR 0003）。常駐で問題化したら別途繰延に追記。
- **設定の live-reload**（再起動なし反映）は当面しない。需要が出たら再評価。
- **実 2 台 LAN 実測（M10）** は引き続き決定者承認の別マイルストーン。M9 はその前提（入れて設定するだけで参加）
  までを担保する。
