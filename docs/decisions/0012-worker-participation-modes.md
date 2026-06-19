# 0012 — worker 参加モード（always / adaptive / off。ADR 0010 の一般化）

- ステータス: **採択（ACCEPTED）。** 起案: 2026-06-19。決定者承認: 2026-06-19（プロジェクトリード）。
  M9.6 で実装（[ADR 0010](0010-cpu-aware-worker-admission.md) の CPU 連動 admission を 3 モードに一般化）。
- 決めること: worker が分散ビルドへどう参加するかの **(1) モード体系**、**(2) 各モードの報告挙動**、
  **(3) 設定（TOML/env）と既定**、**(4) 統一 eligibility への合流**、**(5) 拡張枠（他状態信号）の扱い**。
- 判定基準: 非交渉事項（**ローカルフォールバック常時**：全 worker が off でもビルドは完走／**決定性不変**：
  admission/scheduling のみ＝出力バイト不変）。スコープ膨張回避（今は idle CPU 信号のみ実装）。
- 関連: [ADR 0010](0010-cpu-aware-worker-admission.md)（CPU 連動・本 ADR の adaptive＝その挙動）、
  [ADR 0011](0011-version-gated-admission.md)（版ゲート・同じ eligibility filter に合流）、
  `crates/worker/src/config.rs`（ParticipationMode/ParticipationSettings）、
  `crates/worker/src/cpu_monitor.rs`（floor）、`crates/agent/src/scheduler.rs`（admissible）。

## 背景

[ADR 0010](0010-cpu-aware-worker-admission.md) は「idle CPU に連動して実効 capacity を動的調整する」良き隣人
admission を入れ、`idle_cpu_enabled` の ON/OFF で切り替える設計だった。しかし運用上は 2 値では足りない:

- **常時フル参加したい専用ワーカー**（対話ユーザーが居ない CI/ビルド専用機）＝負荷を見ず静的 capacity 全開。
- **良き隣人**（開発者の作業マシン）＝idle CPU 連動（ADR 0010 既定）。
- **一時的に完全不参加**にしたい（このマシンは今はビルドに使わない）＝実効 0・スケジューリング除外。

そこで `idle_cpu_enabled: bool` を **3 モードの参加モード**に一般化する。旧 `false`（CPU 信号なし＝静的全開）は
`always` に、旧 `true`（CPU 連動）は `adaptive` に対応し、`off`（完全不参加）が新規。

## 決定

### (1) モード体系＝always / adaptive(既定) / off
`ParticipationMode { Always, #[default] Adaptive, Off }`（`crates/worker/src/config.rs`）。

### (2) 各モードの報告挙動
- **adaptive**（既定・良き隣人）: idle CPU サンプラを起動し、EMA 平滑＋ヒステリシス＋reserve で算出した
  schedulable idle% を heartbeat の `idle_cpu_pct` に載せる（[ADR 0010](0010-cpu-aware-worker-admission.md) のまま）。
  新ノブ `participation_floor_pct` で「参加中に提供する最低 idle%」を明示（既定 0＝純良き隣人）。floor は
  参加中のみ適用し、ヒステリシスで脱落中（latched out）は 0 のまま。
- **always**: サンプラを起動せず `idle_cpu_pct` を **None** 送出 → agent は静的 capacity 全開で扱う。
- **off**: サンプラ起動せず None 送出。`Capabilities.participation_mode = "off"` を申告し、**agent が
  eligibility で除外**（登録維持・heartbeat 継続・ダッシュボードに「off」表示）。

### (3) 設定（TOML/env）と既定
- TOML: `participation_mode = "always"|"adaptive"|"off"`（既定 adaptive）、`idle_cpu_floor_pct`（既定 0）。
  adaptive 用しきい値 `idle_cpu_reserve_pct`/`idle_cpu_hysteresis_pct`/`idle_cpu_ema_alpha_pct` は流用。
- env override: `SEMBAZURU_PARTICIPATION_MODE`、`SEMBAZURU_IDLE_CPU_FLOOR_PCT`（既存の reserve/hysteresis/
  ema env も流用）。precedence は既存どおり **env > TOML > default**。
- 旧 `idle_cpu_enabled` / `SEMBAZURU_IDLE_CPU_ENABLED` は撤去（未リリースの v0 ゆえ後方互換不要。
  TOML の未知キーは serde が無視するので旧ファイルも壊れない）。

### (4) 統一 eligibility への合流（ADR 0010/0011 と 1 箇所）
スケジューラの eligibility は 3 ADR が 1 箇所に合流する:
```
worker.version == agent.version      (ADR 0011)
  かつ participation_mode != "off"    (ADR 0012)
  かつ effective_capacity > 0          (ADR 0010: adaptive=CPU連動 / always=静的)
```
`scheduler.rs::admissible` ＝ `version_matched ∧ mode_participating`。`pick_and_reserve` はさらに
`effective_capacity>0` を要求し、`cluster_capacity` は admissible な worker のみ合算。除外理由は単一ソース
`exclusion_reason`（`version-mismatch` → `off` → `cpu-busy` → `""`）で算出し、`WorkerStatus` に載せて
ダッシュボード表示（enforce と表示がドリフトしない）。空モード（pre-0012 worker）は participating 扱い
（版ゲートが旧ノードを捕捉する）。

### (5) 拡張枠＝今は CPU のみ
モードと floor で「参加の度合い」を表現する構造にするが、**状態信号は当面 idle CPU のみ**。memory/在席/
時間帯などは将来 adaptive の入力を増やす形で拡張できる（ParticipationSettings に信号を足す）が、本 ADR では
作り込まない（スコープ膨張回避）。

## 影響

- `crates/worker/src/config.rs`: `ParticipationMode`/`ParticipationSettings`、`participation()`、
  `idle_cpu_floor_pct`、env `SEMBAZURU_PARTICIPATION_MODE`/`SEMBAZURU_IDLE_CPU_FLOOR_PCT`。
- `crates/worker/src/cpu_monitor.rs`: `IdleCpuPolicy` に `participation_floor_pct`、`observe` で下限クランプ。
- `crates/worker/src/coordination.rs`: `local_capabilities(capacity, mode)`、モード別の heartbeat 報告
  （adaptive のみサンプラ起動）。`run.rs` は `config.participation()` を渡す。
- `crates/proto/.../control.proto`: `Capabilities.participation_mode`、`WorkerStatus.participation_mode`（非破壊）。
- `crates/agent/src/scheduler.rs`: `mode_participating`、`admissible` に mode 条件、`exclusion_reason` に "off"。
- `crates/agent/src/status.rs` / `crates/gui`: participation_mode を集約・表示（eligible のホバーにモード）。
- 検証: agent 以外で反証検証。off 除外で run_local 完走の統合テスト、always 包含/三条件 AND/floor の UT、
  env・TOML が効く UT、determinism harness 緑（出力不変）、fmt/clippy/test 緑。

## 繰延・未決（本 ADR の射程外）

- 他状態信号（memory/IO 圧・在席・時間帯）の adaptive への組み込み（拡張枠のみ確保・需要が出たら）。
- floor/reserve/hysteresis/ema の定数チューニングは M10 実 LAN へ（[ADR 0010](0010-cpu-aware-worker-admission.md) と同様）。
- per-worker のモード/しきい値を GUI から編集する UI（まずは表示のみ）。
- モードの live-reload（現状は起動時固定。変更は worker 再起動で反映）。
