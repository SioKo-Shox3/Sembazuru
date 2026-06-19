# 0010 — CPU 連動の動的ワーカー admission（effective_capacity = f(idle_cpu)）

- ステータス: **採択（ACCEPTED）。** 起案: 2026-06-19。決定者承認: 2026-06-19（プロジェクトリード）。
  方針はプロジェクトリードが決定（2026-06-19、選択肢「動的に capacity 調整」）。
  M9.6 で実装着手（本文の方針は確定。`f()` の定数チューニングは M10 実 LAN へ繰延）。
- 決めること: ワーカーが自機の CPU 使用状況を見て分散ビルドへの参加度合いを動的に決める仕組みの
  **(1) サンプリング方法**、**(2) 信号の運び方（proto/heartbeat）**、**(3) 実効 capacity への反映点**、
  **(4) ローカルフォールバック/決定性の保全**、**(5) 設定/UX**。
- 判定基準: 非交渉事項（**正確性 > 速度**：成果物はどこで実行してもバイト一致／**ローカルフォールバック
  常時**：全 worker 飽和でもビルドは完走）。「良き隣人」＝対話ユーザーの裏で worker が動いてもマシンを
  食い潰さない、を満たす。スケジューラの分配が混雑 worker を避けること。
- 関連: ADR `0004-scheduler-and-fanout.md`（スケジューラ/分配）、ADR `0007-arbitrary-process-distribution.md`
  （ローカルフォールバック二段機構）、ADR `0008-...`（常駐サービス・GUI 可視化）、
  `crates/worker/src/lib.rs`（admission セマフォ）、`crates/worker/src/coordination.rs`（heartbeat）、
  `crates/agent/src/coordination.rs`（WorkerTable）、`crates/agent/src/scheduler.rs`（worker 選択）、
  `crates/proto/.../control.proto`（Coordination）。

## 背景

worker は M9 で常駐サービス化され、**開発者の作業マシンが同時に worker** になりうる。現状の admission は
**静的 `capacity`**（最大同時アクション数、起動時固定）で、対話作業中でも capacity 分のコンパイルを引き受け、
ユーザーの体感を悪化させる。「自機が忙しいときは分散ビルドへの寄与を自動で絞る」良き隣人挙動が要る。

リード決定（2026-06-19）は「**動的に capacity 調整**」（一時停止/再開ではなく、負荷に応じて受け入れ並列度を
段階的に増減）。idle CPU が高いほど多く引き受け、低いほど絞る（極限では事実上ゼロ＝引き受けない）。

### 実装前提（現状調査で確定）

- **capacity は静的。** `WorkerConfig.capacity`（`crates/worker/src/config.rs:59`）→ `WorkerService::with_capacity`。
  admission は二段セマフォ（`crates/worker/src/lib.rs`）：`accept`（= capacity×`QUEUE_FACTOR`=8、backlog ゲート、
  超過は即 `resource_exhausted`）と `limit`（= capacity、running ゲート）、`running: AtomicU32` が in-flight。
  起動後に capacity を変える経路はなし（live-reload なし）。
- **heartbeat に CPU 負荷フィールドなし。** `HeartbeatPing`（`control.proto`）は `worker_id`/`monotonic_qpc`/
  `running_actions`/`idle_slots(=cpu_count-running)`。`idle_slots` は**セマフォ占有**であってホスト CPU 負荷では
  ない。register の `Capabilities.cpu_count` は admission capacity（`crates/worker/src/coordination.rs`）。
- **スケジューラは agent 追跡の in-flight を使う。** `scheduler.rs::effective_idle()` =
  `caps.cpu_count - (agent が数える in_flight)`（heartbeat の `idle_slots` は ~5s 遅延ゆえ意図的に不採用）。
  `pick_and_reserve()` は HRW で preferred を選び、空きが無ければ `effective_idle` 最大の worker を選ぶ。
  → **`effective_idle()` が実効 capacity の単一注入点**。
- **CPU サンプリングのコードは皆無**。ただし `GetSystemTimes` は `windows-sys` の `Win32_System_Threading`
  （worker で**既に有効**、Job Objects 用）に含まれ、**新規依存ゼロ**で呼べる。`sysinfo` クレートは新規依存・
  過剰。
- **heartbeat は 5s 周期**、dead timeout 15s（3 回欠で死亡＝`live_snapshot` から除外）。明示的な
  「unhealthy/部分capacity」状態はなし。`dispatch()` は live worker を使い切ると `run_local()` へフォールバック
  （ADR 0007）＝**全 worker が低実効でもビルドは完走**。

## 決定

### (1) サンプリング＝worker が `GetSystemTimes` で idle CPU% を取得（新規依存なし）
worker のバックグラウンドで `GetSystemTimes` を 2 点サンプリングし `idle_delta / total_delta` から idle 率を算出。
`Win32_System_Threading` は導入済みのため **Cargo 変更不要**。フラッピング抑制のため **EMA 平滑化＋ヒステリシス**
を入れる（瞬間値で受け入れ可否が振動しない）。

### (2) 信号＝`HeartbeatPing` に CPU 負荷フィールドを非破壊追加（agent 側で判断）
`HeartbeatPing` に `idle_cpu_pct`（仮、proto3 新フィールド番号、非破壊）を追加し、worker が 5s 毎に報告。
GUI 可視化用に `Status` の `WorkerStatus` にも同様に非破壊追加（現在 idle CPU と実効 capacity を表示）。
**worker-local だけで絞らない**理由：worker が自分のセマフォを勝手に縮めると、agent の `effective_idle()` は
静的 `cpu_count` で過大評価し続け、agent が「空きあり」と誤って割り当て→ worker 側で QUEUED になり、スケジュール
サイクルを無駄にする（Option A の不整合）。よって**信号を agent に運び、分配側で実効値に反映**する（Option B）。

### (3) 反映点＝`scheduler.rs::effective_idle()` を CPU 連動に拡張
agent は受信した `idle_cpu_pct` を `WorkerEntry` に保持し、`on_ping()` で更新。`effective_idle()` を
`min(cpu_count - in_flight, f(idle_cpu_pct))` 相当に拡張：
```
base      = cpu_count.clamp(1, MAX_TRUSTED_CPU)
effective = round(base * idle_fraction)         // f(idle_cpu)
idle_for_scheduling = effective.saturating_sub(in_flight)   // 0 まで許容
```
- **worker の静的セマフォ（capacity）は絶対上限として据え置き**、CPU 連動は上限**以下に絞る**方向のみ。
  二重に絞らない（agent 側が主、worker 側は ceiling）。
- `f()` は EMA 済み idle 率に対して単調増加。予約 reserve（常に CPU を少し残す）を持たせ、過飽和では
  effective→0（＝その瞬間は割り当てられない＝事実上の一時停止だが「動的」の極限として自然に表現）。
- 実効 0 の worker は**選ばれないだけで死んでいない**（heartbeat 継続）。CPU が空けば次 ping で戻る。

### (4) ローカルフォールバック/決定性は不変
- 全 worker が実効低/0 でも `dispatch()` は `run_local()` に落ち、ビルドは必ず完走（非交渉 #2、ADR 0007）。
- 本機能は**どこで/参加するか否かだけ**を変える。成果物のバイト一致（clang-cl、worker==local）は不変＝
  determinism harness に影響なし（非交渉 #1）。スケジューリングのみの変更であることを Done-when に明記する。

### (5) 設定/UX＝既定 ON の良き隣人、worker で調整可、GUI で可視化
- worker config に方針ノブ（有効/無効、reserve/floor、しきい値）を追加（`worker.toml`／`SEMBAZURU_*`）。
  既定は控えめな良き隣人設定（ON）。
- GUI ダッシュボードに各 worker の現在 idle CPU と実効 capacity を表示（`WorkerStatus` 拡張を利用）。

## 影響

- `crates/proto/.../control.proto`: `HeartbeatPing` に `idle_cpu_pct` 追加、`WorkerStatus` にも（非破壊）。
- `crates/worker`: `GetSystemTimes` サンプラ（EMA＋ヒステリシス）、heartbeat 送出に値を載せる
  （`coordination.rs`）。Cargo 変更なし（`Win32_System_Threading` 既存）。config ノブ追加。
- `crates/agent`: `WorkerEntry` に `idle_cpu_pct`、`on_ping()` で更新、`scheduler.rs::effective_idle()` を
  CPU 連動に拡張。`Status` 集約に値を載せる。
- `crates/gui`: ダッシュボードに idle CPU/実効 capacity 表示。
- 検証: agent 以外で反証検証（CLAUDE.md）。determinism harness 緑（出力不変）、スケジューラのユニットテスト
  （実効値で混雑 worker を避ける／全飽和でローカルへ落ちる）、CPU 連動の閾値挙動テスト。

## 繰延・未決（本 ADR の射程外／実装時に確定）

- `f()` の具体形・EMA 窓・ヒステリシス帯・reserve 既定値は実装/M10 実 LAN で実測チューニング。
- メモリ/IO 圧の併用（`Capabilities.memory_bytes` は現状 0/未使用）。需要が出たら拡張。
- per-worker のしきい値を GUI から編集する UI（まずは表示のみ）。
- 「一時停止/再開」モード（しきい値で完全停止）は本決定（動的 capacity）の縮退形として後付け可能だが当面不要。
