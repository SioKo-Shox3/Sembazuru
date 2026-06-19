# 0011 — 版ゲート admission（サーバー役の版を基準に不一致 worker をスケジューリング除外）

- ステータス: **採択（ACCEPTED）。** 起案: 2026-06-19。決定者承認: 2026-06-19（プロジェクトリード）。
  M9.6 で実装（[ADR 0009](0009-app-self-update-github-releases.md) 撤回の代替＝版整合の担保手段）。
- 決めること: クラスタの版整合をどう取るか。**(1) 版の基準**、**(2) 版の運び方（proto）**、
  **(3) 不一致 worker の扱い**、**(4) 決定性/ローカルフォールバックの保全**、**(5) §6「版で sniff しない」との関係**。
- 判定基準: 非交渉事項（**正確性 > 速度**：成果物はどこで実行してもバイト一致／**ローカルフォールバック常時**：
  全 worker 除外でもビルドは完走）。No UBA。版整合は admission/scheduling のみで担保し、**出力バイトは不変**。
- 関連: [ADR 0009](0009-app-self-update-github-releases.md)（撤回・自己更新→手動更新。版整合の担保が本 ADR）、
  [ADR 0010](0010-cpu-aware-worker-admission.md)（CPU 連動 admission・本ゲートを同じ eligibility filter に重ねる）、
  [ADR 0012](0012-worker-participation-modes.md)（参加モード・同 filter に合流）、
  [ADR 0006](0006-trust-and-auth.md)（§6 capability flag・wire 互換）、
  `crates/agent/src/scheduler.rs`（eligibility filter）、`crates/proto/.../control.proto`（Capabilities/WorkerStatus）。

## 背景

[ADR 0009](0009-app-self-update-github-releases.md)（GUI 自己更新）を撤回した。撤回理由の核心は
**分散ビルドでは各ノードが勝手に版を上げると version skew を生み、決定性/キャッシュ整合が崩れる**こと。
worker と agent でツールチェイン/CAS ハッシュ/プロトコル挙動が食い違えば、「どこで実行してもバイト一致」
（非交渉 #1）が成り立たなくなり、action cache のヒットも汚染されうる。

したがってクラスタの版整合は「各ノードが自動更新で勝手に揃える」のではなく、
**サーバー役の版を唯一の基準とし、一致しない worker をビルド参加から外す**ことで担保する。
更新はリードが GitHub Releases の MSI を全ノードに手動配布して 1 版に揃える運用（[ADR 0009](0009-app-self-update-github-releases.md) 末尾）。

### 実装前提（現状調査で確定）

- worker は register 時に `Capabilities` を送る（`crates/worker/src/coordination.rs::local_capabilities`）。
  ここに版フィールドは無い。全 crate は `version.workspace = true`＝**同一ワークスペースビルドなら版は共通**。
- agent は `WorkerEntry.caps` に `Capabilities` を丸ごと保持（`crates/agent/src/coordination.rs`）。
- スケジューラの worker 選別は `scheduler.rs::pick_and_reserve` の 1 箇所の eligibility filter
  （現状 `!tried && effective_capacity>0`）。fan-out スロットルの容量は `cluster_capacity`。
  → **この 2 箇所が admission の単一注入点**（[ADR 0010](0010-cpu-aware-worker-admission.md) と同じ場所）。
- 全 worker が ineligible でも `dispatch()` は `run_local()` に落ち、ビルドは完走（[ADR 0007](0007-arbitrary-process-distribution.md)）。

## 決定

### (1) 基準＝サーバー役（agent/daemon＝コーディネータ）の版
agent の `env!("CARGO_PKG_VERSION")`（= ワークスペース版）を唯一の基準とする。worker は自身の同じ
`CARGO_PKG_VERSION` を register で申告する。同一ビルドから配られたクラスタは一致し、別版のノードだけが外れる。

### (2) 版の運び方＝proto を非破壊追加
`Capabilities` に `string worker_version`、GUI 可視化用に `WorkerStatus` に `string worker_version` と
`string exclusion_reason` を追加（proto3 新フィールド番号、非破壊）。版は register 時に確定する静的属性なので
heartbeat には載せない（`Capabilities` 経由）。

### (3) 不一致 worker＝登録維持・スケジューリング除外・ダッシュボード可視化（拒否ではない）
agent は `worker.version == AGENT_VERSION` を**完全一致**で要求。不一致 worker は
**登録は維持し heartbeat も受けるが、`pick_and_reserve` / `cluster_capacity` から除外**する。
理由 `version-mismatch` を `WorkerStatus.exclusion_reason` に載せ、GUI ダッシュボードに表示する。
**登録自体を拒絶しない**のは、運用者が「不一致ノードが居る」ことを可視化で気づき手動更新できるようにするため
（沈黙の拒否は気づけない）。空の版（pre-0011 worker）は決して一致しないので除外される＝意図的挙動。
完全一致のみ（semver 範囲などには当面緩めない）＝決定性安全側に倒す。

### (4) 決定性/ローカルフォールバックは不変
本ゲートは **worker を選ぶか否かだけ**を変える。成果物のバイト一致（clang-cl、worker==local）は不変で、
determinism harness に影響しない（非交渉 #1）。全 worker が版不一致でも、live worker ゼロと同じく
`run_local()` に落ちてビルドは必ず完走する（非交渉 #2、[ADR 0007](0007-arbitrary-process-distribution.md)）。
Done-when にスケジューリングのみの変更であることを明記する。

### (5) §6「版で sniff しない」との関係（混同しないこと）
[ADR 0006](0006-trust-and-auth.md) §6 の「ゲートは capability flag で行い、版で sniff しない」は
**wire 互換（プロトコル後方互換性）**の原則である。本ゲートはそれとは**別レイヤ**で、プロトコル互換性ではなく
**「同一ビルド成果物を出すクラスタ」を守る admission/scheduling の決定性安全**を目的とする。
両者は衝突しない（プロトコルは互換でも、ビルド成果物の決定性のために版一致を要求する）。proto コメントにも明記する。

## 影響

- `crates/proto/.../control.proto`: `Capabilities.worker_version`、`WorkerStatus.worker_version` /
  `exclusion_reason`（非破壊）。
- `crates/worker/src/coordination.rs`: `local_capabilities` が `env!("CARGO_PKG_VERSION")` を載せる。
- `crates/agent/src/scheduler.rs`: `AGENT_VERSION` 定数、版一致を含む eligibility ヘルパ（`admissible` /
  `exclusion_reason`）、`pick_and_reserve` と `cluster_capacity` をヘルパ経由に切替。
- `crates/agent/src/status.rs`: `WorkerStatus` に `worker_version` と `exclusion_reason` を載せる。
- `crates/gui`: ダッシュボードに「Version」「Status」列（version-mismatch を可視化）。
- 検証: agent 以外で反証検証（CLAUDE.md）。不一致 worker が選ばれない UT、全不一致でローカル完走の統合テスト、
  determinism harness 緑（出力不変）、fmt/clippy/test 緑。

## 繰延・未決（本 ADR の射程外）

- 版一致を将来「完全一致」から semver 互換範囲やプロトコル互換ポリシーへ緩めるか（当面は完全一致のみ）。
- 混在クラスタの運用 UX（不一致ノード検知時に GUI から一括更新を案内する等）。表示のみで開始。
- 版基準を daemon 設定で固定/上書きする経路（当面は自身の `CARGO_PKG_VERSION` 固定）。
