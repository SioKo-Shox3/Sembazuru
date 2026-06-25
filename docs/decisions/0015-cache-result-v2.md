# 0015 — cache result v2（出力公開の action 単位 atomic・blob 再検証・stdio 復元）

- ステータス: **一部実装（PARTIAL）。** 起案: 2026-06-24。決定者承認: 保留（プロジェクトリード）。
  出所: コードレビュー（COR-007）。module 局所の publish path 再設計。
  **実装済み (1)-(4)**: `resolve` を **2-pass set-atomic publish** に再設計（全 output を堅牢 temp
  sibling に `get_verified` 付きで stage→全 commit）。固定 temp 名 `.sbz-cache-tmp` を **O_EXCL の
  pid+seq sibling** に置換（同時 resolve 衝突・preplaced symlink 追従を解消）、republish を
  **`store.get_verified`** に（破損 blob は公開せず miss＝再実行）、全量 memory 展開をやめ **1 blob ずつ**
  staging（大 output で OOM しない）。回帰テスト `corrupt_output_blob_misses_instead_of_serving_wrong_bytes`
  ＋既存 `missing_output_blob_misses_without_partial_publish`。
  **未実装 (5)**: stdout/stderr の捕捉・cache-hit replay（`record`/`resolve`/`intake` の emit 経路に跨る
  cross-cutting＝別 PR の follow-up。型/codec の stdout/stderr digest は既存対応）。
- 決めること: cache hit の出力公開を**どう正しく/atomic に行うか**。**(1) action 単位 atomic 公開**、
  **(2) 堅牢 temp**、**(3) republish 再検証**、**(4) memory 上限/streaming**、**(5) stdout/stderr 捕捉・replay**。
- 判定基準: 非交渉（**正しさ>速度**＝部分公開・破損 blob・誤 stdio を出さない／出力バイト不変）。
- 関連: [ADR 0003](0003-cas-hash-and-chunking.md)（digest/CAS）、`crates/agent/src/action_cache.rs`、
  `crates/cas/src/store.rs`（`write_atomic`/`get_verified`・既存再利用）、`crates/agent/src/intake.rs`（emit 経路）。

## 背景

action cache の出力公開（COR-007）に5つの欠陥:

- **非 atomic**: `resolve`(`agent/action_cache.rs:88-143`) は全 blob を memory に**全量** `Vec` 展開後、per-file `publish_atomically` で公開＝**set 単位で atomic でない**。N 個中 2 個目の rename 失敗で 1 個目だけ新版＝mixed set。
- **固定 temp 名**: `publish_atomically`(`:303`) は `<final>.sbz-cache-tmp` の**固定名**＋plain `std::fs::write`＝同時 resolve が衝突し、preplaced reparse/symlink を追従しうる。
- **republish 非検証**: `store.get`(`:129`、非検証)で読む＝disk 上で破損した CAS blob を**そのまま公開**。`get_verified`(`store.rs:150`) は存在するが republish 経路で未使用。
- **全量 memory**: 出力集合を同時に常駐＝大規模 result で OOM。
- **stdio 非復元**: `ActionResult.stdout/stderr`＋codec に field はあるが `record` で**常時 None**（`:201-202`）＝cache hit が semantic stdout を再生しない。

### 実装前提（現状調査で確定）
- `cas/store.rs::write_atomic`(`:266`) は **pid+seq＋`create_new`(O_EXCL)** の堅牢 temp ＝**そのまま再利用可能**（agent の `publish_atomically` はこの性質を持たない）。
- `store.get` の doc 不変条件(`:131-139`): 短い open→read→close（`FILE_SHARE_DELETE` なし）が eviction の `remove_file` を tear させない契約＝streaming/mmap 化は eviction 契約を壊すので慎重に。
- `Execution::Remote` は既に `o.stdout`/`o.stderr` bytes を持ち `emit_outcome`(`intake.rs:387-393`) が live 転送＝捕捉経路の素材は既存。

## 決定

### (1) action 単位 atomic 公開
per-action staging dir に**全 output を materialize → 全 verify → set 単位で公開**（途中失敗で mixed set を残さない）。dependent action は publish 完了まで開始しない。

### (2) 堅牢 temp
固定 temp 名を `cas/store.rs::write_atomic`（pid+seq＋`create_new`(O_EXCL)）に置換＝同時 resolve 非衝突、preplaced reparse/symlink を defeat。

### (3) republish 再検証
republish を `store.get`→**`store.get_verified`**（digest 再ハッシュ）に。破損 blob は公開せず miss に倒す。

### (4) memory 上限/streaming
全量 `Vec` 常駐をやめ、staging で 1 ファイルずつ materialize＋上限。streaming は `get` の eviction 不変条件を尊重しつつ検討（mmap 化は回避）。

### (5) stdout/stderr 捕捉・replay
`record` で stream を CAS に ingest し `ActionResult.stdout/stderr` digest を埋める（型/codec は既存対応）。cache hit 時に `intake.rs` の emit 経路で**初回と同順**に replay。

## 影響

- `crates/agent/src/action_cache.rs`（resolve/record/publish 再設計、staging、`write_atomic`/`get_verified` 再利用、stdio digest）。`crates/agent/src/intake.rs`（cache hit の stdio replay）。`crates/cas/src/store.rs`（必要なら streaming API・eviction 契約厳守）。
- 検証: 2 番目の output rename を意図的失敗→mixed set 残らない UT／同時 resolve が互いの temp を壊さない UT／cache hit の stdout/stderr が初回と同順 UT／corrupt CAS blob を publish しない UT／大 output で memory が上限超えない UT。`verifier`(opus)＋determinism harness（出力バイト不変）。

## 繰延・未決

- 出力の attribute/directory/symlink/registry-write 等の非 regular-file 復元（[ADR 0007](0007-arbitrary-process-distribution.md) 系・当面 regular file bytes のみ）。
- 真の streaming CAS（`get` の eviction 安全契約と両立する設計）。
