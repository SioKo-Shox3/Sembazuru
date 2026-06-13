# 0004 — スケジューラ配置と分配戦略（M5）

- ステータス: **決定済み（ACCEPTED）。** 起案: M5.0、2026-06-14。決定者承認: プロジェクトリード、2026-06-14
  （agent 内分散・ソフト affinity＋least-loaded・static list first・LAN 前提無認証 start・dead 判定 15s・
  レイテンシ予算タイマは M5.5 で調整、で承認）。
- 決めること: `docs/protocol/v0.md` §3.3 と `docs/DESIGN.md` §7 M5 / §9 が M5 に委ねた、
  **(1) スケジューラの配置**（agent 内分散か将来の中央スケジューラか）、
  **(2) 複数ワーカーへの分配戦略**、**(3) ワーカー発見方式**、
  **(4) ヘルスチェック・切断検知・再割り当ての契約**、
  **(5) フォールバック判定の閾値**、**(6) ワーカー信頼モデルの当面の前提**。
- 判定基準: M5 Done-when＝「コンパイルフェーズについてワーカー数に対し並列効率 8 割以上」。
  正確性 > 速度（CLAUDE.md 非交渉事項 #1）、ローカルフォールバック常時動作（#2）を満たすこと。

## 決定

### 1. スケジューラ配置＝agent 内分散（v0 §3.3 準拠）
スケジューリングは **agent プロセス内**で行う。中央スケジューラは導入しない（v0 §3.3
「Scheduling is Agent-side in v0」を踏襲）。agent はビルドセッションを所有し、ワーカーテーブルと
分配ロジックを内包する。将来の中央スケジューラへの移行余地は残すが、M5 では非対象。

根拠: BuildXL の orchestrator パターン（orchestrator が pip グラフを保持し worker へ割り当て、
worker はグラフを持たない）と同型。REAPI のクライアント→中央キュー型とは異なるが、Sembazuru は
「agent がローカル FS を所有しワーカーへ供給する」構造上、割り当て判断を agent に置くのが自然
（出典: BuildXL Distributed-Builds.md、bazelbuild/remote-apis）。

### 2. 分配戦略＝ソフト affinity ＋ least-loaded フォールバック
アクション分配は以下の順で決める:

```
preferred = consistent_hash(input_fingerprint) % live_workers
if workers[preferred].idle_slots > 0:   send_to(preferred)
else:                                    send_to(argmax_w idle_slots)   # least-loaded
```

- `input_fingerprint` は **M4 の weak key / input-root digest を流用**（`crates/agent/src/action_cache.rs`）。
  同一ヘッダ/PCH 集合を使うアクションを同じワーカーへ寄せ、worker-local キャッシュ（M4 実装済み、
  一度見た SDK/ヘッダを再送しない）のヒット率を上げ、データプレーン往復を削減する。
- **ソフト affinity 必須**。preferred が過負荷なら least-loaded へ逃がす。ピュア affinity は
  ホットスポット/負荷偏りを生むため**禁止**。
- `idle_slots` は Heartbeat 同梱の容量情報（下記 4）から得る。

根拠: ワーカーローカルキャッシュを持つ Sembazuru では affinity の局所性が実 RTT 削減に直結する
（Reclient/BuildBuddy は共有 CAS で worker ローカルキャッシュを持たないため affinity 不採用）。
ただし affinity と負荷分散の同時最適化は「affinity ベース＋過負荷時に負荷分散へフォールバック」が
最良（出典: DualMap 研究、BuildBuddy 分配ブログ）。N が増えた段階での Power-of-Two-Choices は将来拡張。

### 3. ワーカー発見＝static list first
worker は起動時に agent の Coordination アドレスを受け取り（`SEMBAZURU_WORKERS` 相当の静的設定）、
agent へ **Register**（capabilities 申告）して **Heartbeat** ストリームを張る（worker→agent push）。
mDNS（`mdns-sd` クレート、`_sembazuru._tcp.local.`）による動的発見は M5 後半 or M6 へ繰り延べ。
Windows ファイアウォールの UDP5353 ブロック・VPN マルチキャスト不通は static list フォールバックで担保。

### 4. ヘルスチェック・切断検知・再割り当ての契約
- **二層の生存検知:** (a) tonic の HTTP/2 keepalive（interval 20s / timeout 10s）＝TCP/トランスポート層、
  (b) アプリ層 HeartbeatPing（worker→agent、5s 間隔）＝ワーカープロセス生存・容量層。両者は役割が別で
  片方では代替できない（出典: grpc.io keepalive ガイド）。
- **容量 push:** HeartbeatPing に `running_actions` / `idle_slots` を載せ、least-loaded 判断に使う
  （pull クエリは追加 RPC オーバーヘッドのため不採用）。
- **dead 判定:** HeartbeatPing 連続 3 回欠落（≈15s 無応答）で `DEAD`。誤検知耐性のため単発遅延は無視。
  Pong 復帰で `DEAD→IDLE` への復活を許容。
- **再割り当てトリガ:** worker DEAD ／ Execute ストリームが `Err(Status)` 終了 ／ Abort ACK タイムアウト。
  当該アクションを別 live worker へ再送し、live worker が無ければ**ローカルフォールバック**（非交渉事項 #2）。
- **重複実行ポリシー:** 許容。アクションは宣言出力集合の外で副作用フリー（v0 §3.2）で、アクション
  キャッシュ命中時に出力がバイト一致するため、二重実行しても正しさは崩れない。これにより分散ロック不要。

### 5. フォールバック判定の閾値
- **worker 死/分断タイマ:** 上記 4 の 15s（heartbeat 5s × 3 欠落）。
- **レイテンシ予算タイマ:** アクション単位で「この時間を超えたらローカル再実行へ切替」の上限を設ける。
  足場（タイマ機構）を M5.2 で導入し、**具体値は M5.5 の並列効率実測でキャリブレーション**する
  （現状の `crates/agent/src/lib.rs` はレイテンシ予算タイマ未実装＝M3.5 で繰り延べ済み）。

### 6. ワーカー信頼モデル（当面の前提）
M5 は **LAN 前提・無認証 start**（Register は `accepted=true` を返すだけ）。`RegisterRequest` に
attestation 用フィールド番号（例 10–11）を **予約コメントで確保**し、wire 非破壊で M7 に
mTLS/トークン認証を追加できる形にする。ゼロトラスト可否（DESIGN §9）は M7 寄りの判断だが、
M5 実装後の security-reviewer 所見を本 ADR の追補として残す。

## 並列効率の実測・判定基準（M5.5、決定者承認 2026-06-14、実装後追記 2026-06-14）

### 測定の二層（誠実なスコープ分け）
M5.5 の「コンパイルフェーズの並列効率」は二つの要素から成る。実装では前者を単機で実測し、後者は
実 LAN（決定者承認・繰り延べ）に委ねる。この線引きを明示する（当初 §は両者を混同していた）。

1. **スケジューラの分配 fan-out 効率（単機で実測済み）。** `hooks/test/m5_scale.ps1` ＋ `scale_harness`
   ＋ 合成 CPU 負荷 `burn`。burn は**入出力なし・データプレーン非経由・RTT 注入なし**で、純粋に
   「agent が W ワーカーへアクションを分配し飽和させられるか」だけを測る。`E(W) = T(1)/(W·T(W))`。
   これは**コンパイルフェーズ効率の必要条件の一つ**であり、全体ではない。
2. **完全なコンパイルフェーズ効率（実 LAN へ繰り延べ）。** VFS ファイル供給（往復＋ワーカーローカル
   キャッシュウォーム）＋実コンパイラ＋ネットワーク RTT を含む end-to-end。単機では (a) ターボ
   throttle（W↑で使用コア↑→全コアクロック↓）、(b) 複数ワーカープロセス co-tenancy で交絡するため、
   **忠実な測定は実 2 台 LAN（1 worker/machine）でのみ可能**。決定者承認で別途。

### 実測値（ローカル証拠、artifact）
分配 fan-out 効率、ターボ統制（固定 8 コアを W 分割、`E(W)=T(1)/T(W)`）、開発機 32 論理コア、
`burn 80M`、各 3 回最小値（再現: `pwsh hooks/test/m5_scale.ps1`、コア数依存）:

| 構成 | makespan | E(W) |
|---|---|---|
| W=1 cap8 | 725 ms | 1.00 |
| **W=2 cap4** | 828 ms | **0.88** |
| W=4 cap2 | 995 ms | 0.73 |
| W=8 cap1 | 1208 ms | 0.60 |

- **E(2)=0.88 ≥ 0.8** を満たす。スケジューラの分配は低 W で実用効率。高 W の低下は上記 (b) の
  per-process オーバーヘッド（実 LAN には存在しない単機固有コスト）。
- 実測過程で実バグ 3 件を発見・修正（チャネルプール未実装／分配 TOCTOU レース／ワーカー容量の過大
  申告＋ランタイムスレッド固定で高並行が直列化）。修正は M5.5b コミット参照。

### CI ゲートと判定
- **CI（フレークなし）:** `run_build_fans_out_a_whole_phase_across_workers`（多ワーカー全完了・全分配）。
  E(W) は単機・コア数依存でフレークしうるため CI ハードゲートにせず、ローカル証拠とする（決定者選択）。
- **正直な但し書き:** burn は VFS/RTT を測らないため、上表は分配層のみの上限的数値。完全な
  compile+VFS+RTT 効率は実 LAN で別途実証する。

## セキュリティ追補（M5.2 security-reviewer、2026-06-14）
§6 で予告した「M5 実装後の security-reviewer 所見」を集約する。M5 は LAN 前提・無認証 start の
ため以下は受容するが、認証/サンドボックス強化（M7）の前提として明記する。

- **対処済み（M5.2 で fix）:**
  - DoS — admission Semaphore で実行中の子プロセス数を capacity に制限。さらに **accept Semaphore**
    （`QUEUE_FACTOR=8 × capacity`）で待機タスクの backlog を上限化し、超過分は `RESOURCE_EXHAUSTED`
    で即拒否（待機タスクのメモリ枯渇を防止）。
  - 孤児プロセス — `kill_on_drop(true)`＋`tx.closed()` 検知で、agent がフォールバックで Execute
    ストリームを drop した時に子を kill。さらに **hung-child 上限タイマ**（`SEMBAZURU_ACTION_TIMEOUT_SECS`、
    既定 3600s）で agent 経由でない hung 子も slot を解放。
  - 偽 capabilities の部分緩和 — agent は worker 申告の `cpu_count` を `clamp(1, 256)` してスケジュール
    （巨大 cpu_count による全アクション吸引を緩和）。
- **受容（M5 LAN 前提・M7 で対処）:**
  - **無認証 Register。** 悪意 worker が登録し (1) 誤った出力を返す (2) アクションを吸引してブラック
    ホール化（各アクションは budget 経由でフォールバックするが遅延）。緩和は M7 の mTLS/attestation
    （`RegisterRequest` の予約フィールド 10–11）。
  - **孫プロセス孤児。** `kill_on_drop` は直接の子のみ kill し、孫（`cmd /c <compiler>` の compiler）は
    残りうる。Job Object（`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`）によるプロセスツリー一括 kill は M7
    サンドボックス境界で導入。署名可能な標準 Win32 手法で EDR 的に問題なし。
  - **重複 WriteBack（M4/将来）。** 再割り当て境界で元 worker と再割り当て先が同一出力を WriteBack
    しうる。v0 §3.2 の「副作用フリー＋出力バイト一致 CAS」前提で正しさは保たれるが、WriteBack 実装時に
    content-addressed 冪等をテストで固定すること。
  - **Mutex poisoning の連鎖 abort（L1）。** `WorkerTable`/`in_flight` の `.expect` は内部パニック時のみ。
    M7 品質改善で `lock().unwrap_or_else(into_inner)` 等へ。
- **EDR/署名:** 本変更はプロセス spawn と kill のみで、RWX・直接 syscall・スレッド注入等のマルウェア的
  シグナルは増えていない（security-reviewer 確認済み）。

## 影響
- v0 §3.3 の未解決（worker discovery / scheduling placement）を static-list + agent-side で解消。
- `docs/protocol/v0.md` §3.1 の `RegisterRequest` に attestation 予約、`HeartbeatPing` に容量フィールドを追加
  （wire 非破壊、§6 の versioning 方針に従い新フィールドのみ）。
- フォールバック閾値（DESIGN §9・v0 §7 #4）の worker 死タイマを 15s に確定、レイテンシ予算タイマは M5.5 で調整。
- 信頼モデル（DESIGN §9）は M5 では LAN 前提で確定、ゼロトラスト判断は M7 へ。
