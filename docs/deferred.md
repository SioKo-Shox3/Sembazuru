# 繰り越し事項・既知の制約（バックログ）

M3 までで「後回し」「事後判断」「ベストエフォート」とした項目を一箇所に集約する。
各項目は **何を / なぜ繰り越したか / 出所** を記す。詳細は各リンク先。担当
マイルストーンごとに整理（M3 の Done-when は阻害しない＝意図的な繰り越し）。

> 更新ルール: 着手・解消したら当該行を消すか「解消（コミット）」を付す。新たな
> 繰り越しが出たらここに足す。レビュー（verifier/security-reviewer）の指摘で
> 繰り越したものは必ずここへ。

---

## Phase 5（Worker Execution 認証、ADR 0017）残差

Phase 5.2 で unauthenticated-Execute RCE を signed action capability（blake3 keyed-hash MAC、key は
cluster token 由来）で封じた（token 設定時に enforce、worker_id/action_id/session_id/command_digest/
vfs_digest を bind、verify-before-spawn）。三者レビュー（security-reviewer/verifier/Codex）で
crypto/enforcement は sound・RCE closed と確認。Phase 5.3 で worker_id squatting による
execution_endpoint 乗っ取りも閉じた（`upsert_register` の first-registrant-wins-while-live）。

- **VfsExecution 設定の binding — 解消（F3, commit `6df1de1`）。** `vfs_root` のみ・`req.vfs=Some` 時
  のみだった binding を `vfs_digest`（presence + agent_fileserver + vfs_root + trace_dir + strict の
  digest、無条件照合）へ置換。vfs=None downgrade・agent_fileserver 差し替えの双方を拒否。
  verifier(opus) 全7軸 CONFIRMED。
- **worker_id squatting による execution_endpoint 乗っ取り — 解消（Phase 5.3, commit `793d565`）。**
  `upsert_register` が live な既存 entry への異なる endpoint での再登録を reject。
- **capability replay（TTL 300s 内）。** server 側 replay cache が無く、captured cap を TTL 内に
  同一 worker へ再送すると同一の署名済み action を再実行し得る（worker_id/action_id/session_id/
  command/vfs すべて一致・payload swap 不可）。severity LOW（deterministic build の再実行、
  token-LAN 内）。closed later: bounded seen-nonce LRU または mTLS（ADR 0017 §将来余地）。
  出所: security-reviewer/Codex(Phase 5.2)。
- **非-loopback Execution bind gate 未緩和。** capability enforce 時は非-loopback bind も auth 済みで
  safe なはずだが、`run.rs` の gate（`unsafe_allow_insecure_execution_lan`）は独立レイヤーとして
  維持し緩和していない（ADR 0017 §繰延、実 LAN 運用が要件化してから再評価）。
- **worker identity は自己申告（`COMPUTERNAME#pid`）。** cluster token 保持者なら任意の worker_id を
  名乗れる（Phase 5.3 は routing table 乗っ取りのみ閉じた。identity 詐称自体は token 保持が前提の
  inside-the-trust-boundary 問題）。per-worker 鍵/証明書による暗号学的 identity は mTLS（ADR 0017）で
  導入予定。
- **mTLS 移行時の installer 証明書配布（新規バックログ、ADR 0017）。** worker 固有クライアント証明書
  （CN/SAN を worker_id に対応）の生成・CSR・配布・失効/ローテーションを installer（WiX/MSI）が担う
  必要がある。ADR 0006 §繰延の Authenticode コード署名証明書（バイナリ署名・EDR/SmartScreen 対策）
  とは**別系統の PKI**——混同しないこと。現段階では未着手（実 2 台以上のクラスタ運用・外部公開が
  要件化してから）。出所: ADR 0017 §将来余地。

---

## コードレビュー指摘（`Sembazuru_code_review_action_guide.md`）最終ステータス（2026-06-27）

外部静的レビュー全 20 指摘の最終状態。**CLOSED**＝コード実装済み（main マージ済み or 本ブランチ commit）。
**DEFERRED-ACCEPTED**＝現脅威モデル（LAN-trusted＋共有トークン, ADR 0006）で意図的に受容。
**DEFERRED-blocked**＝実装したいが当環境（Rust/CI のみ・実 Windows サービス/2 ユーザー/秘密鍵なし）で安全に実装・検証不能＝lead/実機（M9.5/M10）。各 verifier(opus) 反証検証済み。

| ID | 区分 | 状態 | 要点 / blocker |
|---|---|---|---|
| COR-001 | P0 | **CLOSED** | agent 権威 per-action session capability＋single-flight pin（PR#1 38079a6） |
| COR-002 | P0 | **CLOSED** | Absent 入力 re-read＋ディレクトリ入力除外（PR#1/#2） |
| COR-003 | P0 | **CLOSED** | 不完全 trace を uncacheable（lost-input warning のみ・root 帰属曖昧は除外, PR#1） |
| COR-004 | P0 | **CLOSED** | 「未知 exe は既定 cache off／verified-deterministic profile（cl/clang-cl/clang/clang++/dxc＋`SEMBAZURU_VERIFIED_TOOLS` opt-in）のみ記録」へ既定反転を実装（9c56295）。記録ポリシー厳格化に伴い `WEAK_KEY_SCHEMA` v3 で旧ポリシー entry を一掃（hardening 34895dc）。決定者承認 2026-06-29（ADR 0014 (2)、Codex/verifier(opus) 二重レビュー＋CI hooks: M8.5 distributed-but-not-cached／M8.4・M4・M6 cache-hit 緑）。残存は別件継続: heterogeneous worker≠agent identity 閉鎖＝**COR-005 worker 再検証**、registry/enumerate/RMW の key 被覆＝**ADR 0014 (3)**。 |
| COR-005 | P0 | **CLOSED** | weak key に cwd・schema version＋**解決済みコンパイラ binary の content digest**（同名更新で invalidation, PR#1/#2）。heterogeneous で agent≠worker の別 cl を閉じる **worker 再検証も実装済み**（worker が起動 binary を自機 digest し `ExitStatus.resolved_tool_digest`(proto field 5) で報告→agent が weak key の toolchain digest と record ゲートで照合・不一致/未報告は非記録。Pass A a19c125＋Pass B cd7b8dc、2026-06-29、Codex+verifier(opus) 二重レビュー＋CI hooks M4/M6 で homogeneous 命中継続を確認） |
| COR-006 | P1 | **CLOSED** | temp 中間物 heuristic を厳格化（`\temp\` 広域 fallback 除去, PR#1） |
| COR-007 | P0 | **CLOSED** | 出力公開を set-atomic＋get_verified＋有界 memory／stdout-stderr の CAS 記録＆hit 時 replay（PR#1/#2） |
| SEC-001 | P0 | **PARTIAL→繰延(B-machine)** | 暫定: 無認証 Status 書込み RPC を default-deny opt-in 化済み（PR#1）。本道＝**named-pipe transport＋`ImpersonateNamedPipeClient`＋非 LocalSystem 既定**で local EoP→SYSTEM を閉じる。実 Windows サービス＋2 ユーザー SID＋DACL＋EDR 申請を要し当環境で実装・検証不能＝M9.5/M10・lead（`docs/handoff/lead-actions.md` §3） |
| SEC-002 | P0 | **CLOSED** | worker plain-spawn が継承 env の `SEMBAZURU_*` を除去（PR#1） |
| SEC-003 | P1 | **CLOSED** | WriteBack を within-root に scope（agent 権威, PR#1） |
| SEC-004 | P1 | **CLOSED** | fileserver が worker 申告 root を無視し agent 権威 root を使用（PR#1） |
| SEC-005 | P2 | **DEFERRED-ACCEPTED** | `normalize_requested`（字句正規化）＋`path_in_scope`＋fail-closed で `..`/境界を処理済み。完全な handle ベース（`GetFinalPathNameByHandle`）検証は LAN-trusted で受容繰延 |
| PROTO-001 | P1 | **CLOSED** | session_id を 128-bit CSPRNG 化（予測不可, PR#1） |
| REL-001 | P2 | **DEFERRED-ACCEPTED** | remote 失敗時の自動 local fallback は hermetic（compiler staging）アクション前提の at-least-once。at-most-once は副作用宣言を要する将来方針 |
| REL-002 | P2 | **DEFERRED-ACCEPTED(minor)** | JoinSet supervisor は実装済み。graceful drain の精緻化は M10（実 2 台）で |
| RES-001 | P1 | **CLOSED** | worker capacity clamp＋FileClient per-op timeout＋agent console バッファ 8 MiB 上限（PR#1/#2）。prefetch 件数/per-op 件数の上限は LAN-trusted で低優先（必要なら同パターンで追加可） |
| CFG-001 | P1 | **CLOSED** | daemon＋worker とも破損 config を起動拒否（load_or_refuse）＋atomic save（PR#1/#2） |
| MAINT-001 | P3 | **PARTIAL** | local fallback 理由を typed `LocalFallbackReason` 化（脆い `starts_with("route-away")` 契約を除去, commit c657c0f）。codec の magic/version は COR-005/007 で付与済み。残る大物（C++ hook の 4 ファイル分割・winsvc 共通 crate・action lifecycle state machine・ActionContext 引数束ね）は欠陥でなく意図的リファクタ＝計画的に実施 |
| TEST-001 | P2 | **PARTIAL→残=非 admin のみ** | cache 正当性ゲートの大半はユニットテスト済み＋codec 決定的 fuzz（c6cb607）。**supply-chain CI 実装・CI 緑**（cargo-deny advisories/licenses/bans/sources＋`deny.toml`・CycloneDX SBOM・C++ hooks の CodeQL、SHA-pin、b480b28、CI #109＋CodeQL run success）。**property-based fuzzing harness 実装・CI 緑**（proptest で dataplane wire/ops decode＋cas ActionResult codec の no-panic＋round-trip、f159b41、workspace 303）。SHA-pin は 8584537 で済。**残り＝security 非 admin 系のみ**（2 ユーザー/admin 権限の B-machine、当環境で安全に検証不能） |
| DOC-001 | P3 | **CLOSED** | 本ステータス表が指摘状態を同期（doc とコードの整合） |

**未クローズで実装が残るのは実 Windows サービス/2 ユーザー/EDR に依存する 2 件のみ**: SEC-001 本道（named-pipe transport＋`ImpersonateNamedPipeClient`＋非 LocalSystem・要実機 M9.5/M10）、TEST-001 の security 非 admin 系テスト（2 ユーザー/admin の B-machine）。いずれも当環境で安全に検証不能＝lead/後続マイルストーン（検証できない特権分離コードは非交渉 #1 により実装しない）。それ以外は全て CLOSED または現脅威モデルで受容（DEFERRED-ACCEPTED）。2026-06-29 にクローズ: **COR-004**（既定 cache off／verified-only、9c56295＋34895dc）、**COR-005** heterogeneous worker 再検証（worker digest 報告→agent 照合、a19c125＋cd7b8dc）、**TEST-001 の supply-chain CI**（cargo-deny＋SBOM＋CodeQL、b480b28）と **property-based fuzzing harness**（proptest no-panic、f159b41）。いずれも CI（#106/#107/#109＋CodeQL run）緑。

---

## M3.x（近接の正しさ。M4 と並行 or 直前に片付ける候補）

- **未仮想化アクセスの検知→フォールバック機構が未実装。** M3.4 は「安全側」
  （リモート失敗時にアクション全体をローカル再実行）のみ。ADR `0001-vfs-approach.md`
  §113 が M3 設計項目とした「未知の直接 syscall / breakaway 子 / msys2 を検知して
  ローカルへ回す」検知器は未着手。出所: ADR 0001、計画 M3.4。
- **kProbe（メタデータのみ open）は非リダイレクト。** 実トレースで cl は read 12＋
  probe 4。単一マシンでは probe がローカル（同居）に当たり無害だが、実 2 台リモート
  では project ファイルの存在確認が失敗しうる。フックに Stat/exists 経路を通す必要。
  出所: verifier(M3.2)。
- **per-file の暗黙ローカルフォールバックはバイト一致の隠れた危険。** worker 供給
  不可時にフックがローカル open へ落ちる。実ワーカーに同名の別バージョンがあると
  agent ではなくローカルを読む。正しい姿はアクション全体のローカル再実行（M3.4
  チューニング側）。出所: verifier(M3.2)。
- **パス形の取りこぼし（リダイレクト不発→ローカル）:** 8.3 短名 / `\\?\` 長パス
  接頭辞 / UNC / ドライブ相対 `c:foo` / シンボリックリンク・ジャンクション は
  `IsUnderVfsRoot` の前置一致を外れる。フェイルセーフ（ローカル）だが「リダイレクト
  が黙って起きない」のは将来 determinism 差として現れうる。出所: verifier/security
  (M3.2)。`GetLongPathName` 正規化等で対処。
- **Unicode の大文字小文字畳み込み:** `towlower` はロケール依存で非 ASCII を確実に
  畳み込まない。非 ASCII の VFS root/パスで稀に不一致→ローカル。出所: verifier(M3.2)。
- **`\Device\HarddiskVolumeN\` 形の rename 宛先**は `unify`（tracer）が未正規化。
  lld の宛先が稀にこの形だとソースと畳み込めない。出所: security(M3.1.5 M-1)。
- **CWD の実行中変更（SetCurrentDirectoryW）未追従。** アタッチ時 CWD のみ記録。
  VFS の相対パス解決に影響しうる。出所: M2 負債 #4（trace-format §6「Remaining gaps」）。
- **mspdbsrv.exe の扱い未決。** PDB 書き込みは別プロセス＋共有メモリ。注入/監視/無視の
  いずれにするか未決定（PDB は M2/M3 scope 外だが CI 影響あり）。出所: 実測2
  (m3-prestudy §1 Open questions)。
- **temp ディレクトリ分類 — 解消（Phase 6.1, COR-006 クローズ）。** `graph.rs::is_intermediate`
  （`temp_dirs` 前置一致 ＋ `\appdata\local\temp\` substring の双方）と `collect_temp_dirs` /
  `temp_dirs` パラメータを **完全に除去**。location ベースの drop を廃し、survival ベースの
  event-sequence 分類へ置換した：
  - content READ は location に依らず常に input（temp/%TEMP% 配下でも落とさない＝本体の stale hit を解消）。
  - transient は「同一プロセスが生成（OpenWrite/OpenReadWrite/CreateDir/Move-dst）して **成功裏に**
    delete / rename-away / RemoveDir した」パスのみ outputs から除去（per-trace `produced` 集合 ＋
    per-pid 除去で判定）。失敗した delete/rename（`!ev.succeeded()`）は生存出力を残す。
  - cross-process の delete-then-write（例 incremental link で driver が旧 artifact を削除し linker が
    新 output を書く）は trace 順に依らず survivor を保持。
  これにより旧エントリの「`temp_dirs` 空 ＋ TEMP が `appdata\local\temp` 外 → run-varying temp が
  input 集合に漏れて M2 input-hash flap」という残差は **moot**（location 推測自体が無くなった）。
  残る既知の限定事項（いずれも false-hit ではなく false-miss、または既存 deferred）：
  - 稀な cross-process write-then-delete（あるプロセスが書き別プロセスが消す）は survivor 保持の
    保守側に倒すため、非生存パスが false output として残りうる（action cache の miss 増のみ、誤結果なし）。
  - 同一トレース内 RMW ＋ rename-away（`OpenRead(A)→OpenWrite(A)→Move(A→B)`）は A を input から落とすが、
    これは output-shadows-input（ADR 0014(3)）と同族の既存 deferred で、6.1 は悪化させていない（旧コードは
    無条件 `inputs.remove` でより広く落としていた）。
  出所: code-review COR-006 ＋ adversarial review（Codex + verifier opus, 多ラウンド, Phase 6.1）。
- **side-effect read の cache policy（Phase 6.2, ADR 0014 §3 の fail-closed 化）。** registry / env / dir
  enumeration は graph に記録されるが action key に入らず cacheable もブロックしていなかった（stale-hit
  vector）。6.2 で `action_key.rs::input_manifest` に fail-closed gate を追加：registry QueryValue read /
  directory Enumerate / whole-environment BlockRead は `SideEffectPolicy` の allowlist に無ければ
  cacheable=false（record/resolve 両方が honor）。初期 profile は空（最大安全）。残る deferred:
  - **profile 未populated（env-gated）。** cl/clang-cl/dxc の許容 registry/enumerate 範囲は実 compiler
    trace が必要（clang-cl は local に無し）。空 profile は over-block（compiler が routinely registry/
    enumerate するなら cache が薄くなる — M4/M8 で要検証）だが false-miss であり false-hit ではない。
  - **registry OpenKey（key-existence）は未 gate。** hook は記録するが `build_graph` は QueryValue のみ
    fold する。OpenKey は遍在するため fail-closed fold は cache を潰す；正攻法は file probe と同様に
    registry key-existence を absent/present marker として **key に取り込む**こと（hook/trace 変更、6.2 scope 外）。
    現状は稀な key-existence 依存が stale-hit し得る残差。
  - **single-var env read（非-VFS mode）。** VFS mode は worker が env_clear し cmd.env のみで実行するため
    single-var read は weak-key で keyed-safe。非-VFS branch は worker env を継承するため、submit されない
    継承 env var を compiler が読むと unkeyed（stale-hit 残差）。profile tuning と併せて対処。
  - registry allowlist は将来 populate 時に `(key, value)` tuple 比較（delimiter 衝突回避済み）。
  出所: ADR 0014 §3 ＋ adversarial review（Codex review + verifier opus, Phase 6.2）。

## M4（CAS とキャッシュ）— 本バックログの主対象

- **スナップショット一貫性 — 解消（コミット M4.2）。** agent fileserver は初回タッチで内容を CAS に
  ingest し `path→digest` を pin、以降の Read は pin した CAS blob から供給（ディスク再読みしない）。
  セッション開始後の局所編集が走行中アクションを破壊しない。出所: fileserver.rs、v0 §4.1。
- **ワーカーローカルキャッシュ — 解消（コミット M4.2）。** worker は cas_root 配下のローカル CAS を持ち、
  hydrate を digest-first 化（probe で digest のみ取得→ローカル CAS ヒットなら転送ゼロ、ミスのみ fetch）。
  2 回目ビルドで content 転送ゼロを結合テストで実証。出所: DESIGN §7 M4、v0 §4.1。
- **CAS の重複排除・`Has(digests[])` バッチプローブ — 解消（コミット M4.2）。** `OpCode::Has` を追加し
  agent CAS のメンバシップを一括回答。読み側の重複排除は worker ローカル CAS（ローカル has）で、
  書き/出力側は network Has() で実現（後者は M4.3/M4.4 の出力アップロードで活用）。出所: v0 §4.3。
- **ハッシュ方式とチャンク戦略 — 解消（ADR 0003、コミット M4.0）。** 実測で BLAKE3 採用、
  チャンクは whole-file 基準＋大ファイル(2MiB超)のみ固定チャンク、CDC 見送り。`sembazuru-cas`
  の `Digest`（algo タグ付き、既定 BLAKE3）に集約。`determinism.rs::sha256_hex` は M2 ゲート用に温存。
- **CAS コアの DoS 上限がレイヤ外。** `put_verified`/`get` は untrusted バイト列を全量メモリに
  載せる（巨大 blob で OOM）。BLAKE3 はストリーミング可能だが現コアは全量読み。blob サイズ上限・
  ストリーミングハッシュはデータプレーン受信側で対処すべき（CAS コアの責務外）。出所: security(M4.1 LOW)。
- **CAS の eviction/total_size がフルスキャン O(N)。** blob 数増で evict が重くなる（簡易版、ADR 0003
  が明言）。将来サイズ累計のサイドカー化。出所: security(M4.1 LOW)。
- **put と evict の並行でスプリアス失敗の余地。** content-addressed ゆえ内容汚染は無いが、稀に put が
  一時的 io エラーを返し上位が永続失敗と誤認しうる。並行運用するなら `CasError` で一時/永続を区別。
  出所: security(M4.1 MEDIUM)。
- **agent セッション CAS／pin マップが無制限に増加。** fileserver の `Session` は接続をまたいで単一で、
  初回タッチ ingest した blob（temp 下の連番 CAS）と `pinned` マップが単調増加する。eviction は worker CAS
  向けで agent セッション CAS には掛からない。短命セッションでは無害だが長寿命 agent で膨らむ。M4.3/M5 で
  セッション境界の破棄／eviction を設計。出所: verifier(M4.2 懸念2)。
- **アクションキャッシュ — 解消（コミット M4.3）。** 二段階フィンガープリント:
  weak=BLAKE3(argv＋非volatile env＋toolchain content-hash)→観測入力マニフェスト、
  strong=weak＋観測入力の現在内容ハッシュ（tracer の manifest_hash、verify-determinism の
  input_hash と同種）→ ActionResult（出力 digest 群＋exit）。命中時は CAS から出力を
  アトミック公開し実行スキップ。crates/{tracer/action_key, cas/action_cache, agent/action_cache}。
  なお agent が実トレースを取り record/resolve を実コンパイルに結線するのは M4.6 ゲートで実証。
- **アクションキャッシュの cross-dir（入力パスが変わる）再利用は未対応。** strong キーは入力の
  absolute パスを再読込するため、別ディレクトリへ移ったチェックアウトでは miss する（同一マシン・
  同一パスの rebuild は命中）。cross-dir/cross-machine 再利用は論理パス相対化＋MSVC パス独立
  （M4.5）と併せて将来対応。出所: verifier(M4.3 付随所見)。
- **WriteBack チャンク化 — 解消（コミット M4.4）。** WriteBack を offset＋last のストリームに拡張。
  worker は固定チャンク（1 MiB、ADR 0003）で送信、agent は temp に追記しながら BLAKE3 を逐次計算
  （`DigestHasher`）、last で全体 digest 検証＋アトミック rename 公開。大 .pdb/.exe を全量メモリに
  載せない。小出力は単一チャンク。出所: ops.rs、fileserver.rs。

## M5（スケジューラ・多ワーカー・レイテンシ最適化）

- ~~**接続プール無し。**~~ **M5.3 で解決（worker→agent）。** VfsState がセッション 1 接続を
  OnceCell で遅延共有し、hydrate 毎の新規 TCP 接続を廃止（`FileClient` は `Arc<Mux>` で Clone 可）。
  残: フック→worker パイプは依然 redirected open 毎に新規接続（C++ 側、M5.3 では未対応）。
  出所: vfs_pipe.rs(M5.3)。
- ~~**パイプライン化未活用。**~~ **M5.3 で解決。** `FileClient` の `Mux`（reader タスク＋pending
  マップ）で 1 接続上の並行 in-flight を実現、agent `fileserver` の handle_conn も per-request
  spawn で並行 dispatch（応答は request_id で相関、out-of-order 可）。出所: fileclient.rs/fileserver.rs(M5.3)。
- **agent セッション CAS の境界破棄は部分対応（deferred #8 は未解決）。** M5.3 で Session に Drop を
  足し temp CAS を掃除するが、現状 serve ループが `Arc<Session>` を保持し続けるため**発火は
  agent プロセス終了時のみ**（run をまたぐ temp 残留は解消）。長寿命・多セッション agent での
  ビルド単位 eviction は daemon のセッション寿命（M5.5 統合）が必要。pinned/writebacks マップは
  in-memory で Session と共に drop。出所: verifier(M5.3 b1)、deferred #8。
- **バッチ/先読み未実装:** StatBatch のヘッダ解決一括、DirList のディレクトリ先読み、
  ネガティブプローブ・キャッシュ（ディレクトリ membership fingerprint）、timestamp
  偽装（mtime 起因の再 fetch 回避）。BuildXL 由来。出所: m3-prestudy §3。
- ~~**PrefetchHint（依存予測先読み）未実装。**~~ **M5.4 でメカニズム実装。** 制御プレーンに
  `ExecuteRequest.predicted_paths`（v0 §4.1 は「agent-pushed」だが pull モデルのためヒントは
  制御プレーンに載せ既存データ op で温める）、agent `AgentCache::predicted_paths`（マニフェスト
  から予測パス抽出）、worker `prefetch_warm`／`serve_vfs_with_prefetch`（M5.3 多重化で N パスを
  並行先読み＝実質 1 RTT で温め、後続 open は無往復ヒット）。残: **Execute→prefetch の daemon 配線は
  M5.5**（execute_remote は現状 `predicted_paths: Vec::new()`）。logical↔agent パス整合も M5.5。
  出所: v0 §4.1、M5.4。
- **DirList の depth は直下のみ。** 深い先読みは未対応。出所: fileserver.rs 注。
- **トランスポート 3 者ベイクオフ未実施。** ADR 0002 は TCP 採用（QUIC/gRPC 未実装、
  prior と「TCP が判定基準を満たした」で繰り延べ）。WAN/ロス環境が要件化したら
  QUIC を再評価（`sembazuru-dataplane` のトランスポート境界に差し込む）。出所:
  ADR 0002、m3-prestudy §2。
- **フォールバック判定の閾値（レイテンシ予算タイマ・worker 死/分断タイマ）未調整。**
  M3.4 チューニング側。worker 死/分断タイマは ADR 0004 で 15s に確定（実装済み: WorkerTable
  の last_ping 経過で導出）。レイテンシ予算タイマは M5.2 で機構導入・M5.5 で値調整。
  出所: v0 §7 #4、計画 M3.4、ADR 0004。

### M5.1 実装後の既知の限界（verifier 2026-06-14）
- **in-process 死テストは graceful-drain 経路のみ。** `tests/coordination.rs` の「死」は
  ping ストリーム終端（agent ハンドラの `Ok(None)` 出口）で、急死（transport error＝プロセス
  kill/ソケット RST）のトリガ自体は通らない。tonic はクライアント outbound を接続タスクが
  駆動するため、in-process タスクの abort ではソケットが閉じない。dead 検知タイマと
  ハンドラ終了ロジックは同一出口で共有のため検証済みだが、急死トリガの実証は実 daemon の
  プロセス死のみ。実プロセス起動の死テストは将来（worker bin の死活）。出所: verifier(M5.1 A1)。
- **実 Execute→running カウンタ→容量 push の結合が未検証。** heartbeat の `running_actions`/
  `idle_slots` はテストでハードコード値を流すのみ。`WorkerService` の fetch_add／RunningGuard
  decrement は単体では健全だが、Execute 駆動での増減反映は M5.2（スケジューラが idle_slots を
  消費）で結合テストする。出所: verifier(M5.1 B1)。
- ~~**WorkerTable は単調増大（reaper 無し）。**~~ **解消（M7.4）。** register 時に opportunistic reaper
  （`dead_timeout * REAP_FACTOR=20` 経過の dead エントリを retain で除去）を追加。worker 再起動で pid 違いの
  別エントリが累積しても map は有界。背景タスク不要（derive-liveness-on-read と整合）。テスト
  `reaper_drops_long_dead_entries_on_register`。出所: verifier(M5.1 B2)、coordination.rs。
- ~~**可用性の単一障害点（Mutex poisoning の .expect）。**~~ **解消（M7.4、B3）。** WorkerTable の全 lock を
  poison 耐性（`lock().unwrap_or_else(into_inner)`、`WorkerTable::lock`）へ。1 スレッドの panic が Coordination
  全体を落とさない。テスト `poison_tolerant_lock_recovers_after_a_panic`。heartbeat pong の half-open 滞留（B4）は
  HTTP/2 keepalive(10s) で解消する既知挙動（リークでなく受容）。出所: verifier(M5.1 B3/B4)、coordination.rs。

### M5.2 実装後の既知の残リスク（security-reviewer 2026-06-14、詳細は ADR 0004 追補）
- ~~**無認証 Register による誤結果注入／アクション吸引。**~~ **M7.0 で緩和（ADR 0006）。** 共有
  トークンを持たない worker は Register/データプレーンとも拒否されるため、無認証の rogue worker が
  登録して誤結果を返す／アクションを吸引する経路は閉鎖。トークンを持つ trusted worker のバグ/誤設定は
  残（capacity 申告は依然 clamp(1,256) で正しさを担保）。出所: security(M5.2 M3)、ADR 0006。
- ~~**孫プロセスの孤児。**~~ **解消（M6.1e ツリー kill＋M7.4 サンドボックス強化）。** Job Object でツリー一括
  kill（M6.1e、孫 kill を `dropping_the_job_kills_the_grandchild` テストで実証）に加え、M7.4 で UI 制限
  （desktop/clipboard/exitwindows/globalatoms/displaysettings/systemparameters）＋`DIE_ON_UNHANDLED_EXCEPTION`
  （WER ダイアログで headless worker をハングさせない）を付与。**VFS 経路だけでなく plain-spawn 経路の子にも
  同 Job Object を適用**（security HIGH-1、サンドボックスを両経路で一貫）。breakaway は既定 off 維持
  （job 脱出不可）。`crates/worker/src/job.rs`、`lib.rs build_child`。出所: security(M5.2 L3/M7.4)、M7.4。
- **現サンドボックスの守備範囲＝UI＋孤児＋WER のみ（脅威モデル明記・受容）。** Job Object UI 制限は
  USER/GDI（デスクトップ・クリップボード・atom・display/system params）のみで、**ネットワーク発信・
  ファイル/レジストリ書込み・子プロセス生成・トークン操作は制限しない**。脅威モデルは LAN-trusted＋
  共有トークン認証（rogue worker は閉鎖済み）前提のため、実行コードは「trusted worker が受け取った
  コンパイラ入力」＝脅威は外部攻撃者でなくバグ/誤設定。その前提下で UI 制限＋ツリー kill＋die-on-exception
  は妥当な第一歩。network/FS/registry 隔離（WFP/AppContainer）は受容リスクとして M7 未実装、ゼロトラスト
  方向で将来対応。出所: security(M7.4 MEDIUM-2)、researcher(Job Object 限界)。
- **spawn→assign の TOCTOU 窓（既存残差・MEDIUM-1）。** launcher/子を非サスペンドで spawn してから
  assign するため、極端な競合で grandchild が job 外に出る理論的余地（M6.1 risk5 で既出）。完全排除は
  CREATE_SUSPENDED→assign→ResumeThread だが tokio Command は CREATE_SUSPENDED を直接出せず
  `creation_flags`＋手動 ResumeThread が要る。kill_on_drop が直接子をカバーし通常は assign が勝つ。
  出所: security(M7.4 MEDIUM-1)、M6.1e。
- **再割り当て境界の重複 WriteBack。** WriteBack 実装（M3.3/将来）時に content-addressed 冪等を
  テスト固定。現状 WriteBack 未実装で顕在化せず。出所: security(M5.2 M4)。
- **heartbeat の running_actions を least-loaded に未使用。** スケジューラは agent 自身の in_flight
  のみ参照（単一 agent 前提で正確）。複数 agent/別経路の負荷は見落とす。複数 agent 化時に再検討。
  出所: verifier(M5.2 懸念3)。

### M5.5 実装後の既知の残リスク（quality gates 2026-06-14）
- **完全な compile+VFS+RTT 多ワーカー効率は未実測（実 LAN 繰り延べ）。** 単機ハーネス（burn）は
  分配 fan-out のみ測定し、データプレーン供給・RTT を含まない。ターボ／co-tenancy 交絡のため
  忠実測定は実 2 台 LAN（決定者承認）。E(2)=0.88 は分配層の上限値。出所: verifier(M5.5 A1)、ADR 0004 §M5.5。
- **悪意/誤設定 worker の容量過小・過大申告によるレイテンシ劣化。** agent は cpu_count を clamp(1,256)
  し正しさは守る（reassign＋ローカルフォールバック）が、毎回 remote_budget(120s) を食わされる劣化攻撃は
  成立。緩和は M7 認証。出所: security(M5.5 Low)、ADR 0004 §6。
- **dead-but-TCP-accepting worker がアクションを最大 120s 拘束。** connect_timeout 250ms は connect_lazy で
  初回 RPC まで遅延し、stall すると remote_budget まで reassign しない。レイテンシ予算チューニング（M5.5/M7）。
  出所: verifier(M5.5 B3)。
- **run_build の gate サイズ・channels prune は開始時スナップショット。** ビルド中の worker 増は未反映
  （過小利用、ハングなし）。channels は run_build 開始で live のみ retain（無制限増大は解消）。
  出所: security(M5.5 Low)、verifier(M5.5 B2)。
- **同一 path への真の並行 WriteBack は path ロック未実装。** 現状の逐次 reassignment では発生せず、
  発生しても content-addressed＋digest 検証＋atomic publish で誤バイト publish は構造的に不可（fail-closed）。
  将来 worker 起因の投機的重複実行を入れるなら write_back の path 単位ロックを検討。出所: determinism(M5.5)。
- ~~**worker の Abort 未配線（acknowledge のみ）。**~~ **M6.1e で解消。** VFS アクションは launcher を
  kill-on-close Job Object に割当て、孫（実コンパイラ）まで含むツリーを kill。reassign（ストリーム drop）
  ／Abort RPC（`TerminateJobObject`）どちらでも能動 kill。`crates/worker/src/job.rs`。graceful drain は M7。

## M6（ビルドシステム統合 / Integrations）

### M6.0 実装後の既知の残リスク（quality gates 2026-06-14）
- **解消（M6.0 で fix）: LocalIntake の非ループバック bind 拒否。** intake は提出された任意コマンドを
  実行し無認証（M7）。`SEMBAZURU_INTAKE=0.0.0.0:...` で無認証リモート RCE になりうるため、daemon 起動時に
  `resolve_loopback_intake` で非ループバックを拒否（ランチャは常に 127.0.0.1 を叩くため無コスト）。
  Coordination/fileserver は worker 用 LAN 到達が要るため非ガード。出所: security(M6.0 MEDIUM)。
- **worker が stdout/stderr を捕捉しない（実コンパイラ診断が消える）。** `crates/worker/src/lib.rs` の
  `run_action` は stdin のみ null 化し stdout/stderr は継承。リモート実行時、警告/エラーが worker コンソールへ
  出て開発者に見えない。M6.0 自明ゲート（`cmd /c exit N`）では無害だが、**M6.1 の実コンパイルで診断ミラーが必須**
  （Execution proto への stdout/stderr ストリーム追加＋worker 捕捉）。出所: verifier(M6.0 #3)、author 開示。
- **ランチャが全環境変数を転送（off-box シークレット流出の M6.1 リスク）。** `sembazuru_launcher.rs` は
  `std::env::vars()` 全体を Command.env に載せる。M6.0 は loopback＋ローカルフォールバック忠実性のため受容だが、
  M6.1 で dispatch が実リモート worker（無認証・M7）へ到達した瞬間、開発者のトークン/鍵が wire に乗る。
  M6.1（リモート到達前）に「コンパイラ関連 env のみ」allowlist/denylist を検討。出所: security(M6.0 LOW)。
- **intake 直 dispatch に admission 上限なし。** `IntakeService::submit_action` は per-call の `mpsc::channel(8)` の
  外側に同時 SubmitAction 数の上限を持たず、各 dispatch が（worker 不在時）`run_local` で実 OS プロセスを起こす。
  intake flood → ローカルプロセス storm。loopback 強制で攻撃面はローカルに限定されるため M7（または非ループバック化
  時に必須）で `run_build` 同様の semaphore ゲートを intake 層に。出所: security(M6.0 LOW)。
- **ランチャの run_local 失敗が bare -1 で原因を握り潰す。** daemon 不達＋コンパイラ不在時、メッセージが
  daemon を誤って責め、`run_local` の実エラー（program not found 等）が捨てられ exit -1。ビルドは正しく失敗するが
  診断が誤誘導。M6.1 で run_local エラーを surface。出所: verifier(M6.0 #2)。

### M6.1 実装後の既知の残リスク（2026-06-14）
- **clang-cl の .obj は isatty（stdout/stderr が console か否か）に依存する。** M6.1f で worker が子の stdio を
  pipe 化（非 tty）したところ、参照ビルドを raw console（tty）で取っていたためバイト不一致が顕在化（CI 実測）。
  実ビルドシステム（ninja/msbuild）はコンパイラ出力を pipe する＝非 tty なので、**参照を非 tty（ファイルリダイレクト）で
  ビルド**するのが現実に即した正しい比較。修正後、**分散ビルドと action cache republish は clang-cl バイト一致**
  （CI ゲートで実証）。出所: verifier(M6.1)、CI 実測。
- ~~**ローカルフォールバックの .obj は clang-cl で参照とバイト一致しない（残差・要調査）。**~~ **解消（M7.0、
  原因特定）。** 残差の正体は env/PATH ではなく **COFF ヘッダの TimeDateStamp（offset 4–7）の壁時計タイムスタンプ**
  だった。M7.0 の CI 診断（ref/distributed/cached/fallback の 554 バイト中 offset 4 の 1 バイトのみ相違、値はビルド
  時刻の秒差）で確定。`/Brepro` 無しの clang-cl は COFF タイムスタンプを壁時計で埋めるため、ビルドが別秒に走ると
  1 バイトだけ差が出る（distribution は無関係＝バイト完全保存）。ゲートの clang-cl 呼び出しに `/Brepro` を付与して
  タイムスタンプを sentinel 化し解消。出所: CI 診断(M7.0, run 27489791478)。
- ~~**m6_daemon_compile の distributed/cached バイト一致が CI 実行間でフレークする。**~~ **解消（M7.0、原因特定＋
  修正）。** 原因は上記と同根の **COFF TimeDateStamp（壁時計）**。同一コミット e26eeb2 が branch 間で success/failure に
  割れたのは、参照ビルドと distributed ビルドが同一壁時計秒に収まるか否か（worker 登録リトライの遅延次第）でタイム
  スタンプの 1 バイトが一致/不一致になっていたため。CI 診断で ref/distributed/cached/fallback が offset 4 の 1 バイト
  （タイムスタンプ）のみ相違と確定し、distribution 自体はバイト完全保存（cached==distributed も確認）。M7.0 auth とは
  無関係。ゲートの clang-cl 呼び出しに `/Brepro` を付与して解消。出所: CI 診断(run 27489791478、ref==ref2 で compiler
  決定性も確認、2026-06-14)。
- **他の clang-cl バイトゲートも /Brepro 一貫適用が望ましい（堅牢化・低優先）。** vfs_compile.ps1 /
  m4_cache_rebuild.ps1 / determinism.ps1 等の clang-cl バイト一致比較も、原理的には同じ COFF 壁時計
  タイムスタンプ・フレークの対象。現状は参照と被測定ビルドが近接（同一秒）して安定 PASS するが、ランナー負荷で
  まれにフレークしうる。M6.1 daemon ゲートと同様に各 clang-cl 呼び出しへ `/Brepro` を付与すれば構造的に堅牢化
  できる（タイムスタンプ正規化と等価）。ローカル clang-cl 非搭載のため CI で検証要。出所: M7.0 原因特定の派生。
- **action cache の trace は単機共有 FS 前提（VfsExecution.trace_dir）。** worker が書いた trace を daemon が
  直接読む。2 台分割では trace を data plane で返す必要。実 LAN（決定者承認）で対応。出所: ADR 0005、M6.1c。
- **launcher の出力推論は /Fo ベースの最小ヒューリスティック。** `/Fo` 無し・複数出力・非標準フラグは
  取りこぼし、その場合は無キャッシュ（誤ビルドにはならない）。MSBuild/UE 等は宣言出力を別途与える要あり。
  出所: M6.1c。
- **Job Object 割当に spawn→assign の小窓。** launcher が DLL パス解決中に assign されるため通常は間に合うが、
  極端な競合で孫がツリー外に出る理論的余地。完全排除は CREATE_SUSPENDED→assign→resume（tokio 非対応）。
  従来の kill_on_drop のみ（常に孫を孤児化）より厳密に良い。出所: Plan(M6.1 risk5)、M6.1e、security(M6.1)。

### M6.1/M6.2 security-reviewer 所見（2026-06-14、PASS-with-findings・BLOCK 無し）
- **action cache の trace 過少申告による stale 提供（worker 信頼境界）。** strong key は manifest の入力パスを
  resolve 時に**現在内容で再ハッシュ**するため内容改竄は防げる（誤バイト提供は構造的に不可）。だが悪意/バグ
  worker が trace から入力を**落とす**と、その入力変更が strong key を動かさず stale な cache 命中を招く。
  単機では worker はローカル信頼プロセス。緩和は M7 の Register 認証（mTLS/attestation）と同根。出所: security(M6.1 Low)。
- ~~**launcher の full-env 転送：LAN 分割の直前が今。**~~ **解消（M7.1、LAN 分割前に先行実装）。** launcher は
  `std::env::vars()` 全転送をやめ、コンパイラ関連 env のみの allowlist（`env_filter::filter_compiler_env`：
  PATH/INCLUDE/LIB/LIBPATH/TMP/TEMP・VS/Windows SDK ロケータ・OS 基本＋families の prefix、case-insensitive、
  `SEMBAZURU_ENV_PASSTHROUGH` で追加可）に縮約。開発者のシークレット（AWS/GitHub/SSH 等）と worker 内部
  `SEMBAZURU_*` はワイヤに乗らない。ローカルフォールバック（run_local）は継承 env で従来どおり動作（off-box
  流出は元々なし）。determinism は CI バイトゲートで確認（allowlist が出力影響 env を取りこぼさない）。
  出所: env_filter.rs、tests(env_filter)、security(M6.1 Low/M6.0 LOW)。
- **per-action scratch/trace ディレクトリの無制限増加（disk DoS）— 解消（M9.2）。** worker の hydrated scratch は
  アクション完了後（Job クローズ＋child reap の後）に `remove_dir_all`、daemon の per-action `trace-{n}`
  （`SEMBAZURU_TRACE_ROOT` 下）は run_submission 末尾で削除（記録の有無に依らず）。どちらも全 return 経路を被覆。
  これでビルド反復で scratch/trace は累積しない（プラトー）。出所: security(M6.1 Low)、verifier/determinism-checker(M9.2)。
- **注入が production コンパイル経路に。** worker の DLL 注入（launcher.exe＋DetourCreateProcessWithDll）は M3 と
  同一機構だが、M6.1 で**テスト足場でなく常時動作**に。新たなマルウェア的シグナル（RWX/直接 syscall/スレッド
  注入）は無く署名可能。M7 のベンダ許可リスト申請は steady-state の挙動（injector が cl.exe を子に注入）を明記。
  出所: security(M6.1 Info)、deferred EDR メモ。

### M6.3（CMake/Ninja 統合ゲート）実装後の繰延（2026-06-15）
- **distributed `.obj` がフル env のローカル参照とバイト一致しない（DIAG 降格・best-effort）。** `m6_ninja.ps1` は
  CMake の compile 行で distributed と「launcher 無しローカル参照」を比較すると、clang-cl で ~900B 差が出る（CI 実測、
  TAIL ASCII で確認）。差は `.debug$S` のビルド情報（cwd/パス/コマンドライン文字列）で、ローカル参照は開発者のフル env、
  worker は `env_clear`＋コンパイラ env allowlist（M6.0/M7.1）で走る**非対称**に起因。リンク・実行に無影響（exe exit 0）、
  `distributed==cached` は完全一致（CAS round-trip ロスレス）。よってゲートの hard 不変条件は `cached==distributed` とし、
  dist-vs-ref は DIAG。canonical な distributed==local バイト一致は最小 compile について `m6_daemon_compile.ps1` が所有。
  強い「CMake 経路でも distributed==local」を求めるなら、参照ビルドを worker と同じフィルタ env で取る対応が将来余地。
  出所: CI 診断(M6.3, run 27505885286)、verifier(M6.3 反証)、横断「MSVC ネイティブのバイト一致は best-effort」と同類。
- **単一 worker＋並列 fanout ではスケジューラが一部アクションをローカルフォールバックする（設計通り・ゲートは -j1 で回避）。**
  ninja の並列投入で idle slot 不足時に route-away ではなくローカル実行に落ちる（windows-2025 で remote=3/4 を観測）。
  M6.3 は `ninja -j 1`（直列）で単一 worker に常時スロットを持たせ全 TU の remote を決定化。並列 fanout の取りこぼし削減
  （キューイング/待機の閾値）は M5 のスケーリング領域。出所: CI(M6.3, run 27506175019)。
- **増分ヘッダ依存追跡は分散経路で機能する（clang-cl で実証）。非英語ロケールの cl のみ、`deps = msvc` の
  プレフィックス・エンコーディング不一致で取りこぼす edge。** 当初「`/showIncludes` が伝播せず増分が壊れる」と疑ったが、
  直接実行プローブで**伝播は正常**と判明（launcher の stdout に `メモ: インクルード ファイル:  <build-dir パス>` が正しく出力。
  C++ launcher は全 std ハンドル転送、worker は両ストリームを OutputChunk 化、agent は両蓄積、Rust launcher は両 replay）。
  ninja の `deps = msvc` は CMake が configure 時にサンプルした**ローカライズ済みプレフィックスのバイト列**を前方一致で見るが、
  worker（`env_clear`）の cl が非英語ロケールで出すコードページ（例 CP932）が CMake サンプルと一致しないと `#deps 0` になり、
  その環境では分散後のヘッダ編集が再ビルドを誘発しない。**clang-cl は ASCII の "Note: including file:" 固定で無影響**
  → M6.3 CI（windows-2022/2025・clang-cl）で「編集→依存 TU(a/b/c)のみリモート再コンパイル・main 不変・exe が編集反映(exit 30)」を
  実証済み（ゲートは clang-cl で hard 強制、cl では DIAG）。非英語 cl の堅牢化が要るなら worker の出力コードページを CMake
  サンプルに合わせる（コンソール CP 固定）か、depfile ベース（`/sourceDependencies` JSON）への移行が将来余地。クリーンビルドと
  cached/distributed のバイト経路は元々無影響。出所: M6.3 直接プローブ＋CI 実測(2026-06-15)、launcher.cpp/worker lib.rs/agent intake.rs。
- **MSBuild シム経路の action cache 命中 — 解消（本修正、2026-06-15）。** MSBuild の CL タスクは全ソースを **1 つの
  `cl @<temp>\tmp<RANDOM>.rsp`（レスポンスファイル）で起動した単一バッチアクション**（出力 `obj\{a,b,c}.obj` ＋ 共有 `/Zi`
  PDB `bin\test.pdb`）。これを正しくキャッシュ命中させた。**真因は当初の記述（「ソースが裸相対名でトレースされ一時物
  ヒューリスティックで落ちる」）ではなく、実トレース実測で別物だった**: VFS 実行ではコンパイル対象ソースも `shared.h` も
  **トレース入力に一切現れなかった**（出るのはツールチェーン DLL・PDB・システムファイルのみ）。原因は hook
  （`hooks/src/interceptor.cpp` の `HookedCreateFileW/A`）が **VFS リダイレクトした読み取りを `RecordCreateFile` せずに即
  return** していたため＝VFS 供給入力が trace に乗らず、strong key が空（ツールチェーンのみ）。よって編集しても key が動かず
  stale を serve しえた。
  - **修正 ①（真の BLOCK-A 核心）:** hook がリダイレクト読み取りを**論理（要求）パスで `RecordCreateFile` 記録**
    （GetLastError 退避・True\* のみ・二重記録/再帰なし、security-reviewer 確認済み）。これで a.cpp/b.cpp/c.cpp/shared.h が
    `read` 入力としてトレースに乗る（実測確認）。
  - **修正 ②（入力カバレッジ＋fail-closed）:** `action_key.rs` の `input_manifest` が入力を**実効ルートへ anchor**し、
    `AccessKind::Read` の内容依存を `InputKind::Content`（`manifest_hash` で再読込、読めなければ `<missing>` で force-miss、
    **絶対に silent drop しない**）に。anchor 不能な実 read は `cacheable=false`＝**無キャッシュ**（ADR 0007 §b.3 を入力側にも）。
    cwd 未記録（root_pid cwd=None 実測）でも宣言 `SEMBAZURU_INPUT_ROOT` への anchor で救う。
  - **修正 ③（BLOCK-B 書き込みスコープ）:** `is_under_build_root` を `..`／UNC／device／drive-relative(`c:foo`)／rooted(`\foo`)
    に対し**自己完結で拒否**（`/`区切りの `..` も）。`action_cache.rs` の record/resolve が publish/ingest 前に同関数で全 output
    を再検証（違反は hard error）。`input_root` を **intake で一度だけ `normalize_for_compare` 正規化**し、その単一値を
    relativize（record）と publish join（resolve）で共用＝非対称解消。
  - **修正 ④（weak key 安定化＋TOCTOU）:** launcher が `@<rsp>` を実効ルート配下の content-addressed 安定パス
    （`<root>\.sembazuru\sbz-rsp-<digest>.rsp`）へ**atomic-rename＋書込後 digest 再検証＋symlink 拒否**で実体化し argv を書換え、
    weak key を再現可能化（ランダム rsp パス問題を解消）。
  - **修正 ⑤（恒久ゲート化）:** `hooks/test/m6_msbuild.ps1` を hard アサート化＝ MSBUILD1 remote / MSBUILD2 cache-hit＋全
    obj＋PDB 復元（worker 停止下）/ MSBUILD3 ソース破壊編集→FAIL（stale 不可）/ MSBUILD3b ヘッダ破壊編集→FAIL（VFS 供給
    ヘッダもカバー）/ FALLBACK。MSBuild 統合（Directory.Build.targets / quickstart.md）が `SEMBAZURU_INPUT_ROOT` を宣言。
  - 据え置きの低リスク（変わらず）: 共有 PDB の複数アクション横断キャッシュ（MSBuild バッチでは非発生）／cross-machine 出力
    パス整合（M8.x）／`/Zi` PDB の MSVC 非決定（命中時は build1 一貫セット・byte best-effort）。
  出所: 実トレース実測（VFS リダイレクト読み取りが未記録）＋ローカルゲート PASS＋品質ゲート（verifier/determinism/security,
  model opus, BLOCK 無し・H1/M1/M2 修正後 CLOSED, 2026-06-15）。`hooks/src/interceptor.cpp`、`crates/tracer/src/action_key.rs`、
  `crates/agent/src/{action_cache,intake}.rs`、`crates/agent/src/bin/sembazuru_launcher.rs`。

## M7（堅牢化・セキュリティ）

- **制御/データプレーンの認証 — 解消（M7.0、ADR 0006）。** 信頼モデルを LAN-trusted に
  確定し、共有トークン（`SEMBAZURU_CLUSTER_TOKEN`）を制御プレーン（Register）とデータプレーン
  （session 確立 Hello）両方で照合。誤/無トークンは拒否（無認証 Register／無認証ファイル供給の
  誤結果注入経路を閉鎖）。token 未設定なら従来どおり無条件 accept（M5/M6 後方互換）。VFS パイプ
  （hook↔worker のローカル名前付きパイプ）は機内ローカル経路で非対象（信頼境界は worker→agent TCP）。
  proto は `auth_token`(10)＋`supports_auth` capability flag で wire 非破壊。予約 11 は client-cert/
  attestation 用に継続。出所: ADR 0006、crates/{proto,worker,agent}、tests(coordination/dataplane_fs)。
### M7.0 security-reviewer 残所見（2026-06-14、PASS-with-findings・BLOCK 無し）
- **F1 解消（M7.0g）。** auth 無効かつ非 loopback bind 時に daemon が起動時 WARNING を出す
  （`warn_if_exposed`、coord/fileserver の local_addr が非 loopback で発火）。fail-closed の
  `SEMBAZURU_REQUIRE_AUTH` フラグ化は将来余地。出所: security(M7.0 F1)。
- **F4 解消（M7.0g）。** データプレーン handshake に 10s read タイムアウト（slow-loris で接続タスクを
  無限占有させない）。未認証 in-flight 接続数の上限化は LAN 前提で deferred。出所: security(M7.0 F4)。
- **heartbeat ストリームは token 非検証（LOW・受容）。** `on_ping` は既存エントリのみ更新（新規注入不可、
  Register が gate 済み）。既知 worker_id を推測した peer が liveness clock を refresh し black-hole を
  延命しうるが、新規誤結果注入はできず LAN 前提で許容。HeartbeatPing への token 追加は hot keepalive を
  膨らませるため見送り。出所: security/verifier(M7.0)。
- **VFS パイプのローカル ACL 無し（F2・LOW・既存前提）。** `\\.\pipe\<name>` は同一マシンの任意ユーザ
  プロセスが接続し任意 logical path の hydrate を誘発しうる（M3/M6 からの既存前提、M7 新規欠陥ではない）。
  agent 側パススコープ（M7.1）が別途効く。将来 SDDL で現ユーザ限定 ACL を付す余地。出所: security(M7.0 F2)。
- **token_eq の長さ早期 return（F3・LOW・修正不要）。** 内容比較は定数時間。長さと「presented が空か否か」
  のみタイミングに出るが、共有クラスタトークンで実害なし。出所: security(M7.0 F3)。
- **Register→VFS 供給の一気通貫 e2e は未整備（verifier 指摘）。** 制御プレーン（Register/heartbeat）と
  データプレーン（Hello→fetch）の auth は個別テストで実証、結合は daemon/worker の本番配線で担保。
  authed 全経路の e2e は m7 CI で `SEMBAZURU_CLUSTER_TOKEN` を設定した daemon コンパイルゲートで補完予定。
  出所: verifier(M7.0)。

- **TLS（暗号化）は LAN 既定 off・実 LAN まで繰延。** LAN-trusted ではトークンが認証を担い、TLS は
  「localhost/LAN-trusted スコープを出る時のみ必須」（v0 §5）。実 TLS 配線（tonic ServerTlsConfig/
  ClientTlsConfig＋データプレーン tokio-rustls）は実 2 台 LAN 実測・ゼロトラスト判断と同じ繰延に置く
  （本番条件で on 経路を検証できないため）。wire 非破壊の移行口（予約 11・capability flag）は確保済み。
  digest 検証は TLS 有無に関わらず常時。出所: ADR 0006、AskUser(2026-06-14)。
- **agent fileserver のパススコープ — 解消（M7.1）。** データプレーンの session-open ハンドシェイク
  （`HelloRequest`）を常時化し、worker が宣言した入力ルート（`VfsExecution.vfs_root`）を agent が記録、
  read 系（StatBatch/OpenRead/DirList）をそのルート配下に限定。範囲外は not-found（存在も秘匿）。任意絶対パス
  供給を廃止し、rogue/buggy worker が agent の任意ファイル（例 ~/.ssh）を読む経路を閉鎖。境界一致＋case/
  separator 正規化、path 形エッジ（8.3/`\\?\`/UNC/symlink）は fail-closed。出所: fileserver.rs（path_in_scope）、
  tests(dataplane_fs declared_root_scopes_file_supply)。WriteBack（出力書き戻し）パスのスコープは別項（下記）。
- **DLL 返却パス検証 — 強化（M7.1）。** hook は worker 返却（hydrated scratch）パスを **GetFullPathName で
  正規化してから** scratch 配下を境界チェック（`<scratch>\..\..\secret` の `..` トラバーサルを閉鎖）、かつ
  VFS モードで scratch 未設定なら fail-closed（未検証パスを開かない）。実装済みの anti-recursion（scratch 配下
  open 非リダイレクト）は維持。出所: interceptor.cpp(VfsTryRedirect)。
### M7.1 security-reviewer 所見（2026-06-14、BLOCK-1 は修正済み）
- **BLOCK-1 解消（M7.1）。** Rust の `path_in_scope` が `..` を正規化せず文字列前置一致のみで、
  `c:\root\..\..\secret` がスコープ内判定→OS が `..` を畳んでスコープ外供給（fail-open）だった。
  `normalize_requested`（FS 非依存の字句正規化：ドライブ絶対要求・`.`/`..` 畳み込み・ドライブ脱出は None＝
  fail-closed）を追加し、正規化後に境界一致。C++ 側（GetFullPathName）と規律を揃えた。テスト追加
  （path_in_scope_blocks_dotdot_traversal、normalize_requested_rejects_*、dataplane_fs に `..` 結合）。
  出所: security(M7.1 BLOCK-1)。
- **スコープルートは worker 自己申告（HIGH-2・LAN-trusted で受容、authoritative 化は繰延）。** agent の
  file server はステートレスで Hello の宣言 root をそのまま信用するため、悪意 token 保持 worker は root を
  `c:\`/空に広げ自スコープを無効化できる。LAN-trusted（worker は共有トークン保持）では防御層として受容だが、
  agent が dispatch した `vfs_root` を session_id でキーに authoritative 照合する方式はゼロトラスト方向の
  繰延。v0 §5 に「worker-declared・widen 可」を明記済み。出所: security(M7.1 HIGH-2)、verifier(M7.1 concern)。
- **range Read は scope/pin 認可ゲートを持たない（MEDIUM-3・低実害・繰延）。** `read_range` は digest で
  CAS を引くのみで scope も pin も見ない。BLOCK-1 修正で out-of-scope open は pin しない＝正規経路で digest を
  学習できず、256bit digest は総当たり非現実的。ただし CAS はセッション横断共有のため、別経路で digest を
  得れば scope 無関係に読める構造的弱さは残る。per-session pinned-digest 許可セットに限定するのが将来対応。
  出所: security(M7.1 MEDIUM-3)。
- **エラー sanitize 残存経路（LOW-7・確認済み・許容）。** scheduler の fallback `reason`（worker_id＋transport
  error）は agent→ローカル開発者コンソール（loopback）向けで FS パス非含有・非信頼境界越えでない。M7.1b の
  sanitize 対象（worker→agent・agent WriteBack→worker）は閉鎖済み。intake/coordination に FS パス漏洩は無し。
  出所: security(M7.1 LOW-7)。
- **WriteBack の出力パスはスコープ未検証（M7.1 で繰延）。** 悪意/バグ worker が WriteBack で agent の任意パスへ
  書き込みうる。出力は宣言出力集合（v0 §3.2 declared_outputs）に限定すべきだが、単機モデルでは出力はコマンドが
  名指すローカルパスに落ちる（writeback 非経由）。content-addressed＋digest 検証＋atomic publish で誤バイトは
  構造的に不可。実 2 台 writeback 導入時に declared_outputs ベースの宛先スコープを設計。出所: M7.1 設計判断。
- **EDR/許可リスト申請事項:** DLL は ntdll!NtSetInformationFile をインラインフック
  ＋ファイル open のリダイレクト（観測より強いシグナル）＋名前付きパイプ。RWX/直接
  syscall/スレッド乗っ取り等の TTP は無く署名可能。M7 のベンダ説明で明示。出所:
  security(M3.1.5/M3.2)、m3-prestudy §1 EDR メモ。
- **worker の spawn 上限・タイムアウト無し（DoS）。** Execute 毎に detached spawn、
  孤児子プロセス（クライアント切断時に kill されない）。Capabilities.cpu_count で
  Semaphore＋wait タイムアウト。出所: security(M3.1 F4/F5)。
- **worker の env はクライアント供給を継承環境へ上書き（PATH/COMSPEC 等）＋argv[0] は
  ベア名。** M3.2 で `env_clear`＋絶対 argv0 へ。BatBadBut(.bat/.cmd 引数注入)は
  std 1.77.2 で緩和済だが、worker argv[0] は絶対パスのみ・batch 起動は拒否/明示の
  不変条件を M3.2 サンドボックス仕様に明記。出所: security(M3.1 F6/F7)。
- **エラー詳細の情報漏洩 — 解消（M7.1）。** worker のセットアップ/実行エラー（spawn/scratch/trace/job/wait）の
  詳細（worker 側パス・生 OS エラー）を worker の stderr にローカル出力し、ワイヤ（FAILED detail）には粗い
  カテゴリのみ返す（`setup_err`）。agent の WriteBack I/O エラー（create/temp/seek/write/open/rename）も同様に
  agent stderr へ、worker へは粗いカテゴリ（`wb_io_err`）。digest mismatch 等のハッシュ系は有用かつ非パスなので温存。
  開発者は FAILED→ローカルフォールバックで実コンパイラ出力を直接得る。出所: lib.rs/fileserver.rs。
- ~~**32/64bit 双方の DLL。**~~ **解消（M7.3）。** CMakeLists を arch 連動 DLL 名（x64→sbz_interceptor64、
  x86→sbz_interceptor32）にし両 bit ビルド、同ディレクトリ配置。Detours が 64/32 サフィックスから兄弟 DLL を
  導出して子のビット幅に応じ自動注入。クロスビット注入ゲート（m7_inject32.ps1、正＋負の対照）で実証。
  出所: trace-format §8、M7.3。

### M7.4 残項目（運用堅牢化の繰延、daily 信頼性 Done-when は満たす）
- **障害時フォールバックは網羅テスト済み（M7.4c）。** no-worker（intake/scheduler_dispatch）、remote-unreachable
  （loopback）、daemon-down（m6_daemon_compile）を既存テストでカバー。M7 新規の障害モード（auth 拒否 worker・
  容量過小/過大申告）は「live worker 無し→フォールバック」「remote 失敗→フォールバック」に帰着し既存経路で
  カバー（非交渉事項 #2）。冗長テストは追加せず帰着を記録。出所: M7.4。
- **レイテンシ予算タイマの値調整は実 2 台 LAN まで繰延。** 機構は M5.2 導入済み。M5.5 が「忠実な値調整は
  実 2 台 LAN（決定者承認）」とした方針を踏襲。単機＋RTT エミュでは本番 RTT 分布が得られず実値化不能。
  保守的既定値は維持。出所: ADR 0004 §5、M5.5、M7.4。
- **worker Abort/再割り当ての graceful drain は繰延（refinement）。** 現状の Job Object ツリー kill は正しく
  即時（孤児なし）。graceful drain（in-flight を待って畳む）は綺麗さの改善であり正しさ要件ではないため、
  実 2 台 LAN での reassign 実測と併せて将来対応。出所: M5.x、M7.4。
- **per-action scratch/trace／agent セッション CAS の disk eviction は繰延（deferred #8 と同根）。** 長寿命
  daemon/worker での disk 累積。境界破棄はセッションライフサイクル（M5.5 部分対応）に依存し、ビルド単位
  eviction は daemon のセッション寿命管理が要る。WorkerTable reaper（M7.4）でテーブルは有界化したが、
  scratch/trace/CAS の eviction は別途。出所: deferred #8、security(M6.1 Low)、M7.4。
  **回収（M9.2, ADR 0008）:** (1) per-action scratch/trace はアクション後に削除（上記「解消（M9.2）」）。
  (2) 永続 agent CAS は総量上限（LRU、`SEMBAZURU_CACHE_MAX_BYTES`、`AgentCache::evict_to`→`BlobStore::evict_to`）
  を daemon の周期スイープ＋Status `TriggerEviction` RPC で自動駆動。eviction は correctness-safe（evict は miss を
  生むのみで誤結果は生まない＝determinism 不変、unit/determinism-checker で実証）。
  **残（据え置き）:** fileserver の **agent セッション CAS（temp pin ストア）** の per-build 境界破棄は未実装。
  現状 daemon 1 プロセス＝1 Session のため、同一プロジェクト反復ではタッチ済みファイル集合でプラトーするが、
  多数の異なるプロジェクト/ファイルを跨ぐ超長寿命 daemon では増える。per-build セッションライフサイクル（M5.5 系）
  が要るため別途。出所: deferred #8、verifier(M9.2)。

## M8（汎用化 / Beyond Compilation）— ADR 0007

- **M3.x「未仮想化検知器未実装」「per-file 暗黙ローカルフォールバックの危険」を M8.2 で対応予定。**
  ADR 0007 §(a) の二段機構（route-away スクリーン＋worker fail-closed）で扱う。着手・解消時に M3.x 該当行へ
  「解消（M8.2）」を付す。出所: ADR 0007、deferred M3.x。
- **M6.1「launcher の出力推論は /Fo ヒューリスティック」を M8.1 で汎化（解消）。** trace ベース出力発見
  （`logical_outputs`）を既定経路化し、外部宣言（`SEMBAZURU_OUTPUTS`／declared_outputs）を優先。dxc 等
  非 cl/clang-cl でもキャッシュ可能化。outside-root 出力があるアクションは fail-closed で無キャッシュ
  （`cacheable_outputs`、verifier M8.1 Finding 1）。出所: ADR 0007 §(b)、M6.1。

### M8.1 実装後の既知の残リスク（verifier 2026-06-14）
- **既定 cacheable の非決定性露出（MEDIUM・設計受容・ADR 0007 §c）。** trace 発見でキャッシュ対象が広がった結果、
  宣言出力を持たなかった非決定的ツールも既定（`non_deterministic=false`）でキャッシュされうる。strong key は入力
  再ハッシュのみで**出力の非決定性は検知できない**ため、真に非決定的なツールは run1 のバイトを run2 で誤提供しうる。
  防御は ① 人手の `SEMBAZURU_NONDETERMINISTIC` フラグ（既定 false）と ② determinism ゲート（M8.4、決定的 WL のみ
  キャッシュ実証）。本 changeset は「auto-discover したアクションが determinism ゲートを通過済みか」を強制しない＝
  ADR 0007 §c の「既定決定的・不一致 or 既知フラグで降格」前提に依存。dxc は M8.4 で byte 一致を実証してから
  キャッシュ対象とする。出所: verifier(M8.1 Finding 2)、ADR 0007 §c。
- **non_deterministic record-skip の結合テストは M8.5 で実証。** 単体は `cacheable_outputs`／`infer_outputs` を
  カバー。record-skip 経路（VFS＋cache＋worker 必要）は M8.5 の非決定 WL ゲートで実証。出所: verifier(M8.1 Finding 3)。

### M8.2 実装後の状態と繰延（2026-06-14）
- **① route-away スクリーン・② worker fail-closed は実装（M8.2）。** ①=agent `scheduler::route_away_reason`
  （msys2/cygwin ランタイムリンクのバイナリ走査＋`SEMBAZURU_LOCAL_ONLY` denylist）でリモート投入前にローカルへ。
  ②=`VfsExecution.strict`／`SEMBAZURU_VFS_STRICT` で hook（`interceptor.cpp` `committedFailure`）が vfs_root 配下の
  供給不能 open を**ローカルに落とさず**失敗させ `.sbz-unvirtualized` を drop、worker が exit を抑止→agent が
  「no exit＝fallback」経路でローカル再実行。既定 off で M3-M7 ゲート不変。出所: ADR 0007 §a。
- **③ breakaway 子の注入検証・④ mmap strict 強制は繰延（防御深化・低優先）。** 正しさの核（①②）は満たす。
  ③: 既存 Detours は子へ注入する（M7.3）。env を消して vfs モードを失う breakaway 子の検知は parent の
  CreateProcess フックでの追加検査が要る。コンパイラ/dxc は breakaway 子を生成しないため M8.4 証明には不要。
  ④: read 経路は ② が CreateFile 境界で閉じる（redirected handle 上の mmap は hydrated copy、fail-closed なら
  handle 自体が無い）。非フック open→mmap の残余は route-away（①）の領域。完全強制（handle→path 追跡）は
  EDR シグナル増を伴うため繰延。実装時は security-reviewer 必須。出所: ADR 0007 §a③④。
- **strict fail-closed の e2e は M8.4 dxc ゲートで実証予定。** worker marker→exit 抑止→fallback の結合は
  VFS＋worker＋DLL ハーネス（CI）。単体は route-away（`route_away_reason`/`bypass_runtime_of`/`contains_ascii_ci`）。
  出所: M8.2。

#### M8.2 security-reviewer 所見（opus, 2026-06-14, PASS-with-findings・BLOCK/HIGH 無し）
- **MEDIUM-1 解消（M8.2）。** 非 strict アクションの `cmd.env` に `SEMBAZURU_VFS_STRICT=1` を仕込むと DLL は
  strict 化するが worker は marker を見ず desync しうる問題。worker が `SEMBAZURU_VFS_STRICT` を**権威的に
  "1"/"0" で常時設定**（`SEMBAZURU_MODE` 等と同様）し、action 由来 env の上書きを封じた。出所: security(M8.2 MEDIUM-1)。
- **MEDIUM-2 解消（M8.2）。** `bypass_runtime_of` が dispatch 毎に argv0 全体を読む問題。(path,len,mtime)
  キーで verdict をメモ化（`RUNTIME_VERDICTS`）し、同一ツールチェーンの走査を 1 回に。スキャンは前置打ち切り
  しない（msys2 は route-away が唯一の安全網＝strict で捕捉不能のため完全走査を維持）。出所: security(M8.2 MEDIUM-2)。
- **LOW-1 繰延（観測性）。** strict fail した open は trace に記録されず、どのパスで fallback したかが追いにくい。
  `committedFailure` 前に RecordCreateFile を足せば改善（True*/再入契約は満たす）。安全性ではなく診断性。出所: security(M8.2 LOW-1)。
- **INFO-1 受容。** marker チェックは正常 exit 経路のみ（ceiling/cancel は元々 no-exit→fallback で同結果）。
  将来 timeout が合成 exit を出すようにする場合は marker チェックを回避しないこと。出所: security(M8.2 INFO-1)。

### M8.4 実装後のメモ（2026-06-14）
- **dxc -Qstrip_debug の決定性は determinism-checker で独立確認（解消）。** 連続・2 秒間隔（秒境界跨ぎ）・
  cross-dir の 6 ビルドが単一 sha256 に収束。clang-cl の COFF 壁時計タイムスタンプ相当の依存も埋め込み絶対パスも
  無く、非決定性は debug 情報（PDB）にのみ存在し `-Qstrip_debug` が除去。正規化フラグ不要。M8.4 ゲートは strip 済み
  成果物を比較。出所: determinism-checker(M8.4)、ADR 0007 付録。
- **署名付き DXIL は dxil.dll 同梱が前提（本番メモ・低優先）。** 検証環境（Vulkan SDK dxc）には dxil.dll が
  無く、コンテナ先頭ハッシュは dxc 内部のコンテンツハッシュ（決定的）。本番で署名付き DXIL を配布するなら
  dxc.exe の隣に dxil.dll を置く。M8.4 ゲートは ref vs distributed を同一 dxc で比較するため署名有無に非依存。
  Windows SDK の dxc は 3 点同梱（CI はこれを使用）。出所: determinism-checker(M8.4)。

### M8.x（実 2 台 LAN・決定者承認の別スコープ・繰延）
M8 の汎化作業（単機+RTT で実証）から分離。承認後に着手:
- **cwd=入力ルート崩れの cross-machine 実証**（M8.3 は単機で宣言ルートを実装、2 台での実証は M8.x）。
- **trace のデータプレーン返送**（単機共有 FS 前提＝`VfsExecution.trace_dir` の解消、ADR 0005/M6.1c 繰越）。
- **WriteBack の declared-output スコープ**（M7.1 繰越）。**authoritative root binding**（M7.1 HIGH-2）。
- 環境準備（実 2 台）と決定者承認が前提（M3 以来の方針踏襲）。出所: ADR 0007、AskUser(2026-06-14)。

## M9（配布物と常駐 UX）— ADR 0008 / 0010 / 0011 / 0012（ADR 0009 は撤回）

### M9.6 自己更新（ADR 0009）の撤回（2026-06-19）
ADR 0009（GUI 自己更新）はリード判断で **撤回（SUPERSEDED）**。更新は GitHub Releases の MSI を手動 DL して
入れ直す運用に変更（理由は ADR 0009 末尾「廃止」／ADR 0011 §背景）。撤回に伴い旧・自己更新繰延（publisher pin
差し替え・GitHub API レート制限・自動ロールバック・更新適用の実機一周）は **消滅**。残る関連繰延:
- **署名/実 OV cert は任意降格（機能 gate でない）。** 自己更新が消えたため署名は必須でなくなった。当面未署名で
  運用可（手動 DL は SmartScreen クリック）。実 OV cert（HSM）取得・実 Authenticode 署名は「公開配布で警告を
  消したい時のみ」。`installer/sign_release.ps1`／`.github/workflows/release.yml` は **手動配布用 MSI 発行**として
  保持。出所: ADR 0009 §廃止、ADR 0011 方針（2026-06-19）。
- **winget manifest の作成・winget-pkgs 提出は据え置き。** MSI が配布物の本体、winget はその配布チャネル
  （ADR 0008）。実 OV 署名後のリリース作業。出所: ADR 0008 §(1)。

### M9.6 版ゲート admission（ADR 0011）実装後の繰延（2026-06-19）
- **版一致を「完全一致」から semver 互換範囲へ緩める余地は据え置き。** 当面は決定性安全側に倒し完全一致のみ。
  出所: ADR 0011 §繰延。
- **混在クラスタの運用 UX（不一致ノード検知時に GUI から一括更新を案内等）は表示のみで開始。** ダッシュボードに
  `version-mismatch` 表示は実装済み。出所: ADR 0011 §繰延。
- **版基準を daemon 設定で固定/上書きする経路は据え置き。** 現状は agent 自身の `CARGO_PKG_VERSION` 固定。
  出所: ADR 0011 §繰延。

### M9.6 CPU 連動 admission（ADR 0010）実装後の繰延（2026-06-19）
- **`f()` の関数形・EMA 窓・ヒステリシス帯・reserve／floor 既定値の実 LAN チューニングは M10 送り。** 機構は M9.6
  で完成、定数は控えめな既定値（reserve 10%／hysteresis 10%／alpha 30%／floor 0%）で動作。実測チューニングは
  M10 実 LAN。worker config（`idle_cpu_*`）／`SEMBAZURU_IDLE_CPU_*` で調整可。出所: ADR 0010/0012 §繰延。
- **メモリ/IO 圧の admission 組み込みは据え置き。** `Capabilities.memory_bytes` は現状 0/未使用
  （`crates/worker/src/coordination.rs`）。需要が出たら CPU と同様に信号化（ADR 0012 の参加モードに信号を足す形）。
  出所: ADR 0010/0012 §繰延。
- **per-worker しきい値を GUI から編集する UI は据え置き（まずは表示のみ）。** M9.6 で idle CPU／実効容量／版／
  参加状態のダッシュボード表示は実装済み。編集 UI は需要次第。出所: ADR 0010/0012 §繰延。

### M9.6 worker 参加モード（ADR 0012）実装後の繰延（2026-06-19）
- **状態信号の拡張（memory/IO 圧・在席・時間帯）は拡張枠のみ確保し未実装。** 当面は idle CPU 信号のみ
  （スコープ膨張回避）。adaptive の入力として後から足せる構造。出所: ADR 0012 §繰延。
- **per-worker のモード/しきい値を GUI から編集する UI は据え置き（表示のみ）。** participation_mode／
  exclusion_reason のダッシュボード表示は実装済み。出所: ADR 0012 §繰延。
- **モードの live-reload は未対応。** 現状は worker 起動時に config を 1 回読む（変更は再起動で反映）。
  出所: ADR 0012 §繰延、config.rs（no live reload）。
- ※ ADR 0010 で「当面不要」としていた「一時停止/再開」は、ADR 0012 の `off`（完全不参加）／`always`（常時参加）
  として **実装済み**＝この繰延は消化。

### M9 完了の前提（リード実機ゲート・出荷ゲート）
- **実機 SCM 一周（daemon/worker：install→AutoStart→start→stop→uninstall・残骸ゼロ）、MSI の ACL/FW/PATH/
  初期設定の実機反映確認、アンインストール総合残骸ゼロ。** 実装は MSI（`installer/sembazuru.wxs` の
  `util:PermissionEx`／`FirewallException`／`Environment PATH`／seed-config）に済み＝残るは実機確認。
  出所: docs/handoff/lead-actions.md §1/§2、verifier(M9 audit 2026-06-19)。
- **実 OV cert（HSM）取得・実 Authenticode 署名・EDR 許可リスト提出は任意降格（ブロッカーでない）。** 自己更新撤回
  （ADR 0009）で署名は機能 gate でなくなった＝当面未署名で運用可（手動 DL は SmartScreen クリック）。公開配布で警告
  を消したい時のみ実施。CI は placeholder cert で署名「機構」のみ検証。出所: ADR 0006/0008/0011、lead-actions。

## 横断・既知の制約

- **MSVC ネイティブのバイト一致はベストエフォート（M4.5 で S_OBJNAME のみ正規化）。**
  M4.5 で `.debug$S` の S_OBJNAME（オブジェクトパス）を正規化し cross-dir の一阻害要因を除去。
  ただし実測で MSVC は絶対ビルドパスを**他にも**埋め込むため依然 cross-dir バイト一致しない。
  残る源（deferred、完全対応は ducible 相当の後処理）: (1) `.debug$S` 文字列テーブルの
  build-info cwd（S_BUILDINFO/LF_BUILDINFO 参照、/d1trimfile で消えない）、(2) /Brepro の
  content-hash Build ID（パス込み内容から算出のため S_OBJNAME マスク後も残る）、(3) 長さの
  異なるパスは S_OBJNAME のレコード長・オブジェクトサイズを変え、長さ保存のマスクでは
  一致不能。clang-cl が cross-dir 一致ゲートのまま（first-class）。MSVC はアクションキャッシュ
  を**同一パス rebuild**で活用（cross-dir/cross-machine 再利用はリモートパス正規化 or 上記
  残源の正規化待ち）。出所: determinism.md、実測(M4.5)、AskUser(2026-06-13)。
- **速度実測は単一マシン＋RTT エミュレーション。** 実 2 台 LAN は未実施（決定者承認の
  M3 方針）。RTT 注入は spin-wait（Windows タイマ粒度 ~15ms 対策）。出所: ADR 0002、
  AskUser(2026-06-13)。
- **dev-dep 循環 agent↔worker。** cargo は許容するが、どちらかを通常依存へ昇格すると
  壊れる。将来ハーネス crate を切り出す余地。出所: verifier(M3.5)。
- **Detours 上流凍結・Windows Update 追従。** フォーク保守は自分の責任。CI で継続検知
  （M7 に Windows マトリクス）。出所: CLAUDE.md / DESIGN §8。
