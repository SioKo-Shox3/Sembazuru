# 0014 — action key v2（弱/強キーの実行 identity 被覆と観測 vector の取り込み）

- ステータス: **一部実装（PARTIAL）。** 起案: 2026-06-24。決定者承認: 保留（プロジェクトリード）。
  出所: コードレビュー（COR-005／COR-004 残）。[ADR 0007](0007-arbitrary-process-distribution.md) §c の拡張。
  **実装済み（determinism-safe な部分集合＝key を「細かくする」だけ・false hit 不可・rebuild-hit ゲート不変）**:
  (1) のうち **cwd を weak key に追加**（COR-005 問題B＝cwd 埋込み false hit を閉鎖）、**weak-key schema
  version**（`WEAK_KEY_SCHEMA`＝key の意味が変わるたび bump で全 entry を一度 miss させる安全な migration
  レバー）、(1) **argv0 を agent 側で PATH 解決し解決先 binary の content digest を weak key に畳む**
  （`toolchain_digest`／`resolve_program`／memo `digest_file_memoized`。bare な cl/clang-cl の**同名更新**が
  従来は定数退化で stale hit していたのを invalidation 化。解決/読取不能は従来の name 定数へ **byte 不変 fallback**。
  per-TU 再ハッシュ回避に `(path,mtime,len)` memo＋**TTL 再ハッシュ安全網**＝mtime 保存・同一長 swap の stale を
  TTL 窓に bound）、(4) **ActionResult codec に magic+version**（問題4＝format drift を明示的に miss 化）。テスト:
  `weak_fingerprint_changes_with_meaningful_inputs`・`action_result_decode_gates_on_magic_and_version`・
  `record_and_resolve_agree_for_same_resolved_toolchain`・`toolchain_digest_hashes_resolved_binary_and_tracks_content`・
  `memo_rehashes_after_ttl_...`。`verifier`(opus) で反証検証済み。M4 gate（cache_cli→weak_key）が agent 側解決を自動検証。
  **未実装（determinism gate 連動・別環境/harness 要）**: (1) のうち **worker 再検証**（launcher が解決パス＋digest を
  request に載せ worker が実際に起動する binary を再 digest 照合＝heterogeneous クラスタで agent≠worker の別 cl を
  閉じる。proto field＋launcher＋worker 改修要）／build-commit id（build script）、(2) env profile 制（`VOLATILE_ENV`
  見直しは出力影響 env を取りこぼすと **false hit** になりうるため determinism harness で実証必須）、(3)
  registry/enumerate/RMW 前状態の key 取り込み or uncacheable 化。
  **受容残存**: agent 側解決は agent 上の binary を digest する＝heterogeneous で worker が別 cl を走らせる場合は
  今日の定数同様に衝突しうる（**不悪化**・worker 再検証で閉鎖）／memo の TTL 窓（mtime 保存＋同一長＋TTL 内）は
  ≤TTL の transient stale（永続化せず self-heal）。
- 決めること: action cache キーが**実行 identity と観測入力をどこまで被覆するか**。**(1) weak key の identity 拡張**、
  **(2) env policy（profile 制）**、**(3) 観測済み非 key vector の扱い**、**(4) codec 版管理**。
- 判定基準: 非交渉（**正しさ>速度**＝誤った cache hit を出さない／出力バイト不変／**determinism harness 緑**）。
  key 形変更は既存 cache 全 miss を招くが**安全側**（誤結果でなく再実行）。
- 関連: [ADR 0003](0003-cas-hash-and-chunking.md)（digest）、[ADR 0007](0007-arbitrary-process-distribution.md)（§b 出力宣言・§c 決定性 policy）、
  [ADR 0011](0011-version-gated-admission.md)（版ゲート）、`crates/cas/src/action_cache.rs`、
  `crates/agent/src/action_cache.rs`、`crates/tracer/src/{action_key,graph}.rs`、`crates/agent/src/scheduler.rs`。

## 背景

「任意 Windows プロセス」を対象にするには、現キーは実行 identity と観測入力の被覆が不足する（COR-005/COR-004）:

- **weak key**（`cas/action_cache.rs:58-83`）= `argv + 非volatile env + toolchain digest` のみ。`VOLATILE_ENV`(`:30-45`) に **PATH を含む**ため `PATH=A;argv0=cl` と `PATH=B;argv0=cl` が同一キーに衝突しうる。`toolchain_digest`(`agent/action_cache.rs:294`) は bare/読めぬ argv0 を `toolchain-name:{argv0}` 文字列に**退化**（binary 非検証）。**cwd・build/commit id を含まない**。
- **volatile 前提の綻び**: `TEMP/USERNAME/USERPROFILE/COMPUTERNAME/SESSIONNAME` 等を除外する根拠「miss 増のみ・false hit なし」は**コンパイラ専用の前提**。任意プロセスはこれらを出力に埋め込めるため false hit になりうる。
- **観測済みだが非 key の vector**: `graph` は registry 値・env・`Enumerate` membership・RMW(`OpenReadWrite`) 前状態を記録するが、`action_key.rs` は `graph.registry/env`/enumerate を**一切読まない**（strong key は `graph.inputs` の content/absent ＋ command line のみ）。RMW は `outputs.contains(&logical)` で input 側から落ち、**実行前内容が key に入らない**。
- **commit-blind 版ゲート**: [ADR 0011](0011-version-gated-admission.md) は `CARGO_PKG_VERSION` 完全一致のみ＝**同 version・別 commit** の binary を区別しない。repo に git-commit/build-id は皆無。
- **codec 版なし**（`cas/action_cache.rs:114-209`）＝format drift が decode-error→miss 依存。

### 実装前提（現状調査で確定）
- weak の単一組立点は `weak_fingerprint`／`weak_key`、policy 点は `VOLATILE_ENV`／`toolchain_digest`。strong の単一再計算点は `manifest_hash`、producer は `input_manifest`、分類点は `is_content_read`。観測 vector の取り込みは `input_manifest`/`manifest_hash` に **additive**。
- [ADR 0007 §c](0007-arbitrary-process-distribution.md) の「default-deterministic・mismatch で降格」は policy として**既決**＝本 ADR は coverage と key schema の拡張。

## 決定

### (1) weak key の実行 identity 拡張（key v2）
weak key に **解決済み exe 絶対パス＋content digest**（launcher が CreateProcess 探索規則で argv0 を解決し request に載せ、worker が**実際に起動する binary の digest を再検証**）、**cwd**、**build/commit id**（`vergen`/`built` で git commit を埋込→`Capabilities`＋weak key）を追加。bare argv0 の名前退化を廃する。

### (2) env policy ＝ profile 制
`cache_policy: off | verified | unsafe` を導入（任意プロセスの既定 `off`）。`verified` profile（clang-cl/MSVC/dxc）は許可 exe digest・許可 side effect・required trace coverage・env key policy・determinism flag を定義（[ADR 0007 §c](0007-arbitrary-process-distribution.md) の決定性ゲートと接続）。**profile 未指定アクションは全 env を key に含めるか uncacheable（fail-closed）**。`VOLATILE_ENV` の固定除外は verified profile 内に限定。

**実装メモ（9c56295 / COR-004）**: 既定 `off`／verified-only の記録ゲートは実装済み（`crates/agent/src/intake.rs` の record ゲート `&& tool_verified`）。ただし現実装の verified 判定は toolchain の **basename 一致**（`is_verified_tool`、`file_stem`・大小無視・`SEMBAZURU_VERIFIED_TOOLS` opt-in）であり「M2 で実証済みのバイナリ identity」そのものではない。homogeneous／LAN-trusted では健全: `.exe` の identity は weak_key の content digest（`crates/cas/src/action_cache.rs` `weak_fingerprint`）で固定され、中身の異なる同名 `cl.exe` は別キー化して既存 entry を汚染しない。残存（threat model 周辺）: argv0 が**実在ファイルに解決しない**場合（PATH 不在の素名等）、`toolchain_digest` は content-blind な name-constant に退化するため、name-verified だが未解決のツールは名前だけでキー化され得る（解決する場合は実在 `.bat`/`.cmd` を含め当該ファイルの content digest が weak_key に畳まれ安全＝`candidate_with_exe` は `.exe` 付与前に `is_file()` を拡張子非依存で判定）。heterogeneous の worker≠agent identity 閉鎖は **COR-005 worker 再検証**に委ねる。記録ポリシー厳格化（任意ツールを既定 non-record 化）に伴い `WEAK_KEY_SCHEMA` を v3 に bump し、旧ポリシー下で記録された任意ツール entry を一掃した。

### (3) 観測済み非 key vector
registry 値・enumerate membership・RMW 前内容を strong key に**畳む**か、それらに触れるアクションを **uncacheable**（fail-closed）。`is_content_read` を拡張し、enumerate/registry を「key 化できなければ無キャッシュ」に倒す（[ADR 0007 §b.3](0007-arbitrary-process-distribution.md) を入力側へ拡張）。

### (4) codec 版管理
action-cache codec（weak/strong/result）に **magic＋schema version＋limit** を付与。version 不一致は miss（format drift を明示的に無効化）。

## 影響

- `crates/cas/src/action_cache.rs`（weak_fingerprint・codec 版）、`crates/agent/src/action_cache.rs`（weak_key・toolchain 再解決/再検証・cwd）、`crates/tracer/src/{action_key,graph}.rs`（観測 vector 取り込み・is_content_read 拡張）、`crates/agent/src/scheduler.rs`／`Capabilities`（commit/build-id）、launcher（exe 解決）、build script（`vergen`/`built`）。
- 検証: **determinism harness 緑が最重**（key 形変更で既存 cache は全 miss＝安全だが、env/cwd 取り込みが出力影響 env を取りこぼさない実証が要）。PATH 違い同名 exe で別 key／cwd 違いで別 key／TEMP/USERNAME を出力に埋めるプローブが false-hit しない／agent-worker toolchain 不一致検知／同 version・別 commit で別 key／未知 exe は既定 cache off。`verifier`(opus)＋`determinism-checker`。

## 繰延・未決

- 完全 normalized env の監査済み除外リスト（verified profile の env policy 詳細）。
- registry/enumerate の **membership fingerprint** 化（取り込み vs uncacheable のどちらを既定にするかは profile 単位で決める）。
- cross-machine 出力パス整合（[ADR 0007](0007-arbitrary-process-distribution.md)・M8.x）。
- **規模が大きく determinism 連動が最重ゆえ、実装は C1/C3/C4 の後**。
