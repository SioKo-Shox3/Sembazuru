# 繰り越し事項・既知の制約（バックログ）

M3 までで「後回し」「事後判断」「ベストエフォート」とした項目を一箇所に集約する。
各項目は **何を / なぜ繰り越したか / 出所** を記す。詳細は各リンク先。担当
マイルストーンごとに整理（M3 の Done-when は阻害しない＝意図的な繰り越し）。

> 更新ルール: 着手・解消したら当該行を消すか「解消（コミット）」を付す。新たな
> 繰り越しが出たらここに足す。レビュー（verifier/security-reviewer）の指摘で
> 繰り越したものは必ずここへ。

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
- **WorkerTable は単調増大（reaper 無し）。** worker 再起動は pid 違いで別エントリ化し、旧エントリは
  dead_timeout で live フィルタから外れるが map からは消えない。セッション境界の eviction は
  deferred #8（M5.3）と併せて対応。出所: verifier(M5.1 B2)、deferred #8。
- **可用性の単一障害点（LAN 前提で許容）。** WorkerTable の `std::sync::Mutex` poisoning 時に
  `.expect` で Coordination 全体が落ちる。heartbeat ハンドラの pong 送信は half-open 時に
  HTTP/2 keepalive timeout(10s) まで滞留しうる（リークではない）。M7 の堅牢化で sanitize。
  出所: verifier(M5.1 B3/B4)。

### M5.2 実装後の既知の残リスク（security-reviewer 2026-06-14、詳細は ADR 0004 追補）
- ~~**無認証 Register による誤結果注入／アクション吸引。**~~ **M7.0 で緩和（ADR 0006）。** 共有
  トークンを持たない worker は Register/データプレーンとも拒否されるため、無認証の rogue worker が
  登録して誤結果を返す／アクションを吸引する経路は閉鎖。トークンを持つ trusted worker のバグ/誤設定は
  残（capacity 申告は依然 clamp(1,256) で正しさを担保）。出所: security(M5.2 M3)、ADR 0006。
- **孫プロセスの孤児。** `kill_on_drop` は直接の子のみ。Job Object でツリー一括 kill は M7 サンドボックス。
  出所: security(M5.2 L3)。
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
- **ローカルフォールバックの .obj は clang-cl で参照とバイト一致しない（残差・要調査）。** distributed（worker・
  launcher 注入・env_clear）と参照（非 tty）は一致するが、`run_local` フォールバック（launcher 直 spawn・継承 env）は
  同一 source/cwd/非 tty にも関わらず参照と clang-cl バイトが一致しない残差がある。機能的には正当な .obj で、M6
  Done-when（フォールバックは「完了」）は満たす。ゲートはフォールバックを「exit 0＋非空 .obj」で検証し、バイト一致は
  distributed＋cached に限定。run_local の起動条件（env レイヤリング/PATH 解決の clang-cl 差）を要調査。出所: CI(M6.1)。
- **m6_daemon_compile の distributed/cached バイト一致が CI 実行間でフレークする（要調査・正確性寄り）。**
  同一コミット e26eeb2 が m6/daemon-launcher 実行では success、main 実行では同一ステップ「M6.1 daemon compile
  (byte-identical)」で failure（distributed/cached とも参照不一致）。コード非依存＝daemon 経路のバイト一致が
  run 間で非決定的。下位の vfs_compile.ps1（clang-cl バイト一致）と m4_cache_rebuild は同 run で PASS のため、
  差は launcher→daemon→worker 経路（env レイヤリング/トレース/タイミング）に局在。M7.0 の auth 変更は無関係
  （Rust ジョブ・下位ゲートは PASS、auth=off は M6 と wire 一致）。determinism 非交渉事項に関わるため M7 で
  原因特定（run_local 残差 [上記] と同根の可能性）。それまで本ゲートのバイト一致はフレーク扱い。出所: CI 実測
  (run 27488952841/27487941501 比較、2026-06-14)。
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
- **launcher の full-env 転送：LAN 分割の直前が今。** M6.0 LOW（開発者シークレットの off-box）の「リモート到達前に
  allowlist 検討」のチェックポイントは M6.1 で到来。単機 loopback では未流出（intake loopback ロック）だが、
  実 2 台 LAN を入れる前に env allowlist を必須化する。worker 側 env_clear は worker 内部 var の漏洩を防ぐ正の効果。
  出所: security(M6.1 Low、M6.0 LOW の再タグ)。
- **per-action scratch/trace ディレクトリの無制限増加（disk DoS）。** in-flight 資源（pipe/job/task）は admission で
  有界かつ終了時清掃。だが worker の hydrated scratch（`lib.rs` 注: M3.3/M7）と daemon の per-action `trace-{n}`
  （`SEMBAZURU_TRACE_ROOT` 下）はビルド毎に残置・累積。長寿命 daemon/worker で disk 枯渇。セッション境界 eviction
  （deferred #8）と併せ M7。出所: security(M6.1 Low)。
- **注入が production コンパイル経路に。** worker の DLL 注入（launcher.exe＋DetourCreateProcessWithDll）は M3 と
  同一機構だが、M6.1 で**テスト足場でなく常時動作**に。新たなマルウェア的シグナル（RWX/直接 syscall/スレッド
  注入）は無く署名可能。M7 のベンダ許可リスト申請は steady-state の挙動（injector が cl.exe を子に注入）を明記。
  出所: security(M6.1 Info)、deferred EDR メモ。

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
- **agent fileserver のパススコープ無し。** 要求された任意絶対パスを読む。M7 で
  セッション宣言ルートに限定。出所: security(M3.2 F2)。
- **DLL が worker 返却パスを scratch 配下かのみ検証。** 完全なパススコープ／
  `SEMBAZURU_VFS_SCRATCH` 検証の拡張は M7。出所: security(M3.2)。実装済み: scratch
  配下チェック＋scratch 配下 open の非リダイレクト（anti-recursion）。
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
- **エラー詳細の情報漏洩:** spawn/rename 失敗の Display や FAILED detail が worker 側
  パスを露出。信頼境界が変わる M7 で粗いコードに sanitize。出所: security(M3.1)。
- **32/64bit 双方の DLL。** 子プロセスのビット跨ぎ注入に両 bit の interceptor が要る
  （現状 64bit のみ、命名規約は 32bit を予期済）。出所: trace-format §8、BuildXL。

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
