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

- **接続プール無し。** フックは redirected open 毎に新規パイプ接続、worker は hydrate
  毎に agent へ新規 TCP 接続。出所: vfs_pipe.rs / fileclient.rs 注、ADR 0002。
- **パイプライン化未活用。** wire は request_id で out-of-order 多重化に対応するが、
  クライアントは逐次。出所: fileclient.rs 注。
- **バッチ/先読み未実装:** StatBatch のヘッダ解決一括、DirList のディレクトリ先読み、
  ネガティブプローブ・キャッシュ（ディレクトリ membership fingerprint）、timestamp
  偽装（mtime 起因の再 fetch 回避）。BuildXL 由来。出所: m3-prestudy §3。
- **PrefetchHint（依存予測先読み）未実装。** v0 §4.1。出所: v0。
- **DirList の depth は直下のみ。** 深い先読みは未対応。出所: fileserver.rs 注。
- **トランスポート 3 者ベイクオフ未実施。** ADR 0002 は TCP 採用（QUIC/gRPC 未実装、
  prior と「TCP が判定基準を満たした」で繰り延べ）。WAN/ロス環境が要件化したら
  QUIC を再評価（`sembazuru-dataplane` のトランスポート境界に差し込む）。出所:
  ADR 0002、m3-prestudy §2。
- **フォールバック判定の閾値（レイテンシ予算タイマ・worker 死/分断タイマ）未調整。**
  M3.4 チューニング側。出所: v0 §7 #4、計画 M3.4。

## M7（堅牢化・セキュリティ）

- **データプレーン/制御プレーンに認証・TLS 無し。** worker の Execute、agent の
  ファイルサーバ（任意絶対パスを供給）、VFS パイプ いずれも無認証。v0 §5 が M7 と明記。
  出所: security(M3.1/M3.2)、v0 §5。
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

- **MSVC ネイティブのバイト一致はベストエフォート。** `.debug$S` の S_OBJNAME に絶対
  オブジェクトパスが埋まるため cross-dir で一致せず。clang-cl が一致ゲート（CLAUDE.md /
  determinism.md / 決定者承認）。MSVC を一致させるにはワーカーが同一論理パス
  （ドライブ・大小文字まで）でビルドする必要。出所: determinism.md、AskUser(2026-06-13)。
- **速度実測は単一マシン＋RTT エミュレーション。** 実 2 台 LAN は未実施（決定者承認の
  M3 方針）。RTT 注入は spin-wait（Windows タイマ粒度 ~15ms 対策）。出所: ADR 0002、
  AskUser(2026-06-13)。
- **dev-dep 循環 agent↔worker。** cargo は許容するが、どちらかを通常依存へ昇格すると
  壊れる。将来ハーネス crate を切り出す余地。出所: verifier(M3.5)。
- **Detours 上流凍結・Windows Update 追従。** フォーク保守は自分の責任。CI で継続検知
  （M7 に Windows マトリクス）。出所: CLAUDE.md / DESIGN §8。
