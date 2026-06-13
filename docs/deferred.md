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

- **スナップショット一貫性が簡略。** agent fileserver は OpenRead 時に digest を計算し
  セッションキャッシュするだけ（初回タッチ前のローカル編集は未ガード）。完全な
  「セッション開始時点の fs を digest ピン留め」は未実装。出所: fileserver.rs M3.2 注、
  v0 §4.1。M4 の CAS と併せて設計するのが自然。
- **ワーカーローカルキャッシュ未実装。** 一度見たヘッダ/SDK を再送しない仕組み（M4
  Done-when の核）。現状 hydrate 毎に agent から全取得。出所: DESIGN §7 M4、v0 §4.1
  「worker-local cache consulted first, M4」。
- **CAS の重複排除・`Has(digests[])` バッチプローブ未実装。** 転送前に既存 digest を
  一括確認（v0 §4.3）。出所: v0 §4.3。
- **ハッシュ方式とチャンク戦略が未決。** 現状は std-only SHA-256（tracer の `sha256_hex`）
  を digest-as-identity に流用。候補 BLAKE3、固定 vs content-defined チャンクを実データで
  決める。出所: v0 §4.1/§4.3/§9、DESIGN §9。
- **アクションキャッシュ未実装。** 入力ハッシュ→出力。同一コンパイルをスキップ。
  土台は `verify-determinism --json` が出す入力ハッシュ→出力ハッシュ写像
  （determinism.md「Input-hash → output-hash mapping」）。鍵に command line＋env＋
  入力 digest 集合を含める設計。出所: DESIGN §7 M4、determinism.md。
- **WriteBack は単一メッセージで全量送信。** 大出力向けのチャンク化は未実装（CAS の
  チャンク戦略と整合させる）。出所: ops.rs WriteBack 注。

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
