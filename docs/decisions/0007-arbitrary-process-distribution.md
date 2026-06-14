# 0007 — 汎用プロセス分散レイヤー（M8）: 未仮想化アクセス検知・出力宣言・非決定性ポリシー

- ステータス: **決定済み（ACCEPTED）。** 起案: M8.0、2026-06-14。決定者承認: プロジェクトリード、2026-06-14
  （(a) 二段検知＝route-away＋worker fail-closed、(b) 出力宣言は任意・宣言>trace>無キャッシュ、
  (c) 分散とキャッシュを分離、で承認）。
- 決めること: `docs/DESIGN.md` §7 M8 と「Done when（コンパイル以外のワークロードが専用対応なしに
  そのまま分散される）」、§8（横断的懸念）、§10（勝ち筋＝信頼性＋価格引き下げ）が M8 に委ねた、
  **(a) 未仮想化アクセスの検知→ローカルフォールバックの方式と粒度**、**(b) 任意プロセスの出力宣言
  メカニズム**、**(c) 非決定的ワークロードのキャッシュ／分散ポリシー**。
- 判定基準: 正確性 > 速度（非交渉 #1）、ローカルフォールバック常時（#2）、UBA コード非取り込み（#3）、
  clang-cl ファーストクラス（#4）、そして **無設定（ゼロコンフィグ）の堅持**（DESIGN §2・§10 の差別化軸）。
- 関連: ADR `0001-vfs-approach.md`（案 A の既知の穴・検知メカニズムは M3 設計項目と明記）、
  `0005-build-system-interception.md`（LocalIntake・declared_outputs）、`0006-trust-and-auth.md`（LAN-trusted）、
  `docs/protocol/v0.md` §3.2/§4.1/§5、`docs/deferred.md`（M3.x 未仮想化検知・M6.1 出力推論）。

## 背景

M0–M7 は「無設定 clang-cl 分散ビルド」を確立したが、経路の随所にコンパイラ前提が焼き込まれている
（出力推論の `/Fo` ハードコード、weak key の `VSCMD_*` 限定、fileserver の read-only 入力前提、
`vfs_root = cwd`）。M8 はこれを汎用プロセス分散レイヤーへ引き上げる。最大の論点は **正しさ**である。

### 不可避の制約（ADR 0001 の帰結）

採用済みの案 A（ユーザーモードフック）は、フックされていない I/O を**原理的に観測できない**。
直接 Nt/Zw syscall（msys2/Cygwin 丸ごと、BuildXL #680）、ntdll 静的リンク、breakaway 子、
オープン後のメモリマップは、フック層をすり抜ける。コンパイラ（cl/clang-cl/dxc）はこの穴を踏まないため
顕在化していないだけで、**任意プロセスでは顕在化する**。ADR 0001 §110-113 はこれを「正しさの欠陥ではなく
**検知してローカルフォールバック**で扱う／検知メカニズムは M3 の設計項目」とした。M3 では安全側
（リモート失敗→アクション全体ローカル再実行）のみ実装し、検知器本体は `docs/deferred.md` M3.x に繰り越した。
**本 ADR でその検知器を設計する。**

重要な認識: **user-mode では「見えなかった read」を事後に救えない。** よって検知は「すり抜けた瞬間に
気づく」ことではなく、①すり抜けが確実なプロセスを**最初からリモートに出さない**、②リモート実行中に
**供給できないものを黙ってローカルで代替させない**、の二段に分解される。これは BuildXL が Nt/Zw 直接
呼び出しを観測できない（#680）のと同じ制約を引き継ぐ、誠実な設計である。

## 決定

### (a) 未仮想化アクセス検知 → ローカルフォールバック（二段機構）

**① route-away スクリーン（リモート投入前・agent 側）.**
すり抜けが確実／高確度なプロセスクラスを、`Scheduler::dispatch` の手前で**リモートに出さずローカル実行**へ回す。
判定はプロセス属性ベース（syscall パターン検知は user-mode で原理的に不完全のため**採らない**）:

- **msys2/Cygwin ランタイムリンク**（`msys-2.0.dll`/`cygwin1.dll` への依存）= route-away 確実（#680）。
- **denylist**（既定に既知バイパスツールを収録、`SEMBAZURU_LOCAL_ONLY` 等で追加可能）。
- **breakaway を要求する起動**（`CREATE_BREAKAWAY_FROM_JOB` 等、Job/注入を脱出する意図）。

誤検知時の安全側は**常にローカル**（非交渉 #2）。route-away は「分散の機会損失」を生むが「誤ビルド」は
生まない。判定は保守的に倒す（疑わしきはローカル）。

**② worker 側 fail-closed（リモート実行中・hook 層）.**
現 `hooks/src/interceptor.cpp` の `VfsTryRedirect`（L319-355）は二つの「handled=false」を返す:
(i) パスが vfs_root 配下でない（L327）→ SDK/system ファイル＝ローカル open が正しい、
(ii) vfs_root 配下だが hydrate 失敗（L331-332）→ 呼び出し側 `HookedCreateFileW`（L568-573）が
**TrueCreateFileW で実ローカルパスを開く（silent fail-open）**。

(ii) はコンパイラ（ソース同居）では同一バイトを読むため無害だが、**ソース非同居の worker では誤読**になる
（`docs/deferred.md` M3.x「per-file 暗黙ローカルフォールバックの隠れた危険」）。
**汎用モードでは (ii) を是正する**: vfs_root 配下で供給不能なパスは**ローカル open に落とさず**、
アクションを FAILED（明示シグナル）にして agent がアクション全体をローカル再実行する。
(i) は従来どおりローカル open（正しい）。両者を区別するため `VfsTryRedirect` から第三の結果
（under-root-but-unsupplied）をスレッドする。

**clang-cl/cl/dxc 既存ゲートを壊さない**ため、コンパイラ互換の fail-open 挙動は維持し、fail-closed は
**新モード（汎用モード）でのみ**有効化する（既定の単機モデルは現状維持）。

**③ breakaway 子の注入検証.** `CreateProcess` フック時に子への DLL 注入成立を検証し、未注入の breakaway 子は
未仮想化シグナルとして ② と同じ安全側へ倒す。

**④ mmap 観測.** `CreateFileMapping`/`MapViewOfFile` を観測対象に追加。redirected handle 上の mapping は安全
（hydrated copy を見る）、非 redirect パスの mapping は未仮想化シグナル。**最小限・観測優先**で EDR シグナルを
増やさない（M7 の署名・許可リスト申請の steady-state 挙動に新 TTP を加えない方針＝`docs/deferred.md` M7）。

### (b) 任意プロセスの出力宣言メカニズム（宣言は任意・ゼロコンフィグ堅持）

優先順位を固定する:

1. **外部供給 declared_outputs**（既存・`SubmitActionRequest.declared_outputs` field 2）。ビルドシステム統合・
   launcher 引数・env が宣言を渡せる場合はそれを採用。最も正確。
2. **trace ベース出力発見**（観測した write/rename から事後構築、BuildXL two-phase 思想）。`infer_outputs` の
   `/Fo`/`.obj` ハードコード（`sembazuru_launcher.rs` L31-65）を脱コンパイラ化し、宣言が無い場合の既定経路に。
3. **推論不能なら無キャッシュ**（安全側・現挙動維持）。`crates/agent/src/intake.rs` の「declared_outputs 非空時
   のみ record」ガードを踏襲し、出力が確定しないアクションは**キャッシュしないが分散はする**。

**宣言は必須にしない。** Bazel/BuildXL は宣言必須だが、それは Sembazuru の差別化軸（無設定）を壊す。
宣言なしでも分散は成立する（フックが write を観測し収集する）＝ Incredibuild 対抗のゼロコンフィグを死守する。
宣言があればキャッシュ精度・収集完全性が上がる「高速パス」として位置づける。

### (c) 非決定的ワークロードのキャッシュ／分散ポリシー（分散とキャッシュを分離）

Bazel 標準に倣い、**分散実行**と**結果キャッシュ**を独立概念として扱う:

- **決定的プロセスのみ action cache 対象**。determinism ゲート（M2、非交渉 #1 の品質ゲート）は
  決定的ワークロードにのみ適用する。
- **非決定的プロセス（テスト等、出力 byte 一致が成立しない）は分散可・キャッシュ不可**として明示分離。
  remote 実行は通すが `record` をスキップ（毎回実行）。
- アクションの決定性は既定で「決定的」と扱い、determinism 検証の不一致 or 既知の非決定フラグで「非決定」に
  降格する。降格したアクションはキャッシュから外れるだけで、分散とローカルフォールバックは従来どおり。

これにより非交渉 #1（正確性 > 速度）と determinism ゲートが汎用ワークロードと整合する:
**キャッシュ汚染を構造的に防ぎつつ、テスト分散という差別化（DESIGN §10）への道を開く。**

## 実証ワークロードと範囲（決定者承認済み、2026-06-14 AskUser）

- **最初の証明ワークロード = dxc（HLSL シェーダー）。** MIT OSS・単一プロセス・子なし・3 ファイル配布
  （dxc.exe/dxcompiler.dll/dxil.dll）・`#include` 解決で VFS の真価を示す・CI 導入容易。
- **実 2 台 LAN は M8 で要件化しない。** 単機+RTT で汎化を実証し、cross-machine 固有（cwd=入力ルート崩れの
  実証／trace のデータプレーン返送／WriteBack の declared-output スコープ／authoritative root binding）は
  **決定者承認の別サブマイルストーン M8.x** に切り出す（M3 以来の方針踏襲）。

## 付録: dxc 決定性の実測（M8.0、2026-06-14、ローカル）

環境: `dxcompiler.dll 1.9 - 1.8.0.4806 (75a029d95)`（Vulkan SDK 1.4.309.0 同梱）。Windows 11。
※ローカルは機構確認。CI（windows-2022/2025）での再実測は M8.4 ゲートで担保する。

| 実測 | コマンド（要点） | 結果 |
|---|---|---|
| 同一ディレクトリ 2 回ビルド | `dxc -T ps_6_0 -E main -Qstrip_debug -O3 -Fo {a,b}.dxil tri.hlsl` | **byte 一致（2892 B、a==b）** |
| cross-dir 2 ビルド（別絶対パス・`#include` 解決あり） | 同フラグを D1/D2 で実行 | **byte 一致（cross-dir でも同一）** |
| `#include` 解決の観測 | `dxc ... -Vi` | `Opening file [./common.hlsli]` ＝ stat/open が出る（VFS 対象） |

**所見:** dxc は `-Qstrip_debug`（＋固定フラグ・同一版）で **同一ディレクトリ・cross-dir ともに byte 一致**。
MSVC（絶対ビルドパス埋め込みで cross-dir 不一致、`docs/deferred.md` 横断節）や clang-cl（COFF 壁時計
タイムスタンプで `/Brepro` 要、`docs/deferred.md` M6.1）より**正規化要件が軽い**。DXIL コンテナの HASH part は
内容由来（壁時計タイムスタンプではない）と見られ、本実測でも時刻差由来の差分は観測されなかった。
→ dxc は M8.4 で **(c) の「決定的」分類**に入り、action cache 対象として実証できる見込み。
残確認: CI ランナーでの再現・時刻を空けた spaced build での timestamp 非依存の再確認（M8.4 ゲートで実施）。

## 影響

- `docs/DESIGN.md` §7 M8 を「route-away＋worker fail-closed の二段検知／宣言任意の出力発見／分散・キャッシュ
  分離」で具体化。Done-when は「専用対応なしに分散」＝ dxc 分散成立（M8.4）で満たす。
- `docs/protocol/v0.md`: 必要なら宣言入力ルート・非決定フラグを **§6 versioning（capability flag、非破壊追加）**で
  足す。§3.2 の declared_outputs と §4.1 の op セットは機構非依存のまま流用。
- `docs/deferred.md`: M3.x「未仮想化検知器未実装／per-file 暗黙ローカルフォールバックの危険」を本 ADR の
  ② で解消する旨を着手時に更新。cross-machine 固有項目は M8.x として明記（継続繰越）。
- 非交渉 #4（clang-cl ファーストクラス）: 汎用 fail-closed は新モード限定で、既存 clang-cl バイト一致ゲートは不変。

## 未決・繰延（本 ADR の射程外）

- **route-away denylist の初期収録範囲**と Go/Git-for-Windows の扱い（実測 or 保守的 denylist）— M8.2 実装時に確定。
- **authoritative root binding**（M7.1 HIGH-2、worker-declared root の widen 受容）— ゼロトラスト方向で M8.x。
- **実 2 台 LAN の分散・writeback・trace 返送** — 決定者承認の M8.x。
