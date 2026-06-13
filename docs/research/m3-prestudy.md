# M3 事前実測ノート（M3.0）

- 整理日: 2026-06-13。一次ソースから証拠を収集（確度を本文に注記）。
- 位置づけ: DESIGN.md §7 M3 と ADR `0001-vfs-approach.md` §113 が「M3 設計前に実施」と
  指定した実測の結果。**M3.1.5（NT 層フック範囲）の設計凍結はこのノートに依存する。**
- 委譲: researcher（sonnet）3 体に分担。本ノートは要約と、そこから導く決定のみを記す
  （生ログはセッション履歴）。

このノートが確定させる 3 点:
1. cl/clang-cl/link/lld が直接 Nt* syscall を撃つか → **必要な NT フックの最小集合**。
2. データプレーン・トランスポートの**事前期待**と**ベンチ方法論**。
3. ワーカー側のオンデマンド供給・サンドボックス設計の**取り込み方針**（MIT/Apache のみ）。

---

## 1. 実測2 — 直接 Nt*/Zw* syscall 調査（対象: MSVC/clang-cl）

対象ワークロードは MSVC `cl`/`link` と clang-cl/`lld-link`。msys2/Cygwin は ADR 既知の穴で
対象外。

### 確定した経路
- **読み取り open/read:** `kernel32!CreateFileW → kernelbase → ntdll!NtCreateFile` の多段 thunk。
  UCRT `fopen` も内部で `CreateFileW` 経由（UCRT ソースで確認）。コンパイラ本体の読み取りは
  Win32/UCRT 経由で **Win32 フックで捕捉可能**。確度: 中（import 直接 dump ではなく CRT ソース
  ＋構造推論）。
- **ディレクトリ列挙:** `FindFirstFileEx` は内部で `NtQueryDirectoryFile(Ex)` を呼ぶ。Win32 フックは
  呼び元を捕捉するので**漏れない**（Nt フックと重複するだけ）。一部ツールが直接 `NtQueryDirectoryFile`
  を撃つ例は BuildXL #680 で確認（対象コンパイラでは未確認）。確度: 中。
- **出力 temp→rename（最重要動機）:** clang/lld は `<name>-<rand>.tmp` に書いて
  **`NtSetInformationFile(FileRenameInformation)`** で最終名へ、delete-on-close は
  **`FileDispositionInformation`** を直接撃つ（LLVM `Path.inc` の `sys::fs::rename` Windows 実装で
  確定、determinism.md 既述）。**Win32 `MoveFile`/`ReplaceFile` をバイパスするため Win32 フックでは
  不可視。** 確度: 高（LLVM ソース＋tup ML＋本リポ determinism.md）。MSVC `cl`/`link` が
  temp+rename するかは**未確認**（確度: 低）。

### 残不確実性（M3.1.5 設計凍結前に潰す）
1. **`cl.exe`/`link.exe` の ntdll import 実機 dump**: `dumpbin /imports cl.exe | findstr ntdll`。
   残る最大の不確実性。→ **M3.1.5 着手時に本スレッドで実機確認する。**
2. **`mspdbsrv.exe`**: PDB 書き込みは別プロセス＋共有メモリ（section object）の可能性が高い。
   PDB は M2 で既に scope 外だが、CI 影響があるため「別プロセスをどう扱うか（注入 or 監視 or
   無視）」を M3.2/M3.3 の決定項目として立てる。
3. **`NtQueryDirectoryFileEx`**: Win10 2004+ で `FindFirstFileEx` が内部移行しつつあり、BuildXL も
   フック対象。NICE-to-have として対応推奨。

### 決定: M3.1.5 で実装する NT フック最小集合
**MUST（cl/clang-cl の read+enumerate+rename 正確観測に必須）:**
- `NtCreateFile` — clang/lld の temp open、Win32 フック漏れ補完。
- `NtOpenFile` — NtCreateFile 短縮形（BuildXL は両者を単一実装で扱う）。
- `NtSetInformationFile` — **clang/lld の atomic rename と delete-on-close。M3 の最重要動機。**
- `NtQueryDirectoryFile` — FindFirstFileEx 内部経路＋直接呼び出し防衛。

**NICE-to-have（既知ギャップ観測・フォールバック判断用、余力で）:**
- `NtQueryDirectoryFileEx`、`NtQueryAttributesFile`/`NtQueryFullAttributesFile`。

**不要:** `NtReadFile`（ReadFile→NtReadFile thunk を Win32 で捕捉済み。直接呼び出し証拠なし）。
**スコープ外:** `NtCreateSection`/`NtMapViewOfSection`（mspdbsrv/PE loader 用、M3 範囲外）。

> M3.1.5 は**観測のみ**（True* 先行→記録→結果不変）で上記を追加し、`determinism.ps1` から
> `--output` 回避策を外して pass することを Done-when とする（NT rename が見えれば不要、
> determinism.md 112-136）。これで trace-format §8 ギャップを解消する。
>
> **EDR/M7 メモ:** ntdll エクスポート（NtSetInformationFile）のインラインフックは Win32 フック
> より強いマルウェアシグナルになる（ntdll は syscall 境界で、EDR/マルウェア双方が使う手口）。
> ただし RWX/直接 syscall/スレッド乗っ取り等の TTP は無く、文書化された Detours 経路のまま。
> M7 の署名・許可リスト申請で「DLL は ntdll!NtSetInformationFile をインラインフックする」旨を
> 明示する（ベンダ説明で不意打ちにしない）。

主要ソース: BuildXL DetouredFunctions.h/.cpp、BuildXL #680、LLVM D38570、tup-users ML、
UCRT fopen.cpp、s-schoener.com (FindFirstFile internals)、eternalnop (Win32 callstack)。

---

## 2. データプレーン・トランスポート（事前期待＋ベンチ方法論）

判定は M3.5 の自前ベンチ（→ ADR 0002）。本節はベンチを形作る証拠と事前期待。

### 証拠
- **HOL ブロッキングはロスの関数。** ロスほぼ 0 の LAN では TCP 再送がほぼ起きず、QUIC の HOL 優位は
  測定上ほぼ消える（HOL ratio は WAN ロス条件の値）。確度: 中（lossless LAN の小ファイル多重化
  実測は未発見）。
- **quinn on Windows は不安定要素あり。** USO/URO（WSASendMsg/WSARecvMsg）対応はあるが、Firefox が
  Windows で USO 有効化→パケットロス増→ロールバック（Mozilla #1979279）、quinn #2041 で Windows GRO
  バグ。オフロード無効時は 1 datagram=1 syscall に退行。確度: 高（バグレポート一次）。
- **Windows userspace UDP コスト。** 通常 UDP は 1 datagram=1 syscall。QUIC は userspace 暗号＋ACK で
  Fastly 計測ではスループット約 40%。小メッセージ多重化で相対的に重い。確度: 中。
- **batch-first が根本解。** Bazel "Build without the Bytes"（bulk Has() プローブで往復集約）、
  BuffetFS（open のローカルキャッシュで 70% 高速化＝ネガティブプローブ・バッチの効果）が裏付け。
  ROT は「往復数 >> HOL」。確度: 高。
- **gRPC 小メッセージ:** HTTP/2 フレーム 9B＋HEADERS/DATA。数百 B 以下で 10–50% オーバーヘッド。
  参照点 1 つで十分、勝者候補に非ず。
- **RTT エミュレーション:** **clumsy は loopback 不可（WinDivert 制限）。** Windows QoS も loopback
  バイパス。→ **フレーミング層の in-process 遅延 shim** が最も再現性・公平性が高い（TCP/QUIC に
  同一遅延注入）。syscall コストまで含めた公正比較が要るなら同一ホスト 2VM＋shaping。

### 決定: ベンチ方法論（M3.5）
- 候補: **TCP+独自フレーム（基準＝有力）**、QUIC（quinn）、gRPC（参照点 1）。
- 遅延注入は **in-process shim** で 0.1/0.5/1.0ms スイープ、全候補に同一適用。**判定は遅延注入値**
  （loopback 生値は TCP を不当に有利にするので参考のみ）。
- 公平化: op ストリームを 1 度記録→同一遅延・コールドキャッシュで 3 候補に**同一リプレイ**。
- メトリクス: wall-clock＋**往復数/コンパイル**＋p50/p99 op＋on-wire バイト＋stat:open 比。
- ワークロード: `<windows.h>`/STL 多用ヘッダで数百〜数千の stat/open（負プローブ込み）。
- **事前期待（測定で確認する前提、結論ではない）: lossless LAN では TCP+独自フレーム
  （batch-first 込み）が最有力。** QUIC は M5 以降の広域・ロス環境で再評価。
  → **M3.2 は TCP+独自フレーム基準線で着手して妥当。**

主要ソース: Mozilla #1979279、quinn #2041、quinn-udp docs、Fastly QUIC vs TCP、Bazel BwoB、
BuffetFS (arXiv:2110.13551)、gRPC PROTOCOL-HTTP2、clumsy README/WinDivert。

---

## 3. オンデマンド供給・サンドボックス設計（取り込み方針）

ライセンス: **取り込みは MIT の BuildXL / Apache の REAPI 設計のみ。UBA は clean-room・設計観察のみ
（コード非取り込み）。IncrediBuild は公開ドキュメントの設計レベルのみ。**

### 実証された設計（3 系が hydrate-to-disk に収斂）
- **materialization:** BuildXL=実行前に全入力を digest 指定で eager 取得（`MaterializeInputs`）。
  UBA/IncrediBuild=**レイジー**（open 横取り→fetch→scratch に実体化→パス置換）。**我々の
  hydrate-on-open＋論理パス鏡像は IncrediBuild/UBA 方式そのもので、実験ではなく実証済み。**
  確度: 高（IncrediBuild 公開ドキュメント）。
- **往復削減:** ①**DirList をディレクトリ粒度で先読み**（ディレクトリ内初回 open で全エントリの
  名前＋サイズ＋digest を返し、以降の stat はローカルマップから）→ O(往復) を O(ディレクトリ) に。
  ②**ネガティブプローブ・キャッシュ**（不在 stat をディレクトリ membership fingerprint で記憶、
  fingerprint 不変なら再問い合わせしない＝BuildXL Search-Path Enumeration）。③**digest をキーに
  し timestamp は偽装**（mtime 起因の再 fetch を防ぐ＝BuildXL Timestamp Faking）。
- **子プロセス継承:** `DetourCreateProcessWithDll` で子に再注入。**セッション ID を env で伝播**、
  **32/64bit 双方の DLL を初日から**（cl→link は子プロセス、BuildXL も両 bit 対応）。
- **出力フェンス＋アトミック公開:** 実行前に宣言出力を pre-scrub＋宣言外パスへの書込みをブロック→
  成功時に staging→（M4 で CAS upload）→atomic rename→**完了報告**。失敗時は成果物を残さない。
  REAPI も「CAS upload 完了後に ActionResult を書く」二相コミット。
- **スナップショット一貫性:** **digest ピン留め**（copy-on-read ではない）。実行開始時に digest 確定、
  途中のローカル編集は実行中アクションに影響しない。
- **未検知アクセス:** BuildXL は違反として pip を fail（#680 は未解決）。**我々は「検知→ローカル
  フォールバック」**（非交渉事項 #2）。逃げたプロセス識別子をログ。

### 決定: M3 への取り込み
- hydrate-on-open＋論理パス鏡像（確定）。scratch ツリー寿命は **M3 単一アクションは per-action で開始**
  （正しさが単純）。per-session 再利用（SDK ファイル再 fetch 回避）は M4 のキャッシュと併せて検討。
- DirList ディレクトリ先読み＋ネガティブプローブ・キャッシュ＋timestamp 偽装を M3.2/M3.5 で実装。
- 子注入の env セッション伝播＋32/64bit を M3.2 設計に明記。
- 出力フェンス＋staging→atomic rename を M3.3 に明記（CAS upload は M4）。

主要ソース: BuildXL Distributed-Builds/Sandboxing/Two-Phase-Cache/Search-Path-Enumeration/
Timestamp-Faking/PipExecutor、Detours wiki、IncrediBuild Process Virtualization、Epic UBA docs
（設計観察のみ）、REAPI spec。

---

## 4. M3 計画への反映（差分）

- **M3.1.5:** NT フック MUST 集合を上記 4 つに確定。着手時に `dumpbin /imports` で cl/link の ntdll
  依存を実機確認。
- **M3.2:** TCP+独自フレーム基準線で着手（事前期待が裏付け）。DirList 先読み・ネガティブキャッシュ・
  timestamp 偽装・子注入 env 伝播・32/64bit を設計に織り込む。
- **M3.3:** 出力フェンス＋staging→atomic rename。mspdbsrv の扱いを決定項目化。
- **M3.5:** in-process 遅延 shim ベンチ（clumsy 不可を確定）。ADR 0002 へ。
