# 0003 — CAS のハッシュ方式とチャンク戦略（M4）

- ステータス: **決定済み（ACCEPTED）— ハッシュ=BLAKE3、チャンク=whole-file＋大ファイル固定、CDC 見送り。**
  起案: M4.0、2026-06-13。決定者承認: プロジェクトリード、2026-06-13（実測の SHA-NI 拮抗を
  承知の上で、大ファイル優位・異機種ワーカーでの移植性・並列性・将来のツリーハッシュ検証を理由に
  BLAKE3 を採用）。
- 決めること: `docs/protocol/v0.md` §4.1/§4.3 と `docs/DESIGN.md` §9 が M4 に委ねた、
  CAS（content-addressable storage）の **(1) コンテンツハッシュ方式** と
  **(2) チャンク戦略**。digest はエンドツーエンドのキャッシュキー（CAS・ワーカー
  ローカルキャッシュ・アクションキャッシュ）なので、ここが全キャッシュ層の土台になる。
- 判定基準: 正確性（同一入力→同一 digest）を前提に、レイテンシ最優先（往復削減が命、
  CLAUDE.md）と実データのスループット/重複排除率で決める。

## 決定

1. **ハッシュ＝BLAKE3。** CAS とデータプレーンの digest-as-identity を、現在流用している
   手書き SHA-256（`crates/tracer/src/determinism.rs::sha256_hex`）から **BLAKE3 へ移行**する。
   `blake3` crate（CC0 OR Apache-2.0、取り込み可）を `sembazuru-cas` の本番依存にする。
   `determinism.rs::sha256_hex` は **M2 決定性ゲート専用として無改変で温存**（役割が違う／
   FIPS ベクタでテスト済み）。
2. **チャンク＝whole-file dedup ＋ Has() バッチプローブを基準線**とし、**大ファイル
   （閾値 2 MiB）のみ固定サイズチャンク（256 KiB〜1 MiB）でストリーミング**する。チャンクは
   digest アドレスにし、ストリーミングに必要な往復の範囲内で**重複排除を「ついで」に得る**。
   **content-defined chunking（CDC/FastCDC）は採用しない**（将来 WAN/大規模で再評価）。
3. **Digest 型**を `sembazuru-cas` に定義（`{ algo: DigestAlgo, hex: String }`、既定 `Blake3`）。
   データプレーンの `digest_hex` はこの Digest に揃える。v0 §4.1 が開いていたアルゴリズム選定を解消。

## 根拠（実データ：開発機、release、シングルスレッド、`cargo run -p sembazuru-cas --example hash_bench`）

### ハッシュスループット（MiB/s、大きいほど良い）

| size | 手書き SHA-256 | SHA-256（sha2 + SHA-NI） | BLAKE3 |
|---|---|---|---|
| 1 KiB | 326 | **2211** | 1298 |
| 4 KiB | 353 | 2345 | **3608** |
| 8 KiB | 367 | 2471 | **5193** |
| 64 KiB | 344 | 2469 | **5676** |
| 256 KiB | 379 | 2465 | **5657** |
| 1 MiB | 335 | 2500 | **5662** |
| 4 MiB | 328 | 2427 | **5421** |
| 16 MiB | 327 | 2475 | **5144** |

読み取り:
- **手書き SHA-256 は明確な敗者**（~330 MiB/s）。CAS ホットパスでは継続不可。差し替えは確定。
- **このマシンは SHA-NI を持ち、`sha2` の SHA-NI バックエンドは速い**（~2.4 GiB/s）。
  **1 KiB 以下では SHA-NI が BLAKE3 を上回る**（2211 vs 1298）。4 KiB で逆転、8 KiB 以上で
  BLAKE3 が約 2.3 倍（5.6 vs 2.4 GiB/s）。

**BLAKE3 を選ぶ理由（SHA-NI が小ファイルで拮抗するのを承知の上で）:**
1. **大ファイルで約 2.3 倍**。転送バイトの大半は .obj/.exe/.pdb（数十 KiB〜数十 MiB）で、ここは
   BLAKE3 の高速域。
2. **性能の移植性**。SHA-NI は CPU 機能であり全ワーカーが持つ保証がない。**SHA-NI 非搭載機では
   `sha2` は ~330 MiB/s（手書き相当）に落ちる**が、BLAKE3 は SSE/AVX で数 GiB/s の床を保つ。
   異機種ワーカーのビルドファームで SHA-NI を前提にできない。
3. **並列性内蔵**（`rayon` で巨大 blob は数十 GiB/s）。将来の大 .pdb 等で効く。
4. **ツリーハッシュ構造**が大ファイルのチャンク/ストリーミング検証と整合（決定 2 と相性良）。
5. **ライセンス適合**（CC0 OR Apache-2.0）、crate 成熟（公式メンテ、依存最小）。

**正直な但し書き:**
- SHA-NI 搭載機では sub-4 KiB のヘッダで SHA-256 が拮抗〜優位。BLAKE3 の勝ち筋は大ファイル＋
  移植性＋将来のチャンク化であって、「全領域で速い」ではない。
- REAPI は SHA-256 既定で BLAKE3 はオプション。ただし DESIGN は REAPI 実行プロトコル互換を
  非ゴールと明記しており、ブロッカーにならない。BuildXL は固定ブロックの VSO-Hash。
- M2 決定性 digest は SHA-256 のまま（別役割）。CAS と M2 でハッシュが分かれるのは意図的な二層。
- 計測は単一マシン・シングルスレッド。並列/異機種の優位は文献値（BLAKE3 公式、minio SHA-NI）
  に基づく将来効果。

### チャンク重複排除（クロスビルド、固定サイズチャンク、`hash_bench <objA> <objB>`）

同一ソースを 1 箇所だけ変えて 2 回コンパイルした `.obj` ペアで、B のチャンクのうち A に同一
内容が存在する割合（固定チャンクで再利用可能な上限）:

| 成果物 | 変更 | whole-file 一致 | 4 KiB | 16 KiB | 64 KiB |
|---|---|---|---|---|---|
| 小 .obj（36,917 B） | 1 関数の定数 | no | 50.0% (5/10) | 33.3% | 0.0% |
| 大 .obj（509,336 B） | 1 `#define`（1 関数） | no | **95.2%** (119/125) | 81.2% | 62.5% |

読み取り:
- **小 .obj は局所変更で whole-file が変わる**（64 KiB では 0% 再利用＝1 チャンク）。典型的な
  小オブジェクトに sub-file dedup の余地はほぼ無い。
- **大 .obj は局所変更で大量の未変更領域が残る**（4 KiB で 95.2% 再利用可能）。インクリメンタル
  ビルドの大 TU には sub-file 重複排除の余地が**実在する**。
- ただし決定的に重要なのは、**この再利用が固定チャンクで取れている**点。変更がバイトを
  シフトさせていない（挿入/削除でなく上書き）ため、**CDC の唯一の強み（シフト耐性）が出番なし**。
  fixed-chunk と CDC が同等に拾える領域に、CDC の CPU・実装コストを払う理由がない。

**チャンク戦略の結論:**
- **Done-when（同一プロジェクトの 2 回目ビルド）** は、入力が同一 → **アクションキャッシュ命中で
  コンパイルごとスキップ** → .obj 転送自体がゼロ。チャンク化は無関係。
- **インクリメンタル（1 TU だけ変わる）** では大 .obj に sub-file 類似があるが、**固定チャンクで
  十分**取れる。fine チャンクは Has() プローブと往復を増やしレイテンシ最優先と相反するので、
  **基準は whole-file dedup**、**大ファイルのみ固定チャンクストリーム**（WriteBack/大入力の
  メモリ・往復破綻を防ぐのが主目的、重複排除は副産物）。
- **CDC 見送り**: ビルド成果物はシフトせず再生成で上書きされるため CDC の利得が出ない。
  BuildXL も CDC 不採用（固定ブロック VSO-Hash）。restic/borg が CDC を使うのは partial-edit な
  バックアップ用途で、ビルド CAS とはワークロードが異なる。

## 影響

- v0 §4.1 の「Algorithm choice is open … candidate BLAKE3, decided with CAS chunking in M4」を解消。
  `capabilities` のハッシュ告知は当面 `blake3` のみ。
- `crates/dataplane` の `digest_hex`（現 SHA-256 hex 流用）を BLAKE3 hex に変更。agent fileserver
  と worker fileclient の双方が BLAKE3 を計算・検証する（end-to-end 整合、v0 §4.1）。M3 で運んだ
  digest 値とは非互換になるが、v0 §6 は CAS（M4）の wire 進化を許容、digest は内容アドレスなので
  初回ミスで自然に再登録される。
- 大ファイル固定チャンクは M4.4（WriteBack チャンク化）と M4.2（大入力 Read）で実装。閾値・
  チャンクサイズ（2 MiB / 256 KiB〜1 MiB）は実測で微調整可。
- 計測ハーネス: `crates/cas/examples/hash_bench.rs`（再現可能、`blake3`/`sha2`/手書き SHA-256 を
  並べて測る）。dev-dependency に留め、本決定で `blake3` を本番依存へ昇格する（M4.1）。

## 参考（一次ソース）

- BLAKE3 公式（性能・ツリーハッシュ・ライセンス）: https://github.com/BLAKE3-team/BLAKE3
- 小入力で SHA-256 が拮抗する件: https://forum.solana.com/t/blake3-slower-than-sha-256-for-small-inputs/829
- SHA-NI による SHA-256 高速化: https://github.com/minio/sha256-simd
- FastCDC 論文（CDC のコスト・利得）: https://www.usenix.org/system/files/conference/atc16/atc16-paper-xia.pdf
- BuildXL PagedHash（固定ブロック VSO-Hash、CDC 不採用）: https://github.com/microsoft/BuildXL/blob/main/Documentation/Specs/PagedHash.md
- REAPI（SHA-256 既定・BLAKE3 オプション、FindMissingBlobs）: https://github.com/bazelbuild/remote-apis/blob/main/build/bazel/remote/execution/v2/remote_execution.proto
- BuildBuddy CDC（2 MiB 超のみ適用の実測）: https://www.buildbuddy.io/blog/content-defined-chunking/
