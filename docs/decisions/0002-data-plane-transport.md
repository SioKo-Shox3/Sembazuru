# 0002 — データプレーン・トランスポート選定（M3.5）

- ステータス: **決定済み（ACCEPTED）— TCP＋独自フレームを採用。**
  決定者: プロジェクトリード、2026-06-13。
- 決めること: `docs/protocol/v0.md` §4.4 が M3 の実測に委ねた、データプレーン
  （ファイル供給）のトランスポート。候補: TCP＋独自フレーム（基準線）、QUIC
  （quinn）、gRPC ストリーム（strawman）。
- 判定基準（v0 §4.4 で固定済み）: 代表的な cl/clang-cl コンパイルの実時間が
  ローカルから大きく劣化せず、往復レイテンシで破綻しないこと（LAN 0.5–1ms RTT）。

## 決定

**TCP＋独自フレーム（`sembazuru-dataplane` の length-prefixed バイナリ）を M3 の
データプレーン・トランスポートとして採用する。** QUIC / gRPC は実装せず、広域
（WAN）やロスのある環境が要件になった時点（M5 以降）に再評価する候補として残す。

## 根拠

### 1. 速度 Done-when を実測で満たした（`hooks/test/vfs_bench.ps1`）

リアルなモデルは「ツールチェーン＋SDK はワーカー常駐、プロジェクト・ソースのみ
agent から VFS 供給」。よって**データプレーンを通るのは少数のプロジェクトファイル
だけ**で、数百の SDK ヘッダはワーカーローカルで読まれる（VFS リダイレクトは
`SEMBAZURU_VFS_ROOT` 配下の read のみ／include 探索の負プローブ=kProbe は非
リダイレクト）。

フレーミング層に合成 RTT を注入（clumsy は loopback 不可のため in-process 遅延 shim、
prestudy §2）して実測（開発機、5 回の最小値）:

| 構成 | 実時間 |
|---|---|
| ローカル cl | 66.0 ms |
| VFS（RTT 0ms） | 92.6 ms |
| VFS（RTT 1ms） | 108.9 ms |
| **RTT デルタ（1ms − 0ms）** | **16.3 ms** |

- **往復で破綻していない:** 1ms RTT を入れても +16ms しか増えない。これは VFS を
  通るファイルが少数だから（往復数 × RTT が小さい）。「大量小ファイルで往復爆発」は
  起きない—それらは SDK でワーカーローカル。
- **大きく劣化していない:** VFS(1ms) は local の約 1.65 倍。注入・パイプ・agent 接続の
  固定オーバーヘッド込みでこの範囲。Done-when を満たす。

CI（`-RequireClangCl`）でも clang-cl の VFS 下リモートコンパイルが**ローカルと
バイト一致**することを別途検証済み（`hooks/test/vfs_compile.ps1`）。速度と正しさの
両輪で M3 Done-when を満たす。

### 2. QUIC を実装しなかった理由（prestudy の事前期待が的中）

`docs/research/m3-prestudy.md` §2 の一次ソース調査:

- **ロスレス LAN では QUIC の HOL 優位がほぼ消える**（HOL は基本的にロスの関数）。
- **quinn-on-Windows は USO/URO が不安定**（Mozilla #1979279、quinn #2041）。
  オフロード無効時は 1 datagram=1 syscall に退行。
- **QUIC の userspace 暗号/ACK コスト**（Fastly 実測でスループット約 40%）。

加えて、上記 1 で **TCP が判定基準を満たした**。v0 §4.4 は「ベンチに勝った
トランスポートが出荷」と定めており、TCP が基準を満たす以上、likely-discarded な
QUIC/gRPC をフル実装して比較する費用対効果は低い。**TCP が勝者として出荷**し、
QUIC/gRPC は実装コストを払わず WAN/M5 へ繰り延べる。

### 3. gRPC を使わない理由

小メッセージで HTTP/2 フレーム＋HPACK のオーバーヘッドが相対的に重く（prestudy §2）、
v0 §4.2 も「ホットパスに protobuf を載せない」と規定。制御プレーンは gRPC のまま、
データプレーンは独自バイナリ（crate 境界で物理的に分離済み）。

## 正直な但し書き（透明性）

- 本決定は **TCP のフル実測＋QUIC/gRPC の事前期待** に基づく。QUIC/gRPC の実バイナリ
  比較は**実施していない**（TCP が基準を満たし、prior が強いため繰り延べ）。厳密な
  3 者ベイクオフは将来の論点として残す。
- 実測は**単一マシン＋RTT エミュレーション**（決定者承認の M3 方針）。実 2 台 LAN や
  WAN・ロス環境では QUIC が有利になりうる—その時点で本 ADR を再評価する。
- 現状のデータプレーンは hydrate 毎に agent への TCP 接続を張り、op は逐次
  （request_id による out-of-order 多重化は wire にあるが未活用）。接続プール化・
  パイプライン化・StatBatch/DirList 先読みは M5 のレイテンシ最適化項目。プロジェクト
  ファイルが少数の現状では Done-when に影響しないが、ファイル数が増える将来に効く。

## 影響

- v0 §4.4 の TBD を解消。データプレーンは TCP＋独自フレームで M3 凍結。
- `capabilities.data_plane_transports`（v0 §3.1）は当面 `["tcp-framed"]` のみ。
- QUIC を足す場合は `sembazuru-dataplane` のトランスポート境界（async byte stream）に
  差し込む—wire/codec はトランスポート非依存なので無改変で載る。
