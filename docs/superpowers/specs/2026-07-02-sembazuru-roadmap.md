# Sembazuru ロードマップ（2026-07-02 改訂・詳細版）

- 作成日: 2026-07-02 / 対象 HEAD: `248876a`（全 push 済み）
- この文書の位置づけ: **今後の全体計画のマスター**。`docs/DESIGN.md`（M0〜M10 の原設計）を、実運用ゴールに合わせて再整序した実行計画。原設計を置換するのではなく、次に何を・どの順で・どこまでやれば「Done」かを貢献者が拾える粒度で定義する。
- なぜ今これを濃く書くか: 強いモデル（Fable）が近く使えなくなる可能性があるため、判断の根拠・対象ファイル・受入条件・テスト方針を、後から別のモデルや**外部の貢献者**が読んで単独で実行できる密度で残す。
- **スコープ外（重要）**: セキュリティ（認証・権限・脅威分析・署名/EDR）は本計画では扱わない。プロジェクトオーナーが外部で管理する。旧セキュリティ review-fix「Phase 7〜9」「SEC-001」等は本計画から除外。

---

## 0. 決定ログ（今回のセッションで確定した方針）

| 決定 | 内容 | 理由 |
|---|---|---|
| **順序 = A案** | M11（GUI ワーカー参加フロー）を M10（実2台トライアル）より**先に**完成させる | ある程度の規模のテストには**手伝いを募る**必要があり、GUI が磨かれていないと貢献者・テスターが集まらない。オーナー一人で全部はやらない前提で、まず参加体験を整える |
| セキュリティは外部管理 | 本計画にセキュリティのマイルストーンを置かない | オーナー判断。security-adjacent な設定（cluster token・LAN 許可等）は「動かすための機能設定」として扱う |
| 表現方針 | 文書を自製品の価値（無料・OSS・ゼロ設定・決定性）中心の前向きな表現に統一。競合を攻撃する言い回しは排除し、技術的な先行事例参照（clean-room の出所明示）のみ保持 | 対外文書・OSS 文書として健全な表現にするため |

---

## 1. 目標（前向きな再定義）

**任意の Windows プロセスを無設定で分散実行する、無料・OSS の基盤。** 商用ツールにしか存在しなかった「プロセス仮想化による透過的な分散実行」を、ライセンス費用なしで誰もが使える形で提供する。

達成の質は 3 つの非交渉事項で担保する（`CLAUDE.md`）:
1. **正確性 > 速度。** 同じ入力なら byte-identical。決定性ハーネスは品質ゲート。
2. **ローカルフォールバック必須。** ネットワーク/ワーカーが落ちてもビルドはローカルで完走する。
3. **clang-cl は一級ターゲット。** MSVC 単独に設計を依存させない。

**当面の現実的な到達点**（`DESIGN.md` §10 と整合）: 既存製品を「置き換える」ことではなく、**特定セグメント（非 UE・汎用 Windows ビルド）で、無料・OSS の確実な代替として明白な選択肢になる**こと。

---

## 2. 現状の地図（証拠クラス付き）

セッション内の検証で確認した事実。`[実測]`=実測済み / `[テスト]`=自動テスト有 / `[実装のみ]`=コードはあるが実条件未検証 / `[未着手]`。

| 能力 | 状態 | 証拠 |
|---|---|---|
| プロセス仮想化コア（hook→remote→VFS→writeback） | `[実測・単機]` | cl/clang-cl/dxc で byte-identical、ただし loopback のみ |
| 決定性ハーネス | `[テスト]` | clang-cl+lld クロスディレクトリ byte 一致を CI ゲート、dxc も確認。COFF `TimeDateStamp` までバイト特定 |
| ローカルフォールバック | `[テスト・loopback]` | no-worker / remote-unreachable / daemon-down を統合テスト |
| CAS / アクションキャッシュ | `[テスト]` | versioned+bounded codec、`Has(digests[])` バッチ |
| MSBuild/CMake/Ninja 統合 | `[実装のみ]` | 単機で動作 |
| GUI（トレイ常駐・Status 監視・config・サービス制御） | `[実装のみ]` | `crates/gui`、headless テスト有。**daemon 設定のみ編集可** |
| WiX MSI（サービス2本・FW規則・GUI自動起動・config seed・uninstall） | `[実装のみ]` | `installer/sembazuru.wxs`。ビルド済み MSI は存在するが**未リリース** |
| GitHub リリース配布 | `[実装のみ・未実行]` | `.github/workflows/release.yml`。**`v*` タグ 0 件＝一度も実行されていない** |
| **実ネットワーク速度** | `[未検証]` | レイテンシ数値は同一プロセス内 RTT シム（`SEMBAZURU_VFS_RTT_US`）の合成値のみ。**実 NIC 未測定** |
| **実2台以上での動作** | `[未着手]` | agent+worker を 2 物理マシンで走らせたことがない |
| **2台目を GUI で worker 参加** | `[未着手]` | worker 設定 UI が存在しない（下記ギャップ） |

**壊れている/欠けているのは「2台目 join」と「実ネット速度の証明」の 2 点に集中している。** 1 台利用は滑らか（MSI がサービス2本＋GUI を自動起動、`daemon.toml` 自動シード、FW 規則自動投入）。

### 最大のコードギャップ（M11 の対象）
- GUI（`crates/gui/src/app/config.rs`）は daemon の `coord_addr`/`fileserver_addr` を Status `GetConfig`/`SetConfig` RPC で編集するのみ。**worker 側設定（`agent` アドレス・`advertise`・`listen_addr`・worker の `cluster_token`・参加モード）を入力する UI が皆無。**
- worker のインストーラ・シードは `crates/worker/src/config.rs:508` で `agent: http://127.0.0.1:50070`（loopback）に固定。コメント自身が「2台目は GUI で LAN アドレスに変える」と書くが、その GUI が無い。現状 2台目は `%ProgramData%\Sembazuru\worker.toml` を手編集するしかない。

---

## 3. 戦略の骨子

### 橋頭堡セグメント（最初に完全制覇する一点）
**MSVC 非依存で決定性を重視する、小〜中規模（5〜30人）の clang-cl / LLVM ベース Windows C++ チーム。** 例: クロスプラットフォーム寄りエンジン、非 UE ゲーム、ツール系 OSS、金融/HFT のモダン C++ モノレポ、clang 移行中のショップ。

このセグメントを選ぶ理由: 現状の強み（OSS 無料・clang-cl 一級・CI バイト決定性）がそのまま刺さり、弱点（cl.exe・大規模クラウド・監視 UI）を範囲外に追い出せる。数台の LAN マシンが「妥協」ではなく「ネイティブな規模」になる。

### 避ける/後回しにする領域
- **UE/UBT 統合**: clean-room 制約（`CLAUDE.md` 非交渉 #3、ADR 0005）で study-only。実装しない。
- **cl.exe（MSVC）の一級化**: ライセンス上のグレー領域。H3 の M18 で明示的に判断するまで、clang-cl 一級を維持し、部分対応の忍び込みを許さない。
- **クラウドバースト/大規模プール**: H3 の M20 まで設計もしない（投機的抽象化を作らない）。

---

## 4. ロードマップ全体（3 ホライズン・A案順序）

🖥️ = 実機必須。⭐ = make-or-break の前提を握るマイルストーン。

```
Horizon 1 — 実物であることを証明
  M9.6  初の実 GitHub リリース（CI）
  M9.7  単機・実機インストール受け入れ（🖥️1台）
  M11   2台目 join を GUI 化（開発機で実装）★A案でここを先行
  M10   GUI だけで実2台 LAN join + 分散ビルド + 速度実測（🖥️2台）⭐
  M12   オンボーディング仕上げ（CI/開発機）
Horizon 2 — 橋頭堡セグメントを1つ完全制覇
  M13   マルチワーカー fan-out がスロットを飽和（🖥️）
  M14   雑多な実プロジェクトでの信頼性（🖥️）⭐
  M15   ライブ監視 UI
  M16   障害注入フォールバック堅牢化（🖥️）
  M17   ワーカー間 CAS 共有
Horizon 3 — 適用範囲を広げる（貢献者が集まってから）
  M18   MSVC パス判断（ADR で決着）⭐
  M19   実10台規模
  M20   クラウド/オンデマンド worker 1系統
  M21   IDE 統合
  M22   非コンパイラの任意プロセス実証
  M23   スケールキャッシュ
```

**クリティカルパスの思想**: 唯一の make-or-break の未知＝「実ネットで実ビルドがローカルより速いか」（M10 の速度実測）。A案では GUI（M11）を先に磨くが、**M10 の速度数字が出るまで Horizon 2 以降には着手しない**。GUI 磨きは「テスターを募るための必要条件」であって、速度証明の代替ではない。

---

## 5. マイルストーン詳細

### Horizon 1

#### M9.6 — 初の実 GitHub リリース（MSI 発行）
`release.yml` はタグ起動が一度も走っていない。最小ステップで「タグ → draft → publish」を初めて通す。

**タスク:**
1. `workflow_dispatch` の dry-run を実行し、MSI 成果物が生成されることを先に確認（タグ固有分岐の前に機構確認）。
2. ローカルで `cargo test --workspace` 緑を確認。
3. Cargo/WiX/タグのバージョン整合を確認（`installer/check_version_sync.ps1`。既定 `0.0.1`）。
4. `git tag v0.0.1 && git push origin v0.0.1`（**push はユーザー**）。
5. Actions 完走を CI ログで確認 → draft リリースに `.msi` が添付されるのを確認。
6. draft を手動 Publish。

**Done when:**
- `release.yml` が green 完走し、GitHub Releases ページの draft に `.msi` が 1 本添付。
- 匿名 DL リンクから MSI が落とせる（Publish 後）。
- 成果物ハッシュがクリーンチェックアウトから再現可能。

**注意/リスク:**
- 未署名なので Release は draft 止まり（`release.yml:161` 付近の分岐）。手動 Publish が必要。署名は本計画スコープ外（未署名配布で進める）。
- タグ文脈固有の分岐（バージョン解決 / `gh release create --draft`）は CI 未カバー。初回は失敗前提でログを読む。
- **前提整合**: リリース前に、旧 Phase 5 タグ（`f7c4420`）が真 HEAD（`1930761`）より 1 コミット遅れている件を確定（retag するか、gap を許容するかはオーナー判断。M9.6 のバージョン整合の前提）。

#### M9.7 — 単機・実機インストール受け入れ 🖥️（管理者 PC 1台で可）
2台構成の前に、1台で MSI の実挙動を確定し「入れれば動く」前提リスクを潰す（`docs/handoff/lead-actions.md` §1/§2/§4）。

**Done when（すべて実機・管理者 PowerShell で証跡付き）:**
- DL した MSI を UAC 昇格でインストール → `sc.exe qc SembazuruDaemon` / `SembazuruWorker` が両方 `AUTO_START`、ImagePath に `--service`。
- `%ProgramData%\Sembazuru\{daemon,worker}.toml` が seed、`{scratch,cas}` 作成、worker サービスアカウントの ACL が実効（worker が scratch/cas に書ける）。
- GUI 起動、Dashboard が `DaemonDown` を出さず daemon に接続。Services タブの Start/Stop が UAC 経由で効く。
- 1本の clang-cl ビルドがローカル高速化され、CI ベースラインと byte 一致。
- `msiexec /x` 後、`%ProgramData%\Sembazuru` 全消去・両サービス削除・PATH 復元・残骸ゼロ。

**潜在ブロッカーの確定タスク:** Rust exe の CRT リンク方式を `dumpbin /dependents` で確認。動的リンクなら初見 PC で `VCRUNTIME140.dll` 欠落で起動失敗しうる → M12 の VCRedist 対応を昇格。

#### M11 — 2台目 join を GUI だけで（手編集ゼロ）★A案で先行実装
「簡単導入」の核心。GUI に worker 参加フローを新設し、`worker.toml` を GUI が直接書く。**開発機で着手可能**（実機受入は M10 に合流）。**貢献者を募るための土台＝ここが磨かれていないとテスターが集まらない**ため A案で先行。

##### 2.0 config 変更の前提（両経路共通・M11 全体の前提条件）
M11 は「非昇格 GUI から daemon/worker の config を変更する」ことを要求するが、これは既定で**二重に塞がれている**（いずれも非昇格ローカルユーザーの勝手な config 変更を意図的に防ぐ設計）:
- **daemon 側 `SetConfig` RPC は既定 OFF。** 変更系 Status RPC（`SetConfig`/`TriggerEviction`）は `admin_enabled`（既定 **false**）で、`SEMBAZURU_STATUS_ADMIN=1` / `status_admin = true` を opt-in しない限り `permission_denied`（[`crates/agent/src/status.rs:148-176`](../../../crates/agent/src/status.rs)、ADR 0016。loopback Status は呼出元認証が無いための既定拒否）。**当初の §2.4 はこの無効な SetConfig に依存していた（Codex 指摘）。**
- **config ファイル直書きは既定 ACL で不可。** `daemon.toml`/`worker.toml` は `%ProgramData%\Sembazuru`（[`installer/sembazuru.wxs:54-73`](../../../installer/sembazuru.wxs)）に LocalSystem が seed。既定 ACL では非昇格ユーザーセッション GUI（[`crates/gui/src/lib.rs`](../../../crates/gui/src/lib.rs) は非昇格）が既存ファイルを上書きできない可能性が高い。

M11 の GUI-only 変更を成立させるには config-write 機構を1つ選ぶ必要があり、**どの選択肢も「ローカル GUI が特権 config を変更できる」ことを意味するため、SEC-001/ADR 0016 の姿勢に触れる。機構の選択・実装はオーナーの外部セキュリティ管理と要調整（本ロードマップのスコープ外）。** 選択肢を事実として提示（決定は外部）:
- **(i) `status_admin` を有効化**して SetConfig を使う。ADR 0016 が塞いだ経路を再び開く（loopback の任意ローカルプロセスが config 変更可）。
- **(ii) config ファイルに write ACL 付与**（インストーラ変更）。非昇格 GUI が直書き可＝同様に任意ローカルユーザーも編集可。
- **(iii) 昇格 config-write ヘルパ**（変更ごとに UAC）。「config 変更には特権が要る」意図を保つが、svcctl の昇格境界は現状「固定サービス名のみ、free-form 不可」（`svcctl/mod.rs:24`）なので内容書込用の別パス新設が要る。
機能的に既存の姿勢を保つのは (iii)。**この config-write 機構の確定が M11 全体の前提条件**であり、以降 §2.1〜§2.4 は「選んだ機構」で daemon/worker の config を書く前提で記述する。

##### 2.1 コンポーネント境界（設計の要）
- **daemon 設定**: §2.0 で選んだ config-write 機構で `daemon.toml`（`coord_addr`/`fileserver_addr`/`cluster_token`）を書く。**SetConfig は既定 OFF なので前提にしない。** bind は起動時のみなので、書込後は **daemon サービス再起動**（svcctl、要昇格）で反映する（詳細 §2.4）。
- **worker 設定**: worker には GUI 向け Status RPC が無い。§2.0 の機構で `worker.toml` を書き、`svcctl`（`crates/gui/src/svcctl/mod.rs` は `Service::Worker` を持つ）で Worker サービスを再起動して反映する。新規 worker RPC を足すより小さい。

##### 2.2 ウィザード入力項目
| フィールド | worker.toml キー | 補足 |
|---|---|---|
| coordinator アドレス | `agent` | `http://<A-IP>:50070`。1台目 GUI が表示する値を貼る |
| cluster token | `cluster_token` | 1台目と同一。1台目 GUI がコピー用に表示 |
| このPCの listen | `listen_addr` | 既定 `0.0.0.0:50061` |
| このPCの advertise | `advertise` | `listen` が `0.0.0.0` のとき、このPCの LAN IP で**自動補完** |
| 参加モード | 参加モード設定 | ADR 0010/0011/0012 の既存モード。既定値を提示 |
| LAN 実行許可 | `unsafe_allow_insecure_execution_lan` | LAN 参加に機能上必須。ウィザードが有効化（機能設定として扱う。セキュリティ的判断は外部管理） |

##### 2.3 バリデーションと罠回避
- 保存前に `agent` アドレス形式チェック（`http://host:port`）。
- `listen_addr` が `0.0.0.0`/unspecified かつ `advertise` 空 → このPCの LAN IP を自動補完（`crates/worker/src/run.rs:93` の起動時エラーを未然に防ぐ）。
- ポートを既定（50061/50070/50072）から変えると MSI 投入済み FW 規則（`installer/sembazuru.wxs:113` 付近でハードコード）と食い違い静かに壊れる → 既定ポートを推奨、変更時は警告。

##### 2.4 1台目側「LAN worker を許可」トグル（実装可能な順序手順・Codex 指摘の反映）

daemon の bind は起動時に `config` から一度だけ行われる（[`crates/agent/src/run.rs:68,91,115`](../../../crates/agent/src/run.rs)）。§2.0 のどの config-write 機構で `daemon.toml` を書いても稼働中プロセスは再バインドしないため daemon サービス再起動が要る（SetConfig 経路の場合その応答自身が「restart the daemon to apply」を返す。[`crates/agent/src/status.rs:362`](../../../crates/agent/src/status.rs)）。さらに非 loopback バインドは **cluster_token が無いと daemon が起動を拒否**する（fail-closed。[`run.rs:33-63`](../../../crates/agent/src/run.rs)）。したがってトグルは次の**順序付きオーケストレーション**として実装する（config 書込は §2.0 で選んだ機構を使う）:

1. **前提: cluster_token を確保。** token 未設定なら先に生成/入力させ §2.0 の機構で `daemon.toml` に保存。token 無しのまま LAN バインドに切り替えると次回起動で daemon が拒否して上がらない。GUI は token 未設定の間トグルを無効化（理由をツールチップ表示）。
2. **アドレスを具体 LAN IP で永続化。** GUI がこのPCの LAN IP を検出し、`coord_addr`/`fileserver_addr` を `<LAN-IP>:50070` / `<LAN-IP>:50072` として §2.0 の機構で `daemon.toml` に保存する（**`0.0.0.0` にしない**。理由は下記 routable 化）。
3. **daemon を再起動。** svcctl で daemon サービスを Stop → Start（`crates/gui/src/svcctl` は Start/Stop を持つ＝再起動は2手。**Administrator 昇格＝UAC** が要る。既存 Services タブと同じ導線）。再起動中は Dashboard が一時的に `DaemonDown` を出すので、完了後に loopback Status へ再接続する。
4. **失敗ハンドリング。** 再起動後に daemon が上がらない/Status に繋がらない（token 欠落・ポート使用中・IP 不一致）場合、GUI はエラーを提示し loopback 既定（`127.0.0.1:50070` / `:50072`）への復帰を提案する。

**file-server アドレスの routable 化（ステップ2で必須）:** `0.0.0.0` にしてはならない。agent は file-server を bind したあと `local_addr()` の結果を `agent_fileserver` として worker に渡し（[`run.rs:115-184`](../../../crates/agent/src/run.rs)）、worker はこれを dial してファイル供給を受ける。`0.0.0.0` バインドだと `local_addr()` が `0.0.0.0` を返し worker が dial できず失敗する（worker の `advertise` トラップ [`run.rs:93`] と同型を、agent 側は advertise 概念を持たないまま踏む）。**具体 LAN IP にバインドすれば `local_addr()` が routable な IP を返す**ため無改修で解ける。トグル ON で表示するコピー用 LAN IP は、このバインド IP と同一にする（2台目ウィザードの `agent` = `http://<この LAN IP>:50070`、`ipconfig` 不要）。cluster token も同時にコピー用表示。

**代替（より堅牢だが agent 側コード改修＝load-bearing）:** file-server を `0.0.0.0` に bind しつつ worker へ渡す `agent_fileserver` を別の「advertise」設定から取る（worker の `advertise` と対称な agent 側フィールドを新設）。DHCP で IP 変動/複数 NIC 環境で要る。初版は「具体 LAN IP バインド」で足りるため、必要時に M11 follow-up として ADR 化（agent の protocol/VFS core に触るので main-thread 所有・Codex 実装＋line-by-line レビュー）。

##### 2.5 テスト方針（実機なしで検証できる範囲）
- 入力 → `worker.toml` 出力を pure なマッピング関数に切り出し、egui 非依存でユニットテスト（`crates/gui/tests/status_client.rs` の「表示なしでロジックをテスト」方針を踏襲）。
- daemon トグルの前提: cluster_token 未設定ならトグルが無効化されること（GUI 状態のユニットテスト）。
- daemon トグル実行が「§2.0 の config-write 機構で `daemon.toml` に token＋具体 LAN IP を書く → daemon サービス Stop→Start」の順を発行すること（config 書込内容と svcctl 順序をモックで検証。SetConfig 経路を選んだ場合のみ in-process `serve_status_service` で内容検証）。
- `advertise` 自動補完・アドレス形式・token 前提のバリデーション分岐をユニットテスト。
- 実 LAN 越しの疎通と daemon 実再起動のみ M10 に残す。

**Done when:**
- **前提（§2.0）**: config-write 機構が確定していること（SetConfig 既定 OFF＋直書き ACL 制限のため。オーナー外部管理と要調整）。M11 の GUI-only 変更はこの確定に依存する。
- GUI から worker 参加ウィザードを完了すると正しい `worker.toml` が書かれ（書込は §2.0 の機構）、Worker サービスが再起動される（TOML 出力は headless テストで検証、実ファイル書込＋実再起動は M10）。
- daemon トグルが「cluster_token 確保 → `coord_addr`/`fileserver_addr` を具体 LAN IP（`0.0.0.0` ではない）で §2.0 の機構で永続化 → daemon サービス Stop→Start → Status 再接続」を一連で実行し、再起動後の daemon が LAN IP に bind して `agent_fileserver` が routable になる（config 書込内容＋svcctl 順序＋token 前提をユニットテスト、実再起動の確認は M10。§2.4）。
- worker 側は `advertise` 未設定+`0.0.0.0` を GUI が保存前に検出し補完を促す（§2.3。worker には advertise フィールドが実在するのでこちらは自動補完で正しい）。
- 🖥️ 最終受入は M10 で「TOML を一切手編集せず GUI だけで」2台 join。

**実装委譲**: GUI は load-bearing コア（hook/protocol/VFS）ではないため Codex 実装＋main レビュー（`CLAUDE.md` 規約）。ただし `worker.toml` の書式・キー意味論は config 実体に触れるので、生成部は main が line-by-line レビュー。

#### M10 — 初の実2台 LAN オンボーディング + 分散ビルド + 速度実測 🖥️⭐（2台目 PC 必須）
本命の統合受入テスト。M11 完成後、**GUI のみ**で PC-A（daemon）+ PC-B（worker）を LAN 接続し、実ビルド1本を分散実行し、**実 NIC で速度を測る**。

**構成:**
- 物理2台を実 LAN（理想化しない安物 1GbE スイッチ）。RTT シム無効（`SEMBAZURU_VFS_RTT_US` 未設定）。
- 設定は GUI のみ（A: 「LAN worker を許可」トグル + token 表示 / B: 参加ウィザードに A の IP と token 入力）。

**ワークロード（速度実測）:** `#include` 扇形展開が重い中規模 clang-cl プロジェクト（例: LLVM 自身、または fmt+abseil を束ねた 50〜200 TU）を**コールドキャッシュ**で（CAS ヒットで隠さない）。

**Done when（証跡付き、TOML 手編集ゼロ）:**
- PC-A の GUI Dashboard の Workers 表に PC-B が現れ、last-ping 更新、admission 除外理由なし（両機同一 MSI 版）。
- LAN FW（`localSubnet`、既定ポート 50061/50070/50072）が実 LAN で通る。
- PC-B が PC-A の file-server を **routable なアドレスで dial できている**ことを確認（agent が worker に渡す `agent_fileserver` が `0.0.0.0` でなく PC-A の LAN IP。§2.4 の修正が実機で効いていることの検証点）。
- 実ビルド1本で PC-B 実行のアクションが含まれ、出力がローカル完結と **byte-identical**（決定性ハーネス）。
- **速度実測（この数字が全てを決める）**: (a) ≥50 TU の clang-cl プロジェクトが実 LAN 上の分散で、PC-A ローカル `-j 全コア` より**厳密に速い**（生の両時間＋比率を記録）。(b) **TU 当たりの実データプレーン往復回数**を実 NIC で計測・記録。
- ネットワーク断で**ローカルフォールバックが完走**（非交渉 #2）。

**判定基準（プロジェクトの go/kill）:**
- **GO** — コールドキャッシュ・実 LAN で分散がローカルを有意に上回る（目安 ≥1.3x）。以降の全ギャップは工程問題（＝研究でなく実装）に降格。
- **KILL** — 小ファイル往復の累積で分散が遅い/僅差、バッチ/プリフェッチを尽くしても往復が減らない → アーキの根が命題を支えない。方針転換。
- **NARROW** — 勝つのは大 TU・重 CPU 時のみ（dxc シェーダ、LTO 等）→「任意プロセス・ゼロ設定」を狭め、CPU 律速ワークロードに的を絞る。

**設計要件**: M10 は pass/fail でなく**レイテンシ内訳を捕捉**すること（負の結果を actionable にするため、TU 当たり往復・小ファイル待ち時間・転送量を記録）。

#### M12 — オンボーディング体験の仕上げ（低コスト UX 修正群）
順不同・独立着手可。多くは CI/開発機で達成可能。**貢献者募集の前に最低限やるべき対外整備を含む。**

**Done when（該当項目ごと）:**
- README/quickstart を M9 現実に同期: ステータスバッジ（`pre-alpha single-box M1-M8` を M9 反映）、ロードマップ表、「まだ無い」節を修正。**「GitHub Releases から MSI を DL → インストール → 起動」のエンドユーザー向け手順を新設**（現状ゼロ）。未署名 MSI の SmartScreen「詳細→実行」手順をスクショ付きで記載。
- 初回起動ガイダンス: X ボタンでトレイ最小化する旨のトースト、config フィールドのツールチップ（内部用語の説明）。
- Dashboard 最上部に「ワーカー N台接続中 ✓」の大バッジ（成功可否を非開発者にも一目で）。
- `Cache max bytes` に GB↔bytes の単位ピッカー。
- VC++ ランタイム: M9.7 の確認結果に応じて MSI に VCRedist をバンドル、または README に前提明記。

### Horizon 2 — 橋頭堡セグメントを1つ完全制覇（各項目は着手時に個別 spec 化）

> H2 以降は M10 が **GO** を返してから着手。ここで初めて「実ネットで速い」が前提として使える。

#### M13 — マルチワーカー fan-out がスロットを飽和 🖥️
既知の傷: ninja が遊休スロットを埋めきれず `remote=3/4`、`-j 1` で回避（`deferred.md` 参照）。並列を切らずに正しく飽和させる。
- **Done when:** 1-agent / 3-worker（実 3 ホスト or 🖥️）で ≥100 TU が **remote slot 利用率 ≥90%**。速度がワーカー数 1/2/3 で単調にスケール（比率記録）。

#### M14 — 雑多な実プロジェクトでの信頼性 🖥️⭐（H2 の真の製品リスクゲート）
決定性はハッピーパスのみ CI 保証。実プロジェクトの長い尾（PCH・応答ファイル・生成ソース・サードパーティ SDK include・resource compiler）が hook 方式の詰まりどころ。
- **Done when:** 3 つの実 OSS clang-cl/CMake プロジェクトが分散で正しく byte-deterministic に完走。検出器が扱えないワークロードは**ローカルフォールバックに fail-closed し理由をログ**、決して静かに誤らない。
- **make-or-break の前提**: 検出器の route-away リストが無限に膨らまないと正しさを保てないなら「ゼロ設定」が静かに「設定過多」になる。ここが H2 の核心リスク。

#### M15 — ライブ監視 UI
分散中に GUI が: ワーカー別アクティブ TU・remote/local 分割・キャッシュヒット率・現時点の速度向上を表示。「今ちゃんと分散しているか」をログなしで答えられる。
- **Done when:** 上記 4 指標がビルド中にライブ更新。

#### M16 — 障害注入フォールバック堅牢化 🖥️
- **Done when:** 実分散ビルド中にワーカーをファイルストリーム中/リンク中に kill → 10 回の注入すべてでローカルフォールバック完走・記録。

#### M17 — ワーカー間 CAS 共有
- **Done when:** LAN 上の 2 ワーカーがアクションキャッシュヒットを共有。worker-A でコンパイルした TU が worker-B の要求に再計算なしで供給される（B のコンパイルスキップで検証）。

### Horizon 3 — 適用範囲を広げる（貢献者が集まり、H2 に採用チームがついてから）

> 投機的に作らない。採用チームが規模を求めてから着手。

- **M18 — MSVC パス判断 ⭐**: cl.exe の扱いを ADR で一方に決着（法的に整理した remote-cl パスで `.vcxproj` サンプルを分散・byte-deterministic にビルドして MSVC 市場を開く／または正式に MSVC を切り捨て clang-cl に全振り）。Done when は**判断が下され根拠が defended されること**。グレー領域のまま放置しない。
- **M19 — 実10台規模 🖥️**: opt-in 遊休デスクトップ admission（既存 CPU モニタを実際の busy な開発機で検証）が大規模ビルドで ≥90% 有用利用率を維持、速度がワーカー数 10 まで単調。
- **M20 — クラウド/オンデマンド worker 1系統**: LAN デスクトップ以外の弾力的 worker 源が同じ GUI-join 経路で farm に参加し分散ビルドに寄与（計測）。
- **M21 — IDE 統合**: VS / VS Code に分散状態と監視相当のフィードバックを表示。
- **M22 — 非コンパイラの任意プロセス実証**: 少なくとも 1 つの非コンパイラワークロード（コードジェネレータ／パッケージャ／テストランナー）が分散で byte-deterministic に完走（ADR 0007 の任意プロセス命題の実証。現状はコンパイラのみ）。
- **M23 — スケールキャッシュ**: M17 の共有 CAS が ≥10 ワーカー・日次増分ビルドでヒット率と正しさを維持（実チームの反復ビルドで測定）。

---

## 6. 貢献者募集を見据えた設計（A案の狙い）

オーナー一人で全部はやらない。**手伝いを募る**前提で、以下を整える:

- **拾える粒度のタスク**: 本文書の各 Done when は独立検証可能。特に M12（README/ツールチップ/単位ピッカー）と M11 のサブ項目は **Good First Issue** 候補。
- **磨かれた GUI が入口**: M11 完成後、テスターは MSI を入れて GUI ウィザードだけで 2台目参加を試せる。CLI/TOML 知識を要求しない＝協力のハードルが下がる（A案の本質）。
- **貢献ガイドの最低ライン（M12 で整備）**: README のエンドユーザー導線、ビルド手順、`CLAUDE.md` の作業規約（実装は Codex 委譲＋二重レビュー、決定性ゲート、clean-room）を貢献者向けに要約。
- **実機テストの募集**: M10/M13/M14/M16 は 🖥️ で、オーナー＋協力者の実機が要る。GUI が整っていれば「MSI 入れて速度を報告してほしい」という形で広く募れる。

---

## 7. STOP / DROP / DEFER

1. **loopback/RTT シムの速度数値を意思決定から排除。** `SEMBAZURU_VFS_RTT_US` の合成値は証拠でない。M10 以降は実 NIC 値のみ。
2. **クラウド/弾力スケールの設計は M20 まで着手禁止**（抽象化も ADR も作らない）。
3. **cl.exe/MSVC を M18 まで一級化しない**（clang-cl 一級を維持、部分対応の忍び込み禁止）。
4. **UE/UBT 統合はドロップ**（clean-room、study-only）。
5. **H1〜H2 で新規ビルドシステム統合（Bazel 等）を追加しない**（CMake/Ninja+MSBuild で橋頭堡には十分。breadth より depth）。
6. **M10 以降、単機 CI green を「Done」の根拠にしない**（分散の主張は 🖥️ 2台目が要る）。
7. **セキュリティ関連（旧 Phase 7-9・SEC-001・署名/EDR・mDNS 自動発見）は本計画から除外/後回し**（外部管理 or 将来 UX 改善）。

---

## 8. リスクと未検証の前提（make-or-break）

| 前提 | ホライズン | 判定タイミング |
|---|---|---|
| **実ネットで実ビルドがローカルより速い**（小ファイル VFS 往復が分散の利得を食わない） | H1 | **M10 の速度実測**。KILL ならアーキ再考 |
| 雑多な実プロジェクトで hook 方式が正しさを保つ（route-away が無限膨張しない） | H2 | M14 |
| clang-cl 市場が採用する実需がある | H2 | 橋頭堡プロジェクトの実採用 |
| MSVC を割るべきか、切り捨てるべきか | H3 | M18 の ADR |

**最も危険な単一の前提**: 「データプレーンを渡るのは少数のプロジェクトファイルだけ。SDK/ツールチェインのヘッダはワーカーローカル」。全ての良好なレイテンシ数値がこれに依存し、実ネットで一度も検証されていない。M10 がこれを直接叩く。

---

## 9. 関連文書
- `docs/DESIGN.md` — 原設計（M0〜M10、前向き表現に修正済み）
- `docs/handoff/lead-actions.md` — 実機受入チェックリスト（M9.7/M10 の証跡元）
- `docs/decisions/0008`（インストーラ/GUI/常駐）、`0010`/`0011`/`0012`（admission/参加モード）
- `.github/workflows/release.yml` — M9.6 の対象
- `crates/gui/`、`crates/worker/src/config.rs`、`installer/sembazuru.wxs` — M11 の対象
