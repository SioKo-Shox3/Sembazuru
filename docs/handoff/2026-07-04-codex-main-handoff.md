# 引き継ぎ: Codex をメインオーケストレータへ（2026-07-04）

Claude をメインから外し、**Codex がメイン**として続行する。Codex は `AGENTS.md`（`CLAUDE.md` と同一）に従う。以下はそのまま Codex への初回プロンプトとして使える。

> **⚠️ 更新（2026-07-04、この文書作成の直後）: B6 は完了しました。** 引き継ぎ直前、Codex が書いていた B6 実装が working tree に完成していたのを Claude が検証（cargo test/fmt/clippy -D warnings 全 green）・レビュー・**rescue-commit（`433c97d`）**した。**GUI（M11 + M12）は完成**。ブランチ `gui-completion` は `main` より **15 コミット先行・未 push・未マージ**、working tree クリーン。
> したがって Codex の**最初のタスクはもう B6 ではなく**、下記「この後の全体計画」の **M9.6（初リリース）**、または `gui-completion` の main へのマージ/push（ユーザー判断）である。以降の「未コミット」「最初のタスク: B6」節は履歴として残すが、B6 は済み。

---

## あなた（Codex）の役割

あなたは Sembazuru のメインオーケストレータです（デュアルメイン運用、`AGENTS.md`）。計画・統合・レビュー・実装を主導します。第二レビューは非メイン AI（＝Claude、headless）に回せます。会話は日本語、コード/コメント/対外ドキュメントは英語。競合を攻撃する表現は書かない（自製品の価値＝無料・OSS・ゼロ設定で語る）。セキュリティ分析はオーナーが外部管理（本作業では扱わない）。**push はユーザー操作**（勝手に push しない）。

## リポジトリの現状（ground truth）

- リポジトリ: `C:\Users\<user>\Documents\Sembazuru`
- ブランチ: **`gui-completion`**（`main` より 14 コミット先行、未 push）
- HEAD: `31326b1`
- 直近の作業は「GUI 完成（M11 + M12）」。実装は Codex、レビューは Claude が担当してきた。

### コミット済み（レビュー済み・全ゲート green）
- **M12（UI 仕上げ）**: `a04f4b4` ワーカー接続数バッジ / `0ca4a64` キャッシュ単位ピッカー / `f2405e0` 設定ツールチップ / `7b54a74` トレイ最小化ヒント / `fee82a9` README・quickstart を M9 現状へ同期 / `58e1d17` CRT 依存確定（dumpbin 証跡: 配布 exe は `VCRUNTIME140.dll` を動的リンク＝VCRedist 前提 or crt-static 化が M9.7 前の課題）
- **M11（2台目参加フロー）**: `04174bb` B2 worker.toml 生成・検証（純粋ロジック）/ `e8897f8` B3 `ConfigWriter` 抽象+スタブ / `8ae9d36` B4 サービス再起動（Stop→Start）/ `c833802` B1 LAN IPv4 列挙（`GetAdaptersAddresses` FFI）/ `3d64cc2` 自己レビュー修正（B1 FFI アラインメント修正＝`Vec<MaybeUninit<IP_ADAPTER_ADDRESSES_LH>>`、B4 stop-settle）/ `31326b1` B5 「Join a cluster」ウィザードパネル

### 未コミット（working tree）＝残タスク B6 の RED テストのみ
```
 M crates/gui/src/app/config.rs        # B6 の #[cfg(test)] テスト lan_daemon_addrs_uses_selected_concrete_ip（実装は未記述）
 M crates/gui/tests/status_client.rs   # B6 の統合テスト（lan_daemon_addrs を import）
```
`pub fn lan_daemon_addrs` の**本体・トグル UI・mod.rs 配線は未実装**。この状態は `cargo build`（lib）は通るが `cargo test`（テスト）は `unresolved import lan_daemon_addrs` で失敗する。

> **なぜ B6 が終わっていないか**: Claude→codex-companion 経由の転送で、Codex の patch 適用が **CRLF 行末 / PowerShell クォート**で繰り返し失敗し、小さな RED テストは入ったが ~40 行の実装 patch が適用できなかった。**Codex がメインとして自分のファイルツールで直接編集すれば、この問題は起きない**はず。

## 最初のタスク: B6 を完成させる

**目標**: 既存の RED テストを通す実装を書き、コミットする（テストは書き換えない）。詳細は `docs/superpowers/plans/2026-07-02-gui-completion.md` の **Task B6**。要点:

1. `crates/gui/src/app/config.rs` に `pub fn lan_daemon_addrs(lan_ip: &str, coord_port: u16, fileserver_port: u16) -> (String, String)` を定義 → `("<lan_ip>:<coord_port>", "<lan_ip>:<fileserver_port>")`。**`0.0.0.0` を返してはいけない**（roadmap §2.4: agent は file-server の `local_addr()` を `agent_fileserver` として worker に渡すため、bind は routable な具体 IP でなければならない）。
2. `ConfigPanel` に「Allow LAN workers」セクションを追加:
   - チェックボックスは `ConfigModel.cluster_token_set` が false の間は無効（ツールチップで理由表示）。`crates/agent/src/run.rs:39-62` が「token 無しの非 loopback bind」を拒否するため。
   - `crate::net::lan_ipv4_candidates()` から LAN IP を選ぶ `ComboBox`。
   - 「Apply LAN settings」ボタンで `ConfigEdit` の `coord_addr`/`fileserver_addr` = `lan_daemon_addrs(<選択IP>, 50070, 50072)` を作り、既存の `UiCommand::SetConfig` 経路で送信 → その後 **daemon** を再起動。
3. 配線: `ConfigPanel::render` は現在 `(ui, commands)` で `ServicesPanel` を持たない。`&mut super::services::ServicesPanel` と `&egui::Context` を `ConfigPanel::render` に渡し、`crates/gui/src/app/mod.rs` の `Tab::Settings => self.config.render(...)` を `&mut self.services, &ctx` を渡すよう更新。Apply で `services.restart(Service::Daemon, ctx)` を呼ぶ（`join_panel` が既に `&mut services` を受けているので同型）。`ServicesPanel::restart` の `#[allow(dead_code)]` が不要になれば外す。
4. `SetConfig` が `permission_denied`（admin ゲート、既定 OFF、ADR 0016）を返したら、§2.0 / `status_admin` 有効化を案内する notice を出す（既存 `save()` の SetConfig 応答処理を流用）。

**検証してコミット**: `cargo test -p sembazuru-gui`（pre-written の `lan_daemon_addrs_uses_selected_concrete_ip` と status_client 統合テストを含めて pass）→ `cargo fmt -p sembazuru-gui` → `cargo clippy -p sembazuru-gui --all-targets -- -D warnings` → コミット。メッセージ:
```
M11: daemon「Allow LAN workers」トグル（具体 LAN IP・token 前提・再起動）

Co-Authored-By: Codex <noreply@openai.com>
```
`crates/gui/` 以外に触れない。B6 完了で Part B（M11）完了。

## 重要な設計コンテキスト: §2.0 config-write（外部依存）

M11 の「非昇格 GUI から config を変更する」は既定で二重に塞がれている: (a) daemon の `SetConfig` RPC は admin ゲート既定 OFF（`crates/agent/src/status.rs:148-176`、ADR 0016）、(b) `%ProgramData%\Sembazuru` の config ファイルは既定 ACL で非昇格 GUI が上書き不可。B3 の `ConfigWriter` 抽象＋`StubConfigWriter`（`MechanismUnconfigured` を返す）はこのため。**どの書込機構を採るか（status_admin 有効化 / インストーラで ACL 付与 / 昇格ヘルパ）は SEC-001/ADR 0016 の姿勢に触れるオーナーの外部セキュリティ判断**で、本 GUI 作業のスコープ外。B5 の Join ウィザードと B6 の daemon トグルは、この機構が決まるまでスタブ／admin ゲートの graceful 処理で degrade する設計。詳細は roadmap `docs/superpowers/specs/2026-07-02-sembazuru-roadmap.md` §2.0。

## レビュー済み所見と follow-up（軽微、ブロッカーでない）

- B1 `net.rs`: `GetAdaptersAddresses` が `ERROR_BUFFER_OVERFLOW`（15KB 超＝多アダプタ）時に再試行せず空を返す（契約は「失敗時は空→手入力」なので許容）。多 VPN/NIC 環境で候補ゼロになり得る。
- B5 `join_panel.rs`: `cluster_token` を `ConfigPanel` と違い Drop で zeroize していない（秘密衛生の小差。セキュリティは外部管理だが揃えるなら follow-up）。
- A4 トレイヒント: nav ラベルで、ウィンドウ非表示後に表示されるため次回開いた時に出る挙動。トレイのバルーン通知の方が意図に合う（UX follow-up）。
- A3 ツールチップは「Join タブ」を参照するが、B5 で Join タブは実在するので整合済み。

## この後の全体計画（roadmap: `docs/superpowers/specs/2026-07-02-sembazuru-roadmap.md`）

GUI 完成（M11+M12）後の順序（A案）:
- **M9.6** 初の実 GitHub リリース（`.github/workflows/release.yml` にタグ push、未署名なら draft）
- **M9.7** 単機・実機インストール受け入れ（🖥️1台。CRT 依存 = A6 の VCRedist 課題を解消）
- **M10** 実2台 LAN join + 分散ビルド + **実 NIC での速度実測**（🖥️2台、make-or-break。GO=分散がローカルより速い ≥~1.3x / KILL / NARROW）
- 以降 Horizon 2（clang-cl 小チーム橋頭堡）/ Horizon 3（MSVC 判断・スケール）

## 品質ゲート / 運用

- Rust: `cargo fmt` + `cargo clippy -D warnings` + `cargo test -p sembazuru-gui`（GUI 変更時）。
- 第二レビューは非メイン AI（Claude, headless）へ: 例 `claude -p "<brief>" --permission-mode plan`（読み取り consult）や `.claude/agents/impl-reviewer.md` を渡す。
- コミットは小さく単一目的・日本語メッセージ・マイルストーン参照。**push はユーザー**。
- ブランチ `gui-completion` は main へ未マージ・未 push。マージ/push はユーザー判断。
