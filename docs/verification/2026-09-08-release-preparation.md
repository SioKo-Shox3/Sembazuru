# GitHub での配布パッケージ検証（2026-09-08）

GitHub 上で MSI と Setup.exe のビルドは成功した。ただしインストール後の worker 実行が失敗しており、新しい PC で利用できる公開版には達していない。
診断レコードの環境依存と Rust 1.98.1 の lint はローカルで修正・検証済み。修正版の GitHub 実測は未実施。

## 対象

- push 済みの commit: `2156d473e934483c85257aa081cb6cfcf3a6a3fa`。
- [Draft PR #4](https://github.com/SioKo-Shox3/Sembazuru/pull/4)。main は `8b91020716d90a172e80be4f3eea5a2ded01daa1` で未統合。
- バージョンは 0.0.3。今回の手動実行では Release を公開しておらず、既存 v0.0.3 を上書きしていない。
- 依存関係を更新した `e463b93` はローカルのみ。このページの GitHub 実行には含まれない。

## 結果

| 検証 | 結果と証拠 |
|---|---|
| [Release 34169478977](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/34169478977) | workspace テストで exit 1。worker は `153 passed; 1 failed; 9 ignored`。MSI/Bundle 生成に未到達、artifact 0 件。 |
| [PR CI の installer job](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/34169793558/job/101887784025) | MSI/Bundle はどちらも `Build succeeded. 0 Warning(s) 0 Error(s)`。 |
| 同 installer job の MSI 検証 | install/repair/ACL/uninstall が成功。`MSI REPAIR PASS: exit=0`、`UNINSTALL CLEANUP PASS` を確認。 |
| 同 installer job の worker 実行 | `installed worker plain control failed: exit=-1073741502 states-ok=True`。0xC0000142 で失敗し、artifact upload は未到達。 |
| [PR CI 34169793558](https://github.com/SioKo-Shox3/Sembazuru/actions/runs/34169793558) | C++ は Windows 2022/2025 の両方で P0 negative control が 5 分 timeout。M2 に未到達。LocalIntake の権限分離は成功。 |
| 同 PR CI の Rust | fmt は成功。Rust 1.98.1 の `chunks_exact_to_as_chunks` lint が tracer の determinism.rs 2 箇所、format.rs 1 箇所で失敗。 |
| 同 PR CI の依存検査 | h2 0.4.14 と webbrowser 1.2.1 の脆弱性検査で失敗。ローカルの e463b93 では修正版に更新し、cargo-deny が全項目成功。 |

Release の実際の失敗は `private_station_unnamed_create_rejects_connected_logon_station`。
`fresh unnamed station supported; design review required` と記録され、テストの想定と GitHub runner の挙動が異なる。
ログ中の `sandbox_probe_record_child` の stale destination による子の失敗は、親の negative test が確認する期待結果であり、Release を失敗させた項目ではない。

この結果は Bundle の新規 PC へのインストール成功を証明しない。CI のインストール検査は MSI を使っており、MSI/Bundle とも取得可能な artifact は残らなかった。

## 証拠と残件

実行したログ取得コマンド `gh run view 34169478977 --log` は exit 0。取得後に本文を開き、対象 commit、失敗箇所、終端結果を確認した。
保存ログは `target/release-preparation/release-34169478977.log`、`.harness/pr-4-installer.log`、`.harness/pr-4-rust.log`。
artifact 一覧は GitHub API で取得し、Release run と PR CI の両方が 0 件だった。

- [T-001](../../blocked/T-001.md): 親の期待値から不要な環境収集を除き、cmd 経由の workspace テストも成功。依存更新の検証は完了。
- [T-003](../../blocked/T-003.md): 登録済み Release から同じコミットの診断を呼ぶ定義を追加。修正の push と実測を待つ。診断専用 workflow の main 登録は先行条件ではない。
- installed worker の 0xC0000142、C++/M2、GitHub 固有の unnamed station 初回成功分岐は未解決・未測定。
- GUI Join は設定保存が未実装。参加設定と実際の二台間実行、公開ダウンロードは未検証。

## ローカル修正後の確認

| 対象 | 結果 |
|---|---|
| 親の環境依存（4c3b779） | cmd/PowerShell の対象テスト、fmt、Clippy、独立安全性評価、自動再検証が成功。子の環境の厳密な検査は維持。 |
| Rust 1.98.1 の lint（7daf3d8） | fmt/Clippy は exit 0。tracer/config-store/CAS は `288 passed; 0 failed; 1 ignored`。ハッシュ1,030ケースとtrace446ケースで変更前後・同一入力二回の出力が一致。 |
| unnamed station（c16ba9c） | 最初のハンドルを保持した二回目の生成衝突を検査。対象テストと安全性評価は成功。ローカルは初回183の分岐だけを実測。 |
| Rust 全体（c16ba9c） | `cmd.exe /d /c "rustup run 1.98.1 cargo test --workspace --locked"` → `exit=0`、worker は `154 passed; 0 failed; 9 ignored`。T-006 の修正前には1.97.0の cmd 経由全体テストも成功。 |

証拠は `.harness/T-004-review.txt`、`.harness/runs/20260908-092538/`、`.harness/T-005-tests.log`、
`.harness/T-005-output-equivalence.log`、`.harness/T-005-review.txt`、`.harness/T-006-review.txt`、
`.harness/T-001-workspace-after-T004.log`、`.harness/final-rust-workspace.log`。
Rust の成功は C++/M2 や installed worker の起動成功を代替しない。

## GitHub 実測の再開経路

修正を push 後、`gh workflow run release.yml --ref chore/two-pc-preparation` で同じコミットの診断を呼ぶ。
ブランチ指定の手動実行だけが対象で、診断 job は `contents: read`、secret 非継承、SHA 固定 checkout を使う。
パッケージ job の結果を待たずに診断を実行できる。[同一リポジトリの相対パス参照は呼び出し元と同じコミットを使う](https://docs.github.com/en/actions/how-tos/reuse-automations/reuse-workflows)。
実行後は対象 SHA、A/B の flags、Job UI、分類、cleanup、既存 worker の前後一致をログで確認する。
この定義の構文検査は `actionlint v1.7.12` で成功し、独立安全性評価も通過した。GitHub 上の実行成功はまだ確認していない。
