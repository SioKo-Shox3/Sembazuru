# PROGRESS — Sembazuru

## Done
- 8444fbd: VC++ x64/x86 を同梱する Burn Setup.exe と Release ワークフローを追加。ローカルで MSI/Bundle の内容と SHA を検証済み。公開は未実施。
- 2156d47: CREATE_NO_WINDOW の test 限定 A/B 診断を追加。製品の起動 flags は未変更。独立評価と契約検査済み、SCM 実測は未実施。
- T-001: h2 0.4.16 と webbrowser 1.2.2 へ最小更新。cargo-deny、fmt、clippy、workspace test の保存済み証拠を確認し、独立評価 PASS。配布全体の合格とは区別する。
- 2026-09-08 開始検査: `rustup run 1.97.0 cargo test -p sembazuru-worker --lib session0_ --locked` → `7 passed; 0 failed; 156 filtered out`。fmt --all --check と clippy --all-targets --locked -- -D warnings も exit 0。
- GitHub の chore/two-pc-preparation は 2156d47 と一致、main は 8b91020。開始時の作業ツリーは clean。

## In progress
- T-002: Release の dry run 34169478977 を 2156d47 で開始済み。

## Next
- T-003: Session 0 診断 workflow の default branch 登録後に実測する。現在 dispatch は HTTP 404。
- C++ の P0 cross-bitness negative control が Windows 2022/2025 の両方で 5 分 timeout。M2 は CI で未到達。ローカル M2 は cl の起動失敗で比較前に終了した。
- GUI Join は StubConfigWriter のまま。保存する token と machine store の境界、昇格方法の設計を固めてから実装する。
- 全体の完了にはインストール、参加設定、installed worker 実行、C++/M2、公開ダウンロードの検証が必要。

## Notes
- 最新 main CI: https://github.com/SioKo-Shox3/Sembazuru/actions/runs/34032907718 。ログは target/release-preparation/ci-34032907718-failed.log を取得して確認済み。
- main CI の installed worker は exit=-1073741502 (0xC0000142)。install/repair/ACL/uninstall は通過。Job UI の緩和では解決しなかった。
- ローカル worker/SCM 起動は前セッションの自動承認審査で拒否された。別 CLI、子、ループからも迂回実行しない。通常の cargo 単体・契約テストと静的なパッケージ展開は可。
- 公開版は v0.0.3 のまま。現在の dry run も 0.0.3 だが、既存 Release を上書きしない。次版は修正とゲート完了後に用意する。
- T-001 の検証ログは `.harness/runs/20260908-082159/verify-T-001-1.txt` から `verify-T-001-4.txt` に保存。workspace test のログにある `sandbox_probe_record_child` の FAILED は親テストが意図的に起動した子プロセスの診断出力で、cargo test 全体は exit 0。
- このターンで新たな git push の指示はない。新規変更は作業ブランチへのコミットまで。
