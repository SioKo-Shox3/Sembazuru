# PROGRESS — Sembazuru

## Done
- 8444fbd: VC++ x64/x86 を同梱する Burn Setup.exe と Release ワークフローを追加。ローカルで MSI/Bundle の内容と SHA を検証済み。公開は未実施。
- 2156d47: CREATE_NO_WINDOW の test 限定 A/B 診断を追加。製品の起動 flags は未変更。独立評価と契約検査済み、SCM 実測は未実施。
- e463b93: h2 0.4.16 と webbrowser 1.2.2 へ最小更新。cargo-deny、Rust 1.97.0 の fmt/clippy は成功。T-001 全体は下記の再検証失敗で blocked。
- 2026-09-08 開始検査: `rustup run 1.97.0 cargo test -p sembazuru-worker --lib session0_ --locked` → `7 passed; 0 failed; 156 filtered out`。fmt --all --check と clippy --all-targets --locked -- -D warnings も exit 0。
- GitHub の chore/two-pc-preparation は 2156d47 と一致、main は 8b91020。開始時の作業ツリーは clean。
- T-002: GitHub の Release と PR CI の実ログを取得して確認。結果は docs/verification/2026-09-08-release-preparation.md。PR CI では MSI/Bundle の生成が成功、installed worker は 0xC0000142。Release は診断テストで失敗し、どちらの run も artifact 0 件。公開準備の完了ではない。

## In progress
- T-001: cmd 経由の診断レコード往復テストで environment text が再現。依存更新を保持し、詳細と再開条件を blocked/T-001.md へ記録した。
- T-003: 診断 workflow の default branch 登録待ち。blocked/T-003.md。GitHub 上での実測は未実施。

## Next
- M1 で blocked 項目を解消する修正範囲を決める。現在の一覧は T-001/T-003 が blocked、T-002 の結果確認が done。新規 todo を作るまで同じ一覧を再実行しない。
- Session 0 診断 workflow の default branch 登録後に実測する。現在 dispatch は HTTP 404。
- Rust 1.98.1 の tracer lint と、Release を止めた private_station_unnamed_create_rejects_connected_logon_station の想定を修正・検証する。
- C++ の P0 cross-bitness negative control が Windows 2022/2025 の両方で 5 分 timeout。M2 は CI で未到達。ローカル M2 は cl の起動失敗で比較前に終了した。
- GUI Join は StubConfigWriter のまま。保存する token と machine store の境界、昇格方法の設計を固めてから実装する。
- 全体の完了にはインストール、参加設定、installed worker 実行、C++/M2、公開ダウンロードの検証が必要。

## Notes
- 最新 main CI: https://github.com/SioKo-Shox3/Sembazuru/actions/runs/34032907718 。ログは target/release-preparation/ci-34032907718-failed.log を取得して確認済み。
- main CI の installed worker は exit=-1073741502 (0xC0000142)。install/repair/ACL/uninstall は通過。Job UI の緩和では解決しなかった。
- ローカル worker/SCM 起動は前セッションの自動承認審査で拒否された。別 CLI、子、ループからも迂回実行しない。通常の cargo 単体・契約テストと静的なパッケージ展開は可。
- 公開版は v0.0.3 のまま。現在の dry run も 0.0.3 だが、既存 Release を上書きしない。次版は修正とゲート完了後に用意する。
- T-001 の PowerShell での成功ログは `.harness/runs/20260908-082159/verify-T-001-1.txt`〜`verify-T-001-9.txt`。一方、cmd を使う runner の recheck は 2 回 exit 101。親の collect が特殊な環境変数の名前を拒否することを単独テストで再現した。成功ログだけでは完了条件を満たさない。
- 20260908-082159 の自動反復は、コード変更なしの再検証が 2 回失敗したため所有プロセスを確認して停止した。実行中の反復は残していない。根拠は .harness/loop-state.json と各 recheck ログ。記録上の done を blocked に訂正した。
- このターンで新たな git push の指示はない。新規変更は作業ブランチへのコミットまで。
