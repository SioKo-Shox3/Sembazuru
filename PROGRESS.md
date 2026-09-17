# PROGRESS — Sembazuru

## Done
- 8444fbd: VC++ x64/x86 を同梱する Burn Setup.exe と Release ワークフローを追加。ローカルで MSI/Bundle の内容と SHA を検証済み。公開は未実施。
- 2156d47: CREATE_NO_WINDOW の test 限定 A/B 診断を追加。製品の起動 flags は未変更。独立評価と契約検査済み、SCM 実測は未実施。
- e463b93 / T-001: h2 0.4.16 と webbrowser 1.2.2 へ最小更新。cargo-deny、Rust 1.97.0 の fmt/clippy と独立評価は成功。T-004 後に cmd 経由の workspace 全体テストも exit 0 となり、検証未完を解消。証拠は .harness/T-001-workspace-after-T004.log。
- 2026-09-08 開始検査: `rustup run 1.97.0 cargo test -p sembazuru-worker --lib session0_ --locked` → `7 passed; 0 failed; 156 filtered out`。fmt --all --check と clippy --all-targets --locked -- -D warnings も exit 0。
- 開始確認時の GitHub chore/two-pc-preparation は 2156d47、main は 8b91020。開始時の作業ツリーは clean。今回の修正は未 push。
- T-002: GitHub の Release と PR CI の実ログを取得して確認。結果は docs/verification/2026-09-08-release-preparation.md。PR CI では MSI/Bundle の生成が成功、installed worker は 0xC0000142。Release は診断テストで失敗し、どちらの run も artifact 0 件。公開準備の完了ではない。
- T-004: 診断レコードの親比較を process security 専用収集へ分離し、子の環境全体収集・codec 検証・厳密比較を維持。cmd、PowerShell、fmt、worker clippy の反復1検証と独立安全性評価を確認して完了。
- T-005: Rust 1.98.1 の fmt と workspace Clippy が exit 0。tracer/config-store/CAS の結合テストは 288 passed、0 failed、1 ignored。変更前後および同一入力二回の出力比較はハッシュ 1,030 ケース・trace 446 ケースで一致。安全性・決定性の独立評価 PASS。証拠は .harness/T-005-clippy-2.log、T-005-tests.log、T-005-output-equivalence.log、T-005-review.txt。C++/M2 全体の未合格は残る。
- c16ba9c / T-006: unnamed station の初回成功時にハンドルを維持して二回目の生成衝突を検査する形へ修正。対象テスト、fmt、Clippy は exit 0。独立安全性評価は本文 PASS、blocking なし（回答の先頭は Markdown 見出し）。ローカルは初回183の分岐だけを実測し、初回成功時の分岐は次回 GitHub CI で確認する。証拠は .harness/T-006-test.log、T-006-fmt.log、T-006-clippy.log、T-006-review.txt。
- c16ba9c 時点の最終 Rust 全体検証: `cmd.exe /d /c "rustup run 1.98.1 cargo test --workspace --locked"` が exit 0。worker は `154 passed; 0 failed; 9 ignored`。証拠は .harness/final-rust-workspace.log。
- e5385d6 / cf26037 / T-007: Release のブランチ指定の手動実行から、同じコミットの Session 0 診断を独立 job として呼ぶ定義を追加。contents: read・secret 非継承を維持し、タグ指定の手動実行も除外。actionlint と独立安全性評価が PASS。証拠は .harness/T-007-actionlint-final.log、T-007-review.txt、T-007-review-2.txt。main 登録を要求する記録を更新済み。

- T-008: Detours の cross-bitness helper が `WaitForSingleObject(..., INFINITE)` で rundll32 を待つため、sibling DLL が無い場合に永久に止まっていた。15 秒の有界待ちと、KILL_ON_JOB_CLOSE のジョブによるベストエフォートの後始末を vendored Detours に入れ、無期限待ちを既存の fail-closed が扱える FALSE に変換した。P0 ゲートはローカルで 5 分 timeout から 91.4 秒の PASS になり、rundll32 と probe の残留はゼロ。M7.3 cross-bitness 成功経路、trace_write_batch の x64/x86、nt_rename、hooks の ctest 3 件も PASS。証拠は .harness/T-008-p0-injection.log、T-008-m7-inject32.log、T-008-regression-gates.log。
- T-008 で捨てた案: 不在の事前判定は WOW64 リダイレクトと相対名の探索順のせいで、このプロセスからは確定できず、誤ると正常な注入を拒否する。後始末のジョブを必須にすると、UI 制限付きで breakaway を許さない製品ワーカーのジョブ内で注入が失敗しうる。rundll32 のエラーダイアログはプロセスのエラーモードでは抑止できない（実測）。

- T-009: `fb02b72` が launcher の VFS 経路に attestation を必須化した一方、vfs_redirect・vfs_compile・vfs_bench がそれを用意しておらず、注入の前に落ちていた。生成と破棄を hooks/test/vfs_attestation_bootstrap.ps1 に集約し、4ゲートが同じ契約を共有するようにした。各ゲートの判定条件と製品コードは変更していない。3件とも PASS。証拠は .harness/T-009-gates.log。
- **M2 決定性ハーネスがローカルで PASS した**。`DETERMINISM OK: 2 output(s) reproduce`、`GATE PASS msvc: corpus reproduces byte-for-byte`。以前「cl の起動失敗で比較前に終了」と記録していたのは、下の Notes にある古い modules.obj と同じビルドツリー汚染が原因。clang-cl は不在のため SKIP で、CI 側の担当。証拠は .harness/T-009-determinism.log。

- T-003 完了: run 35208068643 で Session 0 の A/B を初めて実測した。対象 SHA・診断 job の存在・flags・Job UI・分類・cleanup・worker 前後一致をすべて実ログで確認。結果は **NO_WINDOW_NOT_SUFFICIENT** で、両アームとも 0xc0000142。**CREATE_NO_WINDOW は製品に適用しない。** 記録は docs/verification/2026-09-17-session0.md。
- 同じ実測から真因が判明した。アクションは Medium 整合性 (8192、sandbox.rs:510) で、サービスのウィンドウステーションとデスクトップの DACL はサービス SID と Administrators にしか許可がない。StationAccess も DesktopAccess も allowed=false gle=5。開けないプロセスは初期化に失敗して 0xC0000142 になる。起動フラグでは直らない。T-011 として起票。

## In progress

- T-011: installed worker の 0xC0000142 は T-003 と同一の問題で、失敗するのは `--no-vfs` の plain control（フック DLL は関与しない）。実測で真因はウィンドウステーションとデスクトップへのアクセス拒否と判明した。解の方向が未決で、特権境界の設計なので GPT 側へ回す。
- T-010: GUI Join。方式は storectl の helper 化に決定済み。取引機構 (MachineTokenUpdate) と認可 (storectl の authorize) は実装済みで、足りないのは join 動詞と配置と GUI 側 writer。昇格した子への秘密の受け渡しだけが未決。

## Next
- T-011 と T-010 の未決分岐を GPT 側で詰める。どちらも特権境界の設計。
- `private_station_unnamed_create_cannot_allocate_per_action_station` の初回成功分岐を GitHub runner で確認する。
- 次に CI を回すとき、C++ job で新たに見えるようになるのは M2 以降の段。ローカルでは M2・smoke・VFS 3件が通るが、clang-cl を要する段はローカルで未実行なので CI が初出になる。
- GUI Join は StubConfigWriter のまま。MachineTokenUpdate は machine token/daemon設定/worker設定を同じ journal で扱えるが、storectl の7固定動詞には Join 保存がなく、GUI ConfigWriter も token を表現しない。既存の固定パスと認可を維持する Join 専用経路が必要。
- 全体の完了にはインストール、参加設定、installed worker 実行、C++/M2、公開ダウンロードの検証が必要。
- T-004 の証拠は `.harness/runs/20260908-092538/verify-T-004-1.txt`〜`verify-T-004-4.txt`。各ファイルを開いて cmd/PowerShell のテスト結果、不正環境名拒否、fmt、clippy の exit 0 を確認した。

## Notes
- ローカルの `hooks/build/` には旧ツールチェーンが生成した `modules.obj` が残っており、`DetourFindPayloadEx` の本体が 1 バイトの nop だけになっていた。modules.cpp が変わらないため MSBuild が再利用し続け、注入された子プロセスが `DllMain` の先頭で int 3 を踏んで 0xC0000142 で落ちていた。`/t:Rebuild` で解消。ソース側の欠陥ではないので、CI の installed worker の 0xC0000142 と同一視しない。ローカルの hooks ゲートが原因不明で落ちるときは、まず強制リビルドで切り分ける。
- T-007 の残る実測条件: 最初に GitHub run へ診断 job が現れることと SHA を確認する。Release のパッケージ job も同時に動き、署名 secret が設定されていれば既存の署名処理も走る。ブランチ ref では公開ステップを実行しない。
- T-006 の非阻害指摘: 既存の test 専用 AuditWindowStation::close は失敗時に Drop から再試行する。今回の成功時は所有権を消去して一度だけ閉じる。未知の二回目エラーは fail にし、Windows の全環境で183になることは未保証。全体の復元/close に関する既存ヘルパーの改善は別件として残す。
- 独立評価 CLI の終了フックが未コミットの T-005 を f14deaa として自動保存した。変更は依頼差分と一致し、評価 PASS 後に結果記録と件名を整えて 7daf3d8 とした。以降は検証済みソースをコミットしてから、その明示範囲を評価する。展開フックは変更しない。
- T-005 の非阻害指摘: config-store のディレクトリ列挙パーサは CAS と同じ合成破損バッファの直接検査がない。実ファイルシステム経由の検査は成功し、今回の byte-copy・境界検査は不変。将来パーサを変更する際に補う。以降の検証ログにはコマンドと終了コードも保存する。
- 最新 main CI: https://github.com/SioKo-Shox3/Sembazuru/actions/runs/34032907718 。ログは target/release-preparation/ci-34032907718-failed.log を取得して確認済み。
- main CI の installed worker は exit=-1073741502 (0xC0000142)。install/repair/ACL/uninstall は通過。Job UI の緩和では解決しなかった。
- ローカル worker/SCM 起動は前セッションの自動承認審査で拒否された。別 CLI、子、ループからも迂回実行しない。通常の cargo 単体・契約テストと静的なパッケージ展開は可。
- 公開版は v0.0.3 のまま。現在の dry run も 0.0.3 だが、既存 Release を上書きしない。次版は修正とゲート完了後に用意する。
- T-001 の PowerShell での成功ログは `.harness/runs/20260908-082159/verify-T-001-1.txt`〜`verify-T-001-9.txt`。一方、cmd を使う runner の recheck は 2 回 exit 101。親の collect が特殊な環境変数の名前を拒否することを単独テストで再現した。成功ログだけでは完了条件を満たさない。
- 20260908-082159 の自動反復は、コード変更なしの再検証が 2 回失敗したため所有プロセスを確認して停止した。実行中の反復は残していない。根拠は .harness/loop-state.json と各 recheck ログ。記録上の done を blocked に訂正した。
- このターンで新たな git push の指示はない。新規変更は作業ブランチへのコミットまで。
