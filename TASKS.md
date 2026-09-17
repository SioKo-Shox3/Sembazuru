# TASKS — Sembazuru

目的: GitHub Releases から Windows 11 x64 の新しい PC に導入し、LAN 上の実行に参加できる状態にする。
診断テストと CI lint の修正、GitHub 診断の呼び出し定義を検証済みで、作業ブランチは push 済み。
現在は Session 0 の実測待ち。公開、未測定の起動条件の製品適用、GUI 保存方式の決定は未完。

## T-001: 依存関係の脆弱性検査エラーを修正する
- status: done
- done-when: h2 と webbrowser を修正版へ最小更新し、cargo-deny、fmt、clippy、workspace テストの実出力を確認する。差分の独立評価を通す。配布全体の合格とは区別する。
- verify: `cargo deny check advisories bans licenses sources`
- verify: `rustup run 1.97.0 cargo fmt --all --check`
- verify: `rustup run 1.97.0 cargo clippy --all-targets --locked -- -D warnings`
- verify: `rustup run 1.97.0 cargo test --workspace --locked`
- paths: Cargo.lock, TASKS.md, PROGRESS.md, LESSONS.md, NEXT_FINDINGS.md, blocked/T-001.md, .harness/runs/**
- notes: CI 34032907718 の RUSTSEC-2026-0258 (h2 0.4.14、修正版 >=0.4.16) と RUSTSEC-2026-0257 (webbrowser 1.2.1、修正版 >=1.2.2)。一次資料を取得して確認し、対象 package の patch 更新に限定する。例外登録や検査の緩和は禁止。予期しない広範な依存更新は止めて記録する。worker/transport の攻撃面とビルド出力への影響を評価で明示する。C++/M2 の未合格をこのタスクのテストで代替しない。

## T-002: GitHub のセットアップ生成結果を検証する
- status: done
- done-when: Release run 34169478977 の終端結果、対象 SHA、実ログを開いて記録する。成功時は MSI と Bundle artifact を取得してハッシュと同梱内容を確認する。失敗時は最初の失敗と再現条件を記録し、生成成功と報告しない。
- verify: `gh run view 34169478977 --log`
- paths: docs/verification/2026-09-08-release-preparation.md, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, blocked/T-002.md, .harness/runs/**, target/release-preparation/**
- notes: 対象は既に push された 2156d473e934483c85257aa081cb6cfcf3a6a3fa。T-001 の未 push 差分を含む成果物ではない。workflow_dispatch は公開 Release を作らない。既に run は開始済みなので重複 dispatch しない。Setup.exe/MSI は実行しない。WiX extract/decompile は可。少なくとも VC++ x64/x86 と MSI、製品の x64/x86 DLL と storectl の同梱を静的に確認する。失敗の調査記録が完了しても公開準備完了ではない。

## T-003: GitHub runner で Session 0 の起動フラグを測定する
- status: blocked
- done-when: T-007 を含む作業ブランチの SHA を実行前に記録し、GitHub run と診断 job の対象 SHA の一致を確認する。その診断を hosted runner で実測し、A/B の flags、Job UI、分類、cleanup、worker 前後一致を実ログで確認する。
- verify: `rustup run 1.97.0 cargo test -p sembazuru-worker --lib session0_ --locked`
- paths: docs/verification/2026-09-08-session0.md, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, blocked/T-003.md, .harness/runs/**, target/release-preparation/**
- notes: 診断名への直接 dispatch は default branch 未登録により HTTP 404。T-007 で登録済み Release から同じコミットを呼べる定義を追加し、main 登録の前提を外した。残りは修正の push と、gh workflow run release.yml --ref chore/two-pc-preparation による実測。git push、API による同等の直接反映、PR の無断マージをしない。上記 verify は診断の契約検査だけで、実測ログなしに done にしない。ローカル SCM 診断は禁止。

## T-004: 診断レコードの比較を親の環境変数から独立させる
- status: done
- done-when: 親の権限と Job の比較に不要な環境変数を読まず、子の環境全体の収集・厳密な codec 検証・期待値比較を維持する。往復テストが cmd と PowerShell の両方で成功し、不正な環境名の拒否も成功する。test モジュールだけの差分で安全性評価を通す。
- verify: `cmd.exe /d /c "rustup run 1.97.0 cargo test -p sembazuru-worker --lib sandbox::tests::sandbox_probe_record_round_trip_uses_file_not_stdout --locked -- --exact"`
- verify: `pwsh -NoProfile -Command "rustup run 1.97.0 cargo test -p sembazuru-worker --lib sandbox_probe_record_ --locked; exit $LASTEXITCODE"`
- verify: `rustup run 1.97.0 cargo fmt --all --check`
- verify: `rustup run 1.97.0 cargo clippy -p sembazuru-worker --all-targets --locked -- -D warnings`
- paths: crates/worker/src/sandbox.rs, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, blocked/T-001.md, blocked/T-004.md, .harness/**
- notes: メインが collect_process_security を切り出して実装する。collect はその後 normalized_environment を収集する従来の完全レコード経路として保持。往復テストの親は collect_process_security、子は collect のまま。環境検査を緩めたり process environment を書き換えない。製品の token/Job/flags/ACL/codec 変更、ローカル SCM/製品 worker 起動、push/merge/publication は対象外。既存の Cargo.lock 差分の再評価は不要。この新しい worker test 差分だけを評価する。
- execution: メインがソース変更を実装済み。上記4検査の出力は .harness/T-004-cmd.log、T-004-pwsh.log、T-004-fmt.log、T-004-clippy.log。独立した安全性評価は .harness/T-004-review.txt に保存済みで実際に開いて確認すること。評価後はコメント2行の明確化だけ。反復ではソースを追加変更せず、指定検査と証拠確認、T-004 の記録更新、明示列挙によるコミットを行う。他タスクへ進まず、新たな評価者を呼ばない。失敗時はソースを変更せず blocked にして具体的な出力を記録する。反復1の再検証は .harness/runs/20260908-092538/verify-T-004-1.txt〜verify-T-004-4.txt に保存し、4件すべて exit_code=0 を開いて確認した。

## T-005: Rust 1.98.1 の CI lint に対応する
- status: done
- done-when: 定数サイズの chunks_exact を as_chunks に置き換え、SHA-256 の既知ベクトルと trace decode の境界検査を維持する。Rust 1.98.1 の fmt/clippy と tracer テストが成功する。ハッシュ・文字列の出力が変わらないことを評価する。
- verify: `rustup run 1.98.1 cargo fmt --all --check`
- verify: `rustup run 1.98.1 cargo clippy --all-targets --locked -- -D warnings`
- verify: `rustup run 1.98.1 cargo test -p sembazuru-tracer --locked`
- verify: `rustup run 1.98.1 cargo test -p sembazuru-config-store -p sembazuru-cas --locked`
- paths: crates/tracer/src/determinism.rs, crates/tracer/src/format.rs, crates/config-store/src/windows.rs, crates/cas/src/store.rs, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, blocked/T-005.md, .harness/**
- notes: メインが先に実装する。警告の allow や toolchain の downgrade で検査を回避しない。Rust 1.98.1 はローカルにも用意する。新たな lint が他のファイルに見つかったら記録し、内容を確認して範囲を更新する。C++/M2 の既知の不合格を tracer の単体テストで代替したと報告しない。
- scope: 同じ定数サイズの変換が config-store/CAS のディレクトリ列挙にもある。偶数長・境界・整列に関する検査と byte-copy を保持し、as_chunks への置換だけを行う。config-store の test モジュール内の重複 import も削除する。攻撃面とメモリ安全性を独立評価に含める。出力比較用 .harness/T-005-output-equivalence.rs は変更前後のハッシュと trace decode を比較し、同じ入力で二回の出力一致も検査する。製品の ACL や codec 仕様、ハッシュ方式の変更が必要なら止めて別タスクとする。

## T-006: unnamed station の診断をログオン単位の生成契約へ修正する
- status: done
- done-when: 最初の NULL 名による生成が失敗する環境と、ログオン用 station を初回生成できる環境を区別する。初回成功時はそのハンドルを保持して二回目の CWF_CREATE_ONLY を試し、二回目の成功を拒否する。元の process station の復元と全生成ハンドルの close を検査する。未知の失敗を衝突成功としない。test モジュールだけの変更を安全性評価する。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-worker --lib private_station_unnamed_create_ --locked -- --nocapture`
- verify: `rustup run 1.98.1 cargo fmt --all --check`
- verify: `rustup run 1.98.1 cargo clippy -p sembazuru-worker --all-targets --locked -- -D warnings`
- paths: crates/worker/src/sandbox.rs, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, blocked/T-006.md, .harness/**
- notes: Microsoft CreateWindowStationW の NULL 名は呼び出しプロセスのログオンセッション ID から命名される。初回に current と違う station を作れても action 専用性を示さない。初回の既存環境での 183/5 は従来どおり unsupported、初回成功後の二回目は 183 の衝突だけを確定し、その他は indeterminate とする。製品の station/token/Job/ACL 変更、SCM 起動は禁止。GitHub 特有の初回成功分岐の実測は次回 CI まで未確認と明示する。

## T-007: Release の手動実行から同じコミットの診断を呼び出す
- status: done
- done-when: 既存 Release の workflow_dispatch から同じコミットの Session 0 診断を独立 job で呼び出せる定義にする。診断 job の contents: read、secret 非継承、checkout の SHA 固定・資格情報非保持を維持する。タグの公開経路では診断を実行しない。actionlint と独立安全性評価を通す。SCM 実測の合格は T-003 で別途判定する。
- verify: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/release.yml .github/workflows/session0-diagnostic.yml`
- paths: .github/workflows/release.yml, .github/workflows/session0-diagnostic.yml, docs/verification/2026-09-08-release-preparation.md, blocked/T-003.md, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, .harness/**
- notes: GitHub の同一リポジトリ内 ./ 参照は呼び出し元と同じコミットの workflow を使う。session0-diagnostic.yml に workflow_call を追加し、Release 側に手動時限定・contents: read の呼び出し job を追加する。needs を置かず、パッケージ検査が失敗しても診断を実行できる構造とする。スクリプト本体、署名、公開条件は変更しない。権限拡大・secrets 継承が必要なら止める。main 登録を要求する記録を修正し、未 push 差分の実行成功とは報告しない。
- refinement: Release の既存の公開条件は refs/tags/ で、タグ指定の手動実行も含む。診断を github.ref_type == branch で限定し、タグ指定の手動実行も公開経路として維持する。

## T-008: cross-bitness injection の helper 待ちを有界にする
- status: done
- done-when: 別 bitness の子へ注入できないとき、呼び出し元が無期限に待たずに注入失敗として戻る。sibling DLL が存在する正規の helper 経路は従来どおり成功する。P0 ゲートが CI の 5 分予算内で終わり、rundll32 と probe の残留プロセスがない。vendored の変更を VENDORED.md に記録する。独立評価を通す。
- verify: `pwsh -NoProfile -File hooks/test/process_injection_failure.ps1`
- verify: `pwsh -NoProfile -File hooks/test/m7_inject32.ps1`
- verify: `pwsh -NoProfile -File hooks/test/trace_write_batch.ps1 -CandidateDll hooks/build/Release/sbz_interceptor64.dll`
- verify: `pwsh -NoProfile -File hooks/test/nt_rename.ps1`
- verify: `ctest --test-dir hooks/build -C Release --output-on-failure`
- paths: hooks/third_party/detours/creatwth.cpp, hooks/third_party/detours/VENDORED.md, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, .harness/**
- notes: 原因は Detours の `DetourProcessViaHelperDllsA/W` が `WaitForSingleObject(..., INFINITE)` で helper を待つこと。sibling DLL が無いと 32-bit rundll32 がモーダルのエラーダイアログで止まり、誰も閉じないため永久に待つ。プロセスのエラーモードでは抑止できないことを実測で確認した。待機を 15 秒で打ち切り、KILL_ON_JOB_CLOSE のジョブをベストエフォートで併用する。製品の注入方針・fail-closed の意味づけ・署名・公開条件は変更しない。
- review: 独立評価を3周実施（3周目はユーザー承認の例外）。1周目は存在検査の WOW64 誤判定と終了未確認時の後始末、2周目は %WINDIR% 前方一致の取りこぼし・ジョブ必須化が製品の UI 制限ジョブ (crates/worker/src/job.rs:63) と衝突すること・割り当て失敗時の残留、3周目は待機 API 失敗時に終了要求を出していないことを blocking で指摘。いずれも解消済み (60ea6bf, d3da8ce)。証拠は .harness/T-008-review.txt、T-008-review-2.txt、T-008-review-3.txt。3周目の1回目は撤去済み関数を根拠にした無効な回答で、依頼文から過去レビューの参照を外して再実行した。
- residual: 終了要求が拒否される、または確認窓内に効かず、かつジョブが無い場合はヘルパーがこの呼び出しより長く残る。上流は待ち続けることで漏れを避けており、待機を打ち切る以上この差は残る。ワーカー内では既存の action ジョブが外側から回収する。条件は VENDORED.md に記載。d3da8ce 自体は未評価。
- measured: P0 は 91.4 秒で PASS（cross-bitness 6 ケース × 15 秒）。CI の 5 分予算の約 30%。m7_inject32 0.6 秒 PASS、trace_write_batch x64/x86 PASS、nt_rename PASS、ctest 3/3 PASS、rundll32 と probe の残留 0。GitHub CI 上での確認は未実施。

## T-009: VFS bootstrap ハンドルの受け渡しが失敗する
- status: done
- done-when: `hooks/test/vfs_redirect.ps1` の launcher が `VFS bootstrap handles unavailable gle=13` を出さず、redirect がエージェントのバイト列を返す。gle=13 (ERROR_INVALID_DATA) の発生源を実出力で特定し、ローカル環境固有か製品欠陥かを区別して記録する。
- verify: `pwsh -NoProfile -File hooks/test/vfs_redirect.ps1`
- paths: hooks/src/vfs_attestation.cpp, hooks/src/launcher.cpp, hooks/test/vfs_redirect.ps1, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, .harness/**
- notes: T-008 の検証中に発見。失敗は launcher が Detours を呼ぶ前の `OpenFromBootstrapEnvironment` で起きるため T-008 の差分とは経路が交わらない。シェルの入れ子の有無で挙動は変わらず、vcvars 環境でも同じ。
- diagnosis: ローカル固有ではない。`fb02b72`「P0: VFS子プロセス注入を検証し失敗を拒否する」(2026-07-25) が `vfs_attestation` を導入し、launcher の VFS 経路に bootstrap ハンドルを必須化した。`hooks/test/vfs_redirect.ps1` の最終更新は `8096c2e` (2026-07-07) でそれより前であり、attestation オブジェクトを一切用意しない。`SEMBAZURU_VFS_MAPPING_HANDLE` を設定しているテストは `process_injection_failure.ps1` だけで、`vfs_redirect.ps1`・`vfs_compile.ps1`・`vfs_bench.ps1` の3件は `SEMBAZURU_MODE=vfs` を設定しながら用意していない。`m6_worker_vfs_redirect.ps1` は worker 経由なので影響を受けない。
- impact: CI の C++ job は P0 (ci.yml:97) が vfs_redirect (ci.yml:128) より前にあり、P0 のタイムアウトでこの3件は skipped になっていた。T-008 で P0 が通ると、この3件が新たに失敗として現れる。次回 CI で C++ job が緑になると期待しないこと。
- scope: 修正対象は3スクリプト側か、launcher の VFS 経路の要件かを先に決める。製品の fail-closed の意味づけ（attestation なしの VFS 子を走らせない）を緩める方向の修正はしない。
- resolution: 生成と破棄を hooks/test/vfs_attestation_bootstrap.ps1 に集約し、vfs_redirect・vfs_compile・vfs_bench が launcher を起動する各箇所で用意するようにした。既に動いていた process_injection_failure も同じヘルパへ寄せ、重複を残していない。各ゲートの合否判定は変更していない。製品コードは変更していない。
- measured: process_injection_failure PASS 91.3秒、vfs_redirect PASS 1.7秒、vfs_compile PASS 1.9秒、vfs_bench PASS 9.9秒、m7_inject32 PASS 0.6秒、nt_rename PASS 0.7秒、ctest 3/3 PASS、smoke PASS、determinism (M2) PASS。clang-cl はローカル不在で各ゲート SKIP。証拠は .harness/T-009-gates.log、T-009-determinism.log。GitHub CI 上での確認は未実施。
