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
- status: done
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
- review: 独立評価 PASS、blocking なし。ゲートの合否判定と製品の fail-closed 要件を弱める変更はないと確認された。非阻害の指摘2件（生成が途中で失敗したときの解放漏れ、置き換え時の二重解放）は 0dfbfd6 で解消し、4ゲートを再実行して PASS。証拠は .harness/T-009-review.txt。

## T-010: GUI の Join を storectl 経由の特権書き込みにする
- status: todo (設計未決の分岐あり)
- done-when: GUI の Join が machine token・daemon 設定・worker 設定を原子的に永続化し、ProgramData の ACL と status_admin の default-deny を緩めない。秘密が argv とディスクに残らない。Join 後にサービスが新しい設定で動く。
- verify: `cargo test -p sembazuru-config-store --locked`
- verify: `pwsh -NoProfile -File hooks/test/m9_installer_acl.ps1 ...`（ACL 保護が不変であること）
- paths: crates/config-store/src/bin/sembazuru_storectl.rs, crates/gui/src/join/**, installer/sembazuru.wxs, TASKS.md, PROGRESS.md
- decided: 方式は「storectl を install 済み helper にし join 動詞を追加」。ユーザー決定 2026-09-17。status_admin の有効化とインストーラによる ACL 緩和は退けた。
- 調査済み: 取引機構は実装済み。`MachineTokenUpdate` (config-store/src/lib.rs:182) が cluster_token・daemon_config・worker_config の3つを保持し、`prepare_machine_cluster_token_update` と `apply_or_resume_machine_cluster_token_update` が journal で原子的に適用する。Join に必要な書き込みはこれで表現できる。
- 調査済み: 認可も実装済み。`authorize` (storectl:271) は LocalSystem、または token-maintenance 動詞かつ Administrators かつ elevated を要求する。join を token-maintenance に分類すれば昇格した管理者だけが通る。
- 調査済み: storectl は現在 MSI 埋め込みの CA 用で、インストールされない (installer/sembazuru.wxs:21)。helper 化には配置と署名対象の追加が要る。
- 調査済み: `worker_toml.rs` が平文 cluster_token を書く形は実系と不整合。実系は DPAPI の machine secret を使うので、Join ではトークンを設定ファイルに書かず join payload で別に渡す。
- decided: 受け渡しは (b) GUI が立てた一回限りの名前付きパイプ。GPT と Fable の双方が (b) を推し、一時ファイルと GUI 全体の昇格を退けた。payload は 1 本のバージョン付き長さ前置の封筒で、MachineTokenUpdate の3フィールドに 1:1 対応。詳細と到達点の限界は docs/decisions/0018-action-desktop-and-join-transport.md。
- decided: パイプの DACL は **Administrators のみ**。2026-09-18 に GPT が logon SID 案を撤回し二者一致。
  根拠は logon SID 不一致の実証ではなく、`storectl` の `authorize` が既に要求する認可に合わせ、
  不要な読み取り許可を足さないこと。詳細と罠は docs/decisions/0018-action-desktop-and-join-transport.md。
- decided: Join 後のサービス反映は昇格した `storectl join` が担当する。停止 → 更新ガード取得 → journal 適用 →
  **ガード解放後に**起動、の順。設定更新の完了とサービス反映の完了を別の結果にし、起動失敗は Join 成功にしない。
- measured: 非昇格の管理者トークンでは `S-1-5-32-544` が deny-only、logon SID は生の `TokenGroups` に
  しか現れない（`whoami /groups` と .NET は返さない）。記録は
  docs/verification/2026-09-18-interactive-station-and-logon-sid.md。
- 未実測: 同一ユーザーの UAC 昇格で logon SID が保たれるか、別の管理者アカウント経路で通るか。
  どちらも (a) を選ぶ理由には要らないが、実装後に「Medium の GUI が BA のみのパイプを作る → 昇格 helper が
  接続する → PID 照合後にダミー payload を渡す」と「非昇格クライアントの読み取り拒否」を実測する。

## T-011: アクションがウィンドウステーションとデスクトップを開けるようにする
- status: todo (設計未決)
- done-when: Session 0 のサービス配下で、制限付き・Medium 整合性のアクショントークンが起動したプロセスが 0xC0000142 にならず動く。ステーションとデスクトップの許可範囲を、アクションが必要とする最小に保つ。`m9_installer_acl.ps1` の ACL 検証と worker sandbox の既存の隔離（UI 制限ジョブ、breakaway 不可、制限トークン）を緩めない。
- verify: `pwsh -NoProfile -File hooks/test/m9_installer_acl.ps1 ...`
- verify: Session 0 診断を再実行し、`StationAccess`/`DesktopAccess` が allowed=true になること
- paths: crates/worker/src/sandbox.rs, hooks/test/m6_worker_window_station_probe.ps1, docs/verification/**, TASKS.md, PROGRESS.md
- measured: 2026-09-17 の実測 (docs/verification/2026-09-17-session0.md)。Station=Service-0x0-27fb60$ / Desktop=Default の DACL はサービス SID と S-1-5-32-544 にしか許可がなく、StationAccess も DesktopAccess も allowed=false gle=5。
- mechanism: 原因は整合性ではなく制限付きトークンの二重アクセスチェック。制限 SID は sandbox.rs:469-487 で [action_sid(乱数), Everyone, Authenticated Users, Users, RESTRICTED]。DACL に制限 SID 側と一致する ACE が1つもないため、通常側が通っても制限側で落ちる。整合性を上げても解決しない（Medium 以上が作ったオブジェクトは無ラベル=Medium 扱いで no-write-up が効かない）。
- 前提の訂正: 起動フラグでは直らない。CREATE_NO_WINDOW は実測で NO_WINDOW_NOT_SUFFICIENT。製品の起動フラグは変更しない。
- 関連: T-006 のログオン単位ウィンドウステーション生成の調査は、アクション専用ステーションを用意する案の側にある。
- decided: 方向は (a) アクション専用のステーションとデスクトップ。GPT と Fable の双方が (a) を推し、(b) と (c) を退けた。根拠と罠は docs/decisions/0018-action-desktop-and-join-transport.md。
- measured: 2026-09-18 の run 35347944739 で留保に決着。ステーションもデスクトップも
  `label=absent`（= Medium 扱い）なので **MIC では説明できない**。制限 SID 列
  `[action_sid, Everyone, Authenticated Users, Users, RESTRICTED]` に一致する ACE が DACL に1つも無く、
  `MAXIMUM_ALLOWED` すら gle=5 で落ちる。原因は DACL の制限側で確定した。
  記録は docs/verification/2026-09-18-session0-label-and-restricted-sids.md。
- scope: 与えるべきは「もっと狭い mask」ではなく、制限側を満たす `action_sid` の ACE そのもの。
  許可が皆無なので、mask を1ビットずつ削って境界を出す作業には意味が無い。
- 残る未検証: `CreateProcessAsUser` が対象ステーション/デスクトップへの full access を要求する点と、
  最小権限だけを与える構成との折り合い。

## T-012: Session 0 診断に整合性ラベルと制限 SID を足す
- status: done
- done-when: 診断レコードが、ウィンドウステーションとデスクトップの SACL（整合性 SID と mandatory mask）、アクショントークンの `TokenRestrictedSids` と通常 SID と `TokenMandatoryPolicy`、`JOB_OBJECT_UILIMIT_*` の展開結果を含む。GitHub runner で実測し、0xC0000142 の拒否が DACL 由来か MIC 由来かを区別できる。
- verify: `rustup run 1.97.0 cargo test -p sembazuru-worker --lib session0_ --locked`
- verify: `gh workflow run release.yml --ref chore/two-pc-preparation` の診断 job 実ログ
- paths: crates/worker/src/sandbox.rs, hooks/test/m6_worker_window_station_probe.ps1, docs/verification/**, TASKS.md, PROGRESS.md
- notes: T-011 の設計に入る前の前提確認。GPT の留保「SACL 未測定なので DACL だけが原因とは断定できない。MIC は DACL より先に評価される」に答える。診断は test 限定で、製品の起動条件は変更しない。
- notes: 最小権限は現在「プローブした値」であって実測値ではない。mask を1ビットずつ削って境界を出す作業は、この診断が揃ってから別タスクにする。
- implemented: 3162525 と a3caf65。レコードは version 5。追加した項目は (1) ステーションとデスクトップの
  mandatory label を `LABEL_SECURITY_INFORMATION` で読んだラベル ACE の型・フラグ・mask・SID
  (`SE_SECURITY_NAME` を要求しない)、(2) トークン要約の `TokenMandatoryPolicy`、(3) Job の UI 制限マスクの
  `JOB_OBJECT_UILIMIT_*` 全ビット展開、(4) アクショントークンでの順序付き open 6 段と最初の拒否。
  いずれも `#[cfg(test)]` 限定で、製品の起動条件・トークン・Job・ACL は変更していない。
- implemented: (3) は測定ではなくマスクの復号表なので、`encode_into` がマスクとの一致を検査し、
  PowerShell 側 `Expand-Session0JobUi` がビット定義を独立に持って突き合わせる。改竄は新しい拒否ケース
  `job-ui-limit-names` が受け持ち、`relaxed-job-ui` は名称もマスクに合わせて従来どおり A/B 制約で拒否させる。
- limitation: (4) は「最初に失敗する USER32/GDI32 呼び出し」の代替観測にすぎない。子は `user32` の初期化中に
  死ぬため in-child のトレースは取れない。記録文字列に `scope=broker-impersonated` を持たせて限界を明示した。
- measured: ローカル (session 1、対話デスクトップ)。ステーションのラベルは
  `label_aces=[type=17;flags=0;mask=0x00000001;sid=S-1-16-4096]`(Low)。制限付きアクショントークンでも
  6 段すべて `allowed=true`。Session 0 の拒否が「制限トークンそのもの」では説明できないことを示す。
- measured: `rustup run 1.98.1 / 1.97.0 cargo test -p sembazuru-worker --lib session0_ --locked` が
  どちらも 10 passed / 0 failed。`cargo fmt --all --check` と
  `cargo clippy -p sembazuru-worker --all-targets --locked -- -D warnings` は exit 0。証拠は
  .harness/T-012-session0-tests.log、T-012-session0-tests-1.97.log、T-012-fmt.log、T-012-clippy.log、
  T-012-gates-after-review.log。
- review: 独立評価 PASS、blocking なし。非阻害2件（`relaxed-job-ui` が名称検査で先に落ちる、ラベル不在の
  コメントが DACL を唯一の容疑者と読ませる）は a3caf65 で解消し、4 検査を再実行した。a3caf65 自体は未評価。
  証拠は .harness/T-012-review.txt、依頼文は .harness/T-012-review-brief.md。
- measured: run 35347944739 (SHA 3fbed87、job は completed/success) で実測完了。
  `StationSacl` / `DesktopSacl` はどちらも `label=absent;implied_integrity=8192`、
  `UiProbe` は 6 段すべて `allowed=false;gle=5`（`MAXIMUM_ALLOWED` を含む）、
  `JobUiLimits` は `handles=0` で残り 7 ビットが 1。記録は
  docs/verification/2026-09-18-session0-label-and-restricted-sids.md。
- 結論: 拒否は **MIC ではなく DACL**。ラベルが無いオブジェクトは Medium 扱いで、Medium のアクションに
  no-write-up は働かない。version 5 のレコードは hosted runner の PowerShell 解析器を通り、
  Rust と PowerShell の契約が実環境でも一致することも確認できた。

## T-013: junction を含む一時ツリーの後始末が失敗する
- status: done
- done-when: `tests::trace_publish_rejects_reparse_source_directory` がローカルで成功する。失敗の原因が
  このマシンの環境なのか `remove_dir_all` の扱いなのかを区別して記録し、環境依存なら検査側で扱う。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-worker --lib trace_publish_rejects_reparse_source_directory --locked`
- paths: crates/worker/src/lib.rs, TASKS.md, PROGRESS.md
- measured: T-012 の検証中に発見。`crates/worker/src/lib.rs:1754` の `remove_dir_all(root)` が
  `Os { code: 145, DirectoryNotEmpty }` で落ちる。root には `real/`（`read.sbzt` を含む）と、
  それを指す junction `source-junction` がある。`publish_trace_directory` 自体の判定
  （junction を拒否し destination を作らない）は成功しており、失敗するのは後始末だけ。
- measured: T-012 の差分を stash した HEAD でも同じく失敗する。1.97.0 と 1.98.1 の両方で失敗する。
  ツールチェーンの退行でも T-012 の差分由来でもない。
- diagnosed: 失敗後に残る一時ツリーを開いて確認した。`real/` は消えており、**宙に浮いた
  `source-junction` だけが残る**。`remove_dir_all` は名前順に `real` を先に消し、その時点で
  dangling になった junction を「既に無い」として読み飛ばし、親が非空のまま残る。
  常駐ソフトのハンドル保持でも権限でもない。
- diagnosed: dangling になった junction は、対象を解決してから開く API では外せない。
  .NET の `Directory.Delete`、`cmd` の `rmdir`、`fsutil reparsepoint delete` のいずれも失敗する
  （それぞれ path not found / ERROR_INVALID_NAME / 145）。したがって後始末は
  **dangling になる前にリンクとして外す**しかない。
- resolution: `crates/worker/src/lib.rs` の fixture が、木を消す前に `remove_dir(&source)` で
  junction をリンクとして外すようにした。`remove_dir` は reparse point だけを外し、対象には触れない。
  製品コード (`publish_trace_directory`) は変更していない。元々この関数の判定は正しく、
  失敗していたのは後始末だけだった。
- measured: `rustup run 1.98.1 cargo test -p sembazuru-worker --lib --locked` が exit 0、
  `157 passed; 0 failed; 9 ignored`。証拠は .harness/T-013-worker-after.log。
  修正前の全体像は .harness/T-013-workspace-before.log。
- notes: 過去の失敗で `%TEMP%` に残った `sembazuru-worker-trace-reparse-*` は、上記のとおり
  どの API でも外せないまま残っている。新しく作られることは無くなった。

## T-014: Join payload の封筒を定義する
- status: done
- done-when: バージョン付き・長さ前置の1本の封筒を encode/decode でき、論理フィールド
  `cluster_token` / `daemon_config` / `worker_config` が `MachineTokenUpdate` に 1:1 で対応する。
  未知バージョン、全体長の超過、各フィールド長の超過、切り詰め、末尾余剰、フィールド数違いを拒否する。
  秘密は `Zeroizing` に載り、`Debug` に出ない。I/O を含まない純粋な層にする。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-config-store --locked`
- verify: `rustup run 1.98.1 cargo clippy -p sembazuru-config-store --all-targets --locked -- -D warnings`
- paths: crates/config-store/src/join.rs, crates/config-store/src/lib.rs, TASKS.md, PROGRESS.md
- measured: b13994e。lib 89 passed / 0 failed、fmt と clippy は exit 0。
- notes: ADR 0018「payload の形」。3対象を1取引として扱う理由は `prepare_machine_cluster_token_update`
  が1取引で受けること。分割メッセージにすると解析・再試行・順序付けの失敗状態が増える。
  トークンの既存の一行制約 (`MAX_MACHINE_CLUSTER_TOKEN_BYTES`、CR/LF/NUL 禁止) はフィールド内部で維持する。

## T-015: storectl に join 動詞を足す
- status: done
- done-when: `sembazuru-storectl join --pipe <name>` が token-maintenance として既存の `authorize` を通り
  (LocalSystem、または Administrators かつ昇格)、名前付きパイプへ
  `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` で接続して封筒を読み、`MachineTokenUpdate` として
  原子的に適用する。秘密を argv に載せず、ディスクに書かない。既存7動詞の argv・認可・出力コードは不変。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-config-store --locked`
- paths: crates/config-store/src/bin/sembazuru_storectl.rs, TASKS.md, PROGRESS.md
- notes: `authorize` の条件式は変えず、`is_token_maintenance` に join を足すだけにする。
  パイプ名は argv で受けるが、秘密ではない。名前の検証（`\.\pipe\` 配下、長さ、文字種）を入れる。

## T-016: GUI 側の一回限りのパイプを作る
- status: done
- done-when: GUI が `FILE_FLAG_FIRST_PIPE_INSTANCE`・`PIPE_REJECT_REMOTE_CLIENTS`・インスタンス数 1・
  明示のセキュリティ記述子 `D:P(A;;GR;;;BA)` でパイプを作る。`SEE_MASK_NOCLOSEPROCESS` で得た
  プロセスハンドルを保持したまま `GetNamedPipeClientProcessId` と突き合わせ、一致するまで payload を
  1バイトも書かない。ハンドル取得の失敗と照合の失敗はどちらも中止にする。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-gui --locked`
- paths: crates/gui/src/join/**, TASKS.md, PROGRESS.md
- notes: ADR 0018「実装時の罠」。`GENERIC_WRITE` は `FILE_CREATE_PIPE_INSTANCE` を含むので一方向なら
  `PIPE_ACCESS_OUTBOUND` と `GR` だけにする。first-instance は作成時の競合検出であって名前の予約ではないので、
  サーバーハンドルを閉じて同名で作り直す経路を作らない。

## T-017: Join 後のサービス反映を storectl join に持たせる
- status: done
- done-when: `join` が 停止 → 更新ガード取得 → journal 適用 → **ガード解放後に**起動 の順で実行する。
  設定保存の完了とサービス反映の完了を別の結果として返し、起動に失敗したときは Join 成功にしない。
  再起動までの Join 全体を直列化する。SCM 操作は対象名と操作を固定し、停止・開始・状態照会の権限だけを要求する。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-config-store --locked`
- paths: crates/config-store/src/bin/sembazuru_storectl.rs, TASKS.md, PROGRESS.md
- notes: 順序は既存の lease から強制される (`enter_service_runtime_at` crates/config-store/src/windows.rs:573、
  `acquire_committed_root_lease` の共有モード 0 と Busy crates/config-store/src/windows.rs:1105)。
  `crates/agent/src/service.rs:188` は実行ループ開始前に `Running` を報告するので、SCM の `Running` 一回を
  動作確認の代用にしない。

## T-018: storectl をインストール対象に入れる
- status: done
- done-when: `storectl` が MSI 埋め込みの CA 専用から、インストールされる helper になる。配置先と署名対象に
  入り、既存の ProgramData の ACL と `status_admin` の default-deny を緩めない。
- verify: `pwsh -NoProfile -File hooks/test/m9_installer_acl.ps1 ...`
- paths: installer/sembazuru.wxs, TASKS.md, PROGRESS.md
- notes: 現状 `installer/sembazuru.wxs:21` の CA 用でインストールされない。配置と署名対象の追加が要る。

## T-019: GUI のウィザードを Join の経路へつなぐ
- status: todo
- done-when: 参加ウィザードの入力が `JoinPayload` になり、`join::transport::deliver` を通って
  保存される。`StubConfigWriter` の `MechanismUnconfigured` がこの経路から消える。
  昇格の辞退、helper の不在、`join-saved-not-applied` が、利用者に区別できる形で表示される。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-gui --locked`
- paths: crates/gui/src/app/join_panel.rs, crates/gui/src/join/**, TASKS.md, PROGRESS.md
- notes: T-014〜T-018 で経路の両端は揃ったが、**ウィザードからの呼び出しがまだ無い**。
  `worker_toml.rs` は平文の cluster_token を worker.toml に書く形なので、実系に合わせて
  トークンは payload の `cluster_token` として渡し、設定ファイルには書かない。
- notes: 昇格を伴う実測（Medium の GUI がパイプを作り、昇格 helper が接続して PID 照合後に
  payload を受け取る）は人が UAC を押す必要がある。結線が済んでから1回行う。

## T-020: Join の接続と送信に期限を持たせる
- status: todo
- done-when: GUI 側の `ConnectNamedPipe` と書き込みが、helper が接続せずに終了した場合や応答しない
  場合に有界時間で戻る。helper のプロセスハンドルと期限の両方を待機の対象にする。成功経路の
  受け渡しは従来どおり成立する。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-gui --locked`
- paths: crates/gui/src/join/transport.rs, TASKS.md, PROGRESS.md
- notes: 独立評価の blocking。同期の `ConnectNamedPipe` は待ち続ける。現在の 120 秒は
  `hand_over` が終わったあとの `wait_for_helper` にしか効かない。`FILE_FLAG_OVERLAPPED` で
  パイプを作り、接続・書き込みを overlapped にして、イベントと helper のプロセスハンドルを
  一緒に待つ形にする。同期のまま短い待ちを繰り返す形は、取りこぼしと競合を増やすので避ける。

## T-021: サービスの反映を一瞬の Running で判定しない
- status: todo
- done-when: `join` がサービスの起動を「初期化まで到達した」ことで判定する。`Running` を報告した
  直後に失敗して停止する場合を失敗として扱う。判定の根拠を1つに決めて記録する。
- verify: `rustup run 1.98.1 cargo test -p sembazuru-config-store --locked`
- paths: crates/config-store/src/bin/sembazuru_storectl.rs, TASKS.md, PROGRESS.md
- notes: 独立評価の blocking。worker は `crates/worker/src/service.rs:198` で `Running` を報告した
  あと `crates/worker/src/run.rs:53` で listener を bind する。daemon も
  `crates/agent/src/service.rs:188` で実行ループ開始前に `Running` を報告する。ポート競合などで
  直後に落ちても、その間の `Running` を観測すると `join-applied` を返してしまう。
  ADR 0018 の「SCM の `Running` 一回を動作確認の代用にしない」を満たしていない。
- notes: 判定の候補は (a) 一定時間 `Running` が継続することの確認、(b) Status プレーンへの問い合わせ、
  (c) サービス側が初期化完了を報告する仕組みの追加。(b) は ADR 0016 の境界に触れるので、
  選ぶ前に影響を確認する。

## T-022: storectl の配置を MSI 検査の期待値と一致させる
- status: done
- done-when: `hooks/test/m9_installer_acl.ps1` が、storectl の埋め込み Binary ストリームと
  lifecycle CustomAction を従来どおり検証しつつ、INSTALLFOLDER への配置を許可して検証する。
  ProgramData の ACL と `status_admin` の default-deny の検査は緩めない。
- verify: `pwsh -NoProfile -File hooks/test/m9_installer_acl.ps1 ...`
- paths: hooks/test/m9_installer_acl.ps1, installer/sembazuru.wxs, TASKS.md, PROGRESS.md
- notes: 独立評価の blocking。`m9_installer_acl.ps1:145` は
  「storectl must remain an embedded Binary stream, not an installed File」として `File` 要素を拒否し、
  375行目は `StoreCtlExeFile` を名指しで拒否、387行目は File テーブルに `storectl` が現れることを拒否する。
  **T-018 (57e5d8e) はこの必須ゲートに落ちる。**
- decided: ユーザー判断 2026-09-18。ゲートを ADR 0018 の決定に合わせる。「ディスクに置かない」という
  不変条件は正式に手放し、代わりに「置き場所と形が正確に1つであること」を検証する。
- resolution: 拒否を肯定的な検証へ反転した。storectl の `File` はちょうど1つで、`StoreCtlExeFile` として
  `$(var.RustTarget)` から KeyPath で入り、`Binaries` グループの INSTALLFOLDER 配下にあり、PATH エントリも
  ショートカットも持たないこと。埋め込み Binary ストリームが残っていることも別途要求する。
  MSI の File テーブル側も同様に「storectl の行はちょうど1つで、それは `StoreCtlExeFile`」とした。
  ProgramData の ACL と status_admin の default-deny の検査は触っていない。
- measured: `pwsh -NoProfile -File hooks/test/m9_installer_acl.ps1 -Static` が exit 0（4 つの PASS)。
  検査が素通りでないことは、`StoreCtlExe` コンポーネントを一時的に外すと
  `storectl must be installed exactly once as a File (found 0)` で落ち、戻すと PASS に戻ることで確認した。
  証拠は .harness/T-022-static.log。MSI テーブル側の検査は MSI が要るので CI が初出。

## T-023: M6.1b の worker VFS が attestation で落ちる
- status: todo
- done-when: CI の C++ job で `m6_worker_vfs_redirect` 相当の M6.1b ゲートが通る。worker の
  `event=attestation-failed` の原因を特定し、ゲート側の用意不足か製品側の欠陥かを区別して記録する。
- verify: CI の `C++ hooks + tracer (MSVC) (windows-2022)` job
- paths: crates/worker/src/**, hooks/src/vfs_attestation.cpp, hooks/test/**, TASKS.md, PROGRESS.md
- measured: run 35353309959 (SHA 15fbabf) の job 105626448958。
  `M6.1b WORKER VFS GATE FAIL: hosted cl.exe /GL VFS probe failed (exit=-1) /
  plain direct /GL compiler failed (exit=72) / hosted cl.exe /GL CreateFile diagnostic was
  incomplete or invalid (exit=3)` と `M6_SERVICE_STDERR service=worker event=attestation-failed`。
- notes: T-009 は「`m6_worker_vfs_redirect.ps1` は worker 経由なので attestation の用意不足の影響を
  受けない」と記録していた。worker 自身が `attestation-failed` を出しているので、その前提を先に確かめる。
- notes: `plain direct /GL compiler failed (exit=72)` は VFS を介さない経路なので、フック層より前の
  段で既に失敗している可能性がある。そちらを先に切り分ける。

## T-024: M3.5 の速度ゲートが統計的に不安定
- status: todo
- done-when: `hooks/test/vfs_bench.ps1` の永続パイプ判定が、hosted runner の雑音の下でも
  意味のある回帰だけを落とす。合格条件の根拠（何回中何回、なぜ）を記録する。
- verify: `pwsh -NoProfile -File hooks/test/vfs_bench.ps1`
- paths: hooks/test/vfs_bench.ps1, TASKS.md, PROGRESS.md
- measured: run 35353309959 の job 105626449002。
  `persistent pipe did not reduce median CreateFile latency reliably: forced-wins=5/9 (expected >=8)`。
  実測差は `[29.4, 15.8, 10.2, -11.4, 10.7, -14.1, -1.5, -26, 6.6]` us で符号が混在している。
  ローカルでは T-009 のとき PASS しており（9.9秒）、環境差が出ている。
- notes: 9 回中 8 回という符号検定は、1 回あたりのばらつきが効果量と同程度のときに落ちる。
  中央値の差そのものに閾値を置く、反復数を増やす、外れ値を落とす、のどれを採るかを決めて根拠を書く。
  判定を緩めるだけの変更にしない。回帰を見逃さない根拠を示す。
