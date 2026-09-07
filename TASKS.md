# TASKS — Sembazuru

目的: GitHub Releases から Windows 11 x64 の新しい PC に導入し、LAN 上の実行に参加できる状態にする。
現在の承認範囲は配布パッケージの検証と Session 0 診断。公開、未測定の起動条件の製品適用、GUI 保存方式の決定は未完。

## T-001: 依存関係の脆弱性検査エラーを修正する
- status: todo
- done-when: h2 と webbrowser を修正版へ最小更新し、cargo-deny、fmt、clippy、workspace テストの実出力を確認する。差分の独立評価を通す。配布全体の合格とは区別する。
- verify: `cargo deny check advisories bans licenses sources`
- verify: `rustup run 1.97.0 cargo fmt --all --check`
- verify: `rustup run 1.97.0 cargo clippy --all-targets --locked -- -D warnings`
- verify: `rustup run 1.97.0 cargo test --workspace --locked`
- paths: Cargo.lock, TASKS.md, PROGRESS.md, LESSONS.md, NEXT_FINDINGS.md, blocked/T-001.md, .harness/runs/**
- notes: CI 34032907718 の RUSTSEC-2026-0258 (h2 0.4.14、修正版 >=0.4.16) と RUSTSEC-2026-0257 (webbrowser 1.2.1、修正版 >=1.2.2)。一次資料を取得して確認し、対象 package の patch 更新に限定する。例外登録や検査の緩和は禁止。予期しない広範な依存更新は止めて記録する。worker/transport の攻撃面とビルド出力への影響を評価で明示する。C++/M2 の未合格をこのタスクのテストで代替しない。

## T-002: GitHub のセットアップ生成結果を検証する
- status: todo
- done-when: Release run 34169478977 の終端結果、対象 SHA、実ログを開いて記録する。成功時は MSI と Bundle artifact を取得してハッシュと同梱内容を確認する。失敗時は最初の失敗と再現条件を記録し、生成成功と報告しない。
- verify: `gh run view 34169478977 --log`
- paths: docs/verification/2026-09-08-release-preparation.md, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, blocked/T-002.md, .harness/runs/**, target/release-preparation/**
- notes: 対象は既に push された 2156d473e934483c85257aa081cb6cfcf3a6a3fa。T-001 の未 push 差分を含む成果物ではない。workflow_dispatch は公開 Release を作らない。既に run は開始済みなので重複 dispatch しない。Setup.exe/MSI は実行しない。WiX extract/decompile は可。少なくとも VC++ x64/x86 と MSI、製品の x64/x86 DLL と storectl の同梱を静的に確認する。失敗の調査記録が完了しても公開準備完了ではない。

## T-003: GitHub runner で Session 0 の起動フラグを測定する
- status: todo
- done-when: 2156d47 の診断を GitHub hosted runner で実測し、A/B の flags、Job UI、分類、cleanup、worker 前後一致を実ログで確認する。
- verify: `rustup run 1.97.0 cargo test -p sembazuru-worker --lib session0_ --locked`
- paths: docs/verification/2026-09-08-session0.md, TASKS.md, PROGRESS.md, NEXT_FINDINGS.md, blocked/T-003.md, .harness/runs/**, target/release-preparation/**
- notes: 2026-09-08 の dispatch は default branch に workflow がないため HTTP 404。main は 8b91020、作業ブランチだけ 2156d47。default branch への登録が必要。git push、API による同等の直接反映、PR の無断マージをしない。登録待ちは blocked にして測定成功としない。上記 verify は診断の契約検査だけで、実測ログなしに done にしない。ローカル SCM 診断は禁止。
