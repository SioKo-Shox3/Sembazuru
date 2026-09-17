# NEXT_FINDINGS — Sembazuru

- T-004/T-005/T-006/T-007 の独立評価は PASS。阻害指摘なし。非阻害指摘と実測の限界は PROGRESS.md に記録済み。追加の同一差分レビューは行わない。
- T-001 は T-004 後の cmd 経由 workspace 全体テストが exit 0 となり完了。旧 Cargo.lock 差分の追加評価は不要。
- T-003 は push 済みで、残るのは Release をブランチ ref で手動実行し、最初に診断 job の有無と SHA を確認すること。診断専用 workflow の main 登録は先行条件ではない。2026-09-17 の実行は自動承認の分類器が Create Public Surface として拒否した。ユーザーの明示指示が要る。
- T-008 で C++ の P0 タイムアウトは解消。CI 上での確認は次回 CI に持ち越し。
- T-008 の残課題: 2周の独立評価で挙がった blocking 3 件は 60ea6bf で解消したが、その解消差分自体は未評価（1差分あたり最大2周の規約）。危険地帯の差分なので、次に評価者を呼ぶ機会があれば 7f58d56..60ea6bf を対象に含める。
- T-009 (新規): vfs_redirect が `VFS bootstrap handles unavailable gle=13` で失敗する。T-008 の差分とは経路が交わらない。CI 上の現状が未確認なので、ローカル固有と断定する前に CI を見る。
