# NEXT_FINDINGS — Sembazuru

- T-004/T-005/T-006/T-007 の独立評価は PASS。阻害指摘なし。非阻害指摘と実測の限界は PROGRESS.md に記録済み。追加の同一差分レビューは行わない。
- T-001 は T-004 後の cmd 経由 workspace 全体テストが exit 0 となり完了。旧 Cargo.lock 差分の追加評価は不要。
- T-003 は push 済みで、残るのは Release をブランチ ref で手動実行し、最初に診断 job の有無と SHA を確認すること。診断専用 workflow の main 登録は先行条件ではない。2026-09-17 の実行は自動承認の分類器が Create Public Surface として拒否した。ユーザーの明示指示が要る。
- T-008 の残課題: 3周の独立評価で挙がった blocking はすべて解消したが、最後の解消差分 d3da8ce は未評価。危険地帯の差分なので、次に評価者を呼ぶ機会があれば対象に含める。塞ぎ切れない条件は VENDORED.md に記載。
- T-009 完了。C++ ゲートのローカル通過範囲は P0・M7.3・nt_rename・trace_write_batch・smoke・M2 決定性・VFS 3件まで広がった。clang-cl・ninja・dxc を要する段はローカルで未実行。
- 次に CI を回すとき、C++ job は P0 の先まで進む。**そこで初めて実行される段（M3 の clang-cl バイト一致、M4、M6.1/M6.2/M6.3、M8.4/M8.5）が新しい失敗として現れうる。一度で緑になると期待しない。**
- 未着手で大きいのは、installed worker の 0xC0000142（CI の M9.6 installer job）と GUI Join の保存経路。後者は設計判断が未決。
- T-012 の独立評価は PASS、blocking なし。非阻害2件は a3caf65 で解消済み。解消差分そのものは未評価で、
  次に評価者を呼ぶ機会があれば対象に含める。
- T-012 の残りは GitHub runner での実測だけ。実測前に T-011 の設計へ入らない（DACL 由来と断定できる根拠が
  まだ無い）。ローカル実測は「制限付きトークンでも対話セッションのステーションは 6 段すべて開ける」まで。
- T-013（junction を含む一時ツリーの `remove_dir_all` が `DirectoryNotEmpty`）は既存の失敗で、
  T-012 の差分由来ではない。CI で同じ失敗が出るかを見てから直す場所を決める。
