# NEXT_FINDINGS — Sembazuru

- T-001 の診断テスト失敗は T-004 で修正する。再現条件は [blocked/T-001.md](blocked/T-001.md)。T-004 の実装前に同じ検証を繰り返さない。
- 最初の独立評価 PASS は `.harness/runs/20260908-082159/iter-1.err.txt:9732` に実出力として存在し、`.harness/T-001-original-review.md` に抽出済み。「最初の評価が存在しない」という後続評価の指摘は誤り。ただし再検証の失敗は実在し、PASS の記録で取り消されない。
- 同じ Cargo.lock 差分の評価を追加依頼しない。必要なのは別タスクでの診断テスト修正と、その修正に対する検証。
