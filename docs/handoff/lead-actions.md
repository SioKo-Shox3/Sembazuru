# Lead actions — プロジェクトリードだけが実行する保留事項

このファイルは、**プロジェクトリードだけが実行できる／判断すべき保留事項**を 1 か所に集約する
running checklist です。AI セッションは push・実機 SCM 操作・管理者操作・GUI の視覚確認・秘密値の
配布をできないため、それらをここに残します。完了したら ✅ にして残すか、節ごと削除してください。

最終更新: 2026-06-17（M9.3c 完了時点）。

---

## 0. ブランチ運用（随時）

- [ ] **M9.3c を取り込む。** `m9/worker-service`（M9.3c-a〜d ＋ addendum、計 5 コミット）を push し
      `m9/foundation` に統合する。**main 直 push は不可**（分類器が拒否。work ブランチ経由）。
- [ ] **M9.4 の起点。** GUI セッションは、M9.3c 取り込み後の `m9/foundation` tip から `m9/gui` を
      切って開始する（起動プロンプトは別途用意済み）。

## 1. M10（実 2 台 LAN）着手前 — 実機 SCM ライフサイクル gate

`cargo test` では検証できない（管理者 / SCM が要る）ため、実機で一度通すこと。M10＝実 2 台が
事実上の実機テストなので **M10 で兼ねても可**。単機で先に通すと「入れれば worker 参加」前提の
リスクを早く潰せる。

- [ ] **worker サービス（M9.3c）の install→AutoStart→start→stop→uninstall を実機で一周。**
      管理者 PowerShell:
      ```powershell
      cargo build -p sembazuru-worker --release
      $exe = "target\release\sembazuru-worker.exe"
      & $exe install                  # 既定 Virtual（NT SERVICE\SembazuruWorker）
      sc.exe qc SembazuruWorker        # AUTO_START / OWN_PROCESS / ImagePath ...--service を確認
      sc.exe start SembazuruWorker     # services.msc で Running 確認
      #  worker.toml に agent= を設定し、agent 側に worker が register されることを確認
      sc.exe stop SembazuruWorker      # graceful（heartbeat 停止で agent が aging out）
      & $exe uninstall                 # stop→delete で完全削除（persistence 残渣なし）
      ```
- [ ] **daemon サービス（M9.3b）も同様の一周**を未実施なら実施（`sembazuru-daemon install/...`）。

## 2. M9.5（インストーラ）で対応する事項

- [ ] **Virtual アカウントの ACL 付与。** `NT SERVICE\SembazuruWorker` に
      **scratch_root / cas_root への書込み**と **launcher.exe / hook DLL の読取実行**を ACL 付与する。
      最小権限アカウントは既定でこれを持たず、未付与だと **VFS アクションが install 時でなく実行時に失敗**。
      （根拠と意図は `crates/worker/src/service.rs` の `ServiceAccount` doc に明記済み。）
- [ ] **署名 × EDR 申請の接続。** M7.2 の Authenticode 署名パイプラインに新規 exe を載せ、
      `docs/security/edr-allowlist.md`（2 サービス構成に更新済み）で申請する。
- [ ] **ファイアウォール規則・PATH 登録・初期設定**（Coordination/fileserver/worker ポート、
      `SEMBAZURU_AGENT` / `SEMBAZURU_CLUSTER_TOKEN` 等）を MSI に組み込む（ADR 0008 / DESIGN §7 M9）。

## 3. Follow-up（緊急性なし・M9 後でも可）

- [ ] **proto トークン reader 統一。** `sembazuru_proto::auth::cluster_token_from_env` を `var_os` 化し、
      daemon/worker/データプレーンの全 reader を**非 UTF-8 トークンでも一致**させる。M9.3c の verifier が
      検出した既存差異（ASCII では無影響）。**chip 起票済み: `task_eba5301f`**（ワンクリックで別 worktree 着手可）。

## （参考）M9.4 セッションで判断を仰がれ得る点 — リードの事前作業ではない

- サービス start/stop の**昇格方式**（UAC 昇格 / 特権ヘルパ / `sc` 経由）。非昇格のユーザーセッション
  GUI は既定でサービスを停止できないため、M9.4 の Plan でこの設計判断が上がる見込み。
- `cluster_token` の UI 取り扱い（read は presence のみ・書込みは write-only・echo/ログ厳禁）。秘密の実値は
  リードが配布・設定する前提。
