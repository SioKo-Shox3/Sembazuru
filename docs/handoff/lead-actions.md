# Lead actions — プロジェクトリードだけが実行する保留事項

このファイルは、**プロジェクトリードだけが実行できる／判断すべき保留事項**を 1 か所に集約する
running checklist です。AI セッションは push・実機 SCM 操作・管理者操作・GUI の視覚確認・秘密値の
配布をできないため、それらをここに残します。完了したら ✅ にして残すか、節ごと削除してください。

最終更新: 2026-06-19（M9.6: ADR 0009 自己更新 / 0010 CPU 連動 admission 実装・リリース Actions 整備）。

---

## 0. ブランチ運用（随時）

- [ ] **M9.3c を取り込む。** `m9/worker-service`（M9.3c-a〜d ＋ addendum、計 5 コミット）を push し
      `m9/foundation` に統合する。**main 直 push は不可**（分類器が拒否。work ブランチ経由）。
- [ ] **M9.4 の起点。** GUI セッションは、M9.3c 取り込み後の `m9/foundation` tip から `m9/gui` を
      切って開始する（起動プロンプトは別途用意済み）。
- [ ] **M9.6 を取り込む。** `m9/finalize`（`m9/installer` から分岐し、`m9/cpu-admission`＝ADR 0010 と
      `m9/self-update`＝ADR 0009 を `--no-ff` 統合、その上に CI 版同期ゲート・M9.6 docs・リリース Actions）
      を push して main へ。個別 2 ブランチを別々に push したい場合も、内容は finalize に内包される。
      **main 直 push は不可。**

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

> 実装メモ（2026-06-19 audit / verifier）: 上記の ACL 付与・FW 規則・PATH 登録・初期設定(seed-config) は
> `installer/sembazuru.wxs` に**実装済み**（`util:PermissionEx` で worker virtual account の scratch/cas ACL、
> `FirewallException`、`Environment Name="PATH"`、`Seed{Daemon,Worker}Config` CustomAction）。残るアクションは
> 「MSI を実機に入れて実際に効くか」の**反映確認**（launcher/hook DLL は Program Files 既定 ACL で読取実行可のため
> 個別 grant は通常不要）。生成 MSI に PermissionEx/FW が焼かれるかの post-build 確認（Orca/msiinfo）も併せて。

## 3. Follow-up（緊急性なし・M9 後でも可）

- [ ] **proto トークン reader 統一。** `sembazuru_proto::auth::cluster_token_from_env` を `var_os` 化し、
      daemon/worker/データプレーンの全 reader を**非 UTF-8 トークンでも一致**させる。M9.3c の verifier が
      検出した既存差異（ASCII では無影響）。**chip 起票済み: `task_eba5301f`**（ワンクリックで別 worktree 着手可）。

## 4. リリース（M9.6・GitHub Release・ADR 0008 / 0009）

自己更新（ADR 0009）が消費する `releases/latest` の MSI を発行する手順。Actions は整備済み
（`.github/workflows/release.yml`、`v*` タグ起動）。署名 secret 未設定なら **draft** で publish するため、
未署名 MSI が誤って `latest`（＝自己更新の取得対象）になることはない。

### 署名なしの動作確認（cert 取得前・今すぐ可）
- [ ] タグを打って push（リードのみ・main 直 push 不可）: `git tag v0.0.1 && git push origin v0.0.1`。
      → `release.yml` がビルド → 版整合検証 → MSI 生成 → **draft** リリース作成。検知→DL の経路や GUI を
      draft で手動確認できる（署名検証で弾かれるところまで）。
- [ ] あるいは Actions の **workflow_dispatch** で MSI 成果物のみ生成する dry-run（リリースは作らない）。

### 署名つき正式リリース（実 OV cert 取得後）
- [ ] 実 OV cert を **GitHub Secrets** に設定: `SBZ_SIGNING_PFX_BASE64`（PFX の base64）/
      `SBZ_SIGNING_PASSWORD` / `SBZ_TIMESTAMP_URL`（例 `http://timestamp.digicert.com`）。
      ※ HSM/ハードウェアトークンの OV cert は PFX 化不可。その場合は `release.yml` の「Sign …」2 ステップを
      署名プロバイダ（Azure Trusted Signing / DigiCert KeyLocker / token KSP の signtool）へ差し替える
      （契約は `installer/sign_release.ps1` と同じ＝署名して `Valid` 検証）。
- [ ] `crates/gui/src/verify/mod.rs` の `EXPECTED_PUBLISHER` を実 cert subject(CN) に差し替えてマージ
      （未差し替えだと自己更新は実署名 MSI も弾く＝fail-closed で安全側だが更新は機能しない）。
- [ ] バージョンを上げる場合は **Cargo `[workspace.package] version` と WiX `SbzVersion`（`installer/Package.wixproj`）
      を一致**させる（CI / release の `check_version_sync.ps1` が不一致を弾く）。タグは `v<version>`。
- [ ] タグ push → 署名つきで publish された Release が `releases/latest` になり、旧版 GUI の
      「Check for updates…」→ DL → Authenticode＋publisher 検証通過 → UAC msiexec → in-place 更新が通る。
- [ ] 更新適用の実機一周（検知→DL→検証→昇格適用→再起動）を管理者 PC で確認（§1 の SCM 一周と同枠）。

## （参考）M9.4 セッションで判断を仰がれ得る点 — リードの事前作業ではない

- サービス start/stop の**昇格方式**（UAC 昇格 / 特権ヘルパ / `sc` 経由）。非昇格のユーザーセッション
  GUI は既定でサービスを停止できないため、M9.4 の Plan でこの設計判断が上がる見込み。
- `cluster_token` の UI 取り扱い（read は presence のみ・書込みは write-only・echo/ログ厳禁）。秘密の実値は
  リードが配布・設定する前提。
