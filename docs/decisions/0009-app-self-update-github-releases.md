# 0009 — アプリ自己更新（GitHub Releases 確認 → DL → 署名検証 → ユーザー承認で MSI 更新）

- ステータス: **採択（ACCEPTED）。** 起案: 2026-06-19。決定者承認: 2026-06-19（プロジェクトリード）。
  方針はプロジェクトリードが決定（2026-06-19、選択肢「DL＋ユーザー承認で適用」）。
  M9.6 で実装着手（本文の方針は確定。実 OV cert subject の publisher pin は M7/リリースへ繰延）。
- 決めること: 常駐 GUI が GitHub Releases を見て新版を検知し、ユーザーの明示承認のもとで
  署名済み MSI を取得・適用する仕組みの **(1) 起点と置き場所**、**(2) 検知/取得/適用フロー**、
  **(3) 信頼境界（TLS＋署名/publisher 検証）**、**(4) EDR 整合と新規ネットワーク挙動の開示**、
  **(5) 依存追加（外向き HTTP）の是非**。
- 判定基準: 非交渉事項（正確性 > 速度／**ローカルフォールバック常時**／clang-cl ファーストクラス／
  No UBA）と、ADR 0008 §3 の EDR 整合（**開示外の persistence/TTP を足さない**）、
  `docs/security/edr-allowlist.md` の「最小ネットワーク・署名集合＝同梱集合」を崩さないこと。
  更新は **add-on** であり、失敗・拒否で既存の動作環境を壊さないこと。
- 関連: ADR `0008-productization-installer-gui-residency.md`（WiX MSI・GUI 常駐・svcctl 自己昇格）、
  ADR `0006-trust-and-auth.md`（OV 証明書購入は決定者所有・繰延）、ADR `0007-arbitrary-process-distribution.md`
  ④（EDR steady-state に新 TTP を足さない）、`docs/security/edr-allowlist.md`、`installer/`（MSI／
  `MajorUpgrade`・固定 `UpgradeCode`）、`hooks/test/sign_smoke.ps1`（署名機構）。

## 背景

M9.5 で署名対応 MSI 配布が整い、winget も配布チャネルとして想定されている（ADR 0008）。一方、導入後の
**更新導線はゼロ**。OSS の日常採用では「入れたあとに最新へ追従できる」ことが要るが、現状ユーザーは
リリースを自力で監視して手で入れ直すしかない。これを GUI に載せ、**非開発者でも安全に更新**できるようにする。

ただし「アプリが更新を取得して実行する」挙動は AV/EDR が最も警戒するパターン（自動コード取得＋実行）であり、
M9.5 で積み上げた `edr-allowlist.md` の姿勢（最小持続化・最小ネットワーク・自己改変なし・署名集合＝同梱集合）と
正面からぶつかりうる。よって**サイレント自動更新は採らず**、ユーザーが取得と適用を明示承認する方式に限定する
（リード決定 2026-06-19）。

### 実装前提（M9.5 後の現状調査で確定）

- **外向き HTTP は皆無。** ワークスペース全 `Cargo.toml`／`Cargo.lock` に reqwest/hyper/rustls/native-tls/ureq
  なし。`tonic` は loopback gRPC（平文 HTTP/2、TLS feature 無効）専用。GUI（`crates/gui/src/client.rs`）は
  `resolve_loopback()` で 127.0.0.1 接続を強制＝外向き dial 経路なし。
- **GUI に version 表示なし。** `env!("CARGO_PKG_VERSION")` は実行時利用可だが UI 未使用。バージョン源は単一
  （ルート `Cargo.toml` `workspace.package.version = "0.0.1"`、`repository = github.com/SioKo-Shox3/Sembazuru`）。
  MSI の `ProductVersion` は WiX 変数（`installer/Package.wixproj`）で Cargo 版と**手動同期**。
- **MSI は in-place 更新可能。** `installer/sembazuru.wxs` の固定 `UpgradeCode`＋`<MajorUpgrade>` により
  `msiexec /i <newer>.msi` 一発で旧版削除→新版導入が 1 トランザクションで走る（サービス/ACL/FW/設定の更新は
  MSI 側で処理）。raw な exe 差し替えではサービス/データ領域を正しく更新できない。
- **昇格パターンは再利用可能。** `crates/gui/src/svcctl/mod.rs` の `request_action`（`ShellExecuteExW("runas")`
  ＋full path `current_exe()`＋`WaitForSingleObject`＋`GetExitCodeProcess`、`ERROR_CANCELLED` で拒否扱い）を
  そのまま `msiexec.exe /i <msi>` の昇格起動に転用できる（GUI 本体は非昇格のまま、UAC は 1 回）。
- **署名検証はネイティブで可能。** `windows-sys` は GUI に導入済み（`Win32_Security` 有効）。`WinVerifyTrust`
  を使うため `Win32_Security_WinTrust` feature を足すだけ（**新規 crate 不要**）。`hooks/test/sign_smoke.ps1` は
  Authenticode 署名機構（実 cert は M7 繰延、現状 placeholder）。
- **proto に version 面なし。** loopback `Status`/Admin（`crates/proto/.../control.proto`）に version RPC/フィールド
  はなく、追加も不要＝更新確認は **GUI プロセス完結**（daemon 非関与）。

## 決定

### (1) 起点＝GUI プロセス完結・ユーザーセッション。daemon/サービスは非関与
更新確認・取得・適用は **`sembazuru-gui.exe`（ユーザーセッション）内**で行う。session 0 のサービスは関与しない。
GUI はインターネット側に出てよい唯一のコンポーネント（フック DLL はソケットを開かない＝`edr-allowlist` 維持）。
更新の適用（MSI 実行）は既存 svcctl と同じ UAC 昇格で行い、GUI 本体は非昇格を保つ。

### (2) フロー＝検知 → 取得 → **検証** → ユーザー承認 → 昇格適用
1. **検知**: GUI 起動時（プロセス内・1 回・スロットル）と、トレイ/Settings の「Check for updates…」手動操作で、
   `https://api.github.com/repos/SioKo-Shox3/Sembazuru/releases/latest` を GET し `tag_name` を取得。
   `env!("CARGO_PKG_VERSION")` と semver 比較し、新しければ通知（現バージョン/新バージョン/リリースノートリンク）。
   **バックグラウンドの定期ポーリング（スケジュールタスク/Run キー/常駐ポーラ）は作らない**（ADR 0008 §3／
   ADR 0007 ④の「新 TTP を足さない」と整合）。
2. **取得**: ユーザーが「ダウンロード」を押したときのみ、リリース資産の署名済み MSI を一時ディレクトリへ
   ストリーム保存（`reqwest`、TLS）。GitHub の資産ホスト（`objects.githubusercontent.com`）への HTTPS を含む。
3. **検証（適用の前提・必須）**: 取得 MSI を `WinVerifyTrust` で Authenticode 検証し、**publisher（OV 証明書の
   subject）を pin して一致を確認**。検証失敗・publisher 不一致なら**実行経路に進ませない**（ホストが GitHub でも
   ホスト信頼だけに依存しない＝TLS＋署名の二重ゲート）。
4. **承認＋適用**: 検証通過後にユーザーが「インストール」を押すと、svcctl と同じ `ShellExecuteExW("runas",
   "msiexec.exe", "/i \"<temp>.msi\" /passive")` で昇格実行。`MajorUpgrade` が in-place 更新を担う。完了後 GUI は
   再起動を促す/自動再起動（単一インスタンス mutex と整合する形で）。

### (3) 信頼境界＝TLS＋Authenticode＋publisher pin の三点。ホスト信頼に依存しない
- 通信は TLS（`reqwest` の rustls 既定）。
- 取得物は実行前に必ず Authenticode 検証＋publisher pin。**未検証/不一致のバイナリは決して実行しない。**
- 「同梱集合＝署名集合」（ADR 0008／`edr-allowlist`）を更新版にも適用：配布 MSI は同一 OV cert で署名済み。
- 実 OV cert の subject 文字列は M7/リリースで確定（現状 placeholder）。pin はリリース cert 確定後に埋め込む。

### (4) EDR 整合＝開示を更新し、持続化は増やさない
- 新規挙動「`sembazuru-gui.exe` がユーザー操作起点で `api.github.com`／`objects.githubusercontent.com` へ
  外向き HTTPS を行い、署名・publisher 検証済み MSI のみ UAC 昇格 msiexec で適用する」を `edr-allowlist.md` に
  **明示開示**（「What Sembazuru does NOT do」＋ネットワーク姿勢＋新「Update」節）。
- **持続化は増やさない**：更新確認に**スケジュールタスク/Run キー/常駐ポーラを足さない**（持続化は引き続き
  「2 サービス＋GUI Startup ショートカット 1 つ」のまま）。
- フック DLL のソケット非開放（`edr-allowlist`）は不変。外向きは GUI のみ。

### (5) 依存＝`reqwest`（外向き HTTPS）を GUI に追加、検証は windows-sys 既存
- `reqwest`（rustls）を `crates/gui` に新規追加（外向き HTTPS の最小実装、既存 tokio runtime で動く）。
  これは唯一の新規外部依存であり `edr-allowlist` 開示で正当化する。
- 署名検証は `windows-sys` の `Win32_Security_WinTrust`（feature 追加のみ、新 crate なし）。
- MSVC 非依存・clang-cl 不変（更新はビルド経路に介入しない）。

## 影響

- `crates/gui`: トレイ第3メニュー「Check for updates…」、Settings/通知 UI（現バージョン/新バージョン/ノート）、
  更新クライアント（GitHub API GET・MSI ストリーム DL・`WinVerifyTrust` 検証・msiexec 昇格適用）。`reqwest` 追加、
  `windows-sys` に `Win32_Security_WinTrust`。
- `docs/security/edr-allowlist.md`: 外向き HTTPS（GUI・ユーザー起点）と更新フローを開示追記。持続化は不変を明記。
- リリース手順: Cargo 版と WiX `ProductVersion` の同期をチェックリスト化（不一致だと検知比較がずれる）。
  リリース MSI の OV cert subject を GUI の publisher pin に反映。
- `docs/DESIGN.md`／`docs/deferred.md`: 実装着手時に M9.x（または独立マイルストーン）として位置づけを追記。

## 繰延・未決（本 ADR の射程外／実装時に確定）

- **実 OV 証明書の subject 確定と publisher pin の埋め込み**（M7/リリース所有・決定者）。確定までは検証機構を
  placeholder cert で実証（M7.2 と同方針）。
- GitHub API レート制限（未認証 60/h）への対応：on-demand 主体なら十分。必要なら ETag/If-None-Match。
- winget（`winget upgrade`）を補完的な手動更新経路として案内するか（ADR 0008 の配布チャネルと整合）。
- 自動ロールバックは持たない（`MajorUpgrade`＋旧リリース再導入で対応）。デルタ更新も持たない（フル MSI）。
- 更新確認を「起動時 1 回」に加えてユーザー任意の頻度に広げるか（**スケジュールタスクは使わない**前提で）。
