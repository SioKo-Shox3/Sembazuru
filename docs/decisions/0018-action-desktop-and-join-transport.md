# 0018: アクション専用デスクトップと Join の受け渡し経路

- 状態: 決定 2（Join の受け渡し）は確定。決定 1（アクション専用デスクトップ）は実装前の実測が残る
- 日付: 2026-09-17
- 前提: `docs/verification/2026-09-17-session0.md`（Session 0 の A/B 実測）、ADR 0016（ローカル特権分離）

Session 0 でアクションが `0xC0000142` で起動できない件（T-011）と、GUI の Join が
昇格したヘルパーへ秘密を渡す経路（T-010）について、二者の助言を突き合わせて方向を決めた。
助言は GPT（`codex`）と Fable（`claude`）に同じブリーフで独立に求めた。記録は
`.harness/advisor-gpt-2026-09-17.txt` と `.harness/advisor-fable-2026-09-17.txt`。

## 決定 1: アクションごとに専用のウィンドウステーションとデスクトップを作る

両者とも (a) を推した。既存のサービスステーションへ許可を足す (b) と、整合性の方針を
見直す (c) は両者とも退けた。

(b) を退ける理由: 実機でサービスが LocalSystem なら、ステーションは `Service-0x0-3e7$` になり
**同一セッションの全 LocalSystem サービスと共有される**。そこへ制限 SID の許可を足すと、
信頼できないリモート由来のコンパイラツリーが他サービスと同じデスクトップに乗り、
ウィンドウメッセージとフックの攻撃面を共有する。「既存の隔離を緩めない」に反する。
GitHub runner の仮想サービス SID での測定結果を実機に持ち込めない点も両者が指摘した。

(c) を退ける理由: 整合性を上げても解決しない見込みが高く、信頼できないコードの権限を
上げる代償が大きい。

### DACL の置き方

アクションのトークンは `CreateRestrictedToken` 由来なので、アクセスチェックは
**通常 SID 列と制限 SID 列の両方**を通る必要がある。制限 SID は
`crates/worker/src/sandbox.rs:469-487` で `[action_sid(乱数), Everyone, Authenticated Users,
Users, RESTRICTED]`。したがって専用オブジェクトの DACL には、通常側を満たすブローカーの SID と、
**制限側を満たす `action_sid`** の両方が要る。`action_sid` はアクションごとの乱数なので、
これだけで他アクションからの越境が DACL で閉じる。

`Everyone` / `Authenticated Users` / `Users` / `Administrators` を許可の根拠にしない。
`WRITE_DAC` / `WRITE_OWNER` / `DELETE` を `action_sid` に与えない（自分のステーションの
DACL を書き換えられるため）。

### 実装前に潰す罠（両者の指摘）

- `CreateDesktop` は**呼び出しプロセスの現在のステーション**にしか作れない。
  worker が `SetProcessWindowStation` で往復する形はプロセス全体の状態を触るため、
  並列アクション間で直列化が要る。GPT は所有権を単純にする専用の launcher プロセスを挙げた。
- 名前先取り。NULL 名はログオンセッション単位で命名されアクション単位にならない。
  一意名 + `CWF_CREATE_ONLY` で排他する。作成時から明示のセキュリティ記述子を渡す
  （既定の記述子は広くなりうるうえ、作成後に直す形には競合窓がある）。
- **ジョブの UI 制限は DACL とは別の拒否層**。現在 `0xfe` で `GLOBALATOMS` を含む。
  ACL を直しても、この層で落ちる API がありうる。
- `CreateProcessAsUser` の文書は対象ステーション／デスクトップへの full access を要求する。
  最小権限だけを付けた構成と衝突しうる。衝突する場合は、広い権限を共有ステーションではなく
  **アクション専用オブジェクトに限定して置く**という妥協になる。
- desktop heap には上限がある（非対話デスクトップは既定 768KB/desktop）。並列度を上げると
  `CreateDesktop` が失敗し、ワーカーの実効並列度が静かに落ちる。後退経路として
  ワーカー単位の共有ステーション + アクション単位デスクトップを残す。
- 後始末は、最後のハンドルとプロセス参照が消えれば消滅するので永続残骸は出ない。
  `CloseWindowStation` は「現在のステーション」だと失敗し、`CloseDesktop` は自プロセスの
  スレッドが使用中だと失敗する。

### 実装前に必要な実測（GPT の留保）

Fable は「制限 SID の二重チェックが原因」と断定したが、GPT は **SACL（整合性ラベル）が
未測定なので DACL だけが原因とは断定できない**と留保した。MIC は DACL より先に評価される。
この留保は妥当なので、設計に入る前に診断を次の項目まで広げる。

- ステーションとデスクトップの SACL、整合性 SID、mandatory mask
- アクショントークンの `TokenRestrictedSids`、通常 SID、`TokenMandatoryPolicy`
- `0xfe` の各 `JOB_OBJECT_UILIMIT_*` の展開結果
- 最初に失敗する USER32/GDI32 呼び出しと Win32 error

最小権限は「プローブした値」であって実測値ではない。診断の mask を1ビットずつ削って
境界を出すのが確定手段になる。

### この決定が誤りだと分かる観測

専用ステーションとデスクトップ、正しい制限 SID の ACE、`lpDesktop` をすべて揃え、
対象 API の拒否も無いのに同じ `0xC0000142` が出ること。その場合の次の容疑は
DLL ロード経路、csrss/BaseSrv 接続、`\BaseNamedObjects` の DACL、`DISABLE_MAX_PRIVILEGE`
との相互作用。

## 決定 2: Join の payload は GUI が立てた名前付きパイプで渡す

両者とも (b) を推した。一時ファイル (a) は秘密がディスクに残るうえ、High のプロセスが
ユーザー書き込み可能パスを読む形が symlink/reparse の定番経路になるため両者が退けた。
GUI 全体の昇格 (c) は、短時間の設定更新のために GUI の攻撃面を常時 High に上げるため両者が退けた。
Status プレーンの再利用は呼び出し元認証が無いため対象外（ADR 0016 の境界を変えない）。

GUI が一回限りのパイプを先に作り、名前を argv で渡し、昇格した storectl が接続して
payload を読む。`FILE_FLAG_FIRST_PIPE_INSTANCE`、`PIPE_REJECT_REMOTE_CLIENTS`、
インスタンス数 1、明示のセキュリティ記述子（既定の記述子は Everyone や Anonymous の
読み取りを含みうるので NULL に依存しない）。storectl 側は
`SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` で接続し、名前を先取りした偽サーバーに
昇格トークンを impersonate されないようにする。

### 決定: パイプの DACL は Administrators のみ

二者の意見が割れたが、2026-09-18 に GPT が (b) を撤回し、**(a) Administrators のみ**で一致した。
根拠は logon SID の不一致の実証ではなく、**正規の helper が既に満たしている認可に合わせ、
不要な読み取り許可を増やさないこと**。`storectl` の `authorize`
(`crates/config-store/src/bin/sembazuru_storectl.rs:271`) は token-maintenance 動詞・Administrators 所属・
昇格を要求する。別の管理者アカウントで昇格しても同じ条件を満たすので、(a) は GUI と helper の
logon SID の一致に依存しない。

| 案 | GUI と同じ logon SID を持つ非昇格コード | 正規の昇格 helper |
|---|---|---|
| (a) Administrators のみ | BA が deny-only なので許可しない | 有効な BA で許可 |
| (b) logon SID のみ | logon SID で許可してしまう | その SID を持つことに依存 |
| (c) 両方 | logon SID で許可してしまう | BA で許可 |

(c) は AND にならない。同じ権限を与える許可 ACE は、どちらかに一致すれば通る。deny-only の BA は
別の logon SID の許可を打ち消さない。(b)/(c) の余分な読み取り許可は、名前の先取り検出ではなく
**秘密の機密性**の問題として評価する。PID 照合を終えるまで payload を書かなければ接続だけでは漏れないが、
正規の helper に要らない許可を足す理由がない。(a) も特定の helper を識別しないので、PID 照合は依然必要。

実測で分かったのは次の2点で、どちらも UAC 前後の SID 一致の証拠ではない
（`docs/verification/2026-09-18-interactive-station-and-logon-sid.md`）。

- 非昇格の管理者トークンでは `S-1-5-32-544` が deny-only (`0x10`) で、許可 ACE に一致しない。
- logon SID (`SE_GROUP_LOGON_ID`) は生の `TokenGroups` にしか現れない。`whoami /groups` と
  .NET の `WindowsIdentity.Groups` は返さない。logon SID を使う実装はここで足を取られる。

#### 実装時の罠

- 権限 mask を広げすぎない。一方向なら `PIPE_ACCESS_OUTBOUND` と `D:P(A;;GR;;;BA)` が出発点。
  双方向にする場合、`GENERIC_WRITE` は `FILE_CREATE_PIPE_INSTANCE` を含むのでそのまま許可しない。
- PID 照合の前に秘密を書かない。`SEE_MASK_NOCLOSEPROCESS` のハンドルを保持したまま
  `GetNamedPipeClientProcessId` と突き合わせ、取得も照合も失敗したら中止する。helper 側の
  `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` は相手確認とは別の目的なので維持する。
- `FILE_FLAG_FIRST_PIPE_INSTANCE` は作成時の競合検出であって、最後のハンドルが閉じた後まで名前を
  予約しない。サーバーハンドルを閉じて同名で作り直す経路を作らない。
- Administrators のみを「同一ユーザーの悪意あるコードからの完全な隔離」と呼ばない。GUI 自身が秘密を持ち、
  所有者には暗黙の `WRITE_DAC` がある。UAC を security boundary としない整理を維持する。

#### この決定が誤りだと分かる観測

- 正規の UAC 経路で `authorize` を通る helper が、適正な要求アクセス権でも BA のみのパイプに接続できず、
  logon SID の ACE を足したときだけ成功する。
- DACL の変更もハンドルの継承・複製もなしに、BA が deny-only の非昇格クライアントに
  `FILE_READ_DATA` が許可される。

#### 二者の当初の主張（記録）

- Fable: **Administrators のみ**。標準ユーザーが GUI を使うと `runas` は別の管理者アカウントで
  子を起動するため、GUI のユーザー SID に絞ると昇格側が繋げない。非昇格プロセスは
  Administrators が deny-only なので許可 ACE に一致しない。
- GPT: 現在の **logon SID** に限定する。ただし GPT 自身が「正規の UAC 経路で GUI と helper の
  logon SID が異なる場合」を、自分の推奨が誤りだと分かる観測として挙げている。

実測で決める。標準ユーザーの GUI から別の管理者アカウントで同意したときに join が通るかを
確かめる。通らないなら logon SID 案は落ちる。

### 認証の到達点を正直に置く

GPT は helper 側も GUI 側も相手の path と署名まで検証することを求めた。Fable は
「昇格した子が正しい GUI に繋いだか」は**原理的に検証できない**とした。GUI は Medium で動き、
同一ユーザーの Medium のコードは GUI に注入できる。Microsoft 自身 UAC を security boundary と
していない。

採るのは Fable の整理とする。設計目標は次の3点に置き、それ以上を主張しない。

1. 秘密を argv とディスクに残さない
2. 昇格したトークンを偽サーバーになりすまされない
3. パイプ名の先取りとすり替えを検出する

GUI 側の相手確認は `SEE_MASK_NOCLOSEPROCESS` で得たプロセスハンドルを握ったまま
`GetNamedPipeClientProcessId` と突き合わせる形を採る（ハンドルを握っている限り PID は再利用されない）。

UAC が無効な環境では join の保護は無い。これは文書化の対象で、他のどの案でも同じ。

### payload の形

1本のバージョン付き、長さ前置の封筒にする。論理フィールドは `cluster_token`、
`daemon_config`、`worker_config` の3つで、`MachineTokenUpdate` に 1:1 で対応させる。
トークンの既存の一行制約はフィールド内部で維持する。理由は
`prepare_machine_cluster_token_update` が3対象を1取引として受けるため、入力も1取引として
1回の認可・1回の上限・1つの `Zeroizing` バッファで扱うのが契約と一致すること。
分割メッセージにすると解析・再試行・順序付けの失敗状態が増える。

### 決定: Join 後のサービス反映は storectl join が担当する

昇格した `storectl join` の責任範囲を次の順に固定する。順序は既存実装から強制される。
サービスは稼働中に root の lease を保持し (`enter_service_runtime_at`,
`crates/config-store/src/windows.rs:573`)、更新側は共有モード 0 の排他 lease を取って、衝突したら Busy を返す
(`acquire_committed_root_lease`, `crates/config-store/src/windows.rs:1105`)。稼働中に書き換えてから
再起動する順序では更新が Busy で拒否され、逆に更新ガードを保持したまま起動するとサービス側が lease を取れない。

1. 既存の `authorize` を通し、payload のサイズ・形式・許可フィールドを検証する。
2. SCM 経由で `SembazuruDaemon` と `SembazuruWorker` を停止し、停止完了を確認する。
3. 更新ガードを取得し、既存の journal による 3 対象の更新を完了する。
4. **更新ガードを解放してから**サービスを起動し、結果を GUI に返す。

SCM 操作は対象名と操作を固定し、停止・開始・状態照会の権限だけを要求する。GUI や Status/Admin に
権限を足さない。**設定更新の完了とサービス反映の完了は別の結果にする。** 起動に失敗したら
「保存済み・反映未完了」と返し、Join 成功にしない。未完了 journal が残る場合は既存の回復処理を使う
（現実装も未完了 journal があるサービス起動を拒否する: `crates/config-store/src/token_update.rs:694`）。

罠が2つある。設定更新ガードだけでは別の Join による停止・起動の交錯を防げないので、再起動までの
Join 全体を直列化する必要がある。また現コードは実行ループ開始前に `Running` を報告する
(`crates/agent/src/service.rs:188`) ため、SCM の `Running` 一回を動作確認の代用にしない。
