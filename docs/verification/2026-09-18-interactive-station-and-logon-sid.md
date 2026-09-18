# 2026-09-18: 対話セッションのステーションと logon SID の実測

- 対象: このマシン（Windows 11 Home 10.0.22631、Microsoft アカウント / CloudAP ログオン、
  管理者アカウントを非昇格で使用）。セッションは対話 (session 1)。
- 目的: T-010（Join の payload を渡すパイプの DACL を誰に絞るか）と
  T-011（Session 0 でアクションがステーションとデスクトップを開けない件）の前提を実測で固める。
- 測り方: 読み取りのみ。`GetTokenInformation(TokenGroups)`、`GetUserObjectSecurity` +
  `ConvertSecurityDescriptorToStringSecurityDescriptorW`、および T-012 で追加した
  `session0_diagnostic_*` の単体テスト。昇格も、サービスの起動も、資格情報の入力も行っていない。

## 1. logon SID は存在するが、一般的な道具は見せない

生の `TokenGroups` には次がある。

```
S-1-5-5-0-425489    attributes=0xc0000007
```

`0xC0000000` は `SE_GROUP_LOGON_ID`。つまりこのトークンは logon SID を持ち、ログオンセッションを
識別している。一方で

- `whoami /groups /fo csv` の 15 行に `S-1-5-5-*` は無い。
- `[Security.Principal.WindowsIdentity]::GetCurrent().Groups`（12 件）にも無い。

**logon SID を使う実装と診断は、生の `TokenGroups` を読まなければならない。** この確認を飛ばすと
「logon SID が無い」という誤った結論に達する（最初にこの誤りを踏んだ）。

## 2. 非昇格の管理者トークンでは Administrators が deny-only

```
S-1-5-32-544    attributes=0x00000010    (SE_GROUP_USE_FOR_DENY_ONLY)
```

Administrators だけを許可する ACE には、同じユーザーの非昇格プロセスは一致しない。

## 3. 対話ステーションとデスクトップの DACL / ラベル

```
station.dacl : D:(A;NP;LCWP;;;S-1-5-21-…-1001)(A;OICIIO;GAGXGWGR;;;S-1-5-5-0-425489)
               (A;NP;0xf037f;;;S-1-5-5-0-425489)(A;NP;0x20363;;;S-1-5-96-0-1)
               (A;NP;0xf037f;;;S-1-5-90-0-1)(A;OICIIO;GAGXGWGR;;;RC)(A;NP;0xf037f;;;RC)
               (A;OICIIO;CCDCLCDTLOGX;;;BA)(A;NP;DCLCWPDTCRRC;;;BA)
               (A;OICIIO;GAGXGWGR;;;SY)(A;NP;0xf037f;;;SY)
               (A;OICIIO;GXGR;;;S-1-15-2-2)(A;NP;0x20327;;;S-1-15-2-2)
               (A;OICIIO;GXGR;;;AC)(A;NP;0x20327;;;AC)
station.label : S:(ML;;NW;;;LW)
desktop.dacl : D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-5-0-425489)(…;S-1-5-96-0-1)
               (…;S-1-5-90-0-1)(…;RC)(A;;CCDCLCDTLOCRRC;;;BA)(…;SY)(…;S-1-15-2-2)(…;AC)
desktop.label : S:(ML;;NW;;;LW)
```

読みどころは3つ。

1. **`RC`（`S-1-5-12` RESTRICTED）に `0xf037f` の許可 ACE がある。** ステーションにもデスクトップにも
   ある。制限付きトークンの二重アクセスチェックの制限 SID 側が、ここで満たされる。
2. ラベルは両方とも `ML;;NW;;;LW` = Low の no-write-up。Medium のアクションは書き込み側も通る。
3. ユーザー SID 自身への許可は `LCWP` しかない。実際に開けるのは logon SID の ACE によるもので、
   ユーザー SID の ACE によるものではない。

## 4. 制限付きアクショントークンでも、この対話ステーションは開ける

T-012 で足した `diagnostic_ui_probe` の実測（`session0_diagnostic_ui_probe_names_its_first_refusal`）:

```
scope=broker-impersonated;first_failure=none;steps=[
  station:maximum_allowed:mask=0x02000000;allowed=true;gle=0,
  station:read_attributes:mask=0x00000002;allowed=true;gle=0,
  station:action_mask:mask=0x0000006e;allowed=true;gle=0,
  desktop:maximum_allowed:mask=0x02000000;allowed=true;gle=0,
  desktop:read_objects:mask=0x00000001;allowed=true;gle=0,
  desktop:action_mask:mask=0x000000cf;allowed=true;gle=0]
```

同じく `diagnostic_user_object_label` の実測:

```
label_aces=[type=17;flags=0;mask=0x00000001;sid=S-1-16-4096]
```

## 5. この実測が T-011 に与えるもの

Session 0 の実測（`docs/verification/2026-09-17-session0.md`）では、同じ形のアクショントークンが
サービスのステーションとデスクトップを `gle=5` で開けなかった。対話側との違いは
**制限 SID 側を満たす ACE があるかどうか**に見える。対話ステーションには `RC` の許可 ACE があり、
サービスのステーションの DACL にはサービス SID と Administrators しかなかった。

ただしこれは相関であって、まだ因果の確定ではない。Session 0 側の SACL（整合性ラベル）と Job の
UI 制限の展開は T-012 で記録できるようにしたが、実測は GitHub runner 待ちである。ラベルが対話側と
同じ Low の no-write-up なら MIC では説明できず、DACL と Job UI 制限が残る容疑になる。

## 6. このマシンでは測れないこと

- 別の管理者アカウントで同意する UAC 経路（標準ユーザーの GUI から昇格する形）。第二のアカウントが
  無く、資格情報の入力は行わない。
- 同一ユーザーの UAC 昇格で logon SID が保たれるか。人が UAC のプロンプトを押す必要がある。
- Session 0 のサービス配下の値。GitHub runner の実測を待つ。
