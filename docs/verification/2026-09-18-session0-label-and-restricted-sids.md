# 2026-09-18: Session 0 の整合性ラベルと制限 SID の実測

- run: <https://github.com/SioKo-Shox3/Sembazuru/actions/runs/35347944739>
  job `Measure worker creation flags in Session 0 / session0` は completed / success。
- 対象 SHA: `3fbed87982f94ca2f69a9291d158f655f3f437c9`。checkout も呼び出し元の workflow 定義も同じコミット。
- runner: Windows Server 2025 (10.0.26100)、hosted。
- 目的: T-012。0xC0000142 の拒否が **DACL 由来か MIC 由来か Job UI 制限由来か**を切り分ける。
  ADR 0018 で GPT が置いた留保「SACL 未測定なので DACL だけが原因とは断定できない。MIC は DACL より
  先に評価される」に答える。

## 結論

**MIC ではない。DACL である。** 制限付きトークンの制限 SID 列に一致する ACE が
サービスのステーションとデスクトップに1つも無いため、通常側が通っても制限側で落ちる。

## 実測値（version 5 のレコードから）

分類は前回と同じ `NO_WINDOW_NOT_SUFFICIENT` (`service=0x53425b32`)、`session=0`、`markers=0x07`、
両アームとも `ChildExit=0xc0000142`。

### 整合性ラベル（今回初めて測った）

```
StationSacl = label=absent;implied_integrity=8192
DesktopSacl = label=absent;implied_integrity=8192
Action      = ...;integrity=8192;mandatory_policy=0x00000003
```

ステーションにもデスクトップにも**ラベル ACE が無い**。ラベルの無いオブジェクトは Medium 扱いなので、
Medium のアクション (`integrity=8192`) に対して no-write-up は働かない。`mandatory_policy=0x3` は
`NO_WRITE_UP | NEW_PROCESS_MIN` で通常どおり。**整合性では説明できない。**

### DACL（制限 SID 側に一致する ACE が無い）

```
Station = Service-0x0-283c90$   Desktop = Default
StationDacl = control=0x8004;aces=[
  type=0;flags=0; mask=0x000f006e;sid=S-1-5-80-1970768882-…-218607474,
  type=0;flags=13;mask=0x000f00cf;sid=S-1-5-80-1970768882-…-218607474,
  type=0;flags=0; mask=0x00000100;sid=S-1-5-32-544,
  type=0;flags=13;mask=0x000000c1;sid=S-1-5-32-544]
DesktopDacl = control=0x8004;aces=[
  type=0;flags=0;mask=0x000f00cf;sid=S-1-5-80-1970768882-…-218607474,
  type=0;flags=0;mask=0x000000c1;sid=S-1-5-32-544]
```

許可されているのは**サービス SID と Administrators だけ**。アクションの制限 SID 列は
`[action_sid(乱数), Everyone, Authenticated Users, Users, RESTRICTED]`
(`crates/worker/src/sandbox.rs:469-487`) で、この DACL にはそのどれにも一致する ACE が無い。
アクションの通常側のユーザーは同じサービス SID なので通常側は通る。二重チェックの制限側だけが落ちる。

ローカルの対話ステーションとの差がここに出る。対話側には `RC` (`S-1-5-12` RESTRICTED) の
`0xf037f` 許可 ACE があり、制限付きトークンでも6段すべて開けた
（`docs/verification/2026-09-18-interactive-station-and-logon-sid.md`）。サービス側にはその ACE が無い。

### 順序付きの open（今回初めて測った）

```
UiProbe = scope=broker-impersonated;first_failure=station:maximum_allowed;gle=5;steps=[
  station:maximum_allowed:mask=0x02000000;allowed=false;gle=5,
  station:read_attributes:mask=0x00000002;allowed=false;gle=5,
  station:action_mask:mask=0x0000006e;allowed=false;gle=5,
  desktop:maximum_allowed:mask=0x02000000;allowed=false;gle=5,
  desktop:read_objects:mask=0x00000001;allowed=false;gle=5,
  desktop:action_mask:mask=0x000000cf;allowed=false;gle=5]
```

**`MAXIMUM_ALLOWED` すら落ちる。** このトークンにはこのステーションで許される権利が1つも無い。
最小権限を1ビットずつ削って探す作業に意味が無いことも、ここで分かる。与えるべきは
「もっと狭い mask」ではなく、**制限 SID 側に一致する ACE そのもの**である。

### Job の UI 制限（今回初めて名前で展開した）

```
BaselineJobUiLimits = NoWindowJobUiLimits =
  handles=0;readclipboard=1;writeclipboard=1;systemparameters=1;
  displaysettings=1;globalatoms=1;desktop=1;exitwindows=1;unknown=0x00000000
```

`JOB_OBJECT_UILIMIT_HANDLES` は**設定されていない**。また `UiProbe` はブローカー側で
アクショントークンを偽装して実行しており、**ブローカーはアクションのジョブの中に居ない**。
したがってこの gle=5 に Job の UI 制限は関与しない。拒否層としての Job UI 制限は今回の 0xC0000142 の
説明にならない（子プロセス側では依然として別層として存在する）。

## この実測が閉じたもの / 残すもの

- 閉じた: T-011 の `blocked-on`（SACL 未測定）。MIC は除外され、DACL が原因と確定した。
- 閉じた: 「最小権限は測定値ではなくプローブした値」という留保のうち、mask を削る方向の探索。
  許可が皆無なので削る境界が無い。
- 残る: 専用ステーション/デスクトップの DACL に、制限側を満たす `action_sid` の ACE を置く設計（T-011）。
  `CreateProcessAsUser` が対象オブジェクトへの full access を要求する点との折り合いは未検証。
- 付随: version 5 のレコードが hosted runner 上で PowerShell 側の解析器を通り、
  新しい4項目がすべて読めた。Rust と PowerShell の契約は実環境でも一致している。
