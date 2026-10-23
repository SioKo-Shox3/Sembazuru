# 2026-09-23: Session 0 でアクション専用ステーションを作れるか

- run: <https://github.com/SioKo-Shox3/Sembazuru/actions/runs/35772303618>
  job `Measure worker creation flags in Session 0 / session0` は completed / success。
- 対象 SHA: `b4a46f218abf5006764f9619827e4fe9fe721ce6`（診断レコード version 6）。
- 目的: T-011 の実装 (2f0e8b1, a947eaf) が Session 0 で効くかを確かめる。レコードの `ActionDesktop` 欄は、
  製品の起動経路と同じ `ActionDesktop::create` を呼んだ結果を記録する。

## 結果

```
ActionDesktop = unavailable:action desktop: create window station failed (Access is denied. (os error 5))
Broker        = user=S-1-5-80-1970768882-…-218607474;integrity=12288
Station       = Service-0x0-336f7b$   Desktop = Default
Baseline / NoWindow: SpawnSucceeded=True, ChildExit=0xc0000142
分類: NO_WINDOW_NOT_SUFFICIENT
```

**サービスとして動くブローカーでも、ウィンドウステーションを作れない。** 作成は `ERROR_ACCESS_DENIED` で拒否され、
起動経路は継承へ戻ったので、子は従来どおり `0xc0000142` で落ちた。これは T-011 の実装が効かなかった理由であり、
同日の CI (run 35444179338) で installer の installed worker が依然 `0xc0000142` だったことと整合する。

ブローカーは LocalSystem ではなく**仮想サービスアカウント**（`S-1-5-80-…` = `NT SERVICE\<サービス名>`、High 整合性）で
動いている。対話セッションの一般ユーザーと同じく、この ID には新しいウィンドウステーションを作る権限が無い。

## ADR 0018 の前提との食い違い

ADR 0018 は、既存のサービスステーションへ許可を足す案 (b) を次の理由で退けた。

> 実機でサービスが LocalSystem なら、ステーションは `Service-0x0-3e7$` になり
> 同一セッションの全 LocalSystem サービスと共有される。

実測はこれと異なる。

- ステーション名の末尾はサービス自身のログオンセッションの LUID で、実行ごとに変わる
  （9/17 `27fb60`、9/18 `283c90`、9/23 `336f7b`）。LocalSystem の `3e7` ではない。
- 製品の worker も仮想アカウント (`NT SERVICE\SembazuruWorker`、`hooks/test/m9_installer_acl.ps1` の `$workerSid`) で
  インストールされる。

したがって **worker が使うステーションは worker のログオンセッション専用で、他のサービスとは共有されない。**
(b) を退けた理由は、実際の配置には当てはまらない。ただし、そのステーションを同じ worker の複数のアクションが
共有する点は残るので、(b) をそのまま採れるという意味ではない。

## この実測が閉じたもの / 開いたもの

- 閉じた: 「アクションごとに新しいウィンドウステーションを作る」経路は、仮想サービスアカウントでは成立しない。
- 閉じた: 診断 v6 は、専用オブジェクトの作成可否と子の終了コードを同時に記録でき、原因を帰属できることを示した。
- 開いた: 設計の選び直し。ブローカーは自分のステーション上にデスクトップを作れる見込みがある
  （そのステーションの DACL はサービス SID に `0x000f006e` を与え、`WINSTA_CREATEDESKTOP` を含む）。
  ただし子はステーション自体のアクセス検査も通る必要があり、現状はそこで拒否されている
  （2026-09-18 の `UiProbe`、`station:maximum_allowed` から拒否）。デスクトップだけでは足りない。
