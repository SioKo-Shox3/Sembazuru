# 0005 — ビルドシステム横取り方式と LocalIntake プロトコル（M6）

- ステータス: **一部決定（ACCEPTED）・残り計画中。** 起案: M6.0、2026-06-14。
  決定者承認: プロジェクトリード、2026-06-14（受付口＝ループバック gRPC、M6 到達範囲＝MSBuild/VS まで、
  M5 繰越＝e2e 必須配線＋Abort 実 kill、で承認）。
- 決めること: `docs/DESIGN.md` §7 M6 と「Done when（既存プロジェクトを最小設定で分散ビルド）」、
  §8（MSVC リモート実行のライセンスグレー／EDR）、§10（勝ち筋＝非 UE・汎用 Windows）が M6 に委ねた、
  **(1) ビルドシステムからコンパイラ起動を横取りする方式**、**(2) ランチャ↔daemon の受付口プロトコル**、
  **(3) MSVC ライセンス境界への非依存設計**、**(4)「最小設定」の定義と無設定ビルドの受け入れ基準**。
- 判定基準: 正確性 > 速度（非交渉 #1）、ローカルフォールバック常時（#2）、UBA コード非取り込み（#3）、
  clang-cl ファーストクラス（#4）。

> **後続決定:** この ADR の M6.0 時点では LocalIntake を loopback TCP としたが、local caller を識別できず
> LocalSystem service の権限で fallback できるため、[ADR 0016](0016-local-privilege-separation.md) と
> commit `68e5422` が Windows production transport を machine-wide authenticated named pipe へ置換した。
> 以下の loopback 記述は M6 当時の履歴であり、サービス／RPC セマンティクスだけが現行である。

## 決定

### 1. 横取り方式＝ビルドシステム別の使い分け（CMake/Ninja はランチャ優先）

| ビルドシステム | 方式 | 根拠 |
|---|---|---|
| **CMake / Ninja**（第一ターゲット） | **コンパイラランチャ** `CMAKE_<LANG>_COMPILER_LAUNCHER` | 最小設定・無侵襲。CMake がコンパイラ argv の先頭にランチャを prepend（`sembazuru clang-cl /c foo.cpp`）。Ninja/Makefiles のみ対応（CMake 公式）。sccache/Reclient と同じ実績パターン。 |
| **MSBuild / Visual Studio** | **`CLToolExe`/`CLToolPath` シム**（第一候補、`Directory.Build.props` ドロップイン）＋ 補完で **プロセス起動横取り `DetourCreateProcessWithDll`** | `CMAKE_<LANG>_COMPILER_LAUNCHER` は VS ジェネレータ非対応（CMake 公式）。ccache の MSBuild 統合が CLToolExe を使用。IDE 内ビルド等の起動経路は Detours 横取りで補完。M6.2。 |
| **Unreal / UBT** | **エグゼキュータ抽象**（`ActionExecutor` 相当、`BuildConfiguration.xml` フラグで選択）への差し込み | UE は EULA。**設計観察のみ・コード非取り込み・クリーンルーム**（非交渉 #3）。本 M6 では繰り延べ。 |

根拠: コンパイラランチャは「無設定性が高く移植容易」、プロセス起動横取りは「ビルドシステム非依存だが
EDR シグナル増大・実装表面大」。CMake/Ninja を先にランチャで通し、ランチャで覆えない MSBuild/VS にのみ
Detours 横取りを足す（出典: CMake docs `<LANG>_COMPILER_LAUNCHER`、sccache/Reclient launcher、
Incredibuild Process Virtualization Flow＝CreateProcess インターセプト）。取り込みは Apache の Reclient・
MIT の BuildXL・sccache の設計のみ。UBA は設計観察。

### 2. ランチャ↔daemon 受付口＝ローカル gRPC の新 `LocalIntake` サービス（M6 当時は loopback）

ランチャは短命（ビルドツールが TU ごとに起動）、daemon は WorkerTable/fileserver/Scheduler を所有する
長寿命プロセス。両者の受付口は **ローカル専用 gRPC サービス `LocalIntake`**（`control.proto`）:

```proto
service LocalIntake {
  rpc SubmitAction(SubmitActionRequest) returns (stream SubmitActionEvent);
}
```

- 既存 tonic/gRPC・proto・ストリーミング資産を流用（名前付きパイプの新規フレーミングや、Execution の
  agent→worker セマンティクスへの転用＝役割混線を避ける）。
- `SubmitActionRequest` は **full `Command`（argv/env/cwd）＋ declared_outputs**。Execution（agent→worker）が
  入力ルートのみ名指すのと異なり、ランチャは argv を既に持つため full command を運ぶ。これが安全なのは
  **本プレーンが loopback 限定**だから（下記 3 のセキュリティ不変条件）。
- `SubmitActionEvent` は `state | exit`。**stdout/stderr ミラーは M6.1 へ繰り延べ**（worker が現状 stdout/stderr
  を捕捉しない。oneof は後方互換で後から追加可。`docs/deferred.md` M6 節）。
- daemon は受けたアクションを `Scheduler::dispatch` に流し、結果（remote / local fallback）を exit にミラー。
  `session_id` は daemon が採番し fileserver セッションに束縛（M6.1 で実供給に結線）。

**M6.0 当時のセキュリティ不変条件:** LocalIntake は提出された任意コマンドを実行し無認証（認証は M7）。
よって daemon は **非ループバックアドレスへの intake bind を起動時に拒否**（`resolve_loopback_intake`）。
ランチャは常に `127.0.0.1` を叩くため loopback 限定は無コスト。Coordination/fileserver は worker 用 LAN 到達が
要るため非ガード（intake のみが「任意コマンド実行」で結果が重い）。出所: security-reviewer(M6.0 MEDIUM)。
現行 Windows production は ADR 0016 の DACL／caller SID／restricted token 境界を使い、TCP は明示した test fixture
だけに残す。

### 3. MSVC ライセンス境界への非依存設計（clang-cl ファーストクラス）

- **clang-cl をバイト一致ゲート（first-class）**、`cl` はローカル並走/ベストエフォート（同一パス rebuild の
  action cache 活用、cross-dir 不一致は既知）。MSVC リモート実行のライセンスグレー（§8）に設計を依存させない。
- ランチャ・Intake・Scheduler はコンパイラ非依存（argv をそのまま運ぶ）。clang-cl/cl のどちらでも同経路で動く。
  バイト一致の合否は clang-cl で CI ゲート、cl はベストエフォート（`docs/deferred.md` 横断節）。

### 4.「最小設定」の定義と無設定ビルドの受け入れ基準

- **最小設定 = (a) ランチャ指定 1 つ**（CMake: `-DCMAKE_CXX_COMPILER_LAUNCHER=<path>\sembazuru.exe`／
  MSBuild: `Directory.Build.props` 1 枚）＋ **(b) 静的 worker リスト env**（worker が `SEMBAZURU_AGENT` で
  daemon に登録）。**プロジェクトファイル本体は無改変。**
- **出力一致:** clang-cl はローカルビルドと **バイト一致**（ゲート）。cl は同一パス rebuild でベストエフォート。
- **フォールバック:** daemon 不在・worker 全死・ネットワーク断のいずれでもビルドが**ローカルで完走**（非交渉 #2）。
- **キャッシュ:** 2 回目ビルドで action cache 命中（コンパイル実行ゼロ、出力バイト一致）。

## 実装状況（2026-06-14、CI green）

- **済（M6.0）:** `LocalIntake` proto、`IntakeService`/`serve_intake`/`submit_to_daemon`、常駐 daemon bin
  （Coordination＋fileserver＋Scheduler＋LocalIntake 統合）、ランチャ bin `sembazuru`（loopback 投入・
  ローカルフォールバック）、非ループバック intake bind 拒否。
- **済（M6.1）:** CMake/Ninja＋clang-cl の e2e 無設定ビルド。worker の VFS 注入実行（launcher＋DLL＋
  per-action パイプ＋agent fileserver 供給）、daemon の action cache resolve/record、predicted_paths
  prefetch、Execute→prefetch 配線、Abort 実 kill（Job Object でツリー kill）。CI（hooks ジョブ）で
  分散ビルド＝ローカル clang-cl バイト一致／ローカルフォールバック完走／2 回目 action cache 命中を実証
  （`m6_worker_vfs_redirect.ps1`／`m6_daemon_compile.ps1 -RequireClangCl`）。単機モデル（書込み非リダイレクト
  ＝出力ローカル、trace_dir 共有 FS）。実 2 台 LAN 測定・2 台 writeback は決定者承認で繰り延べ。
- **済（M6.2）:** MSBuild/VS の CLToolExe ランチャシム。launcher のシムモード（`SEMBAZURU_SHIM_CC` で実
  コンパイラ前置）、`Directory.Build.targets` ドロップイン、`docs/integrations/README.md`。CI（`m6_msbuild.ps1`）で
  MSBuild の CL タスクが daemon 経由（remote）＋ローカルフォールバックを実証。MSVC cl はベストエフォート
  （バイト一致は CMake/Ninja＋clang-cl が担保）。security-reviewer 済（PASS、注入は M3 と同機構・新シグナル無し）。
  Detours プロセス起動横取りは CLToolExe で覆えない経路向けに将来（EDR シグナル増・M7 寄り）。
- **繰り延べ:** M6.3（UBT 設計観察のみ）、stdout/stderr ミラー（M6.1 残）、実 2 台 LAN 測定・writeback。

## 影響

- `docs/DESIGN.md` §7 M6 の横取り口（MSBuild/CMake/Ninja/UBT）を「ランチャ優先・VS は CLToolExe/Detours・
  UBT は設計観察」で具体化。
- `docs/protocol/v0.md` に **第三のプレーン LocalIntake（loopback control）** を追加（Coordination/Execution は
  agent↔worker、LocalIntake は launcher→agent）。§6 versioning に従い新サービスとして非破壊追加。
- M5 繰越（`docs/deferred.md`）の Execute→prefetch 配線・logical↔agent パス整合・Abort 実 kill を M6.1 で結線、
  レイテンシ予算タイマの値は M6.1 の実 LAN 測定で取得（タイマ実装は M7）。
- 新たな M6.0 残リスク（stdout/stderr 未捕捉・full-env 転送・intake admission）は `docs/deferred.md` M6 節へ。
