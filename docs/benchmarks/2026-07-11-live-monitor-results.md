# ライブビルドモニタ検証結果（2026-07-13）

## 結論

**DONE_WITH_CONCERNS（Task 6 Step 1–5の実行結果）**。ローカルのagent/workspace gate、Codex＋Claudeの修正差分review、production corpusによる性能gate、指定viewportでのlive-data visual確認は通過した。未pushの統合diffに対するCIだけは未実行であり、PASSとは記録しない。

- workspace clippyは初回に`crates/gui/src/app/monitor.rs:96`の`collapsible_if` 1件で失敗したが、条件式だけを結合する最小修正後の再実行で通過した。
- broken-stderr testのflakyは、guardian完了直後にpeer process signalを即時観測するテスト側raceと切り分けた。fixed sleepではなく最大2秒のcondition waitへ修正後、forced fixture 64/64、外側test 32/32、agent all-targets 3/3、workspace 2/2が通過した。
- fresh-built production daemon／launcherへ100 concurrent local-fallback actionを流すcorpusを構成し、GUI未起動とMonitor表示中を各5回測定した。Monitor表示中のmedianはGUI未起動より3.867526%短く、2% regression gateを通過した。
- 902×632とWin32 outer 1440×1024（capture client 1426×1017）でlive activityを確認した。途中でroot背景のcontrast defectを発見したが、explicit dark theme＋root panel fillをTDD修正し、再確認した。

この記録は`a5d2e27c509d151e11e6e25d14c43d833a30ee22`上の未commit統合diffを対象とする。branchは`codex/speed-monitor`である。

## Rust workspace gate

### format

Command:

```powershell
cargo fmt --all -- --check
```

Result: **PASS**（exit 0、出力なし）。

### diff / temporary diagnostic sweep

```powershell
git diff --check
```

Result: **PASS**（exit 0）。`crates/`を対象に、一時診断hook名、診断artifact語彙、切り分け用固有`process::exit` codeを検索し、source内の残存は**0件**だった。

### clippy

Command:

```powershell
cargo clippy --workspace --all-targets -- -D warnings
```

初回Result: **FAIL**（exit 1）。`crates/gui/src/app/monitor.rs:96`のnested `if`に対して`clippy::collapsible-if`が報告された。Task 6は実装verify-onlyのため、この段階では実装ファイルを編集していない。

その後、Task 5の最小fixとしてnested `if`を同じ条件の単一`if`へ畳み、挙動／layoutを変えずに次の同一workspace gateを再実行した。

```powershell
cargo clippy --locked --workspace --all-targets -- -D warnings
```

再実行Result: **PASS**（exit 0、warning 0）。agent、worker、GUIを含むworkspace all-targetsが通過した。

### test

最終Command:

```powershell
cargo test --locked -p sembazuru-agent --all-targets
cargo test --locked --workspace
```

最終Result:

- agent all-targets（標準parallel）: **PASS 3/3**。
- workspace（標準parallel）: **PASS 2/2**。

初回workspaceではagent 228 tests中225 PASS、1 FAIL、2 ignoredだった。失敗は`tests::local_job_broken_stderr_cannot_interrupt_quarantine`で、子fixtureがexit 101となった。focused実行では再現しなかったが、32並列のstage-exit診断で、result、phase、quarantine、Job owner、kill flagの全semantic check通過後にpeer signalの即時snapshotだけが失敗することを特定した。

即時falseの場合だけ最大2秒condition poll/yieldする一時診断を64並列で実行した結果は、即時成功60件、100ms未満でall signaledへ収束4件、100ms以上0件、2秒未収束0件だった。したがってproduction guardianの未収束ではなく、テストのimmediate signal observation raceがroot causeである。

既存の即時assertionをfixed sleepではない最大2秒のcondition waitへ置換した後、次を確認した。

```powershell
# forced inner fixture: 64 parallel processes
# outer broken-stderr test: 32 parallel processes
cargo test --locked -p sembazuru-agent --all-targets  # 3 runs
cargo test --locked --workspace                       # 2 runs
```

Result: forced fixture **64/64 PASS**、外側test **32/32 PASS**、agent all-targets **3/3 PASS**、workspace **2/2 PASS**。

## Codex＋Claude review gate

最終reviewでCodexはlane historyにP1を報告し、修正した。Claudeは同じM1に加えてM2/M3を報告し、いずれも修正した。修正差分を両者へ再提示した結果は次のとおりである。

| Reviewer | 初回指摘 | 修正差分review |
|---|---|---|
| Codex | lane history P1 | **CLEAN** |
| Claude | M1（Codex P1と同一）、M2、M3 | **CLEAN** |

## Build throughput比較

Result: **PASS**。

fresh buildしたproduction daemon／launcher／GUIを使用した。各runで`cmd.exe /d /c exit 0`を100 concurrent actionとしてlauncherからproduction daemonへ投入し、`SEMBAZURU_NONDETERMINISTIC=1`で実行した。workerなしのため全actionはlocal fallbackとなり、production StatusをMonitorがpollできる。GUI未起動とMonitor表示中を各5回、合計1000 action実行し、**1000/1000がexit 0**だった。

最初に実行したstale binaryによる測定はcurrent統合diffを反映していないため無効と判定し、結果から完全に破棄した。次表はfresh-built binaryだけの有効測定である。Monitor表示時のWin32 outer windowは1440×1024、capture clientは1426×1017だった。

| 条件 | raw 1 (ms) | raw 2 (ms) | raw 3 (ms) | raw 4 (ms) | raw 5 (ms) | median (ms) | GUI未起動比 |
|---|---:|---:|---:|---:|---:|---:|---:|
| GUI未起動 | 20933.491 | 20988.637 | 21229.417 | 21174.613 | 20906.942 | 20988.637 | baseline |
| Monitor表示中（1426×1017 client） | 19884.075 | 20024.068 | 20398.557 | 20281.759 | 20176.896 | 20176.896 | -811.741 ms / -3.867526% |

Monitor表示中のmedianはGUI未起動より811.741 ms短かった。回帰ではなく-3.867526%の差であり、「2%未満」のregression gateは**PASS**である。この結果は速度向上の因果を主張するものではなく、Monitor表示による2%以上の回帰が今回の5×2測定で観測されなかったことを示す。

## Privacy sweep

Search command:

```powershell
rg -n "argv|env|cwd|response|token|full.path" crates/proto/proto/sembazuru/v0/control.proto crates/agent/src/action_tracker.rs crates/agent/src/status.rs crates/gui/src
```

分類結果:

- `ActionActivity`（`control.proto:490-500`）には禁止fieldがなく、`activity_id`、attempt、worker、execution kind、basename表示、state、lane、age、durationだけである。
- `action_tracker.rs`の`argv/env/cwd` hitは入力commandからbasenameを導出する処理と、そのredaction test fixtureである。tracker snapshotへfull path、argv、env、tokenは保持しない。
- `status.rs`とGUIのtoken hitは既存のconfig管理／presence-only表示であり、Monitor activity projectionではない。
- GUI Monitorは`ActivityRow.display_name`、worker、lane、state、durationだけを描画する。

plan記載commandはtest名が現状と一致せず、0 testsだったためPASS根拠にはしていない。

```powershell
cargo test -p sembazuru-agent --test status_activity activity_projection_contains_no_path_argv_or_env -- --nocapture
# 0 passed; 2 filtered out
```

実在するredaction integration testを実行した。

```powershell
cargo test -p sembazuru-agent --test status_activity status_exposes_active_then_recent_activity_without_command_material -- --nocapture
```

Result: **PASS**（1 passed、0 failed）。

## Visual smoke

current workspaceのdaemon／launcher／GUIをfresh buildして可視確認した。

```powershell
cargo build --locked -p sembazuru-agent -p sembazuru-gui
```

fresh-built daemonとGUIを起動し、上記100-action corpusのlocal fallback activityをMonitorへ表示して確認した。

確認結果:

| 項目 | 結果 |
|---|---|
| 902×632（default 900×600相当） | dark theme、Dashboard → Monitor → Services → Join → Settingsのnavigation順、ruler／Now、縦方向scrollを確認 |
| Win32 outer 1440×1024 | capture clientは1426×1017。dark theme、ruler／Now、Local/Fallbackのgreen bar、`Completed`状態文字、Recent history、scrollを確認 |
| overflow / clipping | 902×632と1426×1017 clientの両方でnavigation、timeline、historyを確認し、操作を妨げるoverflow／clippingなし |
| activity bar＋history | 実100-action local fallback corpusによりgreen bar、状態文字、historyの実データ行を確認 |

選択target `docs/superpowers/specs/assets/2026-07-11-build-monitor-timeline-target.png`と目視比較し、worker/lane、ruler／Now、activity bar、state text、historyという情報階層をlive data込みで確認した。

最初のvisual確認でtop navigation以外のroot本文がunpainted blackとなり、light-themeのdark textが読めないcontrast defectを発見した。`crates/gui/src/app/mod.rs`でCreationContextのexplicit dark visualsに加え、実root `Ui`へdark styleを設定してcurrent `panel_fill`でroot全面をpaintする最小修正をTDDで行った。headless RED→GREEN、GUI test／check／clippy／fmt／diff check通過後、fresh GUIでdark themeと本文の可読性を再確認した。

永続screenshot:

- [902×632](assets/2026-07-13-live-monitor-902x632.jpg)
- [1426×1017 client（Win32 outer 1440×1024）](assets/2026-07-13-live-monitor-1426x1017.jpg)

## CI状態

この未commit統合diffは未pushのためCIは未実行／未確認であり、PASSとは記録しない。ローカルではagent all-targets 3/3、workspace 2/2、workspace clippy、fmt、diff check、Codex＋Claudeの修正差分review、performance 5×2、live-data visual smokeが通過した。
