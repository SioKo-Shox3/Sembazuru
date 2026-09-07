
## 反復 2 — T-001 の独立評価が workspace test の再現性で NEEDS_WORK

独立評価の保存結果: `.harness/runs/20260908-082159/evaluation-T-001-1.txt`

Cargo.lock の依存差分は h2 0.4.14 -> 0.4.16、webbrowser 1.2.1 -> 1.2.2 のみで、
`core-foundation 0.10.1` の消滅と参照名の整理は webbrowser 1.2.2 の依存グラフ変更に伴うものと確認された。
`verify-T-001-5.txt` から `verify-T-001-8.txt` の4ゲートはすべて exit_code=0 だった。

ただし、同じ作業ツリーの過去の `recheck-T-001-1-4.txt` では、
`rustup run 1.97.0 cargo test --workspace --locked` が exit 101 で終了していた。
失敗は依存更新とは無関係な `sandbox::tests::sandbox_probe_record_round_trip_uses_file_not_stdout`
の `crates/worker/src/sandbox.rs:5061:67` における `Err("environment text")` であり、
今回の `verify-T-001-8.txt` は同じテストを exit 0 で通過している。
追加で同じコマンドを実行した `verify-T-001-9.txt` も exit 0 で通過した。
ログ内の `sandbox_probe_record_child` の FAILED は親が起動した診断用子プロセスの期待された失敗表示であり、
親の cargo test 終了コードとは区別する。

この反復の許可パスには `sandbox.rs` が含まれないため、テストの環境依存性は修正せず、
過去の失敗と今回の2回の成功を証拠として残す。T-001 の status は評価完了まで `doing` のままにする。

### 対応結果

2周目の独立評価 `.harness/runs/20260908-082159/evaluation-T-001-2.txt` は `PASS`。
過去の失敗箇所と今回の成功ログを確認し、T-001 の完了条件を満たしたため status を `done` に更新した。
`sandbox_probe_record_round_trip_uses_file_not_stdout` の環境依存性は原因未特定の別課題として残し、
このタスクの許可パス外なので変更しない。

## 反復 1 — T-001 の verify が再実行で落ちた

コマンド: `rustup run 1.97.0 cargo test --workspace --locked`(cwd: リポジトリ直下)
終了コード: 101

出力(末尾):

```
…(先頭を省略)
 Running unittests src\lib.rs (target\debug\deps\sembazuru_cas-4be0ac3d5579f04f.exe)
     Running unittests src\lib.rs (target\debug\deps\sembazuru_config_store-8835cc527183e652.exe)
     Running unittests src\bin\sembazuru_storectl.rs (target\debug\deps\sembazuru_storectl-53108e1d8aac9df5.exe)
     Running unittests src\lib.rs (target\debug\deps\sembazuru_dataplane-e2da9b1b441d96b8.exe)
     Running unittests src\lib.rs (target\debug\deps\sembazuru_gui-d4f214f18a5fec06.exe)
     Running unittests src\main.rs (target\debug\deps\sembazuru_gui-f8263ae67c0076b0.exe)
     Running tests\cache_unit.rs (target\debug\deps\cache_unit-b69f42127485380b.exe)
     Running tests\dashboard_badge.rs (target\debug\deps\dashboard_badge-fabfb398e66df412.exe)
     Running tests\join_panel.rs (target\debug\deps\join_panel-55acbb32750c8210.exe)
     Running tests\monitor.rs (target\debug\deps\monitor-b5accc7beb9f528e.exe)
     Running tests\net.rs (target\debug\deps\net-31807b6486594b76.exe)
     Running tests\status_client.rs (target\debug\deps\status_client-5adba320a12f79e4.exe)
     Running tests\worker_toml.rs (target\debug\deps\worker_toml-76397d9ec5960f11.exe)
     Running tests\writer_stub.rs (target\debug\deps\writer_stub-542f663116ae05d4.exe)
     Running unittests src\lib.rs (target\debug\deps\sembazuru_proto-33b9b9685bd61793.exe)
     Running unittests src\lib.rs (target\debug\deps\sembazuru_tracer-12c869b9def3e2f6.exe)
     Running unittests src\bin\sembazuru_trace.rs (target\debug\deps\sembazuru_trace-d2c28d2bf57fbb85.exe)
     Running tests\verify_determinism.rs (target\debug\deps\verify_determinism-060819f3d32bb656.exe)
     Running unittests src\lib.rs (target\debug\deps\sembazuru_worker-7a1b0f2c6319767a.exe)

thread 'sandbox::tests::sandbox_probe_record_child' (51736) panicked at crates\worker\src\sandbox.rs:4978:9:
stale destination
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
error: test failed, to rerun pass `-p sembazuru-worker --lib`
```

status を `done` から `doing` に戻した。次の反復はまずこれを直す。
