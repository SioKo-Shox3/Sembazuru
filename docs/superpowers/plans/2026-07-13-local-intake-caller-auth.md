# LocalIntake 呼出元認証 実装計画

> **実装担当エージェント向け:** `superpowers:test-driven-development` を使い、各節で RED を実測してから production code を書くこと。実装コードは implementer のみが編集し、main は判断・統合・レビュー・コミットを担当する。

**目標:** LocalSystem の `sembazuru-daemon` が受理する LocalIntake を OS caller identity に結び付け、daemon-side local fallback を caller の制限付き primary token でのみ起動する。標準ユーザーから SYSTEM または別ユーザーとして任意コマンドを実行できず、正規 launcher の daemon 経由・daemon-down の両 fallback を維持する。

**構成:** Windows production LocalIntake を loopback TCP から machine-wide named pipe brokerへ置換する。pipe は protected DACL、remote拒否、first-instance、client側server token検証を持つ。serverは最初のsuccessful read直後にcallerをimpersonateしてSIDとprimary tokenを取得し、tonic request extensionから全daemon-side fallbackへ明示伝播する。processはcaller tokenを `CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` で制限し、`CreateProcessAsUserW(CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT)` で生成して既存Jobへ割り当ててからresumeする。認証またはtoken処理の失敗時にdaemon tokenで再試行しない。

**技術:** Rust、Tokio Windows named pipe、tonic custom incoming/connector、`windows-sys 0.59`、Win32 Security/Pipes/Threading/UserProfile API、PowerShell elevated security gate。

## 共通制約

- 作業場所は既存の `C:\Users\<user>\Documents\Sembazuru`、ブランチはローカル `main`。新しいbranch/worktreeを作らない。
- Criticalだけをscopeとし、ProgramData設定、worker isolation、P0/P1/Performance、解決済み3件は変更しない。
- Windows production daemonはLocalIntake TCP listenerを作らない。TCP helperは非Windowsまたは既存テストfixtureに限定する。
- pipe名は `\\.\pipe\Sembazuru.LocalIntake.v1`、launcher endpoint表現は `npipe://Sembazuru.LocalIntake.v1` とする。
- protected DACLのSDDLは `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00120003;;;AU)` とする。AU ACEは `FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | SYNCHRONIZE` だけで、bit `0x00000004` (`FILE_CREATE_PIPE_INSTANCE`) を含めない。
- server pipeは `PIPE_REJECT_REMOTE_CLIENTS` と最初のinstanceに `FILE_FLAG_FIRST_PIPE_INSTANCE` を指定する。clientはgeneric writeではなく上記specific access maskでopenし、`SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION` を明示する。
- launcherはcommand bytesを送る前に `GetNamedPipeServerProcessId` → server process token SIDを検証する。許可SIDは `S-1-5-18`（LocalSystem service）またはlauncher自身のSID（同一ユーザーのforeground daemon）だけとする。これはlauncherが偽serverへcommandを漏らさないためのserver認証であり、caller authorizationの権威には使わない。
- `ImpersonateNamedPipeClient` はfirst successful read後、接続ごとの短命な専用OS threadで実行する。HTTP/2 bytesをtonicへ渡す前にそのthread上で `TokenImpersonationLevel >= SecurityImpersonation`、`TokenUser`、`DuplicateTokenEx(TokenPrimary)`、`CreateRestrictedToken(DISABLE_MAX_PRIVILEGE)` を完了し、全経路で `RevertToSelf` を試みてthreadを終了する。いずれかが失敗したら接続を閉じ、caller identityを発行しない。caller authorizationの唯一の権威はこのtokenとする。
- caller tokenがないWindows production requestは `UNAUTHENTICATED`。process/scratch/Jobの副作用を起こさない。
- caller-token spawn失敗後にambient daemon tokenで再試行しない。
- `CREATE_SUSPENDED` → `AssignProcessToJobObject` → guardian seed → initial thread resume の順序とdeadline/kill-on-drop/drain semanticsを維持する。
- callerのenvironment blockを基礎に、提出済み `Command.env` をcase-insensitive keyで上書きする。SYSTEM環境を継承しない。
- `argv[0]`のbare executable、spaceを含むpath、`.cmd`/`.bat`、空引数、backslash+quoteをテストし、既存のarbitrary Windows process契約を維持する。
- Status/Adminは既存の別endpointのまま。LocalIntake pipeには `LocalIntakeServer` だけを登録する。
- 同一手法が2回失敗したら停止し、証拠をmainへ返す。

---

### Task 1: 認証付きnamed-pipe transportをRED→GREENで追加する

**Files:**

- Create: `crates/agent/src/intake_pipe.rs`
- Modify: `crates/agent/src/lib.rs`（module exportだけ。process変更はTask 3）
- Modify: `crates/agent/src/intake.rs`
- Modify: `crates/agent/Cargo.toml`
- Test: `crates/agent/src/intake_pipe.rs`
- Test: `crates/agent/tests/local_intake_security.rs`

**Interfaces:**

- `CallerIdentity { sid: String, primary_token: Arc<OwnedHandle> }` を生成する。
- `AuthenticatedPipe` はTokio `AsyncRead + AsyncWrite` とtonic `Connected`を実装し、`Arc<OnceLock<Result<CallerIdentity, AuthError>>>` をrequest extensionへ渡す。
- `LocalIntakeTransport` にWindows `NamedPipe` を加え、production defaultは `npipe://Sembazuru.LocalIntake.v1` とする。loopback TCP server helperはproduction daemonから参照しない。

- [ ] **Step 1: DACLとpipe optionの失敗テストを書く**

  作成したpipeのsecurity descriptorを `GetSecurityInfo` で読み、DACL protected、SY/BA full、AU maskが正確に `0x00120083`、AU maskに `0x4`なしをassertする。実server process SIDだけに、`PIPE_ACCESS_DUPLEX`で次instanceを作るためのconcrete rights `0x0012019f`を与える。second first-instance作成、`\\localhost\pipe\Sembazuru.LocalIntake.v1`、identification-level clientが拒否されるテストも先に書く。

  実装時のWindows実測で、SQOS付きclient openにはAU側の`FILE_READ_ATTRIBUTES (0x80)`が必要と判明した。また、追加server instanceは`FILE_CREATE_PIPE_INSTANCE (0x4)`だけでなく`FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE`を要求する。AUへ0x4を与えず、具体的server SIDのACEだけを`0x0012019f`とする境界へ補正した。

- [ ] **Step 2: REDを実測する**

  Run:

  ```powershell
  cargo test -p sembazuru-agent --lib intake_pipe::tests -- --nocapture
  cargo test -p sembazuru-agent --test local_intake_security identification_level_client_cannot_submit -- --exact --nocapture
  ```

  Expected: module/variant未実装、または現loopback TCPがcaller identityなしで受理するためFAIL。

- [ ] **Step 3: 最小transportを実装する**

  `ConvertStringSecurityDescriptorToSecurityDescriptorW`で上記SDDLを作り、`ServerOptions::create_with_security_attributes_raw`へ渡す。acceptされたpipeのfirst read完了後、HTTP/2 bytesを上位へ返す前に専用OS threadを起動し、そのthread内だけでimpersonate/token capture/revertを完了してthreadをjoinする。clientはraw `CreateFileW`のspecific maskとimpersonation SQOSで開き、Tokio named-pipe clientへ所有権を移す。server SID検証完了前はHTTP/2 prefaceを送らない。

- [ ] **Step 4: GREENと回帰を実測する**

  Run:

  ```powershell
  cargo test -p sembazuru-agent --lib intake_pipe::tests -- --nocapture
  cargo test -p sembazuru-agent --test local_intake_security -- --nocapture
  cargo test -p sembazuru-agent --test intake -- --nocapture
  ```

  Expected: DACL/SQOS/server SID/first-read testsがPASSし、既存intake fixtureもPASS。

---

### Task 2: caller identity欠落をfail closedにし、全fallbackへ明示伝播する

**Files:**

- Modify: `crates/agent/src/intake.rs`
- Modify: `crates/agent/src/scheduler.rs`
- Modify: `crates/agent/src/run.rs`
- Test: `crates/agent/src/intake.rs`
- Test: `crates/agent/tests/local_intake_security.rs`

**Interfaces:**

- `LocalExecutionContext::CurrentProcess` はlauncher-side fallbackと非Windows/test fixture専用。
- `LocalExecutionContext::AuthenticatedCaller(CallerIdentity)` はWindows production daemon専用。
- `IntakeService` production constructorはtransport extensionからcaller identityを要求し、`run_submission`、plain dispatch、route-away、no-worker/remote-exhausted、publish-failureへ同じcontextを渡す。
- `Scheduler::dispatch_observed_with_context(...)` をintake専用入口とし、既存callerなし入口はproduction daemonから呼ばない。

- [ ] **Step 1: identity欠落とfallback分岐の失敗テストを書く**

  plain tonic requestにextensionがない場合、command/scratch/Job前に `Unauthenticated`。route-away、no-worker/remote-exhausted、publish-failureの各test executorが同じcaller SID/token idを受けることをassertする。

- [ ] **Step 2: REDを実測する**

  Run:

  ```powershell
  cargo test -p sembazuru-agent --lib intake::tests::missing_caller_identity_rejects_before_side_effects -- --exact --nocapture
  cargo test -p sembazuru-agent --test local_intake_security every_daemon_fallback_reason_preserves_caller_token -- --exact --nocapture
  ```

  Expected: 現実装はrequest extensionを読まず、fallbackがambient `run_local`を呼ぶためFAIL。

- [ ] **Step 3: context伝播とfail-closedを実装する**

  requestを`into_inner`する前にpolicyとextensionを検査する。fallback helperの引数にcontextを明示し、caller context欠落時のWindows production pathはerror eventで終了する。便宜的なglobal/task-local caller tokenやambient fallbackは追加しない。

- [ ] **Step 4: GREENを実測する**

  Run:

  ```powershell
  cargo test -p sembazuru-agent --lib intake::tests -- --nocapture
  cargo test -p sembazuru-agent --test local_intake_security -- --nocapture
  cargo test -p sembazuru-agent --test status -- --nocapture
  cargo test -p sembazuru-agent --test prefetch_scope -- --nocapture
  ```

  Expected: identity/fallback testsがPASSし、Status/Prefetch fixtureに退行なし。

---

### Task 3: callerの制限付きtokenでsuspended childを起動し、既存Jobへ割り当てる

**Files:**

- Modify: `crates/agent/src/lib.rs`
- Modify: `crates/agent/Cargo.toml`
- Test: `crates/agent/src/lib.rs`
- Test: `crates/agent/tests/local_intake_security.rs`

**Interfaces:**

- `run_local_with_context(command: &Command, context: &LocalExecutionContext)` を追加し、既存 `run_local` は `CurrentProcess` wrapperとして残す。
- Windows `local_job::run` はcontextを受け、authenticated callerでは `CreateProcessAsUserW`を使う。
- token child wrapperは `id`、process handle、kill、async wait、Drop時reapを提供し、既存guardianのJob/IOCP accountingへ同じprocessを渡す。

- [ ] **Step 1: process token・Job順序・quotingの失敗テストを書く**

  caller-token child自身が `TokenUser` をfileへ書き、SID一致をassertする。token spawn failpointでambient retry回数0、initial user code実行時に `IsProcessInJob=true`、bare exe/path with spaces/`.cmd`/空引数/backslash+quoteのargv round-tripをassertする。

- [ ] **Step 2: REDを実測する**

  Run:

  ```powershell
  cargo test -p sembazuru-agent --lib tests::local_job_as_caller_is_assigned_before_resume -- --exact --nocapture
  cargo test -p sembazuru-agent --test local_intake_security caller_token_spawn_failure_never_retries_with_daemon_token -- --exact --nocapture
  ```

  Expected: caller-token API未実装、またはchild SIDがdaemon/current process SIDとなりFAIL。

- [ ] **Step 3: caller-token spawnを実装する**

  caller environmentを `CreateEnvironmentBlock` から取得し、`Command.env`をcase-insensitive mergeしてdouble-NUL UTF-16 blockにする。Windows quotingは独立pure helperでテストする。`.cmd`/`.bat`だけcaller環境の`ComSpec /d /s /c`へ明示wrapする。`CreateProcessAsUserW`は `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT`、caller cwd、restricted primary tokenを使う。spawn、environment、Job割当て、resumeの失敗はguardianでreapし、ambient token再試行を行わない。

- [ ] **Step 4: GREENとguardian回帰を実測する**

  Run:

  ```powershell
  cargo test -p sembazuru-agent --lib tests::local_job -- --nocapture
  cargo test -p sembazuru-agent --test local_intake_security -- --nocapture
  ```

  Expected: caller SID/Job/argv/fail-closedがPASSし、既存guardian testsもPASS。

---

### Task 4: Windows production daemon/launcherをpipeへ結線する

**Files:**

- Modify: `crates/agent/src/config.rs`
- Modify: `crates/agent/src/run.rs`
- Modify: `crates/agent/src/bin/sembazuru_launcher.rs`
- Modify: `crates/agent/src/service.rs`
- Modify: `crates/agent/tests/config_rpc.rs`
- Modify: `crates/agent/tests/intake.rs`
- Modify: `hooks/test/m6_daemon_compile.ps1`
- Create: `hooks/test/m6_local_intake_security.ps1`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**

- Windows `DEFAULT_INTAKE`/launcher defaultは `npipe://Sembazuru.LocalIntake.v1`。
- non-Windows defaultとexplicit test fixtureはloopback TCPを維持する。
- Windows `run_daemon`はnamed pipe incomingだけをsuperviseし、Status TCPは従来どおり別listener。

- [ ] **Step 1: production wiringの失敗テストを書く**

  Windows daemon起動後にTCP `127.0.0.1:50071`がlistenしていないこと、LocalIntake pipeにStatus/Admin RPCがないこと、正規launcherがdaemon経由でcaller SID childを実行すること、daemon停止時にlauncher自身が同じcommandを完遂することを先に追加する。

- [ ] **Step 2: REDを実測する**

  Run:

  ```powershell
  cargo test -p sembazuru-agent --test config_rpc -- --nocapture
  cargo test -p sembazuru-agent --test intake -- --nocapture
  pwsh -NoProfile -File hooks/test/m6_daemon_compile.ps1 -RequireClangCl
  ```

  Expected: defaultがTCP、production daemonがTCP bindするため新しいsecurity assertionsがFAIL。

- [ ] **Step 3: production wiringを実装する**

  Windows daemon ready signal/test fixtureをpipe endpointへ対応させる。production daemonにTCPへのfallback optionを残さない。launcherのpipe transport errorだけが既存launcher-side `run_local`へ落ちる。serviceの旧EoP警告は「authenticated caller tokenで実行、認証失敗は拒否」へ更新する。

- [ ] **Step 4: 通常権限GREENを実測する**

  Run:

  ```powershell
  cargo fmt --all -- --check
  cargo clippy --all-targets -- -D warnings
  cargo test --workspace
  pwsh -NoProfile -File hooks/test/m6_daemon_compile.ps1 -RequireClangCl
  ```

  Expected: 全コマンドexit 0。daemon経由とdaemon-down fallbackの両ケースが完遂。

- [ ] **Step 5: LocalSystem＋標準ユーザーA/Bのelevated gateを実測する**

  Run（管理者PowerShell）:

  ```powershell
  pwsh -NoProfile -File hooks/test/m6_local_intake_security.ps1 -Configuration Release
  ```

  Expected: service token `S-1-5-18`、A child=A SID、B child=B SID、A/BともSYSTEMまたは相手SIDではない。low-SQOS/direct requestはdispatch前拒否。daemon停止後の正規launcherはcaller SIDで完遂。作成したservice/user/temp dirは `finally` で削除。

  ローカル権限不足で実行不能な場合は完了と断言せず、CI/elevated gate未確認として報告する。

---

### Task 5: ADRとbacklogへ対応コミット・検証証拠を記録する

**Files:**

- Modify: `docs/decisions/0016-local-privilege-separation.md`
- Modify: `docs/security/2026-07-13-original-review-open-findings.md`

- [ ] **Step 1: 実装・検証済み事実だけをADRへ反映する**

  per-user pipe案をmachine-wide authenticated brokerへ更新し、DACL mask、server SID検証、first-read impersonation、restricted caller token、admin endpoint分離、未実施のremote two-host/elevated CI状況を明記する。未検証事項を完了扱いしない。

- [ ] **Step 2: Criticalを削除せず `RESOLVED` へ更新する**

  対応実装コミットhash、日本語の根拠、実行コマンドと実出力要約を添える。他10 OPENと解決済み3件の本文・状態は変更しない。

- [ ] **Step 3: scopeと文書差分を検証する**

  Run:

  ```powershell
  git diff --stat 93efaa2..HEAD
  git diff --check 93efaa2..HEAD
  rg -n "LocalSystem LocalIntake|RESOLVED|S-1-5-18|m6_local_intake_security" docs/decisions/0016-local-privilege-separation.md docs/security/2026-07-13-original-review-open-findings.md
  ```

- [ ] **Step 4: mainが日本語コミットを作成する**

  実装・テスト・ADR・Critical backlog更新を1つのatomic security commitにまとめる。候補:

  ```text
  M7: LocalIntakeを呼出元tokenへ拘束しSYSTEM昇格を遮断する
  ```

  コミット直前にmainがfreshなfmt/clippy/workspace test、通常M6 gate、可能ならelevated gate、Codex security review、Claude second reviewを確認する。

## Round 2残課題

- `resolve_caller_program` は `argv[0]` が `a\..` のように最終ファイル名を持たない明示pathの場合、`file_name().unwrap()`でrequest taskをpanicさせ得る。権限昇格・caller取り違え・pipe乗っ取り・データ損失には該当しないためCriticalのblockingではない。レビュー収束規則に従いRound 3は行わず、次のcode-gardening品質返済へ回す。

## 完了判定

以下をすべて満たすまでCriticalを完了としない。

1. production daemonのLocalIntake TCP listenerがない。
2. DACL/SQOS/server SID/first-read caller captureがfail closedである。
3. 全daemon-side fallbackが同じrestricted caller tokenを使い、ambient daemon token retryがない。
4. child SIDがcaller SIDと一致し、suspended→Job→resume順序が維持される。
5. 正規launcherのdaemon経由fallbackとdaemon-down launcher-side fallbackが完遂する。
6. Status/AdminがLocalIntake pipeから到達できない。
7. fresh verification、security-minded review、統合diffのCodex＋Claude二重レビュー、scope照合が完了する。
8. backlog項目が削除されず、対応commitと検証証拠付きで `RESOLVED` になる。
