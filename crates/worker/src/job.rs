//! アクションのプロセスツリーを制限し、終了要求と終了確認を管理する Windows Job。
//!
//! launcher の子であるコンパイラも同じ Job に属し、最終ハンドルの close または
//! 明示の abort でツリー全体に終了を要求する。隔離資源の所有者は終了要求だけでは
//! 解放せず、作成通知の総数照合と各プロセスハンドルの終了確認が完了するまで保持する。

#![cfg(windows)]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
#[cfg(test)]
use windows_sys::Win32::System::JobObjects::JOB_OBJECT_UILIMIT_HANDLES;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectAssociateCompletionPortInformation, JobObjectBasicAccountingInformation,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, QueryInformationJobObject,
    SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_MSG_NEW_PROCESS;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
};

/// 最終ハンドルの close または terminate でツリーへ終了を要求する Job。
/// 作成通知を総プロセス数と照合し、各プロセスの終了まで確認する。
pub struct JobObject(isize, Arc<Mutex<JobCompletion>>);

struct JobCompletion {
    port: OwnedHandle,
    seen: u32,
    pending: Vec<(u32, Option<OwnedHandle>)>,
}

impl JobObject {
    /// Creates a job whose processes are all killed when the last handle closes,
    /// AND that sandboxes the (untrusted, remotely-supplied) compiler tree it
    /// holds (M7.4):
    ///
    /// * `KILL_ON_JOB_CLOSE` — the orphan-prevention guarantee (M6.1e).
    /// * `DIE_ON_UNHANDLED_EXCEPTION` — a crashing child dies instead of popping a
    ///   Windows Error Reporting dialog that would hang a headless worker.
    /// * UI restrictions — the action is a console compiler that needs no UI, so
    ///   deny it the desktop, clipboard, global atoms, ExitWindows, and
    ///   display/system-parameter changes. This stops untrusted code from
    ///   reaching into the worker operator's session. (`docs/deferred.md` M7
    ///   sandbox; security M5.2/M5.5 flagged Job Object hardening.)
    ///
    /// Process breakaway is deliberately NOT enabled (neither `BREAKAWAY_OK` nor
    /// `SILENT_BREAKAWAY_OK`), so a child cannot escape the job — that is what
    /// makes the tree-kill and these limits inescapable.
    pub fn new_kill_on_close() -> io::Result<JobObject> {
        Self::new_kill_on_close_with_ui_restrictions(Self::STANDARD_UI_RESTRICTIONS)
    }

    const STANDARD_UI_RESTRICTIONS: u32 = JOB_OBJECT_UILIMIT_DESKTOP
        | JOB_OBJECT_UILIMIT_EXITWINDOWS
        | JOB_OBJECT_UILIMIT_READCLIPBOARD
        | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
        | JOB_OBJECT_UILIMIT_GLOBALATOMS
        | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
        | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS;

    fn new_kill_on_close_with_ui_restrictions(ui_restrictions: u32) -> io::Result<JobObject> {
        // SAFETY: 出力構造体をゼロ初期化し、使用前に書き込む。返されたハンドルは
        // null を検査し、失敗経路で閉じる。記述子と関連付け情報は呼出中に有効である。
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let set = |class, ptr: *const core::ffi::c_void, len| -> io::Result<()> {
                if SetInformationJobObject(handle, class, ptr, len) == 0 {
                    let e = io::Error::last_os_error();
                    CloseHandle(handle);
                    return Err(e);
                }
                Ok(())
            };

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            set(
                JobObjectExtendedLimitInformation,
                (&info as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )?;

            let mut ui: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
            ui.UIRestrictionsClass = ui_restrictions;
            set(
                JobObjectBasicUIRestrictions,
                (&ui as *const JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
            )?;

            // 読取りは Mutex で直列化する。以前の呼出スレッドの生存が通知取得を妨げないよう、
            // completion port 自体の同時実行数では待機させない。
            let port =
                CreateIoCompletionPort(INVALID_HANDLE_VALUE, std::ptr::null_mut(), 0, u32::MAX);
            if port.is_null() {
                let error = io::Error::last_os_error();
                CloseHandle(handle);
                return Err(error);
            }
            let port = OwnedHandle::from_raw_handle(port as RawHandle);
            // 最初の割当てより前に関連付け、終了の速い子も通知の対象にする。
            let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
                CompletionKey: 1usize as _,
                CompletionPort: port.as_raw_handle() as _,
            };
            set(
                JobObjectAssociateCompletionPortInformation,
                (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
                std::mem::size_of_val(&association) as u32,
            )?;
            Ok(JobObject(
                handle as isize,
                Arc::new(Mutex::new(JobCompletion {
                    port,
                    seen: 0,
                    pending: Vec::new(),
                })),
            ))
        }
    }

    #[cfg(test)]
    pub(crate) fn new_kill_on_close_with_ui_handle_limit_for_test() -> io::Result<JobObject> {
        Self::new_kill_on_close_with_ui_restrictions(
            Self::STANDARD_UI_RESTRICTIONS | JOB_OBJECT_UILIMIT_HANDLES,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_kill_on_close_without_desktop_limit_for_test() -> io::Result<JobObject> {
        Self::new_kill_on_close_with_ui_restrictions(
            Self::STANDARD_UI_RESTRICTIONS & !JOB_OBJECT_UILIMIT_DESKTOP,
        )
    }

    #[cfg(test)]
    pub(crate) fn ui_restrictions_for_test(&self) -> io::Result<u32> {
        let mut ui: JOBOBJECT_BASIC_UI_RESTRICTIONS = unsafe { std::mem::zeroed() };
        // SAFETY: this owned job handle is live and `ui` is a correctly-sized writable buffer.
        if unsafe {
            QueryInformationJobObject(
                self.0 as _,
                JobObjectBasicUIRestrictions,
                (&mut ui as *mut JOBOBJECT_BASIC_UI_RESTRICTIONS).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(ui.UIRestrictionsClass)
    }

    /// Assigns `process` (a child's raw handle) to this job. The process's own
    /// children join the job automatically, so the whole tree dies together.
    pub fn assign(&self, process: RawHandle) -> io::Result<()> {
        // SAFETY: `process` is a live child handle owned by the caller's `Child`;
        // AssignProcessToJobObject does not take ownership of it.
        unsafe {
            if AssignProcessToJobObject(self.0 as _, process as _) == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Assigns a suspended process and verifies membership in this exact job.
    pub fn assign_verified(&self, process: RawHandle) -> io::Result<()> {
        self.assign(process)?;
        if !self.contains(process)? {
            return Err(io::Error::other("job membership verification failed"));
        }
        Ok(())
    }

    /// Returns whether `process` belongs to this exact job.
    pub fn contains(&self, process: RawHandle) -> io::Result<bool> {
        let mut result = 0;
        // SAFETY: both handles remain live and result is a valid out pointer.
        if unsafe { IsProcessInJob(process as _, self.0 as _, &mut result) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(result != 0)
    }

    /// Abort 用にツリーへ終了を要求する。完了確認と資源解放はプロセスの所有者が行う。
    pub fn terminate(&self) {
        if let Err(error) = self.request_termination() {
            eprintln!("sembazuru-worker: Job の終了要求に失敗: {error}");
        }
    }

    fn request_termination(&self) -> io::Result<()> {
        // SAFETY: 所有する Job ハンドルへ終了を要求する。成功しても終了完了とは扱わない。
        if unsafe { TerminateJobObject(self.0 as _, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn active_processes(&self) -> io::Result<u32> {
        Ok(self.accounting()?.ActiveProcesses)
    }

    fn accounting(&self) -> io::Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION> {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: 所有ハンドルと、API が要求するサイズ・整列の出力先を渡す。
        if unsafe {
            QueryInformationJobObject(
                self.0 as _,
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(info)
    }

    /// ツリー全体へ終了を要求し、全プロセスの終了まで確認する。
    /// 呼出側はこの後に新たなプロセスを割り当てず、失敗時には隔離資源を保持する。
    /// 直下プロセスの終了や stdio の EOF では子孫の終了を証明できない。
    pub(crate) fn terminate_and_wait(&self) -> io::Result<()> {
        self.request_termination()?;
        self.wait_until_empty(std::time::Duration::from_secs(30))
    }

    fn wait_until_empty(&self, timeout: std::time::Duration) -> io::Result<()> {
        let started = std::time::Instant::now();
        let mut state = self
            .1
            .lock()
            .map_err(|_| io::Error::other("Job 終了状態のロックが破損"))?;
        loop {
            // QUERY 権限の失敗も、通知を消費する前に拒否する。
            self.accounting()?;
            loop {
                let (mut message, mut key, mut value) = (0, 0, std::ptr::null_mut());
                // SAFETY: port と出力先は有効。value は通知の整数 PID であり参照しない。
                if unsafe {
                    GetQueuedCompletionStatus(
                        state.port.as_raw_handle() as _,
                        &mut message,
                        &mut key,
                        &mut value,
                        0,
                    )
                } == 0
                {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                        break;
                    }
                    return Err(error);
                }
                if key != 1 {
                    return Err(io::Error::other("Job 通知キーが不正"));
                }
                if message == JOB_OBJECT_MSG_NEW_PROCESS {
                    let pid = u32::try_from(value as usize)
                        .ok()
                        .filter(|pid| *pid != 0)
                        .ok_or_else(|| io::Error::other("Job 通知 PID が不正"))?;
                    state.seen = state
                        .seen
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("Job 通知数が上限を超過"))?;
                    state.pending.push((pid, None));
                }
            }
            let mut index = 0;
            while index < state.pending.len() {
                let (pid, process) = &mut state.pending[index];
                if process.is_none() {
                    // SAFETY: PID を開くだけで操作しない。生存確認後もハンドルを保持する。
                    let raw = unsafe {
                        OpenProcess(
                            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                            0,
                            *pid,
                        )
                    };
                    if raw.is_null() {
                        let error = io::Error::last_os_error();
                        if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                            // PID が既に消滅しているため、元プロセスの終了も完了している。
                            state.pending.swap_remove(index);
                            continue;
                        }
                        return Err(error);
                    }
                    *process = Some(unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) });
                }
                let handle = process.as_ref().unwrap().as_raw_handle();
                // 別 Job の PID に再利用されていれば、元プロセスは既に消滅している。
                if !self.contains(handle)? {
                    state.pending.swap_remove(index);
                    continue;
                }
                match unsafe { WaitForSingleObject(handle as _, 0) } {
                    WAIT_OBJECT_0 => {
                        state.pending.swap_remove(index);
                    }
                    WAIT_TIMEOUT => {
                        index += 1;
                    }
                    _ => return Err(io::Error::last_os_error()),
                }
            }
            let info = self.accounting()?;
            // NEW_PROCESS 通知は欠落しうる。総数に足りない場合は成功にせず期限で拒否する。
            // ActiveProcesses がゼロでも、終了中のカーネル処理が残るので個別待機も必須。
            if info.ActiveProcesses == 0
                && state.seen == info.TotalProcesses
                && state.pending.is_empty()
            {
                return Ok(());
            }
            if started.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Job ツリーの終了確認期限を超過",
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[cfg(test)]
    pub(crate) fn duplicate_with_access_for_test(&self, access: u32) -> Self {
        use windows_sys::Win32::Foundation::DuplicateHandle;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: 元ハンドルを生存させたまま権限を絞った一意のハンドルを受け取る。
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    self.0 as _,
                    GetCurrentProcess(),
                    &mut duplicate,
                    access,
                    0,
                    0,
                )
            },
            0
        );
        Self(duplicate as isize, Arc::clone(&self.1))
    }
}

impl Drop for JobObject {
    fn drop(&mut self) {
        // Closing the last handle to a KILL_ON_JOB_CLOSE job terminates every
        // process still in it (the orphan-prevention guarantee).
        // SAFETY: we own the handle and never hand it out.
        unsafe {
            CloseHandle(self.0 as _);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn missing_creation_notification_cannot_confirm_tree_exit() {
        use std::os::windows::process::CommandExt;
        let job = JobObject::new_kill_on_close().unwrap();
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "exit", "0"])
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        job.assign_verified(child.as_raw_handle()).unwrap();
        let state = job.1.lock().unwrap();
        let (mut message, mut key, mut value) = (0, 0, std::ptr::null_mut());
        assert_ne!(
            unsafe {
                GetQueuedCompletionStatus(
                    state.port.as_raw_handle() as _,
                    &mut message,
                    &mut key,
                    &mut value,
                    5_000,
                )
            },
            0
        );
        assert_eq!(message, JOB_OBJECT_MSG_NEW_PROCESS);
        drop(state);
        // 作成通知を処理前に失わせる。実際には終了していても、確認の欠落を成功にしない。
        job.request_termination().unwrap();
        child.wait().unwrap();
        assert_eq!(job.active_processes().unwrap(), 0);
        assert_eq!(
            job.wait_until_empty(std::time::Duration::ZERO)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn tree_wait_requires_zero_active_processes_and_propagates_errors() {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
        let job = JobObject::new_kill_on_close().unwrap();
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/d", "/c", "exit", "0"])
            .creation_flags(windows_sys::Win32::System::Threading::CREATE_SUSPENDED)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        use std::os::windows::io::AsRawHandle;
        job.assign_verified(child.as_raw_handle()).unwrap();
        assert_eq!(job.active_processes().unwrap(), 1);
        assert_eq!(
            job.wait_until_empty(std::time::Duration::ZERO)
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        let query_only = job.duplicate_with_access_for_test(JOB_OBJECT_QUERY);
        assert!(query_only.terminate_and_wait().is_err());
        assert_eq!(job.active_processes().unwrap(), 1);
        let terminate_only = job.duplicate_with_access_for_test(JOB_OBJECT_TERMINATE);
        assert!(terminate_only.terminate_and_wait().is_err());
        job.terminate_and_wait().unwrap();
        assert_eq!(job.active_processes().unwrap(), 0);
        child.wait().unwrap();
    }

    #[test]
    fn desktop_relaxed_test_job_differs_only_by_desktop_limit() {
        let baseline = JobObject::new_kill_on_close().unwrap();
        let variant = JobObject::new_kill_on_close_without_desktop_limit_for_test().unwrap();
        let baseline_bits = baseline.ui_restrictions_for_test().unwrap();
        let variant_bits = variant.ui_restrictions_for_test().unwrap();
        assert_eq!(baseline_bits, 0x0000_00fe);
        assert_eq!(variant_bits, 0x0000_00be);
        assert_eq!(baseline_bits ^ variant_bits, JOB_OBJECT_UILIMIT_DESKTOP);
    }

    /// Whether `pid` is currently a running process. Uses `tasklist` (no unsafe in
    /// the test): it prints the row only when the PID exists, and "No tasks…"
    /// otherwise.
    fn pid_alive(pid: u32) -> bool {
        match std::process::Command::new("tasklist")
            .args(["/NH", "/FI", &format!("PID eq {pid}")])
            .output()
        {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains(&pid.to_string()),
            Err(_) => false,
        }
    }

    /// The whole reason the Job Object exists (M6.1e): killing the direct child
    /// must also kill the GRANDCHILD (the real compiler the launcher injects).
    /// `powershell -> ping` models `launcher -> compiler`: we capture the
    /// grandchild (ping) PID, drop the job, and assert that exact PID is gone —
    /// proving the *tree* kill, not just the direct child (which `kill_on_drop`
    /// already covered).
    #[tokio::test]
    async fn dropping_the_job_kills_the_grandchild() {
        let dir = std::env::temp_dir().join(format!("sbz-job-gc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let pidfile = dir.join("gc.pid");
        let _ = std::fs::remove_file(&pidfile);

        let job = JobObject::new_kill_on_close().unwrap();
        // The direct child (powershell) launches ping as a grandchild, records its
        // PID, then waits on it (so the grandchild is long-lived until killed).
        let script = format!(
            "$p = Start-Process ping -ArgumentList '-n','30','127.0.0.1' -PassThru \
             -WindowStyle Hidden; Set-Content -Path '{}' -Value $p.Id; Wait-Process -Id $p.Id",
            pidfile.display()
        );
        let mut child = tokio::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        job.assign(child.raw_handle().expect("child handle while running"))
            .unwrap();

        // Read the grandchild PID once powershell records it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let gc_pid = loop {
            if let Ok(s) = std::fs::read_to_string(&pidfile)
                && let Ok(pid) = s.trim().parse::<u32>()
            {
                break pid;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "grandchild PID was never recorded"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        };
        assert!(
            pid_alive(gc_pid),
            "grandchild {gc_pid} should be running before the kill"
        );

        // Drop the job: the OS kills the whole tree (powershell AND ping).
        drop(job);
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait()).await;

        // The grandchild's exact PID must be gone — poll briefly for async teardown.
        let mut gone = false;
        for _ in 0..50 {
            if !pid_alive(gc_pid) {
                gone = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            gone,
            "grandchild PID {gc_pid} survived the job kill — tree kill failed"
        );
    }

    /// A child assigned to a KILL_ON_JOB_CLOSE job is terminated when the job
    /// handle drops — the core orphan-prevention guarantee.
    #[tokio::test]
    async fn dropping_the_job_kills_the_child() {
        let job = JobObject::new_kill_on_close().unwrap();
        // A process that would otherwise run for ~30s.
        let mut child = tokio::process::Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let raw = child
            .raw_handle()
            .expect("child has a handle while running");
        job.assign(raw).unwrap();

        // Drop the job: the OS kills the process tree. Proof is timing — without
        // the job kill the child would run ~30s, so `wait()` returning well
        // inside 5s is the orphan-prevention guarantee. (The exit code of a
        // job-close-terminated process is not reliably nonzero, so we assert on
        // the kill happening, not on the code.)
        drop(job);
        let _status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .expect("child must die quickly after the job is dropped — it was not killed")
            .expect("wait() on the killed child");
    }

    /// `terminate()` (an explicit Abort) kills the job's processes immediately.
    #[tokio::test]
    async fn terminate_kills_the_child() {
        let job = JobObject::new_kill_on_close().unwrap();
        let mut child = tokio::process::Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        job.assign(child.raw_handle().expect("child handle"))
            .unwrap();

        job.terminate();
        let _status = tokio::time::timeout(std::time::Duration::from_secs(5), child.wait())
            .await
            .expect("child must die quickly after terminate() — Abort did not kill it")
            .expect("wait() on the terminated child");
    }
}
