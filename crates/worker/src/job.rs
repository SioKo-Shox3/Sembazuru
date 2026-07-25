//! Windows Job Object wrapper for process-tree kill (M6.1e).
//!
//! The VFS execution path launches the compiler through `launcher.exe`
//! (DetourCreateProcessWithDll), so the real compiler is a *grandchild* of the
//! worker. `kill_on_drop` kills only the direct child (the launcher), orphaning
//! the compiler — it keeps running, holding scratch handles and (on a real
//! reassign) doing redundant work (Plan review M6.1, risk 5; `docs/deferred.md`
//! "孫プロセス孤児").
//!
//! A Job Object created with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` fixes this: the
//! launcher is assigned to the job, the grandchild it spawns is automatically in
//! the same job, and when the last handle to the job closes (this wrapper drops)
//! or it is explicitly terminated (an `Abort`), the OS kills the whole tree.

#![cfg(windows)]

use std::io;
use std::os::windows::io::RawHandle;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
    JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_READCLIPBOARD,
    JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation, SetInformationJobObject,
    TerminateJobObject,
};
#[cfg(test)]
use windows_sys::Win32::System::JobObjects::{
    JOB_OBJECT_UILIMIT_HANDLES, QueryInformationJobObject,
};

/// An owned Job Object that kills every process in it when the handle closes
/// (drop) or [`terminate`](JobObject::terminate) is called. `Send`/`Sync`: the
/// handle is just an opaque kernel handle, safe to move/share across threads.
pub struct JobObject(isize);

// SAFETY: a Windows HANDLE is a process-wide opaque value; the Win32 Job Object
// APIs used here are thread-safe, so sharing the handle across threads is sound.
unsafe impl Send for JobObject {}
unsafe impl Sync for JobObject {}

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
        // SAFETY: standard Win32 calls; the out-param structs are zero-initialized
        // and fully written before use, and the handle is checked for null.
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

            Ok(JobObject(handle as isize))
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

    /// Actively terminates every process in the job now (an explicit `Abort`),
    /// rather than waiting for the handle to drop.
    pub fn terminate(&self) {
        // SAFETY: terminating a job we own; exit code is arbitrary.
        unsafe {
            TerminateJobObject(self.0 as _, 1);
        }
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
