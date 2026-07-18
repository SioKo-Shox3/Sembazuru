//! Dev driver (not shipped): sends ONE `Execute` with a `VfsExecution` to a
//! worker and exits with the action's code. This drives the worker's read-VFS
//! execution path directly (bypassing the daemon's LocalIntake, which wires the
//! VFS config itself in M6.1c), so the M6.1b gate
//! (hooks/test/m6_worker_vfs_redirect.ps1) can prove the worker injects the hook
//! DLL and supplies inputs on demand.
//!
//! Usage:
//!   exec_vfs <worker_endpoint> <agent_fileserver> <vfs_root> <trace_dir|--empty-trace-dir> [--no-vfs] [--worker-id <id>] -- <argv...>
//! e.g.
//!   exec_vfs http://127.0.0.1:50061 127.0.0.1:50072 C:\src C:\trace -- probe.exe C:\src\a.txt
//!   exec_vfs http://127.0.0.1:50061 127.0.0.1:50072 C:\src C:\trace --no-vfs --worker-id HOST#1234 -- probe.exe

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::ptr::null_mut;
use std::time::{SystemTime, UNIX_EPOCH};

use sembazuru_agent::{ActionOutcome, ExecOptions, ExecuteError, execute_on_channel_with};
use sembazuru_proto::capability::{
    self, ActionCapability, CAPABILITY_TTL_SECS, CAPABILITY_VERSION,
};
use sembazuru_proto::v0::{Command, VfsExecution};
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

const EMPTY_TRACE_DIR_SENTINEL: &str = "--empty-trace-dir";
const NO_VFS_FLAG: &str = "--no-vfs";
const WORKER_ID_FLAG: &str = "--worker-id";
const ACTION_ID: &str = "exec-vfs";
const NEGATIVE_ACTION_ID: &str = "exec-vfs-negative-control";
const WORKER_ID_MISMATCH_EXIT: i32 = 86;
const DRIVER_FAILURE_EXIT: i32 = 87;
const WORKER_ID_MISMATCH_DIAGNOSTIC: &str =
    "exec_vfs: worker identity changed before action admission";
const USAGE: &str = "usage: exec_vfs <worker> <agent_fileserver> <vfs_root> <trace_dir|--empty-trace-dir> [--no-vfs] [--worker-id <id>] -- <argv...>";

struct DriverArgs {
    worker_endpoint: String,
    worker_id: Option<String>,
    no_vfs: bool,
    agent_fileserver: String,
    vfs_root: String,
    trace_dir: String,
    argv: Vec<String>,
}

#[derive(Debug)]
enum DriverError {
    Usage,
    Message(&'static str),
    Detail(&'static str, String),
    WorkerIdentityChanged,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DriverError::Usage => f.write_str(USAGE),
            DriverError::Message(message) => f.write_str(message),
            DriverError::Detail(context, detail) => write!(f, "{context}: {detail}"),
            DriverError::WorkerIdentityChanged => {
                f.write_str("worker identity changed before action admission")
            }
        }
    }
}

impl std::error::Error for DriverError {}

fn parse_driver_args(args: &[String]) -> Result<DriverArgs, DriverError> {
    let sep = args
        .iter()
        .position(|arg| arg == "--")
        .ok_or(DriverError::Usage)?;
    if sep < 4 {
        return Err(DriverError::Usage);
    }
    let (no_vfs, worker_id) = match &args[4..sep] {
        [] => (false, None),
        [flag] if flag == NO_VFS_FLAG => (true, None),
        [flag, worker_id] if flag == WORKER_ID_FLAG && !worker_id.is_empty() => {
            (false, Some(worker_id.clone()))
        }
        [no_vfs, flag, worker_id]
            if no_vfs == NO_VFS_FLAG && flag == WORKER_ID_FLAG && !worker_id.is_empty() =>
        {
            (true, Some(worker_id.clone()))
        }
        _ => return Err(DriverError::Usage),
    };
    if args[..4].iter().any(String::is_empty) || sep + 1 >= args.len() {
        return Err(DriverError::Usage);
    }
    let trace_dir = if args[3] == EMPTY_TRACE_DIR_SENTINEL {
        String::new()
    } else {
        args[3].clone()
    };
    Ok(DriverArgs {
        worker_endpoint: args[0].clone(),
        worker_id,
        no_vfs,
        agent_fileserver: args[1].clone(),
        vfs_root: args[2].clone(),
        trace_dir,
        argv: args[sep + 1..].to_vec(),
    })
}

fn request_parts(args: &DriverArgs) -> (Command, ExecOptions) {
    let cwd = std::env::current_dir()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    // Full env so the injected launcher/compiler has PATH etc. (the worker sets
    // the child env explicitly from this, plus the authoritative VFS vars).
    let env: HashMap<String, String> = std::env::vars().collect();
    let command = Command {
        argv: args.argv.clone(),
        env,
        cwd,
    };
    let opts = ExecOptions {
        predicted_paths: Vec::new(),
        vfs: (!args.no_vfs).then(|| VfsExecution {
            agent_fileserver: args.agent_fileserver.clone(),
            vfs_root: args.vfs_root.clone(),
            trace_dir: args.trace_dir.clone(),
            strict: false,
            allow_original_cwd: false,
        }),
    };
    (command, opts)
}

fn encode_action_capability(
    worker_id: &str,
    command: &Command,
    opts: &ExecOptions,
    key: &[u8; 32],
    now: u64,
    nonce: [u8; 16],
) -> Vec<u8> {
    ActionCapability {
        version: CAPABILITY_VERSION,
        worker_id: worker_id.to_string(),
        action_id: ACTION_ID.to_string(),
        session_id: String::new(),
        command_digest: capability::command_digest(&command.argv, &command.env, &command.cwd),
        vfs_digest: capability::vfs_digest(opts.vfs.as_ref()),
        issued_at: now,
        expires_at: now.saturating_add(CAPABILITY_TTL_SECS),
        nonce,
    }
    .encode(key)
}

#[cfg(windows)]
fn secure_nonce() -> io::Result<[u8; 16]> {
    let mut nonce = [0u8; 16];
    // SAFETY: a null algorithm with SYSTEM_PREFERRED requests the OS CSPRNG and
    // nonce is a valid writable buffer for its exact length.
    if unsafe {
        BCryptGenRandom(
            null_mut(),
            nonce.as_mut_ptr(),
            nonce.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err(io::Error::other("secure random generator unavailable"));
    }
    Ok(nonce)
}

#[cfg(not(windows))]
fn secure_nonce() -> io::Result<[u8; 16]> {
    Err(io::Error::other(
        "installed-worker capability gate requires Windows",
    ))
}

fn installed_action_capability(
    worker_id: &str,
    command: &Command,
    opts: &ExecOptions,
) -> Result<Vec<u8>, DriverError> {
    let secret = sembazuru_config_store::read_machine_cluster_token()
        .map_err(|error| {
            DriverError::Detail("machine cluster token read failed", error.to_string())
        })?
        .ok_or(DriverError::Message(
            "machine cluster token is not configured",
        ))?;
    let token = std::str::from_utf8(secret.as_ref())
        .map_err(|_| DriverError::Message("machine cluster token is not valid UTF-8"))?;
    if token.is_empty() {
        return Err(DriverError::Message("machine cluster token is empty"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DriverError::Message("system time is before the Unix epoch"))?
        .as_secs();
    let nonce = secure_nonce().map_err(|error| {
        DriverError::Detail("capability nonce generation failed", error.to_string())
    })?;
    let mut key = capability::cap_key(token);
    let encoded = encode_action_capability(worker_id, command, opts, &key, now, nonce);
    key.fill(0);
    Ok(encoded)
}

fn negative_control_command() -> Command {
    // Empty argv[0] passes request shape validation but can never start a process.
    // With auth enabled the worker rejects it before setup; with auth disabled it
    // safely reaches setup failure and proves the negative control was not enforced.
    Command {
        argv: vec![String::new()],
        env: HashMap::new(),
        cwd: String::new(),
    }
}

fn require_missing_capability(
    result: Result<ActionOutcome, ExecuteError>,
) -> Result<(), DriverError> {
    match result {
        Err(ExecuteError::Rpc(status))
            if status.code() == tonic::Code::PermissionDenied
                && status.message() == "missing action capability" =>
        {
            Ok(())
        }
        Ok(_) => Err(DriverError::Message(
            "negative control was accepted; worker action-capability auth is disabled",
        )),
        Err(error) => Err(DriverError::Detail(
            "negative control did not return the required missing-capability rejection",
            error.to_string(),
        )),
    }
}

fn is_worker_identity_mismatch(error: &ExecuteError) -> bool {
    matches!(
        error,
        ExecuteError::Rpc(status)
            if status.code() == tonic::Code::PermissionDenied
                && status.message() == "capability not for this worker"
    )
}

async fn run() -> Result<i32, DriverError> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_driver_args(&raw)?;
    let (command, opts) = request_parts(&args);
    let channel = tonic::transport::Endpoint::from_shared(args.worker_endpoint.clone())
        .map_err(|error| DriverError::Detail("invalid worker endpoint", error.to_string()))?
        .connect()
        .await
        .map_err(|error| DriverError::Detail("worker connection failed", error.to_string()))?;

    let action_capability = if let Some(worker_id) = args.worker_id.as_deref() {
        let negative = execute_on_channel_with(
            channel.clone(),
            negative_control_command(),
            NEGATIVE_ACTION_ID.to_string(),
            String::new(),
            ExecOptions::default(),
            Vec::new(),
        )
        .await;
        require_missing_capability(negative)?;
        installed_action_capability(worker_id, &command, &opts)?
    } else {
        // Legacy M6 harnesses intentionally run an auth-disabled development worker.
        Vec::new()
    };

    let outcome = match execute_on_channel_with(
        channel,
        command,
        ACTION_ID.to_string(),
        // This dev harness bypasses daemon intake, so no agent-side data-plane
        // session exists. The M9 probe stays outside vfs_root and needs no fetch.
        String::new(),
        opts,
        action_capability,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(error) if is_worker_identity_mismatch(&error) => {
            return Err(DriverError::WorkerIdentityChanged);
        }
        Err(error) => {
            return Err(DriverError::Detail("VFS Execute failed", error.to_string()));
        }
    };
    let code = outcome.exit_code.unwrap_or(-1);
    println!("exec_vfs: states={:?} exit={code}", outcome.states);
    Ok(code)
}

#[tokio::main]
async fn main() {
    let code = match run().await {
        Ok(code) => code,
        Err(DriverError::WorkerIdentityChanged) => {
            eprintln!("{WORKER_ID_MISMATCH_DIAGNOSTIC}");
            WORKER_ID_MISMATCH_EXIT
        }
        Err(error) => {
            eprintln!("exec_vfs: {error}");
            DRIVER_FAILURE_EXIT
        }
    };
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use sembazuru_proto::capability;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn parses_installed_worker_identity_without_changing_legacy_shape() {
        let legacy = parse_driver_args(&strings(&[
            "http://127.0.0.1:50061",
            "127.0.0.1:50072",
            r"C:\src",
            r"C:\trace",
            "--",
            "probe.exe",
        ]))
        .unwrap();
        assert_eq!(legacy.worker_id, None);
        assert!(!legacy.no_vfs);

        let installed = parse_driver_args(&strings(&[
            "http://127.0.0.1:50061",
            "127.0.0.1:50072",
            r"C:\src",
            r"C:\trace",
            "--worker-id",
            "HOST#1234",
            "--",
            "probe.exe",
        ]))
        .unwrap();
        assert_eq!(installed.worker_id.as_deref(), Some("HOST#1234"));
        assert!(!installed.no_vfs);
    }

    #[test]
    fn parses_no_vfs_only_at_the_fixed_position_and_binds_no_vfs_digest() {
        let plain = parse_driver_args(&strings(&[
            "http://127.0.0.1:50061",
            "127.0.0.1:50072",
            r"C:\src",
            r"C:\trace",
            "--no-vfs",
            "--worker-id",
            "HOST#1234",
            "--",
            "probe.exe",
        ]))
        .unwrap();
        assert!(plain.no_vfs);
        assert_eq!(plain.worker_id.as_deref(), Some("HOST#1234"));

        let (_, opts) = request_parts(&plain);
        assert!(opts.vfs.is_none());
        assert_eq!(
            capability::vfs_digest(opts.vfs.as_ref()),
            capability::vfs_digest(None)
        );
        let key = capability::cap_key("test-only-secret");
        let encoded = encode_action_capability(
            "HOST#1234",
            &request_parts(&plain).0,
            &opts,
            &key,
            1_000,
            [8; 16],
        );
        let decoded = capability::decode_and_verify(&encoded, &key, 1_001).unwrap();
        assert_eq!(decoded.vfs_digest, capability::vfs_digest(None));

        for invalid in [
            strings(&[
                "http://127.0.0.1:50061",
                "127.0.0.1:50072",
                r"C:\src",
                r"C:\trace",
                "--worker-id",
                "HOST#1234",
                "--worker-id",
                "HOST#5678",
                "--",
                "probe.exe",
            ]),
            strings(&[
                "http://127.0.0.1:50061",
                "127.0.0.1:50072",
                r"C:\src",
                r"C:\trace",
                "--worker-id",
                "HOST#1234",
                "--no-vfs",
                "--",
                "probe.exe",
            ]),
            strings(&[
                "http://127.0.0.1:50061",
                "127.0.0.1:50072",
                r"C:\src",
                r"C:\trace",
                "--no-vfs",
                "--no-vfs",
                "--",
                "probe.exe",
            ]),
            strings(&[
                "http://127.0.0.1:50061",
                "127.0.0.1:50072",
                r"C:\src",
                r"C:\trace",
                "--no-vfs",
                "--worker-id",
                "",
                "--",
                "probe.exe",
            ]),
            strings(&["http://127.0.0.1:50061", "--", "probe.exe"]),
        ] {
            assert!(matches!(
                parse_driver_args(&invalid),
                Err(DriverError::Usage)
            ));
        }
    }

    #[test]
    fn empty_trace_sentinel_remains_a_vfs_request() {
        let parsed = parse_driver_args(&strings(&[
            "http://127.0.0.1:50061",
            "127.0.0.1:50072",
            r"C:\src",
            EMPTY_TRACE_DIR_SENTINEL,
            "--",
            "probe.exe",
        ]))
        .unwrap();
        assert!(!parsed.no_vfs);
        let (_, opts) = request_parts(&parsed);
        assert_eq!(
            opts.vfs.as_ref().map(|vfs| vfs.trace_dir.as_str()),
            Some("")
        );
    }

    #[test]
    fn encoded_capability_binds_worker_command_and_vfs() {
        let parsed = parse_driver_args(&strings(&[
            "http://127.0.0.1:50061",
            "127.0.0.1:50072",
            r"C:\src",
            r"C:\trace",
            "--worker-id",
            "HOST#1234",
            "--",
            "probe.exe",
        ]))
        .unwrap();
        let (command, opts) = request_parts(&parsed);
        let mut key = capability::cap_key("test-only-secret");
        let encoded = encode_action_capability("HOST#1234", &command, &opts, &key, 1_000, [7; 16]);
        key.fill(0);

        let decoded = capability::decode_and_verify(
            &encoded,
            &capability::cap_key("test-only-secret"),
            1_001,
        )
        .unwrap();
        assert_eq!(decoded.worker_id, "HOST#1234");
        assert_eq!(decoded.action_id, ACTION_ID);
        assert_eq!(
            decoded.command_digest,
            capability::command_digest(&command.argv, &command.env, &command.cwd,)
        );
        assert_eq!(
            decoded.vfs_digest,
            capability::vfs_digest(opts.vfs.as_ref())
        );
        assert_eq!(decoded.issued_at, 1_000);
        assert_eq!(decoded.expires_at, 1_000 + CAPABILITY_TTL_SECS);
        assert_eq!(decoded.nonce, [7; 16]);
    }

    #[test]
    fn negative_control_accepts_only_exact_missing_capability_rejection() {
        let expected = Err(sembazuru_agent::ExecuteError::Rpc(
            tonic::Status::permission_denied("missing action capability"),
        ));
        assert!(require_missing_capability(expected).is_ok());

        let auth_disabled = Ok(sembazuru_agent::ActionOutcome::default());
        assert!(require_missing_capability(auth_disabled).is_err());

        let wrong_reason = Err(sembazuru_agent::ExecuteError::Rpc(
            tonic::Status::permission_denied("command mismatch"),
        ));
        assert!(require_missing_capability(wrong_reason).is_err());
    }

    #[test]
    fn worker_identity_mismatch_classification_is_exact() {
        let mismatch = ExecuteError::Rpc(tonic::Status::permission_denied(
            "capability not for this worker",
        ));
        assert!(is_worker_identity_mismatch(&mismatch));

        let other_reason = ExecuteError::Rpc(tonic::Status::permission_denied(
            "missing action capability",
        ));
        assert!(!is_worker_identity_mismatch(&other_reason));
        let other_code = ExecuteError::Rpc(tonic::Status::invalid_argument(
            "capability not for this worker",
        ));
        assert!(!is_worker_identity_mismatch(&other_code));
    }
}
