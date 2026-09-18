//! The one-shot pipe the GUI hands its join payload to an elevated helper on (ADR 0018).
//!
//! The GUI is Medium and cannot write the machine store itself. It creates one pipe, launches
//! `sembazuru-storectl join --pipe <name>` elevated, and hands the envelope over only after the
//! connected client is proven to be that exact process.
//!
//! What this protects, and what it does not. The design goals are three, and nothing here claims
//! more: the secret never reaches argv or disk; a process that took the pipe name first cannot
//! impersonate the elevated token; and name squatting is detected rather than silently accepted.
//! It is not isolation from the user's own code — the GUI already holds the secret, the owner keeps
//! an implicit `WRITE_DAC` over the pipe, and UAC is not a security boundary.

use std::fmt;

/// Why one join delivery did not complete. None of these carry the payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The platform cannot provide the required Windows pipe semantics.
    Unsupported,
    /// The pipe could not be created under its fixed security descriptor.
    Create(u32),
    /// Another process already held this pipe name.
    NameTaken,
    /// The helper could not be launched, or the user declined the elevation.
    Elevation(String),
    /// Nobody connected, or the connected client was not the helper that was launched.
    Peer(String),
    /// The envelope could not be written, or was written only in part.
    Write(u32),
    /// The helper was launched but did not finish within its bound.
    Timeout,
    /// The helper finished with a failure exit code.
    Helper(i32),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "join over a pipe is only available on Windows"),
            Self::Create(error) => write!(f, "could not create the join pipe (error {error})"),
            Self::NameTaken => write!(f, "the join pipe name was already taken"),
            Self::Elevation(reason) => write!(f, "elevation failed: {reason}"),
            Self::Peer(reason) => write!(f, "the join helper could not be confirmed: {reason}"),
            Self::Write(error) => write!(f, "could not hand over the join payload ({error})"),
            Self::Timeout => write!(f, "the join helper did not finish in time"),
            Self::Helper(code) => write!(f, "the join helper failed (exit code {code})"),
        }
    }
}

impl std::error::Error for TransportError {}

/// The security descriptor every join pipe is created with.
///
/// `D:P` keeps inherited entries out. The single entry grants read to `BA` and to nobody else, which
/// is what the elevated helper already has to be for `storectl` to authorize it at all. A filtered
/// (non-elevated) token carries Administrators as deny-only, so it matches no allow entry here.
pub const JOIN_PIPE_SDDL: &str = "D:P(A;;GR;;;BA)";

/// Fixed prefix of every join pipe name, matching what `storectl` accepts.
pub const JOIN_PIPE_PREFIX: &str = r"\\.\pipe\sembazuru-join-";

/// Builds the pipe name for one delivery. The name is not a secret and is passed in argv.
pub fn pipe_name(suffix: &[u8; 16]) -> String {
    let mut name = String::with_capacity(JOIN_PIPE_PREFIX.len() + 32);
    name.push_str(JOIN_PIPE_PREFIX);
    for byte in suffix {
        name.push(char::from_digit(u32::from(byte >> 4), 16).expect("nibble"));
        name.push(char::from_digit(u32::from(byte & 0x0f), 16).expect("nibble"));
    }
    name
}

/// Decides whether the connected client is the helper this delivery launched.
///
/// The launched process handle is held open across this check, so its id cannot be recycled onto a
/// different process in between. An unavailable id is a refusal, never a pass.
pub const fn peer_is_the_launched_helper(client: Option<u32>, launched: Option<u32>) -> bool {
    match (client, launched) {
        (Some(client), Some(launched)) => client == launched && client != 0,
        _ => false,
    }
}

#[cfg(windows)]
pub use imp::{JoinPipe, deliver};

#[cfg(not(windows))]
pub fn deliver(_payload: &sembazuru_config_store::JoinPayload) -> Result<(), TransportError> {
    Err(TransportError::Unsupported)
}

#[cfg(windows)]
mod imp {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
    use std::ptr::null_mut;

    use sembazuru_config_store::JoinPayload;
    use windows_sys::Win32::Foundation::{
        ERROR_ACCESS_DENIED, ERROR_CANCELLED, ERROR_PIPE_CONNECTED, GetLastError,
        INVALID_HANDLE_VALUE, LocalFree, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FlushFileBuffers, PIPE_ACCESS_OUTBOUND, WriteFile,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessId, WaitForSingleObject,
    };
    use windows_sys::Win32::UI::Shell::{
        SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

    use super::{JOIN_PIPE_SDDL, TransportError, peer_is_the_launched_helper, pipe_name};

    /// How long the helper has to connect and finish. The helper's own work is short; this only
    /// bounds a hang, including a UAC prompt the user leaves open.
    const HELPER_TIMEOUT_MS: u32 = 120_000;

    /// One unconnected join pipe, owned by the GUI.
    pub struct JoinPipe {
        name: String,
        server: OwnedHandle,
    }

    struct LocalSecurityDescriptor(*mut std::ffi::c_void);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the pointer came from the converter, which allocates with LocalAlloc.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    fn random_suffix() -> Result<[u8; 16], TransportError> {
        let mut bytes = [0u8; 16];
        // SAFETY: the buffer is writable for its stated length; the system RNG needs no handle.
        let status = unsafe {
            BCryptGenRandom(
                null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status != 0 {
            return Err(TransportError::Create(status as u32));
        }
        Ok(bytes)
    }

    impl JoinPipe {
        /// Creates the one instance of a fresh pipe name under the fixed descriptor.
        pub fn create() -> Result<Self, TransportError> {
            let name = pipe_name(&random_suffix()?);
            let name_w: Vec<u16> = std::ffi::OsStr::new(&name)
                .encode_wide()
                .chain(Some(0))
                .collect();
            let sddl_w: Vec<u16> = std::ffi::OsStr::new(JOIN_PIPE_SDDL)
                .encode_wide()
                .chain(Some(0))
                .collect();

            let mut descriptor = null_mut();
            // SAFETY: the SDDL text is NUL-terminated and live; the output pointer is valid and the
            // returned descriptor is owned by the guard below.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                // SAFETY: GetLastError is read immediately after the failing call.
                return Err(TransportError::Create(unsafe { GetLastError() }));
            }
            let descriptor = LocalSecurityDescriptor(descriptor);

            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                // The helper is launched by name, never by an inherited handle.
                bInheritHandle: 0,
            };

            // One instance, created here or not at all: `FILE_FLAG_FIRST_PIPE_INSTANCE` turns a
            // name another process already holds into a failure instead of a second instance.
            // SAFETY: the name and the descriptor are live for the call.
            let handle = unsafe {
                CreateNamedPipeW(
                    name_w.as_ptr(),
                    PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    64 * 1024,
                    0,
                    0,
                    &attributes,
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                // SAFETY: GetLastError is read immediately after the failing call.
                let error = unsafe { GetLastError() };
                // A first-instance create whose name is already in use fails with
                // ERROR_ACCESS_DENIED, which is the squatting case; any user may otherwise create
                // a pipe under this namespace, so that code does not mean something else here.
                return Err(if error == ERROR_ACCESS_DENIED {
                    TransportError::NameTaken
                } else {
                    TransportError::Create(error)
                });
            }
            Ok(Self {
                name,
                // SAFETY: CreateNamedPipeW returned one owned kernel handle.
                server: unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) },
            })
        }

        /// The name to pass to the helper. Not a secret.
        pub fn name(&self) -> &str {
            &self.name
        }

        /// Waits for the helper to connect, proves it is the launched process, and only then writes.
        ///
        /// Takes the pipe by value: the helper reads to end of file, and only the server handle
        /// closing gives it one. `DisconnectNamedPipe` would tear the connection down instead, and
        /// the helper's next read would fail rather than end, losing a payload it already has.
        fn hand_over(
            self,
            launched: &OwnedHandle,
            payload: &JoinPayload,
        ) -> Result<(), TransportError> {
            let server = self.server.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
            // SAFETY: the server handle is live and this pipe has exactly one instance.
            let connected = unsafe { ConnectNamedPipe(server, null_mut()) };
            if connected == 0 {
                // SAFETY: GetLastError is read immediately after the failing call.
                let error = unsafe { GetLastError() };
                // A client that connected between creation and this call is already connected.
                if error != ERROR_PIPE_CONNECTED {
                    return Err(TransportError::Peer(format!("connect failed ({error})")));
                }
            }

            let mut client = 0u32;
            // SAFETY: the server handle is connected and the output is a writable u32.
            let queried = unsafe { GetNamedPipeClientProcessId(server, &mut client) };
            let client = (queried != 0).then_some(client);
            // SAFETY: the launched handle is live, which is what keeps its id from being recycled.
            let expected = unsafe { GetProcessId(launched.as_raw_handle() as _) };
            let expected = (expected != 0).then_some(expected);
            if !peer_is_the_launched_helper(client, expected) {
                // Nothing has been written, and dropping this pipe closes the handle, which drops
                // the unproven client with it.
                return Err(TransportError::Peer(
                    "the connected client was not the launched helper".to_owned(),
                ));
            }

            // Only now does the payload exist outside this process.
            let bytes = payload
                .encode()
                .map_err(|_| TransportError::Write(ERROR_ACCESS_DENIED))?;
            let mut written_total = 0usize;
            while written_total < bytes.len() {
                let mut written = 0u32;
                let chunk = &bytes[written_total..];
                // SAFETY: the slice is live for the call and the count fits the remaining length.
                if unsafe {
                    WriteFile(
                        server,
                        chunk.as_ptr(),
                        chunk.len() as u32,
                        &mut written,
                        null_mut(),
                    )
                } == 0
                    || written == 0
                {
                    // SAFETY: GetLastError is read immediately after the failing write.
                    return Err(TransportError::Write(unsafe { GetLastError() }));
                }
                written_total += written as usize;
            }
            // Blocks until the helper has consumed the bytes, so closing below cannot cut the
            // payload short.
            // SAFETY: the server handle is live and connected.
            unsafe { FlushFileBuffers(server) };
            // Dropping `self` closes the server handle, and that close is the helper's end of file.
            Ok(())
        }
    }

    fn launch_helper(pipe: &str) -> Result<OwnedHandle, TransportError> {
        // The helper is launched by its full path next to this image, so ShellExecuteEx performs no
        // PATH or CWD search and a peer cannot redirect the elevated launch by planting an exe.
        let mut helper = std::env::current_exe()
            .map_err(|error| TransportError::Elevation(error.to_string()))?;
        helper.pop();
        helper.push("sembazuru-storectl.exe");
        if !helper.is_file() {
            return Err(TransportError::Elevation(
                "the join helper is not installed next to this program".to_owned(),
            ));
        }
        let helper_w: Vec<u16> = helper.as_os_str().encode_wide().chain(Some(0)).collect();
        let verb_w: Vec<u16> = std::ffi::OsStr::new("runas")
            .encode_wide()
            .chain(Some(0))
            .collect();
        let params_w: Vec<u16> = std::ffi::OsStr::new(&format!("join --pipe {pipe}"))
            .encode_wide()
            .chain(Some(0))
            .collect();

        // SAFETY: zeroing then filling a plain C struct; the wide strings outlive the call below.
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
        // The process handle is what ties the connected client to this launch, so it is required.
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = verb_w.as_ptr();
        info.lpFile = helper_w.as_ptr();
        info.lpParameters = params_w.as_ptr();
        info.nShow = SW_HIDE;

        // SAFETY: `info` is fully initialized per the struct contract.
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            // SAFETY: GetLastError is read immediately after the failing call.
            let error = unsafe { GetLastError() };
            return Err(TransportError::Elevation(if error == ERROR_CANCELLED {
                "elevation was declined".to_owned()
            } else {
                format!("could not launch the join helper (error {error})")
            }));
        }
        if info.hProcess.is_null() {
            return Err(TransportError::Elevation(
                "no handle to the join helper".to_owned(),
            ));
        }
        // SAFETY: ShellExecuteExW returned one owned process handle under SEE_MASK_NOCLOSEPROCESS.
        Ok(unsafe { OwnedHandle::from_raw_handle(info.hProcess as RawHandle) })
    }

    fn wait_for_helper(helper: &OwnedHandle) -> Result<i32, TransportError> {
        let handle = helper.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        // SAFETY: the handle is a live process handle.
        if unsafe { WaitForSingleObject(handle, HELPER_TIMEOUT_MS) } == WAIT_TIMEOUT {
            return Err(TransportError::Timeout);
        }
        let mut code = 0u32;
        // SAFETY: the handle is live and the output is a writable u32.
        if unsafe { GetExitCodeProcess(handle, &mut code) } == 0 {
            // SAFETY: GetLastError is read immediately after the failing call.
            return Err(TransportError::Peer(format!(
                "the join helper's result was unavailable ({})",
                unsafe { GetLastError() }
            )));
        }
        Ok(code as i32)
    }

    /// Creates the pipe, launches the elevated helper, and hands over one payload.
    pub fn deliver(payload: &JoinPayload) -> Result<(), TransportError> {
        let pipe = JoinPipe::create()?;
        let helper = launch_helper(pipe.name())?;
        let handed = pipe.hand_over(&helper, payload);
        let finished = wait_for_helper(&helper);
        // A failed hand-over is the more specific fault, so it wins over the helper's exit code.
        handed?;
        match finished? {
            0 => Ok(()),
            code => Err(TransportError::Helper(code)),
        }
    }

    #[cfg(test)]
    mod tests {
        use windows_sys::Win32::Foundation::CloseHandle;

        use super::*;

        /// Opens a pipe from this process, which is Medium and carries Administrators as deny-only.
        fn open_as_this_process(name: &str) -> Result<OwnedHandle, u32> {
            use windows_sys::Win32::Storage::FileSystem::{
                CreateFileW, FILE_GENERIC_READ, OPEN_EXISTING,
            };

            let name_w: Vec<u16> = std::ffi::OsStr::new(name)
                .encode_wide()
                .chain(Some(0))
                .collect();
            // SAFETY: the name is NUL-terminated and live for the call.
            let handle = unsafe {
                CreateFileW(
                    name_w.as_ptr(),
                    FILE_GENERIC_READ,
                    0,
                    null_mut(),
                    OPEN_EXISTING,
                    0,
                    null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE || handle.is_null() {
                // SAFETY: GetLastError is read immediately after the failing call.
                return Err(unsafe { GetLastError() });
            }
            // SAFETY: CreateFileW returned one owned kernel handle.
            Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
        }

        /// Whether this test process runs with an elevated token.
        fn is_elevated() -> bool {
            use windows_sys::Win32::Security::{
                GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
            };
            use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

            let mut token = null_mut();
            // SAFETY: the output pointer is valid and a success transfers one owned handle.
            if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
                panic!("the test process token is required");
            }
            // SAFETY: OpenProcessToken returned an owned kernel handle.
            let token = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut length = 0u32;
            // SAFETY: the buffer matches the class's fixed size and stays live for the call.
            let queried = unsafe {
                GetTokenInformation(
                    token.as_raw_handle() as _,
                    TokenElevation,
                    std::ptr::addr_of_mut!(elevation).cast(),
                    size_of::<TOKEN_ELEVATION>() as u32,
                    &mut length,
                )
            };
            assert_ne!(queried, 0, "the elevation of this process is required");
            elevation.TokenIsElevated != 0
        }

        #[test]
        fn the_join_pipe_admits_exactly_an_elevated_administrator() {
            let pipe = JoinPipe::create().expect("create the join pipe");
            let opened = open_as_this_process(pipe.name());
            if is_elevated() {
                // The one allow entry is `BA`, which an elevated administrator matches.
                opened.map(|_| ()).expect("an elevated open must succeed");
            } else {
                // A filtered token carries Administrators as deny-only, so it matches no allow
                // entry. That refusal is the whole point of the descriptor.
                assert_eq!(
                    opened
                        .map(|_| ())
                        .expect_err("a non-elevated open must be refused"),
                    ERROR_ACCESS_DENIED,
                    "unexpected refusal reason"
                );
            }
        }

        #[test]
        fn a_second_instance_of_the_same_name_is_refused() {
            let pipe = JoinPipe::create().expect("create the join pipe");
            let name_w: Vec<u16> = std::ffi::OsStr::new(pipe.name())
                .encode_wide()
                .chain(Some(0))
                .collect();
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: null_mut(),
                bInheritHandle: 0,
            };
            // SAFETY: the name is live for the call; a failure returns an invalid handle.
            let second = unsafe {
                CreateNamedPipeW(
                    name_w.as_ptr(),
                    PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    64 * 1024,
                    0,
                    0,
                    &attributes,
                )
            };
            if second != INVALID_HANDLE_VALUE && !second.is_null() {
                // SAFETY: the call returned an owned handle that must not outlive this check.
                unsafe { CloseHandle(second) };
                panic!("a second instance of the name was created");
            }
        }

        #[test]
        fn every_pipe_gets_its_own_name_under_the_fixed_prefix() {
            let first = JoinPipe::create().expect("first pipe");
            let second = JoinPipe::create().expect("second pipe");
            assert_ne!(first.name(), second.name());
            for pipe in [&first, &second] {
                let suffix = pipe
                    .name()
                    .strip_prefix(super::super::JOIN_PIPE_PREFIX)
                    .expect("fixed prefix");
                assert_eq!(suffix.len(), 32);
                assert!(suffix.bytes().all(|byte| byte.is_ascii_hexdigit()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_the_fixed_prefix_and_one_hex_suffix() {
        let name = pipe_name(&[
            0x00, 0xff, 0x10, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ]);
        assert_eq!(
            name,
            r"\\.\pipe\sembazuru-join-00ff100a0102030405060708090a0b0c"
        );
    }

    #[test]
    fn an_unproven_peer_is_never_accepted() {
        assert!(peer_is_the_launched_helper(Some(4321), Some(4321)));
        for (client, launched) in [
            (Some(4321), Some(1234)),
            (None, Some(4321)),
            (Some(4321), None),
            (None, None),
            // An id of zero means the query gave nothing usable, not "the System process".
            (Some(0), Some(0)),
        ] {
            assert!(
                !peer_is_the_launched_helper(client, launched),
                "accepted client={client:?} launched={launched:?}"
            );
        }
    }
}
