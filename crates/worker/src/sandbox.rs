use std::ffi::c_void;
use std::io;
use std::mem::{size_of, size_of_val};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::{
    AllocateAndInitializeSid, CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE,
    FreeSid, GetLengthSid, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    SECURITY_ATTRIBUTES, SECURITY_RESOURCE_MANAGER_AUTHORITY, SID_AND_ATTRIBUTES,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    TOKEN_USER, TokenIntegrityLevel, TokenIsRestricted, TokenUser, WinAuthenticatedUserSid,
    WinBuiltinUsersSid, WinMediumLabelSid, WinRestrictedCodeSid, WinWorldSid,
};
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;
use windows_sys::Win32::System::SystemServices::{
    SE_GROUP_INTEGRITY, SECURITY_MANDATORY_MEDIUM_RID,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct ActionSid(*mut c_void);

impl ActionSid {
    fn random() -> io::Result<Self> {
        let mut nonce = [0u32; 4];
        // SAFETY: a null algorithm plus SYSTEM_PREFERRED uses the OS CSPRNG and nonce is writable.
        if unsafe {
            BCryptGenRandom(
                null_mut(),
                nonce.as_mut_ptr().cast(),
                size_of_val(&nonce) as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } != 0
        {
            return Err(io::Error::other("action identity unavailable"));
        }
        let mut sid = null_mut();
        // The first four subauthorities publicly encode "Sembazuru.action"; the remaining
        // 128 random bits are independent of remote action ids, PIDs, and wall time.
        // SAFETY: authority and out pointer are valid; success transfers a FreeSid allocation.
        if unsafe {
            AllocateAndInitializeSid(
                &SECURITY_RESOURCE_MANAGER_AUTHORITY,
                8,
                0x626d_6553,
                0x7275_7a61,
                0x6361_2e75,
                0x6e6f_6974,
                nonce[0],
                nonce[1],
                nonce[2],
                nonce[3],
                &mut sid,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sid))
    }
}

impl Drop for ActionSid {
    fn drop(&mut self) {
        // SAFETY: self.0 is the outstanding AllocateAndInitializeSid result.
        unsafe { FreeSid(self.0) };
    }
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "wired by following sandbox phases")
)]
pub(crate) struct ActionToken {
    token: OwnedHandle,
    action_sid: ActionSid,
    broker_user: Vec<usize>,
}

#[cfg_attr(
    not(test),
    allow(dead_code, reason = "wired by following sandbox phases")
)]
impl ActionToken {
    pub(crate) fn create() -> io::Result<Self> {
        let token = current_token(TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT)?;
        Self::create_from_token(token.as_raw_handle() as HANDLE)
    }

    fn create_from_token(source: HANDLE) -> io::Result<Self> {
        if token_u32(source, TokenIsRestricted)? != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let action_sid = ActionSid::random()?;
        let broker_user = token_info(source, TokenUser)?;
        let mut sid_storage = Vec::new();
        for kind in [
            WinWorldSid,
            WinAuthenticatedUserSid,
            WinBuiltinUsersSid,
            WinRestrictedCodeSid,
        ] {
            sid_storage.push(well_known_sid(kind)?);
        }
        let mut restrictions = vec![SID_AND_ATTRIBUTES {
            Sid: action_sid.0,
            Attributes: 0,
        }];
        restrictions.extend(sid_storage.iter_mut().map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.as_mut_ptr().cast(),
            Attributes: 0,
        }));
        let mut restricted = null_mut();
        // SAFETY: source is queryable/duplicable; the SID pointers remain alive for this call;
        // the returned primary token is transferred to OwnedHandle and never ambient-fallbacks.
        if unsafe {
            CreateRestrictedToken(
                source,
                DISABLE_MAX_PRIVILEGE,
                0,
                null(),
                0,
                null(),
                restrictions.len() as u32,
                restrictions.as_ptr(),
                &mut restricted,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateRestrictedToken returned a unique live handle.
        let token = unsafe { OwnedHandle::from_raw_handle(restricted as RawHandle) };
        lower_to_medium_if_needed(token.as_raw_handle() as HANDLE)?;
        Ok(Self {
            token,
            action_sid,
            broker_user,
        })
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.token.as_raw_handle() as HANDLE
    }

    fn broker_sid(&self) -> *mut c_void {
        // SAFETY: broker_user owns a complete, aligned TOKEN_USER for self's lifetime.
        unsafe { (*(self.broker_user.as_ptr().cast::<TOKEN_USER>())).User.Sid }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: the pointer is the outstanding LocalAlloc result.
        unsafe { LocalFree(self.0) };
    }
}

fn sid_string(sid: *mut c_void) -> io::Result<String> {
    let mut value = null_mut();
    // SAFETY: sid is live and value receives a LocalAlloc NUL-terminated string.
    if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _allocation = LocalAllocation(value.cast());
    let mut length = 0;
    // SAFETY: allocation remains live and points at a NUL-terminated UTF-16 string.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the preceding scan established the initialized string length.
    Ok(unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(value, length)) })
}

#[allow(dead_code, reason = "wired by sandbox integration phase")]
pub(crate) struct PrivateScratch(PathBuf);

#[allow(dead_code, reason = "wired by sandbox integration phase")]
impl PrivateScratch {
    pub(crate) fn create(root: &Path, leaf: &str, token: &ActionToken) -> io::Result<Self> {
        let components: Vec<_> = Path::new(leaf).components().collect();
        if leaf.contains([':', '\0']) || !matches!(components.as_slice(), [Component::Normal(_)]) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let path = root.join(leaf);
        let sddl = format!(
            "O:{}D:P(A;OICI;FA;;;{})(A;OICI;GRGWGXSD;;;{})(A;OICI;RC;;;OW)",
            sid_string(token.broker_sid())?,
            sid_string(token.broker_sid())?,
            sid_string(token.action_sid.0)?
        );
        create_secured_directory(&path, &sddl)?;
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }

    pub(crate) fn into_path(self) -> PathBuf {
        self.0
    }
}

fn create_secured_directory(path: &Path, sddl: &str) -> io::Result<()> {
    let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
    let mut descriptor = null_mut();
    // SAFETY: the SDDL is NUL-terminated and descriptor is a valid out pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let descriptor = LocalAllocation(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: the path and protected descriptor are live for this atomic create call.
    if unsafe { CreateDirectoryW(wide_path.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn current_token(access: u32) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    // SAFETY: token is a valid out pointer; success returns a unique handle we immediately own.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a unique live handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token as RawHandle) })
}

fn token_info(token: HANDLE, class: i32) -> io::Result<Vec<usize>> {
    let mut needed = 0;
    // SAFETY: a null buffer with zero length is the documented sizing query.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut needed) };
    // usize storage guarantees alignment for the Windows token structures read below.
    let mut info = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: info has at least the reported byte capacity and remains alive for the call.
    if needed == 0
        || unsafe {
            GetTokenInformation(token, class, info.as_mut_ptr().cast(), needed, &mut needed)
        } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

fn token_u32(token: HANDLE, class: i32) -> io::Result<u32> {
    let value = token_info(token, class)?
        .first()
        .copied()
        .ok_or_else(|| io::Error::other("token information was truncated"))? as u32;
    Ok(value)
}

fn well_known_sid(kind: i32) -> io::Result<Vec<u8>> {
    let mut size = 0;
    // SAFETY: the first call is the documented sizing query.
    unsafe { CreateWellKnownSid(kind, null_mut(), null_mut(), &mut size) };
    let mut sid = vec![0; size as usize];
    // SAFETY: sid has the exact reported size and is a valid output buffer.
    if unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

fn integrity_rid(token: HANDLE) -> io::Result<u32> {
    let info = token_info(token, TokenIntegrityLevel)?;
    // SAFETY: TokenIntegrityLevel returns TOKEN_MANDATORY_LABEL with a valid label SID.
    let sid = unsafe { (*(info.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())).Label.Sid };
    // SAFETY: the label SID is valid for both accessor calls while info is alive.
    unsafe {
        let count = *GetSidSubAuthorityCount(sid);
        Ok(*GetSidSubAuthority(sid, u32::from(count - 1)))
    }
}

fn lower_to_medium_if_needed(token: HANDLE) -> io::Result<()> {
    if integrity_rid(token)? <= SECURITY_MANDATORY_MEDIUM_RID as u32 {
        return Ok(());
    }
    set_medium_integrity(token)
}

fn set_medium_integrity(token: HANDLE) -> io::Result<()> {
    let mut sid = well_known_sid(WinMediumLabelSid)?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: sid.as_mut_ptr().cast(),
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    // SAFETY: token has TOKEN_ADJUST_DEFAULT and label points to a live medium-integrity SID.
    if unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            (&label as *const TOKEN_MANDATORY_LABEL).cast(),
            (size_of::<TOKEN_MANDATORY_LABEL>() as u32) + GetLengthSid(label.Label.Sid),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs::File;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE, LUID, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, ImpersonateLoggedOnUser, LookupPrivilegeValueW,
        OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION, RevertToSelf, SE_CHANGE_NOTIFY_NAME,
        SE_DACL_PROTECTED, SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES, TOKEN_GROUPS,
        TOKEN_PRIVILEGES, TOKEN_USER, TokenGroups, TokenPrivileges, TokenRestrictedSids, TokenUser,
        WinCreatorOwnerRightsSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_ALWAYS, CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_SHARE_READ, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    use super::*;

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct RevertGuard;
    impl Drop for RevertGuard {
        fn drop(&mut self) {
            // SAFETY: the guard is created only after this thread was impersonated.
            unsafe { RevertToSelf() };
        }
    }

    impl ActionToken {
        fn only_change_notify_enabled(&self) -> io::Result<bool> {
            let info = token_info(self.handle(), TokenPrivileges)?;
            // SAFETY: TokenPrivileges returns a header followed by PrivilegeCount entries.
            let privileges = unsafe { &*(info.as_ptr().cast::<TOKEN_PRIVILEGES>()) };
            let mut allowed = LUID {
                LowPart: 0,
                HighPart: 0,
            };
            // SAFETY: SE_CHANGE_NOTIFY_NAME is static NUL-terminated data and allowed is valid.
            if unsafe { LookupPrivilegeValueW(null(), SE_CHANGE_NOTIFY_NAME, &mut allowed) } == 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the variable array contains PrivilegeCount entries in bytes.
            let entries = unsafe {
                std::slice::from_raw_parts(
                    privileges.Privileges.as_ptr(),
                    privileges.PrivilegeCount as usize,
                )
            };
            Ok(entries.iter().all(|entry| {
                entry.Attributes & SE_PRIVILEGE_ENABLED == 0
                    || (entry.Luid.LowPart == allowed.LowPart
                        && entry.Luid.HighPart == allowed.HighPart)
            }))
        }

        fn can_open_test_file(&self, action_acl: Option<&ActionToken>) -> io::Result<bool> {
            let mut sddl = format!("D:P(A;;GRGW;;;{})", current_user_sid_string()?);
            if let Some(action) = action_acl {
                sddl.push_str(&format!("(A;;GR;;;{})", sid_string(action.action_sid.0)?));
            }
            let path = create_protected_file(&sddl)?;
            let result = self.impersonated_can_open(&path);
            let _ = std::fs::remove_file(path);
            result
        }

        fn impersonated_can_open(&self, path: &std::path::Path) -> io::Result<bool> {
            // SAFETY: handle is a live restricted token. RevertGuard restores the thread token.
            if unsafe { ImpersonateLoggedOnUser(self.handle()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let _guard = RevertGuard;
            match File::open(path) {
                Ok(_) => Ok(true),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(false),
                Err(error) => Err(error),
            }
        }

        fn impersonated<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
            // SAFETY: handle is live and RevertGuard restores the prior thread token.
            if unsafe { ImpersonateLoggedOnUser(self.handle()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let _guard = RevertGuard;
            operation()
        }
    }

    fn token_groups_contain(token: HANDLE, class: i32, sid: *mut c_void) -> io::Result<bool> {
        let info = token_info(token, class)?;
        // SAFETY: both token group classes return a header followed by GroupCount entries.
        let groups = unsafe { &*(info.as_ptr().cast::<TOKEN_GROUPS>()) };
        // SAFETY: the variable array contains GroupCount entries in bytes.
        let entries = unsafe {
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        // SAFETY: each returned SID and the target SID are valid while their owners are alive.
        Ok(entries
            .iter()
            .any(|entry| unsafe { EqualSid(entry.Sid, sid) } != 0))
    }

    fn current_user_sid_string() -> io::Result<String> {
        let token = current_token(TOKEN_QUERY)?;
        let info = token_info(token.as_raw_handle() as HANDLE, TokenUser)?;
        // SAFETY: TokenUser returns TOKEN_USER with a valid SID while info is alive.
        let user = unsafe { &*(info.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(user.User.Sid)
    }

    fn sid_string(sid: *mut c_void) -> io::Result<String> {
        let mut value = null_mut();
        // SAFETY: sid is valid and value receives a LocalAlloc NUL-terminated string.
        if unsafe { ConvertSidToStringSidW(sid, &mut value) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut length = 0;
        // SAFETY: value is a valid NUL-terminated allocation.
        let text = unsafe {
            while *value.add(length) != 0 {
                length += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(value, length))
        };
        // SAFETY: value is the outstanding LocalAlloc result.
        unsafe { LocalFree(value.cast()) };
        Ok(text)
    }

    fn create_protected_file(sddl: &str) -> io::Result<std::path::PathBuf> {
        let path = std::env::temp_dir().join(format!(
            "sembazuru-action-acl-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        let wide_sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor = null_mut();
        // SAFETY: input is NUL-terminated and descriptor is a valid out pointer.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide_sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let wide_path: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
        // SAFETY: path and descriptor are live; the returned handle is immediately owned.
        let handle = unsafe {
            CreateFileW(
                wide_path.as_ptr(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                &attributes,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                null_mut(),
            )
        };
        // SAFETY: descriptor is the outstanding LocalAlloc result.
        unsafe { LocalFree(descriptor) };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: CreateFileW returned a unique live handle.
        let _handle = unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) };
        Ok(path)
    }

    fn private_scratch_root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "sembazuru-private-scratch-{}-{}",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        create_secured_directory(&path, "D:P(A;OICI;FA;;;WD)").unwrap();
        path
    }

    type ScratchAcl = (String, u16, Vec<(String, u8, u32)>);
    fn scratch_acl(path: &Path) -> io::Result<ScratchAcl> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let (mut owner, mut dacl, mut descriptor) = (null_mut(), null_mut(), null_mut());
        // SAFETY: path is NUL-terminated and all requested outputs are valid.
        let error = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let _descriptor = LocalAllocation(descriptor);
        let (mut control, mut revision) = (0, 0);
        // SAFETY: descriptor and its DACL remain live through _descriptor.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut aces = Vec::new();
        // SAFETY: descriptor owns a non-null DACL with AceCount live entries.
        for index in 0..unsafe { (*dacl).AceCount } as u32 {
            let mut raw = null_mut();
            // SAFETY: index is within AceCount and raw receives an ACE owned by descriptor.
            if unsafe { GetAce(dacl, index, &mut raw) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let ace = unsafe { &*(raw.cast::<ACCESS_ALLOWED_ACE>()) };
            assert_eq!(ace.Header.AceType, ACCESS_ALLOWED_ACE_TYPE as u8);
            aces.push((
                sid_string((&ace.SidStart as *const u32).cast_mut().cast())?,
                ace.Header.AceFlags,
                ace.Mask,
            ));
        }
        Ok((sid_string(owner)?, control, aces))
    }

    fn can_open_directory(path: &Path, access: u32) -> bool {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: path is NUL-terminated and any returned handle is closed below.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            false
        } else {
            // SAFETY: CreateFileW returned a unique live handle.
            drop(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) });
            true
        }
    }

    #[test]
    fn action_token_identity_and_limits() {
        let a = ActionToken::create().unwrap();
        let b = ActionToken::create().unwrap();
        assert!(!token_groups_contain(a.handle(), TokenGroups, a.action_sid.0).unwrap());
        assert!(token_groups_contain(a.handle(), TokenRestrictedSids, a.action_sid.0).unwrap());
        // SAFETY: both action SIDs are valid for the compared token lifetimes.
        assert_eq!(unsafe { EqualSid(a.action_sid.0, b.action_sid.0) }, 0);
        assert!(a.only_change_notify_enabled().unwrap());
        assert!(integrity_rid(a.handle()).unwrap() <= 0x2000);
        set_medium_integrity(a.handle()).unwrap();
    }

    #[test]
    fn action_token_acl_matrix_and_public_tool() {
        let a = ActionToken::create().unwrap();
        let b = ActionToken::create().unwrap();
        assert!(a.can_open_test_file(Some(&a)).unwrap());
        assert!(!a.can_open_test_file(None).unwrap());
        assert!(!a.can_open_test_file(Some(&b)).unwrap());
        let tool = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/where.exe");
        assert!(a.impersonated_can_open(&tool).unwrap());
    }

    #[test]
    fn already_restricted_broker_token_is_rejected() {
        let restricted = ActionToken::create().unwrap();
        assert!(ActionToken::create_from_token(restricted.handle()).is_err());
    }

    #[test]
    fn private_scratch_atomic_acl_and_fail_closed_creation() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "action", &token).unwrap();
        assert_eq!(scratch.path(), root.join("action"));
        std::fs::write(scratch.path().join("sentinel"), b"keep").unwrap();
        assert!(PrivateScratch::create(&root, "action", &token).is_err());
        assert!(PrivateScratch::create(&root.join("missing"), "action", &token).is_err());
        assert!(!root.join("missing").exists());
        assert_eq!(
            std::fs::read(scratch.path().join("sentinel")).unwrap(),
            b"keep"
        );
        for leaf in ["", ".", "..", "a/b", "a\\b", "C:", "a:b", "a\0b"] {
            assert!(
                PrivateScratch::create(&root, leaf, &token).is_err(),
                "{leaf:?}"
            );
        }
        let (owner, control, aces) = scratch_acl(scratch.path()).unwrap();
        assert_eq!(owner, sid_string(token.broker_sid()).unwrap());
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        let inherit = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8;
        let expected = vec![
            (
                sid_string(token.broker_sid()).unwrap(),
                inherit,
                FILE_ALL_ACCESS,
            ),
            (
                sid_string(token.action_sid.0).unwrap(),
                inherit,
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
            ),
            (
                sid_string(
                    well_known_sid(WinCreatorOwnerRightsSid)
                        .unwrap()
                        .as_mut_ptr()
                        .cast(),
                )
                .unwrap(),
                inherit,
                READ_CONTROL,
            ),
        ];
        assert_eq!(aces, expected);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_scratch_matching_action_can_mutate_without_acl_control() {
        let token = ActionToken::create().unwrap();
        let root = private_scratch_root();
        let scratch = PrivateScratch::create(&root, "action", &token).unwrap();
        token
            .impersonated(|| {
                let nested = scratch.path().join("nested");
                std::fs::create_dir(&nested)?;
                let file = nested.join("file");
                std::fs::write(&file, b"value")?;
                assert_eq!(std::fs::read(&file)?, b"value");
                let renamed = nested.join("renamed");
                std::fs::rename(&file, &renamed)?;
                std::fs::remove_file(renamed)?;
                std::fs::remove_dir(nested)?;
                assert!(!can_open_directory(scratch.path(), WRITE_DAC));
                assert!(!can_open_directory(scratch.path(), WRITE_OWNER));
                Ok(())
            })
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn private_scratch_other_action_cannot_discover_or_open() {
        let a = ActionToken::create().unwrap();
        let b = ActionToken::create().unwrap();
        let root = private_scratch_root();
        assert!(
            b.impersonated(|| Ok(std::fs::read_dir(&root).is_ok()))
                .unwrap()
        );
        let scratch = PrivateScratch::create(&root, "action-a", &a).unwrap();
        std::fs::write(scratch.path().join("known"), b"secret").unwrap();
        b.impersonated(|| {
            assert_eq!(
                std::fs::read_dir(scratch.path()).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                File::open(scratch.path().join("known")).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            assert_eq!(
                File::create(scratch.path().join("new")).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            Ok(())
        })
        .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }
}
