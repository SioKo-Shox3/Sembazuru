use super::*;
use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle, RawHandle};
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
};
use windows_sys::Win32::System::Memory::{
    FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile, OpenFileMappingW, UnmapViewOfFile,
};
use windows_sys::Win32::System::Threading::{
    OpenSemaphoreW, ReleaseSemaphore, SEMAPHORE_MODIFY_STATE,
};
const BOOTSTRAP_SELECTOR: &str = "sandbox::vfs_attestation_tests::vfs_attestation_bootstrap_child";
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn access_denied<T>(result: io::Result<T>) {
    let error = match result {
        Ok(_) => panic!("access unexpectedly granted"),
        Err(error) => error,
    };
    assert_eq!(error.raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
}
fn open_mapping(name: &str, access: u32) -> io::Result<OwnedHandle> {
    let name = wide(name);
    // SAFETY: name is NUL-terminated and a successful handle is owned below.
    let handle = unsafe { OpenFileMappingW(access, 0, name.as_ptr()) };
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: OpenFileMappingW returned a unique owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}
fn open_semaphore(name: &str, access: u32) -> io::Result<OwnedHandle> {
    let name = wide(name);
    // SAFETY: name is NUL-terminated and a successful handle is owned below.
    let handle = unsafe { OpenSemaphoreW(access, 0, name.as_ptr()) };
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: OpenSemaphoreW returned a unique owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle as RawHandle) })
    }
}
#[test]
fn vfs_attestation_uses_fixed_abi_and_validates_slot_boundaries() {
    assert_eq!(std::mem::size_of::<VfsAttestationHeader>(), 24);
    assert_eq!(std::mem::size_of::<VfsAttestationSlot>(), 12);
    let clean = [VfsAttestationSlot {
        generation: 7,
        pid: 42,
        attached: 1,
    }];
    assert!(vfs_attestation_slots_valid(7, 1, 0, &clean));
    assert!(!vfs_attestation_slots_valid(7, 0, 0, &clean));
    assert!(!vfs_attestation_slots_valid(7, 1, 1, &clean));
    assert!(!vfs_attestation_slots_valid(7, 2, 0, &clean));
    assert!(!vfs_attestation_slots_valid(
        7,
        (VFS_ATTESTATION_MAX_SLOTS + 1) as u32,
        0,
        &clean,
    ));
}
#[test]
fn vfs_attestation_named_dacl_limits_each_action_to_exact_access() {
    let action = ActionToken::create().unwrap();
    let other = ActionToken::create().unwrap();
    let attestation = VfsAttestation::create(&action).unwrap();
    action
        .impersonated(|| {
            assert!(
                open_mapping(attestation.mapping_name(), FILE_MAP_READ | FILE_MAP_WRITE).is_ok()
            );
            assert!(open_semaphore(attestation.semaphore_name(), SEMAPHORE_MODIFY_STATE).is_ok());
            access_denied(open_mapping(attestation.mapping_name(), 0x0002_0000));
            access_denied(open_semaphore(attestation.semaphore_name(), 0x0010_0000));
            Ok(())
        })
        .unwrap();
    other
        .impersonated(|| {
            access_denied(open_mapping(
                attestation.mapping_name(),
                FILE_MAP_READ | FILE_MAP_WRITE,
            ));
            access_denied(open_semaphore(
                attestation.semaphore_name(),
                SEMAPHORE_MODIFY_STATE,
            ));
            Ok(())
        })
        .unwrap();
}
#[test]
#[ignore]
fn vfs_attestation_bootstrap_child() {
    let args: Vec<_> = std::env::args_os().collect();
    let separator = args.iter().position(|arg| arg == "--").unwrap();
    let values = &args[separator + 1..];
    assert_eq!(values.len(), 3);
    let record = PathBuf::from(&values[0]);
    let mapping = values[1].to_str().unwrap().parse::<usize>().unwrap() as HANDLE;
    let semaphore = values[2].to_str().unwrap().parse::<usize>().unwrap() as HANDLE;
    // SAFETY: the parent supplied this exact inherited mapping handle.
    let view = unsafe { MapViewOfFile(mapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0) };
    let mapped = !view.Value.is_null();
    if mapped {
        // SAFETY: this child owns the just-created view.
        unsafe { UnmapViewOfFile(view) };
    }
    let mut previous = 0;
    // SAFETY: the parent supplied this exact inherited semaphore handle.
    let released = unsafe { ReleaseSemaphore(semaphore, 1, &mut previous) } != 0;
    std::fs::write(record, [mapped as u8, released as u8]).unwrap();
}
#[tokio::test]
async fn vfs_attestation_bootstrap_handles_reach_a_restricted_child() {
    let action = ActionToken::create().unwrap();
    let attestation = VfsAttestation::create(&action).unwrap();
    let bootstrap = attestation.bootstrap_handles().unwrap();
    for handle in bootstrap.as_handle_list() {
        let mut flags = 0;
        // SAFETY: bootstrap owns the live handle and flags is writable.
        assert_ne!(unsafe { GetHandleInformation(handle, &mut flags) }, 0);
        assert_ne!(flags & HANDLE_FLAG_INHERIT, 0);
    }
    let root = std::env::temp_dir().join(format!("sbz-vfs-{}", secure_random_hex().unwrap()));
    std::fs::create_dir(&root).unwrap();
    let scratch = PrivateScratch::create(&root, "child", &action).unwrap();
    let probe = scratch.path().join("vfs-attestation-probe.exe");
    std::fs::copy(std::env::current_exe().unwrap(), &probe).unwrap();
    let record = scratch.path().join("bootstrap.rec");
    let system_root = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
    let handles = bootstrap.as_handle_list();
    let command = RestrictedCommand::new(probe, scratch.path())
        .arg("--ignored")
        .arg("--exact")
        .arg(BOOTSTRAP_SELECTOR)
        .arg("--nocapture")
        .arg("--test-threads=1")
        .arg("--")
        .arg(&record)
        .arg((handles[0] as usize).to_string())
        .arg((handles[1] as usize).to_string())
        .env("Path", system_root.join("System32"))
        .env("SystemDrive", std::env::var_os("SystemDrive").unwrap())
        .env("SystemRoot", system_root);
    let process = RestrictedProcess::spawn_with_inherited(&action, &command, &handles).unwrap();
    let (code, stdout, stderr) = process.wait_with_output().await.unwrap();
    assert_eq!(code, 0, "stdout={stdout:?} stderr={stderr:?}");
    assert_eq!(std::fs::read(record).unwrap(), [1, 1]);
    drop(scratch);
    std::fs::remove_dir_all(root).unwrap();
}
