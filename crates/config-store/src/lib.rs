//! Fail-closed lifecycle for Sembazuru's machine configuration store.

use std::fmt;
use std::io;

use zeroize::Zeroizing;

#[cfg(windows)]
mod windows;

/// Stable failure categories for callers that must fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineStoreErrorClass {
    /// The platform cannot provide the required Windows security semantics.
    Unsupported,
    /// The canonical namespace entry already existed at fresh provisioning.
    NamespaceAlreadyExists,
    /// Persisted identity, type, security, or lifecycle state was not exact.
    IntegrityViolation,
    /// An operating-system operation failed without proving an integrity fault.
    Io,
}

/// A classified machine-store lifecycle failure.
#[derive(Debug)]
pub struct MachineStoreError {
    class: MachineStoreErrorClass,
    context: &'static str,
    source: Option<io::Error>,
}

impl MachineStoreError {
    /// Returns the stable class suitable for mapping to a process exit reason.
    pub const fn classification(&self) -> MachineStoreErrorClass {
        self.class
    }

    fn new(class: MachineStoreErrorClass, context: &'static str) -> Self {
        Self {
            class,
            context,
            source: None,
        }
    }

    fn with_io(class: MachineStoreErrorClass, context: &'static str, source: io::Error) -> Self {
        Self {
            class,
            context,
            source: Some(source),
        }
    }
}

impl fmt::Display for MachineStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(source) = &self.source {
            write!(f, "{}: {source}", self.context)
        } else {
            f.write_str(self.context)
        }
    }
}

impl std::error::Error for MachineStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

/// Atomically creates the fixed `%ProgramData%\Sembazuru` machine store.
pub fn provision_fresh_machine_store() -> Result<(), MachineStoreError> {
    platform::provision()
}

/// Removes an uncommitted store only when its marker and identities are exact.
pub fn rollback_machine_store_provision() -> Result<(), MachineStoreError> {
    platform::rollback()
}

/// Commits an exact provisioned store by deleting its private marker.
pub fn commit_machine_store_provision() -> Result<(), MachineStoreError> {
    platform::commit()
}

/// Removes an exact committed store without following reparse children.
pub fn uninstall_committed_machine_store() -> Result<(), MachineStoreError> {
    platform::uninstall()
}

/// Selects one of the two fixed machine configuration identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineConfigTarget {
    /// `%ProgramData%\Sembazuru\daemon.toml`.
    Daemon,
    /// `%ProgramData%\Sembazuru\worker.toml`.
    Worker,
}

/// Atomically replaces a fixed configuration in an exact committed store.
pub fn replace_machine_config(
    target: MachineConfigTarget,
    contents: &[u8],
) -> Result<(), MachineStoreError> {
    platform::replace_config(target, contents)
}

/// Creates a fixed configuration only when absent in an exact provisioned store.
pub fn seed_machine_config(
    target: MachineConfigTarget,
    contents: &[u8],
) -> Result<bool, MachineStoreError> {
    platform::seed_config(target, contents)
}

/// Plaintext machine cluster token whose owned bytes are zeroized on drop.
pub struct MachineSecret(Zeroizing<Vec<u8>>);

impl MachineSecret {
    fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl AsRef<[u8]> for MachineSecret {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for MachineSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MachineSecret([REDACTED])")
    }
}

/// Reads the fixed `%ProgramData%\Sembazuru\cluster-token.dpapi` secret.
pub fn read_machine_cluster_token() -> Result<Option<MachineSecret>, MachineStoreError> {
    platform::read_machine_secret()
}

/// Atomically replaces the fixed machine cluster token.
pub fn replace_machine_cluster_token(token: &[u8]) -> Result<(), MachineStoreError> {
    platform::replace_machine_secret(token)
}

/// Clears the fixed machine cluster token by its validated held identity.
pub fn clear_machine_cluster_token() -> Result<bool, MachineStoreError> {
    platform::clear_machine_secret()
}

/// One fixed target directive in a machine cluster-token transaction.
pub enum MachineTokenUpdateValue<'a> {
    /// Assert and retain the target's current safe state, including absence.
    Preserve,
    /// Atomically publish the supplied bytes for the fixed target.
    Replace(&'a [u8]),
}

/// The complete fixed machine cluster-token transaction.
pub struct MachineTokenUpdate<'a> {
    pub cluster_token: MachineTokenUpdateValue<'a>,
    pub daemon_config: MachineTokenUpdateValue<'a>,
    pub worker_config: MachineTokenUpdateValue<'a>,
}

/// Shared lease proving that one service runtime may use the committed store.
pub struct MachineServiceRuntimeGuard {
    _inner: platform::MachineServiceRuntimeGuard,
}

impl fmt::Debug for MachineServiceRuntimeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MachineServiceRuntimeGuard([REDACTED])")
    }
}

/// Exclusive capability for one machine token-update transaction sequence.
pub struct MachineTokenUpdateGuard {
    inner: platform::MachineTokenUpdateGuard,
}

impl fmt::Debug for MachineTokenUpdateGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MachineTokenUpdateGuard([REDACTED])")
    }
}

/// Enters the fixed service-runtime lease after proving no update is pending.
pub fn enter_machine_service_runtime() -> Result<MachineServiceRuntimeGuard, MachineStoreError> {
    platform::enter_service_runtime().map(|inner| MachineServiceRuntimeGuard { _inner: inner })
}

/// Begins the one exclusive fixed machine token-update lease.
pub fn begin_machine_token_update() -> Result<MachineTokenUpdateGuard, MachineStoreError> {
    platform::begin_token_update().map(|inner| MachineTokenUpdateGuard { inner })
}

/// Result of preparing an immutable machine cluster-token update journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineTokenUpdatePreparation {
    /// Every replacement was byte-identical to the current safe state.
    NoChange,
    /// The immutable journal is published and retained for apply or resume.
    JournalReady,
}

/// Prepares one fixed, whole machine cluster-token update transaction.
pub fn prepare_machine_cluster_token_update(
    guard: &mut MachineTokenUpdateGuard,
    update: MachineTokenUpdate<'_>,
) -> Result<MachineTokenUpdatePreparation, MachineStoreError> {
    platform::prepare_token_update(&mut guard.inner, update)
}

/// Reports whether a fully validated machine cluster-token journal exists.
pub fn machine_cluster_token_update_pending(
    guard: &mut MachineTokenUpdateGuard,
) -> Result<bool, MachineStoreError> {
    platform::token_update_pending(&mut guard.inner)
}

/// Applies or resumes the one pending fixed machine cluster-token transaction.
pub fn apply_or_resume_machine_cluster_token_update(
    guard: &mut MachineTokenUpdateGuard,
) -> Result<(), MachineStoreError> {
    platform::apply_token_update(&mut guard.inner)
}

#[cfg(test)]
mod machine_config_api_tests {
    use super::*;

    #[test]
    fn machine_config_public_api_is_identity_fixed() {
        let _: fn(MachineConfigTarget, &[u8]) -> Result<(), MachineStoreError> =
            replace_machine_config;
        let _: fn(MachineConfigTarget, &[u8]) -> Result<bool, MachineStoreError> =
            seed_machine_config;
        assert_ne!(MachineConfigTarget::Daemon, MachineConfigTarget::Worker);

        let source = include_str!("lib.rs");
        for name in ["replace_machine_config", "seed_machine_config"] {
            let start = source
                .find(&format!("pub fn {name}"))
                .expect("public machine-config declaration");
            let declaration = source[start..]
                .split_once(" {")
                .expect("complete public machine-config declaration")
                .0;
            assert!(declaration.contains("MachineConfigTarget"), "{declaration}");
            assert!(!declaration.contains("Path"), "{declaration}");
            assert!(!declaration.contains("Policy"), "{declaration}");
            assert!(!declaration.contains("mode"), "{declaration}");
        }

        let windows_source = include_str!("windows.rs");
        assert!(windows_source.contains("NtSetInformationFile"));
        assert!(windows_source.contains("FileRenameInformation"));
        for forbidden in ["MoveFileExW", "ReplaceFileW", "FileRenameInfo,"] {
            assert!(!windows_source.contains(forbidden), "{forbidden}");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn machine_config_is_unsupported_without_side_effects_off_windows() {
        for target in [MachineConfigTarget::Daemon, MachineConfigTarget::Worker] {
            assert_eq!(
                replace_machine_config(target, b"new")
                    .unwrap_err()
                    .classification(),
                MachineStoreErrorClass::Unsupported
            );
            assert_eq!(
                seed_machine_config(target, b"seed")
                    .unwrap_err()
                    .classification(),
                MachineStoreErrorClass::Unsupported
            );
        }
    }
}

#[cfg(test)]
mod machine_secret_api_tests {
    use super::*;

    trait AmbiguousIfImpl<A> {
        fn probe() {}
    }

    impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
    impl<T: Clone> AmbiguousIfImpl<u8> for T {}

    #[test]
    fn machine_secret_public_api_is_fixed_identity_and_secret_is_not_cloneable() {
        let _: fn() -> Result<Option<MachineSecret>, MachineStoreError> =
            read_machine_cluster_token;
        let _: fn(&[u8]) -> Result<(), MachineStoreError> = replace_machine_cluster_token;
        let _: fn() -> Result<bool, MachineStoreError> = clear_machine_cluster_token;
        let _ = <MachineSecret as AmbiguousIfImpl<_>>::probe;

        let source = include_str!("lib.rs");
        for name in [
            "read_machine_cluster_token",
            "replace_machine_cluster_token",
            "clear_machine_cluster_token",
        ] {
            let start = source
                .find(&format!("pub fn {name}"))
                .expect("public machine-secret declaration");
            let declaration = source[start..]
                .split_once(" {")
                .expect("complete public machine-secret declaration")
                .0;
            for forbidden in ["Path", "Policy", "Scope", "Descriptor", "Sddl", "mode"] {
                assert!(!declaration.contains(forbidden), "{declaration}");
            }
        }
    }

    #[test]
    fn machine_secret_debug_is_redacted_and_plaintext_is_borrow_only() {
        let secret = MachineSecret::new(b"machine-secret-debug-sentinel".to_vec());
        assert_eq!(secret.as_ref(), b"machine-secret-debug-sentinel");
        let debug = format!("{secret:?}");
        assert!(!debug.contains("machine-secret-debug-sentinel"), "{debug}");
    }

    #[cfg(not(windows))]
    #[test]
    fn machine_secret_is_unsupported_without_side_effects_off_windows() {
        assert_eq!(
            read_machine_cluster_token().unwrap_err().classification(),
            MachineStoreErrorClass::Unsupported
        );
        assert_eq!(
            replace_machine_cluster_token(b"token")
                .unwrap_err()
                .classification(),
            MachineStoreErrorClass::Unsupported
        );
        assert_eq!(
            clear_machine_cluster_token().unwrap_err().classification(),
            MachineStoreErrorClass::Unsupported
        );
    }
}

#[cfg(test)]
mod machine_token_update_api_tests {
    use super::*;

    trait AmbiguousIfImpl<A> {
        fn probe() {}
    }

    impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
    impl<T: Clone> AmbiguousIfImpl<u8> for T {}

    #[test]
    fn machine_token_lease_public_api_is_fixed_transactional_and_non_cloneable() {
        let _: fn() -> Result<MachineServiceRuntimeGuard, MachineStoreError> =
            enter_machine_service_runtime;
        let _: fn() -> Result<MachineTokenUpdateGuard, MachineStoreError> =
            begin_machine_token_update;
        let _: fn(
            &mut MachineTokenUpdateGuard,
            MachineTokenUpdate<'_>,
        ) -> Result<MachineTokenUpdatePreparation, MachineStoreError> =
            prepare_machine_cluster_token_update;
        let _: fn(&mut MachineTokenUpdateGuard) -> Result<bool, MachineStoreError> =
            machine_cluster_token_update_pending;
        let _: fn(&mut MachineTokenUpdateGuard) -> Result<(), MachineStoreError> =
            apply_or_resume_machine_cluster_token_update;
        let _ = <MachineServiceRuntimeGuard as AmbiguousIfImpl<_>>::probe;
        let _ = <MachineTokenUpdateGuard as AmbiguousIfImpl<_>>::probe;

        let update = MachineTokenUpdate {
            cluster_token: MachineTokenUpdateValue::Preserve,
            daemon_config: MachineTokenUpdateValue::Replace(b"daemon"),
            worker_config: MachineTokenUpdateValue::Preserve,
        };
        assert!(matches!(
            update.cluster_token,
            MachineTokenUpdateValue::Preserve
        ));

        let source = include_str!("lib.rs");
        for name in [
            "enter_machine_service_runtime",
            "begin_machine_token_update",
        ] {
            let start = source
                .find(&format!("pub fn {name}"))
                .expect("public machine-token lease declaration");
            let declaration = source[start..]
                .split_once(" {")
                .expect("complete public machine-token lease declaration")
                .0;
            assert!(declaration.contains("()"), "{declaration}");
            for forbidden in ["Path", "root", "Sid", "Sddl", "Policy", "share", "mode"] {
                assert!(!declaration.contains(forbidden), "{declaration}");
            }
        }
        for name in [
            "prepare_machine_cluster_token_update",
            "machine_cluster_token_update_pending",
            "apply_or_resume_machine_cluster_token_update",
        ] {
            let start = source
                .find(&format!("pub fn {name}"))
                .expect("public machine-token update declaration");
            let declaration = source[start..]
                .split_once(" {")
                .expect("complete public machine-token update declaration")
                .0;
            assert!(
                declaration.contains("&mut MachineTokenUpdateGuard"),
                "{declaration}"
            );
            for forbidden in [
                "Path", "leaf", "root", "Identity", "hash", "journal", "Sddl", "Policy", "mode",
                "fault", "delete",
            ] {
                assert!(!declaration.contains(forbidden), "{declaration}");
            }
        }
        let production_source = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        for (start, _) in production_source.match_indices("impl MachineServiceRuntimeGuard {") {
            let implementation = &production_source[start..];
            let mut depth = 0usize;
            let end = implementation
                .char_indices()
                .find_map(|(offset, character)| match character {
                    '{' => {
                        depth += 1;
                        None
                    }
                    '}' => {
                        depth -= 1;
                        (depth == 0).then_some(offset + character.len_utf8())
                    }
                    _ => None,
                })
                .expect("complete MachineServiceRuntimeGuard implementation");
            let implementation = &implementation[..end];
            assert!(
                !implementation.contains("pub fn "),
                "service runtime guard must not expose public update authority: {implementation}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn machine_token_lease_is_unsupported_without_side_effects_off_windows() {
        assert_eq!(
            enter_machine_service_runtime()
                .unwrap_err()
                .classification(),
            MachineStoreErrorClass::Unsupported
        );
        assert_eq!(
            begin_machine_token_update().unwrap_err().classification(),
            MachineStoreErrorClass::Unsupported
        );
    }
}

#[cfg(windows)]
mod platform {
    use super::{
        MachineConfigTarget, MachineSecret, MachineStoreError, MachineTokenUpdate,
        MachineTokenUpdatePreparation, windows,
    };

    pub(super) type MachineServiceRuntimeGuard = windows::MachineServiceRuntimeGuard;
    pub(super) type MachineTokenUpdateGuard = windows::MachineTokenUpdateGuard;

    pub(super) fn provision() -> Result<(), MachineStoreError> {
        windows::provision_canonical()
    }

    pub(super) fn rollback() -> Result<(), MachineStoreError> {
        windows::rollback_canonical()
    }

    pub(super) fn commit() -> Result<(), MachineStoreError> {
        windows::commit_canonical()
    }

    pub(super) fn uninstall() -> Result<(), MachineStoreError> {
        windows::uninstall_canonical()
    }

    pub(super) fn replace_config(
        target: MachineConfigTarget,
        contents: &[u8],
    ) -> Result<(), MachineStoreError> {
        windows::replace_config_canonical(target, contents)
    }

    pub(super) fn seed_config(
        target: MachineConfigTarget,
        contents: &[u8],
    ) -> Result<bool, MachineStoreError> {
        windows::seed_config_canonical(target, contents)
    }

    pub(super) fn read_machine_secret() -> Result<Option<MachineSecret>, MachineStoreError> {
        windows::read_machine_secret_canonical()
    }

    pub(super) fn replace_machine_secret(token: &[u8]) -> Result<(), MachineStoreError> {
        windows::replace_machine_secret_canonical(token)
    }

    pub(super) fn clear_machine_secret() -> Result<bool, MachineStoreError> {
        windows::clear_machine_secret_canonical()
    }

    pub(super) fn enter_service_runtime() -> Result<MachineServiceRuntimeGuard, MachineStoreError> {
        windows::enter_machine_service_runtime_canonical()
    }

    pub(super) fn begin_token_update() -> Result<MachineTokenUpdateGuard, MachineStoreError> {
        windows::begin_machine_token_update_canonical()
    }

    pub(super) fn prepare_token_update(
        guard: &mut MachineTokenUpdateGuard,
        update: MachineTokenUpdate<'_>,
    ) -> Result<MachineTokenUpdatePreparation, MachineStoreError> {
        windows::prepare_machine_token_update(guard, update)
    }

    pub(super) fn token_update_pending(
        guard: &mut MachineTokenUpdateGuard,
    ) -> Result<bool, MachineStoreError> {
        windows::machine_token_update_pending(guard)
    }

    pub(super) fn apply_token_update(
        guard: &mut MachineTokenUpdateGuard,
    ) -> Result<(), MachineStoreError> {
        windows::apply_machine_token_update(guard)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{
        MachineConfigTarget, MachineSecret, MachineStoreError, MachineStoreErrorClass,
        MachineTokenUpdate, MachineTokenUpdatePreparation,
    };

    pub(super) struct MachineServiceRuntimeGuard;
    pub(super) struct MachineTokenUpdateGuard;

    fn unsupported<T>() -> Result<T, MachineStoreError> {
        Err(MachineStoreError::new(
            MachineStoreErrorClass::Unsupported,
            "machine configuration store lifecycle requires Windows",
        ))
    }

    pub(super) fn provision() -> Result<(), MachineStoreError> {
        unsupported()
    }

    pub(super) fn rollback() -> Result<(), MachineStoreError> {
        unsupported()
    }

    pub(super) fn commit() -> Result<(), MachineStoreError> {
        unsupported()
    }

    pub(super) fn uninstall() -> Result<(), MachineStoreError> {
        unsupported()
    }

    pub(super) fn replace_config(
        _target: MachineConfigTarget,
        _contents: &[u8],
    ) -> Result<(), MachineStoreError> {
        unsupported()
    }

    pub(super) fn seed_config(
        _target: MachineConfigTarget,
        _contents: &[u8],
    ) -> Result<bool, MachineStoreError> {
        unsupported()
    }

    pub(super) fn read_machine_secret() -> Result<Option<MachineSecret>, MachineStoreError> {
        unsupported()
    }

    pub(super) fn replace_machine_secret(_token: &[u8]) -> Result<(), MachineStoreError> {
        unsupported()
    }

    pub(super) fn clear_machine_secret() -> Result<bool, MachineStoreError> {
        unsupported()
    }

    pub(super) fn enter_service_runtime() -> Result<MachineServiceRuntimeGuard, MachineStoreError> {
        unsupported()
    }

    pub(super) fn begin_token_update() -> Result<MachineTokenUpdateGuard, MachineStoreError> {
        unsupported()
    }

    pub(super) fn prepare_token_update(
        _guard: &mut MachineTokenUpdateGuard,
        _update: MachineTokenUpdate<'_>,
    ) -> Result<MachineTokenUpdatePreparation, MachineStoreError> {
        unsupported()
    }

    pub(super) fn token_update_pending(
        _guard: &mut MachineTokenUpdateGuard,
    ) -> Result<bool, MachineStoreError> {
        unsupported()
    }

    pub(super) fn apply_token_update(
        _guard: &mut MachineTokenUpdateGuard,
    ) -> Result<(), MachineStoreError> {
        unsupported()
    }
}

#[cfg(all(test, windows))]
use windows::{
    TestSecurityPolicy as SecurityPolicy, commit_at_for_test, create_secure_test_directory,
    current_user_test_policy, inspect_path_nofollow_for_test,
    install_after_root_drop_hook_for_test, parse_marker_for_test, provision_at_for_test,
    rollback_at_for_test, security_matches_for_test, uninstall_at_for_test,
};

#[cfg(all(test, windows))]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use super::*;
    use tempfile::TempDir;

    const ROOT_NAME: &str = "Sembazuru";
    const MARKER_NAME: &str = ".provisioning-v1";

    struct Fixture {
        temp: TempDir,
        parent: PathBuf,
        root: PathBuf,
        policy: SecurityPolicy,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("create test root");
            let parent = temp.path().join("parent");
            fs::create_dir(&parent).expect("create parent");
            let root = parent.join(ROOT_NAME);
            let policy = current_user_test_policy().expect("current-user policy");
            Self {
                temp,
                parent,
                root,
                policy,
            }
        }

        fn provision(&self) -> Result<(), MachineStoreError> {
            provision_at_for_test(&self.parent, OsStr::new(ROOT_NAME), &self.policy)
        }

        fn commit(&self) -> Result<(), MachineStoreError> {
            commit_at_for_test(&self.parent, OsStr::new(ROOT_NAME), &self.policy)
        }

        fn rollback(&self) -> Result<(), MachineStoreError> {
            rollback_at_for_test(&self.parent, OsStr::new(ROOT_NAME), &self.policy)
        }

        fn uninstall(&self) -> Result<(), MachineStoreError> {
            uninstall_at_for_test(&self.parent, OsStr::new(ROOT_NAME), &self.policy)
        }
    }

    fn create_junction(link: &Path, target: &Path) {
        let output = Command::new("cmd")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                link.to_str().expect("UTF-8 test link"),
                target.to_str().expect("UTF-8 test target"),
            ])
            .output()
            .expect("run mklink");
        assert!(
            output.status.success(),
            "mklink failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn prepositioned_directory_is_rejected_without_mutation() {
        let fixture = Fixture::new();
        fs::create_dir(&fixture.root).unwrap();
        let sentinel = fixture.root.join("sentinel");
        fs::write(&sentinel, b"unchanged").unwrap();

        let error = fixture.provision().unwrap_err();

        assert_eq!(
            error.classification(),
            MachineStoreErrorClass::NamespaceAlreadyExists
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"unchanged");
    }

    #[test]
    fn prepositioned_junction_is_rejected_without_following_target() {
        let fixture = Fixture::new();
        let external = fixture.temp.path().join("external");
        fs::create_dir(&external).unwrap();
        let sentinel = external.join("sentinel");
        fs::write(&sentinel, b"external").unwrap();
        let before = inspect_path_nofollow_for_test(&external).unwrap();
        create_junction(&fixture.root, &external);

        let error = fixture.provision().unwrap_err();

        assert_eq!(
            error.classification(),
            MachineStoreErrorClass::NamespaceAlreadyExists
        );
        assert_eq!(inspect_path_nofollow_for_test(&external).unwrap(), before);
        assert_eq!(fs::read(&sentinel).unwrap(), b"external");
        fs::remove_dir(&fixture.root).unwrap();
    }

    #[test]
    fn provision_creates_verified_root_and_children() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();

        let root = inspect_path_nofollow_for_test(&fixture.root).unwrap();
        let scratch = inspect_path_nofollow_for_test(&fixture.root.join("scratch")).unwrap();
        let cas = inspect_path_nofollow_for_test(&fixture.root.join("cas")).unwrap();
        assert!(root.is_directory && !root.is_reparse);
        assert!(scratch.is_directory && !scratch.is_reparse);
        assert!(cas.is_directory && !cas.is_reparse);
        assert_ne!(root.identity, scratch.identity);
        assert_ne!(root.identity, cas.identity);
        assert_ne!(scratch.identity, cas.identity);
        assert!(security_matches_for_test(&fixture.root, fixture.policy.root_sddl()).unwrap());
        assert!(
            security_matches_for_test(&fixture.root.join("scratch"), fixture.policy.child_sddl())
                .unwrap()
        );
        assert!(
            security_matches_for_test(&fixture.root.join("cas"), fixture.policy.child_sddl())
                .unwrap()
        );

        fixture.rollback().unwrap();
    }

    #[test]
    fn marker_is_reopened_and_removed_by_commit() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        assert!(fixture.root.join(MARKER_NAME).exists());

        fixture.commit().unwrap();

        assert!(!fixture.root.join(MARKER_NAME).exists());
        assert!(fixture.root.is_dir());
        fixture.uninstall().unwrap();
    }

    #[test]
    fn rollback_reopens_and_removes_matching_tree() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();

        fixture.rollback().unwrap();

        assert!(!fixture.root.exists());
    }

    #[test]
    fn missing_or_malformed_marker_preserves_tree() {
        for malformed in [false, true] {
            let fixture = Fixture::new();
            fixture.provision().unwrap();
            let marker = fixture.root.join(MARKER_NAME);
            if malformed {
                fs::write(&marker, b"not a marker").unwrap();
            } else {
                fs::remove_file(&marker).unwrap();
            }

            let error = fixture.rollback().unwrap_err();

            assert_eq!(
                error.classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
            assert!(fixture.root.is_dir());
            fs::remove_dir_all(&fixture.root).unwrap();
        }
    }

    #[test]
    fn child_identity_mismatch_preserves_tree() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let scratch = fixture.root.join("scratch");
        let moved = fixture.root.join("scratch-original");
        fs::rename(&scratch, &moved).unwrap();
        create_secure_test_directory(
            &fixture.root,
            OsStr::new("scratch"),
            fixture.policy.child_sddl(),
        )
        .unwrap();

        let error = fixture.rollback().unwrap_err();

        assert_eq!(
            error.classification(),
            MachineStoreErrorClass::IntegrityViolation
        );
        assert!(fixture.root.is_dir());
        assert!(scratch.is_dir());
        fs::remove_dir(&scratch).unwrap();
        fs::rename(&moved, &scratch).unwrap();
        fixture.rollback().unwrap();
    }

    #[test]
    fn uninstall_unlinks_reparse_child_without_touching_external_target() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        fixture.commit().unwrap();
        let external = fixture.temp.path().join("outside");
        fs::create_dir(&external).unwrap();
        let sentinel = external.join("sentinel");
        fs::write(&sentinel, b"outside").unwrap();
        let before = inspect_path_nofollow_for_test(&external).unwrap();
        create_junction(&fixture.root.join("outside-link"), &external);

        fixture.uninstall().unwrap();

        assert!(!fixture.root.exists());
        assert_eq!(inspect_path_nofollow_for_test(&external).unwrap(), before);
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");
    }

    #[test]
    fn replaced_root_with_stale_marker_is_preserved() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let stale_marker = fs::read(fixture.root.join(MARKER_NAME)).unwrap();
        let original = fixture.parent.join("original");
        fs::rename(&fixture.root, &original).unwrap();

        provision_at_for_test(&fixture.parent, OsStr::new("replacement"), &fixture.policy).unwrap();
        let replacement = fixture.parent.join("replacement");
        let replacement_marker = fs::read(replacement.join(MARKER_NAME)).unwrap();
        fs::write(replacement.join(MARKER_NAME), &stale_marker).unwrap();
        fs::rename(&replacement, &fixture.root).unwrap();

        let error = fixture.rollback().unwrap_err();

        assert_eq!(
            error.classification(),
            MachineStoreErrorClass::IntegrityViolation
        );
        assert!(fixture.root.is_dir());
        fs::write(fixture.root.join(MARKER_NAME), replacement_marker).unwrap();
        fixture.rollback().unwrap();
        rollback_at_for_test(&fixture.parent, OsStr::new("original"), &fixture.policy).unwrap();
    }

    #[test]
    fn regular_file_replacement_after_root_drop_is_preserved() {
        let fixture = Fixture::new();
        fixture.provision().unwrap();
        let replacement = fixture.root.clone();
        install_after_root_drop_hook_for_test(&fixture.root, move || {
            fs::write(replacement, b"replacement").unwrap();
        })
        .unwrap();

        let error = fixture.rollback().unwrap_err();

        assert_eq!(
            error.classification(),
            MachineStoreErrorClass::IntegrityViolation
        );
        assert!(fixture.root.is_file());
        assert_eq!(fs::read(&fixture.root).unwrap(), b"replacement");
        fs::remove_file(&fixture.root).unwrap();
    }

    #[test]
    fn malformed_marker_parser_is_rejected() {
        for bytes in [
            &b""[..],
            &b"SEMBSTORE\0"[..],
            &b"SEMBSTORE\0v=2\n"[..],
            &b"SEMBSTORE\0v=1\nroot=not-an-identity\n"[..],
        ] {
            assert!(parse_marker_for_test(bytes).is_err());
        }
    }

    #[test]
    fn public_api_has_no_path_or_policy_parameters() {
        let _: fn() -> Result<(), MachineStoreError> = provision_fresh_machine_store;
        let _: fn() -> Result<(), MachineStoreError> = rollback_machine_store_provision;
        let _: fn() -> Result<(), MachineStoreError> = commit_machine_store_provision;
        let _: fn() -> Result<(), MachineStoreError> = uninstall_committed_machine_store;

        let source = include_str!("lib.rs");
        for name in [
            "provision_fresh_machine_store",
            "rollback_machine_store_provision",
            "commit_machine_store_provision",
            "uninstall_committed_machine_store",
        ] {
            let declaration = source
                .lines()
                .find(|line| line.contains(&format!("pub fn {name}")))
                .expect("public lifecycle declaration");
            assert!(declaration.contains("()"), "{declaration}");
            assert!(!declaration.contains("Path"), "{declaration}");
            assert!(!declaration.contains("Policy"), "{declaration}");
        }
    }
}
