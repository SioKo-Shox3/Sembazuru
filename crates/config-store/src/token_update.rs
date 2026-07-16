use std::ffi::OsStr;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::*;
use crate::{MachineTokenUpdate, MachineTokenUpdatePreparation, MachineTokenUpdateValue};

pub(super) const JOURNAL_LEAF: &str = ".cluster-token-update-v1";
const JOURNAL_MAGIC: &[u8; 8] = b"SBZTXN\0\0";
const JOURNAL_VERSION: u32 = 1;
const JOURNAL_VERSION_OFFSET: usize = 8;
const JOURNAL_TOTAL_LENGTH_OFFSET: usize = 12;
const JOURNAL_CHECKSUM_OFFSET: usize = 16;
const JOURNAL_CHECKSUM_BYTES: usize = 32;
const JOURNAL_RECORD_COUNT_OFFSET: usize = 48;
const JOURNAL_IDENTITY_OFFSET: usize = 56;
const JOURNAL_FIRST_RECORD_OFFSET: usize = JOURNAL_IDENTITY_OFFSET + IDENTITY_BYTES;
const JOURNAL_RECORD_BYTES: usize = 100;
const JOURNAL_RECORD_COUNT: usize = 3;
const RECORD_TARGET_OFFSET: usize = 0;
const RECORD_DIRECTIVE_OFFSET: usize = 1;
const RECORD_EXPECTED_OFFSET: usize = 2;
const RECORD_VOLUME_OFFSET: usize = 4;
const RECORD_FILE_ID_OFFSET: usize = 12;
const RECORD_OLD_DIGEST_OFFSET: usize = 28;
const RECORD_INTENDED_DIGEST_OFFSET: usize = 60;
const RECORD_PAYLOAD_OFFSET_OFFSET: usize = 92;
const RECORD_PAYLOAD_LENGTH_OFFSET: usize = 96;
const JOURNAL_PAYLOAD_OFFSET: usize =
    JOURNAL_FIRST_RECORD_OFFSET + JOURNAL_RECORD_BYTES * JOURNAL_RECORD_COUNT;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const MAX_JOURNAL_BYTES: usize =
    JOURNAL_PAYLOAD_OFFSET + MAX_MACHINE_SECRET_BLOB_BYTES + MAX_CONFIG_BYTES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum UpdateTarget {
    Secret,
    Daemon,
    Worker,
}

impl UpdateTarget {
    const ALL: [Self; 3] = [Self::Secret, Self::Daemon, Self::Worker];

    fn id(self) -> u8 {
        match self {
            Self::Secret => 0,
            Self::Daemon => 1,
            Self::Worker => 2,
        }
    }

    fn from_id(id: u8) -> Result<Self, MachineStoreError> {
        match id {
            0 => Ok(Self::Secret),
            1 => Ok(Self::Daemon),
            2 => Ok(Self::Worker),
            _ => Err(integrity("machine token update target is invalid")),
        }
    }

    fn leaf(self) -> &'static str {
        self.fixed_file().leaf()
    }

    fn fixed_file(self) -> FixedFile {
        match self {
            Self::Secret => FixedFile::MachineSecret,
            Self::Daemon => FixedFile::Config(MachineConfigTarget::Daemon),
            Self::Worker => FixedFile::Config(MachineConfigTarget::Worker),
        }
    }

    fn payload_bound(self) -> usize {
        match self {
            Self::Secret => MAX_MACHINE_SECRET_BLOB_BYTES,
            Self::Daemon | Self::Worker => MAX_CONFIG_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedState {
    Absent,
    Present {
        identity: FileIdentity,
        digest: [u8; 32],
    },
}

impl ExpectedState {
    #[cfg(test)]
    fn is_absent(self) -> bool {
        matches!(self, Self::Absent)
    }

    #[cfg(test)]
    fn identity(self) -> Option<FileIdentity> {
        match self {
            Self::Absent => None,
            Self::Present { identity, .. } => Some(identity),
        }
    }

    #[cfg(test)]
    fn digest(self) -> Option<[u8; 32]> {
        match self {
            Self::Absent => None,
            Self::Present { digest, .. } => Some(digest),
        }
    }
}

struct JournalRecord {
    target: UpdateTarget,
    expected: ExpectedState,
    payload: Option<Zeroizing<Vec<u8>>>,
    intended_digest: Option<[u8; 32]>,
}

impl JournalRecord {
    fn preserve(target: UpdateTarget, expected: ExpectedState) -> Self {
        Self {
            target,
            expected,
            payload: None,
            intended_digest: None,
        }
    }

    fn replace(target: UpdateTarget, expected: ExpectedState, payload: Vec<u8>) -> Self {
        let digest = hash_bytes(&payload);
        Self {
            target,
            expected,
            payload: Some(Zeroizing::new(payload)),
            intended_digest: Some(digest),
        }
    }

    fn is_replace(&self) -> bool {
        self.payload.is_some()
    }
}

struct Journal {
    identity: FileIdentity,
    records: Vec<JournalRecord>,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("identity", &self.identity)
            .field("record_count", &self.records.len())
            .finish_non_exhaustive()
    }
}

struct TargetSnapshot {
    state: ExpectedState,
    bytes: Zeroizing<Vec<u8>>,
}

struct UpdateStore<'a> {
    root: &'a File,
    policy: &'a SecurityPolicy,
    root_identity: FileIdentity,
    config_descriptor: SecurityDescriptor,
}

impl<'a> UpdateStore<'a> {
    fn from_held_root(
        root: &'a File,
        root_identity: FileIdentity,
        policy: &'a SecurityPolicy,
    ) -> Result<Self, MachineStoreError> {
        if validate_committed_root_handle(root, policy)? != root_identity {
            return Err(integrity(
                "machine token update root identity changed before use",
            ));
        }
        Ok(Self {
            root,
            policy,
            root_identity,
            config_descriptor: SecurityDescriptor::from_sddl(policy.config_sddl())?,
        })
    }

    fn revalidate(&self) -> Result<(), MachineStoreError> {
        if validate_committed_root_handle(self.root, self.policy)? != self.root_identity {
            return Err(integrity(
                "machine token update root identity or lifecycle changed",
            ));
        }
        Ok(())
    }

    fn snapshot(&self, target: UpdateTarget) -> Result<TargetSnapshot, MachineStoreError> {
        let Some(mut file) = open_fixed_file_optional(self.root, OsStr::new(target.leaf()), false)?
        else {
            return Ok(TargetSnapshot {
                state: ExpectedState::Absent,
                bytes: Zeroizing::new(Vec::new()),
            });
        };
        let identity = verify_config_file(&file, &self.config_descriptor)?;
        let bound = target.payload_bound();
        let mut bytes = Zeroizing::new(Vec::new());
        Read::by_ref(&mut file)
            .take((bound + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| map_io("read machine token update target", error))?;
        if bytes.len() > bound {
            return Err(integrity(
                "machine token update target exceeds its fixed bound",
            ));
        }
        if target == UpdateTarget::Secret {
            unprotect_machine_secret(&bytes)?;
        }
        Ok(TargetSnapshot {
            state: ExpectedState::Present {
                identity,
                digest: hash_bytes(&bytes),
            },
            bytes,
        })
    }
}

struct JournalHandle {
    file: File,
    identity: FileIdentity,
    encoded_digest: [u8; 32],
    journal: Journal,
}

struct OpenedJournal {
    file: File,
    encoded: Zeroizing<Vec<u8>>,
    identity: FileIdentity,
    journal: Journal,
}

impl JournalHandle {
    fn revalidate(&self, store: &UpdateStore<'_>) -> Result<(), MachineStoreError> {
        store.revalidate()?;
        if verify_config_file(&self.file, &store.config_descriptor)? != self.identity {
            return Err(integrity("machine token update journal identity changed"));
        }
        let encoded = read_held_journal(&self.file)?;
        let decoded = decode_journal(&encoded)?;
        if decoded.identity != self.identity || hash_bytes(&encoded) != self.encoded_digest {
            return Err(integrity(
                "machine token update journal was replaced or modified",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrepareFault {
    None,
    #[cfg(test)]
    JournalWrite(ConfigWriteFault),
    #[cfg(test)]
    AfterJournal,
}

#[derive(Debug)]
pub(super) enum ApplyFault {
    None,
    #[cfg(test)]
    AfterTarget(UpdateTarget),
    #[cfg(test)]
    TargetWrite(UpdateTarget, ConfigWriteFault),
    #[cfg(test)]
    ReplaceBeforeTarget(UpdateTarget, Vec<u8>),
    #[cfg(test)]
    BeforeJournalDelete,
    #[cfg(test)]
    JournalDelete,
    #[cfg(test)]
    JournalAbsenceProof,
}

#[cfg(test)]
pub(super) fn prepare_update_at(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
    update: MachineTokenUpdate<'_>,
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
    fault: PrepareFault,
) -> Result<MachineTokenUpdatePreparation, MachineStoreError> {
    let root = reopen_validated_committed(parent, root_name, policy)?;
    let root_identity = inspect_handle(&root)?.identity;
    prepare_update_on_held_root(&root, root_identity, policy, update, next_nonce, fault)
}

pub(super) fn prepare_update_on_held_root(
    root: &File,
    root_identity: FileIdentity,
    policy: &SecurityPolicy,
    update: MachineTokenUpdate<'_>,
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
    fault: PrepareFault,
) -> Result<MachineTokenUpdatePreparation, MachineStoreError> {
    let store = UpdateStore::from_held_root(root, root_identity, policy)?;
    store.revalidate()?;
    if read_journal(&store, false)?.is_some() {
        return Err(integrity(
            "a machine token update journal is already pending",
        ));
    }

    let snapshots = UpdateTarget::ALL
        .map(|target| store.snapshot(target))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let directives = [
        update.cluster_token,
        update.daemon_config,
        update.worker_config,
    ];
    let mut records = Vec::with_capacity(JOURNAL_RECORD_COUNT);
    for ((target, snapshot), directive) in UpdateTarget::ALL
        .into_iter()
        .zip(snapshots.iter())
        .zip(directives)
    {
        let record = match directive {
            MachineTokenUpdateValue::Preserve => JournalRecord::preserve(target, snapshot.state),
            MachineTokenUpdateValue::Replace(contents) => {
                resolve_replacement(target, snapshot, contents)?
            }
        };
        records.push(record);
    }
    if records.iter().all(|record| !record.is_replace()) {
        store.revalidate()?;
        for (target, record) in UpdateTarget::ALL.into_iter().zip(&records) {
            verify_expected(&store.snapshot(target)?, record.expected)?;
        }
        return Ok(MachineTokenUpdatePreparation::NoChange);
    }

    store.revalidate()?;
    for (target, record) in UpdateTarget::ALL.into_iter().zip(&records) {
        verify_expected(&store.snapshot(target)?, record.expected)?;
    }

    let write_fault = match fault {
        #[cfg(test)]
        PrepareFault::JournalWrite(fault) => fault,
        _ => ConfigWriteFault::None,
    };
    let journal_handle = publish_journal(&store, records, next_nonce, write_fault)?;
    journal_handle.revalidate(&store)?;
    for (target, record) in UpdateTarget::ALL
        .into_iter()
        .zip(&journal_handle.journal.records)
    {
        verify_expected(&store.snapshot(target)?, record.expected)?;
    }
    #[cfg(test)]
    if fault == PrepareFault::AfterJournal {
        return Err(integrity(
            "injected failure after machine token update journal publication",
        ));
    }
    Ok(MachineTokenUpdatePreparation::JournalReady)
}

#[cfg(test)]
pub(super) fn update_pending_at(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
) -> Result<bool, MachineStoreError> {
    let root = reopen_validated_committed(parent, root_name, policy)?;
    let root_identity = inspect_handle(&root)?.identity;
    update_pending_on_held_root(&root, root_identity, policy)
}

pub(super) fn update_pending_on_held_root(
    root: &File,
    root_identity: FileIdentity,
    policy: &SecurityPolicy,
) -> Result<bool, MachineStoreError> {
    let store = UpdateStore::from_held_root(root, root_identity, policy)?;
    store.revalidate()?;
    Ok(read_journal(&store, false)?.is_some())
}

pub(super) fn require_service_safe_journal_absence(
    root: &File,
    root_identity: FileIdentity,
    policy: &SecurityPolicy,
) -> Result<(), MachineStoreError> {
    let store = UpdateStore::from_held_root(root, root_identity, policy)?;
    store.revalidate()?;
    match read_journal(&store, false)? {
        None => Ok(()),
        Some(_) => Err(integrity(
            "service runtime is blocked by a pending machine token update journal",
        )),
    }
}

#[cfg(test)]
pub(super) fn apply_update_at(
    parent: &File,
    root_name: &OsStr,
    policy: &SecurityPolicy,
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
    fault: ApplyFault,
) -> Result<(), MachineStoreError> {
    let root = reopen_validated_committed(parent, root_name, policy)?;
    let root_identity = inspect_handle(&root)?.identity;
    apply_update_on_held_root(&root, root_identity, policy, next_nonce, fault)
}

pub(super) fn apply_update_on_held_root(
    root: &File,
    root_identity: FileIdentity,
    policy: &SecurityPolicy,
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
    fault: ApplyFault,
) -> Result<(), MachineStoreError> {
    let store = UpdateStore::from_held_root(root, root_identity, policy)?;
    let journal = open_required_journal(&store, true)?;
    journal.revalidate(&store)?;

    for (target, record) in UpdateTarget::ALL.into_iter().zip(&journal.journal.records) {
        if classify_snapshot(&store.snapshot(target)?, record) == TargetState::Neither {
            return Err(integrity(
                "machine token update target is neither expected-old nor intended",
            ));
        }
    }

    for (target, record) in UpdateTarget::ALL.into_iter().zip(&journal.journal.records) {
        journal.revalidate(&store)?;
        #[cfg(test)]
        if let ApplyFault::ReplaceBeforeTarget(fault_target, bytes) = &fault
            && *fault_target == target
        {
            write_test_race(&store, target, bytes, next_nonce)?;
        }
        let current = store.snapshot(target)?;
        match classify_snapshot(&current, record) {
            TargetState::Old if !record.is_replace() => {}
            TargetState::Intended if record.is_replace() => {}
            TargetState::Old => {
                let write_fault = match &fault {
                    #[cfg(test)]
                    ApplyFault::TargetWrite(fault_target, fault) if *fault_target == target => {
                        *fault
                    }
                    _ => ConfigWriteFault::None,
                };
                write_fixed_file_at_handle(
                    store.root,
                    target.fixed_file(),
                    record
                        .payload
                        .as_ref()
                        .ok_or_else(|| integrity("machine token update payload is missing"))?,
                    policy,
                    ConfigWriteMode::Replace,
                    next_nonce,
                    write_fault,
                )?;
                if classify_snapshot(&store.snapshot(target)?, record) != TargetState::Intended {
                    return Err(integrity(
                        "machine token update target is not intended after replacement",
                    ));
                }
            }
            TargetState::Neither | TargetState::Intended => {
                return Err(integrity(
                    "machine token update immediate revalidation rejected target",
                ));
            }
        }
        let required = if record.is_replace() {
            TargetState::Intended
        } else {
            TargetState::Old
        };
        if classify_snapshot(&store.snapshot(target)?, record) != required {
            return Err(integrity(
                "machine token update target changed after immediate verification",
            ));
        }
        journal.revalidate(&store)?;
        #[cfg(test)]
        if matches!(&fault, ApplyFault::AfterTarget(fault_target) if *fault_target == target) {
            return Err(integrity(
                "injected failure after machine token update target",
            ));
        }
    }

    journal.revalidate(&store)?;
    for (target, record) in UpdateTarget::ALL.into_iter().zip(&journal.journal.records) {
        let final_state = classify_snapshot(&store.snapshot(target)?, record);
        let valid = if record.is_replace() {
            final_state == TargetState::Intended
        } else {
            final_state == TargetState::Old
        };
        if !valid {
            return Err(integrity(
                "machine token update final state verification failed",
            ));
        }
    }
    journal.revalidate(&store)?;
    #[cfg(test)]
    if matches!(
        fault,
        ApplyFault::BeforeJournalDelete
            | ApplyFault::JournalDelete
            | ApplyFault::JournalAbsenceProof
    ) {
        return Err(integrity(
            "injected failure before machine token update journal deletion",
        ));
    }
    let identity = journal.identity;
    delete_held_handle(&journal.file)?;
    drop(journal);
    match open_relative_any(store.root, OsStr::new(JOURNAL_LEAF)) {
        Err(error) if is_not_found(&error) => Ok(()),
        Err(_) => Err(integrity(
            "machine token update journal absence cannot be proven",
        )),
        Ok(entry) if inspect_handle(&entry)?.identity == identity => Err(integrity(
            "machine token update journal remained after identity-bound deletion",
        )),
        Ok(_) => Err(integrity(
            "machine token update journal was replaced during deletion",
        )),
    }
}

fn resolve_replacement(
    target: UpdateTarget,
    snapshot: &TargetSnapshot,
    contents: &[u8],
) -> Result<JournalRecord, MachineStoreError> {
    if contents.len() > target.payload_bound() {
        return Err(integrity(
            "machine token update replacement exceeds its fixed bound",
        ));
    }
    if target == UpdateTarget::Secret {
        if contents.is_empty() || contents.len() > MAX_MACHINE_SECRET_BYTES {
            return Err(integrity(
                "machine token update secret length is outside the fixed bound",
            ));
        }
        if !snapshot.bytes.is_empty()
            && unprotect_machine_secret(&snapshot.bytes)?.as_ref() == contents
        {
            return Ok(JournalRecord::preserve(target, snapshot.state));
        }
        return Ok(JournalRecord::replace(
            target,
            snapshot.state,
            protect_machine_secret(contents)?.to_vec(),
        ));
    }
    if snapshot.state != ExpectedState::Absent && snapshot.bytes.as_slice() == contents {
        return Ok(JournalRecord::preserve(target, snapshot.state));
    }
    Ok(JournalRecord::replace(
        target,
        snapshot.state,
        contents.to_vec(),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetState {
    Old,
    Intended,
    Neither,
}

fn verify_expected(
    snapshot: &TargetSnapshot,
    expected: ExpectedState,
) -> Result<(), MachineStoreError> {
    if snapshot.state == expected {
        Ok(())
    } else {
        Err(integrity(
            "machine token update expected state changed before publication",
        ))
    }
}

fn classify_snapshot(snapshot: &TargetSnapshot, record: &JournalRecord) -> TargetState {
    if snapshot.state == record.expected {
        return TargetState::Old;
    }
    match (snapshot.state, record.intended_digest) {
        (ExpectedState::Present { digest, .. }, Some(intended)) if digest == intended => {
            TargetState::Intended
        }
        _ => TargetState::Neither,
    }
}

fn publish_journal(
    store: &UpdateStore<'_>,
    records: Vec<JournalRecord>,
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
    fault: ConfigWriteFault,
) -> Result<JournalHandle, MachineStoreError> {
    #[cfg(not(test))]
    let _ = fault;
    let (temp_name, mut temp, temp_identity) = create_unique_fixed_temp(
        store.root,
        FixedFile::TokenUpdateJournal,
        &store.config_descriptor,
        next_nonce,
    )?;
    let journal = Journal {
        identity: temp_identity,
        records,
    };
    let encoded = match encode_journal(&journal) {
        Ok(encoded) => encoded,
        Err(primary) => {
            remove_temp_or_combine(store.root, &temp_name, temp, temp_identity, Some(primary))?;
            unreachable!("cleanup with a primary error always returns Err")
        }
    };
    let before_publish = (|| {
        #[cfg(test)]
        if fault == ConfigWriteFault::PartialWrite {
            let partial = encoded.len().div_ceil(2);
            temp.write_all(&encoded[..partial])
                .map_err(|error| map_io("write partial machine token update journal", error))?;
            return Err(integrity(
                "injected partial machine token update journal write",
            ));
        }
        temp.write_all(&encoded)
            .map_err(|error| map_io("write machine token update journal", error))?;
        temp.sync_all()
            .map_err(|error| map_io("flush machine token update journal temp", error))?;
        #[cfg(test)]
        if fault == ConfigWriteFault::AfterSync {
            return Err(integrity(
                "injected post-flush machine token update journal failure",
            ));
        }
        if verify_config_file(&temp, &store.config_descriptor)? != temp_identity {
            return Err(integrity(
                "machine token update journal temp identity changed before rename",
            ));
        }
        #[cfg(test)]
        if fault == ConfigWriteFault::Rename {
            return Err(integrity(
                "injected machine token update journal rename failure",
            ));
        }
        rename_config_handle(&temp, store.root, OsStr::new(JOURNAL_LEAF), false)
    })();

    match before_publish {
        Ok(RenameResult::Renamed) => {
            temp.sync_all()
                .map_err(|error| map_io("flush published machine token update journal", error))?;
            if verify_config_file(&temp, &store.config_descriptor)? != temp_identity {
                return Err(integrity(
                    "machine token update journal identity changed after published flush",
                ));
            }
            drop(temp);
            let handle = open_required_journal(store, true)?;
            if handle.identity != temp_identity
                || handle.journal.identity != temp_identity
                || handle.encoded_digest != hash_bytes(&encoded)
            {
                return Err(integrity(
                    "machine token update journal changed after publication",
                ));
            }
            Ok(handle)
        }
        Ok(RenameResult::Collision) => {
            let primary =
                integrity("machine token update journal publication lost create-new race");
            remove_temp_or_combine(store.root, &temp_name, temp, temp_identity, Some(primary))?;
            unreachable!("cleanup with a primary error always returns Err")
        }
        Err(primary) => {
            remove_temp_or_combine(store.root, &temp_name, temp, temp_identity, Some(primary))?;
            unreachable!("cleanup with a primary error always returns Err")
        }
    }
}

fn open_required_journal(
    store: &UpdateStore<'_>,
    delete_access: bool,
) -> Result<JournalHandle, MachineStoreError> {
    let opened = read_journal(store, delete_access)?
        .ok_or_else(|| integrity("machine token update journal is absent"))?;
    Ok(JournalHandle {
        file: opened.file,
        identity: opened.identity,
        encoded_digest: hash_bytes(&opened.encoded),
        journal: opened.journal,
    })
}

fn read_journal(
    store: &UpdateStore<'_>,
    delete_access: bool,
) -> Result<Option<OpenedJournal>, MachineStoreError> {
    let Some(file) = open_fixed_file_optional(store.root, OsStr::new(JOURNAL_LEAF), delete_access)?
    else {
        return Ok(None);
    };
    let identity = verify_config_file(&file, &store.config_descriptor)?;
    let encoded = read_held_journal(&file)?;
    let journal = decode_journal(&encoded)?;
    if journal.identity != identity {
        return Err(integrity(
            "machine token update journal self identity does not match its held file",
        ));
    }
    Ok(Some(OpenedJournal {
        file,
        encoded,
        identity,
        journal,
    }))
}

fn read_held_journal(file: &File) -> Result<Zeroizing<Vec<u8>>, MachineStoreError> {
    let mut reader = file
        .try_clone()
        .map_err(|error| map_io("clone held machine token update journal", error))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| map_io("rewind held machine token update journal", error))?;
    let mut encoded = Zeroizing::new(Vec::new());
    Read::by_ref(&mut reader)
        .take((MAX_JOURNAL_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|error| map_io("read held machine token update journal", error))?;
    if encoded.len() > MAX_JOURNAL_BYTES {
        return Err(integrity(
            "machine token update journal exceeds the fixed bound",
        ));
    }
    Ok(encoded)
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn encode_journal(journal: &Journal) -> Result<Zeroizing<Vec<u8>>, MachineStoreError> {
    if journal.records.len() != JOURNAL_RECORD_COUNT {
        return Err(integrity(
            "machine token update journal record count is invalid",
        ));
    }
    let payload_bytes = journal.records.iter().try_fold(0usize, |total, record| {
        let length = record.payload.as_ref().map_or(0, |payload| payload.len());
        total
            .checked_add(length)
            .ok_or_else(|| integrity("machine token update journal payload length overflow"))
    })?;
    let total = JOURNAL_PAYLOAD_OFFSET
        .checked_add(payload_bytes)
        .ok_or_else(|| integrity("machine token update journal total length overflow"))?;
    if total > MAX_JOURNAL_BYTES || total > u32::MAX as usize {
        return Err(integrity(
            "machine token update journal total length exceeds its bound",
        ));
    }
    let mut encoded = Zeroizing::new(vec![0u8; total]);
    encoded[..JOURNAL_MAGIC.len()].copy_from_slice(JOURNAL_MAGIC);
    encoded[JOURNAL_VERSION_OFFSET..JOURNAL_VERSION_OFFSET + 4]
        .copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
    encoded[JOURNAL_TOTAL_LENGTH_OFFSET..JOURNAL_TOTAL_LENGTH_OFFSET + 4]
        .copy_from_slice(&(total as u32).to_le_bytes());
    encoded[JOURNAL_RECORD_COUNT_OFFSET..JOURNAL_RECORD_COUNT_OFFSET + 4]
        .copy_from_slice(&(JOURNAL_RECORD_COUNT as u32).to_le_bytes());
    encoded[JOURNAL_IDENTITY_OFFSET..JOURNAL_IDENTITY_OFFSET + 8]
        .copy_from_slice(&journal.identity.volume.to_le_bytes());
    encoded[JOURNAL_IDENTITY_OFFSET + 8..JOURNAL_IDENTITY_OFFSET + IDENTITY_BYTES]
        .copy_from_slice(&journal.identity.file_id);
    let mut payload_offset = JOURNAL_PAYLOAD_OFFSET;
    for (index, record) in journal.records.iter().enumerate() {
        if record.target.id() as usize != index {
            return Err(integrity(
                "machine token update journal target order is invalid",
            ));
        }
        let at = JOURNAL_FIRST_RECORD_OFFSET + index * JOURNAL_RECORD_BYTES;
        encoded[at + RECORD_TARGET_OFFSET] = record.target.id();
        encoded[at + RECORD_DIRECTIVE_OFFSET] = u8::from(record.is_replace());
        match record.expected {
            ExpectedState::Absent => {}
            ExpectedState::Present { identity, digest } => {
                encoded[at + RECORD_EXPECTED_OFFSET] = 1;
                encoded[at + RECORD_VOLUME_OFFSET..at + RECORD_VOLUME_OFFSET + 8]
                    .copy_from_slice(&identity.volume.to_le_bytes());
                encoded[at + RECORD_FILE_ID_OFFSET..at + RECORD_FILE_ID_OFFSET + 16]
                    .copy_from_slice(&identity.file_id);
                encoded[at + RECORD_OLD_DIGEST_OFFSET..at + RECORD_OLD_DIGEST_OFFSET + 32]
                    .copy_from_slice(&digest);
            }
        }
        if let (Some(payload), Some(digest)) = (&record.payload, record.intended_digest) {
            if (record.target == UpdateTarget::Secret && payload.is_empty())
                || payload.len() > record.target.payload_bound()
            {
                return Err(integrity(
                    "machine token update journal payload length is invalid",
                ));
            }
            let end = payload_offset
                .checked_add(payload.len())
                .ok_or_else(|| integrity("machine token update journal payload overflow"))?;
            encoded[at + RECORD_INTENDED_DIGEST_OFFSET..at + RECORD_INTENDED_DIGEST_OFFSET + 32]
                .copy_from_slice(&digest);
            encoded[at + RECORD_PAYLOAD_OFFSET_OFFSET..at + RECORD_PAYLOAD_OFFSET_OFFSET + 4]
                .copy_from_slice(&(payload_offset as u32).to_le_bytes());
            encoded[at + RECORD_PAYLOAD_LENGTH_OFFSET..at + RECORD_PAYLOAD_LENGTH_OFFSET + 4]
                .copy_from_slice(&(payload.len() as u32).to_le_bytes());
            encoded[payload_offset..end].copy_from_slice(payload);
            payload_offset = end;
        } else if record.payload.is_some() || record.intended_digest.is_some() {
            return Err(integrity(
                "machine token update journal replacement fields disagree",
            ));
        }
    }
    refresh_journal_checksum(&mut encoded);
    Ok(encoded)
}

fn decode_journal(encoded: &[u8]) -> Result<Journal, MachineStoreError> {
    if encoded.len() < JOURNAL_PAYLOAD_OFFSET || encoded.len() > MAX_JOURNAL_BYTES {
        return Err(integrity(
            "machine token update journal length is outside its bound",
        ));
    }
    if &encoded[..JOURNAL_MAGIC.len()] != JOURNAL_MAGIC {
        return Err(integrity("machine token update journal magic is invalid"));
    }
    if read_u32(encoded, JOURNAL_VERSION_OFFSET)? != JOURNAL_VERSION {
        return Err(integrity(
            "machine token update journal version is unsupported",
        ));
    }
    if read_u32(encoded, JOURNAL_TOTAL_LENGTH_OFFSET)? as usize != encoded.len() {
        return Err(integrity(
            "machine token update journal total length is invalid",
        ));
    }
    if read_u32(encoded, JOURNAL_RECORD_COUNT_OFFSET)? as usize != JOURNAL_RECORD_COUNT
        || encoded[52..56] != [0; 4]
    {
        return Err(integrity(
            "machine token update journal record header is invalid",
        ));
    }
    let expected_checksum =
        &encoded[JOURNAL_CHECKSUM_OFFSET..JOURNAL_CHECKSUM_OFFSET + JOURNAL_CHECKSUM_BYTES];
    if expected_checksum != journal_checksum(encoded) {
        return Err(integrity(
            "machine token update journal checksum is invalid",
        ));
    }
    let journal_volume = read_u64(encoded, JOURNAL_IDENTITY_OFFSET)?;
    let mut journal_file_id = [0u8; 16];
    journal_file_id.copy_from_slice(
        &encoded[JOURNAL_IDENTITY_OFFSET + 8..JOURNAL_IDENTITY_OFFSET + IDENTITY_BYTES],
    );
    if journal_volume == 0 || journal_file_id.iter().all(|byte| *byte == 0) {
        return Err(integrity(
            "machine token update journal self identity is malformed",
        ));
    }
    let journal_identity = FileIdentity {
        volume: journal_volume,
        file_id: journal_file_id,
    };

    let mut records = Vec::with_capacity(JOURNAL_RECORD_COUNT);
    let mut payload_cursor = JOURNAL_PAYLOAD_OFFSET;
    for index in 0..JOURNAL_RECORD_COUNT {
        let at = JOURNAL_FIRST_RECORD_OFFSET + index * JOURNAL_RECORD_BYTES;
        let target = UpdateTarget::from_id(encoded[at + RECORD_TARGET_OFFSET])?;
        if target.id() as usize != index || encoded[at + 3] != 0 {
            return Err(integrity(
                "machine token update journal target is duplicate or out of order",
            ));
        }
        let expected = match encoded[at + RECORD_EXPECTED_OFFSET] {
            0 => {
                if encoded[at + RECORD_VOLUME_OFFSET..at + RECORD_INTENDED_DIGEST_OFFSET]
                    .iter()
                    .any(|byte| *byte != 0)
                {
                    return Err(integrity(
                        "machine token update absent state contains identity material",
                    ));
                }
                ExpectedState::Absent
            }
            1 => {
                let volume = read_u64(encoded, at + RECORD_VOLUME_OFFSET)?;
                let mut file_id = [0u8; 16];
                file_id.copy_from_slice(
                    &encoded[at + RECORD_FILE_ID_OFFSET..at + RECORD_FILE_ID_OFFSET + 16],
                );
                if volume == 0 || file_id.iter().all(|byte| *byte == 0) {
                    return Err(integrity(
                        "machine token update journal identity is malformed",
                    ));
                }
                let mut digest = [0u8; 32];
                digest.copy_from_slice(
                    &encoded[at + RECORD_OLD_DIGEST_OFFSET..at + RECORD_OLD_DIGEST_OFFSET + 32],
                );
                ExpectedState::Present {
                    identity: FileIdentity { volume, file_id },
                    digest,
                }
            }
            _ => {
                return Err(integrity(
                    "machine token update expected-state directive is invalid",
                ));
            }
        };
        let directive = encoded[at + RECORD_DIRECTIVE_OFFSET];
        let payload_offset = read_u32(encoded, at + RECORD_PAYLOAD_OFFSET_OFFSET)? as usize;
        let payload_len = read_u32(encoded, at + RECORD_PAYLOAD_LENGTH_OFFSET)? as usize;
        let record = match directive {
            0 => {
                if payload_offset != 0
                    || payload_len != 0
                    || encoded[at + RECORD_INTENDED_DIGEST_OFFSET
                        ..at + RECORD_INTENDED_DIGEST_OFFSET + 32]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(integrity(
                        "machine token update preserve record carries replacement data",
                    ));
                }
                JournalRecord::preserve(target, expected)
            }
            1 => {
                if (target == UpdateTarget::Secret && payload_len == 0)
                    || payload_len > target.payload_bound()
                    || payload_offset != payload_cursor
                {
                    return Err(integrity(
                        "machine token update journal payload offset or length is invalid",
                    ));
                }
                let end = payload_offset
                    .checked_add(payload_len)
                    .ok_or_else(|| integrity("machine token update payload range overflow"))?;
                if end > encoded.len() {
                    return Err(integrity(
                        "machine token update journal payload is truncated",
                    ));
                }
                let payload = &encoded[payload_offset..end];
                let mut intended_digest = [0u8; 32];
                intended_digest.copy_from_slice(
                    &encoded[at + RECORD_INTENDED_DIGEST_OFFSET
                        ..at + RECORD_INTENDED_DIGEST_OFFSET + 32],
                );
                if hash_bytes(payload) != intended_digest {
                    return Err(integrity(
                        "machine token update intended payload digest is invalid",
                    ));
                }
                if target == UpdateTarget::Secret {
                    unprotect_machine_secret(payload)?;
                }
                payload_cursor = end;
                JournalRecord {
                    target,
                    expected,
                    payload: Some(Zeroizing::new(payload.to_vec())),
                    intended_digest: Some(intended_digest),
                }
            }
            _ => {
                return Err(integrity(
                    "machine token update journal directive is invalid",
                ));
            }
        };
        records.push(record);
    }
    if payload_cursor != encoded.len() {
        return Err(integrity(
            "machine token update journal contains overlap or trailing bytes",
        ));
    }
    Ok(Journal {
        identity: journal_identity,
        records,
    })
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, MachineStoreError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| integrity("machine token update u32 offset overflow"))?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| integrity("machine token update u32 is truncated"))?
            .try_into()
            .map_err(|_| integrity("machine token update u32 is malformed"))?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, MachineStoreError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| integrity("machine token update u64 offset overflow"))?;
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or_else(|| integrity("machine token update u64 is truncated"))?
            .try_into()
            .map_err(|_| integrity("machine token update u64 is malformed"))?,
    ))
}

fn journal_checksum(encoded: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(&encoded[..JOURNAL_CHECKSUM_OFFSET]);
    digest.update([0u8; JOURNAL_CHECKSUM_BYTES]);
    digest.update(&encoded[JOURNAL_CHECKSUM_OFFSET + JOURNAL_CHECKSUM_BYTES..]);
    digest.finalize().into()
}

fn refresh_journal_checksum(encoded: &mut [u8]) {
    let checksum = journal_checksum(encoded);
    encoded[JOURNAL_CHECKSUM_OFFSET..JOURNAL_CHECKSUM_OFFSET + JOURNAL_CHECKSUM_BYTES]
        .copy_from_slice(&checksum);
}

#[cfg(test)]
fn refresh_journal_checksum_for_test(encoded: &mut [u8]) {
    refresh_journal_checksum(encoded);
}

#[cfg(test)]
fn sample_journal_bytes_for_test() -> Zeroizing<Vec<u8>> {
    let records = vec![
        JournalRecord::replace(
            UpdateTarget::Secret,
            ExpectedState::Absent,
            protect_machine_secret(b"codec-secret").unwrap().to_vec(),
        ),
        JournalRecord::replace(
            UpdateTarget::Daemon,
            ExpectedState::Absent,
            b"codec-daemon".to_vec(),
        ),
        JournalRecord::replace(
            UpdateTarget::Worker,
            ExpectedState::Absent,
            b"codec-worker".to_vec(),
        ),
    ];
    encode_journal(&Journal {
        identity: FileIdentity {
            volume: 1,
            file_id: [1; 16],
        },
        records,
    })
    .unwrap()
}

#[cfg(test)]
fn write_test_race(
    store: &UpdateStore<'_>,
    target: UpdateTarget,
    bytes: &[u8],
    next_nonce: &mut dyn FnMut() -> Result<[u8; 16], MachineStoreError>,
) -> Result<(), MachineStoreError> {
    write_fixed_file_at_handle(
        store.root,
        target.fixed_file(),
        bytes,
        store.policy,
        ConfigWriteMode::Replace,
        next_nonce,
        ConfigWriteFault::None,
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use sha2::{Digest, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::{MachineTokenUpdate, MachineTokenUpdatePreparation, MachineTokenUpdateValue};

    const TOKEN: &[u8] = b"journal-plaintext-token-sentinel-71829";
    const NEW_DAEMON: &[u8] = b"[agent]\nlisten = 'journal-daemon-new'\n";
    const NEW_WORKER: &[u8] = b"[worker]\nendpoint = 'journal-worker-new'\n";

    struct Fixture {
        _temp: TempDir,
        parent: PathBuf,
        root: PathBuf,
        policy: SecurityPolicy,
    }

    impl Fixture {
        fn committed() -> Self {
            let temp = tempfile::tempdir().expect("create token-update test directory");
            let parent = temp.path().join("parent");
            fs::create_dir(&parent).expect("create token-update parent");
            let root = parent.join(ROOT_NAME);
            let policy = current_user_test_policy().expect("current-user policy").0;
            let parent_handle = open_directory_path_nofollow(&parent).unwrap();
            provision_at_handle(&parent_handle, OsStr::new(ROOT_NAME), &policy).unwrap();
            commit_at_handle(&parent_handle, OsStr::new(ROOT_NAME), &policy).unwrap();
            Self {
                _temp: temp,
                parent,
                root,
                policy,
            }
        }

        fn parent(&self) -> File {
            open_config_parent_path_nofollow(&self.parent).unwrap()
        }

        fn service_guard(&self) -> Result<crate::MachineServiceRuntimeGuard, MachineStoreError> {
            enter_service_runtime_at_for_test(&self.parent(), OsStr::new(ROOT_NAME), &self.policy)
        }

        fn update_guard(&self) -> Result<crate::MachineTokenUpdateGuard, MachineStoreError> {
            begin_token_update_at_for_test(&self.parent(), OsStr::new(ROOT_NAME), &self.policy)
        }

        fn replace(&self, target: UpdateTarget, bytes: &[u8]) {
            let root =
                reopen_validated_committed(&self.parent(), OsStr::new(ROOT_NAME), &self.policy)
                    .unwrap();
            let mut next = nonce_source(0x10);
            write_fixed_file_at_handle(
                &root,
                target.fixed_file(),
                bytes,
                &self.policy,
                ConfigWriteMode::Replace,
                &mut next,
                ConfigWriteFault::None,
            )
            .unwrap();
        }

        fn replace_journal_safely(&self, bytes: &[u8]) {
            let root =
                reopen_validated_committed(&self.parent(), OsStr::new(ROOT_NAME), &self.policy)
                    .unwrap();
            let mut next = nonce_source(0x70);
            write_fixed_file_at_handle(
                &root,
                FixedFile::TokenUpdateJournal,
                bytes,
                &self.policy,
                ConfigWriteMode::Replace,
                &mut next,
                ConfigWriteFault::None,
            )
            .unwrap();
        }

        fn prepare(
            &self,
            update: MachineTokenUpdate<'_>,
            fault: PrepareFault,
        ) -> Result<MachineTokenUpdatePreparation, MachineStoreError> {
            let mut next = nonce_source(0x20);
            prepare_update_at(
                &self.parent(),
                OsStr::new(ROOT_NAME),
                &self.policy,
                update,
                &mut next,
                fault,
            )
        }

        fn apply(&self, fault: ApplyFault) -> Result<(), MachineStoreError> {
            let mut next = nonce_source(0x40);
            apply_update_at(
                &self.parent(),
                OsStr::new(ROOT_NAME),
                &self.policy,
                &mut next,
                fault,
            )
        }

        fn pending(&self) -> Result<bool, MachineStoreError> {
            update_pending_at(&self.parent(), OsStr::new(ROOT_NAME), &self.policy)
        }

        fn path(&self, target: UpdateTarget) -> PathBuf {
            self.root.join(target.leaf())
        }

        fn journal_path(&self) -> PathBuf {
            self.root.join(JOURNAL_LEAF)
        }

        fn bytes(&self, target: UpdateTarget) -> Option<Vec<u8>> {
            fs::read(self.path(target)).ok()
        }
    }

    fn nonce_source(start: u8) -> impl FnMut() -> Result<[u8; 16], MachineStoreError> {
        let mut values = VecDeque::new();
        for value in start..start.saturating_add(32) {
            values.push_back([value; 16]);
        }
        move || {
            values
                .pop_front()
                .ok_or_else(|| integrity("test token-update nonce source exhausted"))
        }
    }

    fn preserve_all() -> MachineTokenUpdate<'static> {
        MachineTokenUpdate {
            cluster_token: MachineTokenUpdateValue::Preserve,
            daemon_config: MachineTokenUpdateValue::Preserve,
            worker_config: MachineTokenUpdateValue::Preserve,
        }
    }

    fn full_update() -> MachineTokenUpdate<'static> {
        MachineTokenUpdate {
            cluster_token: MachineTokenUpdateValue::Replace(TOKEN),
            daemon_config: MachineTokenUpdateValue::Replace(NEW_DAEMON),
            worker_config: MachineTokenUpdateValue::Replace(NEW_WORKER),
        }
    }

    fn assert_intended(fixture: &Fixture) {
        assert_eq!(
            unprotect_machine_secret(&fixture.bytes(UpdateTarget::Secret).unwrap())
                .unwrap()
                .as_ref(),
            TOKEN
        );
        assert_eq!(fixture.bytes(UpdateTarget::Daemon).unwrap(), NEW_DAEMON);
        assert_eq!(fixture.bytes(UpdateTarget::Worker).unwrap(), NEW_WORKER);
        assert!(!fixture.journal_path().exists());
    }

    fn create_junction(link: &std::path::Path, target: &std::path::Path) {
        let output = std::process::Command::new("cmd")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                link.to_str().unwrap(),
                target.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "mklink failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn machine_token_update_codec_rejects_malformed_bounds_and_checksum() {
        let encoded = sample_journal_bytes_for_test();
        decode_journal(&encoded).unwrap();

        let mut malformed = Vec::new();
        for offset in [0usize, JOURNAL_VERSION_OFFSET, JOURNAL_TOTAL_LENGTH_OFFSET] {
            let mut bytes = encoded.to_vec();
            bytes[offset] ^= 1;
            malformed.push(bytes);
        }
        let mut bad_directive = encoded.to_vec();
        bad_directive[JOURNAL_FIRST_RECORD_OFFSET + RECORD_DIRECTIVE_OFFSET] = 0xff;
        refresh_journal_checksum_for_test(&mut bad_directive);
        malformed.push(bad_directive);
        let mut duplicate = encoded.to_vec();
        duplicate[JOURNAL_FIRST_RECORD_OFFSET + JOURNAL_RECORD_BYTES + RECORD_TARGET_OFFSET] = 0;
        refresh_journal_checksum_for_test(&mut duplicate);
        malformed.push(duplicate);
        for field in [RECORD_PAYLOAD_OFFSET_OFFSET, RECORD_PAYLOAD_LENGTH_OFFSET] {
            let mut bytes = encoded.to_vec();
            let at = JOURNAL_FIRST_RECORD_OFFSET + field;
            bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            refresh_journal_checksum_for_test(&mut bytes);
            malformed.push(bytes);
        }
        let mut overlap = encoded.to_vec();
        let second = JOURNAL_FIRST_RECORD_OFFSET + JOURNAL_RECORD_BYTES;
        overlap[second + RECORD_PAYLOAD_OFFSET_OFFSET..second + RECORD_PAYLOAD_OFFSET_OFFSET + 4]
            .copy_from_slice(&(JOURNAL_PAYLOAD_OFFSET as u32).to_le_bytes());
        refresh_journal_checksum_for_test(&mut overlap);
        malformed.push(overlap);
        malformed.push(encoded[..encoded.len() - 1].to_vec());
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        malformed.push(trailing);
        malformed.push(vec![0; MAX_JOURNAL_BYTES + 1]);

        for bytes in malformed {
            assert_eq!(
                decode_journal(&bytes).unwrap_err().classification(),
                MachineStoreErrorClass::IntegrityViolation
            );
        }
    }

    #[test]
    fn machine_token_update_no_change_and_journal_never_expose_token_material() {
        let fixture = Fixture::committed();
        assert_eq!(
            fixture.prepare(preserve_all(), PrepareFault::None).unwrap(),
            MachineTokenUpdatePreparation::NoChange
        );
        assert!(!fixture.journal_path().exists());

        fixture.replace(
            UpdateTarget::Secret,
            &protect_machine_secret(TOKEN).unwrap(),
        );
        fixture.replace(UpdateTarget::Daemon, NEW_DAEMON);
        fixture.replace(UpdateTarget::Worker, NEW_WORKER);
        assert_eq!(
            fixture.prepare(full_update(), PrepareFault::None).unwrap(),
            MachineTokenUpdatePreparation::NoChange
        );

        let fixture = Fixture::committed();
        assert_eq!(
            fixture.prepare(full_update(), PrepareFault::None).unwrap(),
            MachineTokenUpdatePreparation::JournalReady
        );
        let journal = fs::read(fixture.journal_path()).unwrap();
        let digest = Sha256::digest(TOKEN);
        assert!(!journal.windows(TOKEN.len()).any(|window| window == TOKEN));
        assert!(
            !journal
                .windows(digest.len())
                .any(|window| window == digest.as_slice())
        );
        let decoded = decode_journal(&journal).unwrap();
        assert_eq!(decoded.records.len(), 3);
        assert!(
            decoded
                .records
                .iter()
                .all(|record| record.expected.is_absent())
        );
        assert_eq!(
            unprotect_machine_secret(decoded.records[0].payload.as_ref().unwrap())
                .unwrap()
                .as_ref(),
            TOKEN
        );
        assert_eq!(
            decoded.records[1]
                .payload
                .as_ref()
                .map(|payload| payload.as_slice()),
            Some(NEW_DAEMON)
        );
        assert_eq!(
            decoded.records[2]
                .payload
                .as_ref()
                .map(|payload| payload.as_slice()),
            Some(NEW_WORKER)
        );
    }

    #[test]
    fn machine_token_update_empty_config_replacement_resumes_to_present_empty_file() {
        let fixture = Fixture::committed();
        fixture.replace(UpdateTarget::Daemon, b"cluster_token = 'legacy-only'\n");
        assert_eq!(
            fixture
                .prepare(
                    MachineTokenUpdate {
                        cluster_token: MachineTokenUpdateValue::Replace(TOKEN),
                        daemon_config: MachineTokenUpdateValue::Replace(b""),
                        worker_config: MachineTokenUpdateValue::Preserve,
                    },
                    PrepareFault::None,
                )
                .unwrap(),
            MachineTokenUpdatePreparation::JournalReady
        );
        assert!(
            fixture
                .apply(ApplyFault::AfterTarget(UpdateTarget::Secret))
                .is_err()
        );
        assert_eq!(
            fixture.bytes(UpdateTarget::Daemon).unwrap(),
            b"cluster_token = 'legacy-only'\n"
        );
        assert!(fixture.journal_path().exists());

        fixture.apply(ApplyFault::None).unwrap();
        assert_eq!(fixture.bytes(UpdateTarget::Daemon).unwrap(), b"");
        assert!(fixture.path(UpdateTarget::Daemon).is_file());
        assert_eq!(
            unprotect_machine_secret(&fixture.bytes(UpdateTarget::Secret).unwrap())
                .unwrap()
                .as_ref(),
            TOKEN
        );
        assert!(!fixture.path(UpdateTarget::Worker).exists());
        assert!(!fixture.journal_path().exists());
    }

    #[test]
    fn machine_token_update_prepare_records_exact_old_state_and_is_immutable() {
        let fixture = Fixture::committed();
        fixture.replace(UpdateTarget::Daemon, b"daemon-old");
        let old = inspect_path_nofollow_for_test(&fixture.path(UpdateTarget::Daemon)).unwrap();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        let before = fs::read(fixture.journal_path()).unwrap();
        let decoded = decode_journal(&before).unwrap();
        assert_eq!(decoded.records[1].expected.identity(), Some(old.identity));
        assert_eq!(
            decoded.records[1].expected.digest(),
            Some(Sha256::digest(b"daemon-old").into())
        );
        assert!(fixture.prepare(full_update(), PrepareFault::None).is_err());
        assert_eq!(fs::read(fixture.journal_path()).unwrap(), before);
    }

    #[test]
    fn machine_token_update_unsafe_or_corrupt_journal_fails_closed() {
        let fixture = Fixture::committed();
        let sentinel = fixture.parent.join("outside-journal");
        fs::write(&sentinel, b"outside").unwrap();
        fs::hard_link(&sentinel, fixture.journal_path()).unwrap();
        assert!(fixture.pending().is_err());
        assert!(fixture.prepare(full_update(), PrepareFault::None).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside");

        let fixture = Fixture::committed();
        let external = fixture.parent.join("journal-junction-target");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), b"outside-reparse").unwrap();
        create_junction(&fixture.journal_path(), &external);
        assert!(fixture.pending().is_err());
        assert!(fixture.prepare(full_update(), PrepareFault::None).is_err());
        assert_eq!(
            fs::read(external.join("sentinel")).unwrap(),
            b"outside-reparse"
        );

        let fixture = Fixture::committed();
        fs::write(fixture.journal_path(), sample_journal_bytes_for_test()).unwrap();
        assert!(fixture.pending().is_err());
        assert!(fixture.prepare(full_update(), PrepareFault::None).is_err());

        let fixture = Fixture::committed();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        let mut corrupt = fs::read(fixture.journal_path()).unwrap();
        corrupt[0] ^= 1;
        fs::write(fixture.journal_path(), corrupt).unwrap();
        assert!(fixture.pending().is_err());
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert!(fixture.journal_path().exists());
    }

    #[test]
    fn machine_token_update_neither_preflight_writes_nothing_and_retains_journal() {
        let fixture = Fixture::committed();
        fixture.replace(UpdateTarget::Daemon, b"daemon-old");
        fixture.replace(UpdateTarget::Worker, b"worker-old");
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        fixture.replace(UpdateTarget::Daemon, b"daemon-neither");
        let secret_before = fixture.bytes(UpdateTarget::Secret);
        let worker_before = fixture.bytes(UpdateTarget::Worker);

        assert!(fixture.apply(ApplyFault::None).is_err());
        assert_eq!(fixture.bytes(UpdateTarget::Secret), secret_before);
        assert_eq!(fixture.bytes(UpdateTarget::Worker), worker_before);
        assert_eq!(
            fixture.bytes(UpdateTarget::Daemon).unwrap(),
            b"daemon-neither"
        );
        assert!(fixture.journal_path().exists());
    }

    #[test]
    fn machine_token_update_unsafe_intended_bytes_are_not_accepted() {
        let fixture = Fixture::committed();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        let sentinel = fixture.parent.join("intended-hardlink");
        fs::write(&sentinel, NEW_DAEMON).unwrap();
        fs::hard_link(&sentinel, fixture.path(UpdateTarget::Daemon)).unwrap();
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), NEW_DAEMON);
        assert!(!fixture.path(UpdateTarget::Secret).exists());
        assert!(!fixture.path(UpdateTarget::Worker).exists());
        assert!(fixture.journal_path().exists());

        let fixture = Fixture::committed();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        let external = fixture.parent.join("intended-junction-target");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), b"outside-reparse").unwrap();
        create_junction(&fixture.path(UpdateTarget::Daemon), &external);
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert!(!fixture.path(UpdateTarget::Secret).exists());
        assert_eq!(
            fs::read(external.join("sentinel")).unwrap(),
            b"outside-reparse"
        );

        let fixture = Fixture::committed();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        fs::write(fixture.path(UpdateTarget::Daemon), NEW_DAEMON).unwrap();
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert!(!fixture.path(UpdateTarget::Secret).exists());
        assert_eq!(fixture.bytes(UpdateTarget::Daemon).unwrap(), NEW_DAEMON);
    }

    #[test]
    fn machine_token_update_every_committed_prefix_resumes_forward() {
        for fault in [PrepareFault::AfterJournal, PrepareFault::None] {
            let fixture = Fixture::committed();
            let result = fixture.prepare(full_update(), fault);
            if result.is_err() {
                assert!(fixture.journal_path().exists());
            }
            fixture.apply(ApplyFault::None).unwrap();
            assert_intended(&fixture);
        }
        for fault in [
            ApplyFault::AfterTarget(UpdateTarget::Secret),
            ApplyFault::AfterTarget(UpdateTarget::Daemon),
            ApplyFault::AfterTarget(UpdateTarget::Worker),
            ApplyFault::BeforeJournalDelete,
        ] {
            let fixture = Fixture::committed();
            fixture.prepare(full_update(), PrepareFault::None).unwrap();
            assert!(fixture.apply(fault).is_err());
            assert!(fixture.journal_path().exists());
            fixture.apply(ApplyFault::None).unwrap();
            assert_intended(&fixture);
        }
    }

    #[test]
    fn machine_token_update_atomic_write_faults_keep_old_then_resume() {
        for fault in [
            ConfigWriteFault::PartialWrite,
            ConfigWriteFault::AfterSync,
            ConfigWriteFault::Rename,
        ] {
            let fixture = Fixture::committed();
            fixture.replace(UpdateTarget::Daemon, b"daemon-old");
            fixture.prepare(full_update(), PrepareFault::None).unwrap();
            assert!(
                fixture
                    .apply(ApplyFault::TargetWrite(UpdateTarget::Daemon, fault))
                    .is_err()
            );
            assert_eq!(fixture.bytes(UpdateTarget::Daemon).unwrap(), b"daemon-old");
            assert!(fixture.journal_path().exists());
            fixture.apply(ApplyFault::None).unwrap();
            assert_intended(&fixture);
        }

        for fault in [
            ConfigWriteFault::PartialWrite,
            ConfigWriteFault::AfterSync,
            ConfigWriteFault::Rename,
        ] {
            let fixture = Fixture::committed();
            assert!(
                fixture
                    .prepare(full_update(), PrepareFault::JournalWrite(fault))
                    .is_err()
            );
            assert!(!fixture.journal_path().exists());
            assert!(fs::read_dir(&fixture.root).unwrap().all(|entry| {
                !entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".tmp")
            }));
        }
    }

    #[test]
    fn machine_token_update_immediate_revalidation_stops_later_writes() {
        let fixture = Fixture::committed();
        fixture.replace(UpdateTarget::Daemon, b"daemon-old");
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        assert!(
            fixture
                .apply(ApplyFault::ReplaceBeforeTarget(
                    UpdateTarget::Daemon,
                    b"daemon-raced".to_vec(),
                ))
                .is_err()
        );
        assert_eq!(
            fixture.bytes(UpdateTarget::Daemon).unwrap(),
            b"daemon-raced"
        );
        assert!(!fixture.path(UpdateTarget::Worker).exists());
        assert!(fixture.journal_path().exists());
    }

    #[test]
    fn machine_token_update_identity_and_preserve_semantics_are_exact() {
        let fixture = Fixture::committed();
        fixture.replace(UpdateTarget::Daemon, b"same-old-bytes");
        fixture
            .prepare(
                MachineTokenUpdate {
                    cluster_token: MachineTokenUpdateValue::Replace(TOKEN),
                    daemon_config: MachineTokenUpdateValue::Replace(NEW_DAEMON),
                    worker_config: MachineTokenUpdateValue::Preserve,
                },
                PrepareFault::None,
            )
            .unwrap();
        fixture.replace(UpdateTarget::Daemon, b"same-old-bytes");
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert!(!fixture.path(UpdateTarget::Secret).exists());

        let fixture = Fixture::committed();
        fixture.replace(UpdateTarget::Worker, b"preserved");
        fixture
            .prepare(
                MachineTokenUpdate {
                    cluster_token: MachineTokenUpdateValue::Replace(TOKEN),
                    daemon_config: MachineTokenUpdateValue::Replace(NEW_DAEMON),
                    worker_config: MachineTokenUpdateValue::Preserve,
                },
                PrepareFault::None,
            )
            .unwrap();
        fixture.replace(UpdateTarget::Worker, b"changed-preserve-neither");
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert!(!fixture.path(UpdateTarget::Secret).exists());
        assert!(!fixture.path(UpdateTarget::Daemon).exists());
        assert_eq!(
            fixture.bytes(UpdateTarget::Worker).unwrap(),
            b"changed-preserve-neither"
        );
    }

    #[test]
    fn machine_token_update_all_intended_deletes_only_and_delete_failure_resumes() {
        let fixture = Fixture::committed();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        assert!(fixture.apply(ApplyFault::BeforeJournalDelete).is_err());
        let identities = [
            UpdateTarget::Secret,
            UpdateTarget::Daemon,
            UpdateTarget::Worker,
        ]
        .map(|target| {
            inspect_path_nofollow_for_test(&fixture.path(target))
                .unwrap()
                .identity
        });
        for fault in [ApplyFault::JournalDelete, ApplyFault::JournalAbsenceProof] {
            assert!(fixture.apply(fault).is_err());
            assert!(fixture.journal_path().exists());
        }
        fixture.apply(ApplyFault::None).unwrap();
        let after = [
            UpdateTarget::Secret,
            UpdateTarget::Daemon,
            UpdateTarget::Worker,
        ]
        .map(|target| {
            inspect_path_nofollow_for_test(&fixture.path(target))
                .unwrap()
                .identity
        });
        assert_eq!(identities, after);
        assert_intended(&fixture);
        assert!(fixture.apply(ApplyFault::None).is_err());
    }

    #[test]
    fn machine_token_update_root_and_journal_replacement_fail_closed() {
        let fixture = Fixture::committed();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        let journal = fs::read(fixture.journal_path()).unwrap();
        fixture.replace_journal_safely(&journal);
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert!(!fixture.path(UpdateTarget::Secret).exists());

        let fixture = Fixture::committed();
        fixture.prepare(full_update(), PrepareFault::None).unwrap();
        let original = fixture.parent.join("original-root");
        fs::rename(&fixture.root, &original).unwrap();
        fs::create_dir(&fixture.root).unwrap();
        fs::write(fixture.root.join("external-sentinel"), b"outside").unwrap();
        assert!(fixture.apply(ApplyFault::None).is_err());
        assert_eq!(
            fs::read(fixture.root.join("external-sentinel")).unwrap(),
            b"outside"
        );
    }

    #[test]
    fn machine_token_update_concurrent_prepare_has_one_journal_winner() {
        let fixture = Arc::new(Fixture::committed());
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for daemon in [b"winner-a".as_slice(), b"winner-b".as_slice()] {
            let fixture = Arc::clone(&fixture);
            let barrier = Arc::clone(&barrier);
            threads.push(thread::spawn(move || {
                barrier.wait();
                fixture.prepare(
                    MachineTokenUpdate {
                        cluster_token: MachineTokenUpdateValue::Replace(TOKEN),
                        daemon_config: MachineTokenUpdateValue::Replace(daemon),
                        worker_config: MachineTokenUpdateValue::Preserve,
                    },
                    PrepareFault::None,
                )
            }));
        }
        barrier.wait();
        let results: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        assert!(fixture.pending().unwrap());
        fixture.apply(ApplyFault::None).unwrap();
        assert!(!fixture.journal_path().exists());
        assert!(matches!(
            fixture.bytes(UpdateTarget::Daemon).as_deref(),
            Some(b"winner-a") | Some(b"winner-b")
        ));
    }

    #[test]
    fn machine_token_lease_shared_and_exclusive_guards_conflict_and_release() {
        let fixture = Fixture::committed();

        let service_a = fixture.service_guard().unwrap();
        let service_b = fixture.service_guard().unwrap();
        for debug in [format!("{service_a:?}"), format!("{service_b:?}")] {
            assert!(debug.contains("REDACTED"), "{debug}");
            assert!(
                !debug.contains(&fixture.root.display().to_string()),
                "{debug}"
            );
        }
        assert!(fixture.update_guard().is_err());

        drop(service_a);
        assert!(fixture.update_guard().is_err());
        drop(service_b);

        let update = fixture.update_guard().unwrap();
        let debug = format!("{update:?}");
        assert!(debug.contains("REDACTED"), "{debug}");
        assert!(
            !debug.contains(&fixture.root.display().to_string()),
            "{debug}"
        );
        assert!(fixture.service_guard().is_err());
        assert!(fixture.update_guard().is_err());

        drop(update);
        fixture.service_guard().unwrap();
    }

    #[test]
    fn machine_token_lease_stress_never_allows_service_and_update_together() {
        let fixture = Arc::new(Fixture::committed());

        for _ in 0..32 {
            let start = Arc::new(Barrier::new(3));
            let release = Arc::new(Barrier::new(3));

            let service_fixture = Arc::clone(&fixture);
            let service_start = Arc::clone(&start);
            let service_release = Arc::clone(&release);
            let service = thread::spawn(move || {
                service_start.wait();
                let guard = service_fixture.service_guard();
                let acquired = guard.is_ok();
                service_release.wait();
                acquired
            });

            let update_fixture = Arc::clone(&fixture);
            let update_start = Arc::clone(&start);
            let update_release = Arc::clone(&release);
            let update = thread::spawn(move || {
                update_start.wait();
                let guard = update_fixture.update_guard();
                let acquired = guard.is_ok();
                update_release.wait();
                acquired
            });

            start.wait();
            release.wait();
            let service_acquired = service.join().unwrap();
            let update_acquired = update.join().unwrap();
            assert_ne!(
                service_acquired, update_acquired,
                "service and update leases must have exactly one winner"
            );
        }
    }

    #[test]
    fn machine_token_lease_service_rejects_pending_and_unsafe_journals() {
        let valid = Fixture::committed();
        let mut update = valid.update_guard().unwrap();
        assert_eq!(
            crate::prepare_machine_cluster_token_update(&mut update, full_update()).unwrap(),
            MachineTokenUpdatePreparation::JournalReady
        );
        drop(update);
        assert!(valid.service_guard().is_err());

        let corrupt = Fixture::committed();
        let mut update = corrupt.update_guard().unwrap();
        crate::prepare_machine_cluster_token_update(&mut update, full_update()).unwrap();
        drop(update);
        fs::write(corrupt.journal_path(), b"corrupt-journal").unwrap();
        assert!(corrupt.service_guard().is_err());

        let wrong_dacl = Fixture::committed();
        fs::write(wrong_dacl.journal_path(), sample_journal_bytes_for_test()).unwrap();
        assert!(wrong_dacl.service_guard().is_err());

        let hardlink = Fixture::committed();
        let hardlink_sentinel = hardlink.parent.join("hardlink-sentinel");
        fs::write(&hardlink_sentinel, b"hardlink-sentinel").unwrap();
        fs::hard_link(&hardlink_sentinel, hardlink.journal_path()).unwrap();
        assert!(hardlink.service_guard().is_err());
        assert_eq!(fs::read(&hardlink_sentinel).unwrap(), b"hardlink-sentinel");

        let reparse = Fixture::committed();
        let reparse_sentinel = reparse.parent.join("reparse-sentinel");
        fs::create_dir(&reparse_sentinel).unwrap();
        fs::write(reparse_sentinel.join("sentinel"), b"outside").unwrap();
        create_junction(&reparse.journal_path(), &reparse_sentinel);
        assert!(reparse.service_guard().is_err());
        assert_eq!(
            fs::read(reparse_sentinel.join("sentinel")).unwrap(),
            b"outside"
        );
    }

    #[test]
    fn machine_token_lease_update_fault_resume_releases_to_service() {
        let fixture = Fixture::committed();
        let mut update = fixture.update_guard().unwrap();
        assert_eq!(
            crate::prepare_machine_cluster_token_update(&mut update, full_update()).unwrap(),
            MachineTokenUpdatePreparation::JournalReady
        );
        assert!(fixture.service_guard().is_err());

        let mut next = nonce_source(0xa0);
        assert!(
            apply_update_guard_with_fault_for_test(
                &mut update,
                &mut next,
                ApplyFault::AfterTarget(UpdateTarget::Secret),
            )
            .is_err()
        );
        assert!(crate::machine_cluster_token_update_pending(&mut update).unwrap());
        crate::apply_or_resume_machine_cluster_token_update(&mut update).unwrap();
        assert!(!crate::machine_cluster_token_update_pending(&mut update).unwrap());

        drop(update);
        fixture.service_guard().unwrap();
        assert_intended(&fixture);
    }

    #[test]
    fn machine_token_lease_daemon_sid_is_exact_read_only_and_not_in_children() {
        const DAEMON_SID: &str = "S-1-5-80-1935860780-3819908813-1334579252-621723184-2190217863";
        let policy = SecurityPolicy::production();
        let read_only_ace = format!("(A;;0x1200a9;;;{DAEMON_SID})");
        let inherited_read_only_ace = format!("(A;OICI;0x1200a9;;;{DAEMON_SID})");

        assert!(policy.root_sddl().contains(&read_only_ace));
        assert!(!policy.root_sddl().contains(&inherited_read_only_ace));
        assert!(policy.config_sddl().contains(&read_only_ace));
        assert!(!policy.config_sddl().contains(&inherited_read_only_ace));
        assert!(!policy.child_sddl().contains(DAEMON_SID));

        for broad_principal in [";;;BU)", ";;;AU)", ";;;WD)"] {
            assert!(!policy.root_sddl().contains(broad_principal));
            assert!(!policy.config_sddl().contains(broad_principal));
        }
    }
}
