//! Crash-resumable removal of records after an already verified PF reference release.
//!
//! Retirement removes only protected local records. It never changes PF, reconstructs a PF
//! handle, or treats a token or ticket found on disk as authority to modify the kernel.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::snapshot;
use crate::store::{RecordIdentity, RecordKind, StoreError, StoredRecord, SystemRecordStore};

const DOMAIN: &[u8] = b"tunlatch-pf-retirement-v1\0";
const FINGERPRINT_DOMAIN: &[u8] = b"tunlatch-pf-retired-record-v1\0";
const KINDS: [RecordKind; 6] = [
    RecordKind::PfAnchorStage,
    RecordKind::PfHook,
    RecordKind::PfHookRemoval,
    RecordKind::PfAnchorClear,
    RecordKind::PfReferenceRelease,
    RecordKind::PfReference,
];

/// A failure checking or removing protected records. No PF operation is performed.
#[derive(Debug, thiserror::Error)]
pub enum RetirementError {
    /// Protected storage was unavailable, changed, or had an unresolved pending write.
    #[error("PF retirement store error: {0}")]
    Store(#[from] StoreError),
    /// The completion marker or remaining records failed validation.
    #[error("PF retirement rejected: {0}")]
    Invalid(&'static str),
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    #[serde(default)]
    scope: Option<Scope>,
    fingerprints: [Option<[u8; 32]>; KINDS.len()],
}

#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scope {
    FullSession,
    UnstagedReference,
}

fn included(scope: Scope, kind: RecordKind) -> bool {
    scope == Scope::FullSession
        || matches!(
            kind,
            RecordKind::PfReference | RecordKind::PfReferenceRelease
        )
}

pub(super) struct Progress {
    pub(super) boot_session: String,
    pub(super) remaining: usize,
    session: [u8; 16],
    scope: Scope,
    marker: StoredRecord,
    records: Vec<(RecordKind, StoredRecord)>,
}

trait Records {
    fn pending(&self, kind: RecordKind) -> Result<(), StoreError>;
    fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError>;
    fn replace(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError>;
    fn remove(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError>;
    fn sync(&self) -> Result<(), StoreError>;
}

impl Records for SystemRecordStore {
    fn pending(&self, kind: RecordKind) -> Result<(), StoreError> {
        self.require_no_pending(kind)
    }
    fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
        SystemRecordStore::read(self, kind)
    }
    fn replace(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError> {
        SystemRecordStore::replace(self, kind, record)
    }
    fn remove(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError> {
        self.remove_checked(kind, record)
    }
    fn sync(&self) -> Result<(), StoreError> {
        self.sync_records_directory()
    }
}

fn fingerprint(version: u8, kind: RecordKind, record: &StoredRecord) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(FINGERPRINT_DOMAIN);
    if version >= 2 {
        hash.update((kind.file_name().len() as u64).to_be_bytes());
    }
    hash.update(kind.file_name().as_bytes());
    hash.update(record.identity().as_bytes());
    hash.update((record.payload().len() as u64).to_be_bytes());
    hash.update(record.payload());
    hash.finalize().into()
}

fn marker_record(marker: &Marker) -> Result<StoredRecord, RetirementError> {
    let bytes = serde_json::to_vec(marker)
        .map_err(|_| RetirementError::Invalid("cannot encode completion marker"))?;
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(&bytes);
    Ok(StoredRecord::new(
        RecordIdentity::new(hash.finalize().into())?,
        bytes,
    )?)
}

fn decode_marker(record: &StoredRecord) -> Result<Marker, RetirementError> {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(record.payload());
    let digest: [u8; 32] = hash.finalize().into();
    if record.identity().as_bytes() != &digest {
        return Err(RetirementError::Invalid(
            "completion marker identity mismatch",
        ));
    }
    let marker: Marker = serde_json::from_slice(record.payload())
        .map_err(|_| RetirementError::Invalid("invalid completion marker"))?;
    let scope = match (marker.version, marker.scope) {
        (1, None) => Scope::FullSession,
        (2, Some(scope)) => scope,
        _ => {
            return Err(RetirementError::Invalid(
                "invalid completion marker version or scope",
            ));
        }
    };
    if marker.session == [0; 16]
        || KINDS.into_iter().enumerate().any(|(index, kind)| {
            match (included(scope, kind), marker.fingerprints[index]) {
                (true, Some(digest)) => digest == [0; 32],
                (false, None) => false,
                _ => true,
            }
        })
        || snapshot::parse_boot_session(&marker.boot_session)
            .ok()
            .as_deref()
            != Some(marker.boot_session.as_str())
    {
        return Err(RetirementError::Invalid(
            "invalid completion marker identity",
        ));
    }
    Ok(marker)
}

// Used only after the same process established that no anchor operation was submitted and
// independently confirmed the release of its otherwise-unused reference.
pub(super) fn begin_unstaged_reference(
    store: &mut SystemRecordStore,
    boot_session: &str,
    session: [u8; 16],
) -> Result<(), RetirementError> {
    begin_with(store, boot_session, session, Scope::UnstagedReference)
}

fn begin_with(
    store: &mut impl Records,
    boot_session: &str,
    session: [u8; 16],
    scope: Scope,
) -> Result<(), RetirementError> {
    if session == [0; 16]
        || snapshot::parse_boot_session(boot_session).ok().as_deref() != Some(boot_session)
    {
        return Err(RetirementError::Invalid("invalid session identity"));
    }
    store.pending(RecordKind::PfRetirement)?;
    if store.read(RecordKind::PfRetirement)?.is_some() {
        return Err(RetirementError::Invalid("completion marker already exists"));
    }
    let mut fingerprints = [None; KINDS.len()];
    for (index, kind) in KINDS.into_iter().enumerate() {
        store.pending(kind)?;
        let record = store.read(kind)?;
        if included(scope, kind) {
            let record = record.ok_or(RetirementError::Invalid("completed record missing"))?;
            fingerprints[index] = Some(fingerprint(2, kind, &record));
        } else if record.is_some() {
            return Err(RetirementError::Invalid("unexpected PF operation record"));
        }
    }
    let marker = marker_record(&Marker {
        version: 2,
        boot_session: boot_session.to_owned(),
        session,
        scope: Some(scope),
        fingerprints,
    })?;
    store.replace(RecordKind::PfRetirement, &marker)?;
    Ok(())
}

fn progress(store: &impl Records) -> Result<Option<Progress>, RetirementError> {
    store.pending(RecordKind::PfRetirement)?;
    let Some(marker_record) = store.read(RecordKind::PfRetirement)? else {
        return Ok(None);
    };
    let marker = decode_marker(&marker_record)?;
    let mut records = Vec::with_capacity(KINDS.len());
    for (index, kind) in KINDS.into_iter().enumerate() {
        store.pending(kind)?;
        if let Some(record) = store.read(kind)? {
            if marker.fingerprints[index] != Some(fingerprint(marker.version, kind, &record)) {
                return Err(RetirementError::Invalid("completed record changed"));
            }
            records.push((kind, record));
        }
    }
    store.pending(RecordKind::PfRetirement)?;
    if store.read(RecordKind::PfRetirement)?.as_ref() != Some(&marker_record) {
        return Err(RetirementError::Invalid("completion marker changed"));
    }
    Ok(Some(Progress {
        boot_session: marker.boot_session,
        remaining: records.len(),
        session: marker.session,
        scope: match marker.scope {
            Some(scope) => scope,
            None => Scope::FullSession,
        },
        marker: marker_record,
        records,
    }))
}

pub(super) fn inspect(store: &SystemRecordStore) -> Result<Option<Progress>, RetirementError> {
    progress(store)
}

fn finish_with(store: &mut impl Records) -> Result<bool, RetirementError> {
    let Some(progress) = progress(store)? else {
        return Ok(false);
    };
    for (kind, record) in progress.records {
        store.remove(kind, &record)?;
    }
    let current =
        self::progress(store)?.ok_or(RetirementError::Invalid("completion marker disappeared"))?;
    if current.remaining != 0 || current.marker != progress.marker {
        return Err(RetirementError::Invalid(
            "retirement changed before completion",
        ));
    }
    store.remove(RecordKind::PfRetirement, &progress.marker)?;
    Ok(true)
}

pub(super) fn finish_locked(store: &mut SystemRecordStore) -> Result<bool, RetirementError> {
    finish_with(store)
}

fn complete_full_with(
    store: &mut impl Records,
    boot: &str,
    session: [u8; 16],
) -> Result<(), RetirementError> {
    match progress(store)? {
        None if all_absent(store)? => {
            // The marker's unlink may have succeeded even when its directory sync failed. The
            // live caller already verified PF release, so re-sync an entirely empty set instead
            // of issuing the release again or fabricating a new completion marker.
            store.sync()?;
            if !all_absent(store)? {
                return Err(RetirementError::Invalid(
                    "retired records changed during sync",
                ));
            }
            return Ok(());
        }
        None => begin_with(store, boot, session, Scope::FullSession)?,
        Some(current)
            if current.boot_session == boot
                && current.session == session
                && current.scope == Scope::FullSession => {}
        Some(_) => {
            return Err(RetirementError::Invalid(
                "completion marker belongs to another session",
            ));
        }
    }
    if !finish_with(store)? {
        return Err(RetirementError::Invalid("completion marker disappeared"));
    }
    Ok(())
}

fn all_absent(store: &impl Records) -> Result<bool, RetirementError> {
    for kind in KINDS.into_iter().chain([RecordKind::PfRetirement]) {
        store.pending(kind)?;
        if store.read(kind)?.is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

// Only the live session that has just verified reference release can create a marker. A retry
// after a partial retirement must match that same session and never reissue a PF operation.
pub(super) fn complete_full(
    store: &mut SystemRecordStore,
    boot: &str,
    session: [u8; 16],
) -> Result<(), RetirementError> {
    complete_full_with(store, boot, session)
}

/// Finish an interrupted record retirement using the existing root-protected completion marker.
///
/// Requires root and the provisioned system store. Only matching local records are removed;
/// the operation does not change PF or authorize a kernel cleanup. Returns `false` if no marker
/// exists. Incomplete old sessions without a marker are left untouched.
pub fn finish_completed() -> Result<bool, RetirementError> {
    let mut store = SystemRecordStore::open()?;
    finish_with(&mut store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::UserRecordStore;
    use std::os::unix::fs::PermissionsExt;

    const BOOT: &str = "12345678-1234-1234-1234-123456789abc";

    impl Records for UserRecordStore {
        fn pending(&self, kind: RecordKind) -> Result<(), StoreError> {
            self.require_no_pending(kind)
        }
        fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
            UserRecordStore::read(self, kind)
        }
        fn replace(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError> {
            UserRecordStore::replace(self, kind, record)
        }
        fn remove(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError> {
            self.remove_checked(kind, record)
        }
        fn sync(&self) -> Result<(), StoreError> {
            self.sync_records_directory()
        }
    }

    #[derive(Default)]
    struct Memory {
        records: Vec<(RecordKind, StoredRecord)>,
        pending: Vec<RecordKind>,
        fail: Option<(RecordKind, bool)>,
        fail_marker: Option<bool>,
    }

    impl Memory {
        fn completed() -> Result<Self, StoreError> {
            let mut store = Self::default();
            for (index, kind) in KINDS.into_iter().enumerate() {
                let identity = RecordIdentity::new([(index + 1) as u8; 32])?;
                store
                    .records
                    .push((kind, StoredRecord::new(identity, vec![index as u8])?));
            }
            Ok(store)
        }

        fn index(&self, kind: RecordKind) -> Option<usize> {
            self.records
                .iter()
                .position(|(candidate, _)| *candidate == kind)
        }
    }

    impl Records for Memory {
        fn pending(&self, kind: RecordKind) -> Result<(), StoreError> {
            if self.pending.contains(&kind) {
                Err(StoreError::PendingRecord(kind))
            } else {
                Ok(())
            }
        }
        fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
            Ok(self.index(kind).map(|index| self.records[index].1.clone()))
        }
        fn replace(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError> {
            if kind == RecordKind::PfRetirement && self.fail_marker == Some(false) {
                return Err(StoreError::Refused("injected pre-marker error"));
            }
            if let Some(index) = self.index(kind) {
                self.records[index].1 = record.clone();
            } else {
                self.records.push((kind, record.clone()));
            }
            if kind == RecordKind::PfRetirement && self.fail_marker == Some(true) {
                return Err(StoreError::Refused("injected post-marker error"));
            }
            Ok(())
        }
        fn remove(&mut self, kind: RecordKind, expected: &StoredRecord) -> Result<(), StoreError> {
            if self.fail == Some((kind, false)) {
                return Err(StoreError::Refused("injected pre-removal error"));
            }
            let index = self
                .index(kind)
                .ok_or(StoreError::Refused("record missing"))?;
            if self.records[index].1 != *expected {
                return Err(StoreError::Refused("record changed"));
            }
            self.records.remove(index);
            if self.fail == Some((kind, true)) {
                return Err(StoreError::Refused("injected post-removal error"));
            }
            Ok(())
        }
        fn sync(&self) -> Result<(), StoreError> {
            Ok(())
        }
    }

    #[test]
    fn interrupted_retirement_can_be_inspected_and_resumed_at_every_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        for kind in KINDS.into_iter().chain([RecordKind::PfRetirement]) {
            for after in [false, true] {
                let mut store = Memory::completed()?;
                begin_with(&mut store, BOOT, [1; 16], Scope::FullSession)?;
                store.fail = Some((kind, after));
                assert!(finish_with(&mut store).is_err());
                store.fail = None;
                if kind == RecordKind::PfRetirement && after {
                    assert!(progress(&store)?.is_none());
                    assert!(!finish_with(&mut store)?);
                } else {
                    let remaining = progress(&store)?.ok_or("marker missing")?.remaining;
                    assert_eq!(remaining, store.records.len() - 1);
                    assert!(finish_with(&mut store)?);
                }
                assert!(store.records.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn retirement_resumes_after_reopening_the_protected_store()
    -> Result<(), Box<dyn std::error::Error>> {
        for removed_count in 0..=KINDS.len() {
            let directory = tempfile::Builder::new()
                .prefix("tunlatch-retirement-")
                .tempdir_in("/private/tmp")?;
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
            let path = directory.path().canonicalize()?;
            {
                let mut store = UserRecordStore::open(&path)?;
                for (index, kind) in KINDS.into_iter().enumerate() {
                    let record = StoredRecord::new(
                        RecordIdentity::new([(index + 1) as u8; 32])?,
                        vec![index as u8],
                    )?;
                    store.replace(kind, &record)?;
                }
                begin_with(&mut store, BOOT, [1; 16], Scope::FullSession)?;
                let progress = progress(&store)?.ok_or("missing marker")?;
                for (kind, record) in progress.records.into_iter().take(removed_count) {
                    store.remove_checked(kind, &record)?;
                }
            }
            {
                let mut reopened = UserRecordStore::open(&path)?;
                let observed = progress(&reopened)?.ok_or("missing marker after reopen")?;
                assert_eq!(observed.remaining, KINDS.len() - removed_count);
                assert!(finish_with(&mut reopened)?);
                assert!(progress(&reopened)?.is_none());
                for kind in KINDS {
                    assert!(reopened.read(kind)?.is_none());
                }
            }
        }
        Ok(())
    }

    #[test]
    fn missing_or_pending_completed_record_never_starts_retirement() -> Result<(), StoreError> {
        for missing in KINDS {
            let mut store = Memory::completed()?;
            let index = store
                .index(missing)
                .ok_or(StoreError::Refused("test record missing"))?;
            store.records.remove(index);
            assert!(begin_with(&mut store, BOOT, [1; 16], Scope::FullSession).is_err());
            assert!(store.index(RecordKind::PfRetirement).is_none());
        }
        for pending in KINDS.into_iter().chain([RecordKind::PfRetirement]) {
            let mut store = Memory::completed()?;
            store.pending.push(pending);
            assert!(begin_with(&mut store, BOOT, [1; 16], Scope::FullSession).is_err());
            assert_eq!(store.records.len(), KINDS.len());
        }
        Ok(())
    }

    #[test]
    fn marker_write_failure_never_removes_source_records() -> Result<(), Box<dyn std::error::Error>>
    {
        for after in [false, true] {
            let mut store = Memory::completed()?;
            let original = store.records.clone();
            store.fail_marker = Some(after);
            assert!(begin_with(&mut store, BOOT, [1; 16], Scope::FullSession).is_err());
            for (kind, expected) in original {
                assert_eq!(store.read(kind)?, Some(expected));
            }
            store.fail_marker = None;
            if after {
                assert_eq!(
                    progress(&store)?.ok_or("missing marker")?.remaining,
                    KINDS.len()
                );
                assert!(finish_with(&mut store)?);
                assert!(store.records.is_empty());
            } else {
                assert!(progress(&store)?.is_none());
                assert_eq!(store.records.len(), KINDS.len());
            }
        }
        Ok(())
    }

    #[test]
    fn live_verified_release_can_resume_retirement_without_another_pf_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        for kind in KINDS.into_iter().chain([RecordKind::PfRetirement]) {
            for after in [false, true] {
                let mut store = Memory::completed()?;
                store.fail = Some((kind, after));
                assert!(complete_full_with(&mut store, BOOT, [1; 16]).is_err());
                store.fail = None;
                if progress(&store)?.is_some() {
                    let before = store.records.clone();
                    assert!(complete_full_with(&mut store, BOOT, [2; 16]).is_err());
                    assert_eq!(store.records, before);
                }
                complete_full_with(&mut store, BOOT, [1; 16])?;
                assert!(store.records.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn empty_retirement_still_refuses_unresolved_pending_files() {
        let mut store = Memory::default();
        store.pending.push(RecordKind::PfReference);
        assert!(complete_full_with(&mut store, BOOT, [1; 16]).is_err());
    }

    #[test]
    fn changed_records_or_marker_are_never_retired() -> Result<(), Box<dyn std::error::Error>> {
        for kind in KINDS.into_iter().chain([RecordKind::PfRetirement]) {
            let mut store = Memory::completed()?;
            begin_with(&mut store, BOOT, [1; 16], Scope::FullSession)?;
            let index = store.index(kind).ok_or("test record missing")?;
            store.records[index].1 = StoredRecord::new(RecordIdentity::new([99; 32])?, vec![42])?;
            let before = store.records.clone();
            assert!(progress(&store).is_err());
            assert!(finish_with(&mut store).is_err());
            assert_eq!(store.records, before);
        }
        Ok(())
    }

    #[test]
    fn malformed_scope_is_rejected_even_with_a_matching_digest()
    -> Result<(), Box<dyn std::error::Error>> {
        for invalid_scope in [None, Some("unstaged_reference")] {
            let mut store = Memory::completed()?;
            begin_with(&mut store, BOOT, [1; 16], Scope::FullSession)?;
            let marker = store
                .read(RecordKind::PfRetirement)?
                .ok_or("missing marker")?;
            let mut value: serde_json::Value = serde_json::from_slice(marker.payload())?;
            if let Some(scope) = invalid_scope {
                value["scope"] = serde_json::json!(scope);
            } else {
                value
                    .as_object_mut()
                    .ok_or("invalid marker")?
                    .remove("scope");
            }
            let payload = serde_json::to_vec(&value)?;
            let mut hash = Sha256::new();
            hash.update(DOMAIN);
            hash.update(&payload);
            let invalid = StoredRecord::new(RecordIdentity::new(hash.finalize().into())?, payload)?;
            store.replace(RecordKind::PfRetirement, &invalid)?;
            let before = store.records.clone();
            assert!(finish_with(&mut store).is_err());
            assert_eq!(store.records, before);
        }
        Ok(())
    }

    #[test]
    fn absence_of_marker_never_authorizes_removing_old_records() -> Result<(), StoreError> {
        let mut store = Memory::completed()?;
        let before = store.records.clone();
        assert!(matches!(finish_with(&mut store), Ok(false)));
        assert_eq!(store.records, before);
        Ok(())
    }

    #[test]
    fn unstaged_reference_retirement_rejects_other_operations_and_resumes()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = Memory::completed()?;
        assert!(begin_with(&mut store, BOOT, [1; 16], Scope::UnstagedReference).is_err());
        store
            .records
            .retain(|(kind, _)| included(Scope::UnstagedReference, *kind));
        begin_with(&mut store, BOOT, [1; 16], Scope::UnstagedReference)?;
        assert_eq!(progress(&store)?.ok_or("missing marker")?.remaining, 2);
        let foreign = StoredRecord::new(RecordIdentity::new([9; 32])?, vec![9])?;
        store.replace(RecordKind::PfHook, &foreign)?;
        let before = store.records.clone();
        assert!(finish_with(&mut store).is_err());
        assert_eq!(store.records, before);
        let index = store
            .index(RecordKind::PfHook)
            .ok_or("missing injected record")?;
        store.records.remove(index);
        store.fail = Some((RecordKind::PfReferenceRelease, true));
        assert!(finish_with(&mut store).is_err());
        store.fail = None;
        assert_eq!(progress(&store)?.ok_or("missing marker")?.remaining, 1);
        assert!(finish_with(&mut store)?);
        assert!(store.records.is_empty());
        Ok(())
    }

    #[test]
    fn previous_full_session_marker_remains_readable() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = Memory::completed()?;
        begin_with(&mut store, BOOT, [1; 16], Scope::FullSession)?;
        let marker = store
            .read(RecordKind::PfRetirement)?
            .ok_or("missing marker")?;
        let mut old: serde_json::Value = serde_json::from_slice(marker.payload())?;
        old["version"] = serde_json::json!(1);
        let fingerprints = KINDS
            .into_iter()
            .map(|kind| {
                let record = store
                    .read(kind)?
                    .ok_or(StoreError::Refused("test record missing"))?;
                Ok(fingerprint(1, kind, &record))
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        old["fingerprints"] = serde_json::json!(fingerprints);
        old.as_object_mut()
            .ok_or("invalid test marker")?
            .remove("scope");
        let payload = serde_json::to_vec(&old)?;
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(&payload);
        let legacy = StoredRecord::new(RecordIdentity::new(hash.finalize().into())?, payload)?;
        store.replace(RecordKind::PfRetirement, &legacy)?;
        assert_eq!(
            progress(&store)?.ok_or("legacy marker rejected")?.remaining,
            KINDS.len()
        );
        assert!(finish_with(&mut store)?);
        Ok(())
    }

    #[test]
    fn pending_file_during_retirement_blocks_all_removals() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut store = Memory::completed()?;
        begin_with(&mut store, BOOT, [1; 16], Scope::FullSession)?;
        for pending in KINDS.into_iter().chain([RecordKind::PfRetirement]) {
            store.pending.push(pending);
            let before = store.records.clone();
            assert!(finish_with(&mut store).is_err());
            assert_eq!(store.records, before);
            store.pending.clear();
        }
        Ok(())
    }
}
