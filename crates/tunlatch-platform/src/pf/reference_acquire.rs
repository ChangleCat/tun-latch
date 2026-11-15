//! One-shot PF starter-reference acquisition with a durable intent and child receipt.
//!
//! There is deliberately no automatic retry or release. A saved receipt is a recovery hint,
//! not authorization to release a reference or evidence that traffic is protected.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{qualification, reference, snapshot};
use crate::store::{RecordIdentity, RecordKind, StoreError, StoredRecord, SystemRecordStore};

const MAX_RETURN_BYTES: usize = 4096;
const SESSION_RECORDS: [RecordKind; 7] = [
    RecordKind::PfReference,
    RecordKind::PfAnchorStage,
    RecordKind::PfHook,
    RecordKind::PfHookRemoval,
    RecordKind::PfAnchorClear,
    RecordKind::PfReferenceRelease,
    RecordKind::PfRetirement,
];

/// Failure before or during a one-shot PF reference acquisition.
#[derive(Debug, thiserror::Error)]
pub enum AcquireError {
    /// The protected record could not be read or durably replaced.
    #[error("PF reference record error: {0}")]
    Store(#[from] StoreError),
    /// The OS random generator could not produce a fresh session ID.
    #[error("cannot generate PF reference session")]
    Random,
    /// A fixed system observation or child-process operation failed.
    #[error("PF reference command or observation failed: {0}")]
    Query(#[from] snapshot::SnapshotError),
    /// This system's native PF reader was not independently qualified.
    #[error("PF host qualification failed: {0}")]
    Qualification(#[from] qualification::QualificationError),
    /// The protected slot already exists or the child result was invalid.
    #[error("PF reference acquisition refused: {0}")]
    Refused(&'static str),
    /// The child was started but a complete result or independent confirmation is unavailable.
    #[error(
        "PF reference acquisition outcome is unconfirmed; inspect the protected record before recovery"
    )]
    Unconfirmed,
}

/// A reference observed after acquisition; this is not a protection or cleanup capability.
pub struct AcquiredReference {
    token: reference::ReferenceToken,
    creator_pid: u32,
    pub(super) boot_session: String,
    pub(super) session: [u8; 16],
    pub(super) acquisition_identity: RecordIdentity,
    baseline: Baseline,
    // Keep the protected store's cooperating-writer lock for the entire live handle.
    // Dropping it never releases the PF reference or removes its durable receipt.
    pub(super) store: SystemRecordStore,
}

impl std::fmt::Debug for AcquiredReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AcquiredReference")
            .field("token", &self.token)
            .field("creator_pid", &self.creator_pid)
            .finish_non_exhaustive()
    }
}

impl AcquiredReference {
    pub(super) fn recheck_current(&self) -> Result<(), AcquireError> {
        let current = self
            .store
            .read(RecordKind::PfReference)?
            .ok_or(AcquireError::Refused("acquisition record missing"))?;
        if current.identity() != self.acquisition_identity
            || self.store.read(RecordKind::PfReferenceRelease)?.is_some()
            || snapshot::boot_session()? != self.boot_session
        {
            return Err(AcquireError::Unconfirmed);
        }
        if !pf_enabled(&snapshot::query(snapshot::Query::Info)?)? {
            return Err(AcquireError::Unconfirmed);
        }
        let listing = snapshot::query(snapshot::Query::References)?;
        if !pf_enabled(&snapshot::query(snapshot::Query::Info)?)?
            || snapshot::boot_session()? != self.boot_session
            || !reference::contains_reference(&listing, self.token, self.creator_pid)
                .map_err(|_| AcquireError::Unconfirmed)?
        {
            return Err(AcquireError::Unconfirmed);
        }
        Ok(())
    }

    /// PID reported by the completed `pfctl -E` child.
    pub fn creator_pid(&self) -> u32 {
        self.creator_pid
    }

    /// Token observed in the completed child return; treat it as sensitive.
    pub fn token(&self) -> reference::ReferenceToken {
        self.token
    }

    /// PF enabled status observed before acquisition; not proof of another owner's intent.
    pub fn initially_enabled(&self) -> bool {
        self.baseline.enabled
    }

    /// Number of starter references observed before acquisition; no tokens are exposed.
    pub fn initial_reference_count(&self) -> u16 {
        self.baseline.reference_count
    }

    /// Release this exact reference after a separately authorized protection shutdown.
    ///
    /// Only the internal session backend issues authorization. The operation records its
    /// intent before the fixed `pfctl -X` call and retains both acquisition and release records.
    /// An uncertain outcome is never retried automatically. Other PF references are untouched.
    pub fn release(mut self, authorization: ReleaseAuthorization) -> Result<(), ReleaseError> {
        self.release_borrowed(authorization)
    }

    pub(super) fn release_borrowed(
        &mut self,
        authorization: ReleaseAuthorization,
    ) -> Result<(), ReleaseError> {
        if authorization.session != self.session {
            return Err(ReleaseError::Refused("release session mismatch"));
        }
        let current = self
            .store
            .read(RecordKind::PfReference)?
            .ok_or(ReleaseError::Refused("acquisition record missing"))?;
        if current.identity() != self.acquisition_identity {
            return Err(ReleaseError::Refused("acquisition record changed"));
        }
        let token = self.token;
        let pid = self.creator_pid;
        let boot = &self.boot_session;
        let read = || {
            if snapshot::boot_session().map_err(|_| ReleaseError::Unconfirmed)? != *boot {
                return Err(ReleaseError::Unconfirmed);
            }
            let bytes = snapshot::query(snapshot::Query::References)
                .map_err(|_| ReleaseError::Unconfirmed)?;
            if snapshot::boot_session().map_err(|_| ReleaseError::Unconfirmed)? != *boot {
                return Err(ReleaseError::Unconfirmed);
            }
            Ok(bytes)
        };
        release_with(
            &mut self.store,
            boot,
            self.session,
            token,
            pid,
            read,
            || {
                let listing = read()?;
                if !reference::contains_reference(&listing, token, pid)
                    .map_err(|_| ReleaseError::Unconfirmed)?
                {
                    return Err(ReleaseError::Unconfirmed);
                }
                let result =
                    snapshot::release_reference(token).map_err(|_| ReleaseError::Unconfirmed)?;
                Ok(ChildReturn {
                    pid: result.pid,
                    exit_code: result.status.code(),
                    stdout: result.stdout,
                    stderr: result.stderr,
                })
            },
        )
    }
}

/// Authority to release a session after its protection shutdown is independently verified.
///
/// Only the internal session backend issues this after verifying its same-process shutdown.
/// An observed record cannot be converted into it.
///
/// ```compile_fail
/// use tunlatch_platform::pf::reference_acquire::ReleaseAuthorization;
/// let _ = ReleaseAuthorization { session: [1; 16] };
/// ```
pub struct ReleaseAuthorization {
    pub(super) session: [u8; 16],
}

/// A failure while releasing an acquired PF reference.
#[derive(Debug, thiserror::Error)]
pub enum ReleaseError {
    /// A protected record failed before the release attempt began.
    #[error("PF reference release record error: {0}")]
    Store(#[from] StoreError),
    /// Authorization, session or prior-release checks refused the operation.
    #[error("PF reference release refused: {0}")]
    Refused(&'static str),
    /// A reliable release outcome could not be established; do not retry automatically.
    #[error(
        "PF reference release outcome is unconfirmed; inspect protected records before recovery"
    )]
    Unconfirmed,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum Receipt {
    Intent,
    ChildReturn {
        pid: u32,
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

/// Initial PF status and a digest of the complete reference inventory.
/// This is a non-atomic observation, not proof of who enabled PF or permission to disable it.
#[derive(Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Baseline {
    pub(super) enabled: bool,
    pub(super) reference_count: u16,
    reference_digest: [u8; 32],
}

impl Baseline {
    pub(super) fn valid(self) -> bool {
        self.reference_count <= 256
            && self.reference_digest != [0; 32]
            && (self.enabled || self.reference_count == 0)
    }
}

fn pf_enabled(info: &[u8]) -> Result<bool, AcquireError> {
    if info.len() > 65_536
        || !info.is_ascii()
        || !info.ends_with(b"\n")
        || info
            .iter()
            .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t'))
    {
        return Err(AcquireError::Unconfirmed);
    }
    let text = std::str::from_utf8(info).map_err(|_| AcquireError::Unconfirmed)?;
    let mut status = text.lines().filter(|line| line.starts_with("Status:"));
    let line = status.next().ok_or(AcquireError::Unconfirmed)?;
    if status.next().is_some() {
        return Err(AcquireError::Unconfirmed);
    }
    for (prefix, enabled) in [("Status: Enabled", true), ("Status: Disabled", false)] {
        if let Some(rest) = line.strip_prefix(prefix)
            && (rest.is_empty() || rest.starts_with([' ', '\t']))
        {
            return Ok(enabled);
        }
    }
    Err(AcquireError::Unconfirmed)
}

fn read_baseline() -> Result<Baseline, AcquireError> {
    let before = snapshot::query(snapshot::Query::Info)?;
    let refs = snapshot::query(snapshot::Query::References)?;
    let after = snapshot::query(snapshot::Query::Info)?;
    baseline_from(&before, &refs, &after)
}

fn baseline_from(before: &[u8], refs: &[u8], after: &[u8]) -> Result<Baseline, AcquireError> {
    let before = pf_enabled(before)?;
    let refs = reference::inventory(refs).map_err(|_| AcquireError::Unconfirmed)?;
    let after = pf_enabled(after)?;
    let baseline = Baseline {
        enabled: before,
        reference_count: refs.count,
        reference_digest: refs.digest,
    };
    if before != after || !baseline.valid() {
        return Err(AcquireError::Unconfirmed);
    }
    Ok(baseline)
}

fn acquire_on_unchanged_baseline(
    expected_boot: &str,
    baseline: Baseline,
    mut boot: impl FnMut() -> Result<String, AcquireError>,
    read: impl FnOnce() -> Result<Baseline, AcquireError>,
    execute: impl FnOnce() -> Result<ChildReturn, AcquireError>,
) -> Result<ChildReturn, AttemptError> {
    let preflight = || -> Result<(), AcquireError> {
        if boot()? != expected_boot || read()? != baseline || boot()? != expected_boot {
            return Err(AcquireError::Refused(
                "PF state changed before reference acquisition",
            ));
        }
        Ok(())
    };
    preflight().map_err(AttemptError::NotStarted)?;
    execute().map_err(|_| AttemptError::Unconfirmed)
}

enum AttemptError {
    /// The fixed PF child was definitely not started.
    NotStarted(AcquireError),
    /// Starting or completing the child may have changed PF.
    Unconfirmed,
}

#[derive(Serialize)]
struct Record<'a> {
    version: u8,
    boot_session: &'a str,
    session: [u8; 16],
    baseline: Baseline,
    receipt: Receipt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRecord {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    #[serde(default)]
    baseline: Option<Baseline>,
    receipt: Receipt,
}

/// Read-only interpretation of the protected acquisition record and current PF inventory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceRecordStatus {
    /// A verified reference release has unfinished local record retirement.
    RetirementPending,
    /// A release record exists and requires separate reconciliation.
    ReleaseRecordPresent,
    /// An anchor transaction or hook record exists and requires separate reconciliation.
    AnchorRecordPresent,
    /// No reference acquisition record exists in the fixed protected slot.
    Missing,
    /// An intent or a child return cannot establish a successful acquisition.
    AcquisitionUnconfirmed,
    /// The recorded reference belongs to a different boot session.
    RecordedBootDiffers,
    /// The complete current reference listing contains the recorded token and PID.
    ReferencePresent,
    /// The complete current reference listing does not contain the recorded token.
    ReferenceAbsent,
}

/// Inspect the protected acquisition record without returning its sensitive token.
///
/// Requires root and the provisioned system store. It holds the store's cooperating-writer
/// lock while reading; the store may create its fixed lock file if absent. Observations are
/// not atomic and none of the results establish ownership, authorize release, or prove traffic
/// protection. No PF change, cleanup, or retry is performed.
pub fn inspect_record() -> Result<ReferenceRecordStatus, AcquireError> {
    let store = SystemRecordStore::open()?;
    for kind in [
        RecordKind::PfReference,
        RecordKind::PfAnchorStage,
        RecordKind::PfHook,
        RecordKind::PfHookRemoval,
        RecordKind::PfAnchorClear,
        RecordKind::PfReferenceRelease,
        RecordKind::PfRetirement,
    ] {
        store.require_no_pending(kind)?;
    }
    if super::retirement::inspect(&store)
        .map_err(|_| AcquireError::Refused("invalid PF retirement marker"))?
        .is_some()
    {
        return Ok(ReferenceRecordStatus::RetirementPending);
    }
    if store.read(RecordKind::PfReferenceRelease)?.is_some() {
        return Ok(ReferenceRecordStatus::ReleaseRecordPresent);
    }
    if store.read(RecordKind::PfAnchorClear)?.is_some()
        || store.read(RecordKind::PfHookRemoval)?.is_some()
        || store.read(RecordKind::PfHook)?.is_some()
        || store.read(RecordKind::PfAnchorStage)?.is_some()
    {
        return Ok(ReferenceRecordStatus::AnchorRecordPresent);
    }
    let Some(record) = store.read(RecordKind::PfReference)? else {
        return Ok(ReferenceRecordStatus::Missing);
    };
    let boot = snapshot::boot_session()?;
    let status = inspect_saved(&record, &boot, || {
        snapshot::query(snapshot::Query::References).map_err(AcquireError::from)
    })?;
    if snapshot::boot_session()? != boot {
        return Err(AcquireError::Unconfirmed);
    }
    Ok(status)
}

fn inspect_saved(
    stored: &StoredRecord,
    boot: &str,
    read_references: impl FnOnce() -> Result<Vec<u8>, AcquireError>,
) -> Result<ReferenceRecordStatus, AcquireError> {
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-reference-v1\0");
    hash.update(stored.payload());
    let expected: [u8; 32] = hash.finalize().into();
    if stored.identity().as_bytes() != &expected {
        return Err(AcquireError::Refused("reference record identity mismatch"));
    }
    let record: ReadRecord = serde_json::from_slice(stored.payload())
        .map_err(|_| AcquireError::Refused("invalid reference record"))?;
    if !matches!((record.version, record.baseline), (1, None) | (2, Some(_)))
        || record.baseline.is_some_and(|baseline| !baseline.valid())
        || record.session == [0; 16]
        || snapshot::parse_boot_session(&record.boot_session)
            .ok()
            .as_deref()
            != Some(record.boot_session.as_str())
    {
        return Err(AcquireError::Refused("invalid reference record identity"));
    }
    if record.boot_session != boot {
        return Ok(ReferenceRecordStatus::RecordedBootDiffers);
    }
    let Receipt::ChildReturn {
        pid,
        exit_code,
        stdout,
        stderr,
    } = record.receipt
    else {
        return Ok(ReferenceRecordStatus::AcquisitionUnconfirmed);
    };
    if pid == 0 || stdout.len().saturating_add(stderr.len()) > MAX_RETURN_BYTES {
        return Err(AcquireError::Refused("invalid reference child return"));
    }
    let Ok(token) = reference::parse_acquisition(exit_code == Some(0), &stdout, &stderr) else {
        return Ok(ReferenceRecordStatus::AcquisitionUnconfirmed);
    };
    let listing = read_references()?;
    let present = reference::contains_reference(&listing, token, pid)
        .map_err(|_| AcquireError::Unconfirmed)?;
    Ok(if present {
        ReferenceRecordStatus::ReferencePresent
    } else {
        ReferenceRecordStatus::ReferenceAbsent
    })
}

struct ChildReturn {
    pid: u32,
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct ObservedReference {
    token: reference::ReferenceToken,
    creator_pid: u32,
    acquisition_identity: RecordIdentity,
}

trait Records {
    fn existing(&self) -> Result<bool, StoreError>;
    fn save(&mut self, record: &StoredRecord) -> Result<(), StoreError>;
    fn remove_unstarted_intent(&mut self, record: &StoredRecord) -> Result<(), StoreError>;
}

impl Records for SystemRecordStore {
    fn existing(&self) -> Result<bool, StoreError> {
        Ok(self.read(RecordKind::PfReference)?.is_some())
    }

    fn save(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
        self.replace(RecordKind::PfReference, record)
    }

    fn remove_unstarted_intent(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
        self.remove_checked(RecordKind::PfReference, record)
    }
}

#[derive(Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
enum ReleaseReceipt {
    Intent,
    ChildReturn {
        pid: u32,
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

#[derive(Serialize)]
struct ReleaseRecord<'a> {
    version: u8,
    boot_session: &'a str,
    session: [u8; 16],
    acquisition_pid: u32,
    token: u64,
    receipt: ReleaseReceipt,
}

trait ReleaseRecords {
    fn release_exists(&self) -> Result<bool, StoreError>;
    fn save_release(&mut self, record: &StoredRecord) -> Result<(), StoreError>;
}

impl ReleaseRecords for SystemRecordStore {
    fn release_exists(&self) -> Result<bool, StoreError> {
        Ok(self.read(RecordKind::PfReferenceRelease)?.is_some())
    }
    fn save_release(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
        self.replace(RecordKind::PfReferenceRelease, record)
    }
}

fn save_release(
    records: &mut impl ReleaseRecords,
    record: &ReleaseRecord<'_>,
) -> Result<(), ReleaseError> {
    let payload = serde_json::to_vec(record)
        .map_err(|_| ReleaseError::Refused("cannot encode release record"))?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-release-v1\0");
    hash.update(&payload);
    let identity = RecordIdentity::new(hash.finalize().into())?;
    records.save_release(&StoredRecord::new(identity, payload)?)?;
    Ok(())
}

fn release_with(
    records: &mut impl ReleaseRecords,
    boot: &str,
    session: [u8; 16],
    token: reference::ReferenceToken,
    acquisition_pid: u32,
    read_references: impl Fn() -> Result<Vec<u8>, ReleaseError>,
    execute: impl FnOnce() -> Result<ChildReturn, ReleaseError>,
) -> Result<(), ReleaseError> {
    if boot.is_empty() || session == [0; 16] || acquisition_pid == 0 || records.release_exists()? {
        return Err(ReleaseError::Refused(
            "invalid session or existing release record",
        ));
    }
    let before = read_references()?;
    if !reference::contains_reference(&before, token, acquisition_pid)
        .map_err(|_| ReleaseError::Unconfirmed)?
    {
        return Err(ReleaseError::Refused("acquired reference not present"));
    }
    let mut record = ReleaseRecord {
        version: 1,
        boot_session: boot,
        session,
        acquisition_pid,
        token: token.get(),
        receipt: ReleaseReceipt::Intent,
    };
    save_release(records, &record)?;
    let result = execute().map_err(|_| ReleaseError::Unconfirmed)?;
    if result.pid == 0 || result.stdout.len().saturating_add(result.stderr.len()) > MAX_RETURN_BYTES
    {
        return Err(ReleaseError::Unconfirmed);
    }
    record.receipt = ReleaseReceipt::ChildReturn {
        pid: result.pid,
        exit_code: result.exit_code,
        stdout: result.stdout,
        stderr: result.stderr,
    };
    save_release(records, &record).map_err(|_| ReleaseError::Unconfirmed)?;
    let ReleaseReceipt::ChildReturn {
        exit_code,
        stdout,
        stderr,
        ..
    } = &record.receipt
    else {
        return Err(ReleaseError::Unconfirmed);
    };
    if !valid_release_return(*exit_code, stdout, stderr) {
        return Err(ReleaseError::Unconfirmed);
    }
    let after = read_references().map_err(|_| ReleaseError::Unconfirmed)?;
    if reference::contains_reference(&after, token, acquisition_pid)
        .map_err(|_| ReleaseError::Unconfirmed)?
    {
        return Err(ReleaseError::Unconfirmed);
    }
    Ok(())
}

fn valid_release_return(exit_code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> bool {
    const NOTICE: &[u8] = b"No ALTQ support in kernel\nALTQ related functions disabled\n";
    const DISABLED: &[u8] = b"pf disabled\n";
    if exit_code != Some(0) || !(stdout.is_empty() || stdout == DISABLED) {
        return false;
    }
    let rest = stderr.strip_prefix(NOTICE).unwrap_or(stderr);
    (rest.is_empty() || rest == DISABLED) && !(stdout == DISABLED && rest == DISABLED)
}

fn encode(record: &Record<'_>) -> Result<StoredRecord, AcquireError> {
    let payload = serde_json::to_vec(record)
        .map_err(|_| AcquireError::Refused("cannot encode reference record"))?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-reference-v1\0");
    hash.update(&payload);
    let identity = RecordIdentity::new(hash.finalize().into())?;
    Ok(StoredRecord::new(identity, payload)?)
}

fn save(records: &mut impl Records, record: &Record<'_>) -> Result<RecordIdentity, AcquireError> {
    let stored = encode(record)?;
    records.save(&stored)?;
    Ok(stored.identity())
}

// The first live backend supports only an initially disabled PF. This restriction is checked
// before writing the intent and again by the unchanged-baseline check before starting pfctl.
pub(super) fn acquire_initially_disabled() -> Result<AcquiredReference, AcquireError> {
    let mut store = SystemRecordStore::open()?;
    ensure_fresh_session(
        |kind| store.require_no_pending(kind),
        |kind| store.read(kind).map(|record| record.is_some()),
    )?;
    qualification::check_root_filter()?;
    let boot = snapshot::boot_session()?;
    let baseline = read_baseline()?;
    if snapshot::boot_session()? != boot {
        return Err(AcquireError::Unconfirmed);
    }
    if baseline.enabled {
        return Err(AcquireError::Refused("PF must initially be disabled"));
    }
    let mut session = [0_u8; 16];
    getrandom::fill(&mut session).map_err(|_| AcquireError::Random)?;
    if session == [0; 16] {
        return Err(AcquireError::Random);
    }
    let observed = acquire_with(
        &mut store,
        &boot,
        session,
        baseline,
        || {
            acquire_on_unchanged_baseline(
                &boot,
                baseline,
                || snapshot::boot_session().map_err(AcquireError::from),
                read_baseline,
                || {
                    let result = snapshot::acquire_reference()?;
                    Ok(ChildReturn {
                        pid: result.pid,
                        exit_code: result.status.code(),
                        stdout: result.stdout,
                        stderr: result.stderr,
                    })
                },
            )
        },
        || {
            if snapshot::boot_session()? != boot {
                return Err(AcquireError::Unconfirmed);
            }
            if !pf_enabled(&snapshot::query(snapshot::Query::Info)?)? {
                return Err(AcquireError::Unconfirmed);
            }
            let references = snapshot::query(snapshot::Query::References)?;
            if !pf_enabled(&snapshot::query(snapshot::Query::Info)?)?
                || snapshot::boot_session()? != boot
            {
                return Err(AcquireError::Unconfirmed);
            }
            Ok(references)
        },
    )?;
    Ok(AcquiredReference {
        token: observed.token,
        creator_pid: observed.creator_pid,
        acquisition_identity: observed.acquisition_identity,
        baseline,
        boot_session: boot,
        session,
        store,
    })
}

// A failed or interrupted atomic replacement can leave a temporary file without a final
// record. Check every operation's temporary slot as well as its final slot before any PF write.
fn ensure_fresh_session(
    mut check_pending: impl FnMut(RecordKind) -> Result<(), StoreError>,
    mut exists: impl FnMut(RecordKind) -> Result<bool, StoreError>,
) -> Result<(), AcquireError> {
    for kind in SESSION_RECORDS {
        check_pending(kind)?;
        if exists(kind)? {
            return Err(AcquireError::Refused("PF session record already exists"));
        }
    }
    Ok(())
}

fn acquire_with(
    records: &mut impl Records,
    boot: &str,
    session: [u8; 16],
    baseline: Baseline,
    execute: impl FnOnce() -> Result<ChildReturn, AttemptError>,
    read_references: impl FnOnce() -> Result<Vec<u8>, AcquireError>,
) -> Result<ObservedReference, AcquireError> {
    if records.existing()? || boot.is_empty() || session == [0; 16] || !baseline.valid() {
        return Err(AcquireError::Refused(
            "existing or invalid reference session",
        ));
    }
    let intent = encode(&Record {
        version: 2,
        boot_session: boot,
        session,
        baseline,
        receipt: Receipt::Intent,
    })?;
    records.save(&intent)?;
    let result = match execute() {
        Ok(result) => result,
        Err(AttemptError::NotStarted(reason)) => {
            // No child was spawned. Only this exact intent can be removed; interruption while
            // removing it may leave the intent for conservative diagnosis on the next start.
            records.remove_unstarted_intent(&intent)?;
            return Err(reason);
        }
        Err(AttemptError::Unconfirmed) => return Err(AcquireError::Unconfirmed),
    };
    if result.pid == 0 || result.stdout.len().saturating_add(result.stderr.len()) > MAX_RETURN_BYTES
    {
        return Err(AcquireError::Unconfirmed);
    }
    let ChildReturn {
        pid,
        exit_code,
        stdout,
        stderr,
    } = result;
    let receipt = Record {
        version: 2,
        boot_session: boot,
        session,
        baseline,
        receipt: Receipt::ChildReturn {
            pid,
            exit_code,
            stdout,
            stderr,
        },
    };
    // Save the complete child return before interpreting its contents or querying PF again.
    let acquisition_identity = save(records, &receipt).map_err(|_| AcquireError::Unconfirmed)?;
    let Receipt::ChildReturn { stdout, stderr, .. } = &receipt.receipt else {
        return Err(AcquireError::Unconfirmed);
    };
    let token = reference::parse_acquisition(exit_code == Some(0), stdout, stderr)
        .map_err(|_| AcquireError::Unconfirmed)?;
    let listing = read_references().map_err(|_| AcquireError::Unconfirmed)?;
    if !reference::contains_reference(&listing, token, pid)
        .map_err(|_| AcquireError::Unconfirmed)?
    {
        return Err(AcquireError::Unconfirmed);
    }
    Ok(ObservedReference {
        token,
        creator_pid: pid,
        acquisition_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn acquisition_refuses_every_existing_or_pending_session_record() {
        assert!(ensure_fresh_session(|_| Ok(()), |_| Ok(false)).is_ok());
        for blocked in SESSION_RECORDS {
            let pending = ensure_fresh_session(
                |kind| {
                    if kind == blocked {
                        Err(StoreError::PendingRecord(kind))
                    } else {
                        Ok(())
                    }
                },
                |_| Ok(false),
            );
            assert!(
                matches!(pending, Err(AcquireError::Store(StoreError::PendingRecord(kind))) if kind == blocked)
            );
            let existing = ensure_fresh_session(|_| Ok(()), |kind| Ok(kind == blocked));
            assert!(matches!(existing, Err(AcquireError::Refused(_))));
        }
    }
    #[derive(Default)]
    struct Memory {
        saved: Vec<Vec<u8>>,
        fail_at: Option<usize>,
        fail_remove: bool,
    }
    impl Records for Memory {
        fn existing(&self) -> Result<bool, StoreError> {
            Ok(!self.saved.is_empty())
        }
        fn save(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
            if self.fail_at == Some(self.saved.len()) {
                return Err(StoreError::Refused("injected failure"));
            }
            self.saved.push(record.payload().to_vec());
            Ok(())
        }

        fn remove_unstarted_intent(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
            if self.fail_remove || self.saved.len() != 1 || self.saved[0] != record.payload() {
                return Err(StoreError::Refused("injected or mismatched intent"));
            }
            self.saved.clear();
            Ok(())
        }
    }
    impl ReleaseRecords for Memory {
        fn release_exists(&self) -> Result<bool, StoreError> {
            self.existing()
        }
        fn save_release(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
            self.save(record)
        }
    }
    fn child() -> ChildReturn {
        ChildReturn {
            pid: 123,
            exit_code: Some(0),
            stdout: b"Token : 42\n".to_vec(),
            stderr: vec![],
        }
    }
    const LISTING: &[u8] =
        b"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 pfctl 42 0 days 00:00:01\n";

    fn baseline() -> Baseline {
        Baseline {
            enabled: false,
            reference_count: 0,
            reference_digest: [1; 32],
        }
    }

    #[test]
    fn baseline_requires_complete_consistent_pf_status_and_inventory() -> Result<(), AcquireError> {
        let disabled = b"Status: Disabled for 0 days\nState Table\n";
        let enabled = b"Status: Enabled for 2 days\nState Table\n";
        let none = b"No pf starter references held\n";
        let baseline = baseline_from(disabled, none, disabled)?;
        assert!(!baseline.enabled);
        assert_eq!(baseline.reference_count, 0);
        assert!(baseline_from(disabled, LISTING, disabled).is_err());
        assert!(baseline_from(disabled, none, enabled).is_err());
        assert!(baseline_from(enabled, b"incomplete", enabled).is_err());
        for invalid in [
            &b"Status: Enabled"[..],
            b"Status: EnabledUnknown\n",
            b"Status: Enabled\nStatus: Disabled\n",
            b"\xff\n",
        ] {
            assert!(pf_enabled(invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn changed_baseline_or_boot_prevents_pf_child_start() {
        let expected = baseline();
        let mut changed = expected;
        changed.enabled = true;
        let spawned = std::cell::Cell::new(false);
        let result = acquire_on_unchanged_baseline(
            "boot",
            expected,
            || Ok("boot".to_owned()),
            || Ok(changed),
            || {
                spawned.set(true);
                Ok(child())
            },
        );
        assert!(result.is_err());
        assert!(!spawned.get());
        let reads = std::cell::Cell::new(0);
        let result = acquire_on_unchanged_baseline(
            "boot",
            expected,
            || {
                let count = reads.get();
                reads.set(count + 1);
                Ok(if count == 0 { "boot" } else { "new-boot" }.to_owned())
            },
            || Ok(expected),
            || {
                spawned.set(true);
                Ok(child())
            },
        );
        assert!(result.is_err());
        assert!(!spawned.get());
    }

    #[test]
    fn unchanged_baseline_preflight_failure_removes_only_unstarted_intent() {
        for fail_remove in [false, true] {
            let mut records = Memory {
                fail_remove,
                ..Memory::default()
            };
            let spawned = std::cell::Cell::new(false);
            let observed = std::cell::Cell::new(false);
            let mut changed = baseline();
            changed.enabled = true;
            let result = acquire_with(
                &mut records,
                "boot",
                [1; 16],
                baseline(),
                || {
                    acquire_on_unchanged_baseline(
                        "boot",
                        baseline(),
                        || Ok("boot".to_owned()),
                        || Ok(changed),
                        || {
                            spawned.set(true);
                            Ok(child())
                        },
                    )
                },
                || {
                    observed.set(true);
                    Ok(LISTING.to_vec())
                },
            );
            assert!(!spawned.get());
            assert!(!observed.get());
            if fail_remove {
                assert!(matches!(result, Err(AcquireError::Store(_))));
                assert_eq!(records.saved.len(), 1);
            } else {
                assert!(matches!(result, Err(AcquireError::Refused(_))));
                assert!(records.saved.is_empty());
            }
        }
    }

    #[test]
    fn intent_precedes_execution_and_return_precedes_observation() -> Result<(), AcquireError> {
        let records = RefCell::new(Memory::default());
        let mut adapter = TestRecords(&records);
        let result = acquire_with(
            &mut adapter,
            "boot",
            [1; 16],
            baseline(),
            || {
                assert!(String::from_utf8_lossy(&records.borrow().saved[0]).contains("intent"));
                assert!(String::from_utf8_lossy(&records.borrow().saved[0]).contains("baseline"));
                Ok(child())
            },
            || {
                assert!(
                    String::from_utf8_lossy(&records.borrow().saved[1]).contains("child_return")
                );
                Ok(LISTING.to_vec())
            },
        )?;
        assert_eq!(result.creator_pid, 123);
        assert_eq!(result.token.get(), 42);
        Ok(())
    }

    struct TestRecords<'a>(&'a RefCell<Memory>);
    impl Records for TestRecords<'_> {
        fn existing(&self) -> Result<bool, StoreError> {
            self.0.borrow().existing()
        }
        fn save(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
            self.0.borrow_mut().save(record)
        }

        fn remove_unstarted_intent(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
            self.0.borrow_mut().remove_unstarted_intent(record)
        }
    }
    impl ReleaseRecords for TestRecords<'_> {
        fn release_exists(&self) -> Result<bool, StoreError> {
            self.0.borrow().release_exists()
        }
        fn save_release(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
            self.0.borrow_mut().save_release(record)
        }
    }

    #[test]
    fn failed_persistence_prevents_execution_or_leaves_unresolved_intent() {
        for failed_write in [0, 1] {
            let mut records = Memory {
                saved: vec![],
                fail_at: Some(failed_write),
                ..Memory::default()
            };
            let invoked = std::cell::Cell::new(false);
            let result = acquire_with(
                &mut records,
                "boot",
                [1; 16],
                baseline(),
                || {
                    invoked.set(true);
                    Ok(child())
                },
                || Ok(LISTING.to_vec()),
            );
            assert!(result.is_err());
            assert_eq!(invoked.get(), failed_write == 1);
            assert_eq!(records.saved.len(), failed_write);
            if failed_write == 1 {
                assert!(
                    acquire_with(
                        &mut records,
                        "boot",
                        [1; 16],
                        baseline(),
                        || Ok(child()),
                        || Ok(LISTING.to_vec())
                    )
                    .is_err()
                );
            }
        }
    }

    #[test]
    fn preserves_child_return_when_parse_or_independent_read_fails() {
        for bad_child in [true, false] {
            let mut records = Memory::default();
            let result = acquire_with(
                &mut records,
                "boot",
                [1; 16],
                baseline(),
                || {
                    let mut value = child();
                    if bad_child {
                        value.stdout = b"invalid\n".to_vec();
                    }
                    Ok(value)
                },
                || Ok(b"No pf starter references held\n".to_vec()),
            );
            assert!(matches!(result, Err(AcquireError::Unconfirmed)));
            assert_eq!(records.saved.len(), 2);
        }
    }

    #[test]
    fn interrupted_child_leaves_intent_and_prevents_retry() {
        let mut records = Memory::default();
        let observed = std::cell::Cell::new(false);
        let result = acquire_with(
            &mut records,
            "boot",
            [1; 16],
            baseline(),
            || Err(AttemptError::Unconfirmed),
            || {
                observed.set(true);
                Ok(LISTING.to_vec())
            },
        );
        assert!(matches!(result, Err(AcquireError::Unconfirmed)));
        assert!(!observed.get());
        assert_eq!(records.saved.len(), 1);
        assert!(
            acquire_with(
                &mut records,
                "boot",
                [1; 16],
                baseline(),
                || Ok(child()),
                || Ok(LISTING.to_vec())
            )
            .is_err()
        );
    }

    const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";

    fn stored(receipt: Receipt) -> Result<StoredRecord, AcquireError> {
        let mut records = Memory::default();
        save(
            &mut records,
            &Record {
                version: 2,
                boot_session: BOOT,
                session: [1; 16],
                baseline: baseline(),
                receipt,
            },
        )?;
        let payload = records.saved.remove(0);
        let mut hash = Sha256::new();
        hash.update(b"tunlatch-pf-reference-v1\0");
        hash.update(&payload);
        Ok(StoredRecord::new(
            RecordIdentity::new(hash.finalize().into())?,
            payload,
        )?)
    }

    #[test]
    fn inspection_reports_pending_and_old_boot_without_querying_pf() -> Result<(), AcquireError> {
        let record = stored(Receipt::Intent)?;
        let called = std::cell::Cell::new(false);
        assert_eq!(
            inspect_saved(&record, BOOT, || {
                called.set(true);
                Ok(vec![])
            })?,
            ReferenceRecordStatus::AcquisitionUnconfirmed
        );
        assert_eq!(
            inspect_saved(&record, "different boot", || {
                called.set(true);
                Ok(vec![])
            })?,
            ReferenceRecordStatus::RecordedBootDiffers
        );
        assert!(!called.get());
        Ok(())
    }

    #[test]
    fn legacy_acquisition_record_remains_diagnostic_without_a_baseline()
    -> Result<(), Box<dyn std::error::Error>> {
        let payload = serde_json::to_vec(&serde_json::json!({
            "version": 1, "boot_session": BOOT, "session": vec![1_u8; 16],
            "receipt": {"stage": "intent"}
        }))?;
        let mut hash = Sha256::new();
        hash.update(b"tunlatch-pf-reference-v1\0");
        hash.update(&payload);
        let record = StoredRecord::new(RecordIdentity::new(hash.finalize().into())?, payload)?;
        assert_eq!(
            inspect_saved(&record, BOOT, || Ok(vec![]))?,
            ReferenceRecordStatus::AcquisitionUnconfirmed
        );
        Ok(())
    }

    #[test]
    fn inspection_requires_complete_matching_inventory_and_rejects_corruption()
    -> Result<(), AcquireError> {
        let record = stored(Receipt::ChildReturn {
            pid: 123,
            exit_code: Some(0),
            stdout: b"Token : 42\n".to_vec(),
            stderr: vec![],
        })?;
        assert_eq!(
            inspect_saved(&record, BOOT, || Ok(LISTING.to_vec()))?,
            ReferenceRecordStatus::ReferencePresent
        );
        assert_eq!(
            inspect_saved(&record, BOOT, || Ok(
                b"No pf starter references held\n".to_vec()
            ))?,
            ReferenceRecordStatus::ReferenceAbsent
        );
        assert!(inspect_saved(&record, BOOT, || Ok(b"incomplete".to_vec())).is_err());
        let changed = StoredRecord::new(RecordIdentity::new([3; 32])?, record.payload().to_vec())?;
        assert!(inspect_saved(&changed, BOOT, || Ok(LISTING.to_vec())).is_err());
        let failed = stored(Receipt::ChildReturn {
            pid: 123,
            exit_code: Some(1),
            stdout: b"Token : 42\n".to_vec(),
            stderr: vec![],
        })?;
        assert_eq!(
            inspect_saved(&failed, BOOT, || Ok(LISTING.to_vec()))?,
            ReferenceRecordStatus::AcquisitionUnconfirmed
        );
        Ok(())
    }

    #[test]
    fn release_records_intent_and_return_and_allows_foreign_references() -> Result<(), ReleaseError>
    {
        let records = RefCell::new(Memory::default());
        let mut adapter = TestRecords(&records);
        let token = reference::parse_acquisition(true, b"Token : 42\n", b"")
            .map_err(|_| ReleaseError::Unconfirmed)?;
        let reads = std::cell::Cell::new(0);
        release_with(
            &mut adapter,
            BOOT,
            [1; 16],
            token,
            123,
            || {
                let count = reads.get();
                reads.set(count + 1);
                if count == 0 {
                    Ok(LISTING.to_vec())
                } else {
                    assert!(
                        String::from_utf8_lossy(&records.borrow().saved[1])
                            .contains("child_return")
                    );
                    Ok(
                        b"TOKENS:\nPID Process Name TOKEN TIMESTAMP\n99 pfctl 43 0 days 00:00:01\n"
                            .to_vec(),
                    )
                }
            },
            || {
                assert!(String::from_utf8_lossy(&records.borrow().saved[0]).contains("intent"));
                Ok(ChildReturn {
                    pid: 124,
                    exit_code: Some(0),
                    stdout: vec![],
                    stderr: vec![],
                })
            },
        )?;
        assert_eq!(reads.get(), 2);
        Ok(())
    }

    #[test]
    fn release_never_retries_or_proceeds_without_a_valid_durable_intent() -> Result<(), ReleaseError>
    {
        let token = reference::parse_acquisition(true, b"Token : 42\n", b"")
            .map_err(|_| ReleaseError::Unconfirmed)?;
        for failure in [0, 1] {
            let mut records = Memory {
                saved: vec![],
                fail_at: Some(failure),
                ..Memory::default()
            };
            let invoked = std::cell::Cell::new(false);
            let result = release_with(
                &mut records,
                BOOT,
                [1; 16],
                token,
                123,
                || Ok(LISTING.to_vec()),
                || {
                    invoked.set(true);
                    Err(ReleaseError::Unconfirmed)
                },
            );
            assert!(result.is_err());
            assert_eq!(invoked.get(), failure == 1);
            assert_eq!(records.saved.len(), failure);
            if failure == 1 {
                assert!(
                    release_with(
                        &mut records,
                        BOOT,
                        [1; 16],
                        token,
                        123,
                        || Ok(LISTING.to_vec()),
                        || Err(ReleaseError::Unconfirmed)
                    )
                    .is_err()
                );
            }
        }
        let mut records = Memory::default();
        let invoked = std::cell::Cell::new(false);
        assert!(
            release_with(
                &mut records,
                BOOT,
                [1; 16],
                token,
                123,
                || Ok(b"No pf starter references held\n".to_vec()),
                || {
                    invoked.set(true);
                    Err(ReleaseError::Unconfirmed)
                }
            )
            .is_err()
        );
        assert!(!invoked.get());
        assert!(records.saved.is_empty());
        Ok(())
    }

    #[test]
    fn release_return_requires_complete_successful_known_output() {
        assert!(valid_release_return(Some(0), b"", b""));
        assert!(valid_release_return(Some(0), b"", b"pf disabled\n"));
        assert!(!valid_release_return(Some(1), b"", b""));
        assert!(!valid_release_return(
            Some(0),
            b"pf disabled\n",
            b"pf disabled\n"
        ));
        assert!(!valid_release_return(Some(0), b"unknown\n", b""));
    }

    #[test]
    fn release_persists_child_before_postcheck_and_preserves_uncertainty()
    -> Result<(), ReleaseError> {
        let token = reference::parse_acquisition(true, b"Token : 42\n", b"")
            .map_err(|_| ReleaseError::Unconfirmed)?;
        let child_return = || {
            Ok(ChildReturn {
                pid: 124,
                exit_code: Some(0),
                stdout: vec![],
                stderr: vec![],
            })
        };
        let reads = std::cell::Cell::new(0);
        let mut records = Memory {
            saved: vec![],
            fail_at: Some(1),
            ..Memory::default()
        };
        assert!(matches!(
            release_with(
                &mut records,
                BOOT,
                [1; 16],
                token,
                123,
                || {
                    reads.set(reads.get() + 1);
                    Ok(LISTING.to_vec())
                },
                child_return
            ),
            Err(ReleaseError::Unconfirmed)
        ));
        assert_eq!(reads.get(), 1);
        assert_eq!(records.saved.len(), 1);
        let mut records = Memory::default();
        assert!(matches!(
            release_with(
                &mut records,
                BOOT,
                [1; 16],
                token,
                123,
                || Ok(LISTING.to_vec()),
                child_return
            ),
            Err(ReleaseError::Unconfirmed)
        ));
        assert_eq!(records.saved.len(), 2);
        Ok(())
    }
}
