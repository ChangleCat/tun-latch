//! Read-only inspection of protected PF operation records and current kernel observations.
//!
//! Records and non-atomic observations are recovery hints, never authority to mutate PF.

use std::fs::File;
use std::num::NonZeroU64;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    anchor, hook_readback, native_hook, reference, reference_acquire::Baseline, retirement, rules,
    snapshot,
};
use crate::store::{RecordKind, StoreError, StoredRecord, SystemRecordStore};

/// Error obtaining or validating the protected PF recovery record set.
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// The fixed root-protected store could not be opened or read.
    #[error("PF recovery store error: {0}")]
    Store(#[from] StoreError),
    /// Current boot identity could not be obtained reliably.
    #[error("PF recovery query failed: {0}")]
    Query(#[from] snapshot::SnapshotError),
    /// Records are malformed, inconsistent, or from incompatible sessions.
    #[error("PF recovery records rejected: {0}")]
    Invalid(&'static str),
    /// A completion marker or its remaining local records failed validation.
    #[error("PF retirement inspection failed: {0}")]
    Retirement(#[from] retirement::RetirementError),
}

/// What was durably recorded for an operation, not proof of kernel state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recorded {
    /// The individual record was not interpreted during an incomplete retirement.
    NotChecked,
    /// No operation record exists.
    Missing,
    /// Intent was saved, but no complete return was saved.
    Intent,
    /// A return was saved; independent verification may still have failed.
    Returned,
}

/// Relationship between the protected records and the current boot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Boot {
    /// No PF operation records exist.
    NoRecords,
    /// Records identify the current boot.
    Current,
    /// Records identify a prior or otherwise different boot.
    Different,
}

/// PF status observed before reference acquisition, if the record includes a baseline.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitialPf {
    /// A legacy record or absent record contains no initial status.
    Unknown,
    /// PF appeared disabled before acquisition.
    Disabled,
    /// PF appeared enabled before acquisition.
    Enabled,
}

/// An independently sampled PF object; this is not ownership or protection evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation {
    /// No applicable record or current-boot identity was available.
    NotChecked,
    /// The recorded object or rule was found and matched.
    Matches,
    /// The object or rule was absent in the successful observation.
    Absent,
    /// The anchor filter read returned no rules; anchor existence is not established.
    Empty,
    /// Data was complete but differed from the recorded values.
    Different,
    /// An independent read failed or was inconsistent.
    Unavailable,
}

/// Sanitized operation history and independently sampled PF observations.
/// It contains no reference token, rule text, session ID, or authorization capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Report {
    /// Whether records were created in this boot.
    pub boot: Boot,
    /// Initial status is a sampled fact, not proof of the reason PF was enabled.
    pub initial_pf: InitialPf,
    /// Number of starter references initially observed; untokened enables are not counted.
    pub initial_reference_count: Option<u16>,
    /// Remaining local records after a verified reference release, if retirement is in progress.
    pub retirement_remaining: Option<usize>,
    /// Reference acquisition record.
    pub acquisition: Recorded,
    /// Anchor rule transaction record.
    pub stage: Recorded,
    /// Root-hook insertion record.
    pub hook: Recorded,
    /// Root-hook deletion record.
    pub removal: Recorded,
    /// Anchor filter clearing record.
    pub clear: Recorded,
    /// Reference release record.
    pub release: Recorded,
    /// Current reference-list comparison.
    pub reference_observation: Observation,
    /// Current root-hook comparison against the saved baseline and ticket.
    pub hook_observation: Observation,
    /// Current project-anchor rule comparison.
    pub anchor_observation: Observation,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            boot: Boot::NoRecords,
            initial_pf: InitialPf::Unknown,
            initial_reference_count: None,
            retirement_remaining: None,
            acquisition: Recorded::Missing,
            stage: Recorded::Missing,
            hook: Recorded::Missing,
            removal: Recorded::Missing,
            clear: Recorded::Missing,
            release: Recorded::Missing,
            reference_observation: Observation::NotChecked,
            hook_observation: Observation::NotChecked,
            anchor_observation: Observation::NotChecked,
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case", deny_unknown_fields)]
enum ChildReceipt {
    Intent,
    ChildReturn {
        pid: u32,
        #[serde(deserialize_with = "optional_i32")]
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

fn optional_i32<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i32>, D::Error> {
    Option::<i32>::deserialize(deserializer)
}
fn optional_u64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<u64>, D::Error> {
    Option::<u64>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Acquisition {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    #[serde(default)]
    baseline: Option<Baseline>,
    receipt: ChildReceipt,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    interface: String,
    acquisition_identity: String,
    stage: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hook {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    index: u32,
    stage_identity: String,
    root_before: String,
    #[serde(deserialize_with = "optional_u64")]
    ticket: Option<u64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Removal {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    index: u32,
    ticket: u64,
    stage_identity: String,
    hook_identity: String,
    #[serde(default)]
    root_before: Option<String>,
    stage: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Clear {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    interface: String,
    stage_identity: String,
    removal_identity: String,
    stage: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Release {
    version: u8,
    boot_session: String,
    session: [u8; 16],
    acquisition_pid: u32,
    token: u64,
    receipt: ChildReceipt,
}

#[derive(Default)]
struct Records {
    acquisition: Option<StoredRecord>,
    stage: Option<StoredRecord>,
    hook: Option<StoredRecord>,
    removal: Option<StoredRecord>,
    clear: Option<StoredRecord>,
    release: Option<StoredRecord>,
}

struct Probe {
    session: [u8; 16],
    reference: Option<(reference::ReferenceToken, u32)>,
    interface: Option<String>,
    hook: Option<Hook>,
    removal_baseline: Option<String>,
}

fn decode<T: serde::de::DeserializeOwned>(
    record: &StoredRecord,
    domain: &[u8],
) -> Result<T, RecoveryError> {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(record.payload());
    let digest: [u8; 32] = hash.finalize().into();
    if record.identity().as_bytes() != &digest {
        return Err(RecoveryError::Invalid("record identity mismatch"));
    }
    serde_json::from_slice(record.payload())
        .map_err(|_| RecoveryError::Invalid("invalid record format"))
}

fn identity(
    version: u8,
    boot: &str,
    session: [u8; 16],
    expected_boot: &str,
    expected_session: [u8; 16],
) -> Result<(), RecoveryError> {
    if version != 1
        || session == [0; 16]
        || session != expected_session
        || boot != expected_boot
        || snapshot::parse_boot_session(boot).ok().as_deref() != Some(boot)
    {
        return Err(RecoveryError::Invalid("record session or boot mismatch"));
    }
    Ok(())
}

fn child(receipt: &ChildReceipt) -> Result<Recorded, RecoveryError> {
    match receipt {
        ChildReceipt::Intent => Ok(Recorded::Intent),
        ChildReceipt::ChildReturn {
            pid,
            stdout,
            stderr,
            ..
        } => {
            if *pid == 0 || stdout.len().saturating_add(stderr.len()) > 4096 {
                return Err(RecoveryError::Invalid("invalid child return"));
            }
            Ok(Recorded::Returned)
        }
    }
}

fn phase(value: &str, returned: &str) -> Result<Recorded, RecoveryError> {
    match value {
        "intent" => Ok(Recorded::Intent),
        value if value == returned => Ok(Recorded::Returned),
        _ => Err(RecoveryError::Invalid("invalid operation phase")),
    }
}

fn analyze(
    records: &Records,
    current_boot: &str,
) -> Result<(Report, Option<Probe>), RecoveryError> {
    let mut report = Report::default();
    let Some(acquisition_raw) = &records.acquisition else {
        if records.stage.is_some()
            || records.hook.is_some()
            || records.removal.is_some()
            || records.clear.is_some()
            || records.release.is_some()
        {
            return Err(RecoveryError::Invalid(
                "operation record without acquisition",
            ));
        }
        return Ok((report, None));
    };
    let acquisition: Acquisition = decode(acquisition_raw, b"tunlatch-pf-reference-v1\0")?;
    let boot = &acquisition.boot_session;
    let session = acquisition.session;
    if !matches!(
        (acquisition.version, acquisition.baseline),
        (1, None) | (2, Some(_))
    ) || acquisition
        .baseline
        .is_some_and(|baseline| !baseline.valid())
    {
        return Err(RecoveryError::Invalid("invalid acquisition baseline"));
    }
    identity(1, boot, session, boot, session)?;
    report.boot = if boot == current_boot {
        Boot::Current
    } else {
        Boot::Different
    };
    if let Some(baseline) = acquisition.baseline {
        report.initial_pf = if baseline.enabled {
            InitialPf::Enabled
        } else {
            InitialPf::Disabled
        };
        report.initial_reference_count = Some(baseline.reference_count);
    }
    report.acquisition = child(&acquisition.receipt)?;
    let acquired = match &acquisition.receipt {
        ChildReceipt::ChildReturn {
            pid,
            exit_code,
            stdout,
            stderr,
        } => reference::parse_acquisition(*exit_code == Some(0), stdout, stderr)
            .ok()
            .map(|token| (token, *pid)),
        ChildReceipt::Intent => None,
    };
    let stage = if let Some(raw) = &records.stage {
        let value: Stage = decode(raw, b"tunlatch-pf-anchor-stage-v1\0")?;
        identity(
            value.version,
            &value.boot_session,
            value.session,
            boot,
            session,
        )?;
        if acquired.is_none()
            || rules::outbound_block(&value.interface).is_err()
            || value.acquisition_identity != acquisition_raw.identity().to_string()
        {
            return Err(RecoveryError::Invalid("invalid stage dependency"));
        }
        report.stage = phase(&value.stage, "committed")?;
        Some(value)
    } else {
        None
    };
    let hook = if let Some(raw) = &records.hook {
        let value: Hook = decode(raw, b"tunlatch-pf-hook-v1\0")?;
        identity(
            value.version,
            &value.boot_session,
            value.session,
            boot,
            session,
        )?;
        if report.stage != Recorded::Returned
            || value.ticket == Some(0)
            || records
                .stage
                .as_ref()
                .map(|record| record.identity().to_string())
                .as_deref()
                != Some(value.stage_identity.as_str())
        {
            return Err(RecoveryError::Invalid("invalid hook dependency"));
        }
        hook_readback::validate_index(
            hook_readback::Observation {
                bytes: value.root_before.as_bytes(),
                complete: true,
            },
            &anchor::anchor_name(session),
            value.index as usize,
        )
        .map_err(|_| RecoveryError::Invalid("invalid saved root baseline"))?;
        report.hook = if value.ticket.is_some() {
            Recorded::Returned
        } else {
            Recorded::Intent
        };
        Some(value)
    } else {
        None
    };
    let removal_baseline = if let Some(raw) = &records.removal {
        let value: Removal = decode(raw, b"tunlatch-pf-hook-removal-v1\0")?;
        if !matches!(
            (value.version, &value.root_before),
            (1, None) | (2, Some(_))
        ) {
            return Err(RecoveryError::Invalid("invalid removal baseline version"));
        }
        identity(1, &value.boot_session, value.session, boot, session)?;
        let (Some(stage_raw), Some(hook_raw), Some(hook)) = (&records.stage, &records.hook, &hook)
        else {
            return Err(RecoveryError::Invalid("missing removal dependency"));
        };
        if hook.ticket != Some(value.ticket)
            || value.ticket == 0
            || hook.index != value.index
            || value.stage_identity != stage_raw.identity().to_string()
            || value.hook_identity != hook_raw.identity().to_string()
        {
            return Err(RecoveryError::Invalid("hook removal identity mismatch"));
        }
        if let Some(root_before) = &value.root_before {
            hook_readback::validate_index(
                hook_readback::Observation {
                    bytes: root_before.as_bytes(),
                    complete: true,
                },
                &anchor::anchor_name(session),
                value.index as usize,
            )
            .map_err(|_| RecoveryError::Invalid("invalid removal root baseline"))?;
        }
        report.removal = phase(&value.stage, "returned")?;
        value.root_before
    } else {
        None
    };
    if let Some(raw) = &records.clear {
        let value: Clear = decode(raw, b"tunlatch-pf-anchor-clear-v1\0")?;
        identity(
            value.version,
            &value.boot_session,
            value.session,
            boot,
            session,
        )?;
        let (Some(stage_raw), Some(removal_raw), Some(stage)) =
            (&records.stage, &records.removal, &stage)
        else {
            return Err(RecoveryError::Invalid("missing clear dependency"));
        };
        if report.removal != Recorded::Returned
            || value.interface != stage.interface
            || value.stage_identity != stage_raw.identity().to_string()
            || value.removal_identity != removal_raw.identity().to_string()
        {
            return Err(RecoveryError::Invalid("anchor clear identity mismatch"));
        }
        report.clear = phase(&value.stage, "committed")?;
    }
    if let Some(raw) = &records.release {
        let value: Release = decode(raw, b"tunlatch-pf-release-v1\0")?;
        identity(
            value.version,
            &value.boot_session,
            value.session,
            boot,
            session,
        )?;
        if acquired.map(|(token, pid)| (token.get(), pid))
            != Some((value.token, value.acquisition_pid))
        {
            return Err(RecoveryError::Invalid(
                "reference release identity mismatch",
            ));
        }
        report.release = child(&value.receipt)?;
    }
    let probe = (report.boot == Boot::Current).then(|| Probe {
        session,
        reference: acquired,
        interface: stage.map(|value| value.interface),
        hook,
        removal_baseline,
    });
    Ok((report, probe))
}

/// Inspect all fixed protected PF records and, on the same boot, compare available live state.
///
/// Requires an already-root caller and the provisioned system store. It holds the cooperating
/// writer lock and refuses unresolved pending files. Queries are bounded but not atomic; all
/// results are diagnostic only. This function never writes PF, cleans records, reveals tokens,
/// or grants authorization. The store may create its fixed lock file if it does not exist.
pub fn inspect() -> Result<Report, RecoveryError> {
    let store = SystemRecordStore::open()?;
    inspect_locked(&store)
}

// A live session can inspect without releasing and reacquiring its protected store lock.
pub(super) fn inspect_locked(store: &SystemRecordStore) -> Result<Report, RecoveryError> {
    if let Some(progress) = retirement::inspect(store)? {
        let boot = snapshot::boot_session()?;
        let report = retirement_report(&boot, &progress.boot_session, progress.remaining);
        if snapshot::boot_session()? != boot {
            return Err(RecoveryError::Invalid("boot changed during inspection"));
        }
        return Ok(report);
    }
    let kinds = [
        RecordKind::PfReference,
        RecordKind::PfAnchorStage,
        RecordKind::PfHook,
        RecordKind::PfHookRemoval,
        RecordKind::PfAnchorClear,
        RecordKind::PfReferenceRelease,
        RecordKind::PfRetirement,
    ];
    for kind in kinds {
        store.require_no_pending(kind)?;
    }
    let records = Records {
        acquisition: store.read(RecordKind::PfReference)?,
        stage: store.read(RecordKind::PfAnchorStage)?,
        hook: store.read(RecordKind::PfHook)?,
        removal: store.read(RecordKind::PfHookRemoval)?,
        clear: store.read(RecordKind::PfAnchorClear)?,
        release: store.read(RecordKind::PfReferenceRelease)?,
    };
    for kind in kinds {
        store.require_no_pending(kind)?;
    }
    if records.acquisition.is_none()
        && records.stage.is_none()
        && records.hook.is_none()
        && records.removal.is_none()
        && records.clear.is_none()
        && records.release.is_none()
    {
        return Ok(Report::default());
    }
    let boot = snapshot::boot_session()?;
    let (mut report, probe) = analyze(&records, &boot)?;
    if let Some(probe) = probe {
        observe(&mut report, &probe);
    }
    if snapshot::boot_session()? != boot {
        return Err(RecoveryError::Invalid("boot changed during inspection"));
    }
    Ok(report)
}

fn retirement_report(boot: &str, recorded_boot: &str, remaining: usize) -> Report {
    Report {
        boot: if recorded_boot == boot {
            Boot::Current
        } else {
            Boot::Different
        },
        retirement_remaining: Some(remaining),
        acquisition: Recorded::NotChecked,
        stage: Recorded::NotChecked,
        hook: Recorded::NotChecked,
        removal: Recorded::NotChecked,
        clear: Recorded::NotChecked,
        release: Recorded::NotChecked,
        ..Report::default()
    }
}

const PREVIOUS_BOOT_KINDS: [RecordKind; 6] = [
    RecordKind::PfReferenceRelease,
    RecordKind::PfAnchorClear,
    RecordKind::PfHookRemoval,
    RecordKind::PfHook,
    RecordKind::PfAnchorStage,
    RecordKind::PfReference,
];

trait PreviousBootStore {
    fn pending(&self, kind: RecordKind) -> Result<(), StoreError>;
    fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError>;
    fn remove(&mut self, kind: RecordKind, expected: &StoredRecord) -> Result<(), StoreError>;
}

impl PreviousBootStore for SystemRecordStore {
    fn pending(&self, kind: RecordKind) -> Result<(), StoreError> {
        self.require_no_pending(kind)
    }
    fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
        SystemRecordStore::read(self, kind)
    }
    fn remove(&mut self, kind: RecordKind, expected: &StoredRecord) -> Result<(), StoreError> {
        self.remove_checked(kind, expected)
    }
}

fn previous_boot_header(
    kind: RecordKind,
    record: &StoredRecord,
) -> Result<(String, [u8; 16]), RecoveryError> {
    let (boot, session) = match kind {
        RecordKind::PfReference => {
            let value: Acquisition = decode(record, b"tunlatch-pf-reference-v1\0")?;
            if !matches!((value.version, value.baseline), (1, None) | (2, Some(_)))
                || value.baseline.is_some_and(|baseline| !baseline.valid())
            {
                return Err(RecoveryError::Invalid("invalid acquisition baseline"));
            }
            child(&value.receipt)?;
            (value.boot_session, value.session)
        }
        RecordKind::PfAnchorStage => {
            let value: Stage = decode(record, b"tunlatch-pf-anchor-stage-v1\0")?;
            if value.version != 1 || rules::outbound_block(&value.interface).is_err() {
                return Err(RecoveryError::Invalid("invalid anchor stage record"));
            }
            phase(&value.stage, "committed")?;
            (value.boot_session, value.session)
        }
        RecordKind::PfHook => {
            let value: Hook = decode(record, b"tunlatch-pf-hook-v1\0")?;
            if value.version != 1 || value.ticket == Some(0) {
                return Err(RecoveryError::Invalid("invalid hook record"));
            }
            hook_readback::validate_index(
                hook_readback::Observation {
                    bytes: value.root_before.as_bytes(),
                    complete: true,
                },
                &anchor::anchor_name(value.session),
                value.index as usize,
            )
            .map_err(|_| RecoveryError::Invalid("invalid hook root baseline"))?;
            (value.boot_session, value.session)
        }
        RecordKind::PfHookRemoval => {
            let value: Removal = decode(record, b"tunlatch-pf-hook-removal-v1\0")?;
            if value.ticket == 0
                || !matches!(
                    (value.version, &value.root_before),
                    (1, None) | (2, Some(_))
                )
            {
                return Err(RecoveryError::Invalid("invalid hook removal record"));
            }
            phase(&value.stage, "returned")?;
            if let Some(root) = &value.root_before {
                hook_readback::validate_index(
                    hook_readback::Observation {
                        bytes: root.as_bytes(),
                        complete: true,
                    },
                    &anchor::anchor_name(value.session),
                    value.index as usize,
                )
                .map_err(|_| RecoveryError::Invalid("invalid removal root baseline"))?;
            }
            (value.boot_session, value.session)
        }
        RecordKind::PfAnchorClear => {
            let value: Clear = decode(record, b"tunlatch-pf-anchor-clear-v1\0")?;
            if value.version != 1 || rules::outbound_block(&value.interface).is_err() {
                return Err(RecoveryError::Invalid("invalid anchor clear record"));
            }
            phase(&value.stage, "committed")?;
            (value.boot_session, value.session)
        }
        RecordKind::PfReferenceRelease => {
            let value: Release = decode(record, b"tunlatch-pf-release-v1\0")?;
            if value.version != 1 || value.acquisition_pid == 0 || value.token == 0 {
                return Err(RecoveryError::Invalid("invalid reference release record"));
            }
            child(&value.receipt)?;
            (value.boot_session, value.session)
        }
        _ => return Err(RecoveryError::Invalid("unsupported PF record kind")),
    };
    identity(1, &boot, session, &boot, session)?;
    Ok((boot, session))
}

fn discard_previous_boot_with(
    store: &mut impl PreviousBootStore,
    mut current_boot: impl FnMut() -> Result<String, RecoveryError>,
) -> Result<usize, RecoveryError> {
    let boot = current_boot()?;
    store.pending(RecordKind::PfRetirement)?;
    if store.read(RecordKind::PfRetirement)?.is_some() {
        return Err(RecoveryError::Invalid(
            "finish the pending record retirement first",
        ));
    }
    let mut records = Vec::new();
    let mut previous_identity: Option<(String, [u8; 16])> = None;
    for kind in PREVIOUS_BOOT_KINDS {
        store.pending(kind)?;
        if let Some(record) = store.read(kind)? {
            let found = previous_boot_header(kind, &record)?;
            if found.0 == boot {
                return Err(RecoveryError::Invalid(
                    "PF records belong to the current boot",
                ));
            }
            if previous_identity
                .as_ref()
                .is_some_and(|expected| *expected != found)
            {
                return Err(RecoveryError::Invalid(
                    "PF records belong to different sessions",
                ));
            }
            previous_identity = Some(found);
            records.push((kind, record));
        }
    }
    if current_boot()? != boot {
        return Err(RecoveryError::Invalid(
            "boot changed during record inspection",
        ));
    }
    let count = records.len();
    // Delete dependants before their prerequisites, so an interruption can be resumed.
    for (kind, record) in records {
        if current_boot()? != boot {
            return Err(RecoveryError::Invalid("boot changed during record cleanup"));
        }
        store.remove(kind, &record)?;
    }
    Ok(count)
}

/// Remove validated records from one previous system boot, without changing current PF state.
///
/// Requires root and the fixed protected store. All remaining records must have the same old
/// boot and session, no pending files, and valid checked envelopes. A current-boot session or
/// retirement marker is never removed. Interrupted record deletion can be invoked again.
pub fn discard_previous_boot() -> Result<usize, RecoveryError> {
    let mut store = SystemRecordStore::open()?;
    discard_previous_boot_with(&mut store, || {
        snapshot::boot_session().map_err(RecoveryError::from)
    })
}

fn observe(report: &mut Report, probe: &Probe) {
    if let Some((token, pid)) = probe.reference {
        report.reference_observation = match snapshot::query(snapshot::Query::References)
            .ok()
            .and_then(|listing| reference::contains_reference(&listing, token, pid).ok())
        {
            Some(true) => Observation::Matches,
            Some(false) => Observation::Absent,
            None => Observation::Unavailable,
        };
    }
    if let Some(interface) = &probe.interface {
        report.anchor_observation = match snapshot::query(snapshot::Query::AnchorRules {
            session: &anchor::suffix(probe.session),
        }) {
            Ok(raw) if raw.is_empty() => Observation::Empty,
            Ok(raw) if anchor::matches_block(&raw, interface) => Observation::Matches,
            Ok(_) => Observation::Different,
            Err(_) => Observation::Unavailable,
        };
    }
    if let Some(saved) = &probe.hook {
        report.hook_observation =
            observe_hook(probe.session, saved, probe.removal_baseline.as_deref())
                .unwrap_or(Observation::Unavailable);
    }
}

fn observe_hook(
    session: [u8; 16],
    saved: &Hook,
    removal_baseline: Option<&str>,
) -> Result<Observation, RecoveryError> {
    let (build, kernel) = snapshot::host_identity()?;
    native_hook::check_host(&build, &kernel)
        .map_err(|_| RecoveryError::Invalid("unqualified PF host"))?;
    let device: File = open(
        "/dev/pf",
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| RecoveryError::Invalid("cannot open PF device"))?
    .into();
    let before = snapshot::query(snapshot::Query::RootRules)?;
    let textual = native_hook::parse_rules(&before)
        .map_err(|_| RecoveryError::Invalid("unsupported root rules"))?;
    let native = native_hook::readonly_rules(&device, &build, &kernel)
        .map_err(|_| RecoveryError::Invalid("native root read failed"))?;
    let hook = native_hook::readonly_hook(&device, &build, &kernel, &anchor::suffix(session))
        .map_err(|_| RecoveryError::Invalid("native hook read failed"))?;
    let after = snapshot::query(snapshot::Query::RootRules)?;
    if before != after || textual != native {
        return Err(RecoveryError::Invalid(
            "root rules changed during inspection",
        ));
    }
    Ok(classify_hook(
        session,
        saved,
        hook,
        &after,
        removal_baseline,
    ))
}

fn classify_hook(
    session: [u8; 16],
    saved: &Hook,
    hook: Option<native_hook::Hook>,
    after: &[u8],
    removal_baseline: Option<&str>,
) -> Observation {
    let baseline = hook_readback::Observation {
        bytes: removal_baseline.unwrap_or(&saved.root_before).as_bytes(),
        complete: true,
    };
    let current = hook_readback::Observation {
        bytes: after,
        complete: true,
    };
    let name = anchor::anchor_name(session);
    match hook {
        None => {
            if hook_readback::verify_detached(baseline, current, &name).is_ok() {
                Observation::Absent
            } else {
                Observation::Different
            }
        }
        Some(actual) => {
            let recorded_ticket = saved.ticket.and_then(NonZeroU64::new);
            if recorded_ticket == Some(actual.ticket)
                && saved.index == actual.index
                && hook_readback::verify(baseline, current, &name, saved.index as usize).is_ok()
            {
                Observation::Matches
            } else {
                Observation::Different
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{RecordIdentity, UserRecordStore};
    use serde_json::{Value, json};
    use std::error::Error;
    use std::os::unix::fs::PermissionsExt;

    const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";
    const OTHER_BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456788";

    #[test]
    fn interrupted_retirement_does_not_claim_individual_records_or_pf_state() {
        let report = retirement_report(BOOT, BOOT, 3);
        assert_eq!(report.boot, Boot::Current);
        assert_eq!(report.retirement_remaining, Some(3));
        assert_eq!(report.acquisition, Recorded::NotChecked);
        assert_eq!(report.hook, Recorded::NotChecked);
        assert_eq!(report.release, Recorded::NotChecked);
        assert_eq!(report.reference_observation, Observation::NotChecked);
        assert_eq!(retirement_report(BOOT, OTHER_BOOT, 0).boot, Boot::Different);
    }

    fn record(domain: &[u8], value: Value) -> Result<StoredRecord, Box<dyn Error>> {
        let payload = serde_json::to_vec(&value)?;
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(&payload);
        Ok(StoredRecord::new(
            RecordIdentity::new(hash.finalize().into())?,
            payload,
        )?)
    }

    fn complete() -> Result<Records, Box<dyn Error>> {
        let session = vec![1_u8; 16];
        let acquisition = record(
            b"tunlatch-pf-reference-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": session,
                "receipt": {"stage": "child_return", "pid": 123, "exit_code": 0,
                    "stdout": b"Token : 42\n".to_vec(), "stderr": Vec::<u8>::new()}
            }),
        )?;
        let stage = record(
            b"tunlatch-pf-anchor-stage-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": session,
                "interface": "en0", "acquisition_identity": acquisition.identity().to_string(), "stage": "committed"
            }),
        )?;
        let hook = record(
            b"tunlatch-pf-hook-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": session,
                "index": 0, "stage_identity": stage.identity().to_string(),
                "root_before": "anchor \"com.apple/*\" all\n", "ticket": 456
            }),
        )?;
        let removal = record(
            b"tunlatch-pf-hook-removal-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": session,
                "index": 0, "ticket": 456, "stage_identity": stage.identity().to_string(),
                "hook_identity": hook.identity().to_string(), "stage": "returned"
            }),
        )?;
        let clear = record(
            b"tunlatch-pf-anchor-clear-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": session,
                "interface": "en0", "stage_identity": stage.identity().to_string(),
                "removal_identity": removal.identity().to_string(), "stage": "committed"
            }),
        )?;
        let release = record(
            b"tunlatch-pf-release-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": session,
                "acquisition_pid": 123, "token": 42, "receipt": {"stage": "intent"}
            }),
        )?;
        Ok(Records {
            acquisition: Some(acquisition),
            stage: Some(stage),
            hook: Some(hook),
            removal: Some(removal),
            clear: Some(clear),
            release: Some(release),
        })
    }

    #[derive(Default)]
    struct PreviousStore {
        records: Vec<(RecordKind, StoredRecord)>,
        pending: Vec<RecordKind>,
        fail: Option<(RecordKind, bool)>,
    }

    impl PreviousStore {
        fn from_complete() -> Result<Self, Box<dyn Error>> {
            let records = complete()?;
            Ok(Self {
                records: vec![
                    (
                        RecordKind::PfReference,
                        records.acquisition.ok_or("missing acquisition")?,
                    ),
                    (
                        RecordKind::PfAnchorStage,
                        records.stage.ok_or("missing stage")?,
                    ),
                    (RecordKind::PfHook, records.hook.ok_or("missing hook")?),
                    (
                        RecordKind::PfHookRemoval,
                        records.removal.ok_or("missing removal")?,
                    ),
                    (
                        RecordKind::PfAnchorClear,
                        records.clear.ok_or("missing clear")?,
                    ),
                    (
                        RecordKind::PfReferenceRelease,
                        records.release.ok_or("missing release")?,
                    ),
                ],
                ..Self::default()
            })
        }
    }

    impl PreviousBootStore for PreviousStore {
        fn pending(&self, kind: RecordKind) -> Result<(), StoreError> {
            if self.pending.contains(&kind) {
                Err(StoreError::PendingRecord(kind))
            } else {
                Ok(())
            }
        }
        fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
            Ok(self
                .records
                .iter()
                .find(|(found, _)| *found == kind)
                .map(|(_, record)| record.clone()))
        }
        fn remove(&mut self, kind: RecordKind, expected: &StoredRecord) -> Result<(), StoreError> {
            if self.fail == Some((kind, false)) {
                return Err(StoreError::Refused("injected pre-removal error"));
            }
            let index = self
                .records
                .iter()
                .position(|(found, _)| *found == kind)
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
    }

    impl PreviousBootStore for UserRecordStore {
        fn pending(&self, kind: RecordKind) -> Result<(), StoreError> {
            self.require_no_pending(kind)
        }
        fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
            UserRecordStore::read(self, kind)
        }
        fn remove(&mut self, kind: RecordKind, expected: &StoredRecord) -> Result<(), StoreError> {
            self.remove_checked(kind, expected)
        }
    }

    #[test]
    fn previous_boot_cleanup_resumes_at_every_record_boundary() -> Result<(), Box<dyn Error>> {
        for kind in PREVIOUS_BOOT_KINDS {
            for after in [false, true] {
                let mut store = PreviousStore::from_complete()?;
                store.fail = Some((kind, after));
                assert!(
                    discard_previous_boot_with(&mut store, || Ok(OTHER_BOOT.to_owned())).is_err()
                );
                store.fail = None;
                let remaining = store.records.len();
                assert_eq!(
                    discard_previous_boot_with(&mut store, || Ok(OTHER_BOOT.to_owned()))?,
                    remaining
                );
                assert!(store.records.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn previous_boot_cleanup_resumes_after_reopening_the_store() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::Builder::new()
            .prefix("tunlatch-previous-boot-")
            .tempdir_in("/private/tmp")?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = directory.path().canonicalize()?;
        {
            let mut store = UserRecordStore::open(&path)?;
            for (kind, value) in PreviousStore::from_complete()?.records {
                store.replace(kind, &value)?;
            }
            for kind in PREVIOUS_BOOT_KINDS.into_iter().take(3) {
                let record = store.read(kind)?.ok_or("missing old record")?;
                store.remove_checked(kind, &record)?;
            }
        }
        let mut reopened = UserRecordStore::open(&path)?;
        assert_eq!(
            discard_previous_boot_with(&mut reopened, || Ok(OTHER_BOOT.to_owned()))?,
            3
        );
        for kind in PREVIOUS_BOOT_KINDS {
            assert!(reopened.read(kind)?.is_none());
        }
        Ok(())
    }

    #[test]
    fn previous_boot_cleanup_rejects_current_or_mixed_sessions_before_deleting()
    -> Result<(), Box<dyn Error>> {
        let mut store = PreviousStore::from_complete()?;
        let original = store.records.clone();
        assert!(discard_previous_boot_with(&mut store, || Ok(BOOT.to_owned())).is_err());
        assert_eq!(store.records, original);
        let index = store
            .records
            .iter()
            .position(|(kind, _)| *kind == RecordKind::PfHook)
            .ok_or("missing hook")?;
        let mut value: Value = serde_json::from_slice(store.records[index].1.payload())?;
        value["session"] = json!(vec![2_u8; 16]);
        store.records[index].1 = record(b"tunlatch-pf-hook-v1\0", value)?;
        let mixed = store.records.clone();
        assert!(discard_previous_boot_with(&mut store, || Ok(OTHER_BOOT.to_owned())).is_err());
        assert_eq!(store.records, mixed);
        Ok(())
    }

    #[test]
    fn previous_boot_cleanup_rejects_corrupt_or_mixed_boot_records() -> Result<(), Box<dyn Error>> {
        for corrupt in [false, true] {
            let mut store = PreviousStore::from_complete()?;
            let index = store
                .records
                .iter()
                .position(|(kind, _)| *kind == RecordKind::PfHook)
                .ok_or("missing hook")?;
            if corrupt {
                store.records[index].1 =
                    StoredRecord::new(store.records[index].1.identity(), b"corrupt".to_vec())?;
            } else {
                let mut value: Value = serde_json::from_slice(store.records[index].1.payload())?;
                value["boot_session"] = json!("abcdef01-2345-6789-abcd-ef0123456787");
                store.records[index].1 = record(b"tunlatch-pf-hook-v1\0", value)?;
            }
            let before = store.records.clone();
            assert!(discard_previous_boot_with(&mut store, || Ok(OTHER_BOOT.to_owned())).is_err());
            assert_eq!(store.records, before);
        }
        Ok(())
    }

    #[test]
    fn previous_boot_cleanup_preserves_pending_or_retirement_records() -> Result<(), Box<dyn Error>>
    {
        for kind in PREVIOUS_BOOT_KINDS
            .into_iter()
            .chain([RecordKind::PfRetirement])
        {
            let mut store = PreviousStore::from_complete()?;
            store.pending.push(kind);
            let original = store.records.clone();
            assert!(discard_previous_boot_with(&mut store, || Ok(OTHER_BOOT.to_owned())).is_err());
            assert_eq!(store.records, original);
        }
        let mut store = PreviousStore::from_complete()?;
        let marker = StoredRecord::new(RecordIdentity::new([9; 32])?, vec![])?;
        store.records.push((RecordKind::PfRetirement, marker));
        let original = store.records.clone();
        assert!(discard_previous_boot_with(&mut store, || Ok(OTHER_BOOT.to_owned())).is_err());
        assert_eq!(store.records, original);
        Ok(())
    }

    #[test]
    fn previous_boot_cleanup_stops_when_current_boot_changes() -> Result<(), Box<dyn Error>> {
        let mut store = PreviousStore::from_complete()?;
        let calls = std::cell::Cell::new(0);
        let result = discard_previous_boot_with(&mut store, || {
            let count = calls.get();
            calls.set(count + 1);
            Ok(if count < 3 { OTHER_BOOT } else { BOOT }.to_owned())
        });
        assert!(result.is_err());
        assert_eq!(store.records.len(), PREVIOUS_BOOT_KINDS.len() - 1);
        assert_eq!(
            discard_previous_boot_with(&mut store, || Ok(OTHER_BOOT.to_owned()))?,
            PREVIOUS_BOOT_KINDS.len() - 1
        );
        Ok(())
    }

    #[test]
    fn reports_recorded_phases_without_converting_them_to_protection() -> Result<(), Box<dyn Error>>
    {
        let records = complete()?;
        let (report, probe) = analyze(&records, BOOT)?;
        assert_eq!(report.boot, Boot::Current);
        assert_eq!(report.initial_pf, InitialPf::Unknown);
        assert_eq!(report.initial_reference_count, None);
        assert_eq!(report.acquisition, Recorded::Returned);
        assert_eq!(report.stage, Recorded::Returned);
        assert_eq!(report.hook, Recorded::Returned);
        assert_eq!(report.removal, Recorded::Returned);
        assert_eq!(report.clear, Recorded::Returned);
        assert_eq!(report.release, Recorded::Intent);
        assert_eq!(report.reference_observation, Observation::NotChecked);
        assert!(probe.is_some());
        let output = format!("{report:?}");
        assert!(!output.contains("42"));
        assert!(!output.contains("root_before"));
        let (old, probe) = analyze(&records, OTHER_BOOT)?;
        assert_eq!(old.boot, Boot::Different);
        assert!(probe.is_none());
        Ok(())
    }

    #[test]
    fn reports_a_valid_initial_baseline_without_exposing_its_digest() -> Result<(), Box<dyn Error>>
    {
        let mut records = Records {
            acquisition: Some(record(
                b"tunlatch-pf-reference-v1\0",
                json!({
                    "version": 2, "boot_session": BOOT, "session": vec![1_u8; 16],
                    "baseline": {"enabled": true, "reference_count": 2, "reference_digest": vec![7_u8; 32]},
                    "receipt": {"stage": "intent"}
                }),
            )?),
            ..Records::default()
        };
        let report = analyze(&records, BOOT)?.0;
        assert_eq!(report.initial_pf, InitialPf::Enabled);
        assert_eq!(report.initial_reference_count, Some(2));
        assert!(!format!("{report:?}").contains("reference_digest"));
        records.acquisition = Some(record(
            b"tunlatch-pf-reference-v1\0",
            json!({
                "version": 2, "boot_session": BOOT, "session": vec![1_u8; 16],
                "receipt": {"stage": "intent"}
            }),
        )?);
        assert!(analyze(&records, BOOT).is_err());
        Ok(())
    }

    #[test]
    fn rejects_orphan_corrupt_and_cross_session_records() -> Result<(), Box<dyn Error>> {
        let empty = Records::default();
        assert_eq!(analyze(&empty, BOOT)?.0.boot, Boot::NoRecords);
        let mut orphan = complete()?;
        orphan.acquisition = None;
        assert!(analyze(&orphan, BOOT).is_err());
        let mut bad = complete()?;
        let raw = bad.stage.as_ref().ok_or("missing fixture")?;
        bad.stage = Some(StoredRecord::new(
            RecordIdentity::new([7; 32])?,
            raw.payload().to_vec(),
        )?);
        assert!(analyze(&bad, BOOT).is_err());
        let mut bad = complete()?;
        let acquisition_id = bad
            .acquisition
            .as_ref()
            .ok_or("missing acquisition")?
            .identity()
            .to_string();
        bad.stage = Some(record(
            b"tunlatch-pf-anchor-stage-v1\0",
            json!({
                "version": 1, "boot_session": OTHER_BOOT, "session": vec![1_u8; 16],
                "interface": "en0", "acquisition_identity": acquisition_id, "stage": "committed"
            }),
        )?);
        assert!(analyze(&bad, BOOT).is_err());
        Ok(())
    }

    #[test]
    fn rejects_mismatched_hook_and_incomplete_operation_records() -> Result<(), Box<dyn Error>> {
        let mut records = complete()?;
        records.acquisition = Some(record(
            b"tunlatch-pf-reference-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": vec![1_u8; 16],
                "receipt": {"stage": "child_return", "pid": 123, "exit_code": 0,
                    "stdout": b"pf enabled\nToken : 42\n".to_vec(), "stderr": Vec::<u8>::new()}
            }),
        )?);
        assert!(analyze(&records, BOOT).is_err());
        let mut records = complete()?;
        let acquisition_id = records
            .acquisition
            .as_ref()
            .ok_or("missing acquisition")?
            .identity()
            .to_string();
        records.stage = Some(record(
            b"tunlatch-pf-anchor-stage-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": vec![1_u8; 16],
                "interface": "en1", "acquisition_identity": acquisition_id, "stage": "committed"
            }),
        )?);
        assert!(analyze(&records, BOOT).is_err());
        let mut records = complete()?;
        records.removal = Some(record(
            b"tunlatch-pf-hook-removal-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": vec![1_u8; 16],
                "index": 0, "ticket": 999, "stage_identity": "wrong", "hook_identity": "wrong", "stage": "returned"
            }),
        )?);
        assert!(analyze(&records, BOOT).is_err());
        let mut records = complete()?;
        let stage_id = records
            .stage
            .as_ref()
            .ok_or("missing stage")?
            .identity()
            .to_string();
        records.hook = Some(record(
            b"tunlatch-pf-hook-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": vec![1_u8; 16],
                "index": 0, "stage_identity": stage_id, "root_before": "anchor \"com.apple/*\" all\n"
            }),
        )?);
        assert!(analyze(&records, BOOT).is_err());
        let mut records = complete()?;
        records.acquisition = Some(record(
            b"tunlatch-pf-reference-v1\0",
            json!({
                "version": 1, "boot_session": BOOT, "session": vec![1_u8; 16],
                "receipt": {"stage": "child_return", "pid": 123,
                    "stdout": b"Token : 42\n".to_vec(), "stderr": Vec::<u8>::new()}
            }),
        )?);
        assert!(analyze(&records, BOOT).is_err());
        Ok(())
    }

    #[test]
    fn compares_saved_hook_ticket_and_unchanged_root_rules() -> Result<(), Box<dyn Error>> {
        let records = complete()?;
        let raw = records.hook.as_ref().ok_or("missing hook")?;
        let saved: Hook = decode(raw, b"tunlatch-pf-hook-v1\0")?;
        let session = [1_u8; 16];
        let name = anchor::anchor_name(session);
        let present = format!("anchor \"{name}\" all\n{}", saved.root_before);
        let ticket = NonZeroU64::new(456).ok_or("zero ticket")?;
        assert_eq!(
            classify_hook(
                session,
                &saved,
                Some(native_hook::Hook { index: 0, ticket }),
                present.as_bytes(),
                None,
            ),
            Observation::Matches
        );
        assert_eq!(
            classify_hook(session, &saved, None, saved.root_before.as_bytes(), None),
            Observation::Absent
        );
        assert_eq!(
            classify_hook(
                session,
                &saved,
                Some(native_hook::Hook { index: 1, ticket }),
                present.as_bytes(),
                None,
            ),
            Observation::Different
        );
        assert_eq!(
            classify_hook(session, &saved, None, b"pass all\n", None),
            Observation::Different
        );
        let changed_baseline = format!("{}pass out proto tcp all\n", saved.root_before);
        assert_eq!(
            classify_hook(
                session,
                &saved,
                None,
                changed_baseline.as_bytes(),
                Some(&changed_baseline)
            ),
            Observation::Absent
        );
        let mut pending = saved;
        pending.ticket = None;
        assert_eq!(
            classify_hook(
                session,
                &pending,
                Some(native_hook::Hook { index: 0, ticket }),
                present.as_bytes(),
                None,
            ),
            Observation::Different
        );
        Ok(())
    }

    #[test]
    fn version_two_removal_records_use_the_recorded_pre_removal_baseline()
    -> Result<(), Box<dyn Error>> {
        let mut records = complete()?;
        records.clear = None;
        records.release = None;
        let raw = records.removal.as_ref().ok_or("missing removal")?;
        let mut value: Value = serde_json::from_slice(raw.payload())?;
        value["version"] = json!(2);
        value["root_before"] = json!("anchor \"com.apple/*\" all\npass out all\n");
        records.removal = Some(record(b"tunlatch-pf-hook-removal-v1\0", value.clone())?);
        let (_, probe) = analyze(&records, BOOT)?;
        assert_eq!(
            probe
                .ok_or("missing current-boot probe")?
                .removal_baseline
                .as_deref(),
            Some("anchor \"com.apple/*\" all\npass out all\n")
        );
        value["root_before"] = json!("invalid rule\n");
        records.removal = Some(record(b"tunlatch-pf-hook-removal-v1\0", value)?);
        assert!(analyze(&records, BOOT).is_err());
        Ok(())
    }
}
