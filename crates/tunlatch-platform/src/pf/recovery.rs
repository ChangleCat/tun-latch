//! Read-only inspection of protected PF operation records and current kernel observations.
//!
//! Records and non-atomic observations are recovery hints, never authority to mutate PF.

use std::fs::File;
use std::num::NonZeroU64;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{anchor, hook_readback, native_hook, reference, rules, snapshot};
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
}

/// What was durably recorded for an operation, not proof of kernel state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Recorded {
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
    identity(acquisition.version, boot, session, boot, session)?;
    report.boot = if boot == current_boot {
        Boot::Current
    } else {
        Boot::Different
    };
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
    if let Some(raw) = &records.removal {
        let value: Removal = decode(raw, b"tunlatch-pf-hook-removal-v1\0")?;
        identity(
            value.version,
            &value.boot_session,
            value.session,
            boot,
            session,
        )?;
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
        report.removal = phase(&value.stage, "returned")?;
    }
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
    let kinds = [
        RecordKind::PfReference,
        RecordKind::PfAnchorStage,
        RecordKind::PfHook,
        RecordKind::PfHookRemoval,
        RecordKind::PfAnchorClear,
        RecordKind::PfReferenceRelease,
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
            observe_hook(probe.session, saved).unwrap_or(Observation::Unavailable);
    }
}

fn observe_hook(session: [u8; 16], saved: &Hook) -> Result<Observation, RecoveryError> {
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
    Ok(classify_hook(session, saved, hook, &after))
}

fn classify_hook(
    session: [u8; 16],
    saved: &Hook,
    hook: Option<native_hook::Hook>,
    after: &[u8],
) -> Observation {
    let baseline = hook_readback::Observation {
        bytes: saved.root_before.as_bytes(),
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
    use crate::store::RecordIdentity;
    use serde_json::{Value, json};
    use std::error::Error;

    const BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456789";
    const OTHER_BOOT: &str = "abcdef01-2345-6789-abcd-ef0123456788";

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

    #[test]
    fn reports_recorded_phases_without_converting_them_to_protection() -> Result<(), Box<dyn Error>>
    {
        let records = complete()?;
        let (report, probe) = analyze(&records, BOOT)?;
        assert_eq!(report.boot, Boot::Current);
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
                present.as_bytes()
            ),
            Observation::Matches
        );
        assert_eq!(
            classify_hook(session, &saved, None, saved.root_before.as_bytes()),
            Observation::Absent
        );
        assert_eq!(
            classify_hook(
                session,
                &saved,
                Some(native_hook::Hook { index: 1, ticket }),
                present.as_bytes()
            ),
            Observation::Different
        );
        assert_eq!(
            classify_hook(session, &saved, None, b"pass all\n"),
            Observation::Different
        );
        let mut pending = saved;
        pending.ticket = None;
        assert_eq!(
            classify_hook(
                session,
                &pending,
                Some(native_hook::Hook { index: 0, ticket }),
                present.as_bytes()
            ),
            Observation::Different
        );
        Ok(())
    }
}
