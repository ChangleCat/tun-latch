//! One-shot PF starter-reference acquisition with a durable intent and child receipt.
//!
//! There is deliberately no automatic retry or release. A saved receipt is a recovery hint,
//! not authorization to release a reference or evidence that traffic is protected.

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{qualification, reference, snapshot};
use crate::store::{RecordIdentity, RecordKind, StoreError, StoredRecord, SystemRecordStore};

const MAX_RETURN_BYTES: usize = 4096;

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
    // Keep the protected store's cooperating-writer lock for the entire live handle.
    // Dropping it never releases the PF reference or removes its durable receipt.
    _store: SystemRecordStore,
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
    /// PID reported by the completed `pfctl -E` child.
    pub fn creator_pid(&self) -> u32 {
        self.creator_pid
    }

    /// Token observed in the completed child return; treat it as sensitive.
    pub fn token(&self) -> reference::ReferenceToken {
        self.token
    }
}

#[derive(Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
enum Receipt {
    Intent,
    ChildReturn {
        pid: u32,
        exit_code: Option<i32>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
}

#[derive(Serialize)]
struct Record<'a> {
    version: u8,
    boot_session: &'a str,
    session: [u8; 16],
    receipt: Receipt,
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
}

trait Records {
    fn existing(&self) -> Result<bool, StoreError>;
    fn save(&mut self, record: &StoredRecord) -> Result<(), StoreError>;
}

impl Records for SystemRecordStore {
    fn existing(&self) -> Result<bool, StoreError> {
        Ok(self.read(RecordKind::PfReference)?.is_some())
    }

    fn save(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
        self.replace(RecordKind::PfReference, record)
    }
}

fn save(records: &mut impl Records, record: &Record<'_>) -> Result<(), AcquireError> {
    let payload = serde_json::to_vec(record)
        .map_err(|_| AcquireError::Refused("cannot encode reference record"))?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-reference-v1\0");
    hash.update(&payload);
    let identity = RecordIdentity::new(hash.finalize().into())?;
    records.save(&StoredRecord::new(identity, payload)?)?;
    Ok(())
}

/// Acquire one PF enable reference, recording intent before starting `/sbin/pfctl -E`.
///
/// Requires root and the provisioned fixed system store. Refuses any existing reference record,
/// including an unresolved earlier attempt. Enabling PF can activate other existing PF rules.
/// After a command or storage failure, inspect the protected record and PF state; do not retry
/// automatically. This function does not install rules, establish protection, or release PF.
/// The returned handle retains the store lock; dropping it never releases the PF reference.
/// The synchronous OS calls and child reaping can block beyond the nominal query deadline.
pub fn acquire_once() -> Result<AcquiredReference, AcquireError> {
    let mut store = SystemRecordStore::open()?;
    if store.existing()? {
        return Err(AcquireError::Refused("reference record already exists"));
    }
    qualification::check_root_filter()?;
    let boot = snapshot::boot_session()?;
    let mut session = [0_u8; 16];
    getrandom::fill(&mut session).map_err(|_| AcquireError::Random)?;
    if session == [0; 16] {
        return Err(AcquireError::Random);
    }
    let observed = acquire_with(
        &mut store,
        &boot,
        session,
        || {
            if snapshot::boot_session()? != boot {
                return Err(AcquireError::Unconfirmed);
            }
            let result = snapshot::acquire_reference()?;
            Ok(ChildReturn {
                pid: result.pid,
                exit_code: result.status.code(),
                stdout: result.stdout,
                stderr: result.stderr,
            })
        },
        || {
            if snapshot::boot_session()? != boot {
                return Err(AcquireError::Unconfirmed);
            }
            let references = snapshot::query(snapshot::Query::References)?;
            if snapshot::boot_session()? != boot {
                return Err(AcquireError::Unconfirmed);
            }
            Ok(references)
        },
    )?;
    Ok(AcquiredReference {
        token: observed.token,
        creator_pid: observed.creator_pid,
        _store: store,
    })
}

fn acquire_with(
    records: &mut impl Records,
    boot: &str,
    session: [u8; 16],
    execute: impl FnOnce() -> Result<ChildReturn, AcquireError>,
    read_references: impl FnOnce() -> Result<Vec<u8>, AcquireError>,
) -> Result<ObservedReference, AcquireError> {
    if records.existing()? || boot.is_empty() || session == [0; 16] {
        return Err(AcquireError::Refused(
            "existing or invalid reference session",
        ));
    }
    save(
        records,
        &Record {
            version: 1,
            boot_session: boot,
            session,
            receipt: Receipt::Intent,
        },
    )?;
    // Any failure after the intent is durable is indeterminate and must not be retried.
    let result = execute().map_err(|_| AcquireError::Unconfirmed)?;
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
        version: 1,
        boot_session: boot,
        session,
        receipt: Receipt::ChildReturn {
            pid,
            exit_code,
            stdout,
            stderr,
        },
    };
    // Save the complete child return before interpreting its contents or querying PF again.
    save(records, &receipt).map_err(|_| AcquireError::Unconfirmed)?;
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Memory {
        saved: Vec<Vec<u8>>,
        fail_at: Option<usize>,
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

    #[test]
    fn intent_precedes_execution_and_return_precedes_observation() -> Result<(), AcquireError> {
        let records = RefCell::new(Memory::default());
        let mut adapter = TestRecords(&records);
        let result = acquire_with(
            &mut adapter,
            "boot",
            [1; 16],
            || {
                assert!(String::from_utf8_lossy(&records.borrow().saved[0]).contains("intent"));
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
    }

    #[test]
    fn failed_persistence_prevents_execution_or_leaves_unresolved_intent() {
        for failed_write in [0, 1] {
            let mut records = Memory {
                saved: vec![],
                fail_at: Some(failed_write),
            };
            let invoked = std::cell::Cell::new(false);
            let result = acquire_with(
                &mut records,
                "boot",
                [1; 16],
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
            || Err(AcquireError::Unconfirmed),
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
                || Ok(child()),
                || Ok(LISTING.to_vec())
            )
            .is_err()
        );
    }
}
