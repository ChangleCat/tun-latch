//! Guarded PF anchor rule staging for the retained product session.
//!
//! Staging does not attach the anchor or prove that traffic is filtered. Its authorization has
//! no constructor until the privileged backend can establish resource ownership and scope.

use std::fs::File;
use std::num::NonZeroU64;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;
use pfctl::{AnchorChange, Transaction};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    hook_readback, native_hook, qualification, reference, reference_acquire::AcquiredReference,
    rules, snapshot,
};
use crate::store::{RecordIdentity, RecordKind, StoreError, StoredRecord, SystemRecordStore};

/// Authority to stage a rule for one approved interface and one live PF session.
///
/// No constructor is provided until the privileged backend verifies the interface, fresh anchor,
/// execution scope and writer coordination. Configuration or interface names do not grant it.
///
/// ```compile_fail
/// use tunlatch_platform::pf::anchor::StageAuthorization;
/// let _ = StageAuthorization { session: [1; 16], interface: "en0".into() };
/// ```
pub struct StageAuthorization {
    session: [u8; 16],
    interface: String,
}

/// Error while recording, submitting or observing an anchor rule transaction.
#[derive(Debug, thiserror::Error)]
pub enum StageError {
    /// The protected record could not be accessed before submission.
    #[error("PF anchor record error: {0}")]
    Store(#[from] StoreError),
    /// The session, scope, candidate or existing record was not acceptable.
    #[error("PF anchor operation refused: {0}")]
    Refused(&'static str),
    /// A PF write may have occurred but the complete outcome was not confirmed.
    #[error("PF anchor operation outcome is unconfirmed; inspect the protected record")]
    Unconfirmed,
}

/// A successful stage and independent rule readback, not a protection capability.
#[derive(Debug)]
pub struct StagedAnchor {
    session: [u8; 16],
    interface: String,
    stage_identity: RecordIdentity,
}

/// Authority to attach the staged anchor after checking root rules and writer coordination.
/// No constructor is available until those guarantees are established by the real backend.
///
/// ```compile_fail
/// use tunlatch_platform::pf::anchor::HookAuthorization;
/// let _ = HookAuthorization { session: [1; 16] };
/// ```
pub struct HookAuthorization {
    session: [u8; 16],
}

/// Authority to remove the exact hook after an explicit, verified shutdown decision.
/// There is no constructor until the privileged control and resource-ownership checks exist.
///
/// ```compile_fail
/// use tunlatch_platform::pf::anchor::DetachAuthorization;
/// let _ = DetachAuthorization { session: [1; 16] };
/// ```
pub struct DetachAuthorization {
    session: [u8; 16],
}

/// Authority to clear a detached, exclusively owned session anchor.
/// The product currently provides no constructor for this authority.
///
/// ```compile_fail
/// use tunlatch_platform::pf::anchor::ClearAuthorization;
/// let _ = ClearAuthorization { session: [1; 16] };
/// ```
pub struct ClearAuthorization {
    session: [u8; 16],
}

/// A root hook observed after insertion, without a claim of effective packet protection.
pub struct AttachedAnchor {
    session: [u8; 16],
    index: u32,
    ticket: NonZeroU64,
    interface: String,
    stage_identity: RecordIdentity,
    hook_identity: RecordIdentity,
    root_before: Vec<u8>,
}

impl std::fmt::Debug for AttachedAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachedAnchor")
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

/// A verified removal of the session hook; its anchor rules may still exist.
pub struct DetachedAnchor {
    session: [u8; 16],
    interface: String,
    stage_identity: RecordIdentity,
    removal_identity: RecordIdentity,
    root_before: Vec<u8>,
}

impl std::fmt::Debug for DetachedAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DetachedAnchor")
            .field("interface", &self.interface)
            .finish_non_exhaustive()
    }
}

/// A cleared session anchor observed after the transaction; this is not release authority.
#[derive(Debug)]
pub struct ClearedAnchor {
    session: [u8; 16],
    clear_identity: RecordIdentity,
}

impl ClearedAnchor {
    /// Name of the project anchor whose filter rules were cleared.
    pub fn name(&self) -> String {
        anchor_name(self.session)
    }
    /// Identity of the durable clear receipt; not an ownership or release capability.
    pub fn record_identity(&self) -> RecordIdentity {
        self.clear_identity
    }
}

impl DetachedAnchor {
    /// Name of the previously attached project anchor.
    pub fn name(&self) -> String {
        anchor_name(self.session)
    }
    /// Interface of the still-staged rule.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Clear only the detached session anchor's filter rules.
    ///
    /// The authority is currently unconstructible. Existing stage and removal receipts,
    /// current root rules, hook absence, anchor contents and PF reference are checked first.
    /// The transaction is recorded before submission; failures are never retried or cleaned up
    /// here. This does not release the PF reference or prove ownership against foreign writers.
    pub fn clear(
        self,
        owner: &mut AcquiredReference,
        authorization: ClearAuthorization,
    ) -> Result<ClearedAnchor, StageError> {
        if self.session != owner.session || authorization.session != self.session {
            return Err(StageError::Refused("anchor session mismatch"));
        }
        owner
            .recheck_current()
            .map_err(|_| StageError::Refused("PF reference session unavailable"))?;
        for (kind, identity) in [
            (RecordKind::PfAnchorStage, self.stage_identity),
            (RecordKind::PfHookRemoval, self.removal_identity),
        ] {
            let record = owner
                .store
                .read(kind)?
                .ok_or(StageError::Refused("original anchor record missing"))?;
            if record.identity() != identity {
                return Err(StageError::Refused("original anchor record changed"));
            }
        }
        qualification::check_root_filter()
            .map_err(|_| StageError::Refused("root filter qualification failed"))?;
        let (build, kernel) = snapshot::host_identity()
            .map_err(|_| StageError::Refused("host identity unavailable"))?;
        let device: File = open(
            "/dev/pf",
            OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| StageError::Refused("cannot open PF device"))?
        .into();
        let suffix = suffix(self.session);
        let name = self.name();
        let writer = native_hook::Writer::new(&device, &build, &kernel, &suffix)
            .map_err(|_| StageError::Refused("protected root writer unavailable"))?;
        let leaf = || {
            snapshot::query(snapshot::Query::AnchorRules { session: &suffix })
                .map_err(|_| StageError::Unconfirmed)
        };
        let boot = owner.boot_session.clone();
        let token = owner.token();
        let pid = owner.creator_pid();
        let check_reference = || -> Result<(), StageError> {
            if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot {
                return Err(StageError::Unconfirmed);
            }
            let refs = snapshot::query(snapshot::Query::References)
                .map_err(|_| StageError::Unconfirmed)?;
            if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot
                || !reference::contains_reference(&refs, token, pid)
                    .map_err(|_| StageError::Unconfirmed)?
            {
                return Err(StageError::Unconfirmed);
            }
            Ok(())
        };
        let verify_detached = || -> Result<(), StageError> {
            check_reference()?;
            if writer
                .observe()
                .map_err(|_| StageError::Unconfirmed)?
                .is_some()
            {
                return Err(StageError::Unconfirmed);
            }
            let current =
                snapshot::query(snapshot::Query::RootRules).map_err(|_| StageError::Unconfirmed)?;
            hook_readback::verify_detached(
                hook_readback::Observation {
                    bytes: &self.root_before,
                    complete: true,
                },
                hook_readback::Observation {
                    bytes: &current,
                    complete: true,
                },
                &name,
            )
            .map_err(|_| StageError::Unconfirmed)
        };
        verify_detached().map_err(|_| StageError::Refused("root hook or rules changed"))?;
        if !matches_block(&leaf()?, &self.interface) {
            return Err(StageError::Refused("staged anchor changed"));
        }
        let mut change = AnchorChange::new();
        change.set_filter_rules(Vec::new());
        let mut transaction = Transaction::new();
        transaction.add_change(&name, change);
        let context = ClearContext {
            boot: &boot,
            session: self.session,
            interface: &self.interface,
            stage_identity: self.stage_identity,
            removal_identity: self.removal_identity,
        };
        let clear_identity = clear_with(
            &mut owner.store,
            &context,
            || {
                verify_detached()?;
                if !matches_block(&leaf()?, &self.interface) {
                    return Err(StageError::Unconfirmed);
                }
                transaction.commit().map_err(|_| StageError::Unconfirmed)
            },
            || {
                verify_detached()?;
                if !leaf()?.is_empty() {
                    return Err(StageError::Unconfirmed);
                }
                Ok(())
            },
        )?;
        owner
            .recheck_current()
            .map_err(|_| StageError::Unconfirmed)?;
        Ok(ClearedAnchor {
            session: self.session,
            clear_identity,
        })
    }
}

impl AttachedAnchor {
    /// Name of the attached project anchor.
    pub fn name(&self) -> String {
        anchor_name(self.session)
    }
    /// Observed native filter index; subsequent changes can invalidate it.
    pub fn index(&self) -> u32 {
        self.index
    }
    /// The nonzero per-rule ticket returned by the native insertion.
    pub fn ticket(&self) -> NonZeroU64 {
        self.ticket
    }

    /// Remove this exact root hook after an explicit, independently authorized shutdown.
    ///
    /// The authorization is currently unconstructible. The original session lock and
    /// records must still match; intent is durable before deletion and the returned state
    /// is independently checked. An uncertain result is never retried or cleaned up here.
    /// This removes the hook but does not clear its anchor or release the PF reference.
    pub fn detach(
        self,
        owner: &mut AcquiredReference,
        authorization: DetachAuthorization,
    ) -> Result<DetachedAnchor, StageError> {
        if self.session != owner.session || authorization.session != self.session {
            return Err(StageError::Refused("hook session mismatch"));
        }
        owner
            .recheck_current()
            .map_err(|_| StageError::Refused("PF reference session unavailable"))?;
        for (kind, identity) in [
            (RecordKind::PfAnchorStage, self.stage_identity),
            (RecordKind::PfHook, self.hook_identity),
        ] {
            let record = owner
                .store
                .read(kind)?
                .ok_or(StageError::Refused("original anchor record missing"))?;
            if record.identity() != identity {
                return Err(StageError::Refused("original anchor record changed"));
            }
        }
        qualification::check_root_filter()
            .map_err(|_| StageError::Refused("root filter qualification failed"))?;
        let (build, kernel) = snapshot::host_identity()
            .map_err(|_| StageError::Refused("host identity unavailable"))?;
        let device: File = open(
            "/dev/pf",
            OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| StageError::Refused("cannot open PF device"))?
        .into();
        let suffix = suffix(self.session);
        let name = self.name();
        let writer = native_hook::Writer::new(&device, &build, &kernel, &suffix)
            .map_err(|_| StageError::Refused("protected root writer unavailable"))?;
        let leaf = || {
            snapshot::query(snapshot::Query::AnchorRules { session: &suffix })
                .map_err(|_| StageError::Unconfirmed)
        };
        let boot = owner.boot_session.clone();
        let token = owner.token();
        let pid = owner.creator_pid();
        let check_reference = || -> Result<(), StageError> {
            if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot {
                return Err(StageError::Unconfirmed);
            }
            let refs = snapshot::query(snapshot::Query::References)
                .map_err(|_| StageError::Unconfirmed)?;
            if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot
                || !reference::contains_reference(&refs, token, pid)
                    .map_err(|_| StageError::Unconfirmed)?
            {
                return Err(StageError::Unconfirmed);
            }
            Ok(())
        };
        let verify_attached = || -> Result<(), StageError> {
            check_reference()?;
            if writer.observe().map_err(|_| StageError::Unconfirmed)?
                != Some(native_hook::Hook {
                    index: self.index,
                    ticket: self.ticket,
                })
                || !matches_block(&leaf()?, &self.interface)
            {
                return Err(StageError::Unconfirmed);
            }
            let current =
                snapshot::query(snapshot::Query::RootRules).map_err(|_| StageError::Unconfirmed)?;
            hook_readback::verify(
                hook_readback::Observation {
                    bytes: &self.root_before,
                    complete: true,
                },
                hook_readback::Observation {
                    bytes: &current,
                    complete: true,
                },
                &name,
                self.index as usize,
            )
            .map_err(|_| StageError::Unconfirmed)
        };
        verify_attached().map_err(|_| StageError::Refused("original hook or rules changed"))?;
        let context = RemovalContext {
            boot: &boot,
            session: self.session,
            index: self.index,
            ticket: self.ticket,
            stage_identity: self.stage_identity,
            hook_identity: self.hook_identity,
        };
        let removal_identity = remove_with(
            &mut owner.store,
            &context,
            || {
                verify_attached()?;
                writer
                    .remove(self.index, self.ticket)
                    .map_err(|_| StageError::Unconfirmed)
            },
            || {
                check_reference()?;
                if writer
                    .observe()
                    .map_err(|_| StageError::Unconfirmed)?
                    .is_some()
                    || !matches_block(&leaf()?, &self.interface)
                {
                    return Err(StageError::Unconfirmed);
                }
                let current = snapshot::query(snapshot::Query::RootRules)
                    .map_err(|_| StageError::Unconfirmed)?;
                hook_readback::verify_detached(
                    hook_readback::Observation {
                        bytes: &self.root_before,
                        complete: true,
                    },
                    hook_readback::Observation {
                        bytes: &current,
                        complete: true,
                    },
                    &name,
                )
                .map_err(|_| StageError::Unconfirmed)
            },
        )?;
        owner
            .recheck_current()
            .map_err(|_| StageError::Unconfirmed)?;
        Ok(DetachedAnchor {
            session: self.session,
            interface: self.interface,
            stage_identity: self.stage_identity,
            removal_identity,
            root_before: self.root_before,
        })
    }
}

impl StagedAnchor {
    /// The product-owned anchor name corresponding to this staged session.
    pub fn name(&self) -> String {
        anchor_name(self.session)
    }
    /// Interface selected by the staged rule; identity and ongoing ownership are not proved.
    pub fn interface(&self) -> &str {
        &self.interface
    }

    /// Attach this staged anchor through the fixed native root-filter insertion.
    ///
    /// The authorization cannot currently be constructed. Intent and the returned per-rule
    /// ticket are durably recorded before independent native and textual readback. An error
    /// after insertion never triggers removal or retry. The fixed system daemon and its parent
    /// path must be root-owned and protected. This does not prove traffic is protected.
    pub fn attach(
        self,
        owner: &mut AcquiredReference,
        authorization: HookAuthorization,
    ) -> Result<AttachedAnchor, StageError> {
        if self.session != owner.session || authorization.session != self.session {
            return Err(StageError::Refused("hook session mismatch"));
        }
        owner
            .recheck_current()
            .map_err(|_| StageError::Refused("PF reference session unavailable"))?;
        let stage = owner
            .store
            .read(RecordKind::PfAnchorStage)?
            .ok_or(StageError::Refused("anchor stage record missing"))?;
        if stage.identity() != self.stage_identity {
            return Err(StageError::Refused("anchor stage record changed"));
        }
        qualification::check_root_filter()
            .map_err(|_| StageError::Refused("root filter qualification failed"))?;
        let (build, kernel) = snapshot::host_identity()
            .map_err(|_| StageError::Refused("host identity unavailable"))?;
        let device: File = open(
            "/dev/pf",
            OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| StageError::Refused("cannot open PF device"))?
        .into();
        let suffix = suffix(self.session);
        let name = self.name();
        let writer = native_hook::Writer::new(&device, &build, &kernel, &suffix)
            .map_err(|_| StageError::Refused("protected root writer unavailable"))?;
        let index = writer
            .index()
            .map_err(|_| StageError::Refused("root insertion position unavailable"))?;
        if writer
            .observe()
            .map_err(|_| StageError::Refused("root hook observation failed"))?
            .is_some()
        {
            return Err(StageError::Refused("root hook already exists"));
        }
        let baseline = snapshot::query(snapshot::Query::RootRules)
            .map_err(|_| StageError::Refused("root rules unavailable"))?;
        let text_rules = native_hook::parse_rules(&baseline)
            .map_err(|_| StageError::Refused("unsupported root rules"))?;
        let native_rules = native_hook::readonly_rules(&device, &build, &kernel)
            .map_err(|_| StageError::Refused("native root read failed"))?;
        if text_rules != native_rules
            || snapshot::query(snapshot::Query::RootRules)
                .map_err(|_| StageError::Refused("root rules unavailable"))?
                != baseline
        {
            return Err(StageError::Refused("root rules changed during inspection"));
        }
        hook_readback::validate_index(
            hook_readback::Observation {
                bytes: &baseline,
                complete: true,
            },
            &name,
            index as usize,
        )
        .map_err(StageError::Refused)?;
        let leaf = || {
            snapshot::query(snapshot::Query::AnchorRules { session: &suffix })
                .map_err(|_| StageError::Unconfirmed)
        };
        if !matches_block(&leaf()?, &self.interface) {
            return Err(StageError::Refused("staged anchor changed"));
        }
        let boot = owner.boot_session.clone();
        let token = owner.token();
        let pid = owner.creator_pid();
        let check_reference = || -> Result<(), StageError> {
            if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot {
                return Err(StageError::Unconfirmed);
            }
            let refs = snapshot::query(snapshot::Query::References)
                .map_err(|_| StageError::Unconfirmed)?;
            if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot
                || !reference::contains_reference(&refs, token, pid)
                    .map_err(|_| StageError::Unconfirmed)?
            {
                return Err(StageError::Unconfirmed);
            }
            Ok(())
        };
        let context = HookContext {
            boot: &boot,
            session: self.session,
            index,
            stage_identity: self.stage_identity,
            baseline: &baseline,
        };
        let (ticket, hook_identity) = attach_with(
            &mut owner.store,
            &context,
            || {
                check_reference()?;
                if snapshot::query(snapshot::Query::RootRules)
                    .map_err(|_| StageError::Unconfirmed)?
                    != baseline
                    || !matches_block(&leaf()?, &self.interface)
                {
                    return Err(StageError::Unconfirmed);
                }
                writer.insert(index).map_err(|_| StageError::Unconfirmed)
            },
            |ticket| {
                check_reference()?;
                if writer.observe().map_err(|_| StageError::Unconfirmed)?
                    != Some(native_hook::Hook { index, ticket })
                    || !matches_block(&leaf()?, &self.interface)
                {
                    return Err(StageError::Unconfirmed);
                }
                let current = snapshot::query(snapshot::Query::RootRules)
                    .map_err(|_| StageError::Unconfirmed)?;
                hook_readback::verify(
                    hook_readback::Observation {
                        bytes: &baseline,
                        complete: true,
                    },
                    hook_readback::Observation {
                        bytes: &current,
                        complete: true,
                    },
                    &name,
                    index as usize,
                )
                .map_err(|_| StageError::Unconfirmed)?;
                Ok(())
            },
        )?;
        owner
            .recheck_current()
            .map_err(|_| StageError::Unconfirmed)?;
        Ok(AttachedAnchor {
            session: self.session,
            index,
            ticket,
            interface: self.interface,
            stage_identity: self.stage_identity,
            hook_identity,
            root_before: baseline,
        })
    }
}

impl AcquiredReference {
    /// Stage one stateless outbound drop rule in the session anchor using a PF transaction.
    ///
    /// The authorization is currently unconstructible. The protected session lock is retained,
    /// intent is persisted before submission, and one independent readback follows. Neither a
    /// successful transaction nor this readback verifies root attachment, TUN identity, old
    /// states or effective protection. The synchronous PF transaction may block indefinitely.
    pub fn stage_anchor(
        &mut self,
        authorization: StageAuthorization,
    ) -> Result<StagedAnchor, StageError> {
        if authorization.session != self.session {
            return Err(StageError::Refused("authorization session mismatch"));
        }
        let interface = authorization.interface;
        let rule = rules::outbound_block(&interface)
            .map_err(|_| StageError::Refused("invalid interface or rule"))?;
        self.recheck_current()
            .map_err(|_| StageError::Refused("PF reference session unavailable"))?;
        let session = self.session;
        let boot = self.boot_session.clone();
        let suffix = suffix(session);
        let token = self.token();
        let pid = self.creator_pid();
        let mut change = AnchorChange::new();
        change.set_filter_rules(vec![rule]);
        let mut transaction = Transaction::new();
        transaction.add_change(&anchor_name(session), change);
        let read = || {
            snapshot::query(snapshot::Query::AnchorRules { session: &suffix })
                .map_err(|_| StageError::Unconfirmed)
        };
        let stage_identity = stage_with(
            &mut self.store,
            &boot,
            session,
            &interface,
            self.acquisition_identity,
            read,
            || {
                if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot {
                    return Err(StageError::Unconfirmed);
                }
                let listing = snapshot::query(snapshot::Query::References)
                    .map_err(|_| StageError::Unconfirmed)?;
                if snapshot::boot_session().map_err(|_| StageError::Unconfirmed)? != boot
                    || !reference::contains_reference(&listing, token, pid)
                        .map_err(|_| StageError::Unconfirmed)?
                {
                    return Err(StageError::Unconfirmed);
                }
                transaction.commit().map_err(|_| StageError::Unconfirmed)
            },
        )?;
        self.recheck_current()
            .map_err(|_| StageError::Unconfirmed)?;
        Ok(StagedAnchor {
            session,
            interface,
            stage_identity,
        })
    }
}

pub(super) fn suffix(session: [u8; 16]) -> String {
    session.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn anchor_name(session: [u8; 16]) -> String {
    format!("tunlatch-lab-{}", suffix(session))
}

#[derive(Serialize)]
struct StageRecord<'a> {
    version: u8,
    boot_session: &'a str,
    session: [u8; 16],
    interface: &'a str,
    acquisition_identity: String,
    stage: &'static str,
}

trait StageRecords {
    fn stage_exists(&self) -> Result<bool, StoreError>;
    fn save_stage(&mut self, value: &StoredRecord) -> Result<(), StoreError>;
}

impl StageRecords for SystemRecordStore {
    fn stage_exists(&self) -> Result<bool, StoreError> {
        Ok(self.read(RecordKind::PfAnchorStage)?.is_some())
    }
    fn save_stage(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
        self.replace(RecordKind::PfAnchorStage, value)
    }
}

fn save(
    records: &mut impl StageRecords,
    record: &StageRecord<'_>,
) -> Result<RecordIdentity, StageError> {
    let payload = serde_json::to_vec(record)
        .map_err(|_| StageError::Refused("cannot encode stage record"))?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-anchor-stage-v1\0");
    hash.update(&payload);
    let identity = RecordIdentity::new(hash.finalize().into())?;
    records.save_stage(&StoredRecord::new(identity, payload)?)?;
    Ok(identity)
}

fn stage_with(
    records: &mut impl StageRecords,
    boot: &str,
    session: [u8; 16],
    interface: &str,
    acquisition_identity: RecordIdentity,
    read: impl Fn() -> Result<Vec<u8>, StageError>,
    submit: impl FnOnce() -> Result<(), StageError>,
) -> Result<RecordIdentity, StageError> {
    if session == [0; 16] || boot.is_empty() || records.stage_exists()? {
        return Err(StageError::Refused("existing or invalid anchor session"));
    }
    if !read()?.is_empty() {
        return Err(StageError::Refused("anchor is not empty"));
    }
    let mut record = StageRecord {
        version: 1,
        boot_session: boot,
        session,
        interface,
        acquisition_identity: acquisition_identity.to_string(),
        stage: "intent",
    };
    save(records, &record)?;
    submit().map_err(|_| StageError::Unconfirmed)?;
    record.stage = "committed";
    let identity = save(records, &record).map_err(|_| StageError::Unconfirmed)?;
    let observed = read().map_err(|_| StageError::Unconfirmed)?;
    if !matches_block(&observed, interface) {
        return Err(StageError::Unconfirmed);
    }
    Ok(identity)
}

struct HookContext<'a> {
    boot: &'a str,
    session: [u8; 16],
    index: u32,
    stage_identity: RecordIdentity,
    baseline: &'a [u8],
}

#[derive(Serialize)]
struct HookRecord<'a> {
    version: u8,
    boot_session: &'a str,
    session: [u8; 16],
    index: u32,
    stage_identity: String,
    root_before: &'a str,
    ticket: Option<u64>,
}

trait HookRecords {
    fn hook_exists(&self) -> Result<bool, StoreError>;
    fn save_hook(&mut self, value: &StoredRecord) -> Result<(), StoreError>;
}

impl HookRecords for SystemRecordStore {
    fn hook_exists(&self) -> Result<bool, StoreError> {
        Ok(self.read(RecordKind::PfHook)?.is_some())
    }
    fn save_hook(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
        self.replace(RecordKind::PfHook, value)
    }
}

fn save_hook(
    records: &mut impl HookRecords,
    record: &HookRecord<'_>,
) -> Result<RecordIdentity, StageError> {
    let payload =
        serde_json::to_vec(record).map_err(|_| StageError::Refused("cannot encode hook record"))?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-hook-v1\0");
    hash.update(&payload);
    let identity = RecordIdentity::new(hash.finalize().into())?;
    records.save_hook(&StoredRecord::new(identity, payload)?)?;
    Ok(identity)
}

fn attach_with(
    records: &mut impl HookRecords,
    context: &HookContext<'_>,
    insert: impl FnOnce() -> Result<NonZeroU64, StageError>,
    observe: impl FnOnce(NonZeroU64) -> Result<(), StageError>,
) -> Result<(NonZeroU64, RecordIdentity), StageError> {
    if context.session == [0; 16] || context.boot.is_empty() || records.hook_exists()? {
        return Err(StageError::Refused("existing or invalid hook session"));
    }
    let baseline = std::str::from_utf8(context.baseline)
        .map_err(|_| StageError::Refused("invalid root baseline"))?;
    let mut record = HookRecord {
        version: 1,
        boot_session: context.boot,
        session: context.session,
        index: context.index,
        stage_identity: context.stage_identity.to_string(),
        root_before: baseline,
        ticket: None,
    };
    save_hook(records, &record)?;
    let ticket = insert().map_err(|_| StageError::Unconfirmed)?;
    record.ticket = Some(ticket.get());
    let identity = save_hook(records, &record).map_err(|_| StageError::Unconfirmed)?;
    observe(ticket).map_err(|_| StageError::Unconfirmed)?;
    Ok((ticket, identity))
}

struct RemovalContext<'a> {
    boot: &'a str,
    session: [u8; 16],
    index: u32,
    ticket: NonZeroU64,
    stage_identity: RecordIdentity,
    hook_identity: RecordIdentity,
}

#[derive(Serialize)]
struct RemovalRecord<'a> {
    version: u8,
    boot_session: &'a str,
    session: [u8; 16],
    index: u32,
    ticket: u64,
    stage_identity: String,
    hook_identity: String,
    stage: &'static str,
}

trait RemovalRecords {
    fn removal_exists(&self) -> Result<bool, StoreError>;
    fn save_removal(&mut self, value: &StoredRecord) -> Result<(), StoreError>;
}

impl RemovalRecords for SystemRecordStore {
    fn removal_exists(&self) -> Result<bool, StoreError> {
        Ok(self.read(RecordKind::PfHookRemoval)?.is_some())
    }
    fn save_removal(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
        self.replace(RecordKind::PfHookRemoval, value)
    }
}

fn save_removal(
    records: &mut impl RemovalRecords,
    record: &RemovalRecord<'_>,
) -> Result<RecordIdentity, StageError> {
    let payload = serde_json::to_vec(record)
        .map_err(|_| StageError::Refused("cannot encode hook removal record"))?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-hook-removal-v1\0");
    hash.update(&payload);
    let identity = RecordIdentity::new(hash.finalize().into())?;
    records.save_removal(&StoredRecord::new(identity, payload)?)?;
    Ok(identity)
}

fn remove_with(
    records: &mut impl RemovalRecords,
    context: &RemovalContext<'_>,
    remove: impl FnOnce() -> Result<(), StageError>,
    observe: impl FnOnce() -> Result<(), StageError>,
) -> Result<RecordIdentity, StageError> {
    if context.session == [0; 16] || context.boot.is_empty() || records.removal_exists()? {
        return Err(StageError::Refused("existing or invalid hook removal"));
    }
    let mut record = RemovalRecord {
        version: 1,
        boot_session: context.boot,
        session: context.session,
        index: context.index,
        ticket: context.ticket.get(),
        stage_identity: context.stage_identity.to_string(),
        hook_identity: context.hook_identity.to_string(),
        stage: "intent",
    };
    save_removal(records, &record)?;
    remove().map_err(|_| StageError::Unconfirmed)?;
    record.stage = "returned";
    let identity = save_removal(records, &record).map_err(|_| StageError::Unconfirmed)?;
    observe().map_err(|_| StageError::Unconfirmed)?;
    Ok(identity)
}

struct ClearContext<'a> {
    boot: &'a str,
    session: [u8; 16],
    interface: &'a str,
    stage_identity: RecordIdentity,
    removal_identity: RecordIdentity,
}

#[derive(Serialize)]
struct ClearRecord<'a> {
    version: u8,
    boot_session: &'a str,
    session: [u8; 16],
    interface: &'a str,
    stage_identity: String,
    removal_identity: String,
    stage: &'static str,
}

trait ClearRecords {
    fn clear_exists(&self) -> Result<bool, StoreError>;
    fn save_clear(&mut self, value: &StoredRecord) -> Result<(), StoreError>;
}

impl ClearRecords for SystemRecordStore {
    fn clear_exists(&self) -> Result<bool, StoreError> {
        Ok(self.read(RecordKind::PfAnchorClear)?.is_some())
    }
    fn save_clear(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
        self.replace(RecordKind::PfAnchorClear, value)
    }
}

fn save_clear(
    records: &mut impl ClearRecords,
    record: &ClearRecord<'_>,
) -> Result<RecordIdentity, StageError> {
    let payload = serde_json::to_vec(record)
        .map_err(|_| StageError::Refused("cannot encode anchor clear record"))?;
    let mut hash = Sha256::new();
    hash.update(b"tunlatch-pf-anchor-clear-v1\0");
    hash.update(&payload);
    let identity = RecordIdentity::new(hash.finalize().into())?;
    records.save_clear(&StoredRecord::new(identity, payload)?)?;
    Ok(identity)
}

fn clear_with(
    records: &mut impl ClearRecords,
    context: &ClearContext<'_>,
    submit: impl FnOnce() -> Result<(), StageError>,
    observe: impl FnOnce() -> Result<(), StageError>,
) -> Result<RecordIdentity, StageError> {
    if context.session == [0; 16] || context.boot.is_empty() || records.clear_exists()? {
        return Err(StageError::Refused("existing or invalid anchor clear"));
    }
    let mut record = ClearRecord {
        version: 1,
        boot_session: context.boot,
        session: context.session,
        interface: context.interface,
        stage_identity: context.stage_identity.to_string(),
        removal_identity: context.removal_identity.to_string(),
        stage: "intent",
    };
    save_clear(records, &record)?;
    submit().map_err(|_| StageError::Unconfirmed)?;
    record.stage = "committed";
    let identity = save_clear(records, &record).map_err(|_| StageError::Unconfirmed)?;
    observe().map_err(|_| StageError::Unconfirmed)?;
    Ok(identity)
}

pub(super) fn matches_block(raw: &[u8], interface: &str) -> bool {
    if raw.len() > 512
        || !raw.is_ascii()
        || !raw.ends_with(b"\n")
        || raw
            .iter()
            .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t'))
    {
        return false;
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return false;
    };
    let mut lines = text.lines();
    let Some(line) = lines.next() else {
        return false;
    };
    if lines.next().is_some() {
        return false;
    }
    let words: Vec<_> = line.split_ascii_whitespace().collect();
    words == ["block", "drop", "out", "quick", "on", interface, "all"]
        || words
            == [
                "block", "drop", "out", "quick", "on", interface, "all", "no", "state",
            ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[derive(Default)]
    struct Memory {
        records: Vec<Vec<u8>>,
        fail_at: Option<usize>,
    }
    struct Store<'a>(&'a RefCell<Memory>);
    impl StageRecords for Store<'_> {
        fn stage_exists(&self) -> Result<bool, StoreError> {
            Ok(!self.0.borrow().records.is_empty())
        }
        fn save_stage(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
            let mut state = self.0.borrow_mut();
            if state.fail_at == Some(state.records.len()) {
                return Err(StoreError::Refused("injected failure"));
            }
            state.records.push(value.payload().to_vec());
            Ok(())
        }
    }
    impl HookRecords for Store<'_> {
        fn hook_exists(&self) -> Result<bool, StoreError> {
            self.stage_exists()
        }
        fn save_hook(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
            self.save_stage(value)
        }
    }
    impl RemovalRecords for Store<'_> {
        fn removal_exists(&self) -> Result<bool, StoreError> {
            self.stage_exists()
        }
        fn save_removal(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
            self.save_stage(value)
        }
    }
    impl ClearRecords for Store<'_> {
        fn clear_exists(&self) -> Result<bool, StoreError> {
            self.stage_exists()
        }
        fn save_clear(&mut self, value: &StoredRecord) -> Result<(), StoreError> {
            self.save_stage(value)
        }
    }
    #[test]
    fn stages_only_after_intent_and_checks_independent_rules() -> Result<(), StageError> {
        let state = RefCell::new(Memory::default());
        let mut store = Store(&state);
        let reads = Cell::new(0);
        stage_with(
            &mut store,
            "boot",
            [1; 16],
            "en0",
            RecordIdentity::new([2; 32])?,
            || {
                let n = reads.get();
                reads.set(n + 1);
                if n == 0 {
                    Ok(vec![])
                } else {
                    assert!(
                        String::from_utf8_lossy(&state.borrow().records[1]).contains("committed")
                    );
                    Ok(b"block drop out quick on en0 all\n".to_vec())
                }
            },
            || {
                assert!(String::from_utf8_lossy(&state.borrow().records[0]).contains("intent"));
                Ok(())
            },
        )?;
        assert_eq!(reads.get(), 2);
        Ok(())
    }
    #[test]
    fn failure_retains_intent_and_prevents_replay() -> Result<(), StageError> {
        let state = RefCell::new(Memory {
            records: vec![],
            fail_at: Some(1),
        });
        let mut store = Store(&state);
        let reads = Cell::new(0);
        let result = stage_with(
            &mut store,
            "boot",
            [1; 16],
            "en0",
            RecordIdentity::new([2; 32])?,
            || {
                reads.set(reads.get() + 1);
                Ok(vec![])
            },
            || Ok(()),
        );
        assert!(matches!(result, Err(StageError::Unconfirmed)));
        assert_eq!(reads.get(), 1);
        assert_eq!(state.borrow().records.len(), 1);
        assert!(
            stage_with(
                &mut store,
                "boot",
                [1; 16],
                "en0",
                RecordIdentity::new([2; 32])?,
                || Ok(vec![]),
                || Ok(())
            )
            .is_err()
        );
        Ok(())
    }
    #[test]
    fn rule_reader_rejects_broader_or_changed_rules() {
        for valid in [
            "block drop out quick on en0 all\n",
            "block drop out quick on en0 all no state\n",
        ] {
            assert!(matches_block(valid.as_bytes(), "en0"));
        }
        for invalid in [
            "block drop out on en0 all\n",
            "pass out quick on en0 all\n",
            "block drop out quick on en1 all\n",
            "block drop out quick on en0 all keep state\n",
            "block drop out quick on en0 all\npass all\n",
            "block drop out quick on en0 all",
        ] {
            assert!(!matches_block(invalid.as_bytes(), "en0"));
        }
    }

    #[test]
    fn hook_receipt_is_durable_before_independent_observation() -> Result<(), StageError> {
        let state = RefCell::new(Memory::default());
        let mut store = Store(&state);
        let context = HookContext {
            boot: "boot",
            session: [1; 16],
            index: 1,
            stage_identity: RecordIdentity::new([1; 32])?,
            baseline: b"pass all\n",
        };
        let ticket = NonZeroU64::new(42).ok_or(StageError::Unconfirmed)?;
        let result = attach_with(
            &mut store,
            &context,
            || {
                assert!(
                    String::from_utf8_lossy(&state.borrow().records[0]).contains("\"ticket\":null")
                );
                Ok(ticket)
            },
            |observed| {
                assert_eq!(observed, ticket);
                assert!(
                    String::from_utf8_lossy(&state.borrow().records[1]).contains("\"ticket\":42")
                );
                Ok(())
            },
        )?;
        assert_eq!(result.0, ticket);
        Ok(())
    }

    #[test]
    fn hook_unconfirmed_after_insert_is_never_replayed() -> Result<(), StageError> {
        let state = RefCell::new(Memory {
            records: vec![],
            fail_at: Some(1),
        });
        let mut store = Store(&state);
        let context = HookContext {
            boot: "boot",
            session: [1; 16],
            index: 1,
            stage_identity: RecordIdentity::new([1; 32])?,
            baseline: b"pass all\n",
        };
        let ticket = NonZeroU64::new(42).ok_or(StageError::Unconfirmed)?;
        let observed = Cell::new(false);
        assert!(matches!(
            attach_with(
                &mut store,
                &context,
                || Ok(ticket),
                |_| {
                    observed.set(true);
                    Ok(())
                }
            ),
            Err(StageError::Unconfirmed)
        ));
        assert!(!observed.get());
        assert_eq!(state.borrow().records.len(), 1);
        assert!(attach_with(&mut store, &context, || Ok(ticket), |_| Ok(())).is_err());
        Ok(())
    }

    #[test]
    fn shutdown_records_intents_before_mutations_and_receipts_before_reads()
    -> Result<(), StageError> {
        let stage_identity = RecordIdentity::new([1; 32])?;
        let hook_identity = RecordIdentity::new([2; 32])?;
        let ticket = NonZeroU64::new(42).ok_or(StageError::Unconfirmed)?;
        let state = RefCell::new(Memory::default());
        let mut store = Store(&state);
        let removal = RemovalContext {
            boot: "boot",
            session: [3; 16],
            index: 1,
            ticket,
            stage_identity,
            hook_identity,
        };
        let removal_identity = remove_with(
            &mut store,
            &removal,
            || {
                assert!(String::from_utf8_lossy(&state.borrow().records[0]).contains("intent"));
                Ok(())
            },
            || {
                assert!(String::from_utf8_lossy(&state.borrow().records[1]).contains("returned"));
                Ok(())
            },
        )?;
        let state = RefCell::new(Memory::default());
        let mut store = Store(&state);
        let clear = ClearContext {
            boot: "boot",
            session: [3; 16],
            interface: "en0",
            stage_identity,
            removal_identity,
        };
        clear_with(
            &mut store,
            &clear,
            || {
                assert!(String::from_utf8_lossy(&state.borrow().records[0]).contains("intent"));
                Ok(())
            },
            || {
                assert!(String::from_utf8_lossy(&state.borrow().records[1]).contains("committed"));
                Ok(())
            },
        )?;
        Ok(())
    }

    #[test]
    fn failed_shutdown_observation_leaves_records_and_forbids_replay() -> Result<(), StageError> {
        let stage_identity = RecordIdentity::new([1; 32])?;
        let hook_identity = RecordIdentity::new([2; 32])?;
        let ticket = NonZeroU64::new(42).ok_or(StageError::Unconfirmed)?;
        let state = RefCell::new(Memory::default());
        let mut store = Store(&state);
        let removal = RemovalContext {
            boot: "boot",
            session: [3; 16],
            index: 1,
            ticket,
            stage_identity,
            hook_identity,
        };
        assert!(matches!(
            remove_with(
                &mut store,
                &removal,
                || Ok(()),
                || Err(StageError::Unconfirmed)
            ),
            Err(StageError::Unconfirmed)
        ));
        assert_eq!(state.borrow().records.len(), 2);
        let retried = Cell::new(false);
        assert!(
            remove_with(
                &mut store,
                &removal,
                || {
                    retried.set(true);
                    Ok(())
                },
                || Ok(())
            )
            .is_err()
        );
        assert!(!retried.get());
        let state = RefCell::new(Memory {
            records: vec![],
            fail_at: Some(0),
        });
        let mut store = Store(&state);
        let clear = ClearContext {
            boot: "boot",
            session: [3; 16],
            interface: "en0",
            stage_identity,
            removal_identity: hook_identity,
        };
        let submitted = Cell::new(false);
        assert!(
            clear_with(
                &mut store,
                &clear,
                || {
                    submitted.set(true);
                    Ok(())
                },
                || Ok(())
            )
            .is_err()
        );
        assert!(!submitted.get());
        Ok(())
    }

    #[test]
    fn clearing_after_commit_failure_preserves_the_intent_and_does_not_retry()
    -> Result<(), StageError> {
        let state = RefCell::new(Memory {
            records: vec![],
            fail_at: Some(1),
        });
        let mut store = Store(&state);
        let context = ClearContext {
            boot: "boot",
            session: [3; 16],
            interface: "en0",
            stage_identity: RecordIdentity::new([1; 32])?,
            removal_identity: RecordIdentity::new([2; 32])?,
        };
        let submissions = Cell::new(0);
        let observed = Cell::new(false);
        assert!(matches!(
            clear_with(
                &mut store,
                &context,
                || {
                    submissions.set(submissions.get() + 1);
                    Ok(())
                },
                || {
                    observed.set(true);
                    Ok(())
                }
            ),
            Err(StageError::Unconfirmed)
        ));
        assert_eq!(state.borrow().records.len(), 1);
        assert!(!observed.get());
        assert!(
            clear_with(
                &mut store,
                &context,
                || {
                    submissions.set(submissions.get() + 1);
                    Ok(())
                },
                || Ok(())
            )
            .is_err()
        );
        assert_eq!(submissions.get(), 1);
        Ok(())
    }
}
