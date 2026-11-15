//! A single live PF blocking session held by the privileged product daemon.
//!
//! This is an initial block-only backend, not a complete leak-protection policy. It keeps the
//! original reference and hook handles in memory and does not reconstruct ownership on restart.

use std::fs::File;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

use super::{
    anchor::{
        AttachedAnchor, ClearAuthorization, ClearedAnchor, DetachAuthorization, DetachedAnchor,
        HookAuthorization, StageAuthorization, StageError, StagedAnchor,
    },
    native_hook, qualification, recovery,
    reference_acquire::{
        self, AcquireError, AcquiredReference, ReleaseAuthorization, ReleaseError,
    },
    retirement::{self, RetirementError},
    rules, snapshot,
};
use crate::{
    network,
    store::{RecordKind, StoreError},
};

/// Failure during a live session. A failed operation may have changed PF; inspect its records.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The requested deployment, host, PF state or interface was not acceptable.
    #[error("PF session refused: {0}")]
    Refused(&'static str),
    /// The PF reference could not be acquired or verified.
    #[error("PF reference acquisition: {0}")]
    Acquire(#[from] AcquireError),
    /// The anchor or root hook could not be changed and verified.
    #[error("PF anchor operation: {0}")]
    Anchor(#[from] StageError),
    /// The PF reference could not be released and verified.
    #[error("PF reference release: {0}")]
    Release(#[from] ReleaseError),
    /// PF was released, but completed-record cleanup failed or is uncertain.
    #[error("PF reference was released, but record cleanup failed: {0}")]
    Cleanup(#[from] RetirementError),
    /// Startup failed before any anchor submission, and the unused reference was released.
    #[error("PF startup failed; the unused reference was released: {0}")]
    StartRolledBack(#[source] Box<SessionError>),
    /// A verified rollback could not be completed; records require inspection.
    #[error(
        "PF startup failed: {startup}; reference rollback or record cleanup failed: {rollback}"
    )]
    StartRollback {
        /// The original startup failure.
        startup: Box<SessionError>,
        /// The subsequent rollback or cleanup failure.
        rollback: Box<SessionError>,
    },
    /// Storage could not establish whether rollback was safe to attempt.
    #[error("cannot check PF startup records for safe rollback: {0}")]
    RollbackCheck(#[source] StoreError),
    /// An earlier PF operation has an unknown result and must be reconciled before retrying.
    #[error("PF {0:?} outcome is unconfirmed; inspect the protected records")]
    StopUnconfirmed(StopOperation),
}

/// The shutdown operation whose result could not be confirmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopOperation {
    /// Removal of the root hook.
    Detach,
    /// Clearing the session anchor.
    Clear,
    /// Releasing the session's PF reference.
    Release,
}

/// Last locally verified shutdown phase, not evidence of current packet protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionStatus {
    /// The initial hook was verified, but may have changed since that observation.
    Attached,
    /// Hook removal was verified; anchor clearing remains.
    Detached,
    /// Anchor clearing was verified; reference release remains.
    Cleared,
    /// Reference release was verified; local record retirement remains.
    Retiring,
    /// A PF operation might have occurred and cannot be retried from this handle.
    Unconfirmed(StopOperation),
    /// Shutdown and local record retirement completed.
    Stopped,
}

/// Startup checkpoint at which a live reference had to be retained for diagnosis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartPhase {
    /// Staging failed or could not be confirmed.
    Stage,
    /// Hook attachment failed or could not be confirmed.
    Attach,
    /// Releasing an otherwise-unused reference or retiring its records failed.
    Rollback,
}

/// A failed startup that still owns its original reference and protected store lock.
/// It cannot retry a PF mutation or turn saved records into cleanup authority.
pub struct InterruptedSession {
    reference: AcquiredReference,
    phase: StartPhase,
    staged: Option<StagedAnchor>,
}

impl std::fmt::Debug for InterruptedSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InterruptedSession")
            .field("phase", &self.phase)
            .field("has_staged_handle", &self.staged.is_some())
            .finish_non_exhaustive()
    }
}

impl InterruptedSession {
    /// Return the step at which startup stopped, not an observation of the current PF state.
    pub fn phase(&self) -> StartPhase {
        self.phase
    }

    /// Inspect protected records using this session's existing lock, without changing PF.
    pub fn inspect(&self) -> Result<recovery::Report, recovery::RecoveryError> {
        recovery::inspect_locked(&self.reference.store)
    }
}

/// Startup failure and, when available, the still-held session for read-only diagnosis.
#[derive(Debug, thiserror::Error)]
#[error("{source}")]
pub struct StartError {
    #[source]
    source: SessionError,
    interrupted: Option<Box<InterruptedSession>>,
}

impl StartError {
    /// Separate the failure from any still-held session. Dropping it never changes PF.
    pub fn into_parts(self) -> (SessionError, Option<InterruptedSession>) {
        (self.source, self.interrupted.map(|session| *session))
    }
}

enum Phase<A, D, C> {
    Attached(A),
    Detached(D),
    Cleared(C),
    Retiring,
    Stopped,
}

struct LiveSession<O: Operations> {
    reference: O::Reference,
    phase: Phase<O::Attached, O::Detached, O::Cleared>,
    unconfirmed: Option<StopOperation>,
}

impl<O: Operations> LiveSession<O> {
    fn status(&self) -> SessionStatus {
        if let Some(operation) = self.unconfirmed {
            return SessionStatus::Unconfirmed(operation);
        }
        match &self.phase {
            Phase::Attached(_) => SessionStatus::Attached,
            Phase::Detached(_) => SessionStatus::Detached,
            Phase::Cleared(_) => SessionStatus::Cleared,
            Phase::Retiring => SessionStatus::Retiring,
            Phase::Stopped => SessionStatus::Stopped,
        }
    }
}

/// A live, locked PF session. Dropping it never changes PF or proves protection.
pub struct BlockingSession {
    live: LiveSession<Native>,
}

trait Operations {
    type Reference;
    type Staged;
    type Attached;
    type Detached;
    type Cleared;

    fn acquire(&mut self) -> Result<Self::Reference, SessionError>;
    fn stage(
        &mut self,
        reference: &mut Self::Reference,
        interface: &str,
    ) -> Result<Self::Staged, SessionError>;
    /// Return true only if an unused reference was safely released and its records retired.
    fn abort_unstaged(&mut self, reference: &mut Self::Reference) -> Result<bool, SessionError>;
    fn attach(
        &mut self,
        reference: &mut Self::Reference,
        staged: &Self::Staged,
    ) -> Result<Self::Attached, SessionError>;
    fn detach(
        &mut self,
        reference: &mut Self::Reference,
        attached: &Self::Attached,
    ) -> Result<Self::Detached, SessionError>;
    fn clear(
        &mut self,
        reference: &mut Self::Reference,
        detached: &Self::Detached,
    ) -> Result<Self::Cleared, SessionError>;
    fn release(
        &mut self,
        reference: &mut Self::Reference,
        cleared: &Self::Cleared,
    ) -> Result<(), SessionError>;
    fn retire(&mut self, reference: &mut Self::Reference) -> Result<(), SessionError>;
    fn not_submitted(
        &mut self,
        reference: &Self::Reference,
        operation: StopOperation,
    ) -> Result<bool, SessionError>;
}

#[derive(Debug)]
enum StartFailure<R, S> {
    NoHandle(SessionError),
    Interrupted {
        source: SessionError,
        phase: StartPhase,
        reference: R,
        staged: Option<S>,
    },
}

type StartOutcome<O> = Result<
    (<O as Operations>::Reference, <O as Operations>::Attached),
    StartFailure<<O as Operations>::Reference, <O as Operations>::Staged>,
>;

fn start_with<O: Operations>(ops: &mut O, interface: &str) -> StartOutcome<O> {
    let mut reference = ops.acquire().map_err(StartFailure::NoHandle)?;
    let staged = match ops.stage(&mut reference, interface) {
        Ok(staged) => staged,
        Err(startup) => {
            return Err(match ops.abort_unstaged(&mut reference) {
                Ok(true) => {
                    StartFailure::NoHandle(SessionError::StartRolledBack(Box::new(startup)))
                }
                Ok(false) => StartFailure::Interrupted {
                    source: startup,
                    phase: StartPhase::Stage,
                    reference,
                    staged: None,
                },
                Err(rollback) => StartFailure::Interrupted {
                    source: SessionError::StartRollback {
                        startup: Box::new(startup),
                        rollback: Box::new(rollback),
                    },
                    phase: StartPhase::Rollback,
                    reference,
                    staged: None,
                },
            });
        }
    };
    let attached = match ops.attach(&mut reference, &staged) {
        Ok(attached) => attached,
        Err(source) => {
            return Err(StartFailure::Interrupted {
                source,
                phase: StartPhase::Attach,
                reference,
                staged: Some(staged),
            });
        }
    };
    Ok((reference, attached))
}

fn stop_with<O: Operations>(ops: &mut O, live: &mut LiveSession<O>) -> Result<(), SessionError> {
    if let Some(operation) = live.unconfirmed {
        return Err(SessionError::StopUnconfirmed(operation));
    }
    loop {
        let failed = match &live.phase {
            Phase::Attached(attached) => match ops.detach(&mut live.reference, attached) {
                Ok(detached) => {
                    live.phase = Phase::Detached(detached);
                    continue;
                }
                Err(error) => Some((StopOperation::Detach, error)),
            },
            Phase::Detached(detached) => match ops.clear(&mut live.reference, detached) {
                Ok(cleared) => {
                    live.phase = Phase::Cleared(cleared);
                    continue;
                }
                Err(error) => Some((StopOperation::Clear, error)),
            },
            Phase::Cleared(cleared) => match ops.release(&mut live.reference, cleared) {
                Ok(()) => {
                    live.phase = Phase::Retiring;
                    continue;
                }
                Err(error) => Some((StopOperation::Release, error)),
            },
            Phase::Retiring => {
                ops.retire(&mut live.reference)?;
                live.phase = Phase::Stopped;
                continue;
            }
            Phase::Stopped => return Ok(()),
        };
        if let Some((operation, error)) = failed {
            // A saved or unresolved intent means the kernel write may have run. A failed check
            // is equally uncertain. Only an explicitly confirmed absence allows a later retry.
            if !matches!(ops.not_submitted(&live.reference, operation), Ok(true)) {
                live.unconfirmed = Some(operation);
            }
            return Err(error);
        }
    }
}

struct Native;

impl Operations for Native {
    type Reference = AcquiredReference;
    type Staged = StagedAnchor;
    type Attached = AttachedAnchor;
    type Detached = DetachedAnchor;
    type Cleared = ClearedAnchor;

    fn acquire(&mut self) -> Result<Self::Reference, SessionError> {
        Ok(reference_acquire::acquire_initially_disabled()?)
    }
    fn stage(
        &mut self,
        reference: &mut Self::Reference,
        interface: &str,
    ) -> Result<Self::Staged, SessionError> {
        let session = reference.session;
        Ok(reference.stage_anchor(StageAuthorization {
            session,
            interface: interface.to_owned(),
        })?)
    }
    fn abort_unstaged(&mut self, reference: &mut Self::Reference) -> Result<bool, SessionError> {
        let safe = no_anchor_attempt(
            |kind| reference.store.require_no_pending(kind),
            |kind| reference.store.read(kind).map(|record| record.is_some()),
        )
        .map_err(SessionError::RollbackCheck)?;
        if !safe {
            return Ok(false);
        }
        let session = reference.session;
        let boot = reference.boot_session.clone();
        reference.release_borrowed(ReleaseAuthorization { session })?;
        retirement::begin_unstaged_reference(&mut reference.store, &boot, session)?;
        if !retirement::finish_locked(&mut reference.store)? {
            return Err(SessionError::Cleanup(RetirementError::Invalid(
                "completion marker disappeared",
            )));
        }
        Ok(true)
    }
    fn attach(
        &mut self,
        reference: &mut Self::Reference,
        staged: &Self::Staged,
    ) -> Result<Self::Attached, SessionError> {
        let session = reference.session;
        Ok(staged.attach(reference, HookAuthorization { session })?)
    }
    fn detach(
        &mut self,
        reference: &mut Self::Reference,
        attached: &Self::Attached,
    ) -> Result<Self::Detached, SessionError> {
        let session = reference.session;
        Ok(attached.detach(reference, DetachAuthorization { session })?)
    }
    fn clear(
        &mut self,
        reference: &mut Self::Reference,
        detached: &Self::Detached,
    ) -> Result<Self::Cleared, SessionError> {
        let session = reference.session;
        Ok(detached.clear(reference, ClearAuthorization { session })?)
    }
    fn release(
        &mut self,
        reference: &mut Self::Reference,
        cleared: &Self::Cleared,
    ) -> Result<(), SessionError> {
        let session = reference.session;
        let stored = reference
            .store
            .read(RecordKind::PfAnchorClear)
            .map_err(|_| SessionError::Refused("cannot read anchor clear record"))?
            .ok_or(SessionError::Refused("anchor clear record is missing"))?;
        if cleared.name() != super::anchor::anchor_name(session)
            || stored.identity() != cleared.record_identity()
        {
            return Err(SessionError::Refused("anchor clear record changed"));
        }
        reference.release_borrowed(ReleaseAuthorization { session })?;
        Ok(())
    }

    fn retire(&mut self, reference: &mut Self::Reference) -> Result<(), SessionError> {
        let session = reference.session;
        let boot = reference.boot_session.clone();
        retirement::complete_full(&mut reference.store, &boot, session)?;
        Ok(())
    }

    fn not_submitted(
        &mut self,
        reference: &Self::Reference,
        operation: StopOperation,
    ) -> Result<bool, SessionError> {
        let kind = match operation {
            StopOperation::Detach => RecordKind::PfHookRemoval,
            StopOperation::Clear => RecordKind::PfAnchorClear,
            StopOperation::Release => RecordKind::PfReferenceRelease,
        };
        reference
            .store
            .require_no_pending(kind)
            .map_err(SessionError::RollbackCheck)?;
        if reference
            .store
            .read(kind)
            .map_err(SessionError::RollbackCheck)?
            .is_some()
        {
            return Ok(false);
        }
        if operation == StopOperation::Release {
            reference
                .store
                .require_no_pending(RecordKind::PfRetirement)
                .map_err(SessionError::RollbackCheck)?;
            if reference
                .store
                .read(RecordKind::PfRetirement)
                .map_err(SessionError::RollbackCheck)?
                .is_some()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

const OTHER_RECORDS: [RecordKind; 6] = [
    RecordKind::PfAnchorStage,
    RecordKind::PfHook,
    RecordKind::PfHookRemoval,
    RecordKind::PfAnchorClear,
    RecordKind::PfReferenceRelease,
    RecordKind::PfRetirement,
];

fn no_anchor_attempt(
    mut pending: impl FnMut(RecordKind) -> Result<(), StoreError>,
    mut exists: impl FnMut(RecordKind) -> Result<bool, StoreError>,
) -> Result<bool, StoreError> {
    pending(RecordKind::PfReference)?;
    for kind in OTHER_RECORDS {
        pending(kind)?;
        if exists(kind)? {
            return Ok(false);
        }
    }
    Ok(true)
}

impl BlockingSession {
    /// Load and attach a block-all-outbound rule to an explicitly selected interface.
    ///
    /// This initial mode requires the fixed root-installed daemon, a previously disabled PF,
    /// and an existing, up, non-loopback interface. It can interrupt network connectivity and
    /// can activate existing PF rules. If no anchor submission was made, a failed stage attempts
    /// to release only the unused reference. Any unconfirmed operation retains diagnostic records
    /// and is never automatically retried. The rule has no system or proxy exceptions.
    pub fn start(interface: &str) -> Result<Self, StartError> {
        preflight(interface).map_err(|source| StartError {
            source,
            interrupted: None,
        })?;
        let (reference, anchor) =
            start_with(&mut Native, interface).map_err(|failure| match failure {
                StartFailure::NoHandle(source) => StartError {
                    source,
                    interrupted: None,
                },
                StartFailure::Interrupted {
                    source,
                    phase,
                    reference,
                    staged,
                } => StartError {
                    source,
                    interrupted: Some(Box::new(InterruptedSession {
                        reference,
                        phase,
                        staged,
                    })),
                },
            })?;
        Ok(Self {
            live: LiveSession {
                reference,
                phase: Phase::Attached(anchor),
                unconfirmed: None,
            },
        })
    }

    /// Return the last locally verified phase without claiming current protection.
    pub fn status(&self) -> SessionStatus {
        self.live.status()
    }

    /// Inspect records and available PF observations while retaining the session lock.
    pub fn inspect(&self) -> Result<recovery::Report, recovery::RecoveryError> {
        recovery::inspect_locked(&self.live.reference.store)
    }

    /// Detach the original hook, clear its anchor, and release only this session's reference.
    ///
    /// Operations stop at the first error and retain their live handles. A later explicit retry
    /// proceeds only if the failed operation was proved not submitted; unknown outcomes are
    /// refused. Retirement after a verified release can be retried without another PF write.
    pub fn stop(&mut self) -> Result<(), SessionError> {
        stop_with(&mut Native, &mut self.live)
    }
}

fn preflight(interface: &str) -> Result<(), SessionError> {
    rules::outbound_block(interface)
        .map_err(|_| SessionError::Refused("invalid interface name"))?;
    crate::store::check_fixed_daemon()
        .map_err(|_| SessionError::Refused("fixed protected root daemon required"))?;
    let interfaces =
        network::snapshot().map_err(|_| SessionError::Refused("interface enumeration failed"))?;
    if !interfaces
        .iter()
        .any(|candidate| candidate.name == interface && candidate.up && !candidate.loopback)
    {
        return Err(SessionError::Refused(
            "interface is missing, down, or loopback",
        ));
    }
    qualification::check_root_filter()
        .map_err(|_| SessionError::Refused("root filter qualification failed"))?;
    let (build, kernel) = snapshot::host_identity()
        .map_err(|_| SessionError::Refused("host identity unavailable"))?;
    let device: File = open(
        "/dev/pf",
        OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| SessionError::Refused("cannot open PF device for writing"))?
    .into();
    let writer =
        native_hook::Writer::new(&device, &build, &kernel, "10000000000000000000000000000000")
            .map_err(|_| SessionError::Refused("protected PF writer unavailable"))?;
    writer
        .index()
        .map_err(|_| SessionError::Refused("root insertion position unavailable"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;

    #[derive(Default)]
    struct Mock {
        calls: Vec<&'static str>,
        fail: Option<&'static str>,
        release_unstaged: bool,
        submitted: bool,
        check_fails: bool,
        rollback_fails: bool,
    }

    impl Mock {
        fn step(&mut self, name: &'static str) -> Result<(), SessionError> {
            self.calls.push(name);
            if self.fail == Some(name) {
                Err(SessionError::Refused("injected failure"))
            } else {
                Ok(())
            }
        }
    }

    impl Operations for Mock {
        type Reference = ();
        type Staged = ();
        type Attached = ();
        type Detached = ();
        type Cleared = ();

        fn acquire(&mut self) -> Result<(), SessionError> {
            self.step("acquire")
        }
        fn stage(&mut self, _: &mut (), interface: &str) -> Result<(), SessionError> {
            assert_eq!(interface, "en0");
            self.step("stage")
        }
        fn abort_unstaged(&mut self, _: &mut ()) -> Result<bool, SessionError> {
            self.step("abort_unstaged")?;
            if self.rollback_fails {
                return Err(SessionError::Refused("injected rollback failure"));
            }
            Ok(self.release_unstaged)
        }
        fn attach(&mut self, _: &mut (), _: &()) -> Result<(), SessionError> {
            self.step("attach")
        }
        fn detach(&mut self, _: &mut (), _: &()) -> Result<(), SessionError> {
            self.step("detach")
        }
        fn clear(&mut self, _: &mut (), _: &()) -> Result<(), SessionError> {
            self.step("clear")
        }
        fn release(&mut self, _: &mut (), _: &()) -> Result<(), SessionError> {
            self.step("release")
        }
        fn retire(&mut self, _: &mut ()) -> Result<(), SessionError> {
            self.step("retire")
        }
        fn not_submitted(&mut self, _: &(), _: StopOperation) -> Result<bool, SessionError> {
            if self.check_fails {
                Err(SessionError::Refused("cannot check intent"))
            } else {
                Ok(!self.submitted)
            }
        }
    }

    #[test]
    fn complete_session_follows_required_order() -> Result<(), SessionError> {
        let mut ops = Mock::default();
        let (reference, attached) = start_with(&mut ops, "en0")
            .map_err(|_| SessionError::Refused("test startup failed"))?;
        let mut live = LiveSession {
            reference,
            phase: Phase::Attached(attached),
            unconfirmed: None,
        };
        stop_with(&mut ops, &mut live)?;
        assert_eq!(live.status(), SessionStatus::Stopped);
        stop_with(&mut ops, &mut live)?;
        assert_eq!(
            ops.calls,
            [
                "acquire", "stage", "attach", "detach", "clear", "release", "retire"
            ]
        );
        Ok(())
    }

    #[test]
    fn failures_stop_the_sequence_without_automatic_cleanup_or_retry() {
        let startup = ["acquire", "stage", "attach"];
        for (index, fail) in startup.iter().enumerate() {
            let mut ops = Mock {
                fail: Some(fail),
                ..Mock::default()
            };
            assert!(start_with(&mut ops, "en0").is_err());
            let mut expected = startup[..=index].to_vec();
            if *fail == "stage" {
                expected.push("abort_unstaged");
            }
            assert_eq!(ops.calls, expected);
        }
        let shutdown = [
            ("detach", StopOperation::Detach),
            ("clear", StopOperation::Clear),
            ("release", StopOperation::Release),
        ];
        for (index, (fail, operation)) in shutdown.iter().enumerate() {
            let mut ops = Mock {
                fail: Some(fail),
                submitted: true,
                ..Mock::default()
            };
            let mut live = LiveSession {
                reference: (),
                phase: Phase::Attached(()),
                unconfirmed: None,
            };
            assert!(stop_with(&mut ops, &mut live).is_err());
            assert_eq!(live.status(), SessionStatus::Unconfirmed(*operation));
            let previous = ops.calls.clone();
            assert_eq!(
                previous,
                shutdown[..=index]
                    .iter()
                    .map(|item| item.0)
                    .collect::<Vec<_>>()
            );
            ops.fail = None;
            assert!(matches!(
                stop_with(&mut ops, &mut live),
                Err(SessionError::StopUnconfirmed(_))
            ));
            assert_eq!(ops.calls, previous);
        }
    }

    #[test]
    fn explicit_retry_resumes_only_a_provably_unsubmitted_shutdown_step() -> Result<(), SessionError>
    {
        for (fail, expected_status) in [
            ("detach", SessionStatus::Attached),
            ("clear", SessionStatus::Detached),
            ("release", SessionStatus::Cleared),
            ("retire", SessionStatus::Retiring),
        ] {
            let mut ops = Mock {
                fail: Some(fail),
                ..Mock::default()
            };
            let mut live = LiveSession {
                reference: (),
                phase: Phase::Attached(()),
                unconfirmed: None,
            };
            assert!(stop_with(&mut ops, &mut live).is_err());
            assert_eq!(live.status(), expected_status);
            let release_calls = ops.calls.iter().filter(|name| **name == "release").count();
            ops.fail = None;
            stop_with(&mut ops, &mut live)?;
            assert_eq!(live.status(), SessionStatus::Stopped);
            if fail == "retire" {
                assert_eq!(release_calls, 1);
                assert_eq!(
                    ops.calls.iter().filter(|name| **name == "release").count(),
                    1
                );
            }
        }
        Ok(())
    }

    #[test]
    fn inability_to_check_for_an_intent_is_also_unconfirmed() {
        let mut ops = Mock {
            fail: Some("detach"),
            check_fails: true,
            ..Mock::default()
        };
        let mut live = LiveSession {
            reference: (),
            phase: Phase::Attached(()),
            unconfirmed: None,
        };
        assert!(stop_with(&mut ops, &mut live).is_err());
        assert_eq!(
            live.status(),
            SessionStatus::Unconfirmed(StopOperation::Detach)
        );
    }

    #[test]
    fn stage_failure_reports_a_successfully_released_unused_reference() {
        let mut ops = Mock {
            fail: Some("stage"),
            release_unstaged: true,
            ..Mock::default()
        };
        assert!(matches!(
            start_with(&mut ops, "en0"),
            Err(StartFailure::NoHandle(SessionError::StartRolledBack(_)))
        ));
        assert_eq!(ops.calls, ["acquire", "stage", "abort_unstaged"]);
    }

    #[test]
    fn startup_failures_preserve_the_latest_available_handle() {
        let mut stage = Mock {
            fail: Some("stage"),
            ..Mock::default()
        };
        assert!(matches!(
            start_with(&mut stage, "en0"),
            Err(StartFailure::Interrupted {
                phase: StartPhase::Stage,
                staged: None,
                ..
            })
        ));
        let mut attach = Mock {
            fail: Some("attach"),
            ..Mock::default()
        };
        assert!(matches!(
            start_with(&mut attach, "en0"),
            Err(StartFailure::Interrupted {
                phase: StartPhase::Attach,
                staged: Some(()),
                ..
            })
        ));
        let mut rollback = Mock {
            fail: Some("stage"),
            rollback_fails: true,
            ..Mock::default()
        };
        assert!(matches!(
            start_with(&mut rollback, "en0"),
            Err(StartFailure::Interrupted {
                phase: StartPhase::Rollback,
                ..
            })
        ));
    }

    #[test]
    fn failed_start_and_stop_retain_owned_handles_until_the_session_is_dropped()
    -> Result<(), Box<dyn std::error::Error>> {
        struct Tracked {
            reference: Rc<()>,
            staged: Rc<()>,
        }
        impl Operations for Tracked {
            type Reference = Rc<()>;
            type Staged = Rc<()>;
            type Attached = Rc<()>;
            type Detached = Rc<()>;
            type Cleared = Rc<()>;
            fn acquire(&mut self) -> Result<Self::Reference, SessionError> {
                Ok(self.reference.clone())
            }
            fn stage(
                &mut self,
                _: &mut Self::Reference,
                _: &str,
            ) -> Result<Self::Staged, SessionError> {
                Ok(self.staged.clone())
            }
            fn abort_unstaged(&mut self, _: &mut Self::Reference) -> Result<bool, SessionError> {
                Ok(false)
            }
            fn attach(
                &mut self,
                _: &mut Self::Reference,
                _: &Self::Staged,
            ) -> Result<Self::Attached, SessionError> {
                Err(SessionError::Refused("injected attach failure"))
            }
            fn detach(
                &mut self,
                _: &mut Self::Reference,
                _: &Self::Attached,
            ) -> Result<Self::Detached, SessionError> {
                Err(SessionError::Refused("injected detach failure"))
            }
            fn clear(
                &mut self,
                _: &mut Self::Reference,
                _: &Self::Detached,
            ) -> Result<Self::Cleared, SessionError> {
                Err(SessionError::Refused("not reached"))
            }
            fn release(
                &mut self,
                _: &mut Self::Reference,
                _: &Self::Cleared,
            ) -> Result<(), SessionError> {
                Err(SessionError::Refused("not reached"))
            }
            fn retire(&mut self, _: &mut Self::Reference) -> Result<(), SessionError> {
                Err(SessionError::Refused("not reached"))
            }
            fn not_submitted(
                &mut self,
                _: &Self::Reference,
                _: StopOperation,
            ) -> Result<bool, SessionError> {
                Ok(false)
            }
        }
        let reference = Rc::new(());
        let staged = Rc::new(());
        let reference_weak = Rc::downgrade(&reference);
        let staged_weak = Rc::downgrade(&staged);
        let mut ops = Tracked { reference, staged };
        let failed = start_with(&mut ops, "en0");
        drop(ops);
        let Err(StartFailure::Interrupted {
            reference,
            staged: Some(staged),
            ..
        }) = failed
        else {
            return Err("test attach failure did not retain handles".into());
        };
        assert!(reference_weak.upgrade().is_some());
        assert!(staged_weak.upgrade().is_some());
        drop(reference);
        drop(staged);
        assert!(reference_weak.upgrade().is_none());
        assert!(staged_weak.upgrade().is_none());

        let reference = Rc::new(());
        let attached = Rc::new(());
        let reference_weak = Rc::downgrade(&reference);
        let attached_weak = Rc::downgrade(&attached);
        let mut live = LiveSession::<Tracked> {
            reference,
            phase: Phase::Attached(attached),
            unconfirmed: None,
        };
        let mut ops = Tracked {
            reference: Rc::new(()),
            staged: Rc::new(()),
        };
        assert!(stop_with(&mut ops, &mut live).is_err());
        assert!(reference_weak.upgrade().is_some());
        assert!(attached_weak.upgrade().is_some());
        drop(live);
        assert!(reference_weak.upgrade().is_none());
        assert!(attached_weak.upgrade().is_none());
        Ok(())
    }

    #[test]
    fn rollback_never_releases_when_any_anchor_or_pending_record_exists() {
        assert!(matches!(
            no_anchor_attempt(|_| Ok(()), |_| Ok(false)),
            Ok(true)
        ));
        for kind in OTHER_RECORDS {
            assert!(matches!(
                no_anchor_attempt(|_| Ok(()), |value| Ok(value == kind)),
                Ok(false)
            ));
        }
        for pending in OTHER_RECORDS.into_iter().chain([RecordKind::PfReference]) {
            assert!(
                no_anchor_attempt(
                    |kind| if kind == pending {
                        Err(StoreError::PendingRecord(kind))
                    } else {
                        Ok(())
                    },
                    |_| Ok(false),
                )
                .is_err()
            );
        }
    }
}
