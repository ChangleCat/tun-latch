//! Pure lifecycle ordering for a future coordinator and enforcement adapter.
//!
//! This reducer performs no I/O and authenticates neither callers nor evidence. Its actions are
//! reconciliation requirements, never authority to write PF or permit packets. In particular,
//! `Verified` means only that caller-supplied internal evidence matched the current operation.
//! It is not an externally reportable protected state, a trusted TUN, or an enforcement capability.
//! The existing read-only status and isolated simulation contracts remain separate.
//!
//! The owner must serialize events, authenticate their producers, retain operation-id history,
//! allocate a fresh service epoch after every restart, and tick with its monotonic clock before
//! publishing observations. A digest must cover the complete effective policy, including UID
//! grants, physical scopes, system exceptions and their generations; a config-only digest cannot
//! establish that identity. Nothing here supplies those missing platform guarantees.

use thiserror::Error;

use crate::config::DesiredProtection;

/// Caller-computed digest of the complete effective enforcement plan, not a config digest.
///
/// The trusted planner must hash normalized policy, UID approvals, physical scopes, TUN binding,
/// system exceptions and state-revocation requirements with a separate domain. This wrapper
/// only rejects the unset value; it authenticates neither that calculation nor its authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EffectivePolicyDigest([u8; 32]);

impl EffectivePolicyDigest {
    /// Wrap a complete-plan digest. Ordinary `PolicyDigest` is intentionally not convertible.
    pub fn new(bytes: [u8; 32]) -> Result<Self, TransitionError> {
        if bytes == [0; 32] {
            return Err(TransitionError::InvalidPolicyDigest);
        }
        Ok(Self(bytes))
    }

    /// Return the exact opaque digest bytes, never an authorization credential.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact correlation identity, not a privilege or proof that the represented policy exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    /// Fresh owner-allocated service epoch; old-process completions must never share it.
    pub service_epoch: [u8; 16],
    /// Reducer-assigned, monotonically advancing policy generation within this epoch.
    pub generation: u64,
    /// Nonzero coordinator-owned operation identifier.
    pub operation_id: u64,
    /// Content identity of the complete effective policy, not an authorization credential.
    pub policy_digest: EffectivePolicyDigest,
    /// Requested intent, including an explicit release of this product's own policy only.
    pub desired: DesiredProtection,
}

/// A compare-and-swap request; accepting it does not establish authorization or kernel state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransitionRequest {
    /// Nonzero identifier whose cross-generation deduplication belongs to the coordinator.
    pub operation_id: u64,
    /// Generation expected before accepting this request.
    pub expected_generation: u64,
    /// Digest of the complete effective policy to reconcile.
    pub policy_digest: EffectivePolicyDigest,
    /// New intent, independent of the last acknowledged or observed policy.
    pub desired: DesiredProtection,
}

/// Ordering checkpoint for one operation. Terminal uncertainty requires a new generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitPhase {
    /// The request was accepted in memory; no persistence acknowledgment was received.
    Requested,
    /// The owner reports the exact intent durably recorded, before any kernel submission.
    IntentDurable,
    /// The adapter acknowledged the exact operation; independent evidence is still required.
    KernelAcknowledged,
    /// Matching fresh independent evidence was accepted, with no public protection claim.
    KernelVerified,
    /// A definitive failure was reported before a kernel commit was acknowledged.
    Rejected,
    /// Whether the operation reached or still matches the kernel is unknown.
    OutcomeUnknown,
    /// A continuity, clock or freshness failure revoked this generation's observation.
    Invalidated,
}

/// Current operation checkpoint, returned by value so callers cannot mutate the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CurrentOperation {
    /// Full identity that every completion must echo exactly.
    pub identity: OperationIdentity,
    /// Last accepted lifecycle checkpoint.
    pub phase: CommitPhase,
}

/// Caller-supplied independent observation. This data is not authenticated by the reducer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerificationEvidence {
    /// Exact operation independently observed by the trusted adapter boundary.
    pub identity: OperationIdentity,
    /// Nonzero trusted collector counter; each renewal must advance it.
    pub observation_sequence: u64,
    /// Collection time in the owner's monotonic millisecond epoch.
    pub observed_at: u64,
    /// Exclusive freshness deadline in the same monotonic epoch.
    pub valid_until: u64,
}

/// Internal evidence bookkeeping, deliberately distinct from public protection status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationState {
    /// No currently acceptable evidence establishes even an internal policy match.
    Unknown {
        /// Why reconciliation or fresh evidence is required.
        reason: ReconcileReason,
    },
    /// Caller evidence matched, subject to producer trust and its exclusive freshness deadline.
    Verified(VerificationEvidence),
}

/// Closed reasons for reconciliation; none authorize a system operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileReason {
    /// No independent observation has been received in this service instance.
    NotObserved,
    /// The current desired generation has not yet been independently verified.
    PendingOperation,
    /// An acknowledgment requires a separate fresh kernel read.
    KernelAcknowledged,
    /// Intent persistence definitively failed before submission.
    IntentNotDurable,
    /// The adapter definitively rejected submission before committing.
    KernelRejected,
    /// Submission, persistence or subsequent observation has an ambiguous outcome.
    OutcomeUnknown,
    /// An old, terminal or uncorrelated submission reported a possible kernel mutation.
    UncorrelatedKernelResult,
    /// Continuous TUN identity or ownership can no longer be established.
    TunTrustLost,
    /// PF was disabled or its rules/state were changed outside this operation.
    PfChanged,
    /// Independent observations are unavailable or incomplete.
    ObservationUnavailable,
    /// Accepted evidence reached its exclusive freshness deadline.
    ObservationExpired,
    /// The supplied monotonic time moved backwards, so freshness is no longer established.
    ClockRegressed,
    /// Startup records are hints requiring new independent inspection.
    Recovery,
}

/// Requirements for a future owner. These values do not authorize executing their side effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionAction {
    /// Durably record this exact intent before scheduling its policy submission.
    PersistIntent(OperationIdentity),
    /// Schedule reconciliation of the exact policy using separately established authority.
    /// Disabled means release only explicitly owned resources; never globally disable PF.
    SubmitPolicy(OperationIdentity),
    /// Independently inspect current kernel state; the optional identity is only a locator.
    Inspect {
        /// Current operation or an untrusted recovery-record hint.
        identity: Option<OperationIdentity>,
        /// Why inspection is required.
        reason: ReconcileReason,
    },
    /// Reconcile ordinary traffic toward blocking, retaining separately valid UID grants.
    /// This is neither evidence that blocking happened nor authority to change PF.
    RequireBlocking {
        /// Superseded operation or recovery hint; never authority to reuse old allow rules.
        identity: Option<OperationIdentity>,
        /// Why the owner must establish its fail-closed policy through a new operation.
        reason: ReconcileReason,
    },
}

/// Internal completion and invalidation events, never client-submitted authority DTOs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransitionEvent {
    /// Durable storage acknowledged the exact intent, including parent-directory durability.
    IntentDurable(OperationIdentity),
    /// Persistence definitively failed and no kernel submission was started.
    IntentNotDurable(OperationIdentity),
    /// The enforcement adapter acknowledged the exact submitted operation.
    KernelAcknowledged(OperationIdentity),
    /// The adapter definitively rejected it without committing.
    KernelRejected(OperationIdentity),
    /// Fresh separate observation of the complete effective policy, not a submit return code.
    IndependentlyVerified(VerificationEvidence),
    /// Any boundary could not establish the operation's outcome.
    OutcomeUnknown(OperationIdentity),
    /// TUN evidence/continuity was lost; this cannot be reversed by an old completion.
    TunTrustLost,
    /// An external PF disable, replacement or relevant state change was detected.
    PfChanged,
    /// A required independent observation failed or was incomplete.
    ObservationUnavailable,
    /// A client waiter left; the owner and operation continue without rollback or cancellation.
    ClientTimedOut(OperationIdentity),
    /// Check evidence freshness with the `now` argument, including before publication.
    Tick,
}

/// A disk record is only a recovery locator, regardless of its recorded successful phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryHint {
    /// No record was found; this does not prove that no kernel resources remain.
    Missing,
    /// A structurally checked record, still incapable of restoring current kernel evidence.
    Recorded(CurrentOperation),
    /// The record could not be read; do not interpret it as disabled.
    Unavailable,
    /// A damaged, truncated or unsupported record; do not interpret it as disabled.
    Corrupt,
}

/// Deterministic rejection; callers must inspect lifecycle state rather than treating `Ok` as
/// protected. A successfully processed invalidation also returns `Ok` and reconciliation actions.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TransitionError {
    /// An all-zero digest is reserved for an unset complete-policy identity.
    #[error("effective policy digest must be nonzero")]
    InvalidPolicyDigest,
    /// An all-zero epoch cannot distinguish service instances.
    #[error("service epoch must be nonzero")]
    InvalidEpoch,
    /// A recovery record proves the supplied epoch is not fresh.
    #[error("recovery must use a fresh service epoch")]
    EpochReused,
    /// Operation zero is reserved and must never identify a request.
    #[error("operation identifier must be nonzero")]
    InvalidOperationId,
    /// Compare-and-swap generation did not match.
    #[error("policy generation conflict")]
    Conflict,
    /// The current operation identifier was reused with different request contents.
    #[error("operation identifier reused with different contents")]
    OperationIdReused,
    /// Generation arithmetic exhausted; no new operation was accepted.
    #[error("policy generation exhausted")]
    GenerationExhausted,
    /// There is no current operation to complete.
    #[error("no current operation")]
    NoCurrentOperation,
    /// Epoch, generation, identifier, digest or desired intent did not exactly match.
    #[error("completion identity mismatch")]
    IdentityMismatch,
    /// A stage was skipped, or a terminal operation received a late completion.
    #[error("completion is out of order")]
    OutOfOrder,
    /// Evidence has zero sequence, a malformed/future window, or is already expired.
    #[error("invalid or expired verification evidence")]
    InvalidEvidence,
    /// A renewal reused/regressed a collector sequence or observation time.
    #[error("verification evidence did not advance")]
    StaleEvidence,
}

/// Small deterministic reducer, with desired, acknowledged and observed facts kept separate.
#[derive(Debug)]
pub struct ProtectionLifecycle {
    service_epoch: [u8; 16],
    generation: u64,
    desired: DesiredProtection,
    current: Option<CurrentOperation>,
    current_request: Option<TransitionRequest>,
    committed: Option<OperationIdentity>,
    observed: VerificationState,
    acknowledged_at: Option<u64>,
    last_now: Option<u64>,
    recovery_hint: Option<RecoveryHint>,
}

impl ProtectionLifecycle {
    /// Start with unknown kernel state and no acknowledged policy. Initial intent is not trust.
    /// Persisted startup must instead use [`Self::recover`] and process its inspection actions.
    pub fn new(
        service_epoch: [u8; 16],
        desired: DesiredProtection,
    ) -> Result<Self, TransitionError> {
        if service_epoch == [0; 16] {
            return Err(TransitionError::InvalidEpoch);
        }
        Ok(Self {
            service_epoch,
            generation: 0,
            desired,
            current: None,
            current_request: None,
            committed: None,
            observed: VerificationState::Unknown {
                reason: ReconcileReason::NotObserved,
            },
            acknowledged_at: None,
            last_now: None,
            recovery_hint: None,
        })
    }

    /// Retain disk data only as hints, with no current operation, commit or verified observation.
    /// A fresh epoch is required. Missing records still require inspection; unreadable/corrupt
    /// records require blocking even when the separately supplied initial intent is disabled.
    pub fn recover(
        service_epoch: [u8; 16],
        desired: DesiredProtection,
        hint: RecoveryHint,
    ) -> Result<(Self, Vec<TransitionAction>), TransitionError> {
        let mut state = Self::new(service_epoch, desired)?;
        let hint = match hint {
            RecoveryHint::Recorded(operation)
                if operation.identity.service_epoch == [0; 16]
                    || operation.identity.generation == 0
                    || operation.identity.operation_id == 0 =>
            {
                RecoveryHint::Corrupt
            }
            hint => hint,
        };
        if let RecoveryHint::Recorded(operation) = hint
            && operation.identity.service_epoch == service_epoch
        {
            return Err(TransitionError::EpochReused);
        }
        let identity = match hint {
            RecoveryHint::Recorded(operation) => Some(operation.identity),
            _ => None,
        };
        let must_block = desired == DesiredProtection::Enabled
            || identity.is_some_and(|identity| identity.desired == DesiredProtection::Enabled)
            || matches!(hint, RecoveryHint::Unavailable | RecoveryHint::Corrupt);
        state.recovery_hint = Some(hint);
        state.observed = VerificationState::Unknown {
            reason: ReconcileReason::Recovery,
        };
        let actions = reconciliation(identity, ReconcileReason::Recovery, must_block);
        Ok((state, actions))
    }

    /// Current in-process generation, starting at zero independently of disk hints.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Latest accepted desired intent; it is never a kernel-state assertion.
    pub fn desired(&self) -> DesiredProtection {
        self.desired
    }

    /// Current operation checkpoint, including terminal uncertainty.
    pub fn current(&self) -> Option<CurrentOperation> {
        self.current
    }

    /// Last exactly acknowledged operation, retained as historical fact after invalidation.
    /// It does not establish what is currently installed or observed.
    pub fn committed(&self) -> Option<OperationIdentity> {
        self.committed
    }

    /// Internal observation at the last applied monotonic time. Tick before publishing it.
    /// `Verified` must never be mapped directly to the public protected state.
    pub fn observed(&self) -> VerificationState {
        self.observed
    }

    /// Original recovery locator, never a restored commit or source of enforcement authority.
    pub fn recovery_hint(&self) -> Option<RecoveryHint> {
        self.recovery_hint
    }

    /// Accept a new generation, immediately invalidating previous observed success.
    /// An identical retry of the current request emits no duplicate side effects. The owner
    /// retains older request identities/outcomes; this reducer deliberately has no history map.
    pub fn request(
        &mut self,
        request: TransitionRequest,
    ) -> Result<Vec<TransitionAction>, TransitionError> {
        if request.operation_id == 0 {
            return Err(TransitionError::InvalidOperationId);
        }
        if let Some(current) = self.current_request
            && request.operation_id == current.operation_id
        {
            return if request == current {
                Ok(Vec::new())
            } else {
                Err(TransitionError::OperationIdReused)
            };
        }
        if request.expected_generation != self.generation {
            return Err(TransitionError::Conflict);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(TransitionError::GenerationExhausted)?;
        let identity = OperationIdentity {
            service_epoch: self.service_epoch,
            generation,
            operation_id: request.operation_id,
            policy_digest: request.policy_digest,
            desired: request.desired,
        };
        self.generation = generation;
        self.desired = request.desired;
        self.current = Some(CurrentOperation {
            identity,
            phase: CommitPhase::Requested,
        });
        self.current_request = Some(request);
        self.acknowledged_at = None;
        self.observed = VerificationState::Unknown {
            reason: ReconcileReason::PendingOperation,
        };
        let mut actions = vec![TransitionAction::PersistIntent(identity)];
        if self.desired == DesiredProtection::Enabled {
            actions.push(TransitionAction::RequireBlocking {
                identity: Some(identity),
                reason: ReconcileReason::PendingOperation,
            });
        }
        Ok(actions)
    }

    /// Apply one trusted-owner event at a monotonic millisecond time. `Ok` means processed,
    /// never protected. Clock regression or expiry takes precedence over the supplied event,
    /// invalidates the current operation and returns reconciliation actions. The owner must
    /// submit a new generation after such a failure; late evidence cannot resurrect this one.
    pub fn apply(
        &mut self,
        event: TransitionEvent,
        now: u64,
    ) -> Result<Vec<TransitionAction>, TransitionError> {
        if self.last_now.is_some_and(|previous| now < previous) {
            return Ok(self.invalidate(ReconcileReason::ClockRegressed));
        }
        self.last_now = Some(now);
        if let VerificationState::Verified(evidence) = self.observed
            && now >= evidence.valid_until
        {
            return Ok(self.invalidate(ReconcileReason::ObservationExpired));
        }
        match event {
            TransitionEvent::Tick => Ok(Vec::new()),
            TransitionEvent::TunTrustLost => Ok(self.invalidate(ReconcileReason::TunTrustLost)),
            TransitionEvent::PfChanged => Ok(self.invalidate(ReconcileReason::PfChanged)),
            TransitionEvent::ObservationUnavailable => {
                Ok(self.invalidate(ReconcileReason::ObservationUnavailable))
            }
            TransitionEvent::ClientTimedOut(identity) => {
                self.match_current(identity)?;
                Ok(Vec::new())
            }
            TransitionEvent::IntentDurable(identity) => {
                let phase = self.match_current(identity)?;
                match phase {
                    CommitPhase::Requested => {
                        self.set_phase(CommitPhase::IntentDurable);
                        Ok(vec![TransitionAction::SubmitPolicy(identity)])
                    }
                    CommitPhase::IntentDurable
                    | CommitPhase::KernelAcknowledged
                    | CommitPhase::KernelVerified => Ok(Vec::new()),
                    _ => Err(TransitionError::OutOfOrder),
                }
            }
            TransitionEvent::KernelAcknowledged(identity) => {
                match self.match_current(identity) {
                    Ok(CommitPhase::IntentDurable) => {
                        self.set_phase(CommitPhase::KernelAcknowledged);
                        self.committed = Some(identity);
                        self.acknowledged_at = Some(now);
                        Ok(vec![TransitionAction::Inspect {
                            identity: Some(identity),
                            reason: ReconcileReason::KernelAcknowledged,
                        }])
                    }
                    Ok(CommitPhase::KernelAcknowledged | CommitPhase::KernelVerified) => {
                        Ok(Vec::new())
                    }
                    // A late write acknowledgment may mean the kernel changed after a newer
                    // policy. Rejecting its identity alone cannot preserve the newer evidence.
                    _ => Ok(self.invalidate(ReconcileReason::UncorrelatedKernelResult)),
                }
            }
            TransitionEvent::IndependentlyVerified(evidence) => self.verify(evidence, now),
            TransitionEvent::IntentNotDurable(identity) => {
                if self.match_current(identity)? != CommitPhase::Requested {
                    return Err(TransitionError::OutOfOrder);
                }
                Ok(self.reject(ReconcileReason::IntentNotDurable))
            }
            TransitionEvent::KernelRejected(identity) => {
                if self.match_current(identity)? != CommitPhase::IntentDurable {
                    return Err(TransitionError::OutOfOrder);
                }
                Ok(self.reject(ReconcileReason::KernelRejected))
            }
            TransitionEvent::OutcomeUnknown(identity) => {
                if self.match_current(identity).is_err() {
                    return Ok(self.invalidate(ReconcileReason::UncorrelatedKernelResult));
                }
                self.set_phase(CommitPhase::OutcomeUnknown);
                self.observed = VerificationState::Unknown {
                    reason: ReconcileReason::OutcomeUnknown,
                };
                Ok(reconciliation(
                    Some(identity),
                    ReconcileReason::OutcomeUnknown,
                    self.desired == DesiredProtection::Enabled,
                ))
            }
        }
    }

    fn match_current(&self, identity: OperationIdentity) -> Result<CommitPhase, TransitionError> {
        let current = self.current.ok_or(TransitionError::NoCurrentOperation)?;
        if current.identity != identity {
            return Err(TransitionError::IdentityMismatch);
        }
        Ok(current.phase)
    }

    fn set_phase(&mut self, phase: CommitPhase) {
        if let Some(current) = &mut self.current {
            current.phase = phase;
        }
    }

    fn verify(
        &mut self,
        evidence: VerificationEvidence,
        now: u64,
    ) -> Result<Vec<TransitionAction>, TransitionError> {
        if !matches!(
            self.match_current(evidence.identity)?,
            CommitPhase::KernelAcknowledged | CommitPhase::KernelVerified
        ) {
            return Err(TransitionError::OutOfOrder);
        }
        if evidence.observation_sequence == 0
            || evidence.observed_at > now
            || now >= evidence.valid_until
            || self
                .acknowledged_at
                .is_none_or(|acknowledged_at| evidence.observed_at < acknowledged_at)
        {
            return Err(TransitionError::InvalidEvidence);
        }
        if let VerificationState::Verified(previous) = self.observed {
            if evidence == previous {
                return Ok(Vec::new());
            }
            if evidence.observation_sequence <= previous.observation_sequence
                || evidence.observed_at < previous.observed_at
            {
                return Err(TransitionError::StaleEvidence);
            }
        }
        self.set_phase(CommitPhase::KernelVerified);
        self.observed = VerificationState::Verified(evidence);
        Ok(Vec::new())
    }

    fn reject(&mut self, reason: ReconcileReason) -> Vec<TransitionAction> {
        self.set_phase(CommitPhase::Rejected);
        self.observed = VerificationState::Unknown { reason };
        reconciliation(
            self.current.map(|current| current.identity),
            reason,
            self.desired == DesiredProtection::Enabled,
        )
    }

    fn invalidate(&mut self, reason: ReconcileReason) -> Vec<TransitionAction> {
        self.set_phase(CommitPhase::Invalidated);
        self.observed = VerificationState::Unknown { reason };
        reconciliation(
            self.current.map(|current| current.identity),
            reason,
            self.desired == DesiredProtection::Enabled,
        )
    }
}

fn reconciliation(
    identity: Option<OperationIdentity>,
    reason: ReconcileReason,
    must_block: bool,
) -> Vec<TransitionAction> {
    let mut actions = vec![TransitionAction::Inspect { identity, reason }];
    if must_block {
        actions.push(TransitionAction::RequireBlocking { identity, reason });
    }
    actions
}
