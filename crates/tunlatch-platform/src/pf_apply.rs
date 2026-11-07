//! Bounded synchronous submission ordering with an explicitly isolated simulated executor.
//!
//! No PF writer, reference operation, state deletion, shell or subprocess is implemented here.
//! The real execution-plan boundary requires the currently unconstructible administrator
//! capability. Offline candidates enter only [`SimulatedPlan`], never that boundary.
//! A simulated model match is not real protection: state convergence, interface lifetime,
//! execution position and administrator authorization remain unestablished.
//!
//! Persistence may perform ordinary synchronous file I/O. Run this driver on a blocking CLI
//! path, never an async service's executor thread. All injected callbacks must return within
//! their own bounds. Elapsed time is checked before and after them; it cannot interrupt a
//! blocked callback, prove cancellation, or provide a hard wall-clock termination guarantee.

use std::collections::VecDeque;
use std::time::Instant;

use sha2::{Digest, Sha256};
use thiserror::Error;
use tunlatch_core::config::DesiredProtection;
use tunlatch_core::egress::EnforcementAuthorization;
use tunlatch_core::transition::{
    EffectivePolicyDigest, OperationIdentity, ProtectionLifecycle, ReconcileReason,
    TransitionAction, TransitionError, TransitionEvent, TransitionRequest, VerificationEvidence,
    VerificationState,
};

use crate::policy_compile::{PfCandidateStatus, PfCompileCandidate};

/// Maximum reducer actions processed during one synchronous call.
pub const MAX_APPLY_ACTIONS: usize = 16;
/// Exclusive elapsed budget, checked after callbacks return, in monotonic milliseconds.
pub const APPLY_BUDGET_MS: u64 = 3_000;

/// Opaque production plan. Constructing it requires actual enforcement authority, not a draft.
/// No production backend is provided and no candidate conversion exists.
///
/// ```compile_fail
/// use tunlatch_platform::pf_apply::ExecutionPlan;
/// use tunlatch_platform::policy_compile::PfCompileCandidate;
/// fn promote(candidate: PfCompileCandidate) -> ExecutionPlan { candidate.into() }
/// ```
/// ```compile_fail
/// use tunlatch_platform::pf_apply::ExecutionPlan;
/// fn deserialize<T: for<'de> serde::Deserialize<'de>>() {}
/// deserialize::<ExecutionPlan>();
/// ```
#[derive(Debug)]
pub struct ExecutionPlan {
    identity: OperationIdentity,
    authorization: EnforcementAuthorization,
}

impl ExecutionPlan {
    /// Retain the actual execution capability. No caller can supply one in the current project.
    /// A future capability implementation must bind this complete identity at its trusted boundary.
    pub fn new(
        identity: OperationIdentity,
        authorization: EnforcementAuthorization,
    ) -> Result<Self, ApplyError> {
        if identity.service_epoch == [0; 16]
            || identity.operation_id == 0
            || identity.generation == 0
        {
            return Err(ApplyError::InvalidIdentity);
        }
        Ok(Self {
            identity,
            authorization,
        })
    }

    /// Exact identity attached to this opaque production plan.
    pub fn identity(&self) -> OperationIdentity {
        self.identity
    }

    /// Borrow the retained real capability, without creating or duplicating it.
    pub fn authorization(&self) -> &EnforcementAuthorization {
        &self.authorization
    }
}

/// Future production executor boundary. There is intentionally no implementation in this module.
pub trait SubmitBackend {
    /// Submit only a plan that retains real enforcement authority.
    fn submit(&mut self, plan: &ExecutionPlan) -> SubmissionOutcome;
}

/// Offline candidate in a separate simulation domain. It has no executable-plan conversion.
#[derive(Clone, Debug)]
pub struct SimulatedPlan {
    candidate: PfCompileCandidate,
    digest: EffectivePolicyDigest,
    desired: DesiredProtection,
}

impl SimulatedPlan {
    /// Bind an offline candidate to the complete *simulated* plan identity. This digest includes
    /// the explicit absence of live authority, state convergence and execution-position proof.
    /// It must never be reused as the digest of a real enforcement plan.
    pub fn from_candidate(candidate: PfCompileCandidate) -> Result<Self, ApplyError> {
        let desired = match candidate.status() {
            PfCandidateStatus::BlockedNotReady => DesiredProtection::Enabled,
            PfCandidateStatus::Unmanaged => DesiredProtection::Disabled,
        };
        let mut hash = Sha256::new();
        hash.update(b"tunlatch-simulated-apply-plan-v1\0");
        hash.update(b"no-live-authority\0no-state-convergence\0no-execution-position-proof\0");
        hash.update(candidate.digest().as_bytes());
        let digest = EffectivePolicyDigest::new(hash.finalize().into())?;
        Ok(Self {
            candidate,
            digest,
            desired,
        })
    }

    /// Candidate available only for isolated model evaluation, never loading into PF.
    pub fn candidate(&self) -> &PfCompileCandidate {
        &self.candidate
    }

    /// Simulation-domain policy identity, not live-policy authority.
    pub fn digest(&self) -> EffectivePolicyDigest {
        self.digest
    }

    /// Simulated desired mode. Disabled models releasing only this product's own policy.
    pub fn desired(&self) -> DesiredProtection {
        self.desired
    }
}

/// A persistence outcome must identify the exact requested operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PersistenceOutcome {
    /// File and containing-directory durability were both established.
    Durable(OperationIdentity),
    /// Definitive failure before replacing the old record; no backend submission began.
    RejectedBeforeReplace(OperationIdentity),
    /// Replace may have happened, directory synchronization failed, or the reply was lost.
    /// This must not be converted into rejection or assumed durable by rereading new bytes.
    Unknown(OperationIdentity),
}

/// Intent storage, permitted to use bounded ordinary-user synchronous file I/O.
pub trait IntentPersistence {
    /// Store the complete exact identity before any submission. The implementation owns its
    /// durability classification and must not call PF or claim disk/PF atomicity.
    fn persist_intent(&mut self, operation: OperationIdentity) -> PersistenceOutcome;
}

/// Submission completion with explicit uncertainty and exact operation identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmissionOutcome {
    /// The adapter acknowledged the exact commit; an independent read is still necessary.
    Acknowledged(OperationIdentity),
    /// It definitively rejected this operation before a commit could occur.
    RejectedBeforeCommit(OperationIdentity),
    /// Commit/reply/reclamation could not be established; never retry automatically.
    Unknown(OperationIdentity),
}

/// Isolated model executor, deliberately separate from [`SubmitBackend`].
pub trait SimulatedSubmitBackend {
    /// Change only in-memory model state. No PF, interfaces, references, subprocesses or network.
    /// Returning after a waiter timeout does not imply rollback; operation ownership remains here.
    fn submit(&mut self, operation: OperationIdentity, plan: &SimulatedPlan) -> SubmissionOutcome;
}

/// Separate read outcome. A submit reply alone must never construct the evidence branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndependentObservation {
    /// A fresh independent read of isolated model state; not real kernel enforcement evidence.
    Evidence(VerificationEvidence),
    /// Independent model contents differ from the requested identity.
    Mismatch,
    /// No complete independent result was available.
    Unavailable,
}

/// Independent model reader. It must not implement real PF queries or network activity here.
/// An adapter of unqualified read-only captures must return unavailable/mismatch, never evidence.
pub trait IndependentObserver {
    /// Independently inspect model state rather than echoing the requested identity.
    fn observe(&mut self, expected: OperationIdentity) -> IndependentObservation;
}

/// Owner-provided monotonic clock, sampled around every potentially blocking callback.
pub trait MonotonicClock {
    /// Current monotonic milliseconds, with no epoch changes during a controller lifetime.
    fn now_ms(&mut self) -> u64;
}

/// Local elapsed monotonic clock suitable for a synchronous CLI simulation.
#[derive(Debug)]
pub struct ElapsedClock(Instant);

impl ElapsedClock {
    /// Start a new local monotonic epoch.
    pub fn new() -> Self {
        Self(Instant::now())
    }
}

impl Default for ElapsedClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for ElapsedClock {
    fn now_ms(&mut self) -> u64 {
        u64::try_from(self.0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }
}

/// Result of processing one simulated request. No variant means actual protected traffic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimulatedApplyOutcome {
    /// Durable intent, modeled acknowledgment and separate model read matched this generation.
    ModelVerified,
    /// An identical current request emitted no duplicate callback; inspect lifecycle for its state.
    NoNewSubmission,
    /// The intent was definitively rejected before replacement.
    IntentRejected,
    /// Intent durability could not be established; no submission was attempted.
    IntentUnknown,
    /// The simulated executor definitively rejected before committing.
    SubmissionRejected,
    /// The simulated commit/reply outcome could not be established.
    SubmissionUnknown,
    /// An acknowledgment or persistence result belonged to another operation.
    UncorrelatedResult,
    /// Independent read contents differed from the operation.
    ObservationMismatch,
    /// No complete independent model read was available.
    ObservationUnavailable,
    /// Independent evidence was stale, malformed, replayed or bound to another identity.
    ObservationRejected,
    /// A clock, elapsed-time or action-count boundary ended this synchronous run.
    BudgetExceeded,
}

/// One bounded run's report. Required reconciliation actions were deliberately not executed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulatedApplyReport {
    /// Operation whose in-process request was accepted.
    pub operation: OperationIdentity,
    /// Model-only outcome; never map this directly to public protection status.
    pub outcome: SimulatedApplyOutcome,
    /// Unfulfilled inspection/blocking requirements. No automatic PF cleanup or retry occurs.
    pub required_actions: Vec<TransitionAction>,
}

/// Errors before or while ordering the model workflow, distinct from its reported failure paths.
#[derive(Debug, Error)]
pub enum ApplyError {
    /// A production identity omitted a mandatory nonzero correlation field.
    #[error("incomplete operation identity")]
    InvalidIdentity,
    /// A reducer request or event was rejected.
    #[error(transparent)]
    Transition(#[from] TransitionError),
    /// A rejected request still carries reconciliation discovered before validation.
    #[error("simulated request rejected: {source}")]
    RequestRejected {
        /// Why the new request was refused.
        source: TransitionError,
        /// Outstanding inspection and blocking requirements discovered before rejection.
        required_actions: Vec<TransitionAction>,
    },
    /// The reducer did not retain the operation it had just accepted.
    #[error("accepted operation is unavailable")]
    MissingOperation,
}

impl ApplyError {
    /// Requirements produced by the lifecycle before a rejected request.
    pub fn required_actions(&self) -> &[TransitionAction] {
        match self {
            Self::RequestRejected {
                required_actions, ..
            } => required_actions,
            _ => &[],
        }
    }
}

/// Owns serialized, bounded simulation ordering. There are no suspension points or detached
/// tasks, and dropping it performs no cleanup, reference release or change of modeled policy.
pub struct SimulatedApplyController<P, B, O, C> {
    lifecycle: ProtectionLifecycle,
    persistence: P,
    backend: B,
    observer: O,
    clock: C,
}

impl<P: IntentPersistence, B: SimulatedSubmitBackend, O: IndependentObserver, C: MonotonicClock>
    SimulatedApplyController<P, B, O, C>
{
    /// Assemble an explicitly simulated executor. Production writers cannot consume this plan.
    pub fn new(
        lifecycle: ProtectionLifecycle,
        persistence: P,
        backend: B,
        observer: O,
        clock: C,
    ) -> Self {
        Self {
            lifecycle,
            persistence,
            backend,
            observer,
            clock,
        }
    }

    /// Inspect internal lifecycle bookkeeping, never a real protected status.
    pub fn lifecycle(&self) -> &ProtectionLifecycle {
        &self.lifecycle
    }

    /// Return ownership without triggering PF, modeled cleanup or disk rollback.
    pub fn into_parts(self) -> (ProtectionLifecycle, P, B, O, C) {
        (
            self.lifecycle,
            self.persistence,
            self.backend,
            self.observer,
            self.clock,
        )
    }

    /// Persist once, submit once, independently read once. Failure leaves reconciliation
    /// requirements rather than rolling back, resubmitting or interpreting uncertainty as success.
    /// The coordinator must retain older operation-id history across generations.
    pub fn submit(
        &mut self,
        operation_id: u64,
        expected_generation: u64,
        plan: &SimulatedPlan,
    ) -> Result<SimulatedApplyReport, ApplyError> {
        let started_at = self.clock.now_ms();
        let earlier_requirements = self.lifecycle.apply(TransitionEvent::Tick, started_at)?;
        let actions = match self.lifecycle.request(TransitionRequest {
            operation_id,
            expected_generation,
            policy_digest: plan.digest(),
            desired: plan.desired(),
        }) {
            Ok(actions) => actions,
            Err(source) => {
                return Err(ApplyError::RequestRejected {
                    source,
                    required_actions: earlier_requirements,
                });
            }
        };
        let operation = self
            .lifecycle
            .current()
            .ok_or(ApplyError::MissingOperation)?
            .identity;
        let mut report = SimulatedApplyReport {
            operation,
            outcome: SimulatedApplyOutcome::NoNewSubmission,
            required_actions: Vec::new(),
        };
        for action in earlier_requirements {
            retain_requirement(&mut report, action);
        }
        let mut pending = VecDeque::from(actions);
        let mut processed = 0;
        let mut halted = false;
        while let Some(action) = pending.pop_front() {
            if halted {
                retain_requirement(&mut report, action);
                continue;
            }
            if processed >= MAX_APPLY_ACTIONS {
                let now = self.clock.now_ms();
                self.mark_unknown(now, &mut report)?;
                report.outcome = SimulatedApplyOutcome::BudgetExceeded;
                break;
            }
            processed += 1;
            if matches!(action, TransitionAction::RequireBlocking { .. }) {
                retain_requirement(&mut report, action);
                continue;
            }
            if let TransitionAction::Inspect { reason, .. } = action
                && reason != ReconcileReason::KernelAcknowledged
            {
                retain_requirement(&mut report, action);
                continue;
            }
            if self.checked_time(started_at, &mut report)?.is_none() {
                halted = true;
                continue;
            }
            let (event, mut outcome) = match action {
                TransitionAction::PersistIntent(identity) => {
                    match self.persistence.persist_intent(identity) {
                        PersistenceOutcome::Durable(receipt) if receipt == identity => (
                            TransitionEvent::IntentDurable(receipt),
                            SimulatedApplyOutcome::NoNewSubmission,
                        ),
                        PersistenceOutcome::RejectedBeforeReplace(receipt)
                            if receipt == identity =>
                        {
                            (
                                TransitionEvent::IntentNotDurable(receipt),
                                SimulatedApplyOutcome::IntentRejected,
                            )
                        }
                        PersistenceOutcome::Unknown(receipt) if receipt == identity => (
                            TransitionEvent::OutcomeUnknown(receipt),
                            SimulatedApplyOutcome::IntentUnknown,
                        ),
                        _ => (
                            TransitionEvent::OutcomeUnknown(identity),
                            SimulatedApplyOutcome::UncorrelatedResult,
                        ),
                    }
                }
                TransitionAction::SubmitPolicy(identity) => {
                    let reply = self.backend.submit(identity, plan);
                    submission_event(reply, identity)
                }
                TransitionAction::Inspect { identity, .. } => {
                    let expected = identity.ok_or(ApplyError::MissingOperation)?;
                    match self.observer.observe(expected) {
                        IndependentObservation::Evidence(evidence) => (
                            TransitionEvent::IndependentlyVerified(evidence),
                            SimulatedApplyOutcome::ModelVerified,
                        ),
                        IndependentObservation::Mismatch => (
                            TransitionEvent::PfChanged,
                            SimulatedApplyOutcome::ObservationMismatch,
                        ),
                        IndependentObservation::Unavailable => (
                            TransitionEvent::ObservationUnavailable,
                            SimulatedApplyOutcome::ObservationUnavailable,
                        ),
                    }
                }
                TransitionAction::RequireBlocking { .. } => continue,
            };
            let Some(now) = self.checked_time(started_at, &mut report)? else {
                halted = true;
                continue;
            };
            let next = match self.lifecycle.apply(event, now) {
                Ok(actions) => actions,
                Err(_) if matches!(event, TransitionEvent::IndependentlyVerified(_)) => {
                    outcome = SimulatedApplyOutcome::ObservationRejected;
                    self.lifecycle
                        .apply(TransitionEvent::ObservationUnavailable, now)?
                }
                Err(error) => return Err(error.into()),
            };
            if matches!(
                self.lifecycle.observed(),
                VerificationState::Unknown {
                    reason: ReconcileReason::UncorrelatedKernelResult,
                }
            ) {
                outcome = SimulatedApplyOutcome::UncorrelatedResult;
            }
            report.outcome = outcome;
            halted = !matches!(
                outcome,
                SimulatedApplyOutcome::NoNewSubmission | SimulatedApplyOutcome::ModelVerified
            );
            pending.extend(next);
        }
        Ok(report)
    }

    /// A waiter leaving changes neither operation ownership nor model/disk policy.
    pub fn client_timed_out(
        &mut self,
        operation: OperationIdentity,
    ) -> Result<Vec<TransitionAction>, ApplyError> {
        Ok(self.lifecycle.apply(
            TransitionEvent::ClientTimedOut(operation),
            self.clock.now_ms(),
        )?)
    }

    /// Correlate a late callback without submitting anything again. Old or uncorrelated kernel
    /// results invalidate newer observations; returned blocking requirements are not executed.
    pub fn receive_late_submission(
        &mut self,
        reply: SubmissionOutcome,
    ) -> Result<Vec<TransitionAction>, ApplyError> {
        let current = self
            .lifecycle
            .current()
            .ok_or(ApplyError::MissingOperation)?
            .identity;
        let (event, _) = submission_event(reply, current);
        Ok(self.lifecycle.apply(event, self.clock.now_ms())?)
    }

    fn checked_time(
        &mut self,
        started_at: u64,
        report: &mut SimulatedApplyReport,
    ) -> Result<Option<u64>, ApplyError> {
        let now = self.clock.now_ms();
        let actions = self.lifecycle.apply(TransitionEvent::Tick, now)?;
        if !actions.is_empty() {
            for action in actions {
                retain_requirement(report, action);
            }
            report.outcome = SimulatedApplyOutcome::BudgetExceeded;
            return Ok(None);
        }
        if now
            .checked_sub(started_at)
            .is_none_or(|elapsed| elapsed >= APPLY_BUDGET_MS)
        {
            self.mark_unknown(now, report)?;
            report.outcome = SimulatedApplyOutcome::BudgetExceeded;
            return Ok(None);
        }
        Ok(Some(now))
    }

    fn mark_unknown(
        &mut self,
        now: u64,
        report: &mut SimulatedApplyReport,
    ) -> Result<(), ApplyError> {
        for action in self
            .lifecycle
            .apply(TransitionEvent::OutcomeUnknown(report.operation), now)?
        {
            retain_requirement(report, action);
        }
        Ok(())
    }
}

fn retain_requirement(report: &mut SimulatedApplyReport, action: TransitionAction) {
    if matches!(
        action,
        TransitionAction::Inspect { .. } | TransitionAction::RequireBlocking { .. }
    ) && !report.required_actions.contains(&action)
        && report.required_actions.len() < MAX_APPLY_ACTIONS
    {
        report.required_actions.push(action);
    }
}

fn submission_event(
    reply: SubmissionOutcome,
    expected: OperationIdentity,
) -> (TransitionEvent, SimulatedApplyOutcome) {
    match reply {
        SubmissionOutcome::Acknowledged(identity) => (
            TransitionEvent::KernelAcknowledged(identity),
            if identity == expected {
                SimulatedApplyOutcome::NoNewSubmission
            } else {
                SimulatedApplyOutcome::UncorrelatedResult
            },
        ),
        SubmissionOutcome::RejectedBeforeCommit(identity) if identity == expected => (
            TransitionEvent::KernelRejected(identity),
            SimulatedApplyOutcome::SubmissionRejected,
        ),
        SubmissionOutcome::Unknown(identity) => (
            TransitionEvent::OutcomeUnknown(identity),
            if identity == expected {
                SimulatedApplyOutcome::SubmissionUnknown
            } else {
                SimulatedApplyOutcome::UncorrelatedResult
            },
        ),
        _ => (
            TransitionEvent::OutcomeUnknown(expected),
            SimulatedApplyOutcome::UncorrelatedResult,
        ),
    }
}
