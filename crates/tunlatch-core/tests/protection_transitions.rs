//! Pure ordering and recovery checks. These tests provide no real PF or leak-protection evidence.

use std::error::Error;
use std::io;

use tunlatch_core::config::DesiredProtection;
use tunlatch_core::transition::{
    CommitPhase, CurrentOperation, EffectivePolicyDigest, OperationIdentity, ProtectionLifecycle,
    ReconcileReason, RecoveryHint, TransitionAction, TransitionError, TransitionEvent,
    TransitionRequest, VerificationEvidence, VerificationState,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn lifecycle() -> TestResult<ProtectionLifecycle> {
    Ok(ProtectionLifecycle::new(
        [1; 16],
        DesiredProtection::Disabled,
    )?)
}

fn current(state: &ProtectionLifecycle) -> TestResult<CurrentOperation> {
    state
        .current()
        .ok_or_else(|| io::Error::other("missing current operation").into())
}

fn request(
    state: &ProtectionLifecycle,
    operation_id: u64,
    digest: u8,
    desired: DesiredProtection,
) -> TestResult<TransitionRequest> {
    Ok(TransitionRequest {
        operation_id,
        expected_generation: state.generation(),
        policy_digest: EffectivePolicyDigest::new([digest; 32])?,
        desired,
    })
}

fn begin(
    state: &mut ProtectionLifecycle,
    operation_id: u64,
    desired: DesiredProtection,
) -> TestResult<OperationIdentity> {
    let request = request(state, operation_id, 2, desired)?;
    state.request(request)?;
    Ok(current(state)?.identity)
}

fn acknowledge(
    state: &mut ProtectionLifecycle,
    identity: OperationIdentity,
    now: u64,
) -> TestResult {
    state.apply(TransitionEvent::IntentDurable(identity), now)?;
    state.apply(TransitionEvent::KernelAcknowledged(identity), now)?;
    Ok(())
}

fn evidence(identity: OperationIdentity, now: u64) -> VerificationEvidence {
    VerificationEvidence {
        identity,
        observation_sequence: 1,
        observed_at: now,
        valid_until: now + 100,
    }
}

fn verified(
    state: &mut ProtectionLifecycle,
    identity: OperationIdentity,
    now: u64,
) -> TestResult<VerificationEvidence> {
    acknowledge(state, identity, now)?;
    let evidence = evidence(identity, now);
    state.apply(TransitionEvent::IndependentlyVerified(evidence), now)?;
    Ok(evidence)
}

fn assert_unknown(state: &ProtectionLifecycle, reason: ReconcileReason) {
    assert_eq!(state.observed(), VerificationState::Unknown { reason });
}

fn assert_reconciliation(
    actions: &[TransitionAction],
    identity: Option<OperationIdentity>,
    reason: ReconcileReason,
    must_block: bool,
) {
    let mut expected = vec![TransitionAction::Inspect { identity, reason }];
    if must_block {
        expected.push(TransitionAction::RequireBlocking { identity, reason });
    }
    assert_eq!(actions, expected);
}

#[test]
fn rejects_unset_epoch_digest_and_operation() -> TestResult {
    assert!(matches!(
        ProtectionLifecycle::new([0; 16], DesiredProtection::Enabled),
        Err(TransitionError::InvalidEpoch)
    ));
    assert_eq!(
        EffectivePolicyDigest::new([0; 32]),
        Err(TransitionError::InvalidPolicyDigest)
    );
    assert_eq!(EffectivePolicyDigest::new([7; 32])?.as_bytes(), &[7; 32]);
    let mut state = lifecycle()?;
    let invalid = request(&state, 0, 2, DesiredProtection::Enabled)?;
    assert_eq!(
        state.request(invalid),
        Err(TransitionError::InvalidOperationId)
    );
    assert_eq!(state.generation(), 0);
    assert_eq!(state.desired(), DesiredProtection::Disabled);
    assert!(state.current().is_none());
    assert!(state.committed().is_none());
    Ok(())
}

#[test]
fn orders_persistence_submission_acknowledgment_and_independent_verification() -> TestResult {
    let mut state = lifecycle()?;
    assert_unknown(&state, ReconcileReason::NotObserved);
    let request = request(&state, 9, 3, DesiredProtection::Enabled)?;
    let actions = state.request(request)?;
    let identity = current(&state)?.identity;
    assert_eq!(identity.service_epoch, [1; 16]);
    assert_eq!(identity.operation_id, 9);
    assert_eq!(identity.generation, 1);
    assert_eq!(identity.policy_digest.as_bytes(), &[3; 32]);
    assert_eq!(state.desired(), DesiredProtection::Enabled);
    assert_eq!(current(&state)?.phase, CommitPhase::Requested);
    assert!(state.committed().is_none());
    assert_unknown(&state, ReconcileReason::PendingOperation);
    assert_eq!(
        actions,
        vec![
            TransitionAction::PersistIntent(identity),
            TransitionAction::RequireBlocking {
                identity: Some(identity),
                reason: ReconcileReason::PendingOperation,
            },
        ]
    );
    assert_eq!(
        state.apply(TransitionEvent::IntentDurable(identity), 10)?,
        vec![TransitionAction::SubmitPolicy(identity)]
    );
    assert_eq!(current(&state)?.phase, CommitPhase::IntentDurable);
    assert!(state.committed().is_none());
    assert_reconciliation(
        &state.apply(TransitionEvent::KernelAcknowledged(identity), 11)?,
        Some(identity),
        ReconcileReason::KernelAcknowledged,
        false,
    );
    assert_eq!(current(&state)?.phase, CommitPhase::KernelAcknowledged);
    assert_eq!(state.committed(), Some(identity));
    assert_unknown(&state, ReconcileReason::PendingOperation);
    let evidence = evidence(identity, 12);
    assert!(
        state
            .apply(TransitionEvent::IndependentlyVerified(evidence), 12)?
            .is_empty()
    );
    assert_eq!(current(&state)?.phase, CommitPhase::KernelVerified);
    assert_eq!(state.observed(), VerificationState::Verified(evidence));
    Ok(())
}

#[test]
fn current_retries_do_not_resubmit_or_reinspect() -> TestResult {
    let mut state = lifecycle()?;
    let request = request(&state, 1, 2, DesiredProtection::Enabled)?;
    state.request(request)?;
    let identity = current(&state)?.identity;
    assert!(state.request(request)?.is_empty());
    acknowledge(&mut state, identity, 10)?;
    for event in [
        TransitionEvent::IntentDurable(identity),
        TransitionEvent::KernelAcknowledged(identity),
    ] {
        assert!(state.apply(event, 11)?.is_empty());
    }
    let evidence = evidence(identity, 12);
    state.apply(TransitionEvent::IndependentlyVerified(evidence), 12)?;
    assert!(state.request(request)?.is_empty());
    assert!(
        state
            .apply(TransitionEvent::IndependentlyVerified(evidence), 13)?
            .is_empty()
    );
    assert_eq!(state.generation(), 1);
    assert_eq!(state.observed(), VerificationState::Verified(evidence));
    Ok(())
}

#[test]
fn conflicts_and_reused_current_identifiers_preserve_existing_intent() -> TestResult {
    let mut state = lifecycle()?;
    let original = request(&state, 1, 2, DesiredProtection::Enabled)?;
    state.request(original)?;
    for changed in [
        TransitionRequest {
            policy_digest: EffectivePolicyDigest::new([3; 32])?,
            ..original
        },
        TransitionRequest {
            desired: DesiredProtection::Disabled,
            ..original
        },
        TransitionRequest {
            expected_generation: 1,
            ..original
        },
    ] {
        assert_eq!(
            state.request(changed),
            Err(TransitionError::OperationIdReused)
        );
    }
    assert_eq!(
        state.request(TransitionRequest {
            operation_id: 2,
            ..original
        }),
        Err(TransitionError::Conflict)
    );
    assert_eq!(state.generation(), 1);
    assert_eq!(state.desired(), DesiredProtection::Enabled);
    assert_eq!(current(&state)?.phase, CommitPhase::Requested);
    Ok(())
}

#[test]
fn every_identity_component_must_match_for_durability_and_verification() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    let mismatches = [
        OperationIdentity {
            service_epoch: [2; 16],
            ..identity
        },
        OperationIdentity {
            generation: 2,
            ..identity
        },
        OperationIdentity {
            operation_id: 2,
            ..identity
        },
        OperationIdentity {
            policy_digest: EffectivePolicyDigest::new([3; 32])?,
            ..identity
        },
        OperationIdentity {
            desired: DesiredProtection::Disabled,
            ..identity
        },
    ];
    for mismatch in mismatches {
        assert_eq!(
            state.apply(TransitionEvent::IntentDurable(mismatch), 10),
            Err(TransitionError::IdentityMismatch)
        );
    }
    acknowledge(&mut state, identity, 11)?;
    for mismatch in mismatches {
        assert_eq!(
            state.apply(
                TransitionEvent::IndependentlyVerified(evidence(mismatch, 12)),
                12,
            ),
            Err(TransitionError::IdentityMismatch)
        );
    }
    assert_eq!(current(&state)?.phase, CommitPhase::KernelAcknowledged);
    assert_eq!(state.committed(), Some(identity));
    assert_unknown(&state, ReconcileReason::PendingOperation);
    Ok(())
}

#[test]
fn precommit_observation_and_skipped_persistence_cannot_establish_verification() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    assert_eq!(
        state.apply(
            TransitionEvent::IndependentlyVerified(evidence(identity, 10)),
            10,
        ),
        Err(TransitionError::OutOfOrder)
    );
    assert_reconciliation(
        &state.apply(TransitionEvent::KernelAcknowledged(identity), 11)?,
        Some(identity),
        ReconcileReason::UncorrelatedKernelResult,
        true,
    );
    assert_eq!(current(&state)?.phase, CommitPhase::Invalidated);
    assert!(state.committed().is_none());
    assert_eq!(
        state.apply(TransitionEvent::IntentDurable(identity), 12),
        Err(TransitionError::OutOfOrder)
    );
    Ok(())
}

#[test]
fn unknown_submission_rejects_late_success_without_inventing_a_commit() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    state.apply(TransitionEvent::IntentDurable(identity), 10)?;
    assert_reconciliation(
        &state.apply(TransitionEvent::OutcomeUnknown(identity), 11)?,
        Some(identity),
        ReconcileReason::OutcomeUnknown,
        true,
    );
    assert_eq!(current(&state)?.phase, CommitPhase::OutcomeUnknown);
    assert_unknown(&state, ReconcileReason::OutcomeUnknown);
    assert_reconciliation(
        &state.apply(TransitionEvent::KernelAcknowledged(identity), 12)?,
        Some(identity),
        ReconcileReason::UncorrelatedKernelResult,
        true,
    );
    assert!(state.committed().is_none());
    assert_eq!(
        state.apply(
            TransitionEvent::IndependentlyVerified(evidence(identity, 13)),
            13,
        ),
        Err(TransitionError::OutOfOrder)
    );
    Ok(())
}

#[test]
fn definitive_failures_preserve_historical_commit_without_claiming_current_protection() -> TestResult
{
    for durable in [false, true] {
        let mut state = lifecycle()?;
        let first = begin(&mut state, 1, DesiredProtection::Enabled)?;
        verified(&mut state, first, 10)?;
        let update = begin(&mut state, 2, DesiredProtection::Enabled)?;
        let (event, reason) = if durable {
            state.apply(TransitionEvent::IntentDurable(update), 11)?;
            (
                TransitionEvent::KernelRejected(update),
                ReconcileReason::KernelRejected,
            )
        } else {
            (
                TransitionEvent::IntentNotDurable(update),
                ReconcileReason::IntentNotDurable,
            )
        };
        assert_reconciliation(&state.apply(event, 12)?, Some(update), reason, true);
        assert_eq!(state.committed(), Some(first));
        assert_eq!(current(&state)?.phase, CommitPhase::Rejected);
        assert_unknown(&state, reason);
        assert_eq!(
            state.apply(
                TransitionEvent::IndependentlyVerified(evidence(update, 13)),
                13,
            ),
            Err(TransitionError::OutOfOrder)
        );
    }
    Ok(())
}

#[test]
fn tun_pf_and_observer_failures_revoke_verification_and_fence_old_results() -> TestResult {
    for (event, reason) in [
        (TransitionEvent::TunTrustLost, ReconcileReason::TunTrustLost),
        (TransitionEvent::PfChanged, ReconcileReason::PfChanged),
        (
            TransitionEvent::ObservationUnavailable,
            ReconcileReason::ObservationUnavailable,
        ),
    ] {
        let mut state = lifecycle()?;
        let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
        let old = verified(&mut state, identity, 10)?;
        assert_reconciliation(&state.apply(event, 11)?, Some(identity), reason, true);
        assert_unknown(&state, reason);
        assert_eq!(current(&state)?.phase, CommitPhase::Invalidated);
        assert_eq!(state.committed(), Some(identity));
        for evidence in [
            old,
            VerificationEvidence {
                observation_sequence: 2,
                observed_at: 12,
                ..old
            },
        ] {
            assert_eq!(
                state.apply(TransitionEvent::IndependentlyVerified(evidence), 12),
                Err(TransitionError::OutOfOrder)
            );
        }
    }
    Ok(())
}

#[test]
fn client_timeout_only_removes_a_waiter_and_does_not_rollback_the_operation() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    assert!(
        state
            .apply(TransitionEvent::ClientTimedOut(identity), 10)?
            .is_empty()
    );
    assert_eq!(current(&state)?.phase, CommitPhase::Requested);
    state.apply(TransitionEvent::IntentDurable(identity), 11)?;
    state.apply(TransitionEvent::ClientTimedOut(identity), 12)?;
    assert_eq!(current(&state)?.phase, CommitPhase::IntentDurable);
    state.apply(TransitionEvent::KernelAcknowledged(identity), 13)?;
    let evidence = evidence(identity, 14);
    state.apply(TransitionEvent::IndependentlyVerified(evidence), 14)?;
    state.apply(TransitionEvent::ClientTimedOut(identity), 15)?;
    assert_eq!(state.observed(), VerificationState::Verified(evidence));
    assert_eq!(state.committed(), Some(identity));
    Ok(())
}

#[test]
fn expiry_is_exclusive_and_late_completion_cannot_revive_the_generation() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    let old = verified(&mut state, identity, 10)?;
    assert!(state.apply(TransitionEvent::Tick, 109)?.is_empty());
    assert_eq!(state.observed(), VerificationState::Verified(old));
    assert_reconciliation(
        &state.apply(TransitionEvent::Tick, 110)?,
        Some(identity),
        ReconcileReason::ObservationExpired,
        true,
    );
    assert_unknown(&state, ReconcileReason::ObservationExpired);
    assert_eq!(
        state.apply(
            TransitionEvent::IndependentlyVerified(VerificationEvidence {
                observation_sequence: 2,
                observed_at: 111,
                valid_until: 211,
                ..old
            }),
            111,
        ),
        Err(TransitionError::OutOfOrder)
    );
    Ok(())
}

#[test]
fn expiry_takes_precedence_over_a_newly_arrived_success() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    let old = verified(&mut state, identity, 10)?;
    let late = VerificationEvidence {
        observation_sequence: 2,
        observed_at: 110,
        valid_until: 210,
        ..old
    };
    assert_reconciliation(
        &state.apply(TransitionEvent::IndependentlyVerified(late), 110)?,
        Some(identity),
        ReconcileReason::ObservationExpired,
        true,
    );
    assert_unknown(&state, ReconcileReason::ObservationExpired);
    Ok(())
}

#[test]
fn fresh_renewals_advance_sequence_and_cannot_reuse_precommit_observations() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    acknowledge(&mut state, identity, 10)?;
    let before_ack = evidence(identity, 9);
    assert_eq!(
        state.apply(TransitionEvent::IndependentlyVerified(before_ack), 11),
        Err(TransitionError::InvalidEvidence)
    );
    let old = evidence(identity, 12);
    state.apply(TransitionEvent::IndependentlyVerified(old), 12)?;
    for stale in [
        VerificationEvidence {
            observed_at: 13,
            ..old
        },
        VerificationEvidence {
            observation_sequence: 2,
            observed_at: 11,
            ..old
        },
    ] {
        assert_eq!(
            state.apply(TransitionEvent::IndependentlyVerified(stale), 13),
            Err(TransitionError::StaleEvidence)
        );
        assert_eq!(state.observed(), VerificationState::Verified(old));
    }
    let renewed = VerificationEvidence {
        observation_sequence: 2,
        observed_at: 14,
        valid_until: 214,
        ..old
    };
    state.apply(TransitionEvent::IndependentlyVerified(renewed), 14)?;
    state.apply(TransitionEvent::Tick, 112)?;
    assert_eq!(state.observed(), VerificationState::Verified(renewed));
    state.apply(TransitionEvent::Tick, 214)?;
    assert_unknown(&state, ReconcileReason::ObservationExpired);
    Ok(())
}

#[test]
fn rejects_zero_sequence_future_and_expired_evidence() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    acknowledge(&mut state, identity, 10)?;
    let valid = evidence(identity, 11);
    for invalid in [
        VerificationEvidence {
            observation_sequence: 0,
            ..valid
        },
        VerificationEvidence {
            observed_at: 12,
            ..valid
        },
        VerificationEvidence {
            valid_until: 11,
            ..valid
        },
        VerificationEvidence {
            valid_until: 9,
            ..valid
        },
    ] {
        assert_eq!(
            state.apply(TransitionEvent::IndependentlyVerified(invalid), 11),
            Err(TransitionError::InvalidEvidence)
        );
    }
    assert_unknown(&state, ReconcileReason::PendingOperation);
    Ok(())
}

#[test]
fn late_old_kernel_success_invalidates_even_a_newer_verified_blocking_plan() -> TestResult {
    let mut state = lifecycle()?;
    let old = begin(&mut state, 1, DesiredProtection::Enabled)?;
    acknowledge(&mut state, old, 10)?;
    state.apply(TransitionEvent::TunTrustLost, 11)?;
    let blocking = begin(&mut state, 2, DesiredProtection::Enabled)?;
    let observation = verified(&mut state, blocking, 12)?;
    assert_eq!(blocking.generation, 2);
    assert_eq!(state.observed(), VerificationState::Verified(observation));
    assert_reconciliation(
        &state.apply(TransitionEvent::KernelAcknowledged(old), 13)?,
        Some(blocking),
        ReconcileReason::UncorrelatedKernelResult,
        true,
    );
    assert_eq!(state.committed(), Some(blocking));
    assert_unknown(&state, ReconcileReason::UncorrelatedKernelResult);
    for late in [evidence(old, 14), evidence(blocking, 14)] {
        assert!(
            state
                .apply(TransitionEvent::IndependentlyVerified(late), 14)
                .is_err()
        );
    }
    Ok(())
}

#[test]
fn a_new_generation_is_required_after_invalidation_and_old_results_remain_isolated() -> TestResult {
    let mut state = lifecycle()?;
    let old = begin(&mut state, 1, DesiredProtection::Enabled)?;
    verified(&mut state, old, 10)?;
    state.apply(TransitionEvent::PfChanged, 11)?;
    let replacement = begin(&mut state, 2, DesiredProtection::Enabled)?;
    assert_eq!(
        state.apply(TransitionEvent::IntentDurable(old), 12),
        Err(TransitionError::IdentityMismatch)
    );
    let current = verified(&mut state, replacement, 13)?;
    assert_eq!(
        state.apply(
            TransitionEvent::IndependentlyVerified(evidence(old, 14)),
            14,
        ),
        Err(TransitionError::IdentityMismatch)
    );
    assert_eq!(state.observed(), VerificationState::Verified(current));
    Ok(())
}

#[test]
fn disabled_intent_releases_only_the_exact_owned_policy_and_is_not_global_pf_disable() -> TestResult
{
    let mut state = lifecycle()?;
    let enabled = begin(&mut state, 1, DesiredProtection::Enabled)?;
    verified(&mut state, enabled, 10)?;
    let request = request(&state, 2, 3, DesiredProtection::Disabled)?;
    let actions = state.request(request)?;
    let disabled = current(&state)?.identity;
    assert_eq!(actions, vec![TransitionAction::PersistIntent(disabled)]);
    assert_eq!(state.desired(), DesiredProtection::Disabled);
    assert_eq!(state.committed(), Some(enabled));
    assert_unknown(&state, ReconcileReason::PendingOperation);
    assert_eq!(
        state.apply(TransitionEvent::IntentDurable(disabled), 11)?,
        vec![TransitionAction::SubmitPolicy(disabled)]
    );
    state.apply(TransitionEvent::KernelAcknowledged(disabled), 12)?;
    let observed_disabled = evidence(disabled, 13);
    state.apply(
        TransitionEvent::IndependentlyVerified(observed_disabled),
        13,
    )?;
    assert_eq!(state.committed(), Some(disabled));
    // This match is internal policy consistency, including disabled intent, never protection.
    assert_eq!(
        state.observed(),
        VerificationState::Verified(observed_disabled)
    );
    assert_reconciliation(
        &state.apply(TransitionEvent::PfChanged, 14)?,
        Some(disabled),
        ReconcileReason::PfChanged,
        false,
    );
    Ok(())
}

#[test]
fn clock_regression_revokes_success_without_accepting_the_supplied_event() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    let old = verified(&mut state, identity, 10)?;
    assert_reconciliation(
        &state.apply(TransitionEvent::IndependentlyVerified(old), 9)?,
        Some(identity),
        ReconcileReason::ClockRegressed,
        true,
    );
    assert_unknown(&state, ReconcileReason::ClockRegressed);
    assert_eq!(current(&state)?.phase, CommitPhase::Invalidated);
    assert_eq!(
        state.apply(TransitionEvent::IndependentlyVerified(old), 11),
        Err(TransitionError::OutOfOrder)
    );
    Ok(())
}

#[test]
fn every_recovery_checkpoint_is_only_a_hint_and_requires_fresh_inspection() -> TestResult {
    let mut original = lifecycle()?;
    let identity = begin(&mut original, 1, DesiredProtection::Enabled)?;
    for phase in [
        CommitPhase::Requested,
        CommitPhase::IntentDurable,
        CommitPhase::KernelAcknowledged,
        CommitPhase::KernelVerified,
        CommitPhase::Rejected,
        CommitPhase::OutcomeUnknown,
        CommitPhase::Invalidated,
    ] {
        let hint = RecoveryHint::Recorded(CurrentOperation { identity, phase });
        let (mut recovered, actions) =
            ProtectionLifecycle::recover([2; 16], DesiredProtection::Disabled, hint)?;
        assert_eq!(recovered.desired(), DesiredProtection::Disabled);
        assert_eq!(recovered.generation(), 0);
        assert!(recovered.current().is_none());
        assert!(recovered.committed().is_none());
        assert_eq!(recovered.recovery_hint(), Some(hint));
        assert_unknown(&recovered, ReconcileReason::Recovery);
        assert_reconciliation(&actions, Some(identity), ReconcileReason::Recovery, true);
        assert_eq!(
            recovered.apply(
                TransitionEvent::IndependentlyVerified(evidence(identity, 10)),
                10,
            ),
            Err(TransitionError::NoCurrentOperation)
        );
        let fresh = begin(&mut recovered, 1, DesiredProtection::Enabled)?;
        assert_eq!(fresh.service_epoch, [2; 16]);
        assert_eq!(fresh.generation, identity.generation);
        assert_eq!(fresh.operation_id, identity.operation_id);
        assert_eq!(
            recovered.apply(TransitionEvent::IntentDurable(identity), 11),
            Err(TransitionError::IdentityMismatch)
        );
        verified(&mut recovered, fresh, 12)?;
    }
    Ok(())
}

#[test]
fn missing_unreadable_and_corrupt_records_never_restore_a_disabled_or_verified_fact() -> TestResult
{
    for desired in [DesiredProtection::Disabled, DesiredProtection::Enabled] {
        for hint in [
            RecoveryHint::Missing,
            RecoveryHint::Unavailable,
            RecoveryHint::Corrupt,
        ] {
            let (state, actions) = ProtectionLifecycle::recover([2; 16], desired, hint)?;
            assert_eq!(state.desired(), desired);
            assert!(state.committed().is_none());
            assert!(state.current().is_none());
            assert_unknown(&state, ReconcileReason::Recovery);
            assert_reconciliation(
                &actions,
                None,
                ReconcileReason::Recovery,
                desired == DesiredProtection::Enabled || hint != RecoveryHint::Missing,
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_recovery_identity_is_corruption_and_cannot_fall_back_to_disabled() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Disabled)?;
    for malformed in [
        OperationIdentity {
            service_epoch: [0; 16],
            ..identity
        },
        OperationIdentity {
            generation: 0,
            ..identity
        },
        OperationIdentity {
            operation_id: 0,
            ..identity
        },
    ] {
        let (recovered, actions) = ProtectionLifecycle::recover(
            [2; 16],
            DesiredProtection::Disabled,
            RecoveryHint::Recorded(CurrentOperation {
                identity: malformed,
                phase: CommitPhase::KernelVerified,
            }),
        )?;
        assert_eq!(recovered.recovery_hint(), Some(RecoveryHint::Corrupt));
        assert_unknown(&recovered, ReconcileReason::Recovery);
        assert_reconciliation(&actions, None, ReconcileReason::Recovery, true);
    }
    Ok(())
}

#[test]
fn recovery_rejects_a_known_reused_service_epoch() -> TestResult {
    let mut state = lifecycle()?;
    let identity = begin(&mut state, 1, DesiredProtection::Enabled)?;
    assert!(matches!(
        ProtectionLifecycle::recover(
            identity.service_epoch,
            DesiredProtection::Enabled,
            RecoveryHint::Recorded(CurrentOperation {
                identity,
                phase: CommitPhase::KernelVerified,
            }),
        ),
        Err(TransitionError::EpochReused)
    ));
    Ok(())
}

#[test]
fn an_uncorrelated_unknown_kernel_outcome_revokes_a_newer_verified_observation() -> TestResult {
    let mut state = lifecycle()?;
    let old = begin(&mut state, 1, DesiredProtection::Enabled)?;
    acknowledge(&mut state, old, 10)?;
    let new = begin(&mut state, 2, DesiredProtection::Enabled)?;
    verified(&mut state, new, 11)?;
    assert_reconciliation(
        &state.apply(TransitionEvent::OutcomeUnknown(old), 12)?,
        Some(new),
        ReconcileReason::UncorrelatedKernelResult,
        true,
    );
    assert_unknown(&state, ReconcileReason::UncorrelatedKernelResult);
    assert_eq!(state.committed(), Some(new));
    Ok(())
}
