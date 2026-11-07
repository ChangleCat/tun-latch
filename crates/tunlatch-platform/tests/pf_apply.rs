//! Injected storage/submit/read fault checks; these tests never open PF or create authorization.

use std::cell::{Cell, RefCell};
use std::error::Error;
use std::rc::Rc;

use tunlatch_core::config::DesiredProtection;
use tunlatch_core::policy::ConfigV2;
use tunlatch_core::transition::{
    CommitPhase, OperationIdentity, ProtectionLifecycle, ReconcileReason, TransitionAction,
    VerificationEvidence, VerificationState,
};
use tunlatch_platform::pf_apply::{
    APPLY_BUDGET_MS, IndependentObservation, IndependentObserver, IntentPersistence,
    MonotonicClock, PersistenceOutcome, SimulatedApplyController, SimulatedApplyOutcome,
    SimulatedPlan, SimulatedSubmitBackend, SubmissionOutcome,
};
use tunlatch_platform::policy_compile::compile_candidate;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type Trace = Rc<RefCell<Vec<&'static str>>>;
type Model = Rc<RefCell<MemoryImage>>;

#[derive(Default)]
struct MemoryImage {
    record: Option<OperationIdentity>,
    own_policy: Option<(OperationIdentity, usize)>,
    foreign_policy: [u8; 32],
    foreign_references: usize,
    sequence: u64,
}

#[derive(Clone, Copy, Default)]
enum StoreFault {
    #[default]
    None,
    BeforeReplace,
    RenameReplyLost,
    DirectorySync,
    WrongIdentity,
}

#[derive(Clone, Copy, Default)]
enum BackendFault {
    #[default]
    None,
    BeforeCommit,
    CommitReplyLost,
    WrongIdentity,
    ForeignChange,
}

#[derive(Clone, Copy, Default)]
enum ObserverFault {
    #[default]
    None,
    Mismatch,
    Unavailable,
    Expired,
    WrongIdentity,
    StateConvergenceUnknown,
}

struct Store {
    model: Model,
    trace: Trace,
    fault: Rc<Cell<StoreFault>>,
    now: Rc<Cell<u64>>,
    delay: Rc<Cell<u64>>,
}

impl IntentPersistence for Store {
    fn persist_intent(&mut self, operation: OperationIdentity) -> PersistenceOutcome {
        self.trace.borrow_mut().push("persist");
        self.now.set(self.now.get() + self.delay.get());
        if matches!(self.fault.get(), StoreFault::BeforeReplace) {
            return PersistenceOutcome::RejectedBeforeReplace(operation);
        }
        self.model.borrow_mut().record = Some(operation);
        match self.fault.get() {
            StoreFault::RenameReplyLost | StoreFault::DirectorySync => {
                PersistenceOutcome::Unknown(operation)
            }
            StoreFault::WrongIdentity => PersistenceOutcome::Durable(OperationIdentity {
                operation_id: operation.operation_id + 1,
                ..operation
            }),
            _ => PersistenceOutcome::Durable(operation),
        }
    }
}

struct Backend {
    model: Model,
    trace: Trace,
    fault: Rc<Cell<BackendFault>>,
    now: Rc<Cell<u64>>,
    delay: Rc<Cell<u64>>,
}

impl SimulatedSubmitBackend for Backend {
    fn submit(&mut self, operation: OperationIdentity, plan: &SimulatedPlan) -> SubmissionOutcome {
        self.trace.borrow_mut().push("submit");
        self.now.set(self.now.get() + self.delay.get());
        if matches!(self.fault.get(), BackendFault::BeforeCommit) {
            return SubmissionOutcome::RejectedBeforeCommit(operation);
        }
        self.model.borrow_mut().own_policy = Some((operation, plan.candidate().rule_count()));
        match self.fault.get() {
            BackendFault::CommitReplyLost => SubmissionOutcome::Unknown(operation),
            BackendFault::WrongIdentity => SubmissionOutcome::Acknowledged(OperationIdentity {
                operation_id: operation.operation_id + 1,
                ..operation
            }),
            BackendFault::ForeignChange => {
                self.model.borrow_mut().foreign_policy = [9; 32];
                SubmissionOutcome::Acknowledged(operation)
            }
            _ => SubmissionOutcome::Acknowledged(operation),
        }
    }
}

struct Observer {
    model: Model,
    trace: Trace,
    fault: Rc<Cell<ObserverFault>>,
    now: Rc<Cell<u64>>,
    delay: Rc<Cell<u64>>,
}

impl IndependentObserver for Observer {
    fn observe(&mut self, expected: OperationIdentity) -> IndependentObservation {
        self.trace.borrow_mut().push("observe");
        self.now.set(self.now.get() + self.delay.get());
        match self.fault.get() {
            ObserverFault::Mismatch => return IndependentObservation::Mismatch,
            ObserverFault::Unavailable | ObserverFault::StateConvergenceUnknown => {
                return IndependentObservation::Unavailable;
            }
            _ => {}
        }
        let mut model = self.model.borrow_mut();
        let Some((installed, _)) = model.own_policy else {
            return IndependentObservation::Unavailable;
        };
        if installed != expected || model.foreign_policy != [8; 32] {
            return IndependentObservation::Mismatch;
        }
        model.sequence += 1;
        let mut evidence = VerificationEvidence {
            identity: installed,
            observation_sequence: model.sequence,
            observed_at: self.now.get(),
            valid_until: self.now.get() + 1_000,
        };
        match self.fault.get() {
            ObserverFault::Expired => evidence.valid_until = self.now.get(),
            ObserverFault::WrongIdentity => evidence.identity.generation += 1,
            _ => {}
        }
        IndependentObservation::Evidence(evidence)
    }
}

struct Clock(Rc<Cell<u64>>);

impl MonotonicClock for Clock {
    fn now_ms(&mut self) -> u64 {
        self.0.get()
    }
}

struct Rig {
    model: Model,
    trace: Trace,
    store_fault: Rc<Cell<StoreFault>>,
    backend_fault: Rc<Cell<BackendFault>>,
    observer_fault: Rc<Cell<ObserverFault>>,
    now: Rc<Cell<u64>>,
    store_delay: Rc<Cell<u64>>,
    backend_delay: Rc<Cell<u64>>,
    observer_delay: Rc<Cell<u64>>,
}

type Controller = SimulatedApplyController<Store, Backend, Observer, Clock>;

impl Rig {
    fn new() -> Self {
        Self {
            model: Rc::new(RefCell::new(MemoryImage {
                foreign_policy: [8; 32],
                foreign_references: 2,
                ..MemoryImage::default()
            })),
            trace: Rc::default(),
            store_fault: Rc::default(),
            backend_fault: Rc::default(),
            observer_fault: Rc::default(),
            now: Rc::new(Cell::new(100)),
            store_delay: Rc::default(),
            backend_delay: Rc::default(),
            observer_delay: Rc::default(),
        }
    }

    fn controller(&self) -> TestResult<Controller> {
        Ok(SimulatedApplyController::new(
            ProtectionLifecycle::new([1; 16], DesiredProtection::Disabled)?,
            Store {
                model: self.model.clone(),
                trace: self.trace.clone(),
                fault: self.store_fault.clone(),
                now: self.now.clone(),
                delay: self.store_delay.clone(),
            },
            Backend {
                model: self.model.clone(),
                trace: self.trace.clone(),
                fault: self.backend_fault.clone(),
                now: self.now.clone(),
                delay: self.backend_delay.clone(),
            },
            Observer {
                model: self.model.clone(),
                trace: self.trace.clone(),
                fault: self.observer_fault.clone(),
                now: self.now.clone(),
                delay: self.observer_delay.clone(),
            },
            Clock(self.now.clone()),
        ))
    }
}

fn plan(desired: DesiredProtection) -> TestResult<SimulatedPlan> {
    let mode = match desired {
        DesiredProtection::Enabled => "enabled",
        DesiredProtection::Disabled => "disabled",
    };
    let config = ConfigV2::parse_json(
        format!(
            "{{\"schema_version\":2,\"desired\":\"{mode}\",\"rules\":[],\"direct_exceptions\":[]}}"
        )
        .as_bytes(),
    )?;
    Ok(SimulatedPlan::from_candidate(compile_candidate(&config)?)?)
}

fn has_blocking(actions: &[TransitionAction]) -> bool {
    actions
        .iter()
        .any(|action| matches!(action, TransitionAction::RequireBlocking { .. }))
}

#[test]
fn durable_intent_precedes_one_submission_and_a_separate_model_read() -> TestResult {
    let rig = Rig::new();
    let mut controller = rig.controller()?;
    let plan = plan(DesiredProtection::Enabled)?;
    assert_ne!(
        plan.digest().as_bytes(),
        plan.candidate().digest().as_bytes()
    );
    let report = controller.submit(7, 0, &plan)?;
    assert_eq!(report.outcome, SimulatedApplyOutcome::ModelVerified);
    assert_eq!(*rig.trace.borrow(), ["persist", "submit", "observe"]);
    assert_eq!(rig.model.borrow().record, Some(report.operation));
    assert_eq!(controller.lifecycle().committed(), Some(report.operation));
    assert!(matches!(
        controller.lifecycle().observed(),
        VerificationState::Verified(evidence) if evidence.identity == report.operation
    ));
    // The isolated model read cannot satisfy real blocking, state or authority prerequisites.
    assert!(has_blocking(&report.required_actions));
    assert_eq!(rig.model.borrow().foreign_policy, [8; 32]);
    assert_eq!(rig.model.borrow().foreign_references, 2);
    Ok(())
}

#[test]
fn failure_before_record_replacement_preserves_the_old_record_and_skips_submit() -> TestResult {
    let rig = Rig::new();
    let mut controller = rig.controller()?;
    let plan = plan(DesiredProtection::Enabled)?;
    let first = controller.submit(1, 0, &plan)?;
    rig.trace.borrow_mut().clear();
    rig.store_fault.set(StoreFault::BeforeReplace);
    let report = controller.submit(2, 1, &plan)?;
    assert_eq!(report.outcome, SimulatedApplyOutcome::IntentRejected);
    assert_eq!(*rig.trace.borrow(), ["persist"]);
    assert_eq!(rig.model.borrow().record, Some(first.operation));
    assert_eq!(
        rig.model.borrow().own_policy.map(|p| p.0),
        Some(first.operation)
    );
    assert_eq!(controller.lifecycle().committed(), Some(first.operation));
    assert!(matches!(
        controller.lifecycle().observed(),
        VerificationState::Unknown { .. }
    ));
    assert!(has_blocking(&report.required_actions));
    Ok(())
}

#[test]
fn rename_or_directory_sync_uncertainty_never_counts_as_durable_or_starts_submission() -> TestResult
{
    for fault in [StoreFault::RenameReplyLost, StoreFault::DirectorySync] {
        let rig = Rig::new();
        rig.store_fault.set(fault);
        let mut controller = rig.controller()?;
        let report = controller.submit(1, 0, &plan(DesiredProtection::Enabled)?)?;
        assert_eq!(report.outcome, SimulatedApplyOutcome::IntentUnknown);
        assert_eq!(*rig.trace.borrow(), ["persist"]);
        // Seeing the new bytes does not prove parent-directory durability.
        assert_eq!(rig.model.borrow().record, Some(report.operation));
        assert!(rig.model.borrow().own_policy.is_none());
        assert!(controller.lifecycle().committed().is_none());
        assert_eq!(
            controller.lifecycle().current().map(|op| op.phase),
            Some(CommitPhase::OutcomeUnknown)
        );
        assert!(has_blocking(&report.required_actions));
    }
    Ok(())
}

#[test]
fn backend_rejection_and_lost_commit_reply_never_trigger_automatic_retry_or_read_as_success()
-> TestResult {
    for (fault, outcome, was_committed) in [
        (
            BackendFault::BeforeCommit,
            SimulatedApplyOutcome::SubmissionRejected,
            false,
        ),
        (
            BackendFault::CommitReplyLost,
            SimulatedApplyOutcome::SubmissionUnknown,
            true,
        ),
    ] {
        let rig = Rig::new();
        rig.backend_fault.set(fault);
        let mut controller = rig.controller()?;
        let plan = plan(DesiredProtection::Enabled)?;
        let report = controller.submit(1, 0, &plan)?;
        assert_eq!(report.outcome, outcome);
        assert_eq!(*rig.trace.borrow(), ["persist", "submit"]);
        assert_eq!(rig.model.borrow().own_policy.is_some(), was_committed);
        assert!(controller.lifecycle().committed().is_none());
        assert_eq!(
            controller.submit(1, 0, &plan)?.outcome,
            SimulatedApplyOutcome::NoNewSubmission
        );
        assert_eq!(*rig.trace.borrow(), ["persist", "submit"]);
        drop(controller);
        assert_eq!(rig.model.borrow().own_policy.is_some(), was_committed);
        assert_eq!(rig.model.borrow().foreign_references, 2);
    }
    Ok(())
}

#[test]
fn separate_read_mismatch_unavailability_and_stale_evidence_reject_model_success() -> TestResult {
    for (fault, outcome) in [
        (
            ObserverFault::Mismatch,
            SimulatedApplyOutcome::ObservationMismatch,
        ),
        (
            ObserverFault::Unavailable,
            SimulatedApplyOutcome::ObservationUnavailable,
        ),
        (
            ObserverFault::Expired,
            SimulatedApplyOutcome::ObservationRejected,
        ),
        (
            ObserverFault::WrongIdentity,
            SimulatedApplyOutcome::ObservationRejected,
        ),
        (
            ObserverFault::StateConvergenceUnknown,
            SimulatedApplyOutcome::ObservationUnavailable,
        ),
    ] {
        let rig = Rig::new();
        rig.observer_fault.set(fault);
        let mut controller = rig.controller()?;
        let report = controller.submit(1, 0, &plan(DesiredProtection::Enabled)?)?;
        assert_eq!(report.outcome, outcome);
        assert_eq!(*rig.trace.borrow(), ["persist", "submit", "observe"]);
        assert_eq!(controller.lifecycle().committed(), Some(report.operation));
        assert!(matches!(
            controller.lifecycle().observed(),
            VerificationState::Unknown { .. }
        ));
        assert!(has_blocking(&report.required_actions));
    }
    Ok(())
}

#[test]
fn wrong_persistence_or_submission_receipts_do_not_advance_the_current_operation() -> TestResult {
    for wrong_store in [true, false] {
        let rig = Rig::new();
        if wrong_store {
            rig.store_fault.set(StoreFault::WrongIdentity);
        } else {
            rig.backend_fault.set(BackendFault::WrongIdentity);
        }
        let mut controller = rig.controller()?;
        let report = controller.submit(1, 0, &plan(DesiredProtection::Enabled)?)?;
        assert_eq!(report.outcome, SimulatedApplyOutcome::UncorrelatedResult);
        let expected: &[&str] = if wrong_store {
            &["persist"]
        } else {
            &["persist", "submit"]
        };
        assert_eq!(&*rig.trace.borrow(), expected);
        assert!(controller.lifecycle().committed().is_none());
        assert!(matches!(
            controller.lifecycle().observed(),
            VerificationState::Unknown { .. }
        ));
    }
    Ok(())
}

#[test]
fn budgets_are_rechecked_after_each_callback_without_claiming_to_interrupt_it() -> TestResult {
    for boundary in 0..3 {
        let rig = Rig::new();
        match boundary {
            0 => rig.store_delay.set(APPLY_BUDGET_MS),
            1 => rig.backend_delay.set(APPLY_BUDGET_MS),
            _ => rig.observer_delay.set(APPLY_BUDGET_MS),
        }
        let mut controller = rig.controller()?;
        let report = controller.submit(1, 0, &plan(DesiredProtection::Enabled)?)?;
        assert_eq!(report.outcome, SimulatedApplyOutcome::BudgetExceeded);
        let expected: &[&str] = match boundary {
            0 => &["persist"],
            1 => &["persist", "submit"],
            _ => &["persist", "submit", "observe"],
        };
        assert_eq!(&*rig.trace.borrow(), expected);
        assert!(matches!(
            controller.lifecycle().observed(),
            VerificationState::Unknown { .. }
        ));
        assert!(has_blocking(&report.required_actions));
        // The callback returned after changing state; budget expiry did not undo its effects.
        assert!(rig.model.borrow().record.is_some());
        assert_eq!(rig.model.borrow().own_policy.is_some(), boundary != 0);
    }
    Ok(())
}

#[test]
fn foreign_policy_change_is_observed_without_cleanup_or_reference_release() -> TestResult {
    let rig = Rig::new();
    rig.backend_fault.set(BackendFault::ForeignChange);
    let mut controller = rig.controller()?;
    let report = controller.submit(1, 0, &plan(DesiredProtection::Enabled)?)?;
    assert_eq!(report.outcome, SimulatedApplyOutcome::ObservationMismatch);
    assert_eq!(rig.model.borrow().foreign_policy, [9; 32]);
    drop(controller);
    assert_eq!(rig.model.borrow().foreign_policy, [9; 32]);
    assert_eq!(rig.model.borrow().foreign_references, 2);
    assert_eq!(*rig.trace.borrow(), ["persist", "submit", "observe"]);
    Ok(())
}

#[test]
fn late_old_kernel_success_revokes_newer_model_verification_without_resubmitting() -> TestResult {
    let rig = Rig::new();
    let mut controller = rig.controller()?;
    let plan = plan(DesiredProtection::Enabled)?;
    let old = controller.submit(1, 0, &plan)?;
    let new = controller.submit(2, 1, &plan)?;
    let calls = rig.trace.borrow().len();
    let actions =
        controller.receive_late_submission(SubmissionOutcome::Acknowledged(old.operation))?;
    assert!(has_blocking(&actions));
    assert_eq!(controller.lifecycle().committed(), Some(new.operation));
    assert_eq!(
        controller.lifecycle().observed(),
        VerificationState::Unknown {
            reason: ReconcileReason::UncorrelatedKernelResult,
        }
    );
    assert_eq!(rig.trace.borrow().len(), calls);
    Ok(())
}

#[test]
fn explicit_disable_and_its_retry_touch_only_owned_modeled_policy() -> TestResult {
    let rig = Rig::new();
    let mut controller = rig.controller()?;
    controller.submit(1, 0, &plan(DesiredProtection::Enabled)?)?;
    let disabled = plan(DesiredProtection::Disabled)?;
    let report = controller.submit(2, 1, &disabled)?;
    assert_eq!(report.outcome, SimulatedApplyOutcome::ModelVerified);
    assert_eq!(report.operation.desired, DesiredProtection::Disabled);
    assert!(report.required_actions.is_empty());
    assert_eq!(rig.model.borrow().own_policy, Some((report.operation, 0)));
    let calls = rig.trace.borrow().len();
    assert_eq!(
        controller.submit(2, 1, &disabled)?.outcome,
        SimulatedApplyOutcome::NoNewSubmission
    );
    assert_eq!(rig.trace.borrow().len(), calls);
    assert_eq!(rig.model.borrow().foreign_policy, [8; 32]);
    assert_eq!(rig.model.borrow().foreign_references, 2);
    Ok(())
}

#[test]
fn waiter_departure_and_drop_never_roll_back_or_clean_up_modeled_policy() -> TestResult {
    let rig = Rig::new();
    let mut controller = rig.controller()?;
    let report = controller.submit(1, 0, &plan(DesiredProtection::Enabled)?)?;
    let observation = controller.lifecycle().observed();
    assert!(controller.client_timed_out(report.operation)?.is_empty());
    assert_eq!(controller.lifecycle().observed(), observation);
    assert_eq!(*rig.trace.borrow(), ["persist", "submit", "observe"]);
    let (_, _store, _backend, _observer, _clock) = controller.into_parts();
    assert_eq!(rig.model.borrow().record, Some(report.operation));
    assert_eq!(
        rig.model.borrow().own_policy.map(|p| p.0),
        Some(report.operation)
    );
    assert_eq!(rig.model.borrow().foreign_references, 2);
    Ok(())
}

#[test]
fn identical_retry_checks_expiry_without_replaying_storage_or_submission() -> TestResult {
    let rig = Rig::new();
    let mut controller = rig.controller()?;
    let plan = plan(DesiredProtection::Enabled)?;
    controller.submit(1, 0, &plan)?;
    rig.now.set(1_100);
    let retry = controller.submit(1, 0, &plan)?;
    assert_eq!(retry.outcome, SimulatedApplyOutcome::NoNewSubmission);
    assert_eq!(*rig.trace.borrow(), ["persist", "submit", "observe"]);
    assert_eq!(
        controller.lifecycle().observed(),
        VerificationState::Unknown {
            reason: ReconcileReason::ObservationExpired,
        }
    );
    assert!(has_blocking(&retry.required_actions));
    Ok(())
}

#[test]
fn rejected_request_returns_reconciliation_discovered_at_expiry() -> TestResult {
    let rig = Rig::new();
    let mut controller = rig.controller()?;
    let plan = plan(DesiredProtection::Enabled)?;
    controller.submit(1, 0, &plan)?;
    rig.now.set(1_100);
    let result = controller.submit(2, 0, &plan);
    let Err(error) = result else {
        return Err("stale generation was accepted".into());
    };
    assert!(has_blocking(error.required_actions()));
    assert!(error.required_actions().iter().any(|action| matches!(
        action,
        TransitionAction::Inspect {
            reason: ReconcileReason::ObservationExpired,
            ..
        }
    )));
    assert_eq!(
        controller.lifecycle().observed(),
        VerificationState::Unknown {
            reason: ReconcileReason::ObservationExpired,
        }
    );
    assert_eq!(*rig.trace.borrow(), ["persist", "submit", "observe"]);
    Ok(())
}
