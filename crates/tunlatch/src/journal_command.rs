//! User-private durable simulation intent; no administrator policy or PF operation is accepted.

use std::{cell::RefCell, path::Path, rc::Rc, time::Instant};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tunlatch_core::{
    config::DesiredProtection,
    policy::ConfigV2,
    transition::{
        CommitPhase, CurrentOperation, EffectivePolicyDigest, OperationIdentity,
        ProtectionLifecycle, RecoveryHint, TransitionAction, VerificationEvidence,
        VerificationState,
    },
};
use tunlatch_platform::{
    pf_apply::{
        IndependentObservation, IndependentObserver, IntentPersistence, MonotonicClock,
        PersistenceOutcome, SimulatedApplyController, SimulatedApplyOutcome, SimulatedPlan,
        SimulatedSubmitBackend, SubmissionOutcome,
    },
    policy_compile::compile_candidate,
    store::{RecordIdentity, RecordKind, StoredRecord, UserRecordStore},
};

use crate::config_command;

const FORMAT: &str = "tunlatch-user-simulated-intent";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    format: String,
    revision: u8,
    epoch: [u8; 16],
    generation: u64,
    operation_id: u64,
    effective_digest: [u8; 32],
    source_digest: [u8; 32],
    candidate_digest: [u8; 32],
    desired: DesiredProtection,
    policy: String,
}

impl Intent {
    fn from_operation(operation: OperationIdentity, plan: &SimulatedPlan, policy: &str) -> Self {
        Self {
            format: FORMAT.into(),
            revision: 1,
            epoch: operation.service_epoch,
            generation: operation.generation,
            operation_id: operation.operation_id,
            effective_digest: *operation.policy_digest.as_bytes(),
            source_digest: *plan.candidate().source_digest().as_bytes(),
            candidate_digest: *plan.candidate().digest().as_bytes(),
            desired: operation.desired,
            policy: policy.to_owned(),
        }
    }

    fn check(&self, policy: &ConfigV2, plan: &SimulatedPlan) -> anyhow::Result<OperationIdentity> {
        if self.format != FORMAT
            || self.revision != 1
            || self.epoch == [0; 16]
            || self.generation == 0
            || self.operation_id == 0
            || self.desired != policy.desired()
            || self.effective_digest != *plan.digest().as_bytes()
            || self.source_digest != *policy.digest().as_bytes()
            || self.candidate_digest != *plan.candidate().digest().as_bytes()
        {
            bail!("local simulation intent does not match its validated policy");
        }
        Ok(OperationIdentity {
            service_epoch: self.epoch,
            generation: self.generation,
            operation_id: self.operation_id,
            policy_digest: EffectivePolicyDigest::new(self.effective_digest)?,
            desired: self.desired,
        })
    }
}

fn fresh_epoch() -> anyhow::Result<[u8; 16]> {
    let mut epoch = [0; 16];
    getrandom::fill(&mut epoch).context("cannot obtain a fresh simulation epoch")?;
    if epoch == [0; 16] {
        bail!("random epoch used a reserved value");
    }
    Ok(epoch)
}

fn open_store(path: &Path) -> anyhow::Result<UserRecordStore> {
    if !std::fs::symlink_metadata(path)?.file_type().is_dir() {
        bail!("state directory must be an existing real directory");
    }
    // Resolve ordinary-user aliases before the store independently checks and holds its chain.
    // No resolved or caller-controlled path is ever passed to the fixed root-store entry.
    let canonical = std::fs::canonicalize(path)?;
    UserRecordStore::open(&canonical).context("cannot open private user record store")
}

fn load(store: &UserRecordStore) -> anyhow::Result<Option<OperationIdentity>> {
    let Some(record) = store.read(RecordKind::Recovery)? else {
        return Ok(None);
    };
    let intent: Intent = serde_json::from_slice(record.payload())?;
    let config = ConfigV2::parse_json(intent.policy.as_bytes())?;
    if config.canonical_json() != intent.policy.as_bytes() {
        bail!("local intent policy is not in canonical form");
    }
    let plan = SimulatedPlan::from_candidate(compile_candidate(&config)?)?;
    if record.identity() != RecordIdentity::new(*plan.digest().as_bytes())? {
        bail!("local intent record identity differs from its policy");
    }
    Ok(Some(intent.check(&config, &plan)?))
}

struct DiskIntent<'a> {
    store: UserRecordStore,
    plan: &'a SimulatedPlan,
    policy: &'a str,
    failure: Option<String>,
    outcome: Option<PersistenceOutcome>,
}

impl IntentPersistence for DiskIntent<'_> {
    fn persist_intent(&mut self, operation: OperationIdentity) -> PersistenceOutcome {
        let result = (|| {
            let payload =
                serde_json::to_vec(&Intent::from_operation(operation, self.plan, self.policy))
                    .map_err(|_| {
                        tunlatch_platform::store::StoreError::Refused("cannot encode intent")
                    })?;
            let record = StoredRecord::new(
                RecordIdentity::new(*operation.policy_digest.as_bytes())?,
                payload,
            )?;
            self.store.replace(RecordKind::Recovery, &record)
        })();
        let outcome = match result {
            Ok(()) => PersistenceOutcome::Durable(operation),
            Err(error) => {
                let unknown = error.is_commit_unknown();
                self.failure = Some(error.to_string());
                if unknown {
                    PersistenceOutcome::Unknown(operation)
                } else {
                    PersistenceOutcome::RejectedBeforeReplace(operation)
                }
            }
        };
        self.outcome = Some(outcome);
        outcome
    }
}

struct ModelWriter(Rc<RefCell<Option<OperationIdentity>>>);
impl SimulatedSubmitBackend for ModelWriter {
    fn submit(&mut self, operation: OperationIdentity, _plan: &SimulatedPlan) -> SubmissionOutcome {
        *self.0.borrow_mut() = Some(operation);
        SubmissionOutcome::Acknowledged(operation)
    }
}

struct PreviewClock(Instant);
impl MonotonicClock for PreviewClock {
    fn now_ms(&mut self) -> u64 {
        self.0.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
    }
}

struct ModelReader {
    state: Rc<RefCell<Option<OperationIdentity>>>,
    started: Instant,
}
impl IndependentObserver for ModelReader {
    fn observe(&mut self, expected: OperationIdentity) -> IndependentObservation {
        match *self.state.borrow() {
            Some(actual) if actual == expected => {
                let now = PreviewClock(self.started).now_ms();
                IndependentObservation::Evidence(VerificationEvidence {
                    identity: actual,
                    observation_sequence: 1,
                    observed_at: now,
                    valid_until: now.saturating_add(1_000),
                })
            }
            Some(_) => IndependentObservation::Mismatch,
            None => IndependentObservation::Unavailable,
        }
    }
}

/// Persist a real local intent and run only a separately named in-memory submission/read model.
pub fn preview(source: &Path, state_dir: &Path, json_output: bool) -> anyhow::Result<()> {
    require_user()?;
    let config = config_command::draft(source)?;
    let plan = SimulatedPlan::from_candidate(compile_candidate(&config)?)?;
    let policy = std::str::from_utf8(config.canonical_json())?;
    let store = open_store(state_dir)?;
    // Refuse to erase damaged or interrupted records. No automatic rollback or repair occurs.
    let previous = load(&store)?;
    let epoch = fresh_epoch()?;
    if previous.is_some_and(|operation| operation.service_epoch == epoch) {
        bail!("simulation epoch reused");
    }
    let lifecycle = ProtectionLifecycle::new(epoch, config.desired())?;
    let started = Instant::now();
    let memory = Rc::new(RefCell::new(None));
    let persistence = DiskIntent {
        store,
        plan: &plan,
        policy,
        failure: None,
        outcome: None,
    };
    let mut controller = SimulatedApplyController::new(
        lifecycle,
        persistence,
        ModelWriter(Rc::clone(&memory)),
        ModelReader {
            state: memory,
            started,
        },
        PreviewClock(started),
    );
    let report = controller.submit(1, 0, &plan)?;
    let (_, persistence, _, _, _) = controller.into_parts();
    let matched = report.outcome == SimulatedApplyOutcome::ModelVerified;
    let durability = match persistence.outcome {
        Some(PersistenceOutcome::Durable(_)) => "durable",
        Some(PersistenceOutcome::RejectedBeforeReplace(_)) => "not_replaced",
        Some(PersistenceOutcome::Unknown(_)) => "unknown",
        None => "not_attempted",
    };
    let out = json!({
        "mode": "simulation", "simulation_outcome": format!("{:?}", report.outcome),
        "generation": report.operation.generation,
        "intent_durability": durability,
        "recovery_record": (durability == "durable").then_some("intent_only"),
        "unfulfilled_reconciliation_actions": report.required_actions.len(),
        "storage_error": persistence.failure,
        "authorization": "none", "actual_protection": "unknown",
        "pf_operations": 0, "network_changes": false,
    });
    print_output(&out, json_output)?;
    if !matched {
        bail!("local simulation did not complete; preserve records, do not infer rollback");
    }
    Ok(())
}

/// Inspect persisted hints with a fresh epoch; never restore commits or observations from disk.
pub fn inspect(state_dir: &Path, json_output: bool) -> anyhow::Result<()> {
    require_user()?;
    let store = open_store(state_dir)?;
    let (state, desired, hint, problem) = match load(&store) {
        Ok(None) => ("missing", None, RecoveryHint::Missing, None),
        Ok(Some(operation)) => (
            "intent",
            Some(operation.desired),
            RecoveryHint::Recorded(CurrentOperation {
                identity: operation,
                phase: CommitPhase::Requested,
            }),
            None,
        ),
        Err(error) => (
            "corrupt_or_unreadable",
            None,
            RecoveryHint::Corrupt,
            Some(error.to_string()),
        ),
    };
    let (lifecycle, actions) = ProtectionLifecycle::recover(
        fresh_epoch()?,
        desired.unwrap_or(DesiredProtection::Disabled),
        hint,
    )?;
    let out = json!({
        "mode": "simulation", "journal_state": state, "recorded_desired": desired,
        "recorded_phase": if state == "intent" { Some("requested") } else { None },
        "restored_committed": lifecycle.committed().is_some(),
        "restored_verified": matches!(lifecycle.observed(), VerificationState::Verified(_)),
        "blocking_required": actions.iter().any(|a| matches!(a, TransitionAction::RequireBlocking { .. })),
        "inspection_required": actions.iter().any(|a| matches!(a, TransitionAction::Inspect { .. })),
        "problem": problem,
        "authorization": "none", "actual_protection": "unknown", "pf_operations": 0,
    });
    print_output(&out, json_output)?;
    if state == "corrupt_or_unreadable" {
        bail!("local records require reconciliation; no disabled state inferred");
    }
    Ok(())
}

fn require_user() -> anyhow::Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        bail!("the local simulation journal requires an ordinary user");
    }
    Ok(())
}

fn print_output(value: &Value, json_output: bool) -> anyhow::Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else {
        println!("User-private simulation journal.");
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}
