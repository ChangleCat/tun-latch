//! One approved, unattached PF rule-slot experiment with independent readback.

#[allow(dead_code)]
#[path = "../tests/pf_lab/bootstrap.rs"]
mod bootstrap;
#[cfg(test)]
#[path = "../tests/pf_lab/sync_flow_tests.rs"]
mod flow_tests;
#[path = "../tests/pf_lab/ledger.rs"]
mod ledger;
#[path = "../tests/pf_lab/native_files.rs"]
mod native_files;
#[path = "../tests/pf_lab/native_filter.rs"]
mod native_filter;
#[path = "../tests/pf_lab/sync_observe.rs"]
mod sync_observe;
#[path = "../tests/pf_lab/sync_storage.rs"]
mod sync_storage;

use bootstrap::{Error, Result};
use ledger::{Ledger, Operation, State};
use native_filter::Replacement;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use sync_observe::{Slot, Snapshot};
use sync_storage::Storage;

const MAX_RECORD: usize = 1024 * 1024;
const STAGE_WINDOW_SECS: u64 = 300;
const MODE: &str = "pf-sync-manual-trial";

#[derive(Clone, Copy)]
enum Action {
    Prepare,
    Status,
    Stage,
    Recover,
    CaptureUnknown,
}

impl Action {
    fn parse(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<Self> {
        let action = match args.next().as_deref().and_then(|arg| arg.to_str()) {
            Some("prepare") => Self::Prepare,
            Some("status") => Self::Status,
            Some("stage") => Self::Stage,
            Some("recover") => Self::Recover,
            Some("capture-unknown") => Self::CaptureUnknown,
            _ => return Err(Error::Refused("expected one fixed PF trial action")),
        };
        if args.next().is_some() {
            return Err(Error::Refused(
                "PF trial does not accept additional arguments",
            ));
        }
        Ok(action)
    }
}

trait Trial {
    fn program_digest(&self) -> Result<[u8; 32]>;
    fn recheck(&self) -> Result<()>;
    fn exists(&self, name: &str) -> Result<bool>;
    fn read(&self, name: &str, max: usize) -> Result<Vec<u8>>;
    fn write(&self, name: &str, data: &[u8]) -> Result<()>;
    fn subdir(&self, name: &str, create: bool) -> Result<File>;
    fn boot(&self) -> Result<String>;
    fn ticks(&self) -> Result<u64>;
    fn observe(&self, anchor: &str) -> Result<Snapshot>;
    fn submit(&self, suffix: &str, replacement: Replacement) -> Result<()>;
}

impl Trial for Storage {
    fn program_digest(&self) -> Result<[u8; 32]> {
        self.program_digest()
    }
    fn recheck(&self) -> Result<()> {
        self.recheck()
    }
    fn exists(&self, name: &str) -> Result<bool> {
        self.exists(name)
    }
    fn read(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        self.read(name, max)
    }
    fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        self.write(name, data)
    }
    fn subdir(&self, name: &str, create: bool) -> Result<File> {
        self.subdir(name, create)
    }
    fn boot(&self) -> Result<String> {
        Ok(sync_observe::boot()?)
    }
    fn ticks(&self) -> Result<u64> {
        let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
        Ok(u64::try_from(now.tv_sec()).map_err(io::Error::other)?)
    }
    fn observe(&self, anchor: &str) -> Result<Snapshot> {
        Ok(sync_observe::read(anchor)?)
    }
    fn submit(&self, suffix: &str, replacement: Replacement) -> Result<()> {
        native_filter::transaction(suffix, replacement)
            .map_err(|_| Error::Refused("fixed filter transaction could not be built"))?
            .commit()
            .map_err(|_| Error::Refused("PF commit outcome unknown; preserve the trial"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    boot: String,
    mode: String,
    sha256: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Session {
    boot: String,
    helper: [u8; 32],
    nonce: [u8; 32],
    created_ticks: u64,
    baseline: [u8; 32],
    prepared_observation: [u8; 32],
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn json_bytes(data: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(data).map_err(io::Error::other)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECORD {
        return Err(Error::Refused("observation record exceeds its bound"));
    }
    Ok(bytes)
}

fn operator(trial: &impl Trial) -> Result<(String, [u8; 32])> {
    let manifest: Manifest = serde_json::from_slice(&trial.read("operator-manifest.json", 512)?)
        .map_err(io::Error::other)?;
    let boot = trial.boot()?;
    let helper = trial.program_digest()?;
    if manifest.mode != MODE || manifest.boot != boot || manifest.sha256 != hex(&helper) {
        return Err(Error::Refused(
            "operator manifest does not match this boot and executable",
        ));
    }
    Ok((boot, helper))
}

fn fresh_observation(trial: &impl Trial, nonce: &[u8; 32]) -> Result<(String, Snapshot)> {
    if *nonce == [0; 32] {
        return Err(Error::Refused("missing trial identity"));
    }
    for name in ["session.json", "prepare.json", "stage", "recovery"] {
        if trial.exists(name)? {
            return Err(Error::Refused("trial directory has prior records"));
        }
    }
    let anchor = format!("tunlatch-lab-{}", hex(&nonce[..4]));
    let first = trial.observe(&anchor)?;
    if first.slot != Slot::Absent {
        return Err(Error::Refused("fresh slot already exists"));
    }
    trial.recheck()?;
    Ok((anchor, first))
}

fn preflight(trial: &impl Trial, nonce: [u8; 32]) -> Result<Value> {
    operator(trial)?;
    let (_, snapshot) = fresh_observation(trial, &nonce)?;
    let mut result = report("not_allocated", "preflight_ready", "absent");
    result["baseline_sha256"] = json!(hex(&snapshot.baseline.digest()));
    Ok(result)
}

fn prepare(trial: &impl Trial, nonce: [u8; 32]) -> Result<Value> {
    let (boot, helper) = operator(trial)?;
    let (anchor, first) = fresh_observation(trial, &nonce)?;
    let observation = json_bytes(&first)?;
    let created_ticks = trial.ticks()?;
    if created_ticks == 0 {
        return Err(Error::Refused("missing trial creation time"));
    }
    let session = Session {
        boot,
        helper,
        nonce,
        created_ticks,
        baseline: first.baseline.digest(),
        prepared_observation: sha(&observation),
    };
    trial.recheck()?;
    trial.write("prepare.json", &observation)?;
    trial.write("session.json", &json_bytes(&session)?)?;
    let mut result = report(&anchor, "prepared", "absent");
    result["baseline_sha256"] = json!(hex(&session.baseline));
    Ok(result)
}

struct Bound {
    session: Session,
    plan: [u8; 32],
    suffix: String,
    anchor: String,
}

impl Bound {
    fn load(trial: &impl Trial) -> Result<Self> {
        let (boot, helper) = operator(trial)?;
        let record = trial.read("session.json", 4096)?;
        let session: Session = serde_json::from_slice(&record).map_err(io::Error::other)?;
        if session.boot != boot
            || session.helper != helper
            || session.nonce == [0; 32]
            || session.created_ticks == 0
            || session.prepared_observation != sha(&trial.read("prepare.json", MAX_RECORD)?)
            || json_bytes(&session)? != record
        {
            return Err(Error::Refused(
                "trial identity or initial observation changed",
            ));
        }
        let suffix = hex(&session.nonce[..4]);
        let anchor = format!("tunlatch-lab-{suffix}");
        Ok(Self {
            session,
            plan: sha(&record),
            suffix,
            anchor,
        })
    }

    fn observe(&self, trial: &impl Trial) -> Result<Snapshot> {
        let current = trial.observe(&self.anchor)?;
        if current.baseline.digest() != self.session.baseline {
            return Err(Error::Refused("root or foreign PF baseline changed"));
        }
        Ok(current)
    }

    fn slot(&self, current: &Slot) -> Result<&'static str> {
        match current {
            Slot::Absent => Ok("absent"),
            Slot::Empty => Ok("empty"),
            Slot::Active(raw) => {
                if native_filter::matches_observed(&self.suffix, raw)
                    .map_err(|_| Error::Refused("invalid fixed rule profile"))?
                {
                    Ok("candidate")
                } else {
                    Ok("unrecognized")
                }
            }
        }
    }

    fn phase_plan(&self, phase: &str, observation: &[u8]) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.plan);
        hash.update(phase.as_bytes());
        hash.update(sha(observation));
        hash.finalize().into()
    }

    fn reopen(&self, trial: &impl Trial, phase: &str, record: &str) -> Result<Ledger> {
        let ledger = Ledger::reopen(trial.subdir(phase, false)?)?;
        let plan = self.phase_plan(phase, &trial.read(record, MAX_RECORD)?);
        if ledger.identity() != (self.session.nonce, plan) {
            return Err(Error::Refused("trial phase record changed"));
        }
        Ok(ledger)
    }

    fn recheck_before_write(&self, trial: &impl Trial, before: &Snapshot) -> Result<()> {
        if self.observe(trial)? != *before {
            return Err(Error::Refused("PF changed before mutation"));
        }
        trial.recheck()
    }

    fn check_stage_window(&self, trial: &impl Trial) -> Result<()> {
        if trial
            .ticks()?
            .checked_sub(self.session.created_ticks)
            .is_none_or(|age| age >= STAGE_WINDOW_SECS)
        {
            return Err(Error::Refused("stage window expired"));
        }
        Ok(())
    }

    fn stage(&self, trial: &impl Trial) -> Result<Value> {
        self.check_stage_window(trial)?;
        if trial.exists("stage")? || trial.exists("recovery")? {
            return Err(Error::Refused("stage attempt already consumed"));
        }
        let before = self.observe(trial)?;
        if before.slot != Slot::Absent {
            return Err(Error::Refused("slot no longer absent before first submit"));
        }
        let dir = trial.subdir("stage", true)?;
        let data = json_bytes(&before)?;
        trial.write("before-stage.json", &data)?;
        let mut ledger = Ledger::create(dir, self.session.nonce, self.phase_plan("stage", &data))?;
        ledger.begin(Operation::WriteFilter)?;
        let result = self
            .recheck_before_write(trial, &before)
            .and_then(|()| ledger.check_named_objects())
            .and_then(|()| self.check_stage_window(trial))
            .and_then(|()| trial.submit(&self.suffix, Replacement::Stage));
        if let Err(error) = result {
            let _ = ledger.unknown();
            return Err(error);
        }
        // Intent deliberately remains unsettled. The agreed controlled stop is after
        // the synchronous call returns and before the first post-submit PF query.
        Ok(report(
            &self.anchor,
            "submit_returned_unverified",
            "not_read",
        ))
    }

    fn recover(&self, trial: &impl Trial) -> Result<Value> {
        if trial.exists("recovery")? {
            return Err(Error::Refused("recovery attempt already consumed"));
        }
        let stage = self.reopen(trial, "stage", "before-stage.json")?;
        if !matches!(
            stage.state(),
            State::Intent(Operation::WriteFilter) | State::Unknown(Operation::WriteFilter)
        ) {
            return Err(Error::Refused("stage has no recoverable intent"));
        }
        let before = self.observe(trial)?;
        if self.slot(&before.slot)? == "unrecognized" {
            return Err(Error::Refused(
                "slot contains unrecognized active rules; preserve it",
            ));
        }
        let dir = trial.subdir("recovery", true)?;
        let data = json_bytes(&before)?;
        trial.write("before-recovery.json", &data)?;
        let mut ledger =
            Ledger::create(dir, self.session.nonce, self.phase_plan("recovery", &data))?;
        let verified = std::cell::Cell::new("not_read");
        ledger.apply_and_observe::<Error>(
            Operation::WriteFilter,
            || {
                self.recheck_before_write(trial, &before)?;
                stage.check_named_objects()?;
                // A read of active empty cannot rule out old inactive rules.
                trial.submit(&self.suffix, Replacement::Empty)
            },
            || {
                let after = trial.observe(&self.anchor)?;
                let data = json_bytes(&after)?;
                trial.write("after-recovery.json", &data)?;
                if after.baseline.digest() != self.session.baseline {
                    return Err(Error::Refused(
                        "foreign PF baseline changed during recovery",
                    ));
                }
                match after.slot {
                    Slot::Absent => verified.set("absent"),
                    Slot::Empty => verified.set("empty"),
                    Slot::Active(_) => {
                        return Err(Error::Refused("filter not empty after recovery"));
                    }
                }
                trial.recheck()?;
                trial.write("recovery-return.sha256", &receipt_digest(&data))
            },
        )?;
        ledger.close()?;
        Ok(report(
            &self.anchor,
            "recovery_readback_verified",
            verified.get(),
        ))
    }

    fn status(&self, trial: &impl Trial) -> Result<Value> {
        let phase = if trial.exists("recovery")? {
            let recovered = self.reopen(trial, "recovery", "before-recovery.json")?;
            if recovered.state() == State::Closed {
                let after = trial.read("after-recovery.json", MAX_RECORD)?;
                if trial.read("recovery-return.sha256", 65)? != receipt_digest(&after) {
                    return Err(Error::Refused("recovery readback record changed"));
                }
                "recovery_readback_recorded"
            } else {
                "recovery_unknown"
            }
        } else if trial.exists("stage")? {
            let staged = self.reopen(trial, "stage", "before-stage.json")?;
            match staged.state() {
                State::Intent(Operation::WriteFilter) => "stage_intent_unsettled",
                State::Unknown(Operation::WriteFilter) => "stage_outcome_unknown",
                _ => "stage_consumed_without_intent",
            }
        } else {
            "prepared"
        };
        let snapshot = self.observe(trial)?;
        let slot = self.slot(&snapshot.slot)?;
        if phase == "recovery_readback_recorded" && matches!(snapshot.slot, Slot::Active(_)) {
            return Err(Error::Refused(
                "active filter appeared after recorded recovery",
            ));
        }
        Ok(self.slot_report(phase, slot, &snapshot.slot))
    }

    fn capture_unknown(&self, trial: &impl Trial) -> Result<Value> {
        let stage = self.reopen(trial, "stage", "before-stage.json")?;
        if !matches!(
            stage.state(),
            State::Intent(Operation::WriteFilter) | State::Unknown(Operation::WriteFilter)
        ) {
            return Err(Error::Refused("stage has no unsettled intent"));
        }
        if trial.exists("recovery")?
            && self
                .reopen(trial, "recovery", "before-recovery.json")?
                .state()
                == State::Closed
        {
            return Err(Error::Refused("recorded recovery is already closed"));
        }
        let snapshot = self.observe(trial)?;
        if self.slot(&snapshot.slot)? != "unrecognized" {
            return Err(Error::Refused("no unrecognized active rules to capture"));
        }
        stage.check_named_objects()?;
        trial.write("unrecognized-slot.json", &json_bytes(&snapshot)?)?;
        Ok(self.slot_report("unrecognized_slot_captured", "unrecognized", &snapshot.slot))
    }

    fn slot_report(&self, phase: &str, label: &str, slot: &Slot) -> Value {
        let mut result = report(&self.anchor, phase, label);
        if label == "unrecognized"
            && let Slot::Active(raw) = slot
        {
            result["slot_sha256"] = json!(hex(&sha(raw)));
            result["slot_bytes"] = json!(raw.len());
        }
        result
    }
}

fn receipt_digest(data: &[u8]) -> Vec<u8> {
    format!("{}\n", hex(&sha(data))).into_bytes()
}

fn report(anchor: &str, phase: &str, slot: &str) -> Value {
    json!({"scope":"unattached_filter_trial", "anchor":anchor, "phase":phase,
        "active_slot":slot, "actual_protection":"unknown", "recovery_qualified":false})
}

fn run(action: Action) -> Result<Value> {
    let trial = Storage::open()?;
    if matches!(action, Action::Prepare)
        || (matches!(action, Action::Status) && !trial.exists("session.json")?)
    {
        let mut nonce = [0; 32];
        File::open("/dev/urandom")?.read_exact(&mut nonce)?;
        return match action {
            Action::Status => preflight(&trial, nonce),
            _ => prepare(&trial, nonce),
        };
    }
    let bound = Bound::load(&trial)?;
    match action {
        Action::Prepare => Err(Error::Refused("unexpected prepare action")),
        Action::Status => bound.status(&trial),
        Action::Stage => bound.stage(&trial),
        Action::Recover => bound.recover(&trial),
        Action::CaptureUnknown => bound.capture_unknown(&trial),
    }
}

fn main() -> ExitCode {
    match Action::parse(std::env::args_os().skip(1)).and_then(run) {
        Ok(result) => match writeln!(io::stdout().lock(), "{result}") {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        },
        Err(error) => {
            let reason = error.to_string();
            let _ = writeln!(
                io::stdout().lock(),
                "{}",
                json!({"result":"refused", "reason":reason})
            );
            ExitCode::FAILURE
        }
    }
}
