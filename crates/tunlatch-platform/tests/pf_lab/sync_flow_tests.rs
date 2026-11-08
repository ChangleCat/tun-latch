//! End-to-end flow tests on ordinary temporary files and simulated PF observations.
use super::*;
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

const BOOT: &str = "01234567-89ab-cdef-0123-456789abcdef";
const NONCE: [u8; 32] = [7; 32];

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct FakeTrial {
    dir: tempfile::TempDir,
    mode: &'static str,
    slot: RefCell<Slot>,
    boot: RefCell<String>,
    submissions: RefCell<Vec<&'static str>>,
    ignore_empty: Cell<bool>,
    fail_fault_ready: Cell<bool>,
    ticks: RefCell<VecDeque<u64>>,
    current_tick: Cell<u64>,
}
impl FakeTrial {
    fn new() -> Result<Self> {
        Self::new_in_mode(MODE)
    }

    fn new_in_mode(mode: &'static str) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let this = Self {
            dir,
            mode,
            slot: RefCell::new(Slot::Absent),
            boot: RefCell::new(BOOT.to_owned()),
            submissions: RefCell::new(Vec::new()),
            ignore_empty: Cell::new(false),
            fail_fault_ready: Cell::new(false),
            ticks: RefCell::new(VecDeque::new()),
            current_tick: Cell::new(1000),
        };
        this.write(
            "operator-manifest.json",
            &json_bytes(&json!({"boot": BOOT, "mode": mode, "sha256": hex(&[9; 32])}))?,
        )?;
        Ok(this)
    }
}
impl Trial for FakeTrial {
    fn mode(&self) -> &'static str {
        self.mode
    }

    fn program_digest(&self) -> Result<[u8; 32]> {
        Ok([9; 32])
    }
    fn recheck(&self) -> Result<()> {
        Ok(())
    }
    fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.dir.path().join(name).exists())
    }
    fn read(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        let data = fs::read(self.dir.path().join(name))?;
        if data.len() > max {
            return Err(Error::Refused("fixture record exceeds bound"));
        }
        Ok(data)
    }
    fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.dir.path().join(name))?;
        file.write_all(data)?;
        file.sync_all()?;
        Ok(())
    }
    fn subdir(&self, name: &str, create: bool) -> Result<File> {
        if name == "fault-ready" && create && self.fail_fault_ready.get() {
            return Err(Error::Refused(
                "injected failure before readiness publication",
            ));
        }
        let path = self.dir.path().join(name);
        if create {
            fs::create_dir(&path)?;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(File::open(path)?)
    }
    fn ticks(&self) -> Result<u64> {
        if let Some(next) = self.ticks.borrow_mut().pop_front() {
            self.current_tick.set(next);
        }
        Ok(self.current_tick.get())
    }
    fn boot(&self) -> Result<String> {
        Ok(self.boot.borrow().clone())
    }
    fn observe(&self, anchor: &str) -> Result<Snapshot> {
        Ok(sync_observe::fixture(anchor, self.slot.borrow().clone()))
    }
    fn submit(&self, suffix: &str, replacement: Replacement) -> Result<()> {
        match replacement {
            Replacement::Stage => {
                self.submissions.borrow_mut().push("stage");
                let rules = native_filter::expected_rules(suffix)
                    .map_err(|_| Error::Refused("bad test suffix"))?;
                *self.slot.borrow_mut() = Slot::Active(rules);
            }
            Replacement::Empty => {
                self.submissions.borrow_mut().push("empty");
                if !self.ignore_empty.get() {
                    *self.slot.borrow_mut() = Slot::Empty;
                }
            }
        }
        Ok(())
    }
}

#[test]
fn preflight_does_not_allocate_a_slot_or_start_the_stage_window() -> TestResult {
    let trial = FakeTrial::new()?;
    let first = preflight(&trial, NONCE)?;
    assert_eq!(first["phase"], "preflight_ready");
    assert_eq!(first["anchor"], "not_allocated");
    assert_eq!(preflight(&trial, [8; 32])?, first);
    for path in ["prepare.json", "session.json", "stage", "recovery"] {
        assert!(!trial.exists(path)?);
    }
    assert!(trial.submissions.borrow().is_empty());
    Ok(())
}

#[test]
fn stage_durable_intent_then_recovery_clears_candidate_without_replay() -> TestResult {
    let trial = FakeTrial::new()?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    assert_eq!(bound.stage(&trial)?["phase"], "submit_returned_unverified");
    assert_eq!(
        bound.reopen(&trial, "stage", "before-stage.json")?.state(),
        State::Intent(Operation::WriteFilter)
    );
    assert!(bound.stage(&trial).is_err());
    assert_eq!(
        bound.recover(&trial)?["phase"],
        "recovery_readback_verified"
    );
    assert_eq!(
        bound
            .reopen(&trial, "recovery", "before-recovery.json")?
            .state(),
        State::Closed
    );
    assert!(bound.recover(&trial).is_err());
    assert_eq!(*trial.submissions.borrow(), ["stage", "empty"]);
    assert_eq!(bound.status(&trial)?["phase"], "recovery_readback_recorded");
    fs::write(trial.dir.path().join("after-recovery.json"), b"changed")?;
    assert!(bound.status(&trial).is_err());
    Ok(())
}

#[test]
fn recovery_submits_empty_even_when_active_view_was_already_empty() -> TestResult {
    let trial = FakeTrial::new()?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    bound.stage(&trial)?;
    *trial.slot.borrow_mut() = Slot::Empty;
    assert_eq!(bound.recover(&trial)?["active_slot"], "empty");
    assert_eq!(*trial.submissions.borrow(), ["stage", "empty"]);
    Ok(())
}

#[test]
fn display_only_differences_allow_recovery_of_the_fixed_candidate() -> TestResult {
    let trial = FakeTrial::new()?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    bound.stage(&trial)?;
    let rules = String::from_utf8(native_filter::expected_rules(&bound.suffix)?)?
        .replace("port = 55000", "port 55000")
        .replace("127.0.0.1", "127.0.0.1/32");
    *trial.slot.borrow_mut() = Slot::Active(rules.into_bytes());
    assert_eq!(bound.status(&trial)?["active_slot"], "candidate");
    assert_eq!(
        bound.recover(&trial)?["phase"],
        "recovery_readback_verified"
    );
    Ok(())
}

#[test]
fn unrecognized_slot_can_be_captured_without_starting_recovery() -> TestResult {
    let trial = FakeTrial::new()?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    bound.stage(&trial)?;
    let observed = b"pass out quick on lo0 all\n".to_vec();
    *trial.slot.borrow_mut() = Slot::Active(observed.clone());
    let status = bound.status(&trial)?;
    assert_eq!(status["active_slot"], "unrecognized");
    assert_eq!(status["slot_sha256"], hex(&sha(&observed)));
    assert_eq!(status["slot_bytes"], observed.len());
    assert!(bound.recover(&trial).is_err());
    assert!(!trial.exists("recovery")?);
    assert_eq!(
        bound.capture_unknown(&trial)?["phase"],
        "unrecognized_slot_captured"
    );
    let capture = trial.read("unrecognized-slot.json", MAX_RECORD)?;
    assert_eq!(capture, json_bytes(&trial.observe(&bound.anchor)?)?);
    assert!(bound.capture_unknown(&trial).is_err());
    assert_eq!(trial.read("unrecognized-slot.json", MAX_RECORD)?, capture);
    assert_eq!(*trial.submissions.borrow(), ["stage"]);
    Ok(())
}

#[test]
fn mismatching_independent_readback_leaves_recovery_unknown_and_cannot_replay() -> TestResult {
    let trial = FakeTrial::new()?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    bound.stage(&trial)?;
    trial.ignore_empty.set(true);
    assert!(bound.recover(&trial).is_err());
    assert_eq!(
        bound
            .reopen(&trial, "recovery", "before-recovery.json")?
            .state(),
        State::Unknown(Operation::WriteFilter)
    );
    assert!(trial.exists("after-recovery.json")?);
    assert!(bound.recover(&trial).is_err());
    assert_eq!(*trial.submissions.borrow(), ["stage", "empty"]);
    Ok(())
}

#[test]
fn stale_window_and_changed_boot_refuse_before_any_submit() -> TestResult {
    let trial = FakeTrial::new()?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    trial.current_tick.set(1000 + STAGE_WINDOW_SECS);
    assert!(bound.stage(&trial).is_err());
    *trial.boot.borrow_mut() = "changed-boot".to_owned();
    assert!(Bound::load(&trial).is_err());
    assert!(trial.submissions.borrow().is_empty());
    Ok(())
}

#[test]
fn deadline_crossed_during_preflight_refuses_before_submission() -> TestResult {
    let trial = FakeTrial::new()?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    *trial.ticks.borrow_mut() = VecDeque::from([1001, 1000 + STAGE_WINDOW_SECS]);
    assert!(bound.stage(&trial).is_err());
    assert!(trial.submissions.borrow().is_empty());
    assert_eq!(
        bound.reopen(&trial, "stage", "before-stage.json")?.state(),
        State::Unknown(Operation::WriteFilter)
    );
    Ok(())
}

#[test]
fn fault_recovery_requires_the_direct_sigkill_and_bound_witness() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    for killed in [true, false] {
        let trial = FakeTrial::new_in_mode(FAULT_MODE)?;
        prepare(&trial, NONCE)?;
        let bound = Bound::load(&trial)?;
        let result = fault::launch(&bound, &trial, || {
            let writer = fault::write_candidate(&bound, &trial)?;
            assert!(bound.recover(&trial).is_err());
            assert_eq!(writer.state(), State::Intent(Operation::WriteFilter));
            drop(writer);
            Ok(ExitStatus::from_raw(if killed {
                nix::libc::SIGKILL
            } else {
                137 << 8
            }))
        });
        if killed {
            assert_eq!(result?["phase"], "fault_writer_reaped");
            let status = bound.status(&trial)?;
            assert_eq!(status["phase"], "fault_writer_reaped");
            assert_eq!(status["active_slot"], "candidate");
            assert_eq!(
                bound.recover(&trial)?["phase"],
                "recovery_readback_verified"
            );
            assert_eq!(*trial.submissions.borrow(), ["stage", "empty"]);
        } else {
            assert!(result.is_err());
            assert_eq!(bound.status(&trial)?["phase"], "fault_unconfirmed");
            assert!(bound.recover(&trial).is_err());
            assert!(!trial.exists("recovery")?);
            assert_eq!(*trial.submissions.borrow(), ["stage"]);
        }
        assert!(
            fault::launch(&bound, &trial, || Err(Error::Refused("unexpected replay"))).is_err()
        );
    }
    Ok(())
}

#[test]
fn missing_or_changed_fault_evidence_never_allows_empty_submit() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    let trial = FakeTrial::new_in_mode(FAULT_MODE)?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    let result = fault::launch(&bound, &trial, || {
        let writer = fault::write_candidate(&bound, &trial)?;
        drop(writer);
        fs::write(
            trial.dir.path().join("fault-before-signal.json"),
            b"different stage",
        )?;
        Ok(ExitStatus::from_raw(nix::libc::SIGKILL))
    });
    assert!(result.is_err());
    assert!(!trial.exists("fault-reaped.json")?);
    assert_eq!(bound.status(&trial)?["phase"], "fault_unconfirmed");
    assert!(bound.recover(&trial).is_err());
    assert_eq!(*trial.submissions.borrow(), ["stage"]);
    Ok(())
}

#[test]
fn complete_witness_without_ready_marker_is_not_a_reaped_fault() -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    let trial = FakeTrial::new_in_mode(FAULT_MODE)?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    trial.fail_fault_ready.set(true);
    let result = fault::launch(&bound, &trial, || {
        assert!(fault::write_candidate(&bound, &trial).is_err());
        assert!(trial.exists("fault-before-signal.json")?);
        assert!(!trial.exists("fault-ready")?);
        Ok(ExitStatus::from_raw(nix::libc::SIGKILL))
    });
    assert!(result.is_err());
    assert_eq!(bound.status(&trial)?["phase"], "fault_unconfirmed");
    assert!(bound.recover(&trial).is_err());
    assert_eq!(*trial.submissions.borrow(), ["stage"]);
    Ok(())
}

#[test]
fn late_writer_after_lost_parent_wait_cannot_authorize_recovery() -> TestResult {
    let trial = FakeTrial::new_in_mode(FAULT_MODE)?;
    prepare(&trial, NONCE)?;
    let bound = Bound::load(&trial)?;
    assert!(
        fault::launch(&bound, &trial, || Err(Error::Refused(
            "wait outcome unknown"
        )))
        .is_err()
    );
    assert_eq!(bound.status(&trial)?["phase"], "fault_unconfirmed");
    let writer = fault::write_candidate(&bound, &trial)?;
    assert!(bound.recover(&trial).is_err());
    drop(writer);
    assert!(trial.exists("fault-ready")?);
    assert!(!trial.exists("fault-reaped.json")?);
    assert_eq!(bound.status(&trial)?["phase"], "fault_unconfirmed");
    assert!(bound.recover(&trial).is_err());
    assert_eq!(*trial.submissions.borrow(), ["stage"]);
    Ok(())
}
