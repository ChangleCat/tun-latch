//! Fault injection after the synchronous PF call, before any writer acknowledgment.

use nix::sys::signal::{Signal, raise};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::{Bound, Error, FAULT_MODE, Ledger, Operation, Result, State, Storage, Trial};
use super::{hex, json, json_bytes, report, sha};
use serde_json::Value;

const LAUNCH: &str = "fault-launch.json";
const WITNESS: &str = "fault-before-signal.json";
const READY: &str = "fault-ready";
const REAPED: &str = "fault-reaped.json";
const RECORD_LIMIT: usize = 512;

pub(super) fn has_records(trial: &impl Trial) -> Result<bool> {
    Ok(trial.exists(LAUNCH)?
        || trial.exists(WITNESS)?
        || trial.exists(READY)?
        || trial.exists(REAPED)?)
}

fn launch_record(bound: &Bound) -> Result<Vec<u8>> {
    json_bytes(&json!({"anchor": bound.anchor, "session_sha256": hex(&bound.plan)}))
}

fn witness_record(bound: &Bound, ledger: &Ledger) -> Result<Vec<u8>> {
    if ledger.state() != State::Intent(Operation::WriteFilter) {
        return Err(Error::Refused(
            "fault trial requires an unsettled stage intent",
        ));
    }
    ledger.check_named_objects()?;
    json_bytes(
        &json!({"anchor": bound.anchor, "stage_plan_sha256": hex(&ledger.identity().1),
        "point": "after_native_return_before_ack"}),
    )
}

fn reaped_record(bound: &Bound, trial: &impl Trial, ledger: &Ledger) -> Result<Vec<u8>> {
    let expected = witness_record(bound, ledger)?;
    // The marker is created only after the witness write and its sync return.
    // A complete-looking witness left by an earlier crash is insufficient.
    trial.subdir(READY, false)?;
    if trial.read(LAUNCH, RECORD_LIMIT)? != launch_record(bound)?
        || trial.read(WITNESS, RECORD_LIMIT)? != expected
    {
        return Err(Error::Refused("fault witness does not match this stage"));
    }
    json_bytes(
        &json!({"anchor": bound.anchor, "witness_sha256": hex(&sha(&expected)),
        "observed_signal": "SIGKILL"}),
    )
}

pub(super) fn verify_reaped(bound: &Bound, trial: &impl Trial, ledger: &Ledger) -> Result<()> {
    let expected = reaped_record(bound, trial, ledger)?;
    if trial.read(REAPED, RECORD_LIMIT)? != expected {
        return Err(Error::Refused(
            "fault writer reaping record does not match this trial",
        ));
    }
    Ok(())
}

pub(super) fn launch(
    bound: &Bound,
    trial: &impl Trial,
    supervise: impl FnOnce() -> Result<ExitStatus>,
) -> Result<Value> {
    bound.check_stage_window(trial)?;
    if trial.mode() != FAULT_MODE
        || trial.exists("stage")?
        || trial.exists("recovery")?
        || has_records(trial)?
    {
        return Err(Error::Refused("fault launch outside a fresh fault trial"));
    }
    trial.write(LAUNCH, &launch_record(bound)?)?;
    trial.recheck()?;
    if supervise()?.signal() != Some(Signal::SIGKILL as i32) {
        return Err(Error::Refused(
            "direct fault writer did not terminate with SIGKILL",
        ));
    }
    // The wait status belongs to the exact child. Reopen must also acquire both
    // stage locks before publishing the receipt. Neither step claims a kernel phase.
    let stage = bound.reopen(trial, "stage", "before-stage.json")?;
    trial.recheck()?;
    trial.write(REAPED, &reaped_record(bound, trial, &stage)?)?;
    Ok(report(&bound.anchor, "fault_writer_reaped", "not_read"))
}

pub(super) fn write_candidate(bound: &Bound, trial: &impl Trial) -> Result<Ledger> {
    if trial.mode() != FAULT_MODE || trial.read(LAUNCH, RECORD_LIMIT)? != launch_record(bound)? {
        return Err(Error::Refused("fault writer has no matching launch"));
    }
    if trial.exists(WITNESS)? || trial.exists(READY)? || trial.exists(REAPED)? {
        return Err(Error::Refused("fault writer witness already exists"));
    }
    let ledger = bound.submit_candidate(trial)?;
    trial.write(WITNESS, &witness_record(bound, &ledger)?)?;
    trial.subdir(READY, true)?;
    Ok(ledger)
}

pub(super) fn terminate_self() -> Result<()> {
    // This safe API addresses only the calling process, never an operator PID.
    Ok(raise(Signal::SIGKILL)?)
}

fn wait(mut child: Child, budget: Duration) -> Result<ExitStatus> {
    let deadline = Instant::now() + budget;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(Error::Refused(
                "fault writer exit not confirmed by deadline; preserve trial",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(super) fn spawn_writer(trial: &Storage) -> Result<ExitStatus> {
    let child = Command::new(trial.executable())
        .arg("stage-fault-writer")
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    // On timeout do not signal any PID or treat a still running writer as recovered.
    wait(child, Duration::from_secs(30))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signal_fixture() -> Result<()> {
        if std::env::var_os("TUNLATCH_SELF_SIGNAL_FIXTURE").is_some() {
            if nix::unistd::geteuid().is_root() {
                return Err(Error::Refused("ordinary-user process fixture only"));
            }
            terminate_self()?;
            return Err(Error::Refused("process fixture unexpectedly survived"));
        }
        Ok(())
    }

    #[test]
    fn ordinary_parent_observes_real_child_sigkill() -> Result<()> {
        let child = Command::new(std::env::current_exe()?)
            .args(["--exact", "fault::tests::self_signal_fixture"])
            .env_clear()
            .env("TUNLATCH_SELF_SIGNAL_FIXTURE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        assert_eq!(
            wait(child, Duration::from_secs(5))?.signal(),
            Some(Signal::SIGKILL as i32)
        );
        Ok(())
    }
}
