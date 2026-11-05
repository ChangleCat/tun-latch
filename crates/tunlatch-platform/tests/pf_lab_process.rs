//! Real ordinary-user process tests. The isolated fixture uses this test binary, never PF.

#[path = "pf_lab/process.rs"]
mod process;

use std::error::Error;
use std::io::{self, Write};
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use process::{
    Completion, Fixture, GatePoint, Id, Limits, Observation, Probe, Reason, Stage, Ticket,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
static SERIAL: Mutex<()> = Mutex::new(());
fn serial() -> TestResult<std::sync::MutexGuard<'static, ()>> {
    SERIAL
        .lock()
        .map_err(|_| io::Error::other("test serialization poisoned").into())
}
fn limits() -> TestResult<Limits> {
    Ok(Limits::new(
        Duration::from_secs(2),
        Duration::from_millis(500),
        65536,
    )?)
}
fn finish(ticket: Ticket) -> TestResult<Completion> {
    assert_eq!(ticket.wait(Duration::from_secs(4))?, Observation::Reclaimed);
    Ok(process::collect(ticket.id())?)
}
fn wait_id(id: Id, target: Observation) -> TestResult {
    let began = Instant::now();
    loop {
        if process::observe(id)? == target {
            return Ok(());
        }
        if began.elapsed() > Duration::from_secs(4) {
            return Err(io::Error::other("owner did not reach expected state").into());
        }
        std::thread::park_timeout(Duration::from_millis(2));
    }
}

#[test]
fn echo_delivers_bounded_input_closes_stdin_and_reaps() -> TestResult {
    let _serial = serial()?;
    for data in [
        Vec::new(),
        b"no newline needed\0\xff".to_vec(),
        vec![b'x'; 8192],
    ] {
        let result = finish(process::start(Probe::Echo, data.clone(), limits()?)?)?;
        assert_eq!(result.reason, Reason::Success);
        assert_eq!(result.stdout, data);
        assert!(result.stderr.is_empty());
        assert_eq!(result.input_written, data.len());
        assert!(result.child_started && result.parent_reaped && result.pipes_closed);
        assert!(!result.truncated && !result.capture_failed && !result.kill_failed);
    }
    Ok(())
}

#[test]
fn exact_output_cap_succeeds_but_one_extra_byte_is_truncated_failure() -> TestResult {
    let _serial = serial()?;
    for (size, reason, truncated) in [
        (4096, Reason::Success, false),
        (4097, Reason::OutputLimit, true),
    ] {
        let limits = Limits::new(Duration::from_secs(2), Duration::from_millis(500), 4096)?;
        let result = finish(process::start(Probe::Echo, vec![b'x'; size], limits)?)?;
        assert_eq!(result.reason, reason);
        assert_eq!(result.stdout.len(), 4096);
        assert_eq!(result.truncated, truncated);
    }
    Ok(())
}

#[test]
fn stdout_stderr_and_simultaneous_floods_share_a_hard_capture_cap() -> TestResult {
    let _serial = serial()?;
    for mode in [Fixture::FloodOut, Fixture::FloodErr, Fixture::FloodBoth] {
        let limits = Limits::new(Duration::from_secs(2), Duration::from_millis(500), 2048)?;
        let result = finish(process::start(Probe::Fixture(mode), Vec::new(), limits)?)?;
        assert_eq!(result.reason, Reason::OutputLimit);
        assert!(result.truncated);
        assert_eq!(result.stdout.len() + result.stderr.len(), 2048);
        assert!(result.parent_reaped && result.pipes_closed);
    }
    Ok(())
}

#[test]
fn timeout_kills_and_reaps_direct_child_without_waiting_for_fixture_delay() -> TestResult {
    let _serial = serial()?;
    let began = Instant::now();
    let limits = Limits::new(Duration::from_millis(100), Duration::from_millis(500), 4096)?;
    let result = finish(process::start(
        Probe::Fixture(Fixture::Wait),
        Vec::new(),
        limits,
    )?)?;
    assert_eq!(result.reason, Reason::Timeout);
    assert!(result.parent_reaped);
    assert!(began.elapsed() < Duration::from_secs(1));
    Ok(())
}

#[test]
fn closed_stdout_and_stderr_do_not_substitute_for_child_exit() -> TestResult {
    let _serial = serial()?;
    let limits = Limits::new(Duration::from_millis(200), Duration::from_millis(500), 4096)?;
    let result = finish(process::start(
        Probe::Fixture(Fixture::CloseOutput),
        Vec::new(),
        limits,
    )?)?;
    assert_eq!(result.reason, Reason::Timeout);
    assert!(result.parent_reaped && result.pipes_closed);
    assert!(String::from_utf8_lossy(&result.stdout).contains("closing-output"));
    Ok(())
}

#[test]
fn exit_failure_binary_output_and_closed_input_are_observed() -> TestResult {
    let _serial = serial()?;
    let fail = finish(process::start(
        Probe::Fixture(Fixture::Fail),
        Vec::new(),
        limits()?,
    )?)?;
    assert_eq!(fail.reason, Reason::ExitFailure);
    let binary = finish(process::start(
        Probe::Fixture(Fixture::Binary),
        Vec::new(),
        limits()?,
    )?)?;
    assert_eq!(binary.reason, Reason::Success);
    assert!(binary.stdout.windows(3).any(|s| s == [0xff, 0xfe, 0]));
    let closed = finish(process::start(
        Probe::Fixture(Fixture::CloseInput),
        vec![b'x'; 8192],
        limits()?,
    )?)?;
    // A successful pipe write only means the kernel accepted bytes, not that the child read them.
    assert!(matches!(
        closed.reason,
        Reason::Success | Reason::InputFailure
    ));
    assert!(closed.parent_reaped && closed.pipes_closed);
    Ok(())
}

#[test]
fn spawn_failure_returns_no_child_and_can_be_collected_only_once() -> TestResult {
    let _serial = serial()?;
    let ticket = process::start(Probe::Fixture(Fixture::SpawnFailure), Vec::new(), limits()?)?;
    let id = ticket.id();
    let result = finish(ticket)?;
    assert_eq!(result.reason, Reason::SpawnFailure);
    assert!(!result.child_started && result.parent_reaped && result.pipes_closed);
    assert!(matches!(process::observe(id), Err(process::Error::Unknown)));
    assert!(matches!(process::collect(id), Err(process::Error::Unknown)));
    Ok(())
}

#[test]
fn environment_and_working_directory_are_fixed_without_shell_or_path_search() -> TestResult {
    let _serial = serial()?;
    let result = finish(process::start(
        Probe::Fixture(Fixture::CleanEnvironment),
        Vec::new(),
        limits()?,
    )?)?;
    assert_eq!(result.reason, Reason::Success);
    assert!(String::from_utf8_lossy(&result.stdout).contains("clean-environment"));
    Ok(())
}

#[test]
fn caller_wait_budget_does_not_discard_live_ownership() -> TestResult {
    let _serial = serial()?;
    let ticket = process::start(Probe::Fixture(Fixture::Wait), Vec::new(), limits()?)?;
    assert!(matches!(
        ticket.wait(Duration::ZERO)?,
        Observation::Pending(_)
    ));
    assert!(matches!(
        process::collect(ticket.id()),
        Err(process::Error::Unsettled)
    ));
    ticket.cancel();
    let result = finish(ticket)?;
    assert_eq!(result.reason, Reason::Cancelled);
    Ok(())
}

#[test]
fn cancellation_before_launch_check_stays_owned_and_prevents_that_launch() -> TestResult {
    let _serial = serial()?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let limits = Limits::new(Duration::from_secs(2), Duration::from_millis(20), 4096)?;
    let ticket = process::start_gated(
        Probe::Echo,
        limits,
        GatePoint::BeforeSpawn,
        ready_tx,
        release_rx,
    )?;
    ready_rx.recv_timeout(Duration::from_secs(1))?;
    let id = ticket.id();
    drop(ticket);
    wait_id(id, Observation::Unsettled(Stage::Starting))?;
    assert!(matches!(
        process::collect(id),
        Err(process::Error::Unsettled)
    ));
    release_tx.send(())?;
    wait_id(id, Observation::Reclaimed)?;
    let result = process::collect(id)?;
    assert_eq!(result.reason, Reason::Cancelled);
    assert!(!result.child_started);
    Ok(())
}

#[test]
fn blocked_post_spawn_call_remains_owned_past_reclaim_budget_and_later_reaps() -> TestResult {
    let _serial = serial()?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let limits = Limits::new(Duration::from_secs(2), Duration::from_millis(20), 4096)?;
    let ticket = process::start_gated(
        Probe::Fixture(Fixture::Wait),
        limits,
        GatePoint::AfterSpawn,
        ready_tx,
        release_rx,
    )?;
    ready_rx.recv_timeout(Duration::from_secs(1))?;
    ticket.cancel();
    assert_eq!(
        ticket.wait(Duration::from_secs(1))?,
        Observation::Unsettled(Stage::Running)
    );
    assert!(matches!(
        process::collect(ticket.id()),
        Err(process::Error::Unsettled)
    ));
    release_tx.send(())?;
    wait_id(ticket.id(), Observation::Reclaimed)?;
    let result = process::collect(ticket.id())?;
    assert_eq!(result.reason, Reason::Cancelled);
    assert!(result.child_started && result.parent_reaped);
    Ok(())
}

#[test]
fn unproven_descendant_is_not_reclaimed_even_after_parent_exit_and_pipe_eof() -> TestResult {
    let _serial = serial()?;
    let before = process::retained_count()?;
    let ticket = process::start(
        Probe::Fixture(Fixture::InheritedPipe),
        Vec::new(),
        limits()?,
    )?;
    wait_id(ticket.id(), Observation::Unsettled(Stage::Finished))?;
    let result = process::report(ticket.id())?;
    assert_eq!(result.reason, Reason::DescendantsUnproven);
    assert!(result.parent_reaped && result.pipes_closed && !result.descendants_known_leaf);
    assert!(String::from_utf8_lossy(&result.stdout).contains("pipe-holder"));
    assert!(matches!(
        process::collect(ticket.id()),
        Err(process::Error::Unsettled)
    ));
    assert_eq!(process::retained_count()?, before + 1);
    // This deliberately quarantined record stays in the bounded registry. The controlled
    // non-PF descendant has finished by EOF; no general descendant proof is inferred from it.
    Ok(())
}

#[test]
fn capacity_counts_unsettled_work_and_rejects_new_jobs_until_owned_work_finishes() -> TestResult {
    let _serial = serial()?;
    let baseline = process::retained_count()?;
    let mut tickets = Vec::new();
    let mut gates = Vec::new();
    for _ in baseline..4 {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let ticket = process::start_gated(
            Probe::Echo,
            limits()?,
            GatePoint::BeforeSpawn,
            ready_tx,
            release_rx,
        )?;
        ready_rx.recv_timeout(Duration::from_secs(1))?;
        tickets.push(ticket);
        gates.push(release_tx);
    }
    assert!(matches!(
        process::start(Probe::Echo, Vec::new(), limits()?),
        Err(process::Error::Busy)
    ));
    for ticket in &tickets {
        ticket.cancel();
    }
    for gate in gates {
        gate.send(())?;
    }
    for ticket in tickets {
        let result = finish(ticket)?;
        assert!(!result.child_started);
    }
    assert_eq!(process::retained_count()?, baseline);
    Ok(())
}

#[test]
fn rejects_invalid_limits_and_oversize_input_before_reserving_a_slot() -> TestResult {
    let _serial = serial()?;
    let before = process::retained_count()?;
    for (run, reclaim, output) in [
        (Duration::ZERO, Duration::from_secs(1), 1),
        (Duration::from_secs(11), Duration::from_secs(1), 1),
        (Duration::from_secs(1), Duration::ZERO, 1),
        (Duration::from_secs(1), Duration::from_secs(3), 1),
        (Duration::from_secs(1), Duration::from_secs(1), 0),
        (Duration::from_secs(1), Duration::from_secs(1), 65537),
    ] {
        assert!(Limits::new(run, reclaim, output).is_err());
    }
    assert!(matches!(
        process::start(Probe::Echo, vec![0; 8193], limits()?),
        Err(process::Error::InvalidLimits)
    ));
    assert_eq!(process::retained_count()?, before);
    Ok(())
}

/// Re-executed with an exact test name and closed private mode. Without that mode, validate
/// the fixture vocabulary; this entry is infrastructure, not an extra process feature test.
#[test]
fn controlled_fixture() -> TestResult {
    let Some(mode) = std::env::var_os("TUNLATCH_LAB_CHILD") else {
        assert_eq!(Fixture::Wait.name(), "wait");
        assert_eq!(Fixture::PipeHolder.name(), "pipe-holder");
        return Ok(());
    };
    if nix::unistd::geteuid().is_root() {
        return Err(io::Error::other("fixture must not run as root").into());
    }
    match mode.to_str() {
        Some("wait") => std::thread::sleep(Duration::from_secs(2)),
        Some("fail") => return Err(io::Error::other("intentional controlled child failure").into()),
        Some("binary") => std::io::stdout().write_all(&[0xff, 0xfe, 0])?,
        Some("close-input") => {
            nix::unistd::close(0)?;
        }
        Some("close-output") => {
            println!("closing-output");
            std::io::stdout().flush()?;
            nix::unistd::close(1)?;
            nix::unistd::close(2)?;
            std::thread::sleep(Duration::from_secs(2));
        }
        Some("clean-environment") => {
            assert!(std::env::var_os("PATH").is_none());
            assert_eq!(std::env::var("LC_ALL")?, "C");
            assert_eq!(std::env::current_dir()?, std::path::Path::new("/"));
            println!("clean-environment");
        }
        Some("inherited-pipe") => {
            let child = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", "controlled_fixture", "--nocapture"])
                .env_clear()
                .env("LC_ALL", "C")
                .env("TUNLATCH_LAB_CHILD", Fixture::PipeHolder.name())
                .stdin(std::process::Stdio::null())
                .spawn()?;
            // Intentional fault fixture: parent exits while a finite non-PF child inherits pipes.
            drop(child);
        }
        Some("pipe-holder") => {
            println!("pipe-holder");
            std::thread::sleep(Duration::from_millis(200));
        }
        Some("flood-out" | "flood-err" | "flood-both") => {
            let data = [b'x'; 4096];
            for _ in 0..256 {
                if mode != "flood-err" && std::io::stdout().write_all(&data).is_err() {
                    break;
                }
                if mode != "flood-out" && std::io::stderr().write_all(&data).is_err() {
                    break;
                }
            }
        }
        _ => return Err(io::Error::other("unknown fixture mode").into()),
    }
    Ok(())
}
