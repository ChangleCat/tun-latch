//! One controlled, self-owned utun mapping experiment; default mode only prints a plan.
//! Connecting creates an interface and the kernel may set it UP. No packet is sent,
//! and this program never configures addresses, routes, interface flags, or PF.

use std::{
    ffi::OsStr,
    io::Write,
    os::fd::{AsRawFd, OwnedFd},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, fcntl},
    net::if_::if_nametoindex,
    sys::signal::{Signal, kill},
    sys::socket::{self, AddressFamily, SockFlag, SockProtocol, SockType, SysControlAddr, sockopt},
    unistd::{Pid, Uid, close},
};
use serde_json::{Value, json};
use tunlatch_platform::identity::{
    ProcessIdentity, RawInspection, RawObservation, inspect_selected_process_privileged,
};

const CONTROL_NAME: &str = "com.apple.net.utun_control";
const BUDGET: Duration = Duration::from_secs(5);
const WATCHDOG_BUDGET: Duration = Duration::from_secs(6);

#[derive(Clone, Debug, Eq, PartialEq)]
struct Mapping {
    fd: i32,
    ifname: String,
    control_id: u32,
    unit: u32,
    ifindex: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Failure {
    stage: &'static str,
    error: &'static str,
}

fn fail(stage: &'static str, error: &'static str) -> Failure {
    Failure { stage, error }
}

fn validate_snapshot(
    raw: &RawInspection,
    pid: u32,
    mapping: &Mapping,
    now: Instant,
) -> Result<ProcessIdentity, Failure> {
    let RawInspection::CompleteRaw(observation) = raw else {
        return Err(fail("before", "partial_or_unreadable"));
    };
    validate_observation(observation, pid, mapping, now)
}

fn validate_observation(
    raw: &RawObservation,
    pid: u32,
    mapping: &Mapping,
    now: Instant,
) -> Result<ProcessIdentity, Failure> {
    if raw.process.pid != pid
        || raw.process.uid != 0
        || raw.process.birth_seconds == 0
        || raw.process.birth_microseconds >= 1_000_000
        || now >= raw.expires_at
        || raw.started_at > raw.finished_at
        || raw.finished_at > now
    {
        return Err(fail("before", "invalid_or_stale_snapshot"));
    }
    if raw
        .fds
        .iter()
        .filter(|item| item.fd == mapping.fd && item.kind == 2)
        .count()
        != 1
        || raw.fds.iter().filter(|item| item.fd == mapping.fd).count() != 1
    {
        return Err(fail("before", "own_fd_missing_or_ambiguous"));
    }
    let candidates: Vec<_> = raw
        .controls
        .iter()
        .filter(|entry| {
            entry.name == CONTROL_NAME
                && entry.id == mapping.control_id
                && entry.unit == mapping.unit
        })
        .collect();
    if candidates.len() != 1
        || candidates[0].fd != mapping.fd
        || raw
            .controls
            .iter()
            .filter(|entry| entry.fd == mapping.fd)
            .count()
            != 1
    {
        return Err(fail("before", "control_missing_or_ambiguous"));
    }
    Ok(raw.process.clone())
}

fn post_fd(
    raw: &RawInspection,
    expected: Option<&ProcessIdentity>,
    fd: i32,
    now: Instant,
) -> &'static str {
    let RawInspection::CompleteRaw(raw) = raw else {
        return "unknown";
    };
    if expected != Some(&raw.process) || now >= raw.expires_at || raw.finished_at > now {
        return "unknown";
    }
    if raw.fds.iter().any(|entry| entry.fd == fd) {
        "present_or_reused"
    } else {
        "absent"
    }
}

fn interface_state(result: Result<u32, Errno>) -> &'static str {
    match result {
        Ok(index) if index != 0 => "present",
        Err(Errno::ENXIO) => "absent",
        _ => "unknown",
    }
}

fn initial() -> Value {
    json!({"result":"incomplete", "stage":"input", "error":null, "mapping":null, "observed_ifname":null,
        "owned_fd_released":null, "close_errno":null, "fd_after_close":"unknown", "interface_after_close":"unknown",
        "kernel_may_set_interface_up":true, "program_configures_addresses_routes":false,
        "system_side_effects_unknown":true, "actual_protection":"unknown", "tun_ownership":"unknown"})
}

fn plan() -> Value {
    let mut out = initial();
    out["result"] = json!("plan");
    out["stage"] = json!("plan");
    out
}

fn peer(fd: &OwnedFd) -> Result<SysControlAddr, Failure> {
    socket::getpeername(fd.as_raw_fd()).map_err(|_| fail("between", "peer_unavailable"))
}

fn name(fd: &OwnedFd) -> Result<String, Failure> {
    let name = socket::getsockopt(fd, sockopt::UtunIfname)
        .map_err(|_| fail("between", "ifname_unavailable"))?;
    let name = name
        .into_string()
        .map_err(|_| fail("between", "ifname_invalid"))?;
    let valid = name.strip_prefix("utun").is_some_and(|suffix| {
        !suffix.is_empty()
            && (suffix == "0" || !suffix.starts_with('0'))
            && suffix.bytes().all(|byte| byte.is_ascii_digit())
            && suffix.parse::<u32>().is_ok()
    });
    if !valid || name.len() >= nix::libc::IFNAMSIZ {
        return Err(fail("between", "ifname_invalid"));
    }
    Ok(name)
}

fn endpoint_stable(
    initial_peer: SysControlAddr,
    current_peer: Result<SysControlAddr, Failure>,
    current_name: Result<String, Failure>,
    current_index: Result<u32, Errno>,
    mapping: &Mapping,
) -> bool {
    matches!(current_peer, Ok(peer) if peer == initial_peer)
        && matches!(current_name, Ok(name) if name == mapping.ifname)
        && current_index == Ok(mapping.ifindex)
}

fn collect_open(
    fd: &OwnedFd,
    start: Instant,
    observed_ifname: &mut Option<String>,
) -> Result<(Mapping, ProcessIdentity), Failure> {
    fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
        .map_err(|_| fail("socket", "cloexec_failed"))?;
    let address = SysControlAddr::from_name(fd.as_raw_fd(), CONTROL_NAME, 0)
        .map_err(|_| fail("control_lookup", "control_unavailable"))?;
    if address.id() == 0 {
        return Err(fail("control_lookup", "control_id_invalid"));
    }
    socket::connect(fd.as_raw_fd(), &address).map_err(|_| fail("connect", "connect_failed"))?;
    let ifname = name(fd)?;
    *observed_ifname = Some(ifname.clone());
    let peer1 = peer(fd)?;
    if peer1.id() != address.id()
        || peer1.unit() == 0
        || ifname != format!("utun{}", peer1.unit() - 1)
    {
        return Err(fail("before", "name_or_peer_mismatch"));
    }
    let ifindex =
        if_nametoindex(ifname.as_str()).map_err(|_| fail("before", "interface_unavailable"))?;
    let mapping = Mapping {
        fd: fd.as_raw_fd(),
        ifname,
        control_id: peer1.id(),
        unit: peer1.unit(),
        ifindex,
    };
    let pid = std::process::id();
    let first = inspect_selected_process_privileged(pid);
    let p1 = validate_snapshot(&first, pid, &mapping, Instant::now())?;
    if Instant::now().duration_since(start) > BUDGET {
        return Err(fail("before", "budget_elapsed"));
    }
    if !endpoint_stable(
        peer1,
        peer(fd),
        name(fd),
        if_nametoindex(mapping.ifname.as_str()),
        &mapping,
    ) {
        return Err(fail("between", "changed_or_disconnected"));
    }
    let second = inspect_selected_process_privileged(pid);
    let p2 = validate_snapshot(&second, pid, &mapping, Instant::now())
        .map_err(|failure| fail("after", failure.error))?;
    if p1 != p2 {
        return Err(fail("after", "process_changed"));
    }
    if Instant::now().duration_since(start) > BUDGET {
        return Err(fail("after", "budget_elapsed"));
    }
    Ok((mapping, p2))
}

fn record_close(out: &mut Value, result: Result<(), Errno>) -> bool {
    match result {
        Ok(()) => {
            out["owned_fd_released"] = json!(true);
            true
        }
        Err(error) => {
            out["close_errno"] = json!(error as i32);
            if out["error"].is_null() {
                out["stage"] = json!("close");
                out["error"] = json!("close_unknown");
            }
            false
        }
    }
}

fn record_interface_after_close(
    out: &mut Value,
    observed_ifname: Option<&str>,
    lookup: impl FnOnce(&str) -> Result<u32, Errno>,
) {
    if let Some(name) = observed_ifname {
        out["observed_ifname"] = json!(name);
        out["interface_after_close"] = json!(interface_state(lookup(name)));
    }
}

fn run() -> Value {
    let mut out = initial();
    let start = Instant::now();
    let fd = match socket::socket(
        AddressFamily::System,
        SockType::Datagram,
        SockFlag::empty(),
        SockProtocol::KextControl,
    ) {
        Ok(fd) => fd,
        Err(_) => {
            out["stage"] = json!("socket");
            out["error"] = json!("socket_failed");
            return out;
        }
    };
    let own_fd = fd.as_raw_fd();
    let mut observed_ifname = None;
    let collected = collect_open(&fd, start, &mut observed_ifname);
    if let Err(failure) = &collected {
        out["stage"] = json!(failure.stage);
        out["error"] = json!(failure.error);
    }
    let close_ok = record_close(&mut out, close(fd));
    record_interface_after_close(&mut out, observed_ifname.as_deref(), if_nametoindex);
    if !close_ok {
        return out;
    }
    let (mapping, process) = match collected {
        Ok(values) => values,
        Err(failure) => {
            out["stage"] = json!(failure.stage);
            out["error"] = json!(failure.error);
            return out;
        }
    };
    out["mapping"] = json!({"fd":mapping.fd, "ifname":mapping.ifname, "control_id":mapping.control_id,
                             "unit":mapping.unit, "ifindex":mapping.ifindex});
    if Instant::now().duration_since(start) > BUDGET {
        out["stage"] = json!("post_close");
        out["error"] = json!("budget_elapsed");
        return out;
    }
    let post = inspect_selected_process_privileged(std::process::id());
    out["fd_after_close"] = json!(post_fd(&post, Some(&process), own_fd, Instant::now()));
    if out["fd_after_close"] != "absent"
        || out["interface_after_close"] == "unknown"
        || Instant::now().duration_since(start) > BUDGET
    {
        out["stage"] = json!("post_close");
        out["error"] = json!("post_observation_incomplete");
        return out;
    }
    out["result"] = json!("complete");
    out["stage"] = json!("complete");
    out
}

fn watchdog_event(
    received: Result<(), RecvTimeoutError>,
    finished: &AtomicBool,
    terminate_self: impl FnOnce(),
) {
    if received == Err(RecvTimeoutError::Timeout)
        && finished
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    {
        terminate_self();
    }
}

fn run_guarded() -> Value {
    let (sender, receiver) = mpsc::channel();
    let finished = Arc::new(AtomicBool::new(false));
    let watchdog_finished = Arc::clone(&finished);
    let spawn = std::thread::Builder::new()
        .name("utun-self-watchdog".to_owned())
        .spawn(move || {
            let result = receiver.recv_timeout(WATCHDOG_BUDGET);
            watchdog_event(result, &watchdog_finished, || {
                // Only the process containing this thread is signalled. An
                // delayed SIGKILL does not establish reclamation.
                let _ = kill(Pid::this(), Signal::SIGKILL);
            });
        });
    if spawn.is_err() {
        let mut out = initial();
        out["stage"] = json!("socket");
        out["error"] = json!("watchdog_unavailable");
        return out;
    }
    let mut out = run();
    let timed_out = finished.swap(true, Ordering::SeqCst);
    let _ = sender.send(());
    // The watchdog was never joined: an uninterruptible OS operation, failure
    // to schedule, a pending SIGKILL, or an uninterruptible operation leaves completion unknown.
    if timed_out && out["result"] == "complete" {
        out["result"] = json!("incomplete");
        out["stage"] = json!("post_close");
        out["error"] = json!("budget_elapsed");
    }
    out
}

fn select_action(args: &[std::ffi::OsString], root: bool) -> Result<bool, Failure> {
    match args {
        [] => Ok(false),
        [value] if value == OsStr::new("--run-controlled-utun-mapping") && root => Ok(true),
        [value] if value == OsStr::new("--run-controlled-utun-mapping") => {
            Err(fail("input", "root_required"))
        }
        _ => Err(fail("input", "invalid_arguments")),
    }
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(2).collect();
    let out = match select_action(&args, Uid::effective().is_root()) {
        Ok(false) => plan(),
        Ok(true) => run_guarded(),
        Err(failure) => {
            let mut out = initial();
            out["stage"] = json!(failure.stage);
            out["error"] = json!(failure.error);
            out
        }
    };
    let success = out["result"] == "plan" || out["result"] == "complete";
    let mut stdout = std::io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &out).is_err() || writeln!(stdout).is_err() {
        return ExitCode::FAILURE;
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunlatch_platform::identity::{
        InspectionFailure, InspectionProblem, InspectionStage, RawControl, RawFd,
    };

    fn fixture() -> (Mapping, RawObservation) {
        let now = Instant::now();
        (
            Mapping {
                fd: 7,
                ifname: "utun5".into(),
                control_id: 123,
                unit: 6,
                ifindex: 44,
            },
            RawObservation {
                process: ProcessIdentity {
                    pid: 42,
                    uid: 0,
                    birth_seconds: 10,
                    birth_microseconds: 20,
                },
                fds: vec![RawFd { fd: 7, kind: 2 }],
                controls: vec![RawControl {
                    fd: 7,
                    name: CONTROL_NAME.into(),
                    id: 123,
                    unit: 6,
                    socket: 12345678,
                    pcb: 98765432,
                }],
                started_at: now,
                finished_at: now,
                expires_at: now + Duration::from_secs(1),
            },
        )
    }

    #[test]
    fn default_and_invalid_modes_never_authorize_creation() {
        assert_eq!(select_action(&[], false), Ok(false));
        assert_eq!(select_action(&[], true), Ok(false));
        let flag = ["--run-controlled-utun-mapping".into()];
        assert_eq!(select_action(&flag, true), Ok(true));
        assert_eq!(
            select_action(&flag, false),
            Err(fail("input", "root_required"))
        );
        assert_eq!(
            select_action(
                &["--run-controlled-utun-mapping".into(), "extra".into()],
                true
            ),
            Err(fail("input", "invalid_arguments"))
        );
        let p = plan();
        assert_eq!(p["kernel_may_set_interface_up"], true);
        assert_eq!(p["program_configures_addresses_routes"], false);
        assert_eq!(p["actual_protection"], "unknown");
        assert_eq!(p["tun_ownership"], "unknown");
    }

    #[test]
    fn watchdog_only_requests_signal_on_unfinished_timeout() {
        let mut signals = 0;
        let finished = AtomicBool::new(false);
        watchdog_event(Ok(()), &finished, || signals += 1);
        watchdog_event(Err(RecvTimeoutError::Disconnected), &finished, || {
            signals += 1
        });
        assert_eq!(signals, 0);
        watchdog_event(Err(RecvTimeoutError::Timeout), &finished, || signals += 1);
        assert_eq!(signals, 1);
        watchdog_event(Err(RecvTimeoutError::Timeout), &finished, || signals += 1);
        assert_eq!(signals, 1);
        let already_finished = AtomicBool::new(true);
        watchdog_event(Err(RecvTimeoutError::Timeout), &already_finished, || {
            signals += 1
        });
        assert_eq!(signals, 1);
    }

    #[test]
    fn raw_mapping_must_match_own_fd_and_unique_control() {
        let (mapping, raw) = fixture();
        assert_eq!(
            validate_observation(&raw, 42, &mapping, Instant::now()),
            Ok(raw.process.clone())
        );
        let mut different = raw.clone();
        different.controls[0].unit += 1;
        assert_eq!(
            validate_observation(&different, 42, &mapping, Instant::now()),
            Err(fail("before", "control_missing_or_ambiguous"))
        );
        let mut duplicate = raw.clone();
        let mut other = duplicate.controls[0].clone();
        other.fd = 8;
        duplicate.controls.push(other);
        assert_eq!(
            validate_observation(&duplicate, 42, &mapping, Instant::now()),
            Err(fail("before", "control_missing_or_ambiguous"))
        );
        let mut no_fd = raw.clone();
        no_fd.fds.clear();
        assert_eq!(
            validate_observation(&no_fd, 42, &mapping, Instant::now()),
            Err(fail("before", "own_fd_missing_or_ambiguous"))
        );
    }

    #[test]
    fn peer_disconnect_or_interface_change_never_passes_recheck() {
        let (mapping, _) = fixture();
        let original = SysControlAddr::new(mapping.control_id, mapping.unit);
        assert!(endpoint_stable(
            original,
            Ok(original),
            Ok(mapping.ifname.clone()),
            Ok(mapping.ifindex),
            &mapping
        ));
        assert!(!endpoint_stable(
            original,
            Err(fail("between", "peer_unavailable")),
            Ok(mapping.ifname.clone()),
            Ok(mapping.ifindex),
            &mapping
        ));
        assert!(!endpoint_stable(
            original,
            Ok(SysControlAddr::new(mapping.control_id, mapping.unit + 1)),
            Ok(mapping.ifname.clone()),
            Ok(mapping.ifindex),
            &mapping
        ));
        assert!(!endpoint_stable(
            original,
            Ok(original),
            Ok(mapping.ifname.clone()),
            Err(Errno::ENXIO),
            &mapping
        ));
    }

    #[test]
    fn partial_unreadable_and_expired_samples_are_incomplete() {
        let (mapping, raw) = fixture();
        let partial = RawInspection::Partial(InspectionFailure {
            stage: InspectionStage::After,
            problem: InspectionProblem::NotReadable,
            errno: None,
        });
        assert_eq!(
            validate_snapshot(&partial, 42, &mapping, Instant::now()),
            Err(fail("before", "partial_or_unreadable"))
        );
        assert_eq!(
            validate_observation(&raw, 42, &mapping, raw.expires_at),
            Err(fail("before", "invalid_or_stale_snapshot"))
        );
        assert_eq!(
            post_fd(&partial, Some(&raw.process), 7, Instant::now()),
            "unknown"
        );
    }

    #[test]
    fn close_error_remains_unknown_and_never_becomes_released() {
        let mut out = initial();
        assert!(!record_close(&mut out, Err(Errno::EINTR)));
        assert!(out["owned_fd_released"].is_null());
        assert_eq!(out["close_errno"], Errno::EINTR as i32);
        assert_eq!(out["stage"], "close");
        assert_eq!(out["result"], "incomplete");
        let mut earlier = initial();
        earlier["stage"] = json!("before");
        earlier["error"] = json!("partial_or_unreadable");
        assert!(!record_close(&mut earlier, Err(Errno::EINTR)));
        assert_eq!(earlier["stage"], "before");
        assert_eq!(earlier["error"], "partial_or_unreadable");
        assert_eq!(earlier["close_errno"], Errno::EINTR as i32);
        let mut success = initial();
        assert!(record_close(&mut success, Ok(())));
        assert_eq!(success["owned_fd_released"], true);
    }

    #[test]
    fn failed_mapping_retains_observed_name_and_checks_after_close() {
        let mut out = initial();
        out["stage"] = json!("before");
        out["error"] = json!("partial_or_unreadable");
        assert!(record_close(&mut out, Ok(())));
        let mut observed = None;
        record_interface_after_close(&mut out, Some("utun5"), |name| {
            observed = Some(name.to_owned());
            Err(Errno::ENXIO)
        });
        assert_eq!(observed.as_deref(), Some("utun5"));
        assert_eq!(out["observed_ifname"], "utun5");
        assert_eq!(out["interface_after_close"], "absent");
        assert_eq!(out["fd_after_close"], "unknown");
        assert!(out["mapping"].is_null());
        assert_eq!(out["stage"], "before");
        assert_eq!(out["error"], "partial_or_unreadable");
        assert_eq!(out["result"], "incomplete");
    }

    #[test]
    fn after_close_reports_only_bounded_observations() {
        let (_mapping, raw) = fixture();
        let expected = raw.process.clone();
        assert_eq!(
            post_fd(
                &RawInspection::CompleteRaw(raw.clone()),
                Some(&expected),
                7,
                Instant::now()
            ),
            "present_or_reused"
        );
        let mut absent = raw.clone();
        absent.fds.clear();
        absent.controls.clear();
        assert_eq!(
            post_fd(
                &RawInspection::CompleteRaw(absent.clone()),
                Some(&expected),
                7,
                Instant::now()
            ),
            "absent"
        );
        absent.process.birth_seconds += 1;
        assert_eq!(
            post_fd(
                &RawInspection::CompleteRaw(absent),
                Some(&expected),
                7,
                Instant::now()
            ),
            "unknown"
        );
        assert_eq!(interface_state(Ok(10)), "present");
        assert_eq!(interface_state(Err(Errno::ENXIO)), "absent");
        assert_eq!(interface_state(Err(Errno::EPERM)), "unknown");
        assert!(!plan().to_string().contains("12345678"));
        assert!(!plan().to_string().contains("98765432"));
    }
}
