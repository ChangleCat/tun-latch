//! Point-in-time correlation of a dynamic code requirement, control socket and interface.

use std::time::Duration;

use thiserror::Error;
use tunlatch_core::status::NetworkInterface;

use super::{
    ImageInspection, ImageProblem, ProcessIdentity, RawInspection,
    image::inspect_root_target_cdhash, inspect_expected_cdhash, inspect_selected_process,
    process::inspect_bound_process,
};
use crate::events::{NetworkObserver, ScanError, continuous_now};

const BUDGET: Duration = Duration::from_secs(1);
const UTUN_CONTROL: &str = "com.apple.net.utun_control";

/// A diagnostic candidate derived from the observed utun control unit and two interface scans.
/// The unit-to-name convention and matching samples do not establish direct or continuous
/// ownership. The candidate conveys no approval or enforcement eligibility.
#[derive(Debug, Eq, PartialEq)]
pub struct TunnelCandidate {
    /// Process fields matched by all reads in this sampling window.
    pub process: ProcessIdentity,
    /// Numeric descriptor in the selected process, not an owned FD.
    pub fd: i32,
    /// Kernel-control registration ID observed on the socket.
    pub control_id: u32,
    /// Reported utun unit used to derive the candidate name.
    pub unit: u32,
    /// Enumerated name matching the derived candidate.
    pub ifname: String,
    /// Index sampled in both scans, which may be reused.
    pub ifindex: u32,
    /// Whole sampling window, including elapsed sleep time.
    pub elapsed: Duration,
}

/// Reason the diagnostic could not produce a candidate.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TunnelCandidateError {
    /// PID is outside the native range or the expected CDHash is zero.
    #[error("invalid PID or expected CDHash")]
    InvalidInput,
    /// This diagnostic entry point requires an ordinary user.
    #[error("the ordinary-user diagnostic refuses effective UID 0")]
    RootObserver,
    /// The dedicated administrator entry point requires effective UID 0.
    #[error("the administrator diagnostic requires effective UID 0")]
    AdminRequired,
    /// A selected process in the administrator path was not running as root.
    #[error("the administrator diagnostic requires a target with effective UID 0")]
    TargetUidMismatch,
    /// The OS could not check the running code.
    #[error("running code requirement unavailable")]
    ImageUnavailable,
    /// The OS explicitly rejected the expected CDHash.
    #[error("running code requirement did not match")]
    ImageMismatch,
    /// The native process or FD read was incomplete.
    #[error("incomplete process or FD sample")]
    RawIncomplete,
    /// The code checks and FD sample did not agree on the process instance.
    #[error("process identity changed during sampling")]
    ProcessChanged,
    /// The complete raw sample had no utun control record.
    #[error("no utun control in the raw sample")]
    NoUtunControl,
    /// Multiple control records prevent selecting a single candidate.
    #[error("multiple utun control records")]
    AmbiguousControl,
    /// The control record could not be paired with a socket FD and nonzero unit/ID.
    #[error("inconsistent utun control record")]
    InvalidControl,
    /// An interface scan failed or exceeded its bounds.
    #[error("interface scan unavailable")]
    NetworkUnavailable,
    /// A unique, consistent interface was unavailable across the two scans.
    #[error("candidate interface unavailable, ambiguous or changed")]
    InterfaceChanged,
    /// The clock failed or went backwards.
    #[error("sampling clock unavailable")]
    ClockUnavailable,
    /// The sampling budget expired before the reads could be accepted.
    #[error("sampling window expired")]
    TimedOut,
}

impl TunnelCandidateError {
    /// Stable diagnostic reason, without native process details.
    pub fn kind(self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::RootObserver => "root_observer",
            Self::AdminRequired => "admin_required",
            Self::TargetUidMismatch => "target_uid_mismatch",
            Self::ImageUnavailable => "image_unavailable",
            Self::ImageMismatch => "image_mismatch",
            Self::RawIncomplete => "raw_incomplete",
            Self::ProcessChanged => "process_changed",
            Self::NoUtunControl => "no_utun_control",
            Self::AmbiguousControl => "ambiguous_control",
            Self::InvalidControl => "invalid_control",
            Self::NetworkUnavailable => "network_unavailable",
            Self::InterfaceChanged => "interface_changed",
            Self::ClockUnavailable => "clock_unavailable",
            Self::TimedOut => "timed_out",
        }
    }
}

/// Look for one candidate associated with a selected, readable PID as an ordinary user.
/// Two interface scans bracket two dynamic code checks and the bounded FD sample. The
/// one-second budget is checked after synchronous reads and cannot cancel them. These
/// non-atomic reads can miss changes, and unit-to-name derivation is only a candidate.
pub fn inspect_tunnel_candidate(
    pid: u32,
    expected: [u8; 20],
) -> Result<TunnelCandidate, TunnelCandidateError> {
    validate_target(pid, expected)?;
    if nix::unistd::Uid::effective().is_root() {
        return Err(TunnelCandidateError::RootObserver);
    }
    collect_candidate(
        |_| inspect_expected_cdhash(pid, expected),
        |_| inspect_selected_process(pid),
    )
}

/// Read one selected effective-UID-zero process from a dedicated, protected admin executable.
/// The ordinary CLI must use [`inspect_tunnel_candidate`]. Both paths produce a diagnostic
/// candidate only. Snapshot equality can miss PID, exec, FD, and interface reuse between reads.
pub fn inspect_tunnel_candidate_privileged(
    pid: u32,
    expected: [u8; 20],
) -> Result<TunnelCandidate, TunnelCandidateError> {
    validate_target(pid, expected)?;
    if !nix::unistd::Uid::effective().is_root() {
        return Err(TunnelCandidateError::AdminRequired);
    }
    collect_candidate(
        |previous| inspect_root_target_cdhash(pid, expected, previous),
        inspect_bound_process,
    )
}

fn validate_target(pid: u32, expected: [u8; 20]) -> Result<(), TunnelCandidateError> {
    if pid == 0 || i32::try_from(pid).is_err() || expected == [0; 20] {
        return Err(TunnelCandidateError::InvalidInput);
    }
    Ok(())
}

fn collect_candidate(
    image: impl FnMut(Option<&ProcessIdentity>) -> ImageInspection,
    raw: impl FnOnce(&ProcessIdentity) -> RawInspection,
) -> Result<TunnelCandidate, TunnelCandidateError> {
    let mut observer = NetworkObserver::new(BUDGET);
    correlate(
        || {
            observer
                .refresh()
                .map(|snapshot| snapshot.interfaces().to_vec())
        },
        image,
        raw,
        continuous_now,
    )
}

fn correlate(
    mut network: impl FnMut() -> Result<Vec<NetworkInterface>, ScanError>,
    mut image: impl FnMut(Option<&ProcessIdentity>) -> ImageInspection,
    raw: impl FnOnce(&ProcessIdentity) -> RawInspection,
    mut now: impl FnMut() -> Result<Duration, nix::Error>,
) -> Result<TunnelCandidate, TunnelCandidateError> {
    use TunnelCandidateError as Error;

    let start = now().map_err(|_| Error::ClockUnavailable)?;
    let mut last = start;
    let mut check_time = || {
        let current = now().map_err(|_| Error::ClockUnavailable)?;
        if current < last {
            return Err(Error::ClockUnavailable);
        }
        last = current;
        let elapsed = current - start;
        if elapsed >= BUDGET {
            return Err(Error::TimedOut);
        }
        Ok(elapsed)
    };

    let before = network().map_err(|_| Error::NetworkUnavailable)?;
    check_time()?;
    let first_code = image(None);
    check_time()?;
    let first = matched_process(first_code)?;
    let sample = raw(&first);
    check_time()?;
    let RawInspection::CompleteRaw(sample) = sample else {
        return Err(Error::RawIncomplete);
    };
    if first != sample.process {
        return Err(Error::ProcessChanged);
    }
    let second_code = image(Some(&sample.process));
    check_time()?;
    if matched_process(second_code)? != sample.process {
        return Err(Error::ProcessChanged);
    }
    let after = network().map_err(|_| Error::NetworkUnavailable)?;
    check_time()?;

    let mut controls = sample
        .controls
        .iter()
        .filter(|control| control.name == UTUN_CONTROL);
    let control = controls.next().ok_or(Error::NoUtunControl)?;
    if controls.next().is_some() {
        return Err(Error::AmbiguousControl);
    }
    let Some(suffix) = control.unit.checked_sub(1) else {
        return Err(Error::InvalidControl);
    };
    // The native collector rejects duplicate FD numbers and bounds both vectors.
    if control.id == 0
        || !sample
            .fds
            .iter()
            .any(|fd| fd.fd == control.fd && fd.kind == 2)
    {
        return Err(Error::InvalidControl);
    }
    let ifname = format!("utun{suffix}");
    let first_interface = unique_interface(&before, &ifname).ok_or(Error::InterfaceChanged)?;
    if unique_interface(&after, &ifname) != Some(first_interface) {
        return Err(Error::InterfaceChanged);
    }
    Ok(TunnelCandidate {
        process: sample.process,
        fd: control.fd,
        control_id: control.id,
        unit: control.unit,
        ifname,
        ifindex: first_interface.index,
        elapsed: check_time()?,
    })
}

fn matched_process(result: ImageInspection) -> Result<ProcessIdentity, TunnelCandidateError> {
    match result {
        ImageInspection::Matched { process, .. } => Ok(process),
        ImageInspection::Mismatched { .. } => Err(TunnelCandidateError::ImageMismatch),
        ImageInspection::Unavailable {
            problem: ImageProblem::TargetUidMismatch,
            ..
        } => Err(TunnelCandidateError::TargetUidMismatch),
        ImageInspection::Unavailable {
            problem: ImageProblem::ProcessChanged,
            ..
        } => Err(TunnelCandidateError::ProcessChanged),
        ImageInspection::Unavailable { .. } => Err(TunnelCandidateError::ImageUnavailable),
    }
}

fn unique_interface<'a>(
    interfaces: &'a [NetworkInterface],
    name: &str,
) -> Option<&'a NetworkInterface> {
    let mut matches = interfaces.iter().filter(|interface| interface.name == name);
    let candidate = matches.next()?;
    if candidate.index == 0
        || candidate.loopback
        || matches.next().is_some()
        || interfaces
            .iter()
            .filter(|interface| interface.index == candidate.index)
            .count()
            != 1
    {
        return None;
    }
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{RawControl, RawFd, RawObservation};
    use std::{cell::RefCell, time::Instant};
    use tunlatch_core::status::InterfaceAddress;

    fn sample() -> RawObservation {
        let now = Instant::now();
        RawObservation {
            process: ProcessIdentity {
                pid: 42,
                uid: 501,
                birth_seconds: 100,
                birth_microseconds: 2,
            },
            fds: vec![RawFd { fd: 3, kind: 2 }],
            controls: vec![RawControl {
                fd: 3,
                name: UTUN_CONTROL.to_owned(),
                id: 5,
                unit: 6,
                socket: 0,
                pcb: 0,
            }],
            started_at: now,
            finished_at: now,
            expires_at: now + Duration::from_secs(1),
        }
    }

    fn network() -> Vec<NetworkInterface> {
        vec![NetworkInterface {
            name: "utun5".to_owned(),
            index: 20,
            up: true,
            loopback: false,
            addresses: vec![InterfaceAddress {
                address: std::net::Ipv6Addr::LOCALHOST.into(),
                scope_id: 20,
            }],
        }]
    }

    fn matched(process: ProcessIdentity) -> ImageInspection {
        ImageInspection::Matched {
            process,
            expected_cdhash: [1; 20],
        }
    }

    fn attempt(
        raw: RawObservation,
        after: Vec<NetworkInterface>,
        second: ImageInspection,
    ) -> Result<TunnelCandidate, TunnelCandidateError> {
        let mut networks = [network(), after].into_iter();
        let mut images = [matched(raw.process.clone()), second].into_iter();
        correlate(
            || networks.next().ok_or(ScanError::Interrupted),
            |_| {
                images.next().unwrap_or(ImageInspection::Unavailable {
                    problem: ImageProblem::ProcessUnavailable,
                    status: None,
                })
            },
            |_| RawInspection::CompleteRaw(raw),
            || Ok(Duration::ZERO),
        )
    }

    #[test]
    fn brackets_one_fd_sample_with_dynamic_checks_and_ipv6_only_interface_scans()
    -> Result<(), TunnelCandidateError> {
        let raw = sample();
        let process = raw.process.clone();
        let order = RefCell::new(Vec::new());
        let candidate = correlate(
            || {
                order.borrow_mut().push("network");
                Ok(network())
            },
            |previous| {
                order.borrow_mut().push("code");
                if let Some(previous) = previous {
                    assert_eq!(previous, &process);
                }
                matched(process.clone())
            },
            |expected| {
                order.borrow_mut().push("fd");
                assert_eq!(expected, &raw.process);
                RawInspection::CompleteRaw(raw)
            },
            || Ok(Duration::ZERO),
        )?;
        assert_eq!(
            order.into_inner(),
            ["network", "code", "fd", "code", "network"]
        );
        assert_eq!(candidate.process, process);
        assert_eq!(
            (candidate.ifname.as_str(), candidate.ifindex, candidate.unit),
            ("utun5", 20, 6)
        );
        Ok(())
    }

    #[test]
    fn missing_ambiguous_or_invalid_controls_never_produce_a_candidate() {
        use TunnelCandidateError as Error;

        for error in [
            Error::NoUtunControl,
            Error::AmbiguousControl,
            Error::InvalidControl,
        ] {
            let mut raw = sample();
            match error {
                Error::NoUtunControl => raw.controls.clear(),
                Error::AmbiguousControl => raw.controls.push(raw.controls[0].clone()),
                _ => raw.controls[0].unit = 0,
            }
            let image = matched(raw.process.clone());
            assert_eq!(attempt(raw, network(), image), Err(error));
        }
    }

    #[test]
    fn rejects_process_and_interface_changes_even_when_the_utun_name_matches() {
        use TunnelCandidateError as Error;

        let raw = sample();
        let mut restarted = raw.process.clone();
        restarted.birth_seconds += 1;
        assert_eq!(
            attempt(raw.clone(), network(), matched(restarted)),
            Err(Error::ProcessChanged)
        );
        assert_eq!(
            attempt(
                raw.clone(),
                network(),
                ImageInspection::Mismatched {
                    process: raw.process.clone()
                }
            ),
            Err(Error::ImageMismatch)
        );
        let mut changed = network();
        changed[0].index += 1;
        assert_eq!(
            attempt(raw.clone(), changed, matched(raw.process.clone())),
            Err(Error::InterfaceChanged)
        );
        let mut alias = network();
        let mut duplicate = alias[0].clone();
        duplicate.name = "utun9".to_owned();
        alias.push(duplicate);
        assert_eq!(
            attempt(raw.clone(), alias, matched(raw.process)),
            Err(Error::InterfaceChanged)
        );
    }

    #[test]
    fn expiry_and_clock_rollback_stop_before_starting_the_next_native_read() {
        let start = Duration::from_secs(10);
        for (tick, error) in [
            (start + BUDGET, TunnelCandidateError::TimedOut),
            (start - BUDGET, TunnelCandidateError::ClockUnavailable),
        ] {
            let mut times = [start, tick].into_iter();
            let mut image_calls = 0;
            let raw = sample();
            let result = correlate(
                || Ok(network()),
                |_| {
                    image_calls += 1;
                    matched(raw.process.clone())
                },
                |_| RawInspection::CompleteRaw(raw.clone()),
                || times.next().ok_or(nix::errno::Errno::EIO),
            );
            assert_eq!(result, Err(error));
            assert_eq!(image_calls, 0);
        }
    }
}
