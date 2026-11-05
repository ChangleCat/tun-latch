//! Ordinary-user process facts. These cannot establish loaded image or FD ownership.

use std::time::{Duration, Instant};

use super::native::{self, NativeError};

/// A single process instance as sampled by the OS, not an authenticated program image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessIdentity {
    /// Process ID, meaningful only with the birth time and current observation.
    pub pid: u32,
    /// Effective user ID at the time of the read.
    pub uid: u32,
    /// Birth time seconds reported by the OS.
    pub birth_seconds: u64,
    /// Birth time microsecond component.
    pub birth_microseconds: u32,
}

/// The point at which an inspection could not complete.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionStage {
    /// Preconditions before a system call.
    Input,
    /// The first system read.
    Before,
    /// The second system read or comparison.
    After,
}

/// Classification of an incomplete or failed inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionProblem {
    /// PID was zero or out of range.
    InvalidPid,
    /// This observer must not run with effective UID 0.
    RootObserver,
    /// The native wrapper did not report why the process could not be read.
    NotReadable,
    /// Reads differ, or contain invalid process identity fields.
    Inconsistent,
    /// Another OS error or a short native read.
    SystemError,
    /// The fixed FD or control result limit was exceeded.
    Truncated,
    /// The native layout is unsupported.
    UnsupportedLayout,
}

/// A typed failure with an optional native errno, without process-sensitive strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InspectionFailure {
    /// Stage of failure.
    pub stage: InspectionStage,
    /// Why this observation could not be used.
    pub problem: InspectionProblem,
    /// OS error number, when supplied by the native API.
    pub errno: Option<i32>,
}

impl std::fmt::Display for InspectionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {:?}", self.stage, self.problem)?;
        if let Some(errno) = self.errno {
            write!(f, " (errno {errno})")?;
        }
        Ok(())
    }
}

/// A process-only observation. No variant establishes TUN ownership or PF eligibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProcessInspection {
    /// Two process reads matched; FD, loaded-image and interface evidence remain unavailable.
    Partial(ProcessIdentity),
    /// Process data could not be read; no identity is retained.
    Unavailable(InspectionFailure),
    /// Invalid input, inconsistent reads, or another native error; no identity is retained.
    Error(InspectionFailure),
}

/// Read one explicitly selected PID twice as the ordinary user.
///
/// This does not enumerate processes, inspect command lines, paths, environments or FDs.
/// Equality is a bounded consistency check, not proof against changes between reads.
/// The native wrapper checks the complete struct size. No client-supplied facts are accepted.
pub fn inspect_process(pid: u32) -> ProcessInspection {
    if nix::unistd::Uid::effective().is_root() {
        return failure(
            InspectionStage::Input,
            InspectionProblem::RootObserver,
            None,
        );
    }
    let Ok(_native_pid) = i32::try_from(pid) else {
        return failure(InspectionStage::Input, InspectionProblem::InvalidPid, None);
    };
    if pid == 0 {
        return failure(InspectionStage::Input, InspectionProblem::InvalidPid, None);
    }
    let before = match native::process(_native_pid) {
        Ok(value) => value,
        Err(error) => return process_failure(InspectionStage::Before, error),
    };
    if !valid(pid, &before) {
        return failure(
            InspectionStage::Before,
            InspectionProblem::Inconsistent,
            None,
        );
    }
    let after = match native::process(_native_pid) {
        Ok(value) => value,
        Err(error) => return process_failure(InspectionStage::After, error),
    };
    if !valid(pid, &after) || before != after {
        return failure(
            InspectionStage::After,
            InspectionProblem::Inconsistent,
            None,
        );
    }
    ProcessInspection::Partial(after)
}

fn process_failure(stage: InspectionStage, error: NativeError) -> ProcessInspection {
    let (problem, errno) = classify(error);
    failure(stage, problem, errno)
}

fn classify(error: NativeError) -> (InspectionProblem, Option<i32>) {
    match error {
        NativeError::Os(errno) => (InspectionProblem::NotReadable, errno),
        NativeError::Truncated => (InspectionProblem::Truncated, None),
        NativeError::UnsupportedLayout => (InspectionProblem::UnsupportedLayout, None),
        NativeError::ShortRead | NativeError::Invalid => (InspectionProblem::SystemError, None),
    }
}

fn valid(pid: u32, value: &ProcessIdentity) -> bool {
    value.pid == pid && value.birth_seconds != 0 && value.birth_microseconds < 1_000_000
}

fn failure(
    stage: InspectionStage,
    problem: InspectionProblem,
    errno: Option<i32>,
) -> ProcessInspection {
    let failure = InspectionFailure {
        stage,
        problem,
        errno,
    };
    match problem {
        InspectionProblem::NotReadable => ProcessInspection::Unavailable(failure),
        _ => ProcessInspection::Error(failure),
    }
}

/// An FD number and kernel-reported type from the selected process, not an owned descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawFd {
    /// Numeric descriptor in the selected process.
    pub fd: i32,
    /// Native descriptor type; 2 denotes a socket.
    pub kind: u32,
}

/// Unauthenticated kernel-control metadata. Values may be reused or hidden by the OS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawControl {
    /// Descriptor number in the selected process.
    pub fd: i32,
    /// Kernel-control registration name.
    pub name: String,
    /// Kernel-control registration id.
    pub id: u32,
    /// Control unit; its relation to an interface is not validated here.
    pub unit: u32,
    /// Opaque socket value; zero or reuse conveys no identity.
    pub socket: u64,
    /// Opaque protocol-control-block value; zero or reuse conveys no identity.
    pub pcb: u64,
}

/// Bounded raw observation, not a loaded-image, TUN, or enforcement identity.
#[derive(Clone, Debug)]
pub struct RawObservation {
    /// Process fields checked twice.
    pub process: ProcessIdentity,
    /// Bounded list of descriptor numbers and types.
    pub fds: Vec<RawFd>,
    /// Bounded kernel-control metadata without network endpoints.
    pub controls: Vec<RawControl>,
    /// Start of this sampling window on this process's monotonic clock.
    pub started_at: Instant,
    /// End of sampling, not a proof of continuous validity.
    pub finished_at: Instant,
    /// Exclusive diagnostic deadline; changes may happen before this time.
    pub expires_at: Instant,
}

/// Completeness refers only to this raw bounded read, never to ownership authentication.
#[derive(Clone, Debug)]
pub enum RawInspection {
    /// Both bounded samples matched; no loaded image or interface ownership is proven.
    CompleteRaw(RawObservation),
    /// Native process data was unavailable.
    Unavailable(InspectionFailure),
    /// Data was missing, truncated or changed during collection.
    Partial(InspectionFailure),
    /// Input, native layout or native structure was invalid.
    Error(InspectionFailure),
}

/// Inspect one selected PID without running as root. No arbitrary process enumeration occurs.
/// The one-second deadline bounds reuse by callers, not kernel lifetime or sampling duration.
pub fn inspect_selected_process(pid: u32) -> RawInspection {
    let started_at = Instant::now();
    if nix::unistd::Uid::effective().is_root() {
        return raw_failure(
            InspectionStage::Input,
            InspectionProblem::RootObserver,
            None,
        );
    }
    let Ok(native_pid) = i32::try_from(pid) else {
        return raw_failure(InspectionStage::Input, InspectionProblem::InvalidPid, None);
    };
    if native_pid == 0 {
        return raw_failure(InspectionStage::Input, InspectionProblem::InvalidPid, None);
    }
    let before = match native::process(native_pid) {
        Ok(p) if valid(pid, &p) => p,
        Ok(_) => {
            return raw_failure(
                InspectionStage::Before,
                InspectionProblem::Inconsistent,
                None,
            );
        }
        Err(e) => return raw_native_failure(InspectionStage::Before, e, false),
    };
    let fds = match native::fds(native_pid) {
        Ok(f) => f,
        Err(e) => return raw_native_failure(InspectionStage::Before, e, true),
    };
    let mut sockets = Vec::new();
    let mut controls = Vec::new();
    for entry in fds.iter().filter(|entry| entry.kind == 2) {
        let sample = match native::socket(native_pid, entry.fd) {
            Ok(s) => s,
            Err(e) => return raw_native_failure(InspectionStage::Before, e, true),
        };
        if let Some(control) = sample.control() {
            if controls.len() == 64 {
                return raw_failure(InspectionStage::Before, InspectionProblem::Truncated, None);
            }
            controls.push(control.clone());
        }
        sockets.push((entry.fd, sample));
    }
    let after_fds = match native::fds(native_pid) {
        Ok(f) => f,
        Err(e) => return raw_native_failure(InspectionStage::After, e, true),
    };
    if fds != after_fds {
        return raw_failure(
            InspectionStage::After,
            InspectionProblem::Inconsistent,
            None,
        );
    }
    for (fd, first) in sockets {
        match native::socket(native_pid, fd) {
            Ok(second) if second == first => {}
            Ok(_) => {
                return raw_failure(
                    InspectionStage::After,
                    InspectionProblem::Inconsistent,
                    None,
                );
            }
            Err(e) => return raw_native_failure(InspectionStage::After, e, true),
        }
    }
    let after = match native::process(native_pid) {
        Ok(p) if valid(pid, &p) && p == before => p,
        Ok(_) => {
            return raw_failure(
                InspectionStage::After,
                InspectionProblem::Inconsistent,
                None,
            );
        }
        Err(e) => return raw_native_failure(InspectionStage::After, e, true),
    };
    let finished_at = Instant::now();
    let Some(expires_at) = finished_at.checked_add(Duration::from_secs(1)) else {
        return raw_failure(InspectionStage::After, InspectionProblem::SystemError, None);
    };
    RawInspection::CompleteRaw(RawObservation {
        process: after,
        fds,
        controls,
        started_at,
        finished_at,
        expires_at,
    })
}

fn raw_native_failure(stage: InspectionStage, error: NativeError, partial: bool) -> RawInspection {
    let (problem, errno) = classify(error);
    if partial && problem == InspectionProblem::NotReadable {
        return RawInspection::Partial(InspectionFailure {
            stage,
            problem,
            errno,
        });
    }
    raw_failure(stage, problem, errno)
}

fn raw_failure(
    stage: InspectionStage,
    problem: InspectionProblem,
    errno: Option<i32>,
) -> RawInspection {
    let failure = InspectionFailure {
        stage,
        problem,
        errno,
    };
    match problem {
        InspectionProblem::NotReadable => RawInspection::Unavailable(failure),
        InspectionProblem::Inconsistent | InspectionProblem::Truncated => {
            RawInspection::Partial(failure)
        }
        _ => RawInspection::Error(failure),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_disappearance_and_truncation_never_return_raw_data() {
        for errno in [nix::libc::EPERM, nix::libc::ESRCH] {
            assert!(matches!(
                raw_native_failure(InspectionStage::Before, NativeError::Os(Some(errno)), false),
                RawInspection::Unavailable(InspectionFailure { errno: Some(actual), .. }) if actual == errno
            ));
            assert!(matches!(
                raw_native_failure(InspectionStage::After, NativeError::Os(Some(errno)), true),
                RawInspection::Partial(InspectionFailure { errno: Some(actual), .. }) if actual == errno
            ));
        }
        assert!(matches!(
            raw_native_failure(InspectionStage::After, NativeError::Truncated, true),
            RawInspection::Partial(InspectionFailure {
                problem: InspectionProblem::Truncated,
                ..
            })
        ));
        assert!(matches!(
            raw_native_failure(InspectionStage::After, NativeError::ShortRead, true),
            RawInspection::Error(InspectionFailure {
                problem: InspectionProblem::SystemError,
                ..
            })
        ));
    }
}
