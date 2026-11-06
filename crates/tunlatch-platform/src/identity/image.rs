//! Narrow dynamic code-requirement diagnostic, not an authenticated binding.
//!
//! A PID can be reused, or exec another image without changing its birth time.
//! Comparing process snapshots reduces some races but does not exclude ABA or
//! establish continuous ownership of file descriptors. The 20-byte CDHash is a
//! CodeDirectory identifier, not a SHA-256 of a complete loaded image.

use std::{
    fmt::Write as _,
    time::{Duration, Instant},
};

use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};

use super::{native, process::ProcessIdentity};

const BUDGET: Duration = Duration::from_secs(3);

/// Outcome of one dynamic requirement check. No variant conveys authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImageInspection {
    /// The OS accepted the expected CodeDirectory requirement during the sample.
    /// This does not establish continuous image or process identity.
    Matched {
        /// Matching process snapshot, subject to PID and exec races.
        process: ProcessIdentity,
    },
    /// The OS explicitly reported that the requirement did not match.
    Mismatched {
        /// Process snapshot captured around the rejected requirement.
        process: ProcessIdentity,
    },
    /// No conclusion can be drawn; OS status is reported only when available.
    Unavailable {
        /// Why no observation was produced.
        problem: ImageProblem,
        /// Security framework status, when a call supplied one.
        status: Option<i32>,
    },
}

/// Reason an image requirement observation was unavailable.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageProblem {
    /// Invalid PID or an all-zero expected CodeDirectory identifier.
    InvalidInput,
    /// The ordinary-user observer is not an elevated diagnostic.
    RootObserver,
    /// A process snapshot could not be read or validated.
    ProcessUnavailable,
    /// The process snapshots were different.
    ProcessChanged,
    /// Security.framework could not construct or check the code requirement.
    SecurityUnavailable,
    /// The elapsed budget was exceeded; a native call was not preempted.
    TimedOut,
}

#[derive(Clone, Copy)]
enum Check {
    Matched,
    Mismatched,
    Unavailable(i32),
}

/// Check one PID against an already selected 20-byte CDHash as an ordinary user.
///
/// The result is a bounded diagnostic only. PID and birth-time checks do not
/// exclude `exec`, PID reuse ABA, or changes while the OS call is in progress.
/// No path, command line, arbitrary requirement, TUN binding, or PF authorization
/// is accepted or produced. A matching ad-hoc signature does not identify a
/// publisher. The elapsed-time budget is checked after synchronous
/// calls return; it is not a cancellation or hard timeout guarantee.
pub fn inspect_expected_cdhash(pid: u32, expected: [u8; 20]) -> ImageInspection {
    inspect_with(
        pid,
        expected,
        nix::unistd::Uid::effective().is_root(),
        |native_pid| native::process(native_pid).ok(),
        check_expected,
        Instant::now,
        BUDGET,
    )
}

fn check_expected(pid: i32, expected: &[u8; 20]) -> Check {
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let guest = match SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE) {
        Ok(guest) => guest,
        Err(error) => return Check::Unavailable(error.code()),
    };
    // The string contains exactly the fixed keyword and 40 lowercase hex digits.
    let mut expression = String::with_capacity(51);
    expression.push_str("cdhash H\"");
    for byte in expected {
        // Writing to a String cannot fail; avoid any unwrap/expect or user text.
        if write!(&mut expression, "{byte:02x}").is_err() {
            return Check::Unavailable(0);
        }
    }
    expression.push('"');
    let requirement: SecRequirement = match expression.parse() {
        Ok(requirement) => requirement,
        Err(error) => return Check::Unavailable(error.code()),
    };
    match guest.check_validity(Flags::NO_NETWORK_ACCESS, &requirement) {
        Ok(()) => Check::Matched,
        // errSecCSReqFailed: a valid dynamic code object did not match.
        Err(error) if error.code() == -67050 => Check::Mismatched,
        Err(error) => Check::Unavailable(error.code()),
    }
}

fn inspect_with(
    pid: u32,
    expected: [u8; 20],
    root: bool,
    mut read: impl FnMut(i32) -> Option<ProcessIdentity>,
    mut check: impl FnMut(i32, &[u8; 20]) -> Check,
    mut now: impl FnMut() -> Instant,
    budget: Duration,
) -> ImageInspection {
    let unavailable = |problem, status| ImageInspection::Unavailable { problem, status };
    let Ok(native_pid) = i32::try_from(pid) else {
        return unavailable(ImageProblem::InvalidInput, None);
    };
    if pid == 0 || expected == [0; 20] {
        return unavailable(ImageProblem::InvalidInput, None);
    }
    if root {
        return unavailable(ImageProblem::RootObserver, None);
    }
    let start = now();
    let expired = |time: Instant| {
        time.checked_duration_since(start)
            .is_none_or(|d| d > budget)
    };
    let valid = |p: &ProcessIdentity| {
        p.pid == pid && p.birth_seconds != 0 && p.birth_microseconds < 1_000_000
    };
    let Some(before) = read(native_pid).filter(valid) else {
        return unavailable(ImageProblem::ProcessUnavailable, None);
    };
    if expired(now()) {
        return unavailable(ImageProblem::TimedOut, None);
    }
    let result = check(native_pid, &expected);
    if expired(now()) {
        return unavailable(ImageProblem::TimedOut, None);
    }
    let Some(after) = read(native_pid).filter(valid) else {
        return unavailable(ImageProblem::ProcessUnavailable, None);
    };
    if expired(now()) {
        return unavailable(ImageProblem::TimedOut, None);
    }
    if before != after {
        return unavailable(ImageProblem::ProcessChanged, None);
    }
    match result {
        Check::Matched => ImageInspection::Matched { process: after },
        Check::Mismatched => ImageInspection::Mismatched { process: after },
        Check::Unavailable(status) => unavailable(ImageProblem::SecurityUnavailable, Some(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(pid: u32) -> ProcessIdentity {
        ProcessIdentity {
            pid,
            uid: 501,
            birth_seconds: 10,
            birth_microseconds: 20,
        }
    }

    #[test]
    fn matches_and_mismatches_are_explicit_and_rechecked() {
        for (check, matched) in [(Check::Matched, true), (Check::Mismatched, false)] {
            let mut reads = 0;
            let result = inspect_with(
                42,
                [1; 20],
                false,
                |_| {
                    reads += 1;
                    Some(process(42))
                },
                |_, _| check,
                Instant::now,
                BUDGET,
            );
            assert_eq!(reads, 2);
            assert_eq!(matches!(result, ImageInspection::Matched { .. }), matched);
        }
    }

    #[test]
    fn changed_or_missing_process_and_security_errors_never_match() {
        let mut count = 0;
        let result = inspect_with(
            42,
            [1; 20],
            false,
            |_| {
                count += 1;
                let mut p = process(42);
                p.birth_seconds += count;
                Some(p)
            },
            |_, _| Check::Matched,
            Instant::now,
            BUDGET,
        );
        assert!(matches!(
            result,
            ImageInspection::Unavailable {
                problem: ImageProblem::ProcessChanged,
                ..
            }
        ));
        let mut count = 0;
        let result = inspect_with(
            42,
            [1; 20],
            false,
            |_| {
                count += 1;
                (count == 1).then(|| process(42))
            },
            |_, _| Check::Matched,
            Instant::now,
            BUDGET,
        );
        assert!(matches!(
            result,
            ImageInspection::Unavailable {
                problem: ImageProblem::ProcessUnavailable,
                ..
            }
        ));
        let result = inspect_with(
            42,
            [1; 20],
            false,
            |_| Some(process(42)),
            |_, _| Check::Unavailable(-1),
            Instant::now,
            BUDGET,
        );
        assert!(matches!(
            result,
            ImageInspection::Unavailable {
                problem: ImageProblem::SecurityUnavailable,
                status: Some(-1)
            }
        ));
    }

    #[test]
    fn elapsed_budget_after_security_or_final_read_never_accepts_a_match() {
        for late_tick in [3, 4] {
            let start = Instant::now();
            let mut tick = 0;
            let result = inspect_with(
                42,
                [1; 20],
                false,
                |_| Some(process(42)),
                |_, _| Check::Matched,
                || {
                    tick += 1;
                    if tick < late_tick {
                        start
                    } else {
                        start + BUDGET + Duration::from_millis(1)
                    }
                },
                BUDGET,
            );
            assert!(matches!(
                result,
                ImageInspection::Unavailable {
                    problem: ImageProblem::TimedOut,
                    ..
                }
            ));
        }
    }

    #[test]
    fn invalid_input_root_and_elapsed_budget_fail_closed() {
        let read = |_| Some(process(42));
        let check = |_, _: &[u8; 20]| Check::Matched;
        assert!(matches!(
            inspect_with(0, [1; 20], false, read, check, Instant::now, BUDGET),
            ImageInspection::Unavailable {
                problem: ImageProblem::InvalidInput,
                ..
            }
        ));
        assert!(matches!(
            inspect_with(42, [0; 20], false, read, check, Instant::now, BUDGET),
            ImageInspection::Unavailable {
                problem: ImageProblem::InvalidInput,
                ..
            }
        ));
        assert!(matches!(
            inspect_with(42, [1; 20], true, read, check, Instant::now, BUDGET),
            ImageInspection::Unavailable {
                problem: ImageProblem::RootObserver,
                ..
            }
        ));
        let start = Instant::now();
        let mut n = 0;
        let result = inspect_with(
            42,
            [1; 20],
            false,
            read,
            check,
            || {
                n += 1;
                if n == 1 {
                    start
                } else {
                    start + BUDGET + Duration::from_millis(1)
                }
            },
            BUDGET,
        );
        assert!(matches!(
            result,
            ImageInspection::Unavailable {
                problem: ImageProblem::TimedOut,
                ..
            }
        ));
    }
}
