//! Single-PID, read-only privileged tunnel candidate diagnostic.

use std::{ffi::OsString, io::Write, process::ExitCode};

use serde_json::{Value, json};
use tunlatch_platform::identity::{
    TunnelCandidate, TunnelCandidateError, inspect_tunnel_candidate_privileged,
};

fn main() -> ExitCode {
    let (response, success) = match parse_args(std::env::args_os().skip(1)) {
        Some((pid, expected, hex)) => {
            render(inspect_tunnel_candidate_privileged(pid, expected), &hex)
        }
        None => unavailable("invalid_input"),
    };
    let mut output = std::io::stdout().lock();
    if serde_json::to_writer(&mut output, &response).is_err() || writeln!(output).is_err() {
        return ExitCode::FAILURE;
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn parse_args(mut args: impl Iterator<Item = OsString>) -> Option<(u32, [u8; 20], String)> {
    if args.next()? != "--pid" {
        return None;
    }
    let pid_arg = args.next()?;
    let pid_text = pid_arg.to_str()?;
    if pid_text.is_empty()
        || pid_text.starts_with('0')
        || !pid_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let pid = pid_text.parse::<u32>().ok()?;
    if i32::try_from(pid).is_err() || args.next()? != "--cdhash" {
        return None;
    }
    let hash_arg = args.next()?;
    let hex = hash_arg.to_str()?;
    if args.next().is_some()
        || hex.len() != 40
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let mut expected = [0_u8; 20];
    for (byte, pair) in expected.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let digit = |byte: u8| {
            if byte <= b'9' {
                byte - b'0'
            } else {
                byte - b'a' + 10
            }
        };
        *byte = digit(pair[0]) * 16 + digit(pair[1]);
    }
    if expected == [0; 20] {
        return None;
    }
    Some((pid, expected, hex.to_owned()))
}

fn render(result: Result<TunnelCandidate, TunnelCandidateError>, hex: &str) -> (Value, bool) {
    match result {
        Ok(candidate) => (
            json!({
                "result":"candidate", "basis":"utun_control_unit_minus_one",
                "process":{
                    "pid":candidate.process.pid, "effective_uid":candidate.process.uid,
                    "birth_seconds":candidate.process.birth_seconds,
                    "birth_microseconds":candidate.process.birth_microseconds,
                },
                "fd":candidate.fd, "control_id":candidate.control_id, "unit":candidate.unit,
                "ifname":candidate.ifname, "ifindex":candidate.ifindex,
                "sampling_milliseconds":candidate.elapsed.as_millis(),
                "matched_expected_cdhash":hex,
                "tun_ownership":"unknown", "actual_protection":"unknown", "authorization":"none",
            }),
            true,
        ),
        Err(error) => unavailable(error.kind()),
    }
}

fn unavailable(reason: &'static str) -> (Value, bool) {
    (
        json!({
            "result":"unavailable", "reason":reason, "tun_ownership":"unknown",
            "actual_protection":"unknown", "authorization":"none",
        }),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tunlatch_platform::identity::ProcessIdentity;

    fn parse(args: &[&str]) -> Option<(u32, [u8; 20], String)> {
        parse_args(args.iter().map(OsString::from))
    }

    #[test]
    fn accepts_only_canonical_ordered_arguments() {
        let hash = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            parse(&["--pid", "2147483647", "--cdhash", hash]),
            Some((
                i32::MAX as u32,
                [
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
                    0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67
                ],
                hash.into()
            ))
        );
        for pid in ["", "0", "01", "+1", "-1", "2147483648", "1 "] {
            assert!(parse(&["--pid", pid, "--cdhash", hash]).is_none());
        }
        for bad in [
            "0000000000000000000000000000000000000000",
            "ABCDEF6789abcdef0123456789abcdef01234567",
            "0123",
            "g123456789abcdef0123456789abcdef01234567",
        ] {
            assert!(parse(&["--pid", "1", "--cdhash", bad]).is_none());
        }
        assert!(parse(&["--cdhash", hash, "--pid", "1"]).is_none());
        assert!(parse(&["--pid", "1", "--cdhash", hash, "extra"]).is_none());
        assert!(parse(&["--pid", "1", "--cdhash"]).is_none());
    }

    #[test]
    fn candidate_output_contains_only_the_fixed_fields() {
        let hex = "0123456789abcdef0123456789abcdef01234567";
        let (output, success) = render(
            Ok(TunnelCandidate {
                process: ProcessIdentity {
                    pid: 123,
                    uid: 0,
                    birth_seconds: 1,
                    birth_microseconds: 2,
                },
                fd: 3,
                control_id: 4,
                unit: 5,
                ifname: "utun4".into(),
                ifindex: 6,
                elapsed: Duration::from_millis(7),
            }),
            hex,
        );
        assert!(success);
        assert_eq!(
            output,
            json!({"result":"candidate", "basis":"utun_control_unit_minus_one",
            "process":{"pid":123,"effective_uid":0,"birth_seconds":1,"birth_microseconds":2},
            "fd":3,"control_id":4,"unit":5,"ifname":"utun4","ifindex":6,
            "sampling_milliseconds":7,"matched_expected_cdhash":hex,
            "tun_ownership":"unknown","actual_protection":"unknown","authorization":"none"})
        );
    }

    #[test]
    fn error_output_uses_only_the_stable_reason() {
        let (output, success) = render(Err(TunnelCandidateError::InvalidInput), "ignored");
        assert!(!success);
        assert_eq!(
            output,
            json!({"result":"unavailable","reason":"invalid_input",
            "tun_ownership":"unknown","actual_protection":"unknown","authorization":"none"})
        );
    }
}
