//! Bounded, read-only PF observations using the system's fixed `pfctl` executable.
//!
//! These separate queries are not an atomic snapshot and do not establish rule ownership,
//! effective packet filtering, or permission to mutate PF.

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant};

const LIMIT: usize = 65_536;
const TIMEOUT: Duration = Duration::from_secs(3);
const NOTICE: &[u8] = b"No ALTQ support in kernel\nALTQ related functions disabled\n";

/// The fixed system observation to request. None of these operations modifies PF.
#[derive(Clone, Copy, Debug)]
pub enum Query<'a> {
    /// Global PF status and counters.
    Info,
    /// PF starter-reference inventory.
    References,
    /// The root filter rules, in the order printed by the system tool.
    RootRules,
    /// Filter rules of the project anchor associated with this session.
    AnchorRules {
        /// Nonzero lowercase 32-digit hexadecimal session ID.
        session: &'a str,
    },
}

/// Failure to obtain one complete, bounded observation.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// The fixed system tool could not be started or monitored.
    #[error("PF query failed: {0}")]
    Io(#[from] io::Error),
    /// The child did not finish within the query deadline.
    #[error("PF query timed out")]
    Timeout,
    /// Combined stdout and stderr exceeded the fixed limit.
    #[error("PF query output exceeded its limit")]
    OutputLimit,
    /// The child failed, a pipe failed, or diagnostic output was unexpected.
    #[error("PF query did not produce a complete successful result")]
    Incomplete,
    /// The session cannot name an anchor managed by this adapter.
    #[error("invalid PF anchor session")]
    InvalidSession,
}

/// Run one fixed read-only PF query as an already privileged caller.
///
/// This does not acquire an enable reference and does not report that protection is effective.
/// The returned bytes must be interpreted according to the selected query's output format.
/// A timed-out child is killed and reaped; synchronous OS calls, including reaping, can block.
pub fn query(which: Query<'_>) -> Result<Vec<u8>, SnapshotError> {
    let anchor = match which {
        Query::AnchorRules { session } => Some(anchor_name(session)?),
        _ => None,
    };
    if !nix::unistd::geteuid().is_root() {
        return Err(SnapshotError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PF queries require root",
        )));
    }
    let mut command = Command::new("/sbin/pfctl");
    match which {
        Query::Info => {
            command.args(["-s", "info"]);
        }
        Query::References => {
            command.args(["-s", "References"]);
        }
        Query::RootRules => {
            command.args(["-s", "rules"]);
        }
        Query::AnchorRules { .. } => {
            let name = anchor.as_deref().ok_or(SnapshotError::InvalidSession)?;
            command.args(["-a", name, "-s", "rules"]);
        }
    }
    command.env_clear().env("LC_ALL", "C").current_dir("/");
    let result = run(command, TIMEOUT)?;
    if !result.status.success() || !(result.stderr.is_empty() || result.stderr == NOTICE) {
        return Err(SnapshotError::Incomplete);
    }
    if !valid_output(&result.stdout) {
        return Err(SnapshotError::Incomplete);
    }
    Ok(result.stdout)
}

fn valid_output(output: &[u8]) -> bool {
    (output.is_empty() || output.ends_with(b"\n"))
        && output.is_ascii()
        && !output
            .iter()
            .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\t'))
}

// Fixed host-identity queries used to qualify the private PF ABI. Do not accept a path or
// arguments from a caller: these identifiers are part of the trust boundary for native reads.
pub(super) fn host_identity() -> Result<(String, String), SnapshotError> {
    Ok((
        system_line("/usr/bin/sw_vers", &["-buildVersion"])?,
        system_line("/usr/sbin/sysctl", &["-n", "kern.version"])?,
    ))
}

fn system_line(program: &str, argument: &[&str]) -> Result<String, SnapshotError> {
    let mut command = Command::new(program);
    command
        .args(argument)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/");
    let result = run(command, TIMEOUT)?;
    if !result.status.success() || !result.stderr.is_empty() || !valid_output(&result.stdout) {
        return Err(SnapshotError::Incomplete);
    }
    let value = std::str::from_utf8(&result.stdout)
        .map_err(|_| SnapshotError::Incomplete)?
        .strip_suffix('\n')
        .ok_or(SnapshotError::Incomplete)?;
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(SnapshotError::Incomplete);
    }
    Ok(value.to_owned())
}

pub(super) fn boot_session() -> Result<String, SnapshotError> {
    let value = system_line("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"])?;
    parse_boot_session(&value)
}

pub(super) fn parse_boot_session(value: &str) -> Result<String, SnapshotError> {
    if value.len() != 36
        || !value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        || value
            .bytes()
            .filter(|b| b.is_ascii_hexdigit())
            .all(|b| b == b'0')
    {
        return Err(SnapshotError::Incomplete);
    }
    Ok(value.to_ascii_lowercase())
}

// This fixed mutating command is only available to the guarded reference acquisition path.
pub(super) fn acquire_reference() -> Result<Return, SnapshotError> {
    let mut command = Command::new("/sbin/pfctl");
    command
        .arg("-E")
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/");
    run(command, TIMEOUT)
}

// Only a successfully acquired token can be supplied; no global disable is supported.
pub(super) fn release_reference(
    token: super::reference::ReferenceToken,
) -> Result<Return, SnapshotError> {
    let mut command = Command::new("/sbin/pfctl");
    command
        .args(["-X", &token.get().to_string()])
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/");
    run(command, TIMEOUT)
}

fn anchor_name(session: &str) -> Result<String, SnapshotError> {
    if session.len() != 32
        || session.bytes().all(|byte| byte == b'0')
        || !session
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SnapshotError::InvalidSession);
    }
    Ok(format!("tunlatch-lab-{session}"))
}

pub(super) struct Return {
    pub(super) pid: u32,
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

enum Message {
    Data(bool, Vec<u8>),
    End,
    Failed,
}

fn pump<R: Read + Send + 'static>(mut pipe: R, stderr: bool, sender: SyncSender<Message>) {
    std::thread::spawn(move || {
        let mut buffer = [0; 4096];
        loop {
            let message = match pipe.read(&mut buffer) {
                Ok(0) => Message::End,
                Ok(length) => Message::Data(stderr, buffer[..length].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => Message::Failed,
            };
            let finished = !matches!(message, Message::Data(..));
            if sender.send(message).is_err() || finished {
                break;
            }
        }
    });
}

fn stop_child(child: &mut Child, status: Option<ExitStatus>) -> Result<(), SnapshotError> {
    if status.is_none() {
        // The process may have exited between try_wait and kill; wait is still required.
        match child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            Err(error) => {
                if child.try_wait()?.is_some() {
                    return Ok(());
                }
                return Err(SnapshotError::Io(error));
            }
        }
        child.wait()?;
    }
    Ok(())
}

fn run(mut command: Command, timeout: Duration) -> Result<Return, SnapshotError> {
    let deadline = Instant::now() + timeout;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (sender, receiver) = mpsc::sync_channel(4);
    let stdout = child.stdout.take().ok_or(SnapshotError::Incomplete)?;
    let stderr = child.stderr.take().ok_or(SnapshotError::Incomplete)?;
    pump(stdout, false, sender.clone());
    pump(stderr, true, sender);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut ends = 0;
    let mut status = None;
    let result = loop {
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(error) => break Err(SnapshotError::Io(error)),
            }
        }
        if ends == 2
            && let Some(status) = status
        {
            break Ok(Return {
                pid: child.id(),
                status,
                stdout: out,
                stderr: err,
            });
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Err(SnapshotError::Timeout);
        }
        if ends == 2 {
            // Both pipes may close just before try_wait observes the child's exit.
            std::thread::sleep(remaining.min(Duration::from_millis(10)));
            continue;
        }
        match receiver.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(Message::Data(is_stderr, bytes)) => {
                if out.len() + err.len() + bytes.len() > LIMIT {
                    break Err(SnapshotError::OutputLimit);
                }
                if is_stderr {
                    err.extend(bytes);
                } else {
                    out.extend(bytes);
                }
            }
            Ok(Message::End) => ends += 1,
            Ok(Message::Failed) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(SnapshotError::Incomplete);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
    };
    if result.is_err() {
        stop_child(&mut child, status)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn gathers_both_streams_and_child_status() -> Result<(), SnapshotError> {
        let result = run(shell("printf out; printf err >&2; exit 3"), TIMEOUT)?;
        assert_eq!(result.stdout, b"out");
        assert_eq!(result.stderr, b"err");
        assert_eq!(result.status.code(), Some(3));
        Ok(())
    }

    #[test]
    fn waits_for_exit_after_both_pipes_close() -> Result<(), SnapshotError> {
        let result = run(shell("exec 1>&- 2>&-; sleep 0.1; exit 3"), TIMEOUT)?;
        assert_eq!(result.status.code(), Some(3));
        Ok(())
    }

    #[test]
    fn aborts_oversized_or_stalled_queries() {
        let excessive = run(shell("exec yes x"), TIMEOUT);
        assert!(matches!(excessive, Err(SnapshotError::OutputLimit)));
        let stalled = run(shell("exec sleep 2"), Duration::from_millis(50));
        assert!(matches!(stalled, Err(SnapshotError::Timeout)));
    }

    #[test]
    fn anchor_queries_reject_foreign_or_ambiguous_names() {
        for session in [
            "",
            "00000000000000000000000000000000",
            "com.apple/*",
            "ABCDEF0123456789abcdef0123456789",
        ] {
            assert!(matches!(
                query(Query::AnchorRules { session }),
                Err(SnapshotError::InvalidSession)
            ));
        }
        assert_eq!(
            anchor_name("0123456789abcdef0123456789abcdef")
                .ok()
                .as_deref(),
            Some("tunlatch-lab-0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn rejects_partial_and_terminal_control_output() {
        assert!(valid_output(b"pass out all\n"));
        assert!(valid_output(b""));
        for bad in [&b"pass out all"[..], b"\x1b[31m\n", b"\xff\n", b"line\r\n"] {
            assert!(!valid_output(bad));
        }
    }

    #[test]
    fn boot_session_requires_a_nonzero_canonical_uuid() {
        assert_eq!(
            parse_boot_session("ABCDEF01-2345-6789-ABCD-EF0123456789")
                .ok()
                .as_deref(),
            Some("abcdef01-2345-6789-abcd-ef0123456789")
        );
        for invalid in [
            "00000000-0000-0000-0000-000000000000",
            "abcdef012345-6789-abcd-ef0123456789",
            "abcdef01-2345-6789-abcd-ef012345678z",
            "abcdef01-2345-6789-abcd-ef0123456789\n",
        ] {
            assert!(parse_boot_session(invalid).is_err());
        }
    }
}
