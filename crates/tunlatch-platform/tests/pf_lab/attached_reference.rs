//! Fixed, one-shot PF reference transport for a separately authorized protected caller.
//! Journaling, current-boot binding, exclusive coordination and writer reclamation belong to
//! the caller. An error after spawn is indeterminate and must never trigger an automatic retry.
use super::references::{Reply, Token, parse_token};
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant};

const LIMIT: usize = 1024;
const EMPTY: &[u8] = b"No pf starter references held\n";
const NOTICE: &[u8] = b"No ALTQ support in kernel\nALTQ related functions disabled\n";

fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}

/// Complete child return; the caller must durably persist these exact bytes and PID.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Return {
    pub(crate) pid: u32,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) exit_code: i32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Owned {
    token: Token,
    pid: u32,
}
impl Owned {
    /// Only after authenticating a durable return for this current-boot experiment. This parser
    /// alone does not prove that the process or reference still belongs to the caller.
    pub(crate) fn from_return(value: &Return) -> io::Result<Self> {
        if value.pid == 0 || value.stdout.len().saturating_add(value.stderr.len()) > LIMIT {
            return Err(refused("missing creator PID"));
        }
        let mut stderr = value.stderr.as_slice();
        if stderr.starts_with(NOTICE) {
            stderr = &stderr[NOTICE.len()..];
        }
        let reply = Reply {
            stdout: value.stdout.clone(),
            stderr: stderr.to_vec(),
            exit_code: value.exit_code,
            truncated: false,
            creator_birth: 1,
        };
        let token = parse_token(&reply).map_err(|_| refused("invalid acquire return"))?;
        Ok(Self {
            token,
            pid: value.pid,
        })
    }
    pub(crate) fn token(self) -> u64 {
        self.token.value()
    }
}

pub(crate) fn read_owned(owner: Owned) -> io::Result<()> {
    singleton(&query(&mut run)?, owner)
}

/// Strict singleton output based on the installed pfctl format. No inference from token alone.
pub(crate) fn singleton(data: &[u8], owner: Owned) -> io::Result<()> {
    let text = std::str::from_utf8(data).map_err(|_| refused("non-text references"))?;
    if data.len() > LIMIT || !text.is_ascii() || !text.ends_with('\n') {
        return Err(refused("incomplete references"));
    }
    let mut lines = text.lines();
    if lines.next() != Some("TOKENS:") {
        return Err(refused("missing token heading"));
    }
    if !lines.next().is_some_and(|line| {
        line.split_ascii_whitespace()
            .eq(["PID", "Process", "Name", "TOKEN", "TIMESTAMP"])
    }) {
        return Err(refused("unrecognized token header"));
    }
    let row = lines.next().ok_or_else(|| refused("missing token row"))?;
    if lines.next().is_some() {
        return Err(refused("multiple token rows"));
    }
    let fields: Vec<_> = row.split_ascii_whitespace().collect();
    if fields.len() != 6
        || fields[0] != owner.pid.to_string()
        || fields[1] != "pfctl"
        || fields[2] != owner.token().to_string()
        || fields[3].parse::<u32>().is_err()
        || fields[4] != "days"
    {
        return Err(refused("reference owner mismatch"));
    }
    let clock: Vec<_> = fields[5].split(':').collect();
    if clock.len() != 3
        || clock
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|b| b.is_ascii_digit()))
        || clock[0].parse::<u8>().map_or(true, |n| n > 23)
        || clock[1..]
            .iter()
            .any(|part| part.parse::<u8>().map_or(true, |n| n > 59))
    {
        return Err(refused("invalid reference timestamp"));
    }
    Ok(())
}

fn pump<R: Read + Send + 'static>(mut pipe: R, tag: u8, tx: SyncSender<(u8, io::Result<Vec<u8>>)>) {
    std::thread::spawn(move || {
        loop {
            let mut bytes = [0; 512];
            match pipe.read(&mut bytes) {
                Ok(n) => {
                    if tx.send((tag, Ok(bytes[..n].to_vec()))).is_err() || n == 0 {
                        break;
                    }
                }
                Err(error) => {
                    let _ = tx.send((tag, Err(error)));
                    break;
                }
            }
        }
    });
}

/// Fixed executable, no shell, caller-supplied executable, environment or retry.
fn run(args: &[&str]) -> io::Result<Return> {
    if !nix::unistd::geteuid().is_root() {
        return Err(refused("protected caller must already be root"));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut child = Command::new("/sbin/pfctl")
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let pid = child.id();
    let (tx, rx) = mpsc::sync_channel(4);
    pump(
        child
            .stdout
            .take()
            .ok_or_else(|| refused("missing stdout"))?,
        0,
        tx.clone(),
    );
    pump(
        child
            .stderr
            .take()
            .ok_or_else(|| refused("missing stderr"))?,
        1,
        tx,
    );
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut ends = 0;
    let mut status = None;
    let result = loop {
        if status.is_none() {
            status = child.try_wait()?;
        }
        if ends == 2 && status.is_some() {
            break Ok(());
        }
        if Instant::now() >= deadline {
            break Err(refused("child return unknown"));
        }
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok((_, Ok(bytes))) if bytes.is_empty() => ends += 1,
            Ok((tag, Ok(bytes))) => {
                if out.len() + err.len() + bytes.len() > LIMIT {
                    break Err(refused("child output exceeded limit"));
                }
                if tag == 0 {
                    out.extend(bytes);
                } else {
                    err.extend(bytes);
                }
            }
            Ok((_, Err(_))) => break Err(refused("child pipe failed")),
            Err(mpsc::RecvTimeoutError::Timeout) => (),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(refused("child pipes incomplete"));
            }
        }
    };
    if result.is_err() && status.is_none() {
        let _ = child.kill();
    }
    result?;
    let code = status
        .and_then(|s| s.code())
        .ok_or_else(|| refused("child terminated by signal"))?;
    Ok(Return {
        pid,
        stdout: out,
        stderr: err,
        exit_code: code,
    })
}

fn query(run: &mut impl FnMut(&[&str]) -> io::Result<Return>) -> io::Result<Vec<u8>> {
    let result = run(&["-s", "References"])?;
    if result.exit_code != 0 || !(result.stderr.is_empty() || result.stderr == NOTICE) {
        return Err(refused("reference read failed"));
    }
    Ok(result.stdout)
}

/// Persist callbacks must synchronously durably store intent before spawn and the unmodified
/// complete return before this function parses it. The caller owns non-replay and recovery rules.
pub(crate) fn acquire_once(
    intent: impl FnOnce() -> io::Result<()>,
    persist_return: impl FnOnce(&Return) -> io::Result<()>,
) -> io::Result<Owned> {
    acquire_with(&mut run, intent, persist_return)
}

fn acquire_with(
    run: &mut impl FnMut(&[&str]) -> io::Result<Return>,
    intent: impl FnOnce() -> io::Result<()>,
    persist_return: impl FnOnce(&Return) -> io::Result<()>,
) -> io::Result<Owned> {
    if query(run)? != EMPTY {
        return Err(refused("reference baseline not empty"));
    }
    intent()?;
    let result = run(&["-E"])?;
    persist_return(&result)?;
    let owner = Owned::from_return(&result)?;
    singleton(&query(run)?, owner)?;
    Ok(owner)
}

/// An independently recovered owner requires caller authentication and a fresh exclusive window.
/// The returned child record must be persisted even when its exit status indicates failure.
pub(crate) fn release_once(
    owner: Owned,
    intent: impl FnOnce() -> io::Result<()>,
    persist_return: impl FnOnce(&Return) -> io::Result<()>,
) -> io::Result<()> {
    release_with(&mut run, owner, intent, persist_return)
}

fn release_with(
    run: &mut impl FnMut(&[&str]) -> io::Result<Return>,
    owner: Owned,
    intent: impl FnOnce() -> io::Result<()>,
    persist_return: impl FnOnce(&Return) -> io::Result<()>,
) -> io::Result<()> {
    singleton(&query(run)?, owner)?;
    intent()?;
    let token = owner.token().to_string();
    let result = run(&["-X", &token])?;
    persist_return(&result)?;
    if result.exit_code != 0
        || !(result.stdout.is_empty() || result.stdout == b"pf disabled\n")
        || !(result.stderr.is_empty()
            || result.stderr == NOTICE
            || result.stderr == b"pf disabled\n"
            || result.stderr == [NOTICE, b"pf disabled\n"].concat())
    {
        return Err(refused("release return failed or ambiguous"));
    }
    if query(run)? != EMPTY {
        return Err(refused("release not independently confirmed"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn receipt() -> Return {
        Return {
            pid: 123,
            stdout: b"pf enabled\nToken : 42\n".to_vec(),
            stderr: vec![],
            exit_code: 0,
        }
    }
    #[test]
    fn singleton_requires_exact_owner_and_complete_inventory() -> io::Result<()> {
        let owner = Owned::from_return(&receipt())?;
        let good = b"TOKENS:\nPID      Process Name                 TOKEN                    TIMESTAMP\n123      pfctl                        42                       0 days 00:00:01\n";
        singleton(good, owner)?;
        for bad in [
            "No pf starter references held\n",
            "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 other 42 0 days 00:00:01\n",
            "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 pfctl 42 0 days 00:00:01\n123 pfctl 43 0 days 00:00:01\n",
            "TOKENS:\nPID Process Name TOKEN TIMESTAMP\n123 pfctl 42 0 days 00:00:01",
        ] {
            assert!(singleton(bad.as_bytes(), owner).is_err());
        }
        Ok(())
    }
    #[test]
    fn return_must_contain_one_complete_successful_token() {
        let mut value = receipt();
        value.stdout.extend(b"Token : 43\n");
        assert!(Owned::from_return(&value).is_err());
        let mut value = receipt();
        value.exit_code = 1;
        assert!(Owned::from_return(&value).is_err());
        let mut value = receipt();
        value.pid = 0;
        assert!(Owned::from_return(&value).is_err());
    }
    #[test]
    fn failed_intent_prevents_mutation_and_bad_return_is_persisted() {
        use std::cell::RefCell;
        let calls = RefCell::new(Vec::new());
        let mut executor = |args: &[&str]| {
            calls.borrow_mut().push(args.join(" "));
            if args == ["-s", "References"] {
                Ok(Return {
                    pid: 77,
                    stdout: EMPTY.to_vec(),
                    stderr: vec![],
                    exit_code: 0,
                })
            } else {
                let mut result = receipt();
                result.exit_code = 1;
                Ok(result)
            }
        };
        assert!(acquire_with(&mut executor, || Err(refused("disk failed")), |_| Ok(())).is_err());
        assert_eq!(&*calls.borrow(), &["-s References"]);
        calls.borrow_mut().clear();
        let persisted = RefCell::new(false);
        assert!(
            acquire_with(
                &mut executor,
                || Ok(()),
                |r| {
                    *persisted.borrow_mut() = r.exit_code == 1;
                    Ok(())
                }
            )
            .is_err()
        );
        assert!(*persisted.borrow());
        assert_eq!(&*calls.borrow(), &["-s References", "-E"]);
    }
}
