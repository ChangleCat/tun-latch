//! Read-only, non-atomic PF observation for the isolated laboratory slot.
//! Equal snapshots do not establish exclusive access or rule execution semantics.
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, SyncSender};
use std::time::{Duration, Instant};

const CAP: usize = 65536;
const NOTICE: &[u8] = b"No ALTQ support in kernel\nALTQ related functions disabled\n";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Baseline {
    root_rules: Vec<u8>,
    root_nat: Vec<u8>,
    inventory: BTreeSet<String>,
    foreign: BTreeMap<String, (Vec<u8>, Vec<u8>)>,
}
impl Baseline {
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"tunlatch-pf-slot-baseline\0");
        for item in std::iter::once(self.root_rules.as_slice())
            .chain(std::iter::once(self.root_nat.as_slice()))
            .chain(self.inventory.iter().map(|name| name.as_bytes()))
        {
            hash.update((item.len() as u64).to_be_bytes());
            hash.update(item);
        }
        hash.update((self.foreign.len() as u64).to_be_bytes());
        for (name, (rules, nat)) in &self.foreign {
            for item in [name.as_bytes(), rules.as_slice(), nat.as_slice()] {
                hash.update((item.len() as u64).to_be_bytes());
                hash.update(item);
            }
        }
        hash.finalize().into()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum Slot {
    Absent,
    Empty,
    Active(Vec<u8>),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Snapshot {
    pub(crate) baseline: Baseline,
    pub(crate) slot: Slot,
}

fn rejected(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name.split('/').count() <= 8
        && name.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && !p.starts_with('-')
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}
fn inventory(data: &[u8]) -> io::Result<BTreeSet<String>> {
    let text = std::str::from_utf8(data).map_err(|_| rejected("inventory is not ASCII"))?;
    if !text.is_ascii()
        || text
            .bytes()
            .any(|b| b.is_ascii_control() && b != b'\n' && b != b'\t')
        || (!text.is_empty() && !text.ends_with('\n'))
    {
        return Err(rejected("invalid inventory framing"));
    }
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let name = line.trim_matches([' ', '\t']);
        if !valid_name(name) || names.len() >= 17 || !names.insert(name.to_owned()) {
            return Err(rejected("invalid or duplicate inventory"));
        }
    }
    if names
        .iter()
        .any(|n| n.rsplit_once('/').is_some_and(|(p, _)| !names.contains(p)))
    {
        return Err(rejected("inventory missing parent"));
    }
    Ok(names)
}
fn root_calls(data: &[u8], own: &str, context: Option<&str>) -> io::Result<()> {
    let text = std::str::from_utf8(data).map_err(|_| rejected("non-UTF8 root rules"))?;
    if !text.is_ascii() || (!text.is_empty() && !text.ends_with('\n')) {
        return Err(rejected("invalid root rule framing"));
    }
    for line in text.lines() {
        let mut words = line.split_ascii_whitespace();
        let first = words.next().ok_or_else(|| rejected("empty root rule"))?;
        if matches!(
            first,
            "anchor" | "nat-anchor" | "rdr-anchor" | "binat-anchor" | "scrub-anchor"
        ) {
            let target = words
                .next()
                .and_then(|w| w.strip_prefix('"'))
                .and_then(|w| w.strip_suffix('"'))
                .ok_or_else(|| rejected("unsupported anchor call"))?;
            if let Some(prefix) = target.strip_suffix("/*") {
                let in_apple =
                    context.is_some_and(|c| c == "com.apple" || c.starts_with("com.apple/"));
                if valid_name(prefix)
                    && !prefix.split('/').any(|part| part == own)
                    && ((context.is_none() && prefix == "com.apple") || in_apple)
                {
                    continue;
                }
                return Err(rejected("unsafe or unsupported wildcard target"));
            }
            if !valid_name(target) || target.split('/').any(|part| part == own) {
                return Err(rejected("unsafe or unsupported anchor target"));
            }
        } else if first.contains("anchor") {
            return Err(rejected("unsupported anchor expression"));
        }
    }
    Ok(())
}

// Reader threads send bounded chunks through a bounded queue. A timeout kills the only child;
// a stuck pipe reader can detach but cannot retain unbounded output or execute another command.
fn pump<R: Read + Send + 'static>(mut pipe: R, tag: u8, tx: SyncSender<(u8, io::Result<Vec<u8>>)>) {
    std::thread::spawn(move || {
        loop {
            let mut buf = [0; 4096];
            match pipe.read(&mut buf) {
                Ok(0) => {
                    let _ = tx.send((tag, Ok(Vec::new())));
                    break;
                }
                Ok(n) => {
                    if tx.send((tag, Ok(buf[..n].to_vec()))).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    let _ = tx.send((tag, Err(e)));
                    break;
                }
            }
        }
    });
}
fn execute_program(
    program: &str,
    args: &[&str],
    outer_deadline: Instant,
) -> io::Result<(Vec<u8>, usize)> {
    let deadline = outer_deadline.min(Instant::now() + Duration::from_secs(3));
    if Instant::now() >= deadline {
        return Err(rejected("observation deadline exceeded"));
    }
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .env("LC_ALL", "C")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let (tx, rx) = mpsc::sync_channel(4);
    pump(
        child
            .stdout
            .take()
            .ok_or_else(|| rejected("missing stdout"))?,
        0,
        tx.clone(),
    );
    pump(
        child
            .stderr
            .take()
            .ok_or_else(|| rejected("missing stderr"))?,
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
        if status.is_some() && ends == 2 {
            break Ok(());
        }
        if Instant::now() >= deadline {
            break Err(rejected("PF read timed out"));
        }
        match rx.recv_timeout(Duration::from_millis(10)) {
            Ok((_, Ok(bytes))) if bytes.is_empty() => ends += 1,
            Ok((tag, Ok(bytes))) => {
                if out.len() + err.len() + bytes.len() > CAP {
                    break Err(rejected("PF output exceeded limit"));
                }
                if tag == 0 {
                    out.extend(bytes);
                } else {
                    err.extend(bytes);
                }
            }
            Ok((_, Err(e))) => break Err(e),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) if ends == 2 => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(rejected("PF pipes incomplete"));
            }
        }
    };
    if result.is_err() && status.is_none() {
        let _ = child.kill();
        let cleanup = Instant::now() + Duration::from_secs(1);
        while Instant::now() < cleanup {
            if child.try_wait()?.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    result?;
    if !status.is_some_and(|s| s.success()) || !(err.is_empty() || err == NOTICE) {
        return Err(rejected("PF read failed or unexpected stderr"));
    }
    let captured = out.len() + err.len();
    Ok((out, captured))
}

fn collect<F>(anchor: &str, mut query: F) -> io::Result<Snapshot>
where
    F: FnMut(&[&str]) -> io::Result<Vec<u8>>,
{
    let suffix = anchor
        .strip_prefix("tunlatch-lab-")
        .ok_or_else(|| rejected("invalid own slot"))?;
    if suffix.len() != 8 || !suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(rejected("invalid own slot"));
    }
    let info = query(&["-s", "info"])?;
    if !info.starts_with(b"Status: Disabled ") {
        return Err(rejected("PF is not disabled"));
    }
    if query(&["-s", "References"])? != b"No pf starter references held\n" {
        return Err(rejected("PF references are not zero"));
    }
    let root_rules = query(&["-s", "rules"])?;
    let root_nat = query(&["-s", "nat"])?;
    root_calls(&root_rules, anchor, None)?;
    root_calls(&root_nat, anchor, None)?;
    let mut names = inventory(&query(&["-v", "-s", "Anchors"])?)?;
    let top = inventory(&query(&["-s", "Anchors"])?)?;
    let expected: BTreeSet<_> = names.iter().filter(|n| !n.contains('/')).cloned().collect();
    if top != expected || names.iter().any(|n| n.starts_with(&format!("{anchor}/"))) {
        return Err(rejected("inconsistent inventory or slot children"));
    }
    if names.iter().filter(|name| name.as_str() != anchor).count() > 16 {
        return Err(rejected("too many foreign anchors"));
    }
    let mut foreign = BTreeMap::new();
    for name in names.iter().filter(|name| name.as_str() != anchor) {
        let rules = query(&["-a", name, "-s", "rules"])?;
        let nat = query(&["-a", name, "-s", "nat"])?;
        root_calls(&rules, anchor, Some(name))?;
        root_calls(&nat, anchor, Some(name))?;
        foreign.insert(name.clone(), (rules, nat));
    }
    let slot = if !top.contains(anchor) {
        Slot::Absent
    } else {
        for kind in ["nat", "Tables", "Anchors"] {
            if !query(&["-a", anchor, "-s", kind])?.is_empty() {
                return Err(rejected("slot has NAT, tables or children"));
            }
        }
        let rules = query(&["-a", anchor, "-s", "rules"])?;
        if rules.is_empty() {
            Slot::Empty
        } else {
            Slot::Active(rules)
        }
    };
    if !query(&["-s", "info"])?.starts_with(b"Status: Disabled ")
        || query(&["-s", "References"])? != b"No pf starter references held\n"
    {
        return Err(rejected("PF status or references changed during read"));
    }
    names.remove(anchor);
    Ok(Snapshot {
        baseline: Baseline {
            root_rules,
            root_nat,
            inventory: names,
            foreign,
        },
        slot,
    })
}
fn collect_bounded<F>(anchor: &str, deadline: Instant, mut query: F) -> io::Result<Snapshot>
where
    F: FnMut(&[&str], Instant) -> io::Result<(Vec<u8>, usize)>,
{
    let mut total = 0_usize;
    let result = collect(anchor, |args| {
        let (out, captured) = query(args, deadline)?;
        total = total
            .checked_add(captured)
            .ok_or_else(|| rejected("PF snapshot size overflow"))?;
        if total > 128 * 1024 {
            return Err(rejected("PF snapshot exceeds aggregate limit"));
        }
        if out
            .split(|b| *b == b'\n')
            .any(|line| line.starts_with(b"pfctl:"))
        {
            return Err(rejected("PF reported an error on stdout"));
        }
        Ok(out)
    })?;
    if Instant::now() >= deadline {
        return Err(rejected("observation deadline exceeded"));
    }
    Ok(result)
}

/// Reads only fixed pfctl views; callers must separately establish exclusive coordination.
pub(crate) fn read(anchor: &str) -> io::Result<Snapshot> {
    collect_bounded(
        anchor,
        Instant::now() + Duration::from_secs(8),
        |args, deadline| execute_program("/sbin/pfctl", args, deadline),
    )
}

/// Read the kernel boot session identity with the same bounded read-only transport.
pub(crate) fn boot() -> io::Result<String> {
    let (bytes, _) = execute_program(
        "/usr/sbin/sysctl",
        &["-n", "kern.bootsessionuuid"],
        Instant::now() + Duration::from_secs(3),
    )?;
    let value = std::str::from_utf8(&bytes).map_err(|_| rejected("invalid boot identity"))?;
    let uuid = value
        .strip_suffix('\n')
        .ok_or_else(|| rejected("invalid boot identity framing"))?;
    if uuid.len() != 36
        || !uuid.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
    {
        return Err(rejected("invalid boot identity"));
    }
    Ok(uuid.to_ascii_lowercase())
}

/// Construct a deterministic offline snapshot; never observes PF.
#[cfg(test)]
pub(crate) fn fixture(_anchor: &str, slot: Slot) -> Snapshot {
    Snapshot {
        baseline: Baseline {
            root_rules: b"anchor \"com.apple/*\" all\n".to_vec(),
            root_nat: Vec::new(),
            inventory: BTreeSet::from(["com.apple".to_owned()]),
            foreign: BTreeMap::from([("com.apple".to_owned(), (Vec::new(), Vec::new()))]),
        },
        slot,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fake(anchor: &str, present: bool, rules: &[u8]) -> io::Result<Snapshot> {
        collect(anchor, |args| {
            Ok(match args {
                ["-s", "info"] => b"Status: Disabled now\n".to_vec(),
                ["-s", "References"] => b"No pf starter references held\n".to_vec(),
                ["-s", "rules"] => b"anchor \"com.apple/*\" all\n".to_vec(),
                ["-s", "nat"] => Vec::new(),
                ["-v", "-s", "Anchors"] | ["-s", "Anchors"] => {
                    if present {
                        format!("com.apple\n{anchor}\n").into_bytes()
                    } else {
                        b"com.apple\n".to_vec()
                    }
                }
                ["-a", name, "-s", "rules"] if *name == anchor => rules.to_vec(),
                ["-a", _, "-s", "rules"] => Vec::new(),
                ["-a", _, "-s", "nat" | "Tables" | "Anchors"] => Vec::new(),
                _ => return Err(rejected("unexpected query")),
            })
        })
    }
    #[test]
    fn slot_transitions_preserve_baseline() -> io::Result<()> {
        let a = "tunlatch-lab-12345678";
        let x = fake(a, false, b"")?;
        let y = fake(a, true, b"")?;
        let z = fake(a, true, b"rule\n")?;
        assert_eq!(x.baseline, y.baseline);
        assert_eq!(y.baseline, z.baseline);
        assert_eq!(x.slot, Slot::Absent);
        assert_eq!(y.slot, Slot::Empty);
        assert_eq!(z.slot, Slot::Active(b"rule\n".to_vec()));
        Ok(())
    }
    #[test]
    fn rejects_reaching_slot_and_wildcards() {
        let a = "tunlatch-lab-12345678";
        for line in [
            format!("anchor \"{a}\" all\n"),
            "anchor \"*\" all\n".into(),
            "nat-anchor \"foo/*\" all\n".into(),
            "anchor unquoted all\n".into(),
        ] {
            assert!(root_calls(line.as_bytes(), a, None).is_err());
        }
        assert!(root_calls(b"anchor \"com.apple/*\" all\n", a, None).is_ok());
        assert!(root_calls(b"anchor \"200.AirDrop/*\" all\n", a, Some("com.apple")).is_ok());
        assert!(root_calls(b"anchor \"../other/*\" all\n", a, Some("com.apple")).is_err());
    }
    #[test]
    fn foreign_rules_are_read_and_baseline_changes_with_them() -> io::Result<()> {
        let anchor = "tunlatch-lab-12345678";
        let observe = |foreign_rules: &[u8]| {
            collect(anchor, |args| {
                Ok(match args {
            ["-s", "info"] => b"Status: Disabled now\n".to_vec(),
            ["-s", "References"] => b"No pf starter references held\n".to_vec(),
            ["-s", "rules"] => b"scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"foreign\" all\n".to_vec(),
            ["-s", "nat"] => b"nat-anchor \"com.apple/*\" all\n".to_vec(),
            ["-v", "-s", "Anchors"] | ["-s", "Anchors"] => b"  foreign\n".to_vec(),
            ["-a", "foreign", "-s", "rules"] => foreign_rules.to_vec(),
            ["-a", "foreign", "-s", "nat"] => Vec::new(),
            _ => return Err(rejected("unexpected query")),
        })
            })
        };
        let empty = observe(b"")?;
        let changed = observe(b"block drop all\n")?;
        assert_ne!(empty.baseline.digest(), changed.baseline.digest());
        assert!(observe(b"anchor \"tunlatch-lab-12345678\" all\n").is_err());
        assert!(observe(b"anchor \"com.apple/*\" all\n").is_err());
        Ok(())
    }
    #[test]
    fn expired_deadline_never_starts_a_child() {
        let result = execute_program("/definitely-not-a-real-executable", &[], Instant::now());
        assert_eq!(
            result.err().map(|e| e.to_string()),
            Some("observation deadline exceeded".to_owned())
        );
    }
    #[test]
    fn snapshot_limit_counts_all_query_bytes() {
        let result = collect_bounded(
            "tunlatch-lab-12345678",
            Instant::now() + Duration::from_secs(1),
            |args, _| {
                let output = match args {
                    ["-s", "info"] => b"Status: Disabled now\n".to_vec(),
                    ["-s", "References"] => b"No pf starter references held\n".to_vec(),
                    ["-s", "rules" | "nat"] => Vec::new(),
                    ["-v", "-s", "Anchors"] | ["-s", "Anchors"] => b"a\nb\nc\n".to_vec(),
                    ["-a", _, "-s", "rules"] => b"block drop all\n".repeat(3300),
                    ["-a", _, "-s", "nat"] => Vec::new(),
                    _ => return Err(rejected("unexpected query")),
                };
                let bytes = output.len() + NOTICE.len();
                Ok((output, bytes))
            },
        );
        assert_eq!(
            result.err().map(|e| e.to_string()),
            Some("PF snapshot exceeds aggregate limit".to_owned())
        );
    }
    #[test]
    fn inventory_accepts_display_indentation() -> io::Result<()> {
        assert_eq!(
            inventory(b"  com.apple\n\tcom.apple/child  \n")?,
            BTreeSet::from(["com.apple".to_owned(), "com.apple/child".to_owned()])
        );
        Ok(())
    }
    #[test]
    fn inventory_refuses_ambiguity() {
        for text in ["x\nx\n", "x/y\n", "-x\n", "x", "x/*\n", "x\r\n"] {
            assert!(inventory(text.as_bytes()).is_err());
        }
    }
}
