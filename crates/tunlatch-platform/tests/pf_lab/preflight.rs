//! Bounded, fail-closed parser/collector preparation. No process or PF device access.
//!
//! This deliberately supports a SMALL pfctl display subset, not arbitrary PF syntax. Source-
//! derived fixtures are not captures from this host. Unsupported formats/policies refuse entry.
//! Two equal sweeps only detect some changes; exclusive administrator coordination is still
//! required and cannot be established by these output bytes (or detect every ABA).

use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

const MAX_BYTES: usize = 65536;
const MAX_ANCHORS: usize = 16;
const MAX_CALLS: usize = 80;
const MAX_SWEEP_MS: u64 = 2000;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct Anchor(String);
impl Anchor {
    pub(crate) fn new(text: &str) -> Result<Self> {
        if text.is_empty()
            || text.len() > 128
            || text.split('/').count() > 8
            || text.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return Err(Error::Rejected("invalid literal anchor path"));
        }
        Ok(Self(text.into()))
    }
    pub(crate) fn name(&self) -> &str {
        &self.0
    }
}

/// Closed read vocabulary. Anchor operands are validated literals; no shell or write arguments.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Query {
    Anchors,
    Rules(Option<Anchor>),
    Tables(Option<Anchor>),
    Interfaces,
    References,
}
impl Query {
    pub(crate) fn argv(&self) -> Vec<&str> {
        match self {
            Self::Anchors => vec!["-v", "-s", "Anchors"],
            Self::Rules(anchor) | Self::Tables(anchor) => {
                let mut args = Vec::new();
                if let Some(path) = anchor {
                    args.extend(["-a", path.name()]);
                }
                args.extend([
                    "-s",
                    if matches!(self, Self::Rules(_)) {
                        "rules"
                    } else {
                        "Tables"
                    },
                ]);
                args
            }
            Self::Interfaces => vec!["-v", "-s", "Interfaces"],
            Self::References => vec!["-s", "References"],
        }
    }
    pub(crate) fn executable(&self) -> &'static str {
        "/sbin/pfctl"
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Output {
    pub(crate) bytes: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) success: bool,
    pub(crate) truncated: bool,
    pub(crate) started_ms: u64,
    pub(crate) ended_ms: u64,
    pub(crate) sequence: u64,
    pub(crate) boot: [u8; 32],
}
pub(crate) trait ReadBoundary {
    fn query(&mut self, query: Query) -> Result<Output>;
}
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum Error {
    #[error("preflight refused: {0}")]
    Rejected(&'static str),
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Rule {
    Call { target: Anchor, wildcard: bool },
    Block,
}

fn rules(text: &str) -> Result<Vec<Rule>> {
    let mut result = Vec::new();
    for line in text.lines() {
        if result.len() >= 256 {
            return Err(Error::Rejected("too many rules"));
        }
        // Any quick/pass/direction/interface expression outside this tiny recognized grammar
        // is refused. In particular no optimistic substring search for an anchor name.
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        if words == ["block", "drop", "out", "all"] {
            result.push(Rule::Block);
        } else if words.len() == 3 && words[0] == "anchor" && words[2] == "all" {
            let target = words[1]
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .ok_or(Error::Rejected("malformed anchor call"))?;
            let (path, wildcard) = target
                .strip_suffix("/*")
                .map_or((target, false), |p| (p, true));
            result.push(Rule::Call {
                target: Anchor::new(path)?,
                wildcard,
            });
        } else {
            return Err(Error::Rejected("unknown, quick or overriding rule"));
        }
    }
    Ok(result)
}

#[derive(Debug, Eq, PartialEq)]
struct Sweep {
    inventory: BTreeSet<Anchor>,
    rules: BTreeMap<Option<Anchor>, Vec<Rule>>,
    interfaces: BTreeMap<String, bool>,
    references: BTreeMap<u64, (u32, String)>,
}

// Display fields verified against the local system binary's static format strings, without
// executing it. Header/row fixtures remain synthetic, not observations of active references.
fn references(text: &str) -> Result<BTreeMap<u64, (u32, String)>> {
    if text == "No pf_enabled references\n" {
        return Ok(BTreeMap::new());
    }
    let mut lines = text.lines();
    let mut header = lines
        .next()
        .ok_or(Error::Rejected("missing reference status"))?;
    if header == "TOKENS:" {
        header = lines
            .next()
            .ok_or(Error::Rejected("missing token header"))?;
    }
    if !header
        .split_ascii_whitespace()
        .eq(["PID", "Process", "Name", "TOKEN", "TIMESTAMP"])
    {
        return Err(Error::Rejected("unknown reference header"));
    }
    let mut entries = BTreeMap::new();
    for line in lines {
        let fields: Vec<_> = line.split_ascii_whitespace().collect();
        if fields.len() < 6 || fields.len() > 16 || entries.len() >= 64 {
            return Err(Error::Rejected("invalid or excessive reference row"));
        }
        let tail = fields.len() - 4;
        let pid = fields[0]
            .parse::<u32>()
            .map_err(|_| Error::Rejected("invalid reference PID"))?;
        let token = fields[tail]
            .parse::<u64>()
            .map_err(|_| Error::Rejected("invalid reference token"))?;
        fields[tail + 1]
            .parse::<u32>()
            .map_err(|_| Error::Rejected("invalid reference days"))?;
        let clock: Vec<_> = fields[tail + 3].split(':').collect();
        if fields[tail + 2] != "days"
            || clock.len() != 3
            || clock
                .iter()
                .any(|n| n.len() != 2 || !n.bytes().all(|b| b.is_ascii_digit()))
            || clock[0].parse::<u8>().map_or(true, |n| n > 23)
            || clock[1..]
                .iter()
                .any(|n| n.parse::<u8>().map_or(true, |n| n > 59))
            || pid == 0
            || pid > i32::MAX as u32
            || token == 0
        {
            return Err(Error::Rejected("invalid reference timestamp or identity"));
        }
        let process = fields[1..tail].join(" ");
        if process.is_empty()
            || process.len() > 128
            || entries.insert(token, (pid, process)).is_some()
        {
            return Err(Error::Rejected("ambiguous reference identity"));
        }
    }
    if entries.is_empty() {
        return Err(Error::Rejected("token header without complete rows"));
    }
    Ok(entries)
}

/// A parsing result is not authority, proof of current exclusivity, PF enabled, or protection.
pub(crate) struct CheckedBoundary {
    own: Anchor,
    sweep: Sweep,
    pub(crate) observed_ms: u64,
    pub(crate) boot: [u8; 32],
}
impl CheckedBoundary {
    pub(crate) fn own(&self) -> &Anchor {
        &self.own
    }
    pub(crate) fn existing_references(&self) -> usize {
        self.sweep.references.len()
    }
    pub(crate) fn empty_owned_leaf(&self) -> bool {
        !self.sweep.inventory.contains(&self.own)
            && !self.sweep.rules.contains_key(&Some(self.own.clone()))
    }
    pub(crate) fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(format!("{:?}", self.sweep).as_bytes()).into()
    }
}

struct Collector<'a, R> {
    reader: &'a mut R,
    boot: [u8; 32],
    start: u64,
    end: u64,
    sequence: u64,
    bytes: usize,
    calls: usize,
}
impl<R: ReadBoundary> Collector<'_, R> {
    fn read(&mut self, query: Query) -> Result<String> {
        if self.calls >= MAX_CALLS {
            return Err(Error::Rejected("query budget exhausted"));
        }
        self.calls += 1;
        let out = self.reader.query(query)?;
        self.bytes = self
            .bytes
            .checked_add(out.bytes.len())
            .and_then(|n| n.checked_add(out.stderr.len()))
            .ok_or(Error::Rejected("output overflow"))?;
        if self.bytes > MAX_BYTES
            || !out.success
            || out.truncated
            || !out.stderr.is_empty()
            || out.boot != self.boot
            || out.sequence <= self.sequence
            || out.started_ms < self.end
            || out.ended_ms < out.started_ms
            || out.ended_ms.saturating_sub(self.start) > MAX_SWEEP_MS
        {
            return Err(Error::Rejected(
                "failed, incomplete, stale or inconsistent observation",
            ));
        }
        self.end = out.ended_ms;
        self.sequence = out.sequence;
        let text = String::from_utf8(out.bytes).map_err(|_| Error::Rejected("non UTF-8 output"))?;
        if (!text.is_empty() && !text.ends_with('\n'))
            || text
                .bytes()
                .any(|b| b == 0 || (!b.is_ascii_graphic() && !b" \t\n".contains(&b)))
        {
            return Err(Error::Rejected("unterminated or invalid output"));
        }
        Ok(text)
    }
    fn sweep(&mut self) -> Result<Sweep> {
        let inventory_text = self.read(Query::Anchors)?;
        let mut inventory = BTreeSet::new();
        for line in inventory_text.lines() {
            let path = Anchor::new(line.trim())?;
            if !inventory.insert(path) || inventory.len() > MAX_ANCHORS {
                return Err(Error::Rejected("duplicate or excessive anchor inventory"));
            }
        }
        // Every nested path must have an enumerated parent; no missing middle node.
        for path in &inventory {
            if let Some((parent, _)) = path.name().rsplit_once('/')
                && !inventory.contains(&Anchor::new(parent)?)
            {
                return Err(Error::Rejected("incomplete recursive anchor inventory"));
            }
        }
        let mut sets = BTreeMap::new();
        for anchor in std::iter::once(None).chain(inventory.iter().cloned().map(Some)) {
            sets.insert(
                anchor.clone(),
                rules(&self.read(Query::Rules(anchor.clone()))?)?,
            );
            // Tables need their own inspection. None are supported in this conservative subset;
            // silently omitting an unfamiliar table-dependent ruleset would be unsafe.
            if !self.read(Query::Tables(anchor))?.is_empty() {
                return Err(Error::Rejected("tables require a reviewed parser"));
            }
        }
        let mut interfaces = BTreeMap::new();
        for line in self.read(Query::Interfaces)?.lines() {
            let (name, skip) = line
                .strip_suffix(" (skip)")
                .map_or((line, false), |p| (p, true));
            if name.is_empty()
                || name.len() > 15
                || !name.bytes().all(|b| b.is_ascii_alphanumeric())
                || interfaces.insert(name.into(), skip).is_some()
                || interfaces.len() > 64
            {
                return Err(Error::Rejected("unknown or excessive interface output"));
            }
        }
        if interfaces.is_empty() || interfaces.iter().any(|(name, skip)| *skip && name != "lo0") {
            return Err(Error::Rejected("skip or incomplete interface coverage"));
        }
        let references = references(&self.read(Query::References)?)?;
        Ok(Sweep {
            inventory,
            rules: sets,
            interfaces,
            references,
        })
    }
}

fn reachable(sweep: &Sweep, own: &Anchor) -> Result<bool> {
    let mut pending = vec![None];
    let mut visited = BTreeSet::new();
    let mut found = false;
    while let Some(node) = pending.pop() {
        if !visited.insert(node.clone()) {
            return Err(Error::Rejected("cyclic or repeated anchor traversal"));
        }
        let set = sweep
            .rules
            .get(&node)
            .ok_or(Error::Rejected("missing ruleset"))?;
        for rule in set {
            if let Rule::Call { target, wildcard } = rule {
                if !*wildcard && target == own {
                    found = true;
                    continue;
                }
                if *wildcard
                    && own
                        .name()
                        .rsplit_once('/')
                        .is_some_and(|(p, _)| p == target.name())
                {
                    // A wildcard parent must itself be in the observed inventory.
                    if !sweep.inventory.contains(target) {
                        return Err(Error::Rejected("wildcard parent missing"));
                    }
                    found = true;
                }
                if *wildcard {
                    for child in &sweep.inventory {
                        if child
                            .name()
                            .rsplit_once('/')
                            .is_some_and(|(p, _)| p == target.name())
                        {
                            pending.push(Some(child.clone()));
                        }
                    }
                } else {
                    if !sweep.inventory.contains(target) {
                        return Err(Error::Rejected("call target missing"));
                    }
                    pending.push(Some(target.clone()));
                }
            }
        }
    }
    Ok(found)
}

pub(crate) fn inspect(
    reader: &mut impl ReadBoundary,
    own: Anchor,
    boot: [u8; 32],
    now_ms: u64,
) -> Result<CheckedBoundary> {
    if boot == [0; 32] {
        return Err(Error::Rejected("unknown boot identity"));
    }
    let mut c = Collector {
        reader,
        boot,
        start: now_ms,
        end: now_ms,
        sequence: 0,
        bytes: 0,
        calls: 0,
    };
    let before = c.sweep()?;
    let after = c.sweep()?;
    if before != after {
        return Err(Error::Rejected("boundary changed across sweeps"));
    }
    if before.inventory.contains(&own)
        || before
            .inventory
            .iter()
            .any(|a| a.name().starts_with(&(own.name().to_owned() + "/")))
        || before
            .rules
            .values()
            .flatten()
            .any(|rule| matches!(rule, Rule::Call {target,wildcard:false} if target == &own))
    {
        return Err(Error::Rejected("foreign namespace or exact hook collision"));
    }
    if !reachable(&before, &own)? {
        return Err(Error::Rejected("leaf is not reachable from the root"));
    }
    Ok(CheckedBoundary {
        own,
        sweep: before,
        observed_ms: c.end,
        boot,
    })
}
