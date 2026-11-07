//! Bounded offline inspection of the existing `pf_lab_readonly` query captures.
//!
//! Files, hashes, command exit status and text equality cannot authenticate kernel state. These
//! reads are non-atomic and contain neither per-query monotonic timestamps nor complete PF state
//! and execution-position evidence. Consequently this adapter can report only unknown or a
//! captured mismatch, never protection or `VerificationEvidence`. It runs no process or I/O.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::policy_compile::{PfCandidateStatus, PfCompileCandidate};

/// Existing operator's maximum complete query schedule: ten root reads and three per anchor.
pub const MAX_CAPTURE_QUERIES: usize = 58;
/// Existing operator's shared stdout/stderr limit for each query.
pub const MAX_QUERY_OUTPUT_BYTES: usize = 65_536;
/// Raw JSON is independently bounded before deserialization, including escaped output.
pub const MAX_CAPTURE_FILE_BYTES: usize = 524_288;
/// Independent aggregate limit for all supplied JSON files.
pub const MAX_CAPTURE_TOTAL_BYTES: usize = 8_388_608;
const ALTQ_NOTICE: &str = "No ALTQ support in kernel\nALTQ related functions disabled\n";

/// Validated literal anchor locator, not resource ownership or an execution capability.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct LiteralAnchor(String);

impl LiteralAnchor {
    /// Accept only bounded ASCII PF path components, with no options, traversal or wildcards.
    pub fn new(name: &str) -> Result<Self, PfObserveError> {
        if name.is_empty()
            || name.len() > 128
            || name.split('/').count() > 8
            || name.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.starts_with('-')
                    || !part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            })
        {
            return Err(PfObserveError::InvalidAnchor);
        }
        Ok(Self(name.into()))
    }

    /// Return the validated literal locator.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Captured evidence never has a protected/success variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureVerdict {
    /// Captured bytes contain a definite difference; no current system-state claim is made.
    Mismatch,
    /// The available files cannot establish current effective enforcement.
    Unknown,
}

/// Textual comparison only, without claiming equivalent kernel behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTextComparison {
    /// Canonical whitespace and exact filter text matched the candidate, including order/labels.
    ExactRenderedText,
    /// Captured filter text differs. This is not a semantic PF equivalence test.
    Different,
    /// Missing, incomplete or unsupported output prevented comparison.
    Unavailable,
}

/// Scope of the root-rule observation, deliberately not an execution-position proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootCallObservation {
    /// Exactly one unconditional literal call was captured, with no other filter root lines.
    DirectLiteralCall,
    /// The selected anchor was not directly called; nested/wildcard traversal is not proven.
    NoDirectCall,
    /// Other calls, root quick rules or unsupported root syntax prevent placement conclusions.
    Ambiguous,
    /// Root output was unavailable.
    Unavailable,
}

/// Explicit diagnostic reasons; missing evidence is never converted to a zero counter or pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureReason {
    /// The bytes and metadata came from ordinary files, not an authenticated kernel source.
    UnauthenticatedCapture,
    /// Independent commands do not form an atomic kernel snapshot.
    NonAtomicReads,
    /// This format cannot establish all execution-position, state and continuity conditions.
    ExecutionPositionUnproven,
    /// Missing or extra reads prevented validating the complete closed schedule.
    IncompleteSchedule,
    /// Output, pipes, child ownership or capture completeness was not established.
    TransportIncomplete,
    /// The fixed query reported a nonzero command outcome.
    CommandFailed,
    /// A fixed query reached its execution budget; reclamation is not inferred.
    TimedOut,
    /// The query output budget was reached.
    OutputLimit,
    /// stderr contained anything other than the exact recorded two-line ALTQ notice.
    UnexpectedStderr,
    /// A required captured output did not match the deliberately supported local format.
    UnsupportedOutput,
    /// Supplied capture start time is unset, future or outside the exclusive age bound.
    StaleOrFutureCapture,
    /// The before/after root rules or NAT text changed during collection.
    RootRulesChanged,
    /// The before/after anchor inventory changed during collection.
    AnchorInventoryChanged,
    /// The enabled candidate was captured while PF reported disabled.
    PfDisabled,
    /// The selected literal anchor was absent from the complete captured inventory.
    AnchorMissing,
    /// Captured filter text differs from the selected candidate's rendered text.
    CandidateTextDifferent,
    /// A root quick filter may bypass the selected literal call.
    RootQuickRule,
    /// Multiple/conditional/wildcard root calls prevented a complete placement conclusion.
    AmbiguousRootCalls,
    /// The captured interface list marked an interface skipped by PF.
    SkipInterface,
    /// No counters were present; this does not mean that rule hits were zero.
    CountersUnavailable,
}

/// Optional counters from one supported canonical PF verbose statistics line.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RuleCounters {
    /// Captured evaluation count, without assuming it counts protected traffic.
    pub evaluations: u64,
    /// Captured packet count, not TUN encryption or leak evidence.
    pub packets: u64,
    /// Captured byte count.
    pub bytes: u64,
    /// Captured current state count.
    pub states: u64,
}

/// Rule attribution without exposing unbounded raw output in diagnostics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CapturedRule {
    /// Bounded ASCII label when present; it does not establish resource ownership.
    pub label: Option<String>,
    /// None explicitly means unavailable, not zero.
    pub counters: Option<RuleCounters>,
}

/// Offline comparison result. No field can become an enforcement or approval capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PfCaptureObservation {
    /// Always unknown or a captured mismatch, never protected.
    pub verdict: CaptureVerdict,
    /// Structured limits and mismatches observed in the supplied files.
    pub reasons: Vec<CaptureReason>,
    /// Unauthenticated, caller-supplied start time from the collection intent.
    pub captured_unix: u64,
    /// Evaluation time used only to reject old/future captures.
    pub checked_unix: u64,
    /// PF enabled flag parsed from the supported status header, if available.
    pub captured_pf_enabled: Option<bool>,
    /// Limited root filter-call observation; never a full placement proof.
    pub root_call: RootCallObservation,
    /// Exact rendered text comparison, without semantic equivalence claims.
    pub rule_text: RuleTextComparison,
    /// Candidate content identity, distinct from source policy and actual kernel identity.
    pub candidate_digest: String,
    /// Bounded labels and optional counters from the selected anchor.
    pub rules: Vec<CapturedRule>,
}

/// Closed input-format failures, without reflecting hostile strings or filesystem paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PfObserveError {
    /// The requested anchor was not a safe literal locator.
    #[error("invalid literal PF anchor")]
    InvalidAnchor,
    /// Raw JSON or decoded output exceeded a fixed byte/count limit.
    #[error("PF capture exceeds a fixed resource limit")]
    LimitExceeded,
    /// Strict JSON fields, types or enum values did not match a supported capture version.
    #[error("unsupported PF capture JSON schema")]
    InvalidSchema,
    /// A query's stored content digest did not match its output bytes.
    #[error("PF capture content digest mismatch")]
    DigestMismatch,
    /// Query name, argv or schedule contained a non-closed query or a changed ordering.
    #[error("PF capture query is outside the closed read-only schedule")]
    InvalidQuery,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCapture {
    query: String,
    pfctl_argv: Vec<String>,
    reason: CompletionReason,
    stdout: String,
    stderr: String,
    truncated: bool,
    capture_failed: bool,
    parent_reaped: bool,
    pipes_closed: bool,
    command_tree_reclaimed: bool,
    stdout_sha256: String,
    stderr_sha256: String,
    // Earlier saved captures omit these two fields. Both versions remain closed schemas.
    #[serde(default)]
    diagnostic: Option<String>,
    #[serde(default)]
    recognized_altq_notice: Option<bool>,
}

#[derive(Clone, Copy, Deserialize)]
enum CompletionReason {
    Success,
    ExitFailure,
    Cancelled,
    Timeout,
    OutputLimit,
    InputFailure,
    IoFailure,
    SpawnFailure,
    DescendantsUnproven,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Query {
    Rules,
    Nat,
    Anchors,
    Interfaces,
    Info,
    References,
    AnchorRules(LiteralAnchor),
    AnchorNat(LiteralAnchor),
    AnchorTables(LiteralAnchor),
}

impl Query {
    fn parse(raw: &RawCapture) -> Result<Self, PfObserveError> {
        let args = raw
            .pfctl_argv
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        let (query, name) = match args.as_slice() {
            ["-s", "rules"] => (Self::Rules, "Rules".into()),
            ["-s", "nat"] => (Self::Nat, "Nat".into()),
            ["-v", "-s", "Anchors"] => (Self::Anchors, "Anchors".into()),
            ["-v", "-s", "Interfaces"] => (Self::Interfaces, "Interfaces".into()),
            ["-s", "info"] => (Self::Info, "Info".into()),
            ["-s", "References"] => (Self::References, "References".into()),
            ["-a", anchor, "-s", kind] => {
                let anchor = LiteralAnchor::new(anchor)?;
                let prefix = match *kind {
                    "rules" => "AnchorRules",
                    "nat" => "AnchorNat",
                    "Tables" => "AnchorTables",
                    _ => return Err(PfObserveError::InvalidQuery),
                };
                let name = format!("{prefix}(Literal(\"{}\"))", anchor.as_str());
                let query = match *kind {
                    "rules" => Self::AnchorRules(anchor),
                    "nat" => Self::AnchorNat(anchor),
                    _ => Self::AnchorTables(anchor),
                };
                (query, name)
            }
            _ => return Err(PfObserveError::InvalidQuery),
        };
        if raw.query != name {
            return Err(PfObserveError::InvalidQuery);
        }
        Ok(query)
    }
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn parse_capture(bytes: &[u8]) -> Result<(Query, RawCapture), PfObserveError> {
    if bytes.len() > MAX_CAPTURE_FILE_BYTES {
        return Err(PfObserveError::LimitExceeded);
    }
    let raw: RawCapture =
        serde_json::from_slice(bytes).map_err(|_| PfObserveError::InvalidSchema)?;
    if raw.stdout.len().saturating_add(raw.stderr.len()) > MAX_QUERY_OUTPUT_BYTES {
        return Err(PfObserveError::LimitExceeded);
    }
    if raw.stdout_sha256 != hash(raw.stdout.as_bytes())
        || raw.stderr_sha256 != hash(raw.stderr.as_bytes())
    {
        return Err(PfObserveError::DigestMismatch);
    }
    if raw
        .recognized_altq_notice
        .is_some_and(|known| known != (raw.stderr == ALTQ_NOTICE))
        || raw.diagnostic.as_deref().is_some_and(|diagnostic| {
            !matches!(
                diagnostic,
                "captured"
                    | "transport_incomplete"
                    | "command_failed"
                    | "unrecognized_stderr"
                    | "anchor_inventory_changed"
                    | "anchor_inventory_invalid"
            )
        })
    {
        return Err(PfObserveError::InvalidSchema);
    }
    Ok((Query::parse(&raw)?, raw))
}

fn push_reason(report: &mut PfCaptureObservation, reason: CaptureReason) {
    if !report.reasons.contains(&reason) {
        report.reasons.push(reason);
    }
}

fn mismatch(report: &mut PfCaptureObservation, reason: CaptureReason) {
    report.verdict = CaptureVerdict::Mismatch;
    push_reason(report, reason);
}

/// Inspect raw `query-XX.json` files from the existing closed operator in their recorded order.
///
/// `captured_unix` is the collection-intent start time, not a manufactured per-query timestamp.
/// The age bound is exclusive: age equal to `max_age_secs` is rejected. A caller must bound file
/// reads before passing these byte slices; this function independently bounds decoding. Missing
/// or incomplete reads return unknown with reasons; hostile schema/argv/hash inputs reject.
/// This function never invokes pfctl/sudo, reads a path, or creates lifecycle evidence.
pub fn verify_readonly_captures(
    candidate: &PfCompileCandidate,
    anchor: &LiteralAnchor,
    files: &[&[u8]],
    captured_unix: u64,
    now_unix: u64,
    max_age_secs: u64,
) -> Result<PfCaptureObservation, PfObserveError> {
    if files.len() > MAX_CAPTURE_QUERIES
        || files
            .iter()
            .try_fold(0_usize, |total, bytes| total.checked_add(bytes.len()))
            .is_none_or(|total| total > MAX_CAPTURE_TOTAL_BYTES)
    {
        return Err(PfObserveError::LimitExceeded);
    }
    let mut report = PfCaptureObservation {
        verdict: CaptureVerdict::Unknown,
        reasons: vec![
            CaptureReason::UnauthenticatedCapture,
            CaptureReason::NonAtomicReads,
            CaptureReason::ExecutionPositionUnproven,
        ],
        captured_unix,
        checked_unix: now_unix,
        captured_pf_enabled: None,
        root_call: RootCallObservation::Unavailable,
        rule_text: RuleTextComparison::Unavailable,
        candidate_digest: candidate.digest().to_string(),
        rules: Vec::new(),
    };
    let records = files
        .iter()
        .map(|bytes| parse_capture(bytes))
        .collect::<Result<Vec<_>, _>>()?;
    if captured_unix == 0
        || now_unix
            .checked_sub(captured_unix)
            .is_none_or(|age| age >= max_age_secs)
    {
        push_reason(&mut report, CaptureReason::StaleOrFutureCapture);
        return Ok(report);
    }
    let mut incomplete = false;
    for (_, raw) in &records {
        let failure = match raw.reason {
            CompletionReason::Success => None,
            CompletionReason::ExitFailure => Some(CaptureReason::CommandFailed),
            CompletionReason::Timeout => Some(CaptureReason::TimedOut),
            CompletionReason::OutputLimit => Some(CaptureReason::OutputLimit),
            _ => Some(CaptureReason::TransportIncomplete),
        };
        if let Some(failure) = failure {
            incomplete = true;
            push_reason(&mut report, failure);
        }
        if raw.truncated
            || raw.capture_failed
            || !raw.parent_reaped
            || !raw.pipes_closed
            || !raw.command_tree_reclaimed
            || raw
                .diagnostic
                .as_deref()
                .is_some_and(|value| value != "captured")
        {
            incomplete = true;
            push_reason(&mut report, CaptureReason::TransportIncomplete);
        }
        if !raw.stderr.is_empty() && raw.stderr != ALTQ_NOTICE {
            incomplete = true;
            push_reason(&mut report, CaptureReason::UnexpectedStderr);
        }
        if !canonical_text(&raw.stdout) {
            incomplete = true;
            push_reason(&mut report, CaptureReason::UnsupportedOutput);
        }
    }
    if incomplete {
        return Ok(report);
    }
    let Some((Query::Anchors, inventory)) = records.get(2) else {
        push_reason(&mut report, CaptureReason::IncompleteSchedule);
        return Ok(report);
    };
    let Some(inventory) = parse_inventory(&inventory.stdout) else {
        push_reason(&mut report, CaptureReason::UnsupportedOutput);
        return Ok(report);
    };
    let mut expected = vec![Query::Rules, Query::Nat, Query::Anchors];
    for name in &inventory {
        expected.extend([
            Query::AnchorRules(name.clone()),
            Query::AnchorNat(name.clone()),
            Query::AnchorTables(name.clone()),
        ]);
    }
    expected.extend([
        Query::Interfaces,
        Query::Info,
        Query::References,
        Query::Rules,
        Query::Nat,
        Query::References,
        Query::Anchors,
    ]);
    if records.len() != expected.len() {
        push_reason(&mut report, CaptureReason::IncompleteSchedule);
        return Ok(report);
    }
    if records.iter().map(|(query, _)| query).ne(expected.iter()) {
        return Err(PfObserveError::InvalidQuery);
    }
    for (query, raw) in &records {
        if !ancillary_format_supported(query, &raw.stdout) {
            push_reason(&mut report, CaptureReason::UnsupportedOutput);
        }
    }
    let root_rules = &records[0].1.stdout;
    let tail = records.len() - 7;
    if root_rules != &records[tail + 3].1.stdout
        || records[1].1.stdout != records[tail + 4].1.stdout
    {
        mismatch(&mut report, CaptureReason::RootRulesChanged);
    }
    if parse_inventory(&records[tail + 6].1.stdout).as_ref() != Some(&inventory) {
        mismatch(&mut report, CaptureReason::AnchorInventoryChanged);
    }
    report.captured_pf_enabled = parse_enabled(&records[tail + 1].1.stdout);
    if report.captured_pf_enabled.is_none() {
        push_reason(&mut report, CaptureReason::UnsupportedOutput);
    } else if report.captured_pf_enabled == Some(false)
        && candidate.status() == PfCandidateStatus::BlockedNotReady
    {
        mismatch(&mut report, CaptureReason::PfDisabled);
    }
    inspect_root(root_rules, anchor, &mut report);
    match parse_interfaces(&records[tail].1.stdout) {
        Some(true) => push_reason(&mut report, CaptureReason::SkipInterface),
        None => push_reason(&mut report, CaptureReason::UnsupportedOutput),
        Some(false) => {}
    }
    if !inventory.contains(anchor) {
        mismatch(&mut report, CaptureReason::AnchorMissing);
        return Ok(report);
    }
    let Some((_, captured)) = records
        .iter()
        .find(|(query, _)| query == &Query::AnchorRules(anchor.clone()))
    else {
        push_reason(&mut report, CaptureReason::IncompleteSchedule);
        return Ok(report);
    };
    let Some((text, rules)) = parse_rules(&captured.stdout) else {
        push_reason(&mut report, CaptureReason::UnsupportedOutput);
        return Ok(report);
    };
    let expected = candidate
        .rules_text()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(normalize_whitespace)
        .collect::<Vec<_>>();
    report.rule_text = if text == expected {
        RuleTextComparison::ExactRenderedText
    } else {
        mismatch(&mut report, CaptureReason::CandidateTextDifferent);
        RuleTextComparison::Different
    };
    if rules.iter().any(|rule| rule.counters.is_none()) {
        push_reason(&mut report, CaptureReason::CountersUnavailable);
    }
    report.rules = rules;
    Ok(report)
}

fn canonical_text(text: &str) -> bool {
    (text.is_empty() || text.ends_with('\n'))
        && text
            .bytes()
            .all(|byte| byte == b'\n' || byte == b'\t' || (b' '..=b'~').contains(&byte))
}

fn parse_inventory(text: &str) -> Option<BTreeSet<LiteralAnchor>> {
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let name = LiteralAnchor::new(line.trim_ascii()).ok()?;
        if !names.insert(name) || names.len() > 16 {
            return None;
        }
    }
    for name in &names {
        if let Some((parent, _)) = name.as_str().rsplit_once('/')
            && !names.contains(&LiteralAnchor::new(parent).ok()?)
        {
            return None;
        }
    }
    Some(names)
}

fn normalize_whitespace(line: &str) -> String {
    line.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

fn ancillary_format_supported(query: &Query, text: &str) -> bool {
    match query {
        Query::Nat | Query::AnchorNat(_) => text.lines().all(|line| {
            let line = normalize_whitespace(line);
            (line.starts_with("nat-anchor \"") || line.starts_with("rdr-anchor \""))
                && line.ends_with("\" all")
        }),
        Query::AnchorTables(_) => text.lines().all(|name| {
            let name = name.trim_ascii();
            !name.is_empty()
                && name.len() < 32
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        }),
        Query::References => matches!(
            text,
            "No pf starter references held\n" | "No pf_enabled references\n"
        ),
        // The selected rules, root rules, inventory, interfaces and status have separate
        // parsers. Other filter anchors cannot establish this anchor's execution position.
        _ => true,
    }
}

fn inspect_root(text: &str, anchor: &LiteralAnchor, report: &mut PfCaptureObservation) {
    let expected = format!("anchor \"{}\" all", anchor.as_str());
    let mut matching = 0;
    let mut other = false;
    for line in text.lines() {
        let line = normalize_whitespace(line);
        if line == expected {
            matching += 1;
        } else if line.starts_with("scrub-anchor \"") && line.ends_with(" all fragment reassemble")
        {
            // This captured normalization call does not prove packet-filter placement.
        } else {
            other = true;
            if (line.starts_with("pass ") || line.starts_with("block "))
                && line.split_ascii_whitespace().any(|word| word == "quick")
            {
                push_reason(report, CaptureReason::RootQuickRule);
            }
        }
    }
    report.root_call = if matching == 1 && !other {
        RootCallObservation::DirectLiteralCall
    } else if matching == 0 && !other {
        RootCallObservation::NoDirectCall
    } else {
        push_reason(report, CaptureReason::AmbiguousRootCalls);
        RootCallObservation::Ambiguous
    };
}

fn parse_enabled(text: &str) -> Option<bool> {
    let mut lines = text.lines();
    let header = lines.next()?;
    let enabled = if header.starts_with("Status: Enabled for ") {
        true
    } else if header.starts_with("Status: Disabled for ") {
        false
    } else {
        return None;
    };
    let (uptime, debug) = header.split_once(" for ")?.1.split_once("Debug: ")?;
    let uptime = uptime.split_ascii_whitespace().collect::<Vec<_>>();
    let [days, "days", time] = uptime.as_slice() else {
        return None;
    };
    let time = time.split(':').collect::<Vec<_>>();
    if !matches!(debug, "None" | "Urgent" | "Misc" | "Loud")
        || days.parse::<u64>().is_err()
        || time.len() != 3
        || time.iter().enumerate().any(|(index, part)| {
            part.len() != 2
                || part
                    .parse::<u8>()
                    .map_or(true, |value| value > if index == 0 { 23 } else { 59 })
        })
    {
        return None;
    }
    // Local -s info format: exact section headings and closed numeric counter keys. Unknown
    // fields/versions stay unavailable instead of being silently treated as the same format.
    let keys = [
        "current entries",
        "searches",
        "inserts",
        "removals",
        "match",
        "bad-offset",
        "fragment",
        "short",
        "normalize",
        "memory",
        "bad-timestamp",
        "congestion",
        "ip-option",
        "proto-cksum",
        "state-mismatch",
        "state-insert",
        "state-limit",
        "src-limit",
        "synproxy",
        "dummynet",
        "invalid-port",
    ];
    let mut lines = lines.map(str::trim_ascii).filter(|line| !line.is_empty());
    if normalize_whitespace(lines.next()?) != "State Table Total Rate" {
        return None;
    }
    for (index, key) in keys.into_iter().enumerate() {
        if index == 4 && lines.next()? != "Counters" {
            return None;
        }
        let numbers = lines.next()?.strip_prefix(key)?;
        if !numbers.starts_with(' ') {
            return None;
        }
        let values = numbers.split_ascii_whitespace().collect::<Vec<_>>();
        let count = values.first()?;
        if count.parse::<u64>().is_err() || values.len() != if index == 0 { 1 } else { 2 } {
            return None;
        }
        if index != 0 {
            let rate = values.get(1)?.strip_suffix("/s")?;
            let (whole, fraction) = rate.split_once('.')?;
            if whole.is_empty()
                || fraction.is_empty()
                || !whole
                    .bytes()
                    .chain(fraction.bytes())
                    .all(|b| b.is_ascii_digit())
            {
                return None;
            }
        }
    }
    lines.next().is_none().then_some(enabled)
}

fn parse_interfaces(text: &str) -> Option<bool> {
    let mut seen = BTreeSet::new();
    let mut skipped = false;
    for line in text.lines() {
        let (name, skip) = if let Some(name) = line.strip_suffix(" (skip)") {
            (name, true)
        } else {
            (line, false)
        };
        if name.is_empty()
            || name.len() > 15
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._".contains(&b))
            || !seen.insert(name)
        {
            return None;
        }
        skipped |= skip;
    }
    (!seen.is_empty()).then_some(skipped)
}

fn parse_rules(text: &str) -> Option<(Vec<String>, Vec<CapturedRule>)> {
    let mut lines = Vec::new();
    let mut rules: Vec<CapturedRule> = Vec::new();
    for line in text.lines() {
        let line = normalize_whitespace(line);
        if line.starts_with("[ ") {
            let last = rules.last_mut()?;
            if last.counters.is_some() {
                return None;
            }
            last.counters = Some(parse_counters(&line)?);
            continue;
        }
        if !(line.starts_with("block ") || line.starts_with("pass ")) {
            return None;
        }
        let label = if let Some((_, label)) = line.rsplit_once(" label \"") {
            let label = label.strip_suffix('"')?;
            if label.is_empty()
                || label.len() >= 64
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return None;
            }
            Some(label.to_string())
        } else {
            None
        };
        lines.push(line);
        rules.push(CapturedRule {
            label,
            counters: None,
        });
    }
    Some((lines, rules))
}

fn parse_counters(line: &str) -> Option<RuleCounters> {
    let words = line.split_ascii_whitespace().collect::<Vec<_>>();
    let [
        "[",
        "Evaluations:",
        evaluations,
        "Packets:",
        packets,
        "Bytes:",
        bytes,
        "States:",
        states,
        "]",
    ] = words.as_slice()
    else {
        return None;
    };
    Some(RuleCounters {
        evaluations: evaluations.parse().ok()?,
        packets: packets.parse().ok()?,
        bytes: bytes.parse().ok()?,
        states: states.parse().ok()?,
    })
}
