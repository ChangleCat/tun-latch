//! Offline assessment of one capture against a frozen three-phase peer plan.
//! All supplied metadata is untrusted evidence, not an authorization or physical proof.
use super::driver::{Error, Result};
use super::exact_filter::{ExactFilter, Flow as RuleFlow};
use super::traffic::{Application, Flow, Plan, Protocol, parse_pcap};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Case {
    family: String,
    protocol: String,
    source: SocketAddr,
    destination: SocketAddr,
    nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Cases {
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenPlan {
    before: Cases,
    blocked: Cases,
    after: Cases,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Window {
    start_us: u64,
    end_us: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Windows {
    before: Window,
    blocked: Window,
    after: Window,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectEvidence {
    family: String,
    protocol: String,
    /// Direct evidence that the blocked probe was actually sent/attempted at the relevant hook.
    sent: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CounterEvidence {
    anchor_suffix: String,
    rules_before: String,
    rules_after: String,
    labels_before: String,
    labels_after: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Reports {
    before: PeerReport,
    blocked: PeerReport,
    after: PeerReport,
}
fn present_string<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error> {
    String::deserialize(deserializer).map(Some)
}
fn present_errno<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Option<i32>>, D::Error> {
    Option::<i32>::deserialize(deserializer).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerReport {
    status: String,
    role: String,
    helper_sha256: String,
    #[serde(default, deserialize_with = "present_string")]
    validator_sha256: Option<String>,
    pf_verdict: String,
    cases: Vec<PeerResult>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerResult {
    family: String,
    protocol: String,
    source: SocketAddr,
    destination: SocketAddr,
    nonce: String,
    result: String,
    #[serde(default, deserialize_with = "present_string")]
    stage: Option<String>,
    #[serde(default, deserialize_with = "present_string")]
    error_kind: Option<String>,
    #[serde(default, deserialize_with = "present_errno")]
    errno: Option<Option<i32>>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Manifest {
    plan: FrozenPlan,
    interface: String,
    capture_complete: bool,
    capture_dropped: u64,
    capture_start_us: u64,
    capture_end_us: u64,
    windows: Windows,
    evidence: Vec<DirectEvidence>,
    pf: CounterEvidence,
    reports: Reports,
}
type Key = (String, String);
fn cases(cases: Vec<Case>) -> Result<BTreeMap<Key, (Flow, [u8; 16])>> {
    let mut out = BTreeMap::new();
    for c in cases {
        let protocol = match c.protocol.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => return Err(Error("invalid protocol")),
        };
        if !matches!(
            (
                c.family.as_str(),
                c.source.is_ipv6(),
                c.destination.is_ipv6()
            ),
            ("ipv4", false, false) | ("ipv6", true, true)
        ) {
            return Err(Error("invalid family"));
        }
        let raw = c.nonce.as_bytes();
        if raw.len() != 32
            || !raw
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return Err(Error("invalid nonce"));
        }
        let mut nonce = [0_u8; 16];
        for (i, pair) in raw.as_chunks::<2>().0.iter().enumerate() {
            let digit = |b: u8| {
                if b.is_ascii_digit() {
                    b - b'0'
                } else {
                    b - b'a' + 10
                }
            };
            nonce[i] = digit(pair[0]) * 16 + digit(pair[1]);
        }
        if nonce == [0; 16]
            || out
                .insert(
                    (c.family, c.protocol),
                    (
                        Flow {
                            source: c.source,
                            destination: c.destination,
                            protocol,
                        },
                        nonce,
                    ),
                )
                .is_some()
        {
            return Err(Error("duplicate case or zero nonce"));
        }
    }
    if out.len() != 4 {
        return Err(Error("four family/protocol cases required"));
    }
    Ok(out)
}
fn within(at: u64, window: &Window) -> bool {
    at >= window.start_us && at <= window.end_us
}
fn receiver_ack(report: &PeerReport, key: &Key, flow: Flow, nonce: [u8; 16]) -> Result<bool> {
    let digest = |s: &str| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    let label = |s: &str| {
        !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    };
    if report.role != "receiver"
        || report.pf_verdict != "not_evaluated"
        || !digest(&report.helper_sha256)
        || report.validator_sha256.as_ref().is_some_and(|s| !digest(s))
        || report.cases.len() != 4
    {
        return Err(Error("invalid peer receiver report"));
    }
    let mut all_completed = true;
    for item in &report.cases {
        match item.result.as_str() {
            "nonce_received_and_echoed"
                if item.stage.is_none() && item.error_kind.is_none() && item.errno.is_none() => {}
            "unavailable"
                if item.stage.as_ref().is_some_and(|s| label(s))
                    && item.error_kind.as_ref().is_some_and(|s| label(s)) =>
            {
                all_completed = false
            }
            _ => return Err(Error("invalid peer case result")),
        }
    }
    if report.status
        != if all_completed {
            "completed"
        } else {
            "incomplete"
        }
    {
        return Err(Error("peer report status inconsistent"));
    }
    let mut matches = report
        .cases
        .iter()
        .filter(|item| item.family == key.0 && item.protocol == key.1);
    let item = matches.next().ok_or(Error("missing peer case"))?;
    if matches.next().is_some()
        || item.source != flow.source
        || item.destination != flow.destination
        || item.nonce != nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    {
        return Err(Error("peer case does not match frozen plan"));
    }
    Ok(item.result == "nonce_received_and_echoed")
}
pub(crate) fn evaluate(manifest: Manifest, bytes: &[u8]) -> Result<Value> {
    let before = cases(manifest.plan.before.cases)?;
    let blocked = cases(manifest.plan.blocked.cases)?;
    let after = cases(manifest.plan.after.cases)?;
    let rule_flows = blocked
        .values()
        .map(|(flow, _)| RuleFlow {
            source: flow.source,
            destination: flow.destination,
        })
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| Error("four exact rule flows required"))?;
    let filter = ExactFilter::new(&manifest.pf.anchor_suffix, &manifest.interface, rule_flows)
        .map_err(|_| Error("invalid exact rule scope"))?;
    let deltas = if filter.matches_observed(manifest.pf.rules_before.as_bytes())
        && filter.matches_observed(manifest.pf.rules_after.as_bytes())
    {
        filter.outbound_deltas(
            manifest.pf.labels_before.as_bytes(),
            manifest.pf.labels_after.as_bytes(),
        )
    } else {
        None
    };
    let mut nonces = BTreeSet::new();
    let mut flows = BTreeSet::new();
    let mut evidence = BTreeMap::new();
    for item in manifest.evidence {
        let key = (item.family.clone(), item.protocol.clone());
        if evidence.insert(key, item).is_some() {
            return Err(Error("duplicate evidence"));
        }
    }
    if evidence.len() != 4 {
        return Err(Error("four direct evidence records required"));
    }
    let w = &manifest.windows;
    if manifest.capture_start_us >= manifest.capture_end_us
        || w.before.start_us < manifest.capture_start_us
        || w.before.start_us > w.before.end_us
        || w.before.end_us >= w.blocked.start_us
        || w.blocked.start_us > w.blocked.end_us
        || w.blocked.end_us >= w.after.start_us
        || w.after.start_us > w.after.end_us
        || w.after.end_us > manifest.capture_end_us
    {
        return Err(Error("invalid capture or phase windows"));
    }
    let packets = parse_pcap(bytes)?;
    if packets
        .iter()
        .any(|p| p.at_us < manifest.capture_start_us || p.at_us > manifest.capture_end_us)
    {
        return Err(Error("packet outside capture window"));
    }
    let mut results = Vec::new();
    let mut any_leak = false;
    let mut any_incomplete = false;
    for (index, (key, &(negative, negative_nonce))) in blocked.iter().enumerate() {
        let delta = deltas.map(|counts| counts[index]);
        let &(pre, pre_nonce) = before.get(key).ok_or(Error("missing before case"))?;
        let &(post, post_nonce) = after.get(key).ok_or(Error("missing after case"))?;
        let e = evidence.get(key).ok_or(Error("missing direct evidence"))?;
        let plan = Plan {
            case_id: u32::try_from(index + 1).map_err(|_| Error("case id"))?,
            interface: manifest.interface.clone(),
            before_control: pre,
            negative,
            after_control: post,
            application: Application::Probe,
        };
        plan.validate()?;
        for (flow, nonce) in [
            (pre, pre_nonce),
            (negative, negative_nonce),
            (post, post_nonce),
        ] {
            let tuple = (flow.source, flow.destination, key.1.clone());
            if !flows.insert(tuple) || !nonces.insert(nonce) {
                return Err(Error("reused flow or nonce"));
            }
        }
        // Any packet on the unique blocked tuple within the capture is a potential leak,
        // including a TCP SYN without application bytes or a nonce.
        let leaked = packets.iter().filter(|p| p.flow == negative).count();
        let pre_seen = packets.iter().any(|p| {
            p.flow == pre
                && within(p.at_us, &w.before)
                && p.payload.windows(16).any(|v| v == pre_nonce)
        });
        let post_seen = packets.iter().any(|p| {
            p.flow == post
                && within(p.at_us, &w.after)
                && p.payload.windows(16).any(|v| v == post_nonce)
        });
        let before_ack = receiver_ack(&manifest.reports.before, key, pre, pre_nonce)?;
        let after_ack = receiver_ack(&manifest.reports.after, key, post, post_nonce)?;
        let blocked_ack = receiver_ack(&manifest.reports.blocked, key, negative, negative_nonce)?;
        let complete = manifest.capture_complete
            && manifest.capture_dropped == 0
            && pre_seen
            && post_seen
            && before_ack
            && after_ack
            && e.sent
            && delta.is_some_and(|count| count > 0)
            && !blocked_ack;
        let verdict = if leaked > 0 {
            any_leak = true;
            "potential_leak"
        } else if complete {
            "no_observed_leak"
        } else {
            any_incomplete = true;
            "incomplete"
        };
        results.push(json!({"family":key.0,"protocol":key.1,"verdict":verdict,"matching_blocked_packets":leaked,"before_capture_nonce_seen":pre_seen,"after_capture_nonce_seen":post_seen,"before_receiver_ack":before_ack,"after_receiver_ack":after_ack,"blocked_receiver_ack":blocked_ack,"sent":e.sent,"pf_rule_hit_delta":delta}));
    }
    Ok(
        json!({"scope":"offline_unverified_input", "verdict":if any_leak {"potential_leak"} else if any_incomplete {"incomplete"} else {"no_observed_leak"}, "cases":results}),
    )
}
