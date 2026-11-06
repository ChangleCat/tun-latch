//! Offline PF filter candidates for a configuration without trusted egress authorization.
//!
//! This is deliberately not the executable PF plan boundary. Every enabled candidate is marked
//! [`PfCandidateStatus::BlockedNotReady`]: it has no trusted TUN binding, administrator-approved
//! direct exception, execution-position proof, state convergence, or recovery authority. Ordinary
//! `allow` rules reach a closed egress floor and therefore render as attributed blocks. The only
//! passes are fixed outbound loopback rules, with no state creation. Nothing here opens PF,
//! executes a program, changes interfaces, or certifies that PF would enforce the candidate.

use std::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;
use tunlatch_core::config::DesiredProtection;
use tunlatch_core::policy::{
    ConfigV2, Destination, PolicyDigest, PortRange, Protocol, Rule, RuleAction,
};

/// Maximum literal rules after address-family and source/destination port-range expansion.
pub const MAX_CANDIDATE_RULES: usize = 4_100;
/// Maximum UTF-8 bytes in the complete rendered candidate, including its fixed explanation.
pub const MAX_CANDIDATE_BYTES: usize = 1_048_576;

/// Offline intent only; neither state claims installed or effective protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PfCandidateStatus {
    /// The candidate renders outbound blocks; installed rules, existing states and protection remain unknown.
    BlockedNotReady,
    /// Disabled intent produces no managed rules and no disable, flush, or cleanup operation.
    Unmanaged,
}

/// Domain-separated SHA-256 identity of this compiler version, source policy, and candidate bytes.
///
/// This content identity is not an approval token, resource-ownership proof, or PF receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PfCandidateDigest([u8; 32]);

impl PfCandidateDigest {
    /// Return the 32 digest bytes without creating an authorization capability.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PfCandidateDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Non-executable preview data. Its private representation has no conversion to PF authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PfCompileCandidate {
    status: PfCandidateStatus,
    source_digest: PolicyDigest,
    digest: PfCandidateDigest,
    rules_text: String,
    rule_count: usize,
}

impl PfCompileCandidate {
    /// Return whether the preview is an unready blocking candidate or unmanaged intent.
    pub fn status(&self) -> PfCandidateStatus {
        self.status
    }
    /// Return the canonical source policy's content identity, never its approval.
    pub fn source_digest(&self) -> PolicyDigest {
        self.source_digest
    }
    /// Return the complete candidate's stable content identity.
    pub fn digest(&self) -> PfCandidateDigest {
        self.digest
    }
    /// Return bounded filter text for inspection only; no loader consumes this type.
    pub fn rules_text(&self) -> &str {
        &self.rules_text
    }
    /// Return the number of literal filter rules, excluding comments.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }
}

/// Selector that cannot be represented faithfully by this conservative PF candidate renderer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedIcmpField {
    /// ICMP type 255 is not emitted because of legacy PF wildcard/+1 representation ambiguity.
    Type,
    /// ICMP code 255 is not emitted because of legacy PF wildcard/+1 representation ambiguity.
    Code,
}

/// Explicit compile rejection; unsupported input never silently loses a condition.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum PfCompileError {
    /// Candidate direct exceptions do not carry the separate administrator enforcement authority.
    #[error("{count} direct exception candidate(s) lack executable authorization")]
    UnsupportedDirectExceptions {
        /// Number of exception candidates that were refused as a group.
        count: usize,
    },
    /// A numerical ICMP selector is outside this renderer's faithfully supported subset.
    #[error("unsupported ICMP {field:?} selector on rule {rule_id}")]
    UnsupportedIcmpSelector {
        /// Core-validated ASCII identifier of the rejected rule.
        rule_id: String,
        /// The condition that cannot be preserved.
        field: UnsupportedIcmpField,
    },
    /// A fixed output resource bound was reached before adding another literal rule.
    #[error("PF candidate exceeds its fixed rule or byte limit")]
    CandidateTooLarge,
}

/// Compile a validated v2 policy into deterministic, bounded, offline filter preview data.
///
/// Ordinary rules keep the core's `(priority, block-first, ASCII ID)` order and their exact
/// destination, protocol, port and supported ICMP conditions. Each match is `quick`; an ordinary
/// allow is still a block at this unready egress floor. Source/destination interval combinations
/// are expanded explicitly, using inclusive PF ranges, without hostname or service resolution.
///
/// Disabled intent returns an empty unmanaged candidate, regardless of dormant rule content.
/// Enabled direct-exception candidates and unsupported ICMP fields are explicit errors. This
/// function neither accepts interface names/indices nor manufactures enforcement authorization.
pub fn compile_candidate(config: &ConfigV2) -> Result<PfCompileCandidate, PfCompileError> {
    let source_digest = config.digest();
    if config.desired() == DesiredProtection::Disabled {
        return Ok(candidate(
            PfCandidateStatus::Unmanaged,
            source_digest,
            String::new(),
            0,
        ));
    }
    if !config.direct_exceptions().is_empty() {
        return Err(PfCompileError::UnsupportedDirectExceptions {
            count: config.direct_exceptions().len(),
        });
    }
    let mut renderer = Renderer {
        text: "# TunLatch offline candidate: BLOCKED_NOT_READY; NOT AN EXECUTABLE PLAN\n\
               # No trusted egress authorization; ordinary allow selectors render as blocks.\n\
               # No state convergence, PF execution-position proof, or recovery is established.\n"
            .into(),
        rule_count: 0,
    };
    renderer.push(
        "pass out quick on lo0 inet all no state allow-opts label \"tl.loopback.v4\"".into(),
    )?;
    renderer.push(
        "pass out quick on lo0 inet6 all no state allow-opts label \"tl.loopback.v6\"".into(),
    )?;
    for rule in config.rules() {
        renderer.rule(rule)?;
    }
    renderer.push("block drop out quick inet all label \"tl.default.v4\"".into())?;
    renderer.push("block drop out quick inet6 all label \"tl.default.v6\"".into())?;
    Ok(candidate(
        PfCandidateStatus::BlockedNotReady,
        source_digest,
        renderer.text,
        renderer.rule_count,
    ))
}

fn candidate(
    status: PfCandidateStatus,
    source_digest: PolicyDigest,
    rules_text: String,
    rule_count: usize,
) -> PfCompileCandidate {
    let mut hasher = Sha256::new();
    hasher.update(b"tunlatch-pf-offline-candidate-v1\0");
    hasher.update([match status {
        PfCandidateStatus::BlockedNotReady => 1,
        PfCandidateStatus::Unmanaged => 0,
    }]);
    hasher.update(source_digest.as_bytes());
    hasher.update(rules_text.as_bytes());
    PfCompileCandidate {
        status,
        source_digest,
        digest: PfCandidateDigest(hasher.finalize().into()),
        rules_text,
        rule_count,
    }
}

struct Renderer {
    text: String,
    rule_count: usize,
}

impl Renderer {
    fn push(&mut self, line: String) -> Result<(), PfCompileError> {
        if self.rule_count >= MAX_CANDIDATE_RULES
            || line.len() >= MAX_CANDIDATE_BYTES
            || self.text.len() > MAX_CANDIDATE_BYTES - line.len() - 1
        {
            return Err(PfCompileError::CandidateTooLarge);
        }
        self.text.push_str(&line);
        self.text.push('\n');
        self.rule_count += 1;
        Ok(())
    }

    fn rule(&mut self, rule: &Rule) -> Result<(), PfCompileError> {
        // The reviewed Apple source cache in W01 has u_int8_t rule type/code fields and
        // matches nonzero fields against (packet value + 1). Reject 255 rather than risk
        // wrapping it to the wildcard representation; there is no local PF execution here.
        for (field, value) in [
            (UnsupportedIcmpField::Type, rule.icmp_type()),
            (UnsupportedIcmpField::Code, rule.icmp_code()),
        ] {
            if value == Some(u8::MAX) {
                return Err(PfCompileError::UnsupportedIcmpSelector {
                    rule_id: rule.id().as_str().into(),
                    field,
                });
            }
        }
        // The complete validated policy bounds each list to four normalized intervals. None
        // expands once without a port restriction; Some expands once for every explicit range.
        let source_count = rule.source_ports().map_or(1, <[PortRange]>::len);
        let destination_count = rule.destination_ports().map_or(1, <[PortRange]>::len);
        for family in [Family::V4, Family::V6] {
            if !family.matches(rule.destination()) {
                continue;
            }
            for source_index in 0..source_count {
                for destination_index in 0..destination_count {
                    let source = rule
                        .source_ports()
                        .and_then(|ports| ports.get(source_index));
                    let destination = rule
                        .destination_ports()
                        .and_then(|ports| ports.get(destination_index));
                    self.push(render_rule(
                        rule,
                        family,
                        source,
                        destination,
                        source_index,
                        destination_index,
                    ))?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn matches(self, destination: &Destination) -> bool {
        match destination {
            Destination::Any => true,
            Destination::Network(network) => network.addr().is_ipv4() == matches!(self, Self::V4),
        }
    }

    fn keyword(self) -> &'static str {
        match self {
            Self::V4 => "inet",
            Self::V6 => "inet6",
        }
    }

    fn suffix(self) -> char {
        match self {
            Self::V4 => '4',
            Self::V6 => '6',
        }
    }
}

fn render_rule(
    rule: &Rule,
    family: Family,
    source_port: Option<&PortRange>,
    destination_port: Option<&PortRange>,
    source_index: usize,
    destination_index: usize,
) -> String {
    let mut line = format!("block drop out quick {}", family.keyword());
    line.push_str(match rule.protocol() {
        Protocol::Any => "",
        Protocol::Tcp => " proto tcp",
        Protocol::Udp => " proto udp",
        Protocol::Icmp => " proto icmp",
        Protocol::Icmpv6 => " proto icmp6",
    });
    line.push_str(" from any");
    render_port(&mut line, source_port);
    line.push_str(" to ");
    match rule.destination() {
        Destination::Any => line.push_str("any"),
        Destination::Network(network) => line.push_str(&network.to_string()),
    }
    render_port(&mut line, destination_port);
    if let Some(icmp_type) = rule.icmp_type() {
        let keyword = if rule.protocol() == Protocol::Icmpv6 {
            "icmp6-type"
        } else {
            "icmp-type"
        };
        line.push_str(&format!(" {keyword} {icmp_type}"));
        if let Some(icmp_code) = rule.icmp_code() {
            line.push_str(&format!(" code {icmp_code}"));
        }
    }
    let action = match rule.action() {
        RuleAction::Block => 'b',
        RuleAction::Allow => 'a',
    };
    // IDs are bounded lowercase ASCII; no arbitrary text, quotes, macros or escape sequences
    // enter the label. These labels identify source selectors, not installed rule ownership.
    line.push_str(&format!(
        " label \"tl.r.{}.{action}{}.{}.{}\"",
        rule.id().as_str(),
        family.suffix(),
        source_index,
        destination_index,
    ));
    line
}

fn render_port(output: &mut String, port: Option<&PortRange>) {
    if let Some(port) = port {
        if port.start() == port.end() {
            output.push_str(&format!(" port = {}", port.start()));
        } else {
            output.push_str(&format!(" port {}:{}", port.start(), port.end()));
        }
    }
}
