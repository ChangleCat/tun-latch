//! Strict version-two policy drafts. Parsing never authorizes exceptions or changes protection.
//!
//! Use the bounded byte parsers for untrusted file and IPC input. `Deserialize` validates the
//! represented schema, quantities and canonical size, but a Serde deserializer cannot reveal the
//! original encoding or whitespace byte count; its caller must enforce the transport's raw limit.
//! Ordinary `allow` results still require independently established egress authorization. Neither
//! these drafts nor their hashes are capabilities or evidence of kernel enforcement.

mod decode;
mod model;
mod validate;

use std::fmt;
use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::config::DesiredProtection;

pub use model::{OrdinaryDecision, PacketDescriptor, PacketProtocol};

/// Required version of the expanded policy format; the original v1 config remains separate.
pub const POLICY_VERSION: u16 = 2;
/// Maximum original UTF-8 TOML or JSON input, including whitespace and comments.
pub const MAX_POLICY_INPUT_BYTES: usize = 65_536;
/// Maximum compact canonical JSON, leaving room inside the existing IPC frame budget.
pub const MAX_CANONICAL_POLICY_BYTES: usize = 49_152;
/// Maximum ordinary rules before normalization.
pub const MAX_RULES: usize = 128;
/// Maximum candidate direct exceptions; none are implicitly approved.
pub const MAX_DIRECT_EXCEPTIONS: usize = 32;
/// Maximum intervals in each source or destination port list before merging.
pub const MAX_PORT_RANGES: usize = 4;

/// Stable, matchable rejection reason. Runtime authorization and PF failures are separate types.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyErrorCode {
    /// Original serialized input exceeded its byte bound.
    #[error("InputTooLarge")]
    InputTooLarge,
    /// Input is not valid UTF-8, including unpaired JSON Unicode surrogates.
    #[error("InvalidEncoding")]
    InvalidEncoding,
    /// Malformed text, duplicate object keys or excessive nesting.
    #[error("InvalidSyntax")]
    InvalidSyntax,
    /// A mandatory field was omitted.
    #[error("MissingField")]
    MissingField,
    /// A field outside the closed schema was provided.
    #[error("UnknownField")]
    UnknownField,
    /// A scalar or collection has the wrong type.
    #[error("InvalidType")]
    InvalidType,
    /// A future or unsupported schema version was supplied.
    #[error("UnsupportedVersion")]
    UnsupportedVersion,
    /// A valid v1 draft needs an explicit offline migration operation.
    #[error("MigrationRequired")]
    MigrationRequired,
    /// An enum or integer lies outside the allowed values.
    #[error("InvalidValue")]
    InvalidValue,
    /// Identifier is not lowercase ASCII with the required length and syntax.
    #[error("InvalidId")]
    InvalidId,
    /// Description is empty, over its UTF-8 bound or contains control characters.
    #[error("InvalidDescription")]
    InvalidDescription,
    /// Rule and exception IDs share one namespace and must be unique.
    #[error("DuplicateId")]
    DuplicateId,
    /// Destination syntax, scope or mapped representation is unsupported.
    #[error("InvalidDestination")]
    InvalidDestination,
    /// A network has host bits set and cannot be silently widened.
    #[error("NonCanonicalNetwork")]
    NonCanonicalNetwork,
    /// Port or ICMP fields do not match the selected protocol or purpose.
    #[error("InvalidProtocolFields")]
    InvalidProtocolFields,
    /// ICMP protocol does not match the destination address family.
    #[error("AddressFamilyMismatch")]
    AddressFamilyMismatch,
    /// A port list is empty or its interval is reversed.
    #[error("InvalidPortRange")]
    InvalidPortRange,
    /// An input collection exceeded its pre-normalization item bound.
    #[error("TooManyItems")]
    TooManyItems,
    /// The validated configuration cannot fit the canonical JSON budget.
    #[error("CanonicalConfigTooLarge")]
    CanonicalConfigTooLarge,
}

/// Typed input error that reports location and limits without reproducing the full configuration.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("{code} at {path}")]
pub struct PolicyError {
    code: PolicyErrorCode,
    path: String,
    limit: Option<usize>,
    actual: Option<usize>,
}

impl PolicyError {
    fn new(code: PolicyErrorCode, path: impl Into<String>) -> Self {
        Self {
            code,
            path: diagnostic_path(path.into()),
            limit: None,
            actual: None,
        }
    }

    fn bounded(
        code: PolicyErrorCode,
        path: impl Into<String>,
        limit: usize,
        actual: usize,
    ) -> Self {
        Self {
            code,
            path: diagnostic_path(path.into()),
            limit: Some(limit),
            actual: Some(actual),
        }
    }

    /// Return the stable reason without parsing diagnostic text.
    pub fn code(&self) -> PolicyErrorCode {
        self.code
    }
    /// Return a bounded field path or duplicate ID. Hostile field names are truncated and control
    /// characters replaced, preventing input-controlled terminal sequences or unbounded errors.
    pub fn path(&self) -> &str {
        &self.path
    }
    /// Return a size/count bound when the failure has one.
    pub fn limit(&self) -> Option<usize> {
        self.limit
    }
    /// Return the observed size/count when the failure has one.
    pub fn actual(&self) -> Option<usize> {
        self.actual
    }
}

fn diagnostic_path(path: String) -> String {
    let mut output = String::new();
    for character in path.chars() {
        let character = if character.is_control() {
            '?'
        } else {
            character
        };
        if output.len() + character.len_utf8() > 252 {
            output.push_str("...");
            break;
        }
        output.push(character);
    }
    output
}

/// Validated lowercase ASCII identifier. Parsing a config is its construction boundary.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PolicyId(String);

impl PolicyId {
    /// Return the stable identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One normalized inclusive transport port interval; zero is an ordinary numerical port.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PortRange {
    end: u16,
    start: u16,
}

impl PortRange {
    /// Lowest matching port, inclusive.
    pub fn start(&self) -> u16 {
        self.start
    }
    /// Highest matching port, inclusive.
    pub fn end(&self) -> u16 {
        self.end
    }
    fn contains(&self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
}

/// An explicit IP prefix or the ordinary-rule-only dual-stack wildcard.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Destination {
    /// Both address families; still subject to the egress floor.
    Any,
    /// A canonical network; host literals normalize to /32 or /128.
    Network(IpNet),
}

impl Serialize for Destination {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Any => serializer.serialize_str("any"),
            Self::Network(network) => serializer.collect_str(network),
        }
    }
}

impl Destination {
    /// Return whether this destination contains the address, with no cross-family matching.
    pub fn contains(&self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Network(network) => network.contains(&address),
        }
    }
}

/// Closed filtering protocol set. QUIC is matched as UDP, never inferred from process identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Every identifiable IP protocol; not malformed or incomplete packet data.
    Any,
    /// TCP with optional transport port restrictions.
    Tcp,
    /// UDP with optional transport port restrictions.
    Udp,
    /// IPv4 ICMP with optional numerical type/code restrictions.
    Icmp,
    /// IPv6 ICMP with optional numerical type/code restrictions.
    Icmpv6,
}

/// Ordinary action. Allow always remains conditional on independently authorized egress.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Deny even if an otherwise matching direct exception exists.
    Block,
    /// Continue to the egress authorization boundary, never directly permit traffic.
    Allow,
}

/// Normalized ordinary rule, constructed only through complete policy validation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Rule {
    action: RuleAction,
    destination: Destination,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_ports: Option<Vec<PortRange>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icmp_code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icmp_type: Option<u8>,
    id: PolicyId,
    priority: u16,
    protocol: Protocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ports: Option<Vec<PortRange>>,
}

impl Rule {
    /// Stable identity used for deterministic attribution, not a kernel counter value.
    pub fn id(&self) -> &PolicyId {
        &self.id
    }
    /// Lower numbers are evaluated first.
    pub fn priority(&self) -> u16 {
        self.priority
    }
    /// Ordinary action, which cannot authorize physical egress.
    pub fn action(&self) -> RuleAction {
        self.action
    }
    /// Validated destination selector.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }
    /// Validated protocol selector.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    /// Normalized source port restrictions, or no restriction.
    pub fn source_ports(&self) -> Option<&[PortRange]> {
        self.source_ports.as_deref()
    }
    /// Normalized destination port restrictions, or no restriction.
    pub fn destination_ports(&self) -> Option<&[PortRange]> {
        self.destination_ports.as_deref()
    }
    /// Numerical ICMP type restriction, if present.
    pub fn icmp_type(&self) -> Option<u8> {
        self.icmp_type
    }
    /// Numerical ICMP code restriction, if present.
    pub fn icmp_code(&self) -> Option<u8> {
        self.icmp_code
    }
    fn sort_key(&self) -> (u16, u8, &str) {
        (
            self.priority,
            if self.action == RuleAction::Block {
                0
            } else {
                1
            },
            self.id.as_str(),
        )
    }
}

/// Purpose of a candidate exception; neither value grants authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionPurpose {
    /// A specific remote proxy endpoint with explicit transport destination ports.
    ProxyUpstream,
    /// Explicitly scoped network bootstrap conditions, pending a separate policy decision.
    NetworkBootstrap,
}

/// Candidate exception data. It cannot represent an approval, trusted link or live authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DirectException {
    description: String,
    destination: Destination,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination_ports: Option<Vec<PortRange>>,
    egress_profile: PolicyId,
    #[serde(skip_serializing_if = "Option::is_none")]
    icmp_code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    icmp_type: Option<u8>,
    id: PolicyId,
    protocol: Protocol,
    purpose: ExceptionPurpose,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ports: Option<Vec<PortRange>>,
}

impl DirectException {
    /// Candidate identity; reusing it does not preserve approval after content changes.
    pub fn id(&self) -> &PolicyId {
        &self.id
    }
    /// Human-readable context, bounded in UTF-8 bytes and included in the content digest.
    pub fn description(&self) -> &str {
        &self.description
    }
    /// Symbolic reference only; its protected physical-link record must be resolved separately.
    pub fn egress_profile(&self) -> &PolicyId {
        &self.egress_profile
    }
    /// Candidate purpose, with no implied approval.
    pub fn purpose(&self) -> ExceptionPurpose {
        self.purpose
    }
    /// Candidate destination restriction.
    pub fn destination(&self) -> &Destination {
        &self.destination
    }
    /// Candidate protocol restriction.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }
    /// Candidate source port restriction.
    pub fn source_ports(&self) -> Option<&[PortRange]> {
        self.source_ports.as_deref()
    }
    /// Candidate destination port restriction.
    pub fn destination_ports(&self) -> Option<&[PortRange]> {
        self.destination_ports.as_deref()
    }
    /// Explicit ICMP type for bootstrap candidates, if applicable.
    pub fn icmp_type(&self) -> Option<u8> {
        self.icmp_type
    }
    /// Explicit ICMP code for bootstrap candidates, if applicable.
    pub fn icmp_code(&self) -> Option<u8> {
        self.icmp_code
    }
    /// Hash of normalized candidate content, including description; never an approval token.
    pub fn digest(&self) -> Result<PolicyDigest, PolicyError> {
        canonical(self).map(|bytes| digest(b"tunlatch-exception-v2\0", &bytes))
    }
}

/// A domain-separated SHA-256 content identity; not an authorization credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDigest([u8; 32]);

impl PolicyDigest {
    /// Return the underlying content digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PolicyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Complete normalized v2 draft. No default, public fields or deserialization bypass exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ConfigV2 {
    desired: DesiredProtection,
    direct_exceptions: Vec<DirectException>,
    rules: Vec<Rule>,
    schema_version: u16,
    #[serde(skip)]
    canonical_json: Vec<u8>,
}

impl<'de> Deserialize<'de> for ConfigV2 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = decode::deserialize_value(deserializer)?;
        validate::config(value, false).map_err(serde::de::Error::custom)
    }
}

impl ConfigV2 {
    /// Parse a complete bounded UTF-8 TOML draft. v1 requires explicit migration.
    pub fn parse_toml(input: &[u8]) -> Result<Self, PolicyError> {
        validate::config(decode::toml(input)?, false)
    }
    /// Parse bounded strict JSON, rejecting duplicate keys and non-finite numbers.
    pub fn parse_json(input: &[u8]) -> Result<Self, PolicyError> {
        validate::config(decode::json(input)?, false)
    }
    /// Explicitly migrate a valid legacy TOML draft in memory; no file or protection is changed.
    pub fn migrate_v1_toml(input: &[u8]) -> Result<Self, PolicyError> {
        validate::config(decode::toml(input)?, true)
    }
    /// Explicitly migrate a valid legacy JSON draft in memory; v2 and unknown versions reject.
    pub fn migrate_v1_json(input: &[u8]) -> Result<Self, PolicyError> {
        validate::config(decode::json(input)?, true)
    }
    /// User intent only; enabled is never evidence of applied protection.
    pub fn desired(&self) -> DesiredProtection {
        self.desired
    }
    /// Ordinary rules in (priority, block-first, ASCII ID) order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
    /// Candidate exceptions in ASCII ID order, without any approval capability.
    pub fn direct_exceptions(&self) -> &[DirectException] {
        &self.direct_exceptions
    }
    /// Exact canonical compact UTF-8 JSON within the reserved budget.
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }
    /// Export an inline-table TOML draft with the same raw byte bound, without writing any file.
    /// Unlike a generic pretty serializer, inline tables avoid exceeding the input bound merely
    /// from expanding each port range into a separate table near the canonical-size limit.
    pub fn to_toml(&self) -> Result<String, PolicyError> {
        let value = serde_json::to_value(self)
            .map_err(|_| PolicyError::new(PolicyErrorCode::InvalidSyntax, "config"))?;
        let Some(fields) = value.as_object() else {
            return Err(PolicyError::new(PolicyErrorCode::InvalidType, "config"));
        };
        let mut output = String::new();
        for (key, value) in fields {
            output.push_str(key);
            output.push('=');
            value
                .serialize(toml::ser::ValueSerializer::new(&mut output))
                .map_err(|_| PolicyError::new(PolicyErrorCode::InvalidSyntax, "config"))?;
            output.push('\n');
        }
        if output.len() > MAX_POLICY_INPUT_BYTES {
            return Err(PolicyError::bounded(
                PolicyErrorCode::InputTooLarge,
                "config",
                MAX_POLICY_INPUT_BYTES,
                output.len(),
            ));
        }
        Ok(output)
    }
    /// Domain-separated identity of the validated normalized draft.
    pub fn digest(&self) -> PolicyDigest {
        digest(b"tunlatch-config-v2\0", &self.canonical_json)
    }
}

fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, PolicyError> {
    // All serialized struct fields are declared in ASCII key order, recursively. There are no
    // user-keyed maps or floating-point fields; a regression test fixes the cross-language bytes.
    serde_json::to_vec(value)
        .map_err(|_| PolicyError::new(PolicyErrorCode::InvalidSyntax, "config"))
}

fn digest(domain: &[u8], content: &[u8]) -> PolicyDigest {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(content);
    PolicyDigest(hasher.finalize().into())
}
