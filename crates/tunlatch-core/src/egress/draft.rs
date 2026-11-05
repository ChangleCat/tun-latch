use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::policy::{self, ConfigV2, PolicyDigest, PolicyError, PolicyErrorCode, PolicyId};

/// Raw authorization JSON/TOML limit, including whitespace and comments.
pub const MAX_AUTHORIZATION_INPUT_BYTES: usize = 8192;
/// Canonical authorization object limit, inside the existing IPC envelope budget.
pub const MAX_AUTHORIZATION_BYTES: usize = 4096;

/// An explicitly selected IP family; this is not evidence of platform support.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressFamily {
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
}

/// Only local TCP/UDP sockets can be candidates for UID-based egress.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// TCP, with no application identity implied.
    Tcp,
    /// UDP, including QUIC without inspecting encrypted payloads.
    Udp,
}

/// Closed maintenance selections. Their actual packet predicates need separate verification.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemRecipe {
    /// Current-client DHCPv4 conditions.
    Dhcpv4Client,
    /// Conditional DHCPv6 client multicast, never a generic UDP exception.
    Dhcpv6Client,
    /// Host ND/DAD and the necessary restricted MLD conditions.
    Ipv6HostControl,
    /// Precisely related errors of currently authorized flows, never generic ICMP.
    RelatedIcmpErrors,
}

/// Validated candidate data. A UID number and a content hash are not approval credentials.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProxyUidGrant {
    egress_profile: PolicyId,
    families: Vec<AddressFamily>,
    id: PolicyId,
    protocols: Vec<Transport>,
    uid: u32,
}

impl ProxyUidGrant {
    /// Stable candidate identifier.
    pub fn id(&self) -> &PolicyId {
        &self.id
    }
    /// Numeric socket-creation UID; the unknown sentinel is never represented here.
    pub fn uid(&self) -> u32 {
        self.uid
    }
    /// Approved-scope candidate reference, never an interface name.
    pub fn egress_profile(&self) -> &PolicyId {
        &self.egress_profile
    }
    /// Normalized family selection.
    pub fn families(&self) -> &[AddressFamily] {
        &self.families
    }
    /// Normalized TCP/UDP selection.
    pub fn protocols(&self) -> &[Transport] {
        &self.protocols
    }
    /// Identity of every candidate field, without approval or OS authority.
    pub fn digest(&self) -> Result<PolicyDigest, PolicyError> {
        bytes(self).map(|b| policy::digest(b"tunlatch-proxy-uid-grant\0", &b))
    }
}

/// Maintenance candidate. Merely selecting a recipe cannot authorize any packet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SystemProfile {
    egress_profile: PolicyId,
    families: Vec<AddressFamily>,
    id: PolicyId,
    recipes: Vec<SystemRecipe>,
}

impl SystemProfile {
    /// Stable candidate identifier.
    pub fn id(&self) -> &PolicyId {
        &self.id
    }
    /// Candidate physical scope reference.
    pub fn egress_profile(&self) -> &PolicyId {
        &self.egress_profile
    }
    /// Selected address families.
    pub fn families(&self) -> &[AddressFamily] {
        &self.families
    }
    /// Selected, independently qualified maintenance predicates.
    pub fn recipes(&self) -> &[SystemRecipe] {
        &self.recipes
    }
    /// Identity of all maintenance candidate fields, without approving them.
    pub fn digest(&self) -> Result<PolicyDigest, PolicyError> {
        bytes(self).map(|b| policy::digest(b"tunlatch-system-profile\0", &b))
    }
}

/// Strict authorization draft with no implicit grants or version/migration fields.
///
/// Byte parsers enforce the original 8 KiB input. Direct Serde can validate represented data,
/// not raw whitespace/encoding length; callers still need a bounded transport.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Authorizations {
    proxy_uid_grants: Vec<ProxyUidGrant>,
    system_profiles: Vec<SystemProfile>,
    #[serde(skip)]
    canonical: Vec<u8>,
}

impl<'de> Deserialize<'de> for Authorizations {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = policy::decode::deserialize_with_limit(
            deserializer,
            MAX_AUTHORIZATION_INPUT_BYTES,
            "authorizations",
        )?;
        validate(&value).map_err(serde::de::Error::custom)
    }
}

impl Authorizations {
    /// An explicit empty draft, not an input default and never permission to disable protection.
    pub fn empty() -> Self {
        Self {
            proxy_uid_grants: Vec::new(),
            system_profiles: Vec::new(),
            canonical: b"{\"proxy_uid_grants\":[],\"system_profiles\":[]}".to_vec(),
        }
    }
    /// Decode bounded UTF-8 JSON, rejecting duplicate keys and extra data.
    pub fn parse_json(input: &[u8]) -> Result<Self, PolicyError> {
        validate(&policy::decode::json_with_limit(
            input,
            MAX_AUTHORIZATION_INPUT_BYTES,
            "authorizations",
        )?)
    }
    /// Decode bounded TOML through the same represented-data validator.
    pub fn parse_toml(input: &[u8]) -> Result<Self, PolicyError> {
        validate(&policy::decode::toml_with_limit(
            input,
            MAX_AUTHORIZATION_INPUT_BYTES,
            "authorizations",
        )?)
    }
    /// Normalized candidates, sorted by stable ID.
    pub fn proxy_uid_grants(&self) -> &[ProxyUidGrant] {
        &self.proxy_uid_grants
    }
    /// Normalized maintenance candidates, not packet permissions.
    pub fn system_profiles(&self) -> &[SystemProfile] {
        &self.system_profiles
    }
    /// Canonical compact UTF-8 bytes. Input order is immaterial.
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical
    }
    /// Domain-separated content identity for this exact draft.
    pub fn digest(&self) -> PolicyDigest {
        policy::digest(b"tunlatch-egress-authorizations\0", &self.canonical)
    }
    /// Export a bounded TOML draft, without side effects or stored approval records.
    pub fn to_toml(&self) -> Result<String, PolicyError> {
        let output = toml::to_string(self)
            .map_err(|_| err(PolicyErrorCode::InvalidSyntax, "authorizations"))?;
        if output.len() > MAX_AUTHORIZATION_INPUT_BYTES {
            return Err(PolicyError::bounded(
                PolicyErrorCode::InputTooLarge,
                "authorizations",
                MAX_AUTHORIZATION_INPUT_BYTES,
                output.len(),
            ));
        }
        Ok(output)
    }
}

/// Immutable composition of ordinary configuration and authorization candidates, not approval.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EgressPolicyDraft {
    config: ConfigV2,
    authorizations: Authorizations,
}

impl EgressPolicyDraft {
    /// Validate the shared ID namespace and maximum four distinct physical scope references.
    pub fn new(config: ConfigV2, authorizations: Authorizations) -> Result<Self, PolicyError> {
        let mut ids = BTreeSet::new();
        for id in config
            .rules()
            .iter()
            .map(|x| x.id())
            .chain(config.direct_exceptions().iter().map(|x| x.id()))
            .chain(authorizations.proxy_uid_grants.iter().map(|x| x.id()))
            .chain(authorizations.system_profiles.iter().map(|x| x.id()))
        {
            if !ids.insert(id.as_str()) {
                return Err(err(PolicyErrorCode::DuplicateId, "policy.id"));
            }
        }
        let result = Self {
            config,
            authorizations,
        };
        if result.profile_ids().len() > 4 {
            return Err(err(PolicyErrorCode::TooManyItems, "policy.egress_profiles"));
        }
        Ok(result)
    }
    /// Borrow unchanged ordinary filtering and target-candidate data.
    pub fn config(&self) -> &ConfigV2 {
        &self.config
    }
    /// Borrow normalized authorization candidates.
    pub fn authorizations(&self) -> &Authorizations {
        &self.authorizations
    }
    pub(super) fn profile_ids(&self) -> BTreeSet<&str> {
        self.config
            .direct_exceptions()
            .iter()
            .map(|x| x.egress_profile().as_str())
            .chain(
                self.authorizations
                    .proxy_uid_grants
                    .iter()
                    .map(|x| x.egress_profile.as_str()),
            )
            .chain(
                self.authorizations
                    .system_profiles
                    .iter()
                    .map(|x| x.egress_profile.as_str()),
            )
            .collect()
    }
}

fn err(code: PolicyErrorCode, path: &str) -> PolicyError {
    PolicyError::new(code, path)
}
pub(super) fn bytes(value: &impl Serialize) -> Result<Vec<u8>, PolicyError> {
    serde_json::to_vec(value).map_err(|_| err(PolicyErrorCode::InvalidSyntax, "authorizations"))
}
fn object<'a>(
    value: &'a Value,
    fields: &[&str],
    path: &str,
) -> Result<&'a Map<String, Value>, PolicyError> {
    let map = value
        .as_object()
        .ok_or_else(|| err(PolicyErrorCode::InvalidType, path))?;
    if map.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err(err(
            PolicyErrorCode::UnknownField,
            &format!("{path}.<unknown>"),
        ));
    }
    for field in fields {
        if !map.contains_key(*field) {
            return Err(err(
                PolicyErrorCode::MissingField,
                &format!("{path}.{field}"),
            ));
        }
    }
    Ok(map)
}
fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Value, PolicyError> {
    map.get(key)
        .ok_or_else(|| err(PolicyErrorCode::MissingField, key))
}
fn array<'a>(value: &'a Value, max: usize, path: &str) -> Result<&'a [Value], PolicyError> {
    let values = value
        .as_array()
        .ok_or_else(|| err(PolicyErrorCode::InvalidType, path))?;
    if values.len() > max {
        return Err(PolicyError::bounded(
            PolicyErrorCode::TooManyItems,
            path,
            max,
            values.len(),
        ));
    }
    Ok(values)
}
fn selection<T>(value: &Value, choices: &[(&str, T)], path: &str) -> Result<Vec<T>, PolicyError>
where
    T: Copy + Ord,
{
    let values = value
        .as_array()
        .ok_or_else(|| err(PolicyErrorCode::InvalidSelection, path))?;
    if values.is_empty() || values.len() > choices.len() {
        return Err(err(PolicyErrorCode::InvalidSelection, path));
    }
    let mut result = BTreeSet::new();
    for value in values {
        let selected = choices
            .iter()
            .find(|(name, _)| value.as_str() == Some(*name))
            .map(|(_, value)| *value)
            .ok_or_else(|| err(PolicyErrorCode::InvalidSelection, path))?;
        if !result.insert(selected) {
            return Err(err(PolicyErrorCode::InvalidSelection, path));
        }
    }
    Ok(result.into_iter().collect())
}
fn families(value: &Value, path: &str) -> Result<Vec<AddressFamily>, PolicyError> {
    selection(
        value,
        &[("ipv4", AddressFamily::Ipv4), ("ipv6", AddressFamily::Ipv6)],
        path,
    )
}
fn validate(value: &Value) -> Result<Authorizations, PolicyError> {
    let map = object(
        value,
        &["proxy_uid_grants", "system_profiles"],
        "authorizations",
    )?;
    let mut ids = BTreeSet::new();
    let mut grants = Vec::new();
    for (index, value) in array(
        field(map, "proxy_uid_grants")?,
        4,
        "authorizations.proxy_uid_grants",
    )?
    .iter()
    .enumerate()
    {
        let path = format!("authorizations.proxy_uid_grants[{index}]");
        let fields = object(
            value,
            &["id", "uid", "protocols", "families", "egress_profile"],
            &path,
        )?;
        let id = PolicyId::from_value(field(fields, "id")?, &format!("{path}.id"))?;
        if !ids.insert(id.clone()) {
            return Err(err(PolicyErrorCode::DuplicateId, "authorizations.id"));
        }
        let uid_value = field(fields, "uid")?;
        if !uid_value.is_i64() && !uid_value.is_u64() {
            return Err(err(PolicyErrorCode::InvalidType, &format!("{path}.uid")));
        }
        let uid = uid_value
            .as_u64()
            .filter(|v| *v < u64::from(u32::MAX))
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| err(PolicyErrorCode::InvalidValue, &format!("{path}.uid")))?;
        grants.push(ProxyUidGrant {
            egress_profile: PolicyId::from_value(
                field(fields, "egress_profile")?,
                &format!("{path}.egress_profile"),
            )?,
            families: families(field(fields, "families")?, &format!("{path}.families"))?,
            id,
            protocols: selection(
                field(fields, "protocols")?,
                &[("tcp", Transport::Tcp), ("udp", Transport::Udp)],
                &format!("{path}.protocols"),
            )?,
            uid,
        });
    }
    let mut systems = Vec::new();
    for (index, value) in array(
        field(map, "system_profiles")?,
        4,
        "authorizations.system_profiles",
    )?
    .iter()
    .enumerate()
    {
        let path = format!("authorizations.system_profiles[{index}]");
        let fields = object(
            value,
            &["id", "recipes", "families", "egress_profile"],
            &path,
        )?;
        let id = PolicyId::from_value(field(fields, "id")?, &format!("{path}.id"))?;
        if !ids.insert(id.clone()) {
            return Err(err(PolicyErrorCode::DuplicateId, "authorizations.id"));
        }
        let selected_families = families(field(fields, "families")?, &format!("{path}.families"))?;
        let recipes = selection(
            field(fields, "recipes")?,
            &[
                ("dhcpv4_client", SystemRecipe::Dhcpv4Client),
                ("dhcpv6_client", SystemRecipe::Dhcpv6Client),
                ("ipv6_host_control", SystemRecipe::Ipv6HostControl),
                ("related_icmp_errors", SystemRecipe::RelatedIcmpErrors),
            ],
            &format!("{path}.recipes"),
        )?;
        if recipes.contains(&SystemRecipe::Dhcpv4Client)
            && !selected_families.contains(&AddressFamily::Ipv4)
            || recipes.iter().any(|r| {
                matches!(
                    r,
                    SystemRecipe::Dhcpv6Client | SystemRecipe::Ipv6HostControl
                )
            }) && !selected_families.contains(&AddressFamily::Ipv6)
        {
            return Err(err(PolicyErrorCode::AddressFamilyMismatch, &path));
        }
        systems.push(SystemProfile {
            egress_profile: PolicyId::from_value(
                field(fields, "egress_profile")?,
                &format!("{path}.egress_profile"),
            )?,
            families: selected_families,
            id,
            recipes,
        });
    }
    grants.sort_by(|a, b| a.id.cmp(&b.id));
    systems.sort_by(|a, b| a.id.cmp(&b.id));
    let mut result = Authorizations {
        proxy_uid_grants: grants,
        system_profiles: systems,
        canonical: Vec::new(),
    };
    result.canonical = bytes(&result)?;
    if result.canonical.len() > MAX_AUTHORIZATION_BYTES {
        return Err(err(
            PolicyErrorCode::AuthorizationTooLarge,
            "authorizations",
        ));
    }
    Ok(result)
}
