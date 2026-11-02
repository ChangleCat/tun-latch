//! Schema validation and normalization after bounded, duplicate-preserving structural decoding.

use std::collections::BTreeSet;
use std::net::IpAddr;

use ipnet::IpNet;
use serde_json::{Map, Value};

use super::{
    ConfigV2, Destination, DirectException, ExceptionPurpose, MAX_CANONICAL_POLICY_BYTES,
    MAX_DIRECT_EXCEPTIONS, MAX_PORT_RANGES, MAX_RULES, POLICY_VERSION, PolicyError,
    PolicyErrorCode, PolicyId, PortRange, Protocol, Rule, RuleAction, canonical,
};
use crate::config::DesiredProtection;

const OPTIONAL: &[&str] = &[
    "source_ports",
    "destination_ports",
    "icmp_type",
    "icmp_code",
];

fn error(code: PolicyErrorCode, path: &str) -> PolicyError {
    PolicyError::new(code, path)
}

fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>, PolicyError> {
    value
        .as_object()
        .ok_or_else(|| error(PolicyErrorCode::InvalidType, path))
}

fn get<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    path: &str,
) -> Result<&'a Value, PolicyError> {
    object
        .get(key)
        .ok_or_else(|| error(PolicyErrorCode::MissingField, &format!("{path}.{key}")))
}

fn shape(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
    path: &str,
) -> Result<(), PolicyError> {
    if object
        .keys()
        .filter(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
        .min()
        .is_some()
    {
        return Err(error(
            PolicyErrorCode::UnknownField,
            &format!("{path}.<unknown>"),
        ));
    }
    for key in required {
        get(object, key, path)?;
    }
    Ok(())
}

fn integer(value: &Value, maximum: u64, path: &str) -> Result<u64, PolicyError> {
    let Value::Number(number) = value else {
        return Err(error(PolicyErrorCode::InvalidType, path));
    };
    if number.is_f64() {
        return Err(error(PolicyErrorCode::InvalidType, path));
    }
    match number.as_u64() {
        Some(value) if value <= maximum => Ok(value),
        _ => Err(error(PolicyErrorCode::InvalidValue, path)),
    }
}

fn number<T: TryFrom<u64>>(value: &Value, maximum: u64, path: &str) -> Result<T, PolicyError> {
    T::try_from(integer(value, maximum, path)?)
        .map_err(|_| error(PolicyErrorCode::InvalidValue, path))
}

fn id(value: &Value, path: &str) -> Result<PolicyId, PolicyError> {
    let text = value
        .as_str()
        .ok_or_else(|| error(PolicyErrorCode::InvalidId, path))?;
    if text.is_empty()
        || text.len() > 32
        || !text.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        || !text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(error(PolicyErrorCode::InvalidId, path));
    }
    Ok(PolicyId(text.into()))
}

fn destination(value: &Value, path: &str) -> Result<Destination, PolicyError> {
    let text = value
        .as_str()
        .ok_or_else(|| error(PolicyErrorCode::InvalidType, path))?;
    if text == "any" {
        return Ok(Destination::Any);
    }
    if text.contains('%') {
        return Err(error(PolicyErrorCode::InvalidDestination, path));
    }
    let (address, prefix) = if let Some((address, prefix)) = text.split_once('/') {
        if prefix.is_empty()
            || (prefix.len() > 1 && prefix.starts_with('0'))
            || !prefix.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(error(PolicyErrorCode::InvalidDestination, path));
        }
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| error(PolicyErrorCode::InvalidDestination, path))?;
        (address, Some(prefix))
    } else {
        (text, None)
    };
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| error(PolicyErrorCode::InvalidDestination, path))?;
    if matches!(address, IpAddr::V6(value) if value.to_ipv4_mapped().is_some()) {
        return Err(error(PolicyErrorCode::InvalidDestination, path));
    }
    let prefix = match prefix {
        Some(prefix) => prefix,
        None => {
            if address.is_ipv4() {
                32
            } else {
                128
            }
        }
    };
    let network = IpNet::new(address, prefix)
        .map_err(|_| error(PolicyErrorCode::InvalidDestination, path))?;
    if network.addr() != network.network() {
        return Err(error(PolicyErrorCode::NonCanonicalNetwork, path));
    }
    Ok(Destination::Network(network))
}

fn protocol(value: &Value, path: &str) -> Result<Protocol, PolicyError> {
    match value.as_str() {
        Some("any") => Ok(Protocol::Any),
        Some("tcp") => Ok(Protocol::Tcp),
        Some("udp") => Ok(Protocol::Udp),
        Some("icmp") => Ok(Protocol::Icmp),
        Some("icmpv6") => Ok(Protocol::Icmpv6),
        _ => Err(error(PolicyErrorCode::InvalidValue, path)),
    }
}

fn array<'a>(value: &'a Value, limit: usize, path: &str) -> Result<&'a [Value], PolicyError> {
    let values = value
        .as_array()
        .ok_or_else(|| error(PolicyErrorCode::InvalidType, path))?;
    if values.len() > limit {
        return Err(PolicyError::bounded(
            PolicyErrorCode::TooManyItems,
            path,
            limit,
            values.len(),
        ));
    }
    Ok(values)
}

fn ranges(value: Option<&Value>, path: &str) -> Result<Option<Vec<PortRange>>, PolicyError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let values = array(value, MAX_PORT_RANGES, path)?;
    if values.is_empty() {
        return Err(error(PolicyErrorCode::InvalidPortRange, path));
    }
    let mut ranges = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let path = format!("{path}[{index}]");
        let value = object(value, &path)?;
        shape(value, &["start", "end"], &[], &path)?;
        let start = number(get(value, "start", &path)?, 65535, &format!("{path}.start"))?;
        let end = number(get(value, "end", &path)?, 65535, &format!("{path}.end"))?;
        if start > end {
            return Err(error(PolicyErrorCode::InvalidPortRange, &path));
        }
        ranges.push(PortRange { start, end });
    }
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = merged.last_mut()
            && u32::from(range.start) <= u32::from(previous.end) + 1
        {
            previous.end = previous.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    Ok(Some(merged))
}

struct Selectors {
    destination: Destination,
    protocol: Protocol,
    source_ports: Option<Vec<PortRange>>,
    destination_ports: Option<Vec<PortRange>>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
}

fn selectors(value: &Map<String, Value>, path: &str) -> Result<Selectors, PolicyError> {
    let destination = destination(
        get(value, "destination", path)?,
        &format!("{path}.destination"),
    )?;
    let protocol = protocol(get(value, "protocol", path)?, &format!("{path}.protocol"))?;
    let has_ports = value.contains_key("source_ports") || value.contains_key("destination_ports");
    let has_icmp = value.contains_key("icmp_type") || value.contains_key("icmp_code");
    if (protocol == Protocol::Any && (has_ports || has_icmp))
        || (matches!(protocol, Protocol::Tcp | Protocol::Udp) && has_icmp)
        || (matches!(protocol, Protocol::Icmp | Protocol::Icmpv6) && has_ports)
        || (value.contains_key("icmp_code") && !value.contains_key("icmp_type"))
    {
        return Err(error(PolicyErrorCode::InvalidProtocolFields, path));
    }
    let source_ports = ranges(value.get("source_ports"), &format!("{path}.source_ports"))?;
    let destination_ports = ranges(
        value.get("destination_ports"),
        &format!("{path}.destination_ports"),
    )?;
    let icmp_type = value
        .get("icmp_type")
        .map(|value| number(value, 255, &format!("{path}.icmp_type")))
        .transpose()?;
    let icmp_code = value
        .get("icmp_code")
        .map(|value| number(value, 255, &format!("{path}.icmp_code")))
        .transpose()?;
    if matches!(protocol, Protocol::Icmp | Protocol::Icmpv6) {
        let correct = matches!(
            (&destination, protocol),
            (Destination::Network(IpNet::V4(_)), Protocol::Icmp)
                | (Destination::Network(IpNet::V6(_)), Protocol::Icmpv6)
        );
        if !correct {
            return Err(error(PolicyErrorCode::AddressFamilyMismatch, path));
        }
    }
    Ok(Selectors {
        destination,
        protocol,
        source_ports,
        destination_ports,
        icmp_type,
        icmp_code,
    })
}

fn rule(value: &Value, path: &str) -> Result<Rule, PolicyError> {
    let value = object(value, path)?;
    shape(
        value,
        &["id", "priority", "action", "destination", "protocol"],
        OPTIONAL,
        path,
    )?;
    let id = id(get(value, "id", path)?, &format!("{path}.id"))?;
    let priority = number(
        get(value, "priority", path)?,
        65535,
        &format!("{path}.priority"),
    )?;
    let action = match get(value, "action", path)?.as_str() {
        Some("block") => RuleAction::Block,
        Some("allow") => RuleAction::Allow,
        _ => {
            return Err(error(
                PolicyErrorCode::InvalidValue,
                &format!("{path}.action"),
            ));
        }
    };
    let selectors = selectors(value, path)?;
    Ok(Rule {
        id,
        priority,
        action,
        destination: selectors.destination,
        protocol: selectors.protocol,
        source_ports: selectors.source_ports,
        destination_ports: selectors.destination_ports,
        icmp_type: selectors.icmp_type,
        icmp_code: selectors.icmp_code,
    })
}

fn exception(value: &Value, path: &str) -> Result<DirectException, PolicyError> {
    let value = object(value, path)?;
    shape(
        value,
        &[
            "id",
            "purpose",
            "description",
            "egress_profile",
            "destination",
            "protocol",
        ],
        OPTIONAL,
        path,
    )?;
    let id = id(get(value, "id", path)?, &format!("{path}.id"))?;
    let purpose = match get(value, "purpose", path)?.as_str() {
        Some("proxy_upstream") => ExceptionPurpose::ProxyUpstream,
        Some("network_bootstrap") => ExceptionPurpose::NetworkBootstrap,
        _ => {
            return Err(error(
                PolicyErrorCode::InvalidValue,
                &format!("{path}.purpose"),
            ));
        }
    };
    let description = get(value, "description", path)?
        .as_str()
        .filter(|text| {
            !text.is_empty()
                && text.len() <= 160
                && !text.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}')
        })
        .ok_or_else(|| {
            error(
                PolicyErrorCode::InvalidDescription,
                &format!("{path}.description"),
            )
        })?;
    let egress_profile = id_value(
        get(value, "egress_profile", path)?,
        &format!("{path}.egress_profile"),
    )?;
    let selectors = selectors(value, path)?;
    let network = match selectors.destination {
        Destination::Network(network) if network.prefix_len() > 0 => network,
        _ => {
            return Err(error(
                PolicyErrorCode::InvalidDestination,
                &format!("{path}.destination"),
            ));
        }
    };
    if selectors.protocol == Protocol::Any
        || (matches!(selectors.protocol, Protocol::Tcp | Protocol::Udp)
            && selectors.destination_ports.is_none())
        || (matches!(selectors.protocol, Protocol::Icmp | Protocol::Icmpv6)
            && (selectors.icmp_type.is_none() || selectors.icmp_code.is_none()))
        || (purpose == ExceptionPurpose::ProxyUpstream
            && (!matches!(selectors.protocol, Protocol::Tcp | Protocol::Udp)
                || network.prefix_len() != if network.addr().is_ipv4() { 32 } else { 128 }))
    {
        return Err(error(PolicyErrorCode::InvalidProtocolFields, path));
    }
    Ok(DirectException {
        id,
        purpose,
        description: description.into(),
        egress_profile,
        destination: Destination::Network(network),
        protocol: selectors.protocol,
        source_ports: selectors.source_ports,
        destination_ports: selectors.destination_ports,
        icmp_type: selectors.icmp_type,
        icmp_code: selectors.icmp_code,
    })
}

fn id_value(value: &Value, path: &str) -> Result<PolicyId, PolicyError> {
    id(value, path)
}

pub(super) fn config(value: Value, migrate: bool) -> Result<ConfigV2, PolicyError> {
    let value = object(&value, "config")?;
    let version: u16 = number(
        get(value, "schema_version", "config")?,
        65535,
        "config.schema_version",
    )?;
    if ![1, POLICY_VERSION].contains(&version) {
        return Err(error(
            PolicyErrorCode::UnsupportedVersion,
            "config.schema_version",
        ));
    }
    let required: &[&str] = if version == 1 {
        &["schema_version", "desired"]
    } else {
        &["schema_version", "desired", "rules", "direct_exceptions"]
    };
    shape(value, required, &[], "config")?;
    let desired = match get(value, "desired", "config")?.as_str() {
        Some("enabled") => DesiredProtection::Enabled,
        Some("disabled") => DesiredProtection::Disabled,
        _ => return Err(error(PolicyErrorCode::InvalidValue, "config.desired")),
    };
    if version == 1 && !migrate {
        return Err(error(
            PolicyErrorCode::MigrationRequired,
            "config.schema_version",
        ));
    }
    if version != 1 && migrate {
        return Err(error(
            PolicyErrorCode::InvalidValue,
            "config.schema_version",
        ));
    }
    let mut config = ConfigV2 {
        desired,
        direct_exceptions: Vec::new(),
        rules: Vec::new(),
        schema_version: POLICY_VERSION,
        canonical_json: Vec::new(),
    };
    if version == POLICY_VERSION {
        for (index, value) in array(get(value, "rules", "config")?, MAX_RULES, "config.rules")?
            .iter()
            .enumerate()
        {
            config
                .rules
                .push(rule(value, &format!("config.rules[{index}]"))?);
        }
        for (index, value) in array(
            get(value, "direct_exceptions", "config")?,
            MAX_DIRECT_EXCEPTIONS,
            "config.direct_exceptions",
        )?
        .iter()
        .enumerate()
        {
            config.direct_exceptions.push(exception(
                value,
                &format!("config.direct_exceptions[{index}]"),
            )?);
        }
    }
    let mut ids = BTreeSet::new();
    for id in config.rules.iter().map(|rule| &rule.id).chain(
        config
            .direct_exceptions
            .iter()
            .map(|exception| &exception.id),
    ) {
        if !ids.insert(id.as_str()) {
            return Err(error(PolicyErrorCode::DuplicateId, id.as_str()));
        }
    }
    config
        .rules
        .sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
    config
        .direct_exceptions
        .sort_by(|left, right| left.id.cmp(&right.id));
    let bytes = canonical(&config)?;
    if bytes.len() > MAX_CANONICAL_POLICY_BYTES {
        return Err(PolicyError::bounded(
            PolicyErrorCode::CanonicalConfigTooLarge,
            "config",
            MAX_CANONICAL_POLICY_BYTES,
            bytes.len(),
        ));
    }
    config.canonical_json = bytes;
    Ok(config)
}
