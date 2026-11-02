//! Pure policy-draft tests. These cannot establish live authorization or kernel protection.

use std::error::Error;
use std::io;
use std::net::IpAddr;

use serde_json::{Value, json};
use tunlatch_core::config::{Config, DesiredProtection};
use tunlatch_core::policy::{
    ConfigV2, MAX_CANONICAL_POLICY_BYTES, MAX_POLICY_INPUT_BYTES, OrdinaryDecision,
    PacketDescriptor, PacketProtocol, PolicyError, PolicyErrorCode,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn field<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .get(key)
        .ok_or_else(|| io::Error::other(format!("fixture missing {key}")).into())
}

fn text(value: &Value) -> TestResult<&str> {
    value
        .as_str()
        .ok_or_else(|| io::Error::other("fixture needs string").into())
}

fn fixture_bytes(case: &Value) -> TestResult<Vec<u8>> {
    let input = field(case, "input")?;
    match case
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or("object")
    {
        "object" => Ok(serde_json::to_vec(input)?),
        "toml" | "json" => Ok(text(input)?.as_bytes().to_vec()),
        "utf8_hex" => {
            let mut result = Vec::new();
            for chunk in text(input)?.as_bytes().chunks(2) {
                let chunk = std::str::from_utf8(chunk)?;
                result.push(u8::from_str_radix(chunk, 16)?);
            }
            Ok(result)
        }
        _ => Err(io::Error::other("unknown fixture format").into()),
    }
}

fn parse_fixture(case: &Value, bytes: &[u8]) -> Result<ConfigV2, PolicyError> {
    let toml = matches!(
        case.get("format").and_then(Value::as_str),
        Some("toml" | "utf8_hex")
    );
    let migrate = case
        .get("migrate")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match (toml, migrate) {
        (true, true) => ConfigV2::migrate_v1_toml(bytes),
        (true, false) => ConfigV2::parse_toml(bytes),
        (false, true) => ConfigV2::migrate_v1_json(bytes),
        (false, false) => ConfigV2::parse_json(bytes),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

#[test]
fn executes_all_69_tracked_configuration_and_digest_contract_vectors() -> TestResult {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures/policy-contract.json"))?;
    let cases = field(&fixtures, "cases")?
        .as_array()
        .ok_or_else(|| io::Error::other("cases array missing"))?;
    assert_eq!(cases.len(), 69);
    let mut config_count = 0;
    let mut digest_count = 0;
    for case in cases {
        let name = text(field(case, "id")?)?;
        let kind = text(field(case, "kind")?)?;
        let expected = field(case, "expect")?;
        let input = fixture_bytes(case)?;
        match kind {
            "config" => {
                config_count += 1;
                let result = parse_fixture(case, &input);
                if let Some(code) = expected.get("error") {
                    assert!(result.is_err(), "{name}: invalid input accepted");
                    if let Err(error) = result {
                        assert_eq!(error.code().to_string(), text(code)?, "{name}");
                    }
                } else {
                    let config =
                        result.map_err(|error| io::Error::other(format!("{name}: {error}")))?;
                    let actual = serde_json::to_value(&config)?;
                    if let Some(keys) = case.get("inspect").and_then(Value::as_array) {
                        for key in keys {
                            let key = text(key)?;
                            assert_eq!(
                                field(&actual, key)?,
                                field(expected, key)?,
                                "{name}: {key}"
                            );
                        }
                    }
                    assert_eq!(
                        ConfigV2::parse_json(config.canonical_json())?,
                        config,
                        "{name}: canonical roundtrip"
                    );
                    assert_eq!(
                        serde_json::from_slice::<ConfigV2>(config.canonical_json())?,
                        config,
                        "{name}: Serde roundtrip"
                    );
                    let encoded = config.to_toml()?;
                    assert_eq!(
                        ConfigV2::parse_toml(encoded.as_bytes())?,
                        config,
                        "{name}: TOML roundtrip"
                    );
                }
            }
            "digest" => {
                digest_count += 1;
                let config = ConfigV2::parse_json(&input)?;
                assert_eq!(
                    hex(config.canonical_json()),
                    text(field(expected, "canonical_hex")?)?,
                    "{name}"
                );
                assert_eq!(
                    config.digest().to_string(),
                    text(field(expected, "sha256")?)?,
                    "{name}"
                );
            }
            _ => {
                return Err(
                    io::Error::other("out-of-scope runtime fixture in policy tests").into(),
                );
            }
        }
    }
    assert_eq!((config_count, digest_count), (68, 1));
    Ok(())
}

fn draft(rules: Value, exceptions: Value) -> Value {
    json!({"schema_version": 2, "desired": "enabled", "rules": rules, "direct_exceptions": exceptions})
}

fn parse(value: &Value) -> TestResult<ConfigV2> {
    Ok(ConfigV2::parse_json(&serde_json::to_vec(value)?)?)
}

fn rule(id: &str, action: &str, priority: u16) -> Value {
    json!({"id":id,"action":action,"priority":priority,"destination":"any","protocol":"any"})
}

fn upstream(id: &str) -> Value {
    json!({"id":id,"purpose":"proxy_upstream","description":"Candidate only","egress_profile":"physical_a",
        "destination":"203.0.113.10/32","protocol":"tcp","destination_ports":[{"start":443,"end":443}]})
}

fn tcp(address: &str, port: u16) -> TestResult<PacketDescriptor> {
    Ok(PacketDescriptor::new(
        address.parse::<IpAddr>()?,
        PacketProtocol::Tcp {
            source_port: 50000,
            destination_port: port,
        },
    )?)
}

#[test]
fn every_allow_and_default_result_still_requires_separate_egress_authorization() -> TestResult {
    // This API cannot accept a "trusted" bool or grant direct permission. The same ordinary result
    // for a hypothetical packet remains conditional regardless of where a consumer would route it.
    for address in ["192.0.2.1", "2001:db8::1", "127.0.0.1", "::1"] {
        for rules in [json!([]), json!([rule("allow", "allow", 0)])] {
            let config = parse(&draft(rules, json!([])))?;
            assert!(matches!(
                config.ordinary_decision(Some(&tcp(address, 443)?)),
                OrdinaryDecision::NeedsEgressAuthorization { .. }
            ));
            assert_eq!(
                config.ordinary_decision(None),
                OrdinaryDecision::Block { rule_id: None }
            );
        }
    }
    Ok(())
}

#[test]
fn uses_priority_block_first_and_lexical_id_independently_of_text_order() -> TestResult {
    let packet = tcp("198.51.100.20", 443)?;
    for rules in [
        json!([
            rule("allow", "allow", 5),
            rule("deny_z", "block", 5),
            rule("deny_a", "block", 5)
        ]),
        json!([
            rule("deny_a", "block", 5),
            rule("allow", "allow", 5),
            rule("deny_z", "block", 5)
        ]),
    ] {
        let config = parse(&draft(rules, json!([])))?;
        match config.ordinary_decision(Some(&packet)) {
            OrdinaryDecision::Block { rule_id: Some(id) } => assert_eq!(id.as_str(), "deny_a"),
            other => return Err(io::Error::other(format!("unexpected decision {other:?}")).into()),
        }
    }
    let config = parse(&draft(
        json!([rule("deny", "block", 6), rule("allow", "allow", 5)]),
        json!([]),
    ))?;
    match config.ordinary_decision(Some(&packet)) {
        OrdinaryDecision::NeedsEgressAuthorization { rule_id: Some(id) } => {
            assert_eq!(id.as_str(), "allow")
        }
        other => return Err(io::Error::other(format!("unexpected decision {other:?}")).into()),
    }
    Ok(())
}

#[test]
fn explicit_ordinary_block_suppresses_all_matching_exception_candidates() -> TestResult {
    let packet = tcp("203.0.113.10", 443)?;
    let candidate = parse(&draft(
        json!([]),
        json!([upstream("node_z"), upstream("node_a")]),
    ))?;
    let ids = candidate
        .matching_direct_candidates(&packet)
        .map(|item| item.id().as_str())
        .collect::<Vec<_>>();
    assert_eq!(ids, ["node_a", "node_z"]);
    assert!(matches!(
        candidate.ordinary_decision(Some(&packet)),
        OrdinaryDecision::NeedsEgressAuthorization { .. }
    ));
    let blocked = parse(&draft(
        json!([rule("deny", "block", 0)]),
        json!([upstream("node_a")]),
    ))?;
    assert_eq!(blocked.matching_direct_candidates(&packet).count(), 0);
    Ok(())
}

#[test]
fn matches_both_port_directions_families_and_explicit_icmp_fields() -> TestResult {
    let config = parse(&draft(
        json!([
            {"id":"v4_tcp","priority":0,"action":"block","destination":"192.0.2.0/24","protocol":"tcp",
             "source_ports":[{"start":50000,"end":50000}],"destination_ports":[{"start":443,"end":444}]},
            {"id":"v6_icmp","priority":1,"action":"block","destination":"2001:db8::/32","protocol":"icmpv6","icmp_type":128,"icmp_code":0}
        ]),
        json!([]),
    ))?;
    assert!(matches!(
        config.ordinary_decision(Some(&tcp("192.0.2.1", 443)?)),
        OrdinaryDecision::Block { .. }
    ));
    assert!(matches!(
        config.ordinary_decision(Some(&tcp("192.0.2.1", 445)?)),
        OrdinaryDecision::NeedsEgressAuthorization { .. }
    ));
    assert!(matches!(
        config.ordinary_decision(Some(&tcp("2001:db8::1", 443)?)),
        OrdinaryDecision::NeedsEgressAuthorization { .. }
    ));
    let wrong_source = PacketDescriptor::new(
        "192.0.2.1".parse()?,
        PacketProtocol::Tcp {
            source_port: 1,
            destination_port: 443,
        },
    )?;
    assert!(matches!(
        config.ordinary_decision(Some(&wrong_source)),
        OrdinaryDecision::NeedsEgressAuthorization { .. }
    ));
    let icmp = PacketDescriptor::new(
        "2001:db8::1".parse()?,
        PacketProtocol::Icmpv6 {
            message_type: 128,
            code: 0,
        },
    )?;
    let other_code = PacketDescriptor::new(
        "2001:db8::1".parse()?,
        PacketProtocol::Icmpv6 {
            message_type: 128,
            code: 1,
        },
    )?;
    assert!(matches!(
        config.ordinary_decision(Some(&icmp)),
        OrdinaryDecision::Block { .. }
    ));
    assert!(matches!(
        config.ordinary_decision(Some(&other_code)),
        OrdinaryDecision::NeedsEgressAuthorization { .. }
    ));
    assert!(
        PacketDescriptor::new(
            "192.0.2.1".parse()?,
            PacketProtocol::Icmpv6 {
                message_type: 128,
                code: 0
            }
        )
        .is_err()
    );
    for number in [1, 6, 17, 58] {
        assert!(
            PacketDescriptor::new("192.0.2.1".parse()?, PacketProtocol::Other(number)).is_err()
        );
    }
    assert!(PacketDescriptor::new("192.0.2.1".parse()?, PacketProtocol::Other(47)).is_ok());
    Ok(())
}

#[test]
fn direct_serde_cannot_bypass_nested_fields_counts_or_canonical_budget() -> TestResult {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures/policy-contract.json"))?;
    let cases = field(&fixtures, "cases")?
        .as_array()
        .ok_or_else(|| io::Error::other("missing cases"))?;
    let mut rejected = 0;
    for case in cases {
        if case.get("kind").and_then(Value::as_str) != Some("config")
            || case.get("format").and_then(Value::as_str).is_some()
            || case.get("migrate").and_then(Value::as_bool) == Some(true)
            || field(case, "expect")?.get("error").is_none()
        {
            continue;
        }
        let encoded = fixture_bytes(case)?;
        assert!(
            serde_json::from_slice::<ConfigV2>(&encoded).is_err(),
            "{}",
            text(field(case, "id")?)?
        );
        rejected += 1;
    }
    assert!(rejected >= 35);
    let mut nested = draft(json!([rule("a", "allow", 0)]), json!([]));
    nested["rules"][0]["trusted"] = json!(true);
    let bytes = serde_json::to_vec(&nested)?;
    let error = ConfigV2::parse_json(&bytes)
        .err()
        .ok_or_else(|| io::Error::other("nested extra accepted"))?;
    assert_eq!(error.code(), PolicyErrorCode::UnknownField);
    assert_eq!(error.path(), "config.rules[0].<unknown>");
    assert!(serde_json::from_slice::<ConfigV2>(&bytes).is_err());
    Ok(())
}

#[test]
fn rejects_duplicate_nested_keys_trailing_data_and_invalid_unicode_without_string_matching()
-> TestResult {
    let duplicate = br#"{"schema_version":2,"desired":"enabled","rules":[{"id":"a","id":"b","action":"allow","priority":0,"destination":"any","protocol":"any"}],"direct_exceptions":[]}"#;
    let error = ConfigV2::parse_json(duplicate)
        .err()
        .ok_or_else(|| io::Error::other("duplicate accepted"))?;
    assert_eq!(error.code(), PolicyErrorCode::InvalidSyntax);
    assert!(serde_json::from_slice::<ConfigV2>(duplicate).is_err());
    for input in [
        br#"{"schema_version":2,"desired":"enabled","rules":[],"direct_exceptions":[]} false"#
            .as_slice(),
        br#"{"schema_version":2,"desired":NaN,"rules":[],"direct_exceptions":[]}"#,
    ] {
        let error = ConfigV2::parse_json(input)
            .err()
            .ok_or_else(|| io::Error::other("malformed JSON accepted"))?;
        assert_eq!(error.code(), PolicyErrorCode::InvalidSyntax);
    }
    for escape in [r#"\ud800"#, r#"\udc00"#, r#"\ud800\ud800"#] {
        let input = format!(
            r#"{{"schema_version":2,"desired":"enabled","rules":[],"direct_exceptions":[],"extra":"{escape}"}}"#
        );
        let error = ConfigV2::parse_json(input.as_bytes())
            .err()
            .ok_or_else(|| io::Error::other("invalid Unicode accepted"))?;
        assert_eq!(error.code(), PolicyErrorCode::InvalidEncoding);
    }
    Ok(())
}

#[test]
fn bounded_parsers_enforce_original_bytes_while_serde_cannot_observe_whitespace() -> TestResult {
    let config = parse(&draft(json!([]), json!([])))?;
    let mut bytes = config.canonical_json().to_vec();
    bytes.resize(MAX_POLICY_INPUT_BYTES, b' ');
    assert_eq!(ConfigV2::parse_json(&bytes)?, config);
    bytes.push(b' ');
    let error = ConfigV2::parse_json(&bytes)
        .err()
        .ok_or_else(|| io::Error::other("raw limit ignored"))?;
    assert_eq!(
        (error.code(), error.limit(), error.actual()),
        (
            PolicyErrorCode::InputTooLarge,
            Some(MAX_POLICY_INPUT_BYTES),
            Some(MAX_POLICY_INPUT_BYTES + 1)
        )
    );
    // This limitation is explicitly documented; file and frame entrypoints must use bounded bytes.
    assert_eq!(serde_json::from_slice::<ConfigV2>(&bytes)?, config);
    assert!(config.canonical_json().len() < MAX_CANONICAL_POLICY_BYTES);
    Ok(())
}

#[test]
fn canonical_bytes_digests_and_unicode_are_stable_across_equivalent_inputs() -> TestResult {
    let mut a = upstream("node");
    a["description"] = json!("中文 \"quoted\" \\ path 😀");
    a["destination_ports"] = json!([{"start":444,"end":444},{"start":443,"end":443}]);
    let mut b = a.clone();
    b["destination_ports"] = json!([{"start":443,"end":444}]);
    let first = parse(&draft(
        json!([rule("b", "allow", 0), rule("a", "allow", 0)]),
        json!([a]),
    ))?;
    let equivalent = parse(&draft(
        json!([rule("a", "allow", 0), rule("b", "allow", 0)]),
        json!([b.clone()]),
    ))?;
    assert_eq!(first.canonical_json(), equivalent.canonical_json());
    assert_eq!(first.digest(), equivalent.digest());
    // Independent Python hashlib + recursively sorted compact UTF-8 JSON vectors, including
    // quotes, a backslash, CJK and a supplementary Unicode character.
    assert_eq!(first.canonical_json().len(), 441);
    assert_eq!(
        first.digest().to_string(),
        "df3762e9623c3283e6a855c6a0f114823a2dda7af2aeedb8432cec5294f8a39b"
    );
    assert_eq!(
        first.direct_exceptions()[0].digest()?.to_string(),
        "bfe0e2941a8bdd5514ca2ea75c400119aa33a76b945e7ef0c7d974ff3092e988"
    );
    assert_eq!(
        first.direct_exceptions()[0].digest()?,
        equivalent.direct_exceptions()[0].digest()?
    );
    b["description"] = json!("Changed candidate");
    let changed = parse(&draft(
        json!([rule("a", "allow", 0), rule("b", "allow", 0)]),
        json!([b]),
    ))?;
    assert_ne!(first.digest(), changed.digest());
    assert_ne!(
        first.direct_exceptions()[0].digest()?,
        changed.direct_exceptions()[0].digest()?
    );
    let value: Value = serde_json::from_slice(first.canonical_json())?;
    assert_eq!(serde_json::to_vec(&value)?, first.canonical_json());
    Ok(())
}

#[test]
fn diagnostic_paths_are_bounded_and_cannot_emit_terminal_control_sequences() -> TestResult {
    let mut config = draft(json!([]), json!([]));
    let marker = "private_unknown_key_must_not_appear";
    let hostile = format!("\u{1b}[31m{marker}{}", "x".repeat(4000));
    let object = config
        .as_object_mut()
        .ok_or_else(|| io::Error::other("object expected"))?;
    object.insert(hostile, json!("sensitive value must not appear in error"));
    let error = ConfigV2::parse_json(&serde_json::to_vec(&config)?)
        .err()
        .ok_or_else(|| io::Error::other("unknown hostile field accepted"))?;
    assert_eq!(error.code(), PolicyErrorCode::UnknownField);
    assert!(error.path().len() <= 255);
    assert!(!error.path().chars().any(char::is_control));
    assert!(!error.to_string().contains("sensitive value"));
    assert!(!error.to_string().contains(marker));
    assert_eq!(error.path(), "config.<unknown>");

    let mut nested = draft(json!([rule("a", "allow", 0)]), json!([]));
    let object = nested["rules"][0]
        .as_object_mut()
        .ok_or_else(|| io::Error::other("rule expected"))?;
    object.insert(format!("{marker}\n\u{1b}[31m"), json!({"rules":[1,2,3]}));
    let error = ConfigV2::parse_json(&serde_json::to_vec(&nested)?)
        .err()
        .ok_or_else(|| io::Error::other("nested hostile field accepted"))?;
    assert_eq!(error.code(), PolicyErrorCode::UnknownField);
    assert_eq!(error.path(), "config.rules[0].<unknown>");
    assert!(!error.to_string().contains(marker));
    assert!(!error.to_string().chars().any(char::is_control));

    let encoded_key = serde_json::to_string(&format!("{marker}\n\u{1b}{}", "x".repeat(4000)))?;
    let duplicate = format!("{{{encoded_key}:1,{encoded_key}:2}}");
    let error = ConfigV2::parse_json(duplicate.as_bytes())
        .err()
        .ok_or_else(|| io::Error::other("duplicate hostile key accepted"))?;
    assert_eq!(error.code(), PolicyErrorCode::InvalidSyntax);
    assert_eq!(error.path(), "config");
    assert!(!error.to_string().contains(marker));
    assert!(!error.to_string().chars().any(char::is_control));
    Ok(())
}

#[test]
fn explicit_migration_preserves_legacy_intent_without_replacing_any_original_value() -> TestResult {
    let original = Config::parse("schema_version=1\ndesired='enabled'")?;
    let migrated = ConfigV2::migrate_v1_toml(b"schema_version=1\ndesired='enabled'")?;
    assert_eq!(original.desired(), DesiredProtection::Enabled);
    assert_eq!(migrated.desired(), DesiredProtection::Enabled);
    assert!(migrated.rules().is_empty() && migrated.direct_exceptions().is_empty());
    assert!(ConfigV2::migrate_v1_json(migrated.canonical_json()).is_err());
    assert!(Config::parse(std::str::from_utf8(migrated.canonical_json())?).is_err());
    let valid = migrated.clone();
    let failed = ConfigV2::parse_json(b"{}");
    assert!(failed.is_err());
    assert_eq!(migrated, valid);
    Ok(())
}
