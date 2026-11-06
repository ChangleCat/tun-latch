//! Offline candidate tests only: these neither parse with pfctl nor establish leak protection.

use std::error::Error;

use serde_json::{Value, json};
use tunlatch_core::policy::{
    ConfigV2, OrdinaryDecision, PacketDescriptor, PacketProtocol, PolicyError,
};
use tunlatch_platform::policy_compile::{
    MAX_CANDIDATE_BYTES, MAX_CANDIDATE_RULES, PfCandidateStatus, PfCompileError,
    UnsupportedIcmpField, compile_candidate,
};

type TestResult = Result<(), Box<dyn Error>>;

fn config(desired: &str, rules: Value, direct_exceptions: Value) -> Result<ConfigV2, PolicyError> {
    ConfigV2::parse_json(
        json!({
            "schema_version": 2,
            "desired": desired,
            "rules": rules,
            "direct_exceptions": direct_exceptions,
        })
        .to_string()
        .as_bytes(),
    )
}

fn rule(id: &str, priority: u16, action: &str, destination: &str, protocol: &str) -> Value {
    json!({
        "id": id,
        "priority": priority,
        "action": action,
        "destination": destination,
        "protocol": protocol,
    })
}

fn exception() -> Value {
    json!({
        "id": "upstream",
        "description": "Explicit candidate only",
        "egress_profile": "physical",
        "purpose": "proxy_upstream",
        "destination": "192.0.2.1",
        "protocol": "tcp",
        "destination_ports": [{"start": 443, "end": 443}],
    })
}

#[test]
fn empty_enabled_policy_has_dual_stack_default_deny_and_only_fixed_outbound_loopback_passes()
-> TestResult {
    let policy = config("enabled", json!([]), json!([]))?;
    let candidate = compile_candidate(&policy)?;
    assert_eq!(candidate.status(), PfCandidateStatus::BlockedNotReady);
    assert_eq!(candidate.source_digest(), policy.digest());
    assert_eq!(candidate.rule_count(), 4);
    let rules = candidate
        .rules_text()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .collect::<Vec<_>>();
    assert_eq!(
        rules,
        [
            "pass out quick on lo0 inet all no state allow-opts label \"tl.loopback.v4\"",
            "pass out quick on lo0 inet6 all no state allow-opts label \"tl.loopback.v6\"",
            "block drop out quick inet all label \"tl.default.v4\"",
            "block drop out quick inet6 all label \"tl.default.v6\"",
        ]
    );
    assert!(candidate.rules_text().contains("NOT AN EXECUTABLE PLAN"));
    Ok(())
}

#[test]
fn ordinary_allow_stops_at_the_closed_egress_floor_without_physical_pass() -> TestResult {
    let policy = config(
        "enabled",
        json!([rule("ordinary", 1, "allow", "any", "any")]),
        json!([]),
    )?;
    let packet = PacketDescriptor::new(
        "198.51.100.1".parse()?,
        PacketProtocol::Tcp {
            source_port: 5_000,
            destination_port: 443,
        },
    )?;
    assert!(matches!(
        policy.ordinary_decision(Some(&packet)),
        OrdinaryDecision::NeedsEgressAuthorization { rule_id: Some(id) }
            if id.as_str() == "ordinary"
    ));
    let candidate = compile_candidate(&policy)?;
    assert!(
        candidate
            .rules_text()
            .contains("block drop out quick inet from any to any label \"tl.r.ordinary.a4.0.0\"")
    );
    assert!(
        candidate
            .rules_text()
            .contains("block drop out quick inet6 from any to any label \"tl.r.ordinary.a6.0.0\"")
    );
    assert!(
        candidate
            .rules_text()
            .lines()
            .filter(|line| line.starts_with("pass "))
            .all(|line| line.starts_with("pass out quick on lo0 "))
    );
    Ok(())
}

#[test]
fn normalized_first_match_order_keeps_priority_block_tie_break_and_ascii_id() -> TestResult {
    let policy = config(
        "enabled",
        json!([
            rule("last", 3, "block", "any", "any"),
            rule("z_block", 2, "block", "any", "any"),
            rule("first", 1, "allow", "any", "any"),
            rule("a_allow", 2, "allow", "any", "any"),
            rule("a_block", 2, "block", "any", "any"),
        ]),
        json!([]),
    )?;
    let candidate = compile_candidate(&policy)?;
    let labels = candidate
        .rules_text()
        .lines()
        .filter(|line| line.contains("tl.r.") && line.contains("inet "))
        .filter_map(|line| line.split_once(" label ").map(|(_, label)| label))
        .collect::<Vec<_>>();
    assert_eq!(
        labels,
        [
            "\"tl.r.first.a4.0.0\"",
            "\"tl.r.a_block.b4.0.0\"",
            "\"tl.r.z_block.b4.0.0\"",
            "\"tl.r.a_allow.a4.0.0\"",
            "\"tl.r.last.b4.0.0\"",
        ]
    );
    assert!(
        candidate
            .rules_text()
            .lines()
            .filter(|line| line.contains("tl.r."))
            .all(|line| line.starts_with("block drop out quick "))
    );
    Ok(())
}

#[test]
fn transport_selectors_expand_exact_inclusive_ranges_without_losing_conditions() -> TestResult {
    let mut tcp = rule("transport", 1, "block", "192.0.2.0/24", "tcp");
    tcp["source_ports"] = json!([
        {"start": 65_535, "end": 65_535},
        {"start": 0, "end": 1},
    ]);
    tcp["destination_ports"] = json!([
        {"start": 443, "end": 443},
        {"start": 1_000, "end": 1_005},
    ]);
    let mut udp = rule("quic", 2, "block", "2001:db8::/32", "udp");
    udp["destination_ports"] = json!([{"start": 443, "end": 443}]);
    let policy = config("enabled", json!([tcp, udp]), json!([]))?;
    let candidate = compile_candidate(&policy)?;
    let transport = candidate
        .rules_text()
        .lines()
        .filter(|line| line.contains("tl.r.transport."))
        .collect::<Vec<_>>();
    assert_eq!(transport.len(), 4);
    for (index, (source, destination)) in [
        ("0:1", "= 443"),
        ("0:1", "1000:1005"),
        ("= 65535", "= 443"),
        ("= 65535", "1000:1005"),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(transport[index].starts_with(&format!(
            "block drop out quick inet proto tcp from any port {source} to 192.0.2.0/24 port {destination} label "
        )));
    }
    assert!(candidate.rules_text().contains(
        "block drop out quick inet6 proto udp from any to 2001:db8::/32 port = 443 label \"tl.r.quic.b6.0.0\""
    ));
    assert_eq!(candidate.rule_count(), 9);
    Ok(())
}

#[test]
fn wildcard_transport_expands_to_both_families_and_explicit_host_keeps_its_family() -> TestResult {
    let policy = config(
        "enabled",
        json!([
            rule("both", 1, "block", "any", "udp"),
            rule("host", 2, "block", "2001:db8::1", "any"),
        ]),
        json!([]),
    )?;
    let candidate = compile_candidate(&policy)?;
    assert!(
        candidate
            .rules_text()
            .contains("inet proto udp from any to any label \"tl.r.both.b4.0.0\"")
    );
    assert!(
        candidate
            .rules_text()
            .contains("inet6 proto udp from any to any label \"tl.r.both.b6.0.0\"")
    );
    assert!(
        candidate
            .rules_text()
            .contains("inet6 from any to 2001:db8::1/128 label \"tl.r.host.b6.0.0\"")
    );
    assert!(!candidate.rules_text().contains("tl.r.host.b4"));
    Ok(())
}

#[test]
fn icmp_type_and_code_are_preserved_for_the_correct_address_family() -> TestResult {
    let mut v4 = rule("echo4", 1, "block", "192.0.2.0/24", "icmp");
    v4["icmp_type"] = json!(8);
    v4["icmp_code"] = json!(0);
    let mut v6 = rule("nd6", 2, "block", "fe80::/10", "icmpv6");
    v6["icmp_type"] = json!(135);
    v6["icmp_code"] = json!(0);
    let mut type_only = rule("type_only", 3, "block", "2001:db8::/32", "icmpv6");
    type_only["icmp_type"] = json!(0);
    let candidate = compile_candidate(&config("enabled", json!([v4, v6, type_only]), json!([]))?)?;
    assert!(candidate.rules_text().contains(
        "inet proto icmp from any to 192.0.2.0/24 icmp-type 8 code 0 label \"tl.r.echo4.b4.0.0\""
    ));
    assert!(candidate.rules_text().contains(
        "inet6 proto icmp6 from any to fe80::/10 icmp6-type 135 code 0 label \"tl.r.nd6.b6.0.0\""
    ));
    assert!(candidate.rules_text().contains(
        "inet6 proto icmp6 from any to 2001:db8::/32 icmp6-type 0 label \"tl.r.type_only.b6.0.0\""
    ));
    Ok(())
}

#[test]
fn ambiguous_icmp_255_selectors_fail_instead_of_becoming_wildcards() -> TestResult {
    for protocol in ["icmp", "icmpv6"] {
        let destination = if protocol == "icmp" {
            "192.0.2.1"
        } else {
            "2001:db8::1"
        };
        for (field, value, expected_field) in [
            ("icmp_type", 255, UnsupportedIcmpField::Type),
            ("icmp_code", 255, UnsupportedIcmpField::Code),
        ] {
            let mut icmp = rule("unsupported", 1, "block", destination, protocol);
            icmp["icmp_type"] = json!(8);
            icmp[field] = json!(value);
            let policy = config("enabled", json!([icmp]), json!([]))?;
            assert_eq!(
                compile_candidate(&policy),
                Err(PfCompileError::UnsupportedIcmpSelector {
                    rule_id: "unsupported".into(),
                    field: expected_field,
                })
            );
        }
    }
    Ok(())
}

#[test]
fn direct_exception_candidates_are_explicitly_refused_without_authority() -> TestResult {
    let policy = config("enabled", json!([]), json!([exception()]))?;
    assert_eq!(
        compile_candidate(&policy),
        Err(PfCompileError::UnsupportedDirectExceptions { count: 1 })
    );
    Ok(())
}

#[test]
fn disabled_intent_is_empty_unmanaged_data_even_with_dormant_rules_and_candidates() -> TestResult {
    let policy = config(
        "disabled",
        json!([rule("dormant", 1, "allow", "any", "any")]),
        json!([exception()]),
    )?;
    let candidate = compile_candidate(&policy)?;
    assert_eq!(candidate.status(), PfCandidateStatus::Unmanaged);
    assert_eq!(candidate.rules_text(), "");
    assert_eq!(candidate.rule_count(), 0);
    assert_eq!(candidate.source_digest(), policy.digest());
    let empty = compile_candidate(&config("disabled", json!([]), json!([]))?)?;
    assert_ne!(candidate.digest(), empty.digest());
    Ok(())
}

#[test]
fn normalized_equivalent_inputs_have_identical_candidates_and_domain_separated_digest() -> TestResult
{
    let early = rule("early", 1, "block", "192.0.2.1", "udp");
    let late = rule("late", 2, "allow", "any", "tcp");
    let first = config("enabled", json!([late, early]), json!([]))?;
    let second = ConfigV2::parse_json(
        br#"{
            "rules": [
                {"protocol":"udp","priority":1,"id":"early","destination":"192.0.2.1/32","action":"block"},
                {"protocol":"tcp","priority":2,"id":"late","destination":"any","action":"allow"}
            ],
            "direct_exceptions": [], "desired":"enabled", "schema_version":2
        }"#,
    )?;
    let candidate = compile_candidate(&first)?;
    assert_eq!(candidate, compile_candidate(&second)?);
    // Fixed independently calculated vector: changing normalization, rendering, version or
    // domain separation must be an explicit candidate-format change, not accidental drift.
    assert_eq!(
        candidate.source_digest().to_string(),
        "59a710ce3c50dc41bebdc907c1f3af994f664c66f43f48b9012444a3926d518a"
    );
    assert_eq!(
        candidate.digest().to_string(),
        "a65f1756cf463252e010437aa3afb83a85b1f74f7ae90fd607f6b38bfc79f999"
    );
    assert_ne!(candidate.digest().as_bytes(), first.digest().as_bytes());
    Ok(())
}

#[test]
fn policy_change_changes_digest_even_when_closed_floor_gives_same_packet_result() -> TestResult {
    let blocked = config(
        "enabled",
        json!([rule("intent", 1, "block", "any", "any")]),
        json!([]),
    )?;
    let allowed = config(
        "enabled",
        json!([rule("intent", 1, "allow", "any", "any")]),
        json!([]),
    )?;
    assert_ne!(
        compile_candidate(&blocked)?.digest(),
        compile_candidate(&allowed)?.digest()
    );
    Ok(())
}

#[test]
fn candidate_adds_no_dns_lan_system_uid_inbound_or_global_control_rules() -> TestResult {
    let candidate = compile_candidate(&config("enabled", json!([]), json!([]))?)?;
    let text = candidate.rules_text();
    for forbidden in [
        "block in ",
        "pass in ",
        "flush",
        "disable",
        "set ",
        "skip",
        "user ",
        "group ",
        "port ",
        "10.0.0.0",
        "192.168.",
        "fe80:",
        "ff02:",
        "anchor ",
        "table ",
        "include ",
    ] {
        assert!(
            !text.contains(forbidden),
            "unexpected candidate token {forbidden}"
        );
    }
    Ok(())
}

#[test]
fn untrusted_tokens_cannot_enter_the_validated_compiler_input() {
    for id in ["a\" pass out all", "a\npass out all", "a$if", "a\\b"] {
        assert!(
            config(
                "enabled",
                json!([rule(id, 1, "block", "any", "any")]),
                json!([])
            )
            .is_err()
        );
    }
    for destination in ["example.com", "<table>", "any\npass out all", "fe80::1%en0"] {
        assert!(
            config(
                "enabled",
                json!([rule("safe_id", 1, "block", destination, "any")]),
                json!([])
            )
            .is_err()
        );
    }
}

#[test]
fn maximal_validated_port_expansion_stays_within_fixed_output_bounds() -> TestResult {
    let ports = json!([
        {"start": 0, "end": 0},
        {"start": 2, "end": 2},
        {"start": 4, "end": 4},
        {"start": 65_535, "end": 65_535},
    ]);
    let mut rules = Vec::new();
    for index in 0..128 {
        let mut value = rule(&format!("rule_{index:03}"), index, "block", "any", "tcp");
        value["source_ports"] = ports.clone();
        value["destination_ports"] = ports.clone();
        rules.push(value);
    }
    let candidate = compile_candidate(&config("enabled", json!(rules), json!([]))?)?;
    assert_eq!(candidate.rule_count(), MAX_CANDIDATE_RULES);
    assert!(candidate.rules_text().len() < MAX_CANDIDATE_BYTES);
    assert_eq!(
        candidate
            .rules_text()
            .lines()
            .filter(|line| line.contains("tl.r."))
            .count(),
        128 * 2 * 4 * 4
    );
    Ok(())
}
