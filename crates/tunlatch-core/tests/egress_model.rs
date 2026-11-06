//! Synthetic model checks only: no OS administrator authentication, PF or real traffic.

use std::error::Error;
use std::io;

use serde_json::{Value, json};
use tunlatch_core::egress::{
    AddressFamily, AdminObservation, ApprovalChannel, ApprovalPreview, Authorizations,
    BindingSelection, EgressError, EgressLocation, EgressModel, EgressPolicyDraft,
    MAX_AUTHORIZATION_INPUT_BYTES, ObservationWindow, ProfileObservation, ProfileSnapshot,
    SocketOwner, UidDecision,
};
use tunlatch_core::policy::{ConfigV2, PacketDescriptor, PacketProtocol};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn field<'a>(v: &'a Value, key: &str) -> TestResult<&'a Value> {
    v.get(key)
        .ok_or_else(|| io::Error::other(format!("missing fixture {key}")).into())
}
fn text(v: &Value) -> TestResult<&str> {
    v.as_str()
        .ok_or_else(|| io::Error::other("expected text").into())
}
fn config(rules: Value) -> TestResult<ConfigV2> {
    Ok(ConfigV2::parse_json(&serde_json::to_vec(&json!({
        "schema_version":2,"desired":"enabled","rules":rules,"direct_exceptions":[]
    }))?)?)
}
fn candidates(uid: u32) -> Value {
    json!({"proxy_uid_grants":[{"id":"proxy_root","uid":uid,"protocols":["tcp","udp"],
        "families":["ipv4","ipv6"],"egress_profile":"primary"}],"system_profiles":[]})
}
fn draft(value: Value, rules: Value) -> TestResult<EgressPolicyDraft> {
    Ok(EgressPolicyDraft::new(
        config(rules)?,
        Authorizations::parse_json(&serde_json::to_vec(&value)?)?,
    )?)
}
fn scope() -> ProfileObservation {
    ProfileObservation {
        profile_id: "primary".into(),
        scope_digest: [3; 32],
        scope_generation: 3,
        attachment_epoch: 7,
        families: vec![AddressFamily::Ipv4, AddressFamily::Ipv6],
    }
}
fn snapshot_with(
    sequence: u64,
    now: u64,
    scopes: Vec<ProfileObservation>,
) -> TestResult<ProfileSnapshot> {
    Ok(ProfileSnapshot::new(
        [2; 16],
        sequence,
        ObservationWindow {
            started_at: now,
            finished_at: now,
            valid_until: now + 5000,
        },
        scopes,
        now,
    )?)
}
fn snapshot(sequence: u64, now: u64) -> TestResult<ProfileSnapshot> {
    snapshot_with(sequence, now, vec![scope()])
}
fn admin(p: &ApprovalPreview) -> AdminObservation {
    AdminObservation {
        channel: ApprovalChannel::Administrator,
        service_epoch: p.service_epoch(),
        operation_id: p.operation_id(),
        nonce: p.nonce(),
        request_digest: *p.request_digest().as_bytes(),
        expected_generation: p.expected_generation(),
        action: "replace_policy".into(),
        expires_at_ms: p.expires_at_ms(),
    }
}
fn prepare(
    model: &mut EgressModel,
    value: Value,
    rules: Value,
    seq: u64,
    now: u64,
    op: u8,
) -> TestResult<ApprovalPreview> {
    Ok(model.prepare(
        draft(value, rules)?,
        &snapshot(seq, now)?,
        BindingSelection::unavailable(),
        [op; 16],
        [op; 32],
        now,
    )?)
}
fn installed(value: Value, rules: Value) -> TestResult<EgressModel> {
    let mut model = EgressModel::new([1; 16], 8)?;
    let p = prepare(&mut model, value, rules, 1, 100, 1)?;
    model.confirm_model(
        admin(&p),
        &snapshot(2, 101)?,
        BindingSelection::unavailable(),
        101,
    )?;
    Ok(model)
}
fn physical() -> EgressLocation<'static> {
    EgressLocation::Physical {
        profile_id: "primary",
        attachment_epoch: 7,
    }
}
fn packet(address: &str, udp: bool, port: u16) -> TestResult<PacketDescriptor> {
    let protocol = if udp {
        PacketProtocol::Udp {
            source_port: 42000,
            destination_port: port,
        }
    } else {
        PacketProtocol::Tcp {
            source_port: 42000,
            destination_port: port,
        }
    };
    Ok(PacketDescriptor::new(address.parse()?, protocol)?)
}

#[test]
fn executes_30_tracked_authorization_and_digest_vectors() -> TestResult {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures/egress-drafts.json"))?;
    let cases = field(&fixtures, "cases")?
        .as_array()
        .ok_or_else(|| io::Error::other("cases"))?;
    assert_eq!(cases.len(), 30);
    for case in cases {
        let id = text(field(case, "id")?)?;
        let kind = text(field(case, "kind")?)?;
        let input = field(case, "input")?;
        let format = case
            .get("format")
            .and_then(Value::as_str)
            .unwrap_or("object");
        let bytes = if format == "object" {
            serde_json::to_vec(input)?
        } else {
            text(input)?.as_bytes().to_vec()
        };
        let parsed = if format == "toml" {
            Authorizations::parse_toml(&bytes)
        } else {
            Authorizations::parse_json(&bytes)
        };
        let expected = field(case, "expect")?;
        if let Some(error) = expected.get("error") {
            let failure = parsed
                .err()
                .ok_or_else(|| io::Error::other(format!("{id}: invalid accepted")))?;
            assert_eq!(failure.code().to_string(), text(error)?, "{id}");
            let direct = if format == "toml" {
                toml::from_str::<Authorizations>(std::str::from_utf8(&bytes)?).is_err()
            } else {
                serde_json::from_slice::<Authorizations>(&bytes).is_err()
            };
            // Raw whitespace limits belong to byte parsers, not a generic Serde visitor.
            if bytes.len() <= MAX_AUTHORIZATION_INPUT_BYTES {
                assert!(direct, "{id}: Serde bypass");
            }
        } else {
            let parsed = parsed.map_err(|e| io::Error::other(format!("{id}: {e}")))?;
            assert_eq!(
                Authorizations::parse_toml(parsed.to_toml()?.as_bytes())?,
                parsed,
                "{id}"
            );
            assert_eq!(
                serde_json::from_slice::<Authorizations>(parsed.canonical_json())?,
                parsed
            );
            if kind == "authorization_digest" {
                let hex = parsed
                    .canonical_json()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                assert_eq!(hex, text(field(expected, "canonical_hex")?)?, "{id}");
                assert_eq!(
                    parsed.digest().to_string(),
                    text(field(expected, "sha256")?)?,
                    "{id}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn diagnostics_and_decoding_remain_bounded_and_do_not_echo_unknown_input() -> TestResult {
    for input in [
        br#"{"proxy_uid_grants":[],"system_profiles":[],"proxy_uid_grants":[]}"#.as_slice(),
        br#"{"proxy_uid_grants":[],"system_profiles":[],"private-secret":true}"#.as_slice(),
        br#"{"proxy_uid_grants":[],"system_profiles":[],"x":"\ud800"}"#.as_slice(),
    ] {
        let e = Authorizations::parse_json(input)
            .err()
            .ok_or_else(|| io::Error::other("invalid accepted"))?;
        assert!(!e.to_string().contains("private-secret"));
        assert!(e.to_string().len() < 512);
    }
    let mut bytes = vec![b' '; MAX_AUTHORIZATION_INPUT_BYTES];
    bytes.push(b' ');
    assert!(Authorizations::parse_json(&bytes).is_err());
    assert!(Authorizations::parse_json(&[0xff]).is_err());
    assert!(Authorizations::parse_json(b"{} {}").is_err());
    Ok(())
}

#[test]
fn all_candidate_changes_change_identity_without_implicitly_approving_them() -> TestResult {
    let original = candidates(0);
    let a = Authorizations::parse_json(&serde_json::to_vec(&original)?)?;
    for (key, value) in [
        ("id", json!("other")),
        ("uid", json!(501)),
        ("protocols", json!(["tcp"])),
        ("families", json!(["ipv4"])),
        ("egress_profile", json!("secondary")),
    ] {
        let mut changed = original.clone();
        changed["proxy_uid_grants"][0][key] = value;
        let b = Authorizations::parse_json(&serde_json::to_vec(&changed)?)?;
        assert_ne!(a.digest(), b.digest());
        assert_ne!(
            a.proxy_uid_grants()[0].digest()?,
            b.proxy_uid_grants()[0].digest()?
        );
    }
    assert_eq!(
        Authorizations::parse_json(Authorizations::empty().canonical_json())?,
        Authorizations::empty()
    );
    let model = EgressModel::new([1; 16], 1)?;
    assert!(model.checked_policy().is_none());
    Ok(())
}

#[test]
fn global_ids_and_scope_count_cannot_be_split_across_draft_sections() -> TestResult {
    let rule = json!({"id":"proxy_root","priority":0,"action":"allow","destination":"any","protocol":"any"});
    assert!(draft(candidates(0), json!([rule])).is_err());
    let mut value = candidates(0);
    value["proxy_uid_grants"] = json!([]);
    value["system_profiles"] = json!([]);
    for i in 0..4 {
        let mut item = candidates(0)["proxy_uid_grants"][0].clone();
        item["id"] = json!(format!("u{i}"));
        item["egress_profile"] = json!(format!("p{i}"));
        value["proxy_uid_grants"]
            .as_array_mut()
            .ok_or_else(|| io::Error::other("array"))?
            .push(item);
    }
    value["system_profiles"] = json!([{"id":"s","families":["ipv4"],"recipes":["dhcpv4_client"],"egress_profile":"fifth"}]);
    assert!(draft(value, json!([])).is_err());
    Ok(())
}

#[test]
fn root_tcp_udp_dual_stack_can_match_without_selected_tun_and_without_target_whitelists()
-> TestResult {
    let mut model = installed(candidates(0), json!([]))?;
    assert_eq!(model.generation(), 9);
    let profiles = snapshot(2, 101)?;
    for address in [
        "203.0.113.80",
        "192.0.2.53",
        "192.168.1.20",
        "2001:db8::80",
        "fe80::20",
    ] {
        for udp in [false, true] {
            for port in [53, 443, 12345] {
                let p = packet(address, udp, port)?;
                let decision = model.evaluate_uid(
                    Some(&p),
                    physical(),
                    SocketOwner::Known(0),
                    &profiles,
                    102,
                )?;
                let UidDecision::Eligible(required) = decision else {
                    return Err(io::Error::other("eligible missing").into());
                };
                assert_eq!(required.grant().uid(), 0);
                assert_eq!(required.generation(), 9);
                assert_eq!(required.attachment_epoch(), 7);
                assert_eq!(required.valid_until_ms(), 5101);
            }
        }
    }
    Ok(())
}

#[test]
fn missing_other_and_unknown_uid_never_inherit_root_permission() -> TestResult {
    let mut model = installed(candidates(0), json!([]))?;
    let p = packet("203.0.113.80", false, 443)?;
    for owner in [
        SocketOwner::Unknown,
        SocketOwner::Known(501),
        SocketOwner::Known(u32::MAX),
    ] {
        assert!(matches!(
            model.evaluate_uid(Some(&p), physical(), owner, &snapshot(2, 101)?, 102)?,
            UidDecision::NeedsOtherAuthorization
        ));
    }
    assert!(matches!(
        model.evaluate_uid(
            Some(&p),
            EgressLocation::Other,
            SocketOwner::Known(0),
            &snapshot(2, 101)?,
            102
        )?,
        UidDecision::NeedsOtherAuthorization
    ));
    let mut no_record = EgressModel::new([1; 16], 8)?;
    assert!(matches!(
        no_record.evaluate_uid(
            Some(&p),
            physical(),
            SocketOwner::Known(0),
            &snapshot(2, 101)?,
            102
        ),
        Err(EgressError::NoCheckedPolicy)
    ));
    Ok(())
}

#[test]
fn non_tcp_udp_does_not_get_uid_permission_even_for_root() -> TestResult {
    let mut model = installed(candidates(0), json!([]))?;
    for (address, protocol) in [
        (
            "203.0.113.1",
            PacketProtocol::Icmp {
                message_type: 8,
                code: 0,
            },
        ),
        (
            "fe80::1",
            PacketProtocol::Icmpv6 {
                message_type: 135,
                code: 0,
            },
        ),
        ("203.0.113.1", PacketProtocol::Other(47)),
    ] {
        let p = PacketDescriptor::new(address.parse()?, protocol)?;
        assert!(matches!(
            model.evaluate_uid(
                Some(&p),
                physical(),
                SocketOwner::Known(0),
                &snapshot(2, 101)?,
                102
            )?,
            UidDecision::NeedsOtherAuthorization
        ));
    }
    Ok(())
}

#[test]
fn ordinary_block_and_incomplete_packets_override_uid_while_allow_still_needs_it() -> TestResult {
    let blocked =
        json!([{"id":"deny","priority":0,"action":"block","destination":"any","protocol":"any"}]);
    let p = packet("203.0.113.80", false, 443)?;
    let mut model = installed(candidates(0), blocked)?;
    for p in [Some(&p), None] {
        assert!(matches!(
            model.evaluate_uid(
                p,
                physical(),
                SocketOwner::Known(0),
                &snapshot(2, 101)?,
                102
            )?,
            UidDecision::BlockedByOrdinaryRule
        ));
    }
    let allow =
        json!([{"id":"permit","priority":0,"action":"allow","destination":"any","protocol":"any"}]);
    let mut model = installed(serde_json::to_value(Authorizations::empty())?, allow)?;
    assert!(matches!(
        model.evaluate_uid(
            Some(&p),
            physical(),
            SocketOwner::Known(0),
            &snapshot(2, 101)?,
            102
        )?,
        UidDecision::NeedsOtherAuthorization
    ));
    Ok(())
}

#[test]
fn physical_loopback_destination_is_not_a_loopback_interface_exception() -> TestResult {
    let mut model = installed(candidates(0), json!([]))?;
    for address in ["127.0.0.1", "::1"] {
        let p = packet(address, false, 443)?;
        assert!(matches!(
            model.evaluate_uid(
                Some(&p),
                physical(),
                SocketOwner::Known(0),
                &snapshot(2, 101)?,
                102
            )?,
            UidDecision::BlockedByOrdinaryRule
        ));
    }
    Ok(())
}

#[test]
fn confirmation_is_exact_one_shot_admin_report_not_proxy_uid_approval() -> TestResult {
    for mutation in 0..9 {
        let mut model = installed(candidates(0), json!([]))?;
        let preview = prepare(&mut model, candidates(501), json!([]), 3, 102, 2)?;
        let mut reported = admin(&preview);
        match mutation {
            0 => reported.channel = ApprovalChannel::Query,
            1 => reported.service_epoch = [5; 16],
            2 => reported.operation_id = [5; 16],
            3 => reported.nonce = [5; 32],
            4 => reported.request_digest = [5; 32],
            5 => reported.expected_generation = 7,
            6 => reported.action = "arbitrary_command".into(),
            7 => reported.expires_at_ms += 1,
            _ => reported.action = "install".into(),
        }
        assert!(
            model
                .confirm_model(
                    reported,
                    &snapshot(4, 103)?,
                    BindingSelection::unavailable(),
                    103
                )
                .is_err()
        );
        assert_eq!(model.generation(), 9);
        assert_eq!(
            model
                .checked_policy()
                .ok_or_else(|| io::Error::other("lost policy"))?
                .draft()
                .authorizations()
                .proxy_uid_grants()[0]
                .uid(),
            0
        );
        assert_eq!(
            model.confirm_model(
                admin(&preview),
                &snapshot(4, 103)?,
                BindingSelection::unavailable(),
                103
            ),
            Err(EgressError::Replay)
        );
    }
    Ok(())
}

#[test]
fn expired_and_replayed_confirmations_do_not_advance_generation() -> TestResult {
    for now in [60100, 60101] {
        let mut model = EgressModel::new([1; 16], 8)?;
        let preview = prepare(&mut model, candidates(0), json!([]), 1, 100, 1)?;
        assert_eq!(
            model.confirm_model(
                admin(&preview),
                &snapshot(2, now)?,
                BindingSelection::unavailable(),
                now
            ),
            Err(EgressError::ConfirmationMismatch)
        );
        assert_eq!(model.generation(), 8);
    }
    let mut model = installed(candidates(0), json!([]))?;
    let preview = prepare(&mut model, candidates(501), json!([]), 3, 102, 2)?;
    model.confirm_model(
        admin(&preview),
        &snapshot(4, 103)?,
        BindingSelection::unavailable(),
        103,
    )?;
    assert_eq!(
        model.confirm_model(
            admin(&preview),
            &snapshot(5, 104)?,
            BindingSelection::unavailable(),
            104
        ),
        Err(EgressError::Replay)
    );
    Ok(())
}

#[test]
fn changed_physical_identity_or_family_must_be_reconfirmed() -> TestResult {
    for mutation in 0..5 {
        let mut model = installed(candidates(0), json!([]))?;
        let preview = prepare(&mut model, candidates(501), json!([]), 3, 102, 2)?;
        let mut changed = scope();
        match mutation {
            0 => changed.attachment_epoch += 1,
            1 => changed.scope_generation += 1,
            2 => changed.scope_digest = [4; 32],
            3 => changed.profile_id = "other".into(),
            _ => changed.families = vec![AddressFamily::Ipv4],
        }
        assert!(
            model
                .confirm_model(
                    admin(&preview),
                    &snapshot_with(4, 103, vec![changed])?,
                    BindingSelection::unavailable(),
                    103
                )
                .is_err()
        );
        assert_eq!(model.generation(), 9);
    }
    Ok(())
}

#[test]
fn vanished_expired_wrong_attachment_and_changed_scope_cannot_match_uid() -> TestResult {
    let p = packet("203.0.113.1", false, 443)?;
    let mut model = installed(candidates(0), json!([]))?;
    assert!(
        model
            .evaluate_uid(
                Some(&p),
                EgressLocation::Physical {
                    profile_id: "primary",
                    attachment_epoch: 8
                },
                SocketOwner::Known(0),
                &snapshot(2, 101)?,
                102
            )
            .is_err()
    );
    assert!(
        model
            .evaluate_uid(
                Some(&p),
                physical(),
                SocketOwner::Known(0),
                &snapshot(2, 101)?,
                5101
            )
            .is_err()
    );
    assert!(
        model
            .evaluate_uid(
                Some(&p),
                physical(),
                SocketOwner::Known(0),
                &snapshot_with(3, 103, vec![])?,
                103
            )
            .is_err()
    );
    let mut changed = scope();
    changed.scope_digest = [4; 32];
    assert!(
        model
            .evaluate_uid(
                Some(&p),
                physical(),
                SocketOwner::Known(0),
                &snapshot_with(4, 104, vec![changed])?,
                104
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn collector_sequence_epoch_and_time_cannot_regress_or_extend_a_replayed_snapshot() -> TestResult {
    for mutation in 0..4 {
        let mut model = EgressModel::new([1; 16], 8)?;
        let preview = prepare(&mut model, candidates(0), json!([]), 1, 100, 1)?;
        let report = match mutation {
            0 => snapshot(1, 100)?,
            1 => snapshot(1, 101)?, // same sequence with a newer deadline is still a replay
            2 => snapshot(2, 99)?,
            _ => ProfileSnapshot::new(
                [9; 16],
                2,
                ObservationWindow {
                    started_at: 101,
                    finished_at: 101,
                    valid_until: 5101,
                },
                vec![scope()],
                101,
            )?,
        };
        assert_eq!(
            model.confirm_model(
                admin(&preview),
                &report,
                BindingSelection::unavailable(),
                101
            ),
            Err(EgressError::StaleObservation)
        );
    }
    let mut model = installed(candidates(0), json!([]))?;
    let p = packet("203.0.113.1", false, 443)?;
    assert!(
        model
            .evaluate_uid(
                Some(&p),
                physical(),
                SocketOwner::Known(0),
                &snapshot(2, 101)?,
                100
            )
            .is_err()
    );
    assert!(
        model
            .evaluate_uid(
                Some(&p),
                physical(),
                SocketOwner::Known(0),
                &snapshot(1, 101)?,
                102
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn malformed_or_missing_scope_observations_are_rejected() -> TestResult {
    for mutation in 0..6 {
        let mut s = scope();
        match mutation {
            0 => s.scope_digest = [0; 32],
            1 => s.scope_generation = 0,
            2 => s.attachment_epoch = 0,
            3 => s.families.clear(),
            4 => s.families = vec![AddressFamily::Ipv4; 2],
            _ => s.profile_id = "bad name".into(),
        }
        assert!(snapshot_with(1, 100, vec![s]).is_err());
    }
    assert!(snapshot_with(1, 100, vec![scope(), scope()]).is_err());
    assert!(snapshot_with(1, 100, vec![scope(); 5]).is_err());
    for window in [
        ObservationWindow {
            started_at: 101,
            finished_at: 100,
            valid_until: 5100,
        },
        ObservationWindow {
            started_at: 100,
            finished_at: 101,
            valid_until: 5100,
        },
        ObservationWindow {
            started_at: 100,
            finished_at: 100,
            valid_until: 100,
        },
        ObservationWindow {
            started_at: 100,
            finished_at: 100,
            valid_until: 5101,
        },
    ] {
        assert!(ProfileSnapshot::new([2; 16], 1, window, vec![scope()], 100).is_err());
    }
    let mut model = EgressModel::new([1; 16], 8)?;
    assert!(
        model
            .prepare(
                draft(candidates(0), json!([]))?,
                &snapshot_with(1, 100, vec![])?,
                BindingSelection::unavailable(),
                [1; 16],
                [1; 32],
                100
            )
            .is_err()
    );
    let mut s = scope();
    s.families = vec![AddressFamily::Ipv4];
    assert!(
        model
            .prepare(
                draft(candidates(0), json!([]))?,
                &snapshot_with(2, 101, vec![s])?,
                BindingSelection::unavailable(),
                [1; 16],
                [1; 32],
                101
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn cancel_and_failed_attempts_preserve_policy_but_retire_operation_and_nonce() -> TestResult {
    let mut model = installed(candidates(0), json!([]))?;
    let _ = prepare(&mut model, candidates(501), json!([]), 3, 102, 2)?;
    let failure = prepare(&mut model, candidates(501), json!([]), 3, 102, 3)
        .err()
        .ok_or_else(|| io::Error::other("second preview accepted"))?;
    assert_eq!(
        failure.downcast_ref::<EgressError>(),
        Some(&EgressError::PendingConfirmation)
    );
    model.cancel_preview();
    for (operation, nonce) in [([2; 16], [3; 32]), ([3; 16], [2; 32])] {
        assert!(matches!(
            model.prepare(
                draft(candidates(501), json!([]))?,
                &snapshot(4, 103)?,
                BindingSelection::unavailable(),
                operation,
                nonce,
                103
            ),
            Err(EgressError::Replay)
        ));
    }
    assert_eq!(model.generation(), 9);
    Ok(())
}

#[test]
fn explicit_replacement_revokes_old_uid_without_erasing_other_checked_data() -> TestResult {
    let mut model = installed(candidates(0), json!([]))?;
    let preview = prepare(
        &mut model,
        json!({"proxy_uid_grants":[],"system_profiles":[]}),
        json!([]),
        3,
        102,
        2,
    )?;
    model.confirm_model(
        admin(&preview),
        &snapshot(4, 103)?,
        BindingSelection::unavailable(),
        103,
    )?;
    let p = packet("203.0.113.1", false, 443)?;
    assert_eq!(model.generation(), 10);
    assert!(matches!(
        model.evaluate_uid(
            Some(&p),
            physical(),
            SocketOwner::Known(0),
            &snapshot(4, 103)?,
            104
        )?,
        UidDecision::NeedsOtherAuthorization
    ));
    assert!(model.checked_policy().is_some());
    Ok(())
}

#[test]
fn bounded_replay_capacity_and_generation_overflow_preserve_existing_policy() -> TestResult {
    let mut model = installed(candidates(0), json!([]))?;
    for operation in 2..=64 {
        let _ = prepare(
            &mut model,
            candidates(501),
            json!([]),
            u64::from(operation) + 1,
            100 + u64::from(operation),
            operation,
        )?;
        model.cancel_preview();
    }
    let failure = prepare(&mut model, candidates(501), json!([]), 100, 200, 65)
        .err()
        .ok_or_else(|| io::Error::other("capacity ignored"))?;
    assert_eq!(
        failure.downcast_ref::<EgressError>(),
        Some(&EgressError::SessionCapacity)
    );
    assert_eq!(model.generation(), 9);
    let mut model = EgressModel::new([1; 16], u64::MAX)?;
    let p = prepare(&mut model, candidates(0), json!([]), 1, 100, 1)?;
    assert_eq!(
        model.confirm_model(
            admin(&p),
            &snapshot(2, 101)?,
            BindingSelection::unavailable(),
            101
        ),
        Err(EgressError::GenerationConflict)
    );
    assert!(model.checked_policy().is_none());
    Ok(())
}

#[test]
fn exact_request_identity_covers_policy_generation_scopes_and_authorizations() -> TestResult {
    let mut identities = Vec::new();
    for mutation in 0..6 {
        let mut model = EgressModel::new([1; 16], if mutation == 1 { 9 } else { 8 })?;
        let mut scopes = scope();
        if mutation == 2 {
            scopes.attachment_epoch = 8;
        }
        if mutation == 3 {
            scopes.scope_digest = [8; 32];
        }
        let rules = if mutation == 4 {
            json!([{"id":"deny","priority":0,"action":"block","destination":"any","protocol":"any"}])
        } else {
            json!([])
        };
        let value = if mutation == 5 {
            candidates(501)
        } else {
            candidates(0)
        };
        let p = model.prepare(
            draft(value, rules)?,
            &snapshot_with(1, 100, vec![scopes])?,
            BindingSelection::unavailable(),
            [1; 16],
            [1; 32],
            100,
        )?;
        assert!(!identities.contains(&p.request_digest()));
        identities.push(p.request_digest());
    }
    Ok(())
}

#[test]
fn narrowed_uid_family_and_protocol_selections_are_enforced() -> TestResult {
    let mut selected = candidates(501);
    selected["proxy_uid_grants"][0]["protocols"] = json!(["udp"]);
    selected["proxy_uid_grants"][0]["families"] = json!(["ipv6"]);
    let mut model = installed(selected, json!([]))?;
    for (address, udp, uid, eligible) in [
        ("2001:db8::1", true, 501, true),
        ("2001:db8::1", false, 501, false),
        ("203.0.113.1", true, 501, false),
        ("2001:db8::1", true, 0, false),
    ] {
        let p = packet(address, udp, 443)?;
        assert_eq!(
            matches!(
                model.evaluate_uid(
                    Some(&p),
                    physical(),
                    SocketOwner::Known(uid),
                    &snapshot(2, 101)?,
                    102
                )?,
                UidDecision::Eligible(_)
            ),
            eligible
        );
    }
    Ok(())
}

#[test]
fn maintenance_candidates_are_bound_to_confirmation_but_cannot_authorize_uid_traffic() -> TestResult
{
    let base = json!({"proxy_uid_grants":[],"system_profiles":[{"id":"s","families":["ipv4","ipv6"],
        "recipes":["dhcpv4_client","dhcpv6_client","ipv6_host_control","related_icmp_errors"],"egress_profile":"primary"}]});
    let a = Authorizations::parse_json(&serde_json::to_vec(&base)?)?;
    let mut changed = base.clone();
    changed["system_profiles"][0]["recipes"] = json!(["dhcpv4_client"]);
    let b = Authorizations::parse_json(&serde_json::to_vec(&changed)?)?;
    assert_ne!(
        a.system_profiles()[0].digest()?,
        b.system_profiles()[0].digest()?
    );
    let mut model = installed(base, json!([]))?;
    let p = packet("255.255.255.255", true, 67)?;
    assert!(matches!(
        model.evaluate_uid(
            Some(&p),
            physical(),
            SocketOwner::Known(0),
            &snapshot(2, 101)?,
            102
        )?,
        UidDecision::NeedsOtherAuthorization
    ));
    let mut s = scope();
    s.families = vec![AddressFamily::Ipv4];
    let mut model = EgressModel::new([1; 16], 8)?;
    assert!(
        model
            .prepare(
                EgressPolicyDraft::new(config(json!([]))?, a)?,
                &snapshot_with(1, 100, vec![s])?,
                BindingSelection::unavailable(),
                [1; 16],
                [1; 32],
                100
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn disabled_intent_stays_unmanaged_without_a_pf_disable_claim() -> TestResult {
    let config = ConfigV2::parse_json(
        br#"{"schema_version":2,"desired":"disabled","rules":[],"direct_exceptions":[]}"#,
    )?;
    let mut model = EgressModel::new([1; 16], 8)?;
    let preview = model.prepare(
        EgressPolicyDraft::new(config, Authorizations::empty())?,
        &snapshot(1, 100)?,
        BindingSelection::unavailable(),
        [1; 16],
        [1; 32],
        100,
    )?;
    model.confirm_model(
        admin(&preview),
        &snapshot(2, 101)?,
        BindingSelection::unavailable(),
        101,
    )?;
    assert!(matches!(
        model.evaluate_uid(
            None,
            EgressLocation::Other,
            SocketOwner::Unknown,
            &snapshot(2, 101)?,
            102
        )?,
        UidDecision::Unmanaged
    ));
    Ok(())
}

fn synthetic_binding(
    fd: u32,
    sequence: u64,
) -> TestResult<tunlatch_core::binding::VerifiedCurrentBinding> {
    use tunlatch_core::binding::{
        CandidateSnapshot, CodeIdentity, ControlSocketObservation, CorrelatedBinding,
        InterfaceObservation, OwnershipMatch, OwnershipMethod, OwnershipSample, ProcessObservation,
        ProxyCore, ProxySelection, ReportCompleteness, SnapshotCompleteness, SnapshotStamp,
        UntrustedOwnershipReport,
    };
    use tunlatch_core::status::{InterfaceAddress, NetworkInterface};
    let stamp = SnapshotStamp {
        observer_epoch: [7; 16],
        generation: 4,
    };
    let interface = InterfaceObservation {
        observation_id: 7,
        interface: NetworkInterface {
            name: "utun4".into(),
            index: 19,
            up: true,
            loopback: false,
            addresses: vec![InterfaceAddress {
                address: "fe80::1".parse()?,
                scope_id: 19,
            }],
        },
    };
    let candidates = CandidateSnapshot::new(
        stamp,
        10,
        SnapshotCompleteness::Complete,
        vec![interface.clone()],
    )?;
    let selection =
        ProxySelection::new(ProxyCore::SingBox, CodeIdentity::WholeImageSha256([9; 32]))?;
    let sample = OwnershipSample {
        snapshot: stamp,
        interface,
        process: ProcessObservation {
            pid: 420,
            birth_seconds: 1800000000,
            birth_microseconds: 123,
            uid: 0,
            core: ProxyCore::SingBox,
            code_identity: CodeIdentity::WholeImageSha256([9; 32]),
        },
        socket: ControlSocketObservation {
            fd,
            method: OwnershipMethod::HolderFdQuery,
            controller_name: "com.apple.net.utun_control".into(),
            controller_id: 4,
            control_unit: 5,
            opaque_socket: 500,
            opaque_pcb: 600,
            associated_interface_name: "utun4".into(),
        },
    };
    let report = UntrustedOwnershipReport {
        collection_sequence: sequence,
        completeness: ReportCompleteness::Complete,
        window: ObservationWindow {
            started_at: 9,
            finished_at: 12,
            valid_until: 20,
        },
        matches: vec![OwnershipMatch {
            before: sample.clone(),
            after: sample,
        }],
    };
    let correlation =
        CorrelatedBinding::verify_report(&candidates, &selection, report.clone(), 12)?;
    let intent = correlation.confirmation_intent();
    let mut fresh = report;
    fresh.collection_sequence += 1;
    Ok(correlation.confirm(
        intent,
        CorrelatedBinding::verify_report(&candidates, &selection, fresh, 12)?,
        12,
    )?)
}

#[test]
fn checked_binding_identity_includes_direct_fd_and_is_bound_to_the_exact_preview() -> TestResult {
    let first = BindingSelection::from_checked(&synthetic_binding(12, 1)?)?;
    let resampled = BindingSelection::from_checked(&synthetic_binding(12, 3)?)?;
    let changed = BindingSelection::from_checked(&synthetic_binding(13, 1)?)?;
    assert_eq!(first, resampled);
    assert_ne!(first, changed);
    assert_ne!(first, BindingSelection::unavailable());
    for current in [changed, BindingSelection::unavailable()] {
        let mut model = EgressModel::new([1; 16], 8)?;
        let preview = model.prepare(
            draft(candidates(0), json!([]))?,
            &snapshot(1, 100)?,
            first,
            [1; 16],
            [1; 32],
            100,
        )?;
        assert_eq!(
            model.confirm_model(admin(&preview), &snapshot(2, 101)?, current, 101),
            Err(EgressError::ScopeChanged)
        );
        assert!(model.checked_policy().is_none());
    }
    let mut model = EgressModel::new([1; 16], 8)?;
    let preview = model.prepare(
        draft(candidates(0), json!([]))?,
        &snapshot(1, 100)?,
        first,
        [1; 16],
        [1; 32],
        100,
    )?;
    model.confirm_model(admin(&preview), &snapshot(2, 101)?, resampled, 101)?;
    assert_eq!(
        model
            .checked_policy()
            .ok_or_else(|| io::Error::other("no policy"))?
            .binding(),
        first
    );
    let mut other = EgressModel::new([1; 16], 8)?;
    let p = prepare(&mut other, candidates(0), json!([]), 1, 100, 1)?;
    assert_ne!(preview.request_digest(), p.request_digest());
    Ok(())
}

#[test]
fn target_candidates_also_require_complete_current_profile_family_coverage() -> TestResult {
    let config = ConfigV2::parse_json(&serde_json::to_vec(
        &json!({"schema_version":2,"desired":"enabled","rules":[],
        "direct_exceptions":[{"id":"upstream","purpose":"proxy_upstream","description":"Synthetic only",
            "egress_profile":"primary","destination":"203.0.113.10/32","protocol":"tcp",
            "destination_ports":[{"start":443,"end":443}]}]}),
    )?)?;
    let proposed = EgressPolicyDraft::new(config, Authorizations::empty())?;
    let mut s = scope();
    s.families = vec![AddressFamily::Ipv6];
    let mut model = EgressModel::new([1; 16], 8)?;
    assert!(matches!(
        model.prepare(
            proposed,
            &snapshot_with(1, 100, vec![s])?,
            BindingSelection::unavailable(),
            [1; 16],
            [1; 32],
            100
        ),
        Err(EgressError::ProfileUnavailable)
    ));
    assert!(model.checked_policy().is_none());
    Ok(())
}
