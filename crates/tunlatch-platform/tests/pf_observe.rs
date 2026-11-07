//! Offline capture fixtures, never live PF queries or protection evidence.

use std::error::Error;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tunlatch_core::policy::ConfigV2;
use tunlatch_platform::pf_observe::{
    CaptureReason, CaptureVerdict, LiteralAnchor, PfCaptureObservation, PfObserveError,
    RootCallObservation, RuleTextComparison, verify_readonly_captures,
};
use tunlatch_platform::policy_compile::{PfCompileCandidate, compile_candidate};

type TestResult = Result<(), Box<dyn Error>>;

fn hash(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn candidate() -> Result<PfCompileCandidate, Box<dyn Error>> {
    Ok(compile_candidate(&ConfigV2::parse_json(
        br#"{"schema_version":2,"desired":"enabled","rules":[],"direct_exceptions":[]}"#,
    )?)?)
}

fn raw(query: &str, args: &[&str], stdout: &str) -> Value {
    json!({
        "query": query, "pfctl_argv": args, "reason": "Success", "stdout": stdout,
        "stderr": "", "truncated": false, "capture_failed": false,
        "parent_reaped": true, "pipes_closed": true, "command_tree_reclaimed": true,
        "diagnostic": "captured", "recognized_altq_notice": false,
        "stdout_sha256": hash(stdout), "stderr_sha256": hash(""),
    })
}

fn info(enabled: bool) -> String {
    let status = if enabled { "Enabled" } else { "Disabled" };
    let mut text = format!(
        "Status: {status} for 0 days 01:52:54          Debug: Urgent\n\n\
         State Table                          Total             Rate\n\
           current entries                        0\n"
    );
    for key in ["searches", "inserts", "removals"] {
        text.push_str(&format!("  {key} 0 0.0/s\n"));
    }
    text.push_str("Counters\n");
    for key in [
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
    ] {
        text.push_str(&format!("  {key} 0 0.0/s\n"));
    }
    text
}

fn fixture(candidate: &PfCompileCandidate) -> Vec<Value> {
    let rules = candidate
        .rules_text()
        .lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    vec![
        raw("Rules", &["-s", "rules"], "anchor \"test.anchor\" all\n"),
        raw("Nat", &["-s", "nat"], ""),
        raw("Anchors", &["-v", "-s", "Anchors"], "  test.anchor\n"),
        raw(
            "AnchorRules(Literal(\"test.anchor\"))",
            &["-a", "test.anchor", "-s", "rules"],
            &rules,
        ),
        raw(
            "AnchorNat(Literal(\"test.anchor\"))",
            &["-a", "test.anchor", "-s", "nat"],
            "",
        ),
        raw(
            "AnchorTables(Literal(\"test.anchor\"))",
            &["-a", "test.anchor", "-s", "Tables"],
            "",
        ),
        raw("Interfaces", &["-v", "-s", "Interfaces"], "ALL\nlo0\nen0\n"),
        raw("Info", &["-s", "info"], &info(true)),
        raw(
            "References",
            &["-s", "References"],
            "No pf starter references held\n",
        ),
        raw("Rules", &["-s", "rules"], "anchor \"test.anchor\" all\n"),
        raw("Nat", &["-s", "nat"], ""),
        raw(
            "References",
            &["-s", "References"],
            "No pf starter references held\n",
        ),
        raw("Anchors", &["-v", "-s", "Anchors"], "  test.anchor\n"),
    ]
}

fn set_output(record: &mut Value, field: &str, text: &str) {
    record[field] = json!(text);
    record[format!("{field}_sha256")] = json!(hash(text));
}

fn verify(
    candidate: &PfCompileCandidate,
    records: &[Value],
) -> Result<PfCaptureObservation, PfObserveError> {
    let bytes = records.iter().map(Value::to_string).collect::<Vec<_>>();
    let files = bytes.iter().map(String::as_bytes).collect::<Vec<_>>();
    verify_readonly_captures(
        candidate,
        &LiteralAnchor::new("test.anchor")?,
        &files,
        100,
        101,
        10,
    )
}

#[test]
fn complete_text_match_remains_unknown_with_missing_counters_explicit() -> TestResult {
    let candidate = candidate()?;
    let report = verify(&candidate, &fixture(&candidate))?;
    assert_eq!(report.verdict, CaptureVerdict::Unknown);
    assert_eq!(report.captured_pf_enabled, Some(true));
    assert_eq!(report.root_call, RootCallObservation::DirectLiteralCall);
    assert_eq!(report.rule_text, RuleTextComparison::ExactRenderedText);
    assert_eq!(report.rules.len(), 4);
    assert_eq!(report.rules[0].label.as_deref(), Some("tl.loopback.v4"));
    assert!(report.rules.iter().all(|rule| rule.counters.is_none()));
    for reason in [
        CaptureReason::UnauthenticatedCapture,
        CaptureReason::NonAtomicReads,
        CaptureReason::ExecutionPositionUnproven,
        CaptureReason::CountersUnavailable,
    ] {
        assert!(report.reasons.contains(&reason));
    }
    Ok(())
}

#[test]
fn known_verbose_counter_line_is_optional_and_not_interpreted_as_encryption() -> TestResult {
    let candidate = candidate()?;
    let mut records = fixture(&candidate);
    let text = records[3]["stdout"]
        .as_str()
        .ok_or("missing rules")?
        .lines()
        .map(|line| format!("{line}\n [ Evaluations: 12 Packets: 9 Bytes: 543 States: 1 ]\n"))
        .collect::<String>();
    set_output(&mut records[3], "stdout", &text);
    let report = verify(&candidate, &records)?;
    assert_eq!(report.verdict, CaptureVerdict::Unknown);
    assert_eq!(report.rule_text, RuleTextComparison::ExactRenderedText);
    assert_eq!(
        report.rules[0]
            .counters
            .ok_or("counters unavailable")?
            .packets,
        9
    );
    assert!(!report.reasons.contains(&CaptureReason::CountersUnavailable));
    Ok(())
}

#[test]
fn truncated_failed_timeout_and_unreclaimed_reads_never_produce_usable_comparison() -> TestResult {
    let candidate = candidate()?;
    for (field, value, reason) in [
        ("truncated", json!(true), CaptureReason::TransportIncomplete),
        (
            "capture_failed",
            json!(true),
            CaptureReason::TransportIncomplete,
        ),
        (
            "parent_reaped",
            json!(false),
            CaptureReason::TransportIncomplete,
        ),
        (
            "pipes_closed",
            json!(false),
            CaptureReason::TransportIncomplete,
        ),
        (
            "command_tree_reclaimed",
            json!(false),
            CaptureReason::TransportIncomplete,
        ),
        ("reason", json!("Timeout"), CaptureReason::TimedOut),
        ("reason", json!("OutputLimit"), CaptureReason::OutputLimit),
        ("reason", json!("ExitFailure"), CaptureReason::CommandFailed),
    ] {
        let mut records = fixture(&candidate);
        records[3][field] = value;
        let report = verify(&candidate, &records)?;
        assert_eq!(report.verdict, CaptureVerdict::Unknown);
        assert_eq!(report.rule_text, RuleTextComparison::Unavailable);
        assert!(report.reasons.contains(&reason));
    }
    Ok(())
}

#[test]
fn exact_altq_notice_is_accepted_but_zero_exit_kernel_errors_remain_unknown() -> TestResult {
    let candidate = candidate()?;
    let notice = "No ALTQ support in kernel\nALTQ related functions disabled\n";
    let mut records = fixture(&candidate);
    set_output(&mut records[0], "stderr", notice);
    records[0]["recognized_altq_notice"] = json!(true);
    assert_eq!(
        verify(&candidate, &records)?.rule_text,
        RuleTextComparison::ExactRenderedText
    );
    for stderr in [
        "pfctl: DIOCGETRULES: Invalid argument\n",
        "No ALTQ support in kernel\n",
        "permission denied\n",
    ] {
        let mut records = fixture(&candidate);
        set_output(&mut records[0], "stderr", stderr);
        let report = verify(&candidate, &records)?;
        assert!(report.reasons.contains(&CaptureReason::UnexpectedStderr));
        assert_eq!(report.rule_text, RuleTextComparison::Unavailable);
    }
    Ok(())
}

#[test]
fn strict_schema_digests_duplicate_fields_and_nonclosed_commands_are_rejected() -> TestResult {
    let candidate = candidate()?;
    let original = fixture(&candidate);
    let mut records = original.clone();
    records[0]["authorized"] = json!(true);
    assert_eq!(
        verify(&candidate, &records),
        Err(PfObserveError::InvalidSchema)
    );
    let mut records = original.clone();
    records[0]["stdout_sha256"] = json!("0".repeat(64));
    assert_eq!(
        verify(&candidate, &records),
        Err(PfObserveError::DigestMismatch)
    );
    let mut records = original.clone();
    records[0]["pfctl_argv"] = json!(["-F", "all"]);
    assert_eq!(
        verify(&candidate, &records),
        Err(PfObserveError::InvalidQuery)
    );
    let mut records = original;
    records[3]["pfctl_argv"] = json!(["-a", "*", "-s", "rules"]);
    assert_eq!(
        verify(&candidate, &records),
        Err(PfObserveError::InvalidAnchor)
    );
    let duplicate = br#"{"query":"Rules","query":"Rules"}"#;
    assert_eq!(
        verify_readonly_captures(
            &candidate,
            &LiteralAnchor::new("test.anchor")?,
            &[duplicate],
            100,
            101,
            10
        ),
        Err(PfObserveError::InvalidSchema)
    );
    Ok(())
}

#[test]
fn legacy_capture_fields_are_supported_without_inventing_missing_timestamps() -> TestResult {
    let candidate = candidate()?;
    let mut records = fixture(&candidate);
    for record in &mut records {
        if let Some(object) = record.as_object_mut() {
            object.remove("diagnostic");
            object.remove("recognized_altq_notice");
        }
    }
    let report = verify(&candidate, &records)?;
    assert_eq!(report.rule_text, RuleTextComparison::ExactRenderedText);
    assert_eq!(report.verdict, CaptureVerdict::Unknown);
    Ok(())
}

#[test]
fn age_limit_is_exclusive_and_unset_future_or_stale_time_is_unknown() -> TestResult {
    let candidate = candidate()?;
    let records = fixture(&candidate)
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>();
    let files = records.iter().map(String::as_bytes).collect::<Vec<_>>();
    for (captured, now, age) in [(0, 101, 10), (102, 101, 10), (100, 110, 10), (100, 100, 0)] {
        let report = verify_readonly_captures(
            &candidate,
            &LiteralAnchor::new("test.anchor")?,
            &files,
            captured,
            now,
            age,
        )?;
        assert_eq!(report.verdict, CaptureVerdict::Unknown);
        assert!(
            report
                .reasons
                .contains(&CaptureReason::StaleOrFutureCapture)
        );
        assert_eq!(report.captured_pf_enabled, None);
    }
    Ok(())
}

#[test]
fn incomplete_or_reordered_schedule_cannot_hide_missing_independent_reads() -> TestResult {
    let candidate = candidate()?;
    let mut records = fixture(&candidate);
    records.pop();
    assert!(
        verify(&candidate, &records)?
            .reasons
            .contains(&CaptureReason::IncompleteSchedule)
    );
    let mut records = fixture(&candidate);
    records.swap(0, 1);
    assert_eq!(
        verify(&candidate, &records),
        Err(PfObserveError::InvalidQuery)
    );
    Ok(())
}

#[test]
fn captured_pf_disable_rule_changes_and_inventory_changes_are_mismatches() -> TestResult {
    let candidate = candidate()?;
    let mut records = fixture(&candidate);
    set_output(&mut records[7], "stdout", &info(false));
    let report = verify(&candidate, &records)?;
    assert_eq!(report.captured_pf_enabled, Some(false));
    assert_eq!(report.verdict, CaptureVerdict::Mismatch);
    assert!(report.reasons.contains(&CaptureReason::PfDisabled));
    let mut records = fixture(&candidate);
    set_output(&mut records[9], "stdout", "");
    assert!(
        verify(&candidate, &records)?
            .reasons
            .contains(&CaptureReason::RootRulesChanged)
    );
    let mut records = fixture(&candidate);
    set_output(&mut records[12], "stdout", "");
    assert!(
        verify(&candidate, &records)?
            .reasons
            .contains(&CaptureReason::AnchorInventoryChanged)
    );
    Ok(())
}

#[test]
fn root_quick_other_anchors_and_skipped_interfaces_never_establish_execution_position() -> TestResult
{
    let candidate = candidate()?;
    for root in [
        "pass out quick all\nanchor \"test.anchor\" all\n",
        "anchor \"other/*\" all\nanchor \"test.anchor\" all\n",
        "anchor \"test.anchor\" all\nanchor \"test.anchor\" all\n",
    ] {
        let mut records = fixture(&candidate);
        set_output(&mut records[0], "stdout", root);
        set_output(&mut records[9], "stdout", root);
        let report = verify(&candidate, &records)?;
        assert_eq!(report.root_call, RootCallObservation::Ambiguous);
        assert_eq!(report.verdict, CaptureVerdict::Unknown);
        assert!(report.reasons.contains(&CaptureReason::AmbiguousRootCalls));
    }
    let mut records = fixture(&candidate);
    set_output(&mut records[6], "stdout", "ALL\nlo0 (skip)\nen0\n");
    assert!(
        verify(&candidate, &records)?
            .reasons
            .contains(&CaptureReason::SkipInterface)
    );
    Ok(())
}

#[test]
fn complete_multiple_anchor_schedule_keeps_target_attribution_and_requires_all_detail_reads()
-> TestResult {
    let candidate = candidate()?;
    let mut records = fixture(&candidate);
    records.splice(
        3..3,
        [
            raw(
                "AnchorRules(Literal(\"other.anchor\"))",
                &["-a", "other.anchor", "-s", "rules"],
                "",
            ),
            raw(
                "AnchorNat(Literal(\"other.anchor\"))",
                &["-a", "other.anchor", "-s", "nat"],
                "",
            ),
            raw(
                "AnchorTables(Literal(\"other.anchor\"))",
                &["-a", "other.anchor", "-s", "Tables"],
                "",
            ),
        ],
    );
    for index in [2, 15] {
        set_output(
            &mut records[index],
            "stdout",
            "  other.anchor\n  test.anchor\n",
        );
    }
    for index in [0, 12] {
        set_output(
            &mut records[index],
            "stdout",
            "anchor \"other.anchor\" all\nanchor \"test.anchor\" all\n",
        );
    }
    let report = verify(&candidate, &records)?;
    assert_eq!(report.verdict, CaptureVerdict::Unknown);
    assert_eq!(report.root_call, RootCallObservation::Ambiguous);
    assert_eq!(report.rule_text, RuleTextComparison::ExactRenderedText);
    assert_eq!(report.rules.len(), 4);
    records.remove(3);
    assert!(
        verify(&candidate, &records)?
            .reasons
            .contains(&CaptureReason::IncompleteSchedule)
    );
    Ok(())
}

#[test]
fn candidate_text_is_not_kernel_semantics_and_unknown_formats_do_not_match() -> TestResult {
    let candidate = candidate()?;
    let mut records = fixture(&candidate);
    let text = records[3]["stdout"]
        .as_str()
        .ok_or("missing rules")?
        .replace("block drop out quick inet all", "pass out quick inet all");
    set_output(&mut records[3], "stdout", &text);
    let report = verify(&candidate, &records)?;
    assert_eq!(report.rule_text, RuleTextComparison::Different);
    assert_eq!(report.verdict, CaptureVerdict::Mismatch);
    let mut records = fixture(&candidate);
    set_output(
        &mut records[7],
        "stdout",
        &(info(true) + "unknown-counter 1 0.0/s\n"),
    );
    let report = verify(&candidate, &records)?;
    assert_eq!(report.captured_pf_enabled, None);
    assert!(report.reasons.contains(&CaptureReason::UnsupportedOutput));
    let mut records = fixture(&candidate);
    set_output(&mut records[3], "stdout", "pass out all\n [ unknown: 2 ]\n");
    assert_eq!(
        verify(&candidate, &records)?.rule_text,
        RuleTextComparison::Unavailable
    );
    Ok(())
}

#[test]
fn literal_locator_and_output_budgets_reject_injection_and_unbounded_input() -> TestResult {
    for name in [
        "*",
        "../x",
        "a/../b",
        "-x",
        "a\npass out all",
        "a\"",
        "a//b",
    ] {
        assert_eq!(LiteralAnchor::new(name), Err(PfObserveError::InvalidAnchor));
    }
    let candidate = candidate()?;
    let mut records = fixture(&candidate);
    set_output(&mut records[3], "stdout", &"x".repeat(65_537));
    assert_eq!(
        verify(&candidate, &records),
        Err(PfObserveError::LimitExceeded)
    );
    let too_large = vec![b' '; 524_289];
    assert_eq!(
        verify_readonly_captures(
            &candidate,
            &LiteralAnchor::new("test.anchor")?,
            &[&too_large],
            100,
            101,
            10
        ),
        Err(PfObserveError::LimitExceeded)
    );
    Ok(())
}
