//! Pure preparation, refusal and leaf-only recovery tests. No live executor is constructed.

mod pf_lab;
#[path = "pf_lab/model.rs"]
mod pf_lab_model;

use std::collections::VecDeque;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use pf_lab::{LabError, Operation, Result};
use pf_lab_model::{Executor, Output};
use serde_json::{Value, json};

#[derive(Default)]
struct Fake {
    calls: Vec<Operation>,
    outputs: VecDeque<Result<Output>>,
}

impl Fake {
    fn responses(stdout: &[&str]) -> Self {
        Self {
            calls: Vec::new(),
            outputs: stdout
                .iter()
                .map(|output| {
                    Ok(Output {
                        stdout: (*output).into(),
                        stderr: String::new(),
                    })
                })
                .collect(),
        }
    }
}

impl Executor for Fake {
    fn execute(&mut self, operation: Operation) -> Result<Output> {
        self.calls.push(operation);
        self.outputs
            .pop_front()
            .ok_or(LabError::Refused("unexpected fake executor call"))?
    }
}

fn receipt() -> Result<Value> {
    let mut fake = Fake::responses(&["", ""]);
    pf_lab_model::model_claim_receipt(&mut fake, "W07-reviewed-record")
}

#[test]
fn default_plan_is_explicitly_unexecuted_and_contains_no_global_cleanup() {
    let plan = pf_lab::plan();
    assert_eq!(plan["result"], "prepared_not_executed");
    assert_eq!(plan["pf_enable_references_created"], 0);
    assert_eq!(
        plan["candidate_block_probe"]["implemented_live_entry"],
        false
    );
    for operation in [
        Operation::ParentAnchors,
        Operation::LeafRules,
        Operation::ClearLeafRules,
    ] {
        assert_eq!(operation.json()["executable"], "/sbin/pfctl");
        assert!(!operation.args().contains(&"-d"));
        assert!(!operation.args().contains(&"-E"));
        assert!(!operation.args().contains(&"-X"));
        assert!(!operation.args().contains(&"-k"));
        assert!(!operation.args().contains(&"all"));
    }
    assert!(pf_lab::RECOVERY_TEXT.contains("LIVE RECOVERY IS DISABLED"));
}

#[test]
fn preparation_writes_an_offline_bundle_without_an_executor()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    pf_lab::prepare_bundle(directory.path())?;
    assert!(directory.path().join("pf-lab").is_file());
    assert_eq!(
        fs::read_to_string(directory.path().join("block-probe.pf"))?,
        pf_lab::RULES
    );
    assert!(fs::read_to_string(directory.path().join("RECOVERY.txt"))?.contains(pf_lab::ANCHOR));
    let plan: Value = serde_json::from_slice(&fs::read(directory.path().join("plan.json"))?)?;
    assert_eq!(plan["result"], "prepared_not_executed");
    assert!(pf_lab::prepare_bundle(directory.path()).is_err());
    Ok(())
}

#[test]
fn preparation_refuses_public_symlink_and_nonempty_directories()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
    assert!(pf_lab::prepare_bundle(directory.path()).is_err());
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    fs::write(directory.path().join("unrelated"), "preserve")?;
    assert!(pf_lab::prepare_bundle(directory.path()).is_err());
    assert_eq!(
        fs::read_to_string(directory.path().join("unrelated"))?,
        "preserve"
    );
    let link = directory.path().join("alias");
    std::os::unix::fs::symlink(directory.path(), &link)?;
    assert!(pf_lab::prepare_bundle(&link).is_err());
    Ok(())
}

#[test]
fn every_live_request_is_rejected_even_when_both_flags_are_present() {
    for options in [(false, false), (true, false), (false, true), (true, true)] {
        assert!(matches!(
            pf_lab::live_rejection(options.0, options.1),
            LabError::Refused(_)
        ));
    }
}

#[test]
fn approval_injection_is_rejected_before_querying() {
    for id in [
        "",
        "../../other",
        "x; echo unsafe",
        "$(command)",
        "a\nb",
        "a b",
        "é",
    ] {
        let mut fake = Fake::default();
        assert!(pf_lab_model::model_claim_receipt(&mut fake, id).is_err());
        assert!(fake.calls.is_empty());
    }
}

#[test]
fn claim_refuses_preexisting_leaf_without_adopting_or_clearing_it() {
    let mut fake = Fake::responses(&[pf_lab_model::LEAF]);
    assert!(pf_lab_model::model_claim_receipt(&mut fake, "W07").is_err());
    assert_eq!(fake.calls, [Operation::ParentAnchors]);
}

#[test]
fn unknown_parent_output_is_not_empty_absence() {
    for output in [
        "parent/child",
        "anchor \"foreign\"",
        "unexpected error: denied",
        "../escape",
    ] {
        let mut fake = Fake::responses(&[output]);
        assert!(pf_lab_model::model_claim_receipt(&mut fake, "W07").is_err());
        assert_eq!(fake.calls, [Operation::ParentAnchors]);
    }
}

#[test]
fn claim_refuses_nonempty_leaf_without_a_mutation() {
    let mut fake = Fake::responses(&["other-owned-anchor\n", "block out all\n"]);
    assert!(pf_lab_model::model_claim_receipt(&mut fake, "W07").is_err());
    assert_eq!(fake.calls, [Operation::ParentAnchors, Operation::LeafRules]);
}

#[test]
fn recovery_rejects_foreign_or_expanded_receipts_before_any_call() -> Result<()> {
    let base = receipt()?;
    for (key, value) in [
        ("anchor", json!("com.apple/unrelated")),
        ("schema_version", json!(2)),
        ("references_created", json!(1)),
        ("stateful_rules_allowed", json!(true)),
        ("phase", json!("unconfirmed")),
        ("approval_id", json!("a; -F all")),
        ("query_warnings", json!(["raw untrusted instructions"])),
        ("extra", json!("-F all")),
    ] {
        let mut altered = base.clone();
        altered[key] = value;
        let mut fake = Fake::default();
        assert!(pf_lab_model::model_recovery(&mut fake, &altered).is_err());
        assert!(fake.calls.is_empty());
    }
    Ok(())
}

#[test]
fn model_requests_fixed_leaf_steps_without_kernel_ownership_authority() -> Result<()> {
    let mut fake = Fake::responses(&[pf_lab::RULES, "", ""]);
    let outcome = pf_lab_model::model_recovery(&mut fake, &receipt()?)?;
    assert_eq!(
        fake.calls,
        [
            Operation::LeafRules,
            Operation::ClearLeafRules,
            Operation::LeafRules
        ]
    );
    assert_eq!(
        Operation::ClearLeafRules.args(),
        ["-a", pf_lab::ANCHOR, "-F", "rules"]
    );
    assert_eq!(outcome["result"], "model_observed_leaf_empty");
    assert_eq!(outcome["states_deleted"], 0);
    assert_eq!(outcome["model_mutation_requested"], true);
    assert_eq!(outcome["references_released"], 0);
    assert_eq!(outcome["protection_status"], "not_established");
    assert_eq!(outcome["live_authority"], false);
    assert_eq!(outcome["kernel_ownership_proved"], false);
    Ok(())
}

#[test]
fn command_failure_preserves_unknown_and_does_not_attempt_global_fallback() -> Result<()> {
    let mut fake = Fake::responses(&[pf_lab::RULES]);
    fake.outputs
        .push_back(Err(LabError::Refused("injected failure")));
    assert!(pf_lab_model::model_recovery(&mut fake, &receipt()?).is_err());
    assert_eq!(
        fake.calls,
        [Operation::LeafRules, Operation::ClearLeafRules]
    );
    Ok(())
}

#[test]
fn nonempty_postcondition_is_a_failure() -> Result<()> {
    let mut fake = Fake::responses(&[pf_lab::RULES, "", pf_lab::RULES]);
    assert!(pf_lab_model::model_recovery(&mut fake, &receipt()?).is_err());
    assert_eq!(
        fake.calls,
        [
            Operation::LeafRules,
            Operation::ClearLeafRules,
            Operation::LeafRules
        ]
    );
    Ok(())
}

#[test]
fn recovery_refuses_foreign_rules_in_the_named_leaf_without_clearing() -> Result<()> {
    for text in [
        "block out all",
        "pass out all",
        "unknown output",
        "block out\npass in",
    ] {
        let mut fake = Fake::responses(&[text]);
        assert!(pf_lab_model::model_recovery(&mut fake, &receipt()?).is_err());
        assert_eq!(fake.calls, [Operation::LeafRules]);
    }
    Ok(())
}

#[test]
fn already_empty_recovery_is_idempotent_without_a_mutation() -> Result<()> {
    let mut fake = Fake::responses(&["", ""]);
    let outcome = pf_lab_model::model_recovery(&mut fake, &receipt()?)?;
    assert_eq!(outcome["model_mutation_requested"], false);
    assert_eq!(fake.calls, [Operation::LeafRules, Operation::LeafRules]);
    Ok(())
}
