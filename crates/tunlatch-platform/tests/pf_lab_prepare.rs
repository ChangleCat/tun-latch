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
    let audit = pf_lab::package::audit(directory.path())?;
    assert_eq!(audit.result, "ordinary_bundle_verified");
    assert_eq!(audit.files_checked, 4);
    assert!(!audit.live_authority);
    assert!(!audit.recovery_qualified);
    assert!(pf_lab::prepare_bundle(directory.path()).is_err());
    Ok(())
}

#[test]
fn native_acl_reads_real_private_files_and_refuses_nonempty_or_unlinked_objects()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use pf_lab::bootstrap::Acl;
    use pf_lab::native_files::NativePathInspection;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("owned-data");
    fs::write(&path, "data")?;
    let file = fs::File::open(&path)?;
    assert_eq!(NativePathInspection.acl(&file), Acl::Empty);
    let uid = nix::unistd::geteuid().as_raw().to_string();
    let entries = [exacl::AclEntry::allow_user(&uid, exacl::Perm::READ, None)];
    exacl::setfacl(&[&path], &entries, None)?;
    assert_eq!(NativePathInspection.acl(&file), Acl::Present);
    exacl::setfacl(&[&path], &[], None)?;
    fs::remove_file(&path)?;
    fs::write(&path, "replacement")?;
    assert_eq!(NativePathInspection.acl(&file), Acl::Unknown);
    Ok(())
}

#[test]
fn native_parent_chain_rejects_user_writable_and_symlinked_paths()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use pf_lab::native_files::ObservedChain;
    assert!(ObservedChain::open(std::path::Path::new("relative")).is_err());
    assert!(ObservedChain::open(std::path::Path::new("/private/../private")).is_err());
    let directory = tempfile::tempdir()?;
    assert!(ObservedChain::open(directory.path()).is_err());
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink("/", &alias)?;
    assert!(ObservedChain::open(&alias).is_err());
    // This observes only a fixed system parent; it is not the private deployment directory.
    let chain = ObservedChain::open(std::path::Path::new("/private"))?;
    chain.recheck()?;
    Ok(())
}

fn ledger_directory() -> std::result::Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    Ok(directory)
}

#[test]
fn durable_intent_survives_controller_loss_and_cannot_be_adopted()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use pf_lab::ledger::{Ledger, Operation as Op, State};
    let directory = ledger_directory()?;
    let mut ledger = Ledger::create(fs::File::open(directory.path())?, [1; 32], [2; 32])?;
    ledger.begin(Op::WriteFilter)?;
    assert!(ledger.begin(Op::ChangeHook).is_err());
    assert!(ledger.close().is_err());
    assert!(Ledger::reopen(fs::File::open(directory.path())?).is_err());
    drop(ledger); // Deliberate simulated controller loss; no Drop rollback.
    let mut resumed = Ledger::reopen(fs::File::open(directory.path())?)?;
    assert_eq!(resumed.state(), State::Intent(Op::WriteFilter));
    assert!(resumed.observed().is_err());
    assert!(resumed.begin(Op::WriteFilter).is_err());
    assert!(resumed.close().is_err());
    drop(resumed);
    assert!(Ledger::create(fs::File::open(directory.path())?, [3; 32], [4; 32]).is_err());
    Ok(())
}

#[test]
fn ledger_unknown_and_clean_close_remain_distinct_after_restart()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use pf_lab::ledger::{Ledger, Operation as Op, State};
    for unknown in [false, true] {
        let directory = ledger_directory()?;
        let mut ledger = Ledger::create(fs::File::open(directory.path())?, [1; 32], [2; 32])?;
        ledger.begin(Op::AcquireReference)?;
        if unknown {
            ledger.unknown()?;
            assert!(ledger.begin(Op::ReleaseReference).is_err());
        } else {
            ledger.observed()?;
            ledger.close()?;
        }
        drop(ledger);
        let reopened = Ledger::reopen(fs::File::open(directory.path())?)?;
        assert_eq!(
            reopened.state(),
            if unknown {
                State::Unknown(Op::AcquireReference)
            } else {
                State::Closed
            }
        );
    }
    Ok(())
}

#[test]
fn ledger_rejects_corruption_partial_records_and_excessive_input()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use pf_lab::ledger::{Ledger, Operation as Op};
    use std::io::Write;
    for damage in 0..5 {
        let directory = ledger_directory()?;
        let mut ledger = Ledger::create(fs::File::open(directory.path())?, [1; 32], [2; 32])?;
        ledger.begin(Op::WriteFilter)?;
        drop(ledger);
        let path = directory.path().join("session.journal");
        let mut bytes = fs::read(&path)?;
        match damage {
            0 => {
                bytes.pop();
            }
            1 => {
                bytes[0] ^= 1;
            }
            2 => {
                bytes[110] ^= 1;
            }
            3 => {
                bytes.extend([0; 74]);
            }
            _ => {
                bytes.resize(104 + 129 * 74, 0);
            }
        }
        fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)?
            .write_all(&bytes)?;
        assert!(Ledger::reopen(fs::File::open(directory.path())?).is_err());
    }
    Ok(())
}

#[test]
fn journal_replacement_poisoning_prevents_later_operations()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use pf_lab::ledger::{Ledger, Operation as Op, State};
    let directory = ledger_directory()?;
    let mut ledger = Ledger::create(fs::File::open(directory.path())?, [1; 32], [2; 32])?;
    let path = directory.path().join("session.journal");
    fs::rename(&path, directory.path().join("preserved-original"))?;
    fs::write(&path, "foreign")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    assert!(ledger.begin(Op::WriteFilter).is_err());
    assert_eq!(ledger.state(), State::StorageUnknown);
    assert!(ledger.begin(Op::ChangeHook).is_err());
    assert_eq!(fs::read(&path)?, b"foreign");
    Ok(())
}

#[test]
fn journal_capacity_cannot_be_reset_by_closing_or_reopening()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use pf_lab::ledger::{Ledger, Operation as Op};
    let directory = ledger_directory()?;
    let mut ledger = Ledger::create(fs::File::open(directory.path())?, [1; 32], [2; 32])?;
    for _ in 0..64 {
        ledger.begin(Op::WriteFilter)?;
        ledger.observed()?;
    }
    assert!(ledger.begin(Op::WriteFilter).is_err());
    assert!(ledger.close().is_err());
    drop(ledger);
    let mut reopened = Ledger::reopen(fs::File::open(directory.path())?)?;
    assert!(reopened.begin(Op::WriteFilter).is_err());
    Ok(())
}

#[test]
fn package_audit_rejects_tampering_and_foreign_authority_fields()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    for damage in 0..4 {
        let directory = ledger_directory()?;
        pf_lab::prepare_bundle(directory.path())?;
        match damage {
            0 => fs::write(directory.path().join("block-probe.pf"), "pass all\n")?,
            1 => {
                let path = directory.path().join("package.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path)?)?;
                value["live_available"] = json!(true);
                fs::write(path, serde_json::to_vec(&value)?)?;
            }
            2 => {
                let path = directory.path().join("plan.json");
                fs::remove_file(&path)?;
                std::os::unix::fs::symlink("/dev/null", path)?;
            }
            _ => {
                let path = directory.path().join("package.json");
                let mut value: Value = serde_json::from_slice(&fs::read(&path)?)?;
                value["files"][0]["name"] = json!("../../foreign");
                fs::write(path, serde_json::to_vec(&value)?)?;
            }
        }
        assert!(pf_lab::package::audit(directory.path()).is_err());
    }
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
