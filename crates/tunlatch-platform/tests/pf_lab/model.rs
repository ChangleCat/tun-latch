//! Pure mock observations only. This file is not included in the standalone executable.

use serde_json::{Value, json};

use crate::pf_lab::{ANCHOR, LabError, Operation, RULES, Result};

pub(crate) const LEAF: &str = "tunlatch-pf-lab-20261102";
const PURPOSE: &str = "tunlatch-pf-lab-only-v1";

pub(crate) struct Output {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Test-only observation interface. There is deliberately no OS executor implementation.
pub(crate) trait Executor {
    fn execute(&mut self, operation: Operation) -> Result<Output>;
}

fn validate_approval_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(LabError::Refused(
            "approval ID must be 1-64 ASCII identifier characters",
        ));
    }
    Ok(())
}

/// Empty or valid single-component anchor names only; malformed output is never absence.
pub(crate) fn leaf_absent(parent_output: &str) -> Result<bool> {
    let mut absent = true;
    for line in parent_output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.len() > 128
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
        {
            return Err(LabError::Refused(
                "unknown parent-anchor output; cannot establish ownership",
            ));
        }
        if line == LEAF {
            absent = false;
        }
    }
    Ok(absent)
}

pub(crate) fn model_claim_receipt(
    executor: &mut impl Executor,
    approval_id: &str,
) -> Result<Value> {
    validate_approval_id(approval_id)?;
    let parent = executor.execute(Operation::ParentAnchors)?;
    if !leaf_absent(&parent.stdout)? {
        return Err(LabError::Refused(
            "leaf already exists; refusing adoption or overwrite",
        ));
    }
    let leaf = executor.execute(Operation::LeafRules)?;
    if !leaf.stdout.trim().is_empty() {
        return Err(LabError::Refused("leaf is not empty; refusing adoption"));
    }
    Ok(json!({
        "schema_version": 1,
        "purpose": PURPOSE,
        "anchor": ANCHOR,
        "approval_id": approval_id,
        "phase": "model_only",
        "references_created": 0,
        "stateful_rules_allowed": false,
        "query_warnings": [!parent.stderr.is_empty(), !leaf.stderr.is_empty()]
    }))
}

fn validate_receipt(value: &Value) -> Result<()> {
    let object = value
        .as_object()
        .ok_or(LabError::Refused("ownership receipt is not an object"))?;
    if object.len() != 8
        || value["schema_version"] != 1
        || value["purpose"] != PURPOSE
        || value["anchor"] != ANCHOR
        || value["phase"] != "model_only"
        || value["references_created"] != 0
        || value["stateful_rules_allowed"] != false
        || !value["query_warnings"]
            .as_array()
            .is_some_and(|warnings| warnings.len() == 2 && warnings.iter().all(Value::is_boolean))
    {
        return Err(LabError::Refused(
            "receipt is foreign, malformed or outside leaf-only recovery",
        ));
    }
    validate_approval_id(
        value["approval_id"]
            .as_str()
            .ok_or(LabError::Refused("receipt approval ID missing"))?,
    )
}

/// Mock-only sequence. A read/clear race remains; this never qualifies a live cleanup.
pub(crate) fn model_recovery(executor: &mut impl Executor, receipt: &Value) -> Result<Value> {
    validate_receipt(receipt)?;
    let before = executor.execute(Operation::LeafRules)?;
    let has_rules = !before.stdout.trim().is_empty();
    if has_rules
        && (before.stdout.trim().lines().count() != 1
            || !before
                .stdout
                .split_whitespace()
                .eq(RULES.split_whitespace()))
    {
        return Err(LabError::Refused(
            "leaf has foreign or unrecognized rules; refusing cleanup",
        ));
    }
    let cleared = if has_rules {
        Some(executor.execute(Operation::ClearLeafRules)?)
    } else {
        None
    };
    let observed = executor.execute(Operation::LeafRules)?;
    if !observed.stdout.trim().is_empty() {
        return Err(LabError::Refused(
            "leaf is not empty after cleanup; receipt retained",
        ));
    }
    Ok(json!({
        "result": "model_observed_leaf_empty",
        "anchor": ANCHOR,
        "model_mutation_requested": has_rules,
        "live_authority": false,
        "kernel_ownership_proved": false,
        "protection_status": "not_established",
        "references_released": 0,
        "states_deleted": 0,
        "warnings_present": [!before.stderr.is_empty(), cleared.is_some_and(|output| !output.stderr.is_empty()), !observed.stderr.is_empty()]
    }))
}
