//! Ordinary-user laboratory preparation and mock-only recovery modelling. No live PF executor.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde_json::{Value, json};
use thiserror::Error;

pub(crate) const ANCHOR: &str = "com.apple/tunlatch-pf-lab-20261102";
pub(crate) const LIVE_DIR: &str = "/var/root/tunlatch-pf-lab-20261102";
pub(crate) const RULES: &str =
    "block drop out quick on ! lo0 all label \"tunlatch-pf-lab-20261102:deny\"\n";
const PFCTL: &str = "/sbin/pfctl";
const PURPOSE: &str = "tunlatch-pf-lab-only-v1";
const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum LabError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error("refused: {0}")]
    Refused(&'static str),
}

pub(crate) type Result<T> = std::result::Result<T, LabError>;

/// Closed command vocabulary: no caller-provided arguments or PF input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    ParentAnchors,
    LeafRules,
    ClearLeafRules,
}

impl Operation {
    pub(crate) fn args(self) -> &'static [&'static str] {
        match self {
            Self::ParentAnchors => &["-a", "com.apple", "-s", "Anchors"],
            Self::LeafRules => &["-a", ANCHOR, "-s", "rules"],
            Self::ClearLeafRules => &["-a", ANCHOR, "-F", "rules"],
        }
    }

    pub(crate) fn json(self) -> Value {
        json!({"executable": PFCTL, "argv": self.args(), "stdin": null})
    }
}

/// Intentionally no live executor exists. Flags cannot confer execution or recovery authority.
pub(crate) fn live_rejection(live_pf: bool, approved_isolated_lab: bool) -> LabError {
    if !live_pf || !approved_isolated_lab {
        return LabError::Refused("live PF is disabled; opt-in flags do not create authority");
    }
    LabError::Refused(
        "live PF is disabled: approved-binary bootstrap, atomic ownership and bounded supervision are not implemented",
    )
}

fn private_directory(path: &Path, uid: u32) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(LabError::Refused(
            "requires an absolute, real, owned 0700 directory",
        ));
    }
    Ok(())
}

fn new_file(path: &Path, mode: u32) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?)
}

pub(crate) fn plan() -> Value {
    json!({
        "schema_version": 1,
        "purpose": PURPOSE,
        "result": "prepared_not_executed",
        "anchor": ANCHOR,
        "candidate_live_directory": LIVE_DIR,
        "live_pf_available": false,
        "privileged_staging_available": false,
        "pf_enable_references_created": 0,
        "proposed_exclusive_resources": [ANCHOR, LIVE_DIR],
        "candidate_claim_queries": [Operation::ParentAnchors.json(), Operation::LeafRules.json()],
        "recovery": {
            "status": "disabled_not_recovery_qualified",
            "candidate_steps": [Operation::LeafRules.json(), Operation::ClearLeafRules.json(), Operation::LeafRules.json()],
            "blockers": ["protected approved binary bootstrap", "atomic kernel ownership/CAS", "bounded process and pipe reclamation"]
        },
        "candidate_block_probe": {
            "executable": PFCTL,
            "argv": ["-a", ANCHOR, "-f", "-"],
            "stdin": RULES,
            "implemented_live_entry": false,
            "requires": ["W07 approval", "kernel reachability and skip/quick preflight", "armed offline recovery"]
        },
        "not_implemented": ["protected binary bootstrap", "atomic kernel ownership", "bounded process supervisor", "root hook insertion", "automatic apply", "utun creation/reuse", "state deletion", "enable references", "packet capture"],
        "safety": "No live PF executor or privileged staging is implemented. Mock success never qualifies recovery or kernel ownership."
    })
}

/// No executor is accepted by preparation: it cannot query or mutate PF.
pub(crate) fn prepare_bundle(path: &Path) -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        return Err(LabError::Refused("prepare must run as the ordinary user"));
    }
    private_directory(path, nix::unistd::geteuid().as_raw())?;
    if fs::read_dir(path)?.next().is_some() {
        return Err(LabError::Refused("preparation directory must be empty"));
    }
    let executable = std::env::current_exe()?;
    // This copies an ordinary user's opened path snapshot, not an attestation of a loaded image.
    // No root entrypoint is allowed to consume this path or promote it into trusted recovery.
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(executable)?;
    let metadata = source.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_BINARY_BYTES {
        return Err(LabError::Refused(
            "preparation executable must be a bounded regular file",
        ));
    }
    let mut copy = new_file(&path.join("pf-lab"), 0o700)?;
    let bytes = io::copy(
        &mut Read::by_ref(&mut source).take(MAX_BINARY_BYTES + 1),
        &mut copy,
    )?;
    let after = source.metadata()?;
    if bytes != metadata.len()
        || bytes > MAX_BINARY_BYTES
        || after.len() != metadata.len()
        || after.mtime() != metadata.mtime()
        || after.mtime_nsec() != metadata.mtime_nsec()
    {
        return Err(LabError::Refused(
            "preparation executable changed during copying",
        ));
    }
    copy.sync_all()?;
    let mut plan_file = new_file(&path.join("plan.json"), 0o600)?;
    serde_json::to_writer_pretty(&mut plan_file, &plan())?;
    plan_file.write_all(b"\n")?;
    plan_file.sync_all()?;
    let mut rules_file = new_file(&path.join("block-probe.pf"), 0o600)?;
    rules_file.write_all(RULES.as_bytes())?;
    rules_file.sync_all()?;
    let mut recovery = new_file(&path.join("RECOVERY.txt"), 0o600)?;
    recovery.write_all(RECOVERY_TEXT.as_bytes())?;
    recovery.sync_all()?;
    File::open(path)?.sync_all()?;
    Ok(())
}

pub(crate) const RECOVERY_TEXT: &str = "TunLatch PF laboratory preparation v2\n\
LIVE RECOVERY IS DISABLED. This bundle is not qualified to modify PF or restore networking.\n\
It contains a standalone PREPARATION tool, a fixed command CANDIDATE and a mock model.\n\
No live PF executor, root-private bootstrap, kernel ownership CAS or bounded process supervisor exists.\n\
The candidate leaf is com.apple/tunlatch-pf-lab-20261102; no claim of current ownership is made.\n\
claim-recovery and live recover requests always refuse, even when both opt-in flags are supplied.\n\
Do not apply the candidate rule or request W07 approval before real recovery and experiment drivers are implemented.\n\
Do not treat fixed names, labels, receipts, a project lock or repeated reads as kernel ownership.\n\
No global flush/disable/state deletion/reference release is provided.\n";
