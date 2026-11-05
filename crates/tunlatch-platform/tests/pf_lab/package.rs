//! An ordinary-user package inventory and auditor. It never grants deployment authority.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::bootstrap::Acl;
use super::ledger::{Ledger, Operation, State};
use super::native_files::NativePathInspection;
use super::{LabError, Result};

const FILES: [&str; 4] = ["pf-lab", "plan.json", "block-probe.pf", "RECOVERY.txt"];
const MAX_FILE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    size: u64,
    mode: u32,
    sha256: [u8; 32],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    purpose: String,
    live_available: bool,
    session: [u8; 32],
    files: Vec<Entry>,
}

#[derive(Debug, Serialize)]
pub(crate) struct Audit {
    pub(crate) result: &'static str,
    pub(crate) files_checked: usize,
    pub(crate) journal: String,
    pub(crate) live_authority: bool,
    pub(crate) recovery_qualified: bool,
}

fn directory(path: &Path) -> Result<File> {
    if !path.is_absolute() || nix::unistd::geteuid().is_root() {
        return Err(LabError::Refused(
            "ordinary-user absolute bundle path required",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_dir()
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.mode() & 0o7777 != 0o700
        || NativePathInspection.acl(&file) != Acl::Empty
    {
        return Err(LabError::Refused(
            "bundle directory is not private or ACL is unknown",
        ));
    }
    Ok(file)
}

fn open(dir: &File, name: &str, create: bool) -> Result<File> {
    let flags = if create {
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL
    } else {
        OFlag::O_RDONLY
    } | OFlag::O_NOFOLLOW
        | OFlag::O_CLOEXEC
        | OFlag::O_NONBLOCK;
    Ok(openat(dir, name, flags, Mode::from_bits_truncate(0o600))
        .map_err(std::io::Error::from)?
        .into())
}

fn read_entry(dir: &File, name: &str, mode: u32) -> Result<(Entry, Vec<u8>)> {
    let mut file = open(dir, name, false)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != nix::unistd::geteuid().as_raw()
        || before.mode() & 0o7777 != mode
        || before.len()
            > if name == "package.json" {
                16384
            } else {
                MAX_FILE
            }
        || NativePathInspection.acl(&file) != Acl::Empty
    {
        return Err(LabError::Refused(
            "bundle member type, owner, mode, links, size or ACL",
        ));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(before.len() + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err(LabError::Refused("bundle member changed while reading"));
    }
    Ok((
        Entry {
            name: name.into(),
            size: before.len(),
            mode,
            sha256: Sha256::digest(&bytes).into(),
        },
        bytes,
    ))
}

/// Inventory only. The candidate program is not executed as root, and a hash does not certify
/// either its publisher or its loaded image. Source files can be malicious but self-consistent.
pub(crate) fn seal(path: &Path) -> Result<()> {
    let dir = directory(path)?;
    let mut session = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut session)?;
    if session == [0; 32] {
        return Err(LabError::Refused("empty random session"));
    }
    let files = FILES
        .iter()
        .map(|name| {
            read_entry(&dir, name, if *name == "pf-lab" { 0o700 } else { 0o600 }).map(|v| v.0)
        })
        .collect::<Result<Vec<_>>>()?;
    let manifest = Manifest {
        purpose: "tunlatch-ordinary-preparation".into(),
        live_available: false,
        session,
        files,
    };
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    let plan = Sha256::digest(&bytes).into();
    let mut ledger = Ledger::create(dir.try_clone()?, session, plan)?;
    ledger.begin(Operation::StageProgram)?;
    let publish = (|| {
        let mut output = open(&dir, "package.json", true)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        dir.sync_all()?;
        let (_, observed) = read_entry(&dir, "package.json", 0o600)?;
        if observed != bytes {
            return Err(LabError::Refused("manifest changed during publication"));
        }
        ledger.observed()?;
        ledger.close()?;
        Ok(())
    })();
    if publish.is_err() && matches!(ledger.state(), State::Intent(_)) {
        // Best effort only: failed logging leaves the original intent (or incomplete bytes)
        // on disk. It never resets the index or claims the failed publication did not occur.
        let _ = ledger.unknown();
    }
    publish
}

/// Opens the held directory and exact files, checks path ACLs/hashes and reads the ledger.
/// Unresolved intents cannot be cleared by audit, and no PF cleanup is attempted.
pub(crate) fn audit(path: &Path) -> Result<Audit> {
    let dir = directory(path)?;
    let (_, bytes) = read_entry(&dir, "package.json", 0o600)?;
    let manifest: Manifest = serde_json::from_slice(&bytes)?;
    if manifest.purpose != "tunlatch-ordinary-preparation"
        || manifest.live_available
        || manifest.session == [0; 32]
        || manifest.files.len() != FILES.len()
    {
        return Err(LabError::Refused(
            "wrong package purpose, scope or authority",
        ));
    }
    for (expected, entry) in FILES.iter().zip(&manifest.files) {
        // Validate closed name/mode vocabulary BEFORE a pathname is used.
        let mode = if *expected == "pf-lab" { 0o700 } else { 0o600 };
        if entry.name != *expected || entry.mode != mode {
            return Err(LabError::Refused("unexpected package member"));
        }
        let (actual, _) = read_entry(&dir, expected, mode)?;
        if actual.size != entry.size || actual.sha256 != entry.sha256 {
            return Err(LabError::Refused("package member hash or length mismatch"));
        }
    }
    let ledger = Ledger::reopen(dir)?;
    if ledger.identity() != (manifest.session, Sha256::digest(&bytes).into()) {
        return Err(LabError::Refused("journal and manifest identities differ"));
    }
    let closed = ledger.state() == State::Closed;
    Ok(Audit {
        result: if closed {
            "ordinary_bundle_verified"
        } else {
            "unsettled_manual_reconciliation"
        },
        files_checked: FILES.len(),
        journal: format!("{:?}", ledger.state()),
        live_authority: false,
        recovery_qualified: false,
    })
}
