//! Fixed protected experiment storage. This is not executable launch attestation.
//!
//! ACL inspection is path based and cannot exclude an ABA replacement by root. Callers must
//! independently establish the exclusive operator window and handle interrupted writes as unknown.

use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, fchmod, fstatat, mkdirat};
use sha2::{Digest, Sha256};

use super::bootstrap::{Acl, Error, Result};
use super::native_files::{NativePathInspection, ObservedChain};

const BASE: &str = "/private/var/root/tunlatch-pf-sync";
const PROGRAM: &str = "pf-lab-sync";
const EXECUTABLE: &str = "/private/var/root/tunlatch-pf-sync/pf-lab-sync";
const FAULT_BASE: &str = "/private/var/root/tunlatch-pf-sync-fault";
const FAULT_EXECUTABLE: &str = "/private/var/root/tunlatch-pf-sync-fault/pf-lab-sync";
const FLOW_BASE: &str = "/private/var/root/tunlatch-pf-first-flow";
const FLOW_PROGRAM: &str = "pf-lab-first-flow";
const FLOW_EXECUTABLE: &str = "/private/var/root/tunlatch-pf-first-flow/pf-lab-first-flow";
const MAX_PROGRAM: usize = 32 * 1024 * 1024;
const MAX_RECORD: usize = 1024 * 1024;

fn record_name(name: &str, layout: Layout) -> Result<()> {
    if matches!(
        name,
        "operator-manifest.json"
            | "session.json"
            | "prepare.json"
            | "before-stage.json"
            | "before-recovery.json"
            | "after-recovery.json"
            | "recovery-return.sha256"
            | "unrecognized-slot.json"
    ) || (layout == Layout::Fault
        && matches!(
            name,
            "fault-launch.json" | "fault-before-signal.json" | "fault-reaped.json"
        ))
        || (layout == Layout::Flow
            && matches!(
                name,
                "flow-plan.json"
                    | "enable-return.json"
                    | "release-return.json"
                    | "counters-before.json"
                    | "counters-after.json"
                    | "capture.json"
                    | "capture-ready.json"
                    | "capture.pcap"
            ))
    {
        Ok(())
    } else {
        Err(Error::Refused("unsupported record name"))
    }
}

fn open_file(dir: &File, name: &str, flags: OFlag, mode: u16) -> Result<File> {
    Ok(openat(
        dir,
        name,
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::from_bits_truncate(mode),
    )?
    .into())
}

fn identity(meta: &Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

fn unchanged(a: &Metadata, b: &Metadata) -> bool {
    identity(a) == identity(b)
        && a.uid() == b.uid()
        && a.mode() == b.mode()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && (a.mtime(), a.mtime_nsec(), a.ctime(), a.ctime_nsec())
            == (b.mtime(), b.mtime_nsec(), b.ctime(), b.ctime_nsec())
}

fn checked(file: &File, mode: u32, directory: bool) -> Result<Metadata> {
    let meta = file.metadata()?;
    if meta.uid() != 0
        || meta.mode() & 0o7777 != mode
        || if directory {
            !meta.is_dir()
        } else {
            !meta.is_file() || meta.nlink() != 1
        }
        || NativePathInspection.acl(file) != Acl::Empty
    {
        return Err(Error::Refused(
            "protected object owner, type, mode, links or ACL invalid",
        ));
    }
    Ok(meta)
}

fn read_bounded(file: &File, max: usize, mode: u32) -> Result<Vec<u8>> {
    let before = checked(file, mode, false)?;
    if before.len() > max as u64 {
        return Err(Error::Refused("protected file exceeds limit"));
    }
    let mut bytes = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut bytes)?;
    let after = checked(file, mode, false)?;
    if bytes.len() as u64 != before.len() || !unchanged(&before, &after) {
        return Err(Error::Refused("protected file changed during read"));
    }
    Ok(bytes)
}

pub(crate) struct Storage {
    chain: ObservedChain,
    program: File,
    layout: Layout,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Layout {
    Sync,
    Fault,
    Flow,
}

impl Layout {
    fn paths(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Self::Sync => (BASE, PROGRAM, EXECUTABLE),
            Self::Fault => (FAULT_BASE, PROGRAM, FAULT_EXECUTABLE),
            Self::Flow => (FLOW_BASE, FLOW_PROGRAM, FLOW_EXECUTABLE),
        }
    }
}

impl Storage {
    pub(crate) fn open() -> Result<Self> {
        if !nix::unistd::geteuid().is_root() {
            return Err(Error::Refused("requires root and fixed executable path"));
        }
        let executable = std::env::current_exe()?;
        let layout = if executable == Path::new(EXECUTABLE) {
            Layout::Sync
        } else if executable == Path::new(FAULT_EXECUTABLE) {
            Layout::Fault
        } else if executable == Path::new(FLOW_EXECUTABLE) {
            Layout::Flow
        } else {
            return Err(Error::Refused("requires root and fixed executable path"));
        };
        let (base, program_name, _) = layout.paths();
        let chain = ObservedChain::open(Path::new(base))?;
        checked(chain.directory()?, 0o700, true)?;
        let program = open_file(chain.directory()?, program_name, OFlag::O_RDONLY, 0)?;
        checked(&program, 0o500, false)?;
        let result = Self {
            chain,
            program,
            layout,
        };
        result.recheck()?;
        Ok(result)
    }

    pub(crate) fn is_fault(&self) -> bool {
        self.layout == Layout::Fault
    }

    pub(crate) fn executable(&self) -> &'static str {
        self.layout.paths().2
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        self.chain.recheck()?;
        let old = checked(self.chain.directory()?, 0o700, true)?;
        let (base, program_name, _) = self.layout.paths();
        let fresh = ObservedChain::open(Path::new(base))?;
        let new = checked(fresh.directory()?, 0o700, true)?;
        if identity(&old) != identity(&new) {
            return Err(Error::Refused("protected directory replaced"));
        }
        let held = checked(&self.program, 0o500, false)?;
        let named = open_file(fresh.directory()?, program_name, OFlag::O_RDONLY, 0)?;
        let named = checked(&named, 0o500, false)?;
        if !unchanged(&held, &named) {
            return Err(Error::Refused("protected executable replaced"));
        }
        Ok(())
    }

    pub(crate) fn program_digest(&self) -> Result<[u8; 32]> {
        self.recheck()?;
        // Open a second descriptor to avoid a shared seek position between digest calls.
        let program = open_file(
            self.chain.directory()?,
            self.layout.paths().1,
            OFlag::O_RDONLY,
            0,
        )?;
        if identity(&program.metadata()?) != identity(&self.program.metadata()?) {
            return Err(Error::Refused("executable identity changed"));
        }
        let bytes = read_bounded(&program, MAX_PROGRAM, 0o500)?;
        if bytes.is_empty() {
            return Err(Error::Refused("empty executable"));
        }
        self.recheck()?;
        Ok(Sha256::digest(bytes).into())
    }

    pub(crate) fn exists(&self, name: &str) -> Result<bool> {
        if !self.subdirectory_name(name) {
            record_name(name, self.layout)?;
        }
        self.recheck()?;
        match fstatat(self.chain.directory()?, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::ENOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn read(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        record_name(name, self.layout)?;
        if max > MAX_RECORD {
            return Err(Error::Refused("record limit excessive"));
        }
        self.recheck()?;
        let file = open_file(self.chain.directory()?, name, OFlag::O_RDONLY, 0)?;
        let bytes = read_bounded(&file, max, 0o600)?;
        let named = open_file(self.chain.directory()?, name, OFlag::O_RDONLY, 0)?;
        if !unchanged(
            &checked(&file, 0o600, false)?,
            &checked(&named, 0o600, false)?,
        ) {
            return Err(Error::Refused("record replaced during read"));
        }
        self.recheck()?;
        Ok(bytes)
    }

    pub(crate) fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        record_name(name, self.layout)?;
        if data.len() > MAX_RECORD {
            return Err(Error::Refused("record limit excessive"));
        }
        self.recheck()?;
        let mut file = open_file(
            self.chain.directory()?,
            name,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
            0o600,
        )?;
        fchmod(&file, Mode::from_bits_truncate(0o600))?;
        checked(&file, 0o600, false)?;
        file.write_all(data)?;
        file.sync_all()?;
        checked(&file, 0o600, false)?;
        self.chain.directory()?.sync_all()?;
        if self.read(name, data.len())? != data {
            return Err(Error::Refused("protected record differs on readback"));
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn create_capture(&self) -> Result<File> {
        if self.layout != Layout::Flow {
            return Err(Error::Refused("capture requires the physical flow layout"));
        }
        self.recheck()?;
        let dir = self.chain.directory()?;
        let file = open_file(
            dir,
            "capture.pcap",
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
            0o600,
        )?;
        fchmod(&file, Mode::from_bits_truncate(0o600))?;
        checked(&file, 0o600, false)?;
        dir.sync_all()?;
        self.recheck()?;
        Ok(file)
    }

    pub(crate) fn subdir(&self, name: &str, create: bool) -> Result<File> {
        if !self.subdirectory_name(name) {
            return Err(Error::Refused("unsupported subdirectory"));
        }
        self.recheck()?;
        if create {
            mkdirat(
                self.chain.directory()?,
                name,
                Mode::from_bits_truncate(0o700),
            )?;
        }
        let dir = open_file(
            self.chain.directory()?,
            name,
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            0,
        )?;
        if create {
            fchmod(&dir, Mode::from_bits_truncate(0o700))?;
        }
        checked(&dir, 0o700, true)?;
        if create {
            self.chain.directory()?.sync_all()?;
        }
        self.recheck()?;
        Ok(dir)
    }

    fn subdirectory_name(&self, name: &str) -> bool {
        matches!(name, "stage" | "recovery")
            || self.is_fault() && name == "fault-ready"
            || self.layout == Layout::Flow
                && matches!(
                    name,
                    "hook" | "flow-lock" | "enable" | "release" | "capture-lock"
                )
    }
}
