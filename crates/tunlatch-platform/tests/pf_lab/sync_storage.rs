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
const MAX_PROGRAM: usize = 32 * 1024 * 1024;
const MAX_RECORD: usize = 1024 * 1024;

fn record_name(name: &str) -> Result<()> {
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
    ) {
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
}

impl Storage {
    pub(crate) fn open() -> Result<Self> {
        if !nix::unistd::geteuid().is_root() || std::env::current_exe()? != Path::new(EXECUTABLE) {
            return Err(Error::Refused("requires root and fixed executable path"));
        }
        let chain = ObservedChain::open(Path::new(BASE))?;
        checked(chain.directory()?, 0o700, true)?;
        let program = open_file(chain.directory()?, PROGRAM, OFlag::O_RDONLY, 0)?;
        checked(&program, 0o500, false)?;
        let result = Self { chain, program };
        result.recheck()?;
        Ok(result)
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        self.chain.recheck()?;
        let old = checked(self.chain.directory()?, 0o700, true)?;
        let fresh = ObservedChain::open(Path::new(BASE))?;
        let new = checked(fresh.directory()?, 0o700, true)?;
        if identity(&old) != identity(&new) {
            return Err(Error::Refused("protected directory replaced"));
        }
        let held = checked(&self.program, 0o500, false)?;
        let named = open_file(fresh.directory()?, PROGRAM, OFlag::O_RDONLY, 0)?;
        let named = checked(&named, 0o500, false)?;
        if !unchanged(&held, &named) {
            return Err(Error::Refused("protected executable replaced"));
        }
        Ok(())
    }

    pub(crate) fn program_digest(&self) -> Result<[u8; 32]> {
        self.recheck()?;
        // Open a second descriptor to avoid a shared seek position between digest calls.
        let program = open_file(self.chain.directory()?, PROGRAM, OFlag::O_RDONLY, 0)?;
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
        if !matches!(name, "stage" | "recovery") {
            record_name(name)?;
        }
        self.recheck()?;
        match fstatat(self.chain.directory()?, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(_) => Ok(true),
            Err(Errno::ENOENT) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn read(&self, name: &str, max: usize) -> Result<Vec<u8>> {
        record_name(name)?;
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
        record_name(name)?;
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

    pub(crate) fn subdir(&self, name: &str, create: bool) -> Result<File> {
        if !matches!(name, "stage" | "recovery") {
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
}
