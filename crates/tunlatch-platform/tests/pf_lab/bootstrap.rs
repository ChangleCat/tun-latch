//! Ordinary-user staging sandbox. No installation, executable launch or authority constructor.
//!
//! ACL/ancestor observations are supplied by an explicit test inspection boundary. There is
//! deliberately no native ACL or privileged bootstrap adapter: mode bits alone never pass.
//! The native part copies DATA between held descriptors, journals intent, and publishes without
//! replacement. A held directory is the sandbox's trust root, not proof of a protected host path.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;

use nix::fcntl::{AtFlags, Flock, FlockArg, OFlag, openat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{UnlinkatFlags, linkat, unlinkat};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_PROGRAM: u64 = 64 * 1024 * 1024;
const MAX_INDEX: u64 = 256;

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    System(#[from] nix::errno::Errno),
    #[error("sandbox refuses: {0}")]
    Refused(&'static str),
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Unknown and nonempty ACLs are both refused, including harmless-looking deny entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Acl {
    Empty,
    Present,
    Unknown,
}

/// Test-only inspection contract. The descriptor, not a reopened path, identifies the object.
pub(crate) trait Inspection {
    fn acl(&mut self, file: &File) -> Acl;
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Ancestor {
    pub(crate) owner: u32,
    pub(crate) mode: u32,
    pub(crate) directory: bool,
    pub(crate) acl: Acl,
}

pub(crate) fn check_ancestors(chain: &[Ancestor], owner: u32) -> Result<()> {
    if chain.is_empty() || chain.len() > 32 {
        return Err(Error::Refused("incomplete or excessive parent chain"));
    }
    for node in chain {
        if node.owner != owner
            || !node.directory
            || node.mode & 0o022 != 0
            || node.acl != Acl::Empty
        {
            return Err(Error::Refused("unprotected ancestor"));
        }
    }
    Ok(())
}

/// Content chosen by a simulated review; this is not a real administrator credential.
#[derive(Clone, Debug)]
pub(crate) struct ReviewedContent {
    digest: [u8; 32],
    size: u64,
    session: [u8; 32],
    boot: [u8; 32],
    generation: u64,
}
impl ReviewedContent {
    pub(crate) fn sandbox_review(
        digest: [u8; 32],
        size: u64,
        session: [u8; 32],
        boot: [u8; 32],
        generation: u64,
    ) -> Result<Self> {
        if digest == [0; 32]
            || size == 0
            || size > MAX_PROGRAM
            || session == [0; 32]
            || boot == [0; 32]
            || generation == 0
        {
            return Err(Error::Refused("invalid content or session bounds"));
        }
        Ok(Self {
            digest,
            size,
            session,
            boot,
            generation,
        })
    }
}

fn open(dir: &File, name: &str, flags: OFlag, mode: u16) -> Result<File> {
    Ok(openat(
        dir,
        name,
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::from_bits_truncate(mode),
    )?
    .into())
}

fn checked(file: &File, mode: u32, inspection: &mut impl Inspection) -> Result<()> {
    let meta = file.metadata()?;
    if meta.uid() != nix::unistd::geteuid().as_raw()
        || meta.mode() & 0o7777 != mode
        || (mode == 0o700 && !meta.is_dir())
        || (mode != 0o700 && (!meta.is_file() || meta.nlink() != 1))
        || inspection.acl(file) != Acl::Empty
    {
        return Err(Error::Refused("wrong type, owner, links, mode or ACL"));
    }
    Ok(())
}

/// Lock and ledger are held together for the whole staging operation. Never unlink the lock.
pub(crate) struct Sandbox {
    dir: File,
    lock: Flock<File>,
    index: File,
    sealed: bool,
}
impl Sandbox {
    /// Initialize a FRESH sandbox. Existing records are never recreated or reset here.
    pub(crate) fn initialize(dir: File, inspection: &mut impl Inspection) -> Result<Self> {
        if nix::unistd::geteuid().is_root() {
            return Err(Error::Refused("ordinary user only"));
        }
        checked(&dir, 0o700, inspection)?;
        let lock = open(
            &dir,
            "lock",
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
            0o600,
        )?;
        checked(&lock, 0o600, inspection)?;
        let lock = Flock::lock(lock, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| Error::System(e))?;
        let mut index = open(
            &dir,
            "index",
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
            0o600,
        )?;
        checked(&index, 0o600, inspection)?;
        index.write_all(b"clean\n")?;
        index.sync_all()?;
        dir.sync_all()?;
        Ok(Self {
            dir,
            lock,
            index,
            sealed: false,
        })
    }

    pub(crate) fn reopen(dir: File, inspection: &mut impl Inspection) -> Result<Self> {
        if nix::unistd::geteuid().is_root() {
            return Err(Error::Refused("ordinary user only"));
        }
        checked(&dir, 0o700, inspection)?;
        let lock = open(&dir, "lock", OFlag::O_RDWR, 0)?;
        checked(&lock, 0o600, inspection)?;
        let lock = Flock::lock(lock, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| Error::System(e))?;
        let mut index = open(&dir, "index", OFlag::O_RDWR, 0)?;
        checked(&index, 0o600, inspection)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut index)
            .take(MAX_INDEX + 1)
            .read_to_end(&mut bytes)?;
        if bytes != b"clean\n" {
            return Err(Error::Refused(
                "unsettled, corrupt or excessive session index",
            ));
        }
        Ok(Self {
            dir,
            lock,
            index,
            sealed: false,
        })
    }

    fn record(&mut self, phase: &str, review: &ReviewedContent) -> Result<()> {
        // Append-only transitions: an interrupted intent can never appear clean on reopening.
        self.index.seek(SeekFrom::End(0))?;
        writeln!(
            self.index,
            "{phase} {:?} {:?} {} {:?}",
            review.session, review.boot, review.generation, review.digest
        )?;
        self.index.sync_all()?;
        Ok(())
    }

    pub(crate) fn stage(
        &mut self,
        source: &mut File,
        review: &ReviewedContent,
        inspection: &mut impl Inspection,
    ) -> Result<Prepared> {
        if self.sealed {
            return Err(Error::Refused("one-shot staging already consumed"));
        }
        self.sealed = true;
        checked(&self.dir, 0o700, inspection)?;
        // Detect lock-path replacement; same inode alone does not establish root cooperation.
        let named = open(&self.dir, "lock", OFlag::O_RDWR, 0)?;
        let a = named.metadata()?;
        let b = self.lock.metadata()?;
        if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
            return Err(Error::Refused("lock object replaced"));
        }
        let before = source.metadata()?;
        if !before.is_file() || before.len() != review.size || before.len() > MAX_PROGRAM {
            return Err(Error::Refused("candidate is not bounded reviewed data"));
        }
        self.record("intent", review)?;
        let mut staged = open(
            &self.dir,
            "candidate",
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_EXCL,
            0o600,
        )?;
        checked(&staged, 0o600, inspection)?;
        source.seek(SeekFrom::Start(0))?;
        let count = io::copy(&mut Read::by_ref(source).take(review.size + 1), &mut staged)?;
        if count != review.size {
            return Err(Error::Refused("partial or excessive copy"));
        }
        staged.sync_all()?;
        staged.seek(SeekFrom::Start(0))?;
        let mut hash = Sha256::new();
        let mut buffer = [0; 8192];
        let mut bounded = Read::by_ref(&mut staged).take(MAX_PROGRAM + 1);
        let mut hashed = 0_u64;
        loop {
            let count = bounded.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hash.update(&buffer[..count]);
            hashed += count as u64;
        }
        let after = source.metadata()?;
        if hashed != review.size
            || <[u8; 32]>::from(hash.finalize()) != review.digest
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
            return Err(Error::Refused("content changed or digest mismatch"));
        }
        fchmod(&staged, Mode::from_bits_truncate(0o500))?;
        checked(&staged, 0o500, inspection)?;
        staged.sync_all()?;
        self.record("verified", review)?;
        // linkat fails if program already exists. Unlike renameat it cannot overwrite a foreign
        // target. A crash between link/unlink is an unresolved journal, never auto-cleaned.
        linkat(
            &self.dir,
            "candidate",
            &self.dir,
            "program",
            AtFlags::empty(),
        )?;
        unlinkat(&self.dir, "candidate", UnlinkatFlags::NoRemoveDir)?;
        self.dir.sync_all()?;
        let program = open(&self.dir, "program", OFlag::O_RDONLY, 0)?;
        checked(&program, 0o500, inspection)?;
        let m = program.metadata()?;
        let s = staged.metadata()?;
        if (m.dev(), m.ino()) != (s.dev(), s.ino()) {
            return Err(Error::Refused("published object replaced"));
        }
        self.record("published", review)?;
        Ok(Prepared {
            program,
            review: review.clone(),
        })
    }
}

/// This value owns DATA in a sandbox, with no exec method or conversion to live authority.
pub(crate) struct Prepared {
    program: File,
    review: ReviewedContent,
}
impl Prepared {
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>> {
        self.program.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut self.program)
            .take(MAX_PROGRAM + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != self.review.size
            || <[u8; 32]>::from(Sha256::digest(&bytes)) != self.review.digest
        {
            return Err(Error::Refused("published content changed"));
        }
        Ok(bytes)
    }

    /// A reopened current_exe/path digest supplies NONE of this launch-chain evidence.
    /// All observations here are simulated; no native process-image adapter is supplied.
    pub(crate) fn check_launch(&self, observation: LaunchObservation) -> Result<()> {
        if observation.session != self.review.session
            || observation.boot != self.review.boot
            || observation.generation != self.review.generation
            || observation.birth == 0
            || observation.launch_sequence == 0
            || observation.launch_sequence != observation.observed_sequence
            || observation.loaded_digest != Some(self.review.digest)
            || observation.inherited_fds != 0
            || !observation.fixed_entry
        {
            return Err(Error::Refused(
                "missing or inconsistent trusted launch chain",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LaunchObservation {
    pub(crate) session: [u8; 32],
    pub(crate) boot: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) birth: u64,
    pub(crate) launch_sequence: u64,
    pub(crate) observed_sequence: u64,
    pub(crate) loaded_digest: Option<[u8; 32]>,
    pub(crate) inherited_fds: usize,
    pub(crate) fixed_entry: bool,
}

/// Candidate paths are opened once without following the final component. Ancestors must be
/// separately inspected by the trusted boundary; this does not certify a running executable.
pub(crate) fn open_candidate(path: &std::path::Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(OFlag::O_NOFOLLOW.bits() | OFlag::O_CLOEXEC.bits() | OFlag::O_NONBLOCK.bits())
        .open(path)?)
}

pub(crate) fn close_on_exec(file: &File) -> Result<bool> {
    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    let flags = fcntl(file, FcntlArg::F_GETFD)?;
    Ok(FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC))
}
