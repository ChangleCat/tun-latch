//! Real, bounded, append-only filesystem ledger for an experimental controller.
//!
//! The ledger detects accidental corruption and preserves unresolved intents. Its digest is
//! not authentication, its records do not prove PF ownership, and reopening never transfers
//! execution or cleanup authority to a new controller. No Drop cleanup is implemented.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;

use nix::fcntl::{Flock, FlockArg, OFlag, openat};
use nix::sys::stat::Mode;
use sha2::{Digest, Sha256};

use super::bootstrap::{Acl, Error, Result};
use super::native_files::NativePathInspection;

const MAGIC: &[u8; 8] = b"TLABLOG\0";
const HEADER: usize = 104;
const RECORD: usize = 74;
const CAPACITY: u64 = 128;
const MAX_BYTES: u64 = HEADER as u64 + CAPACITY * RECORD as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Operation {
    StageProgram = 1,
    StartController = 2,
    WriteFilter = 3,
    ChangeHook = 4,
    AcquireReference = 5,
    ReleaseReference = 6,
    DeleteControlledStates = 7,
    CreateInterface = 8,
    CloseInterface = 9,
    StartCapture = 10,
    StopProbe = 11,
}

impl Operation {
    fn decode(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::StageProgram),
            2 => Ok(Self::StartController),
            3 => Ok(Self::WriteFilter),
            4 => Ok(Self::ChangeHook),
            5 => Ok(Self::AcquireReference),
            6 => Ok(Self::ReleaseReference),
            7 => Ok(Self::DeleteControlledStates),
            8 => Ok(Self::CreateInterface),
            9 => Ok(Self::CloseInterface),
            10 => Ok(Self::StartCapture),
            11 => Ok(Self::StopProbe),
            _ => Err(Error::Refused("unknown journal operation")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum State {
    Ready,
    Intent(Operation),
    Unknown(Operation),
    Closed,
    StorageUnknown,
}

pub(crate) struct Ledger {
    directory: File,
    lock: Flock<File>,
    journal: File,
    session: [u8; 32],
    plan: [u8; 32],
    sequence: u64,
    tail: [u8; 32],
    state: State,
    writable: bool,
    poisoned: bool,
}

fn open(directory: &File, name: &str, create: bool) -> Result<File> {
    let flags = OFlag::O_RDWR | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK;
    let flags = if create {
        flags | OFlag::O_CREAT | OFlag::O_EXCL
    } else {
        flags
    };
    Ok(openat(directory, name, flags, Mode::from_bits_truncate(0o600))?.into())
}

fn inspect(file: &File, directory: bool) -> Result<()> {
    let metadata = file.metadata()?;
    let required_mode = if directory { 0o700 } else { 0o600 };
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != required_mode
        || metadata.is_dir() != directory
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
        || NativePathInspection.acl(file) != Acl::Empty
    {
        return Err(Error::Refused(
            "journal type, owner, links, mode or ACL mismatch",
        ));
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl Ledger {
    /// New directory records only. An existing/missing/corrupt journal is never reset here.
    pub(crate) fn create(directory: File, session: [u8; 32], plan: [u8; 32]) -> Result<Self> {
        if session == [0; 32] || plan == [0; 32] {
            return Err(Error::Refused("empty journal identity"));
        }
        inspect(&directory, true)?;
        let lock = open(&directory, "recovery.lock", true)?;
        inspect(&lock, false)?;
        let lock = Flock::lock(lock, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| Error::System(e))?;
        let mut journal = open(&directory, "session.journal", true)?;
        inspect(&journal, false)?;
        let mut header = Vec::from(*MAGIC);
        header.extend(session);
        header.extend(plan);
        let tail = digest(&header);
        header.extend(tail);
        journal.write_all(&header)?;
        journal.sync_all()?;
        directory.sync_all()?;
        Ok(Self {
            directory,
            lock,
            journal,
            session,
            plan,
            sequence: 0,
            tail,
            state: State::Ready,
            writable: true,
            poisoned: false,
        })
    }

    /// Reads the same fixed lock/index, refusing replacements and incomplete bytes. Even a
    /// clean close is an audit observation, not permission to reopen an old execution queue.
    pub(crate) fn reopen(directory: File) -> Result<Self> {
        inspect(&directory, true)?;
        let lock = open(&directory, "recovery.lock", false)?;
        inspect(&lock, false)?;
        let lock = Flock::lock(lock, FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| Error::System(e))?;
        let mut journal = open(&directory, "session.journal", false)?;
        inspect(&journal, false)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut journal)
            .take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() < HEADER
            || bytes.len() as u64 > MAX_BYTES
            || !(bytes.len() - HEADER).is_multiple_of(RECORD)
            || &bytes[..8] != MAGIC
            || bytes[72..HEADER] != digest(&bytes[..72])
        {
            return Err(Error::Refused("incomplete, excessive or corrupt journal"));
        }
        let session = bytes[8..40]
            .try_into()
            .map_err(|_| Error::Refused("session"))?;
        let plan = bytes[40..72]
            .try_into()
            .map_err(|_| Error::Refused("plan"))?;
        if session == [0; 32] || plan == [0; 32] {
            return Err(Error::Refused("empty recorded identity"));
        }
        let mut ledger = Self {
            directory,
            lock,
            journal,
            session,
            plan,
            sequence: 0,
            tail: digest(&bytes[..72]),
            state: State::Ready,
            writable: false,
            poisoned: false,
        };
        for record in bytes[HEADER..].as_chunks::<RECORD>().0 {
            let sequence = u64::from_be_bytes(
                record[..8]
                    .try_into()
                    .map_err(|_| Error::Refused("sequence"))?,
            );
            if sequence != ledger.sequence + 1
                || record[10..42] != ledger.tail
                || record[42..] != digest(&record[..42])
            {
                return Err(Error::Refused("journal sequence or digest mismatch"));
            }
            ledger.state = transition(ledger.state, record[8], record[9])?;
            ledger.sequence = sequence;
            ledger.tail = digest(&record[..42]);
        }
        ledger.check_named_objects()?;
        Ok(ledger)
    }

    fn check_named_objects(&self) -> Result<()> {
        inspect(&self.directory, true)?;
        for (name, held) in [
            ("recovery.lock", &*self.lock),
            ("session.journal", &self.journal),
        ] {
            inspect(held, false)?;
            let named = open(&self.directory, name, false)?;
            inspect(&named, false)?;
            let a = held.metadata()?;
            let b = named.metadata()?;
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err(Error::Refused("journal or lock path replaced"));
            }
        }
        Ok(())
    }

    fn append(&mut self, phase: u8, operation: u8) -> Result<()> {
        if !self.writable || self.poisoned || self.sequence >= CAPACITY {
            return Err(Error::Refused("read-only, poisoned or exhausted journal"));
        }
        let next = transition(self.state, phase, operation)?;
        // Poison BEFORE attempting any I/O. Disk failure cannot leave an in-memory reusable
        // Ready state while an uncertain intent exists on disk.
        self.poisoned = true;
        self.check_named_objects()?;
        let expected_len = HEADER as u64 + self.sequence * RECORD as u64;
        if self.journal.metadata()?.len() != expected_len {
            return Err(Error::Refused("journal length changed"));
        }
        let mut record = Vec::from((self.sequence + 1).to_be_bytes());
        record.extend([phase, operation]);
        record.extend(self.tail);
        let tail = digest(&record);
        record.extend(tail);
        self.journal.seek(SeekFrom::End(0))?;
        self.journal.write_all(&record)?;
        self.journal.sync_all()?;
        self.state = next;
        self.tail = tail;
        self.sequence += 1;
        self.poisoned = false;
        Ok(())
    }

    pub(crate) fn begin(&mut self, operation: Operation) -> Result<()> {
        self.append(1, operation as u8)
    }

    /// The caller must independently establish its operation's complete postcondition. This
    /// method only durably records that report; it cannot authenticate arbitrary callers.
    pub(crate) fn observed(&mut self) -> Result<()> {
        let State::Intent(operation) = self.state else {
            return Err(Error::Refused("no active intent"));
        };
        self.append(2, operation as u8)
    }

    pub(crate) fn unknown(&mut self) -> Result<()> {
        let State::Intent(operation) = self.state else {
            return Err(Error::Refused("no active intent"));
        };
        self.append(3, operation as u8)
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        self.append(4, 0)
    }

    pub(crate) fn state(&self) -> State {
        if self.poisoned {
            State::StorageUnknown
        } else {
            self.state
        }
    }

    pub(crate) fn identity(&self) -> ([u8; 32], [u8; 32]) {
        (self.session, self.plan)
    }
}

fn transition(state: State, phase: u8, operation: u8) -> Result<State> {
    match (state, phase) {
        (State::Ready, 1) => Ok(State::Intent(Operation::decode(operation)?)),
        (State::Intent(current), 2) if current as u8 == operation => Ok(State::Ready),
        (State::Intent(current), 3) if current as u8 == operation => Ok(State::Unknown(current)),
        (State::Ready, 4) if operation == 0 => Ok(State::Closed),
        _ => Err(Error::Refused(
            "invalid journal transition; manual reconciliation required",
        )),
    }
}
