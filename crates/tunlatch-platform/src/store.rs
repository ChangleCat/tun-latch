//! Bounded atomic records, independent of PF execution and administrator authorization.
//!
//! User stores are ordinary-user local data, never root-protected approval records. The system
//! entry accepts no path and requires an already provisioned fixed root-owned directory.
//! Every operation retains and rechecks its directory chain and exclusive writer lock. ACLs are
//! observed through real paths with inode/ctime checks because exacl has no descriptor API. This
//! rejects ordinary cross-user access; it does not defend against malicious same-UID/root ABA.
//! A successful file sync/rename/directory sync is a storage acknowledgment, not PF protection,
//! content authenticity, or a hardware-independent power-loss guarantee. Corruption is an error,
//! never an implicit disabled policy. Dropping a store only closes its files and writer lock.

use std::fs::{File, Metadata};
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl, open, openat, renameat};
use nix::sys::stat::{Mode, fchmod};
use nix::unistd::{Uid, UnlinkatFlags, unlinkat};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Maximum opaque payload bytes; callers must independently validate the payload's schema.
pub const MAX_RECORD_PAYLOAD_BYTES: usize = 65_536;
/// The sole system-store location; this module never creates its directories.
pub const SYSTEM_STORE_DIRECTORY: &str = "/private/var/db/tunlatch";
const MAGIC: &[u8; 8] = b"TNLREC\0\0";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 80;
const MAX_RECORD_BYTES: usize = HEADER_BYTES + MAX_RECORD_PAYLOAD_BYTES;
pub(crate) const LOCK_NAME: &str = "writer.lock";

/// Separate fixed slots. A record copied between slots fails its envelope-kind check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordKind {
    /// Opaque policy or draft content; this slot does not grant approval by itself.
    Policy,
    /// Recovery hints, not evidence that any policy is installed or verified.
    Recovery,
}

impl RecordKind {
    /// Return the fixed leaf name; callers cannot supply arbitrary record paths.
    pub fn file_name(self) -> &'static str {
        match self {
            Self::Policy => "policy.record",
            Self::Recovery => "recovery.record",
        }
    }

    fn temporary_name(self) -> &'static str {
        match self {
            Self::Policy => "policy.pending",
            Self::Recovery => "recovery.pending",
        }
    }

    fn tag(self) -> u8 {
        match self {
            Self::Policy => 1,
            Self::Recovery => 2,
        }
    }
}

/// Opaque nonzero record identity. A caller must distinguish draft and effective-plan domains.
/// It cannot convert stored bytes into an approval or establish the identity's calculation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordIdentity([u8; 32]);

impl RecordIdentity {
    /// Reject an unset identity without authenticating its origin or represented semantics.
    pub fn new(bytes: [u8; 32]) -> Result<Self, StoreError> {
        if bytes == [0; 32] {
            return Err(StoreError::Refused("record identity must be nonzero"));
        }
        Ok(Self(bytes))
    }

    /// Return the opaque digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for RecordIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Bounded owned payload and caller-computed content identity, never a credential.
#[derive(Clone, Eq, PartialEq)]
pub struct StoredRecord {
    identity: RecordIdentity,
    payload: Vec<u8>,
}

impl std::fmt::Debug for StoredRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredRecord")
            .field("identity", &self.identity)
            .field("payload_bytes", &self.payload.len())
            .finish()
    }
}

impl StoredRecord {
    /// Bound an opaque payload. Its digest authenticates neither its producer nor its contents.
    pub fn new(identity: RecordIdentity, payload: Vec<u8>) -> Result<Self, StoreError> {
        if payload.len() > MAX_RECORD_PAYLOAD_BYTES {
            return Err(StoreError::Refused("record payload exceeds its byte limit"));
        }
        Ok(Self { identity, payload })
    }

    /// Return the caller's content identity without assigning it policy or authorization semantics.
    pub fn identity(&self) -> RecordIdentity {
        self.identity
    }

    /// Return opaque bytes; a caller must validate their schema and authorization separately.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// Storage boundary where a replacement failed; synchronous native calls are not preempted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitStage {
    /// Validation or exclusive temporary-file creation, before writing a replacement.
    Prepare,
    /// Writing the complete temporary envelope.
    Write,
    /// Synchronizing the temporary file before publication.
    FileSync,
    /// A rename was attempted; its failure must conservatively retain uncertainty.
    Rename,
    /// Synchronizing or rechecking the containing directory after a successful rename.
    DirectorySync,
}

/// Errors never manufacture disabled state or a storage/PF authorization capability.
#[derive(Debug, Error)]
pub enum StoreError {
    /// A filesystem operation failed without exposing record contents.
    #[error("record storage I/O failed: {0}")]
    Io(#[from] io::Error),
    /// A descriptor-relative system operation failed.
    #[error("record storage system operation failed: {0}")]
    System(#[from] Errno),
    /// Owner, mode, ACL, path or resource policy was not satisfied.
    #[error("record store refused: {0}")]
    Refused(&'static str),
    /// Another cooperating writer holds the fixed lock, or locking was unavailable.
    #[error("record store exclusive writer lock is unavailable")]
    WriterBusy,
    /// The bounded envelope was corrupt, truncated, extended or unsupported.
    #[error("record envelope rejected: {0}")]
    InvalidRecord(&'static str),
    /// No rename was attempted by this replacement; an existing record was not published over.
    #[error("record replacement failed before rename at {stage:?}: {source}")]
    BeforeRename {
        /// Last attempted stage before publication.
        stage: CommitStage,
        /// The validation or I/O failure.
        source: Box<StoreError>,
    },
    /// Publication/durability is uncertain; rereading is not proof of crash durability.
    #[error("record commit outcome is unknown at {stage:?}: {source}")]
    CommitUnknown {
        /// Rename or post-rename boundary that did not receive a complete acknowledgment.
        stage: CommitStage,
        /// The validation or I/O failure.
        source: Box<StoreError>,
    },
}

impl StoreError {
    /// True when rename was attempted or its subsequent durability acknowledgment failed.
    /// False never turns invalid or missing record data into a disabled policy.
    pub fn is_commit_unknown(&self) -> bool {
        matches!(self, Self::CommitUnknown { .. })
    }
}

/// Ordinary-user local records. This type cannot be opened with effective UID zero.
pub struct UserRecordStore {
    inner: Store,
}

impl UserRecordStore {
    /// Open an existing private 0700 directory through a checked, non-symlink parent chain.
    ///
    /// Ancestors must have empty ACLs, be root/current-user owned and not group/other writable.
    /// The sole shared-parent exception is root-owned, ACL-free 01777 `/private/tmp`, followed
    /// immediately by a current-user-owned 0700 directory. Standard home-directory ACLs may
    /// therefore be refused. This is local storage, not protected administrator approval.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let owner = Uid::effective();
        if owner.is_root() {
            return Err(StoreError::Refused(
                "root cannot open an arbitrary user-store path",
            ));
        }
        Ok(Self {
            inner: Store::open(path, owner.as_raw(), false)?,
        })
    }

    /// Read one checked fixed slot. Missing is explicit; corrupt data remains an error.
    pub fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
        self.inner.read(kind)
    }

    /// Atomically replace a valid/missing slot; errors distinguish pre-rename from unknown.
    pub fn replace(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError> {
        self.inner.replace(kind, record, |_| Ok(()))
    }
}

/// Fixed system-path storage, not a `ProtectedRoot` or administrator authorization credential.
/// Actual provisioning, cross-UID checks and production integration require separate review.
pub struct SystemRecordStore {
    inner: Store,
}

impl SystemRecordStore {
    /// Require actual effective UID zero and the existing fixed root-owned protected chain.
    /// No caller-controlled path or directory creation is accepted.
    pub fn open() -> Result<Self, StoreError> {
        if !Uid::effective().is_root() {
            return Err(StoreError::Refused(
                "system store requires actual effective UID zero",
            ));
        }
        Ok(Self {
            inner: Store::open(Path::new(SYSTEM_STORE_DIRECTORY), 0, true)?,
        })
    }

    /// Read checked bytes without interpreting them as an authorization or installed policy.
    pub fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
        self.inner.read(kind)
    }

    /// Replace fixed record data only; this operation never changes PF or system services.
    pub fn replace(&mut self, kind: RecordKind, record: &StoredRecord) -> Result<(), StoreError> {
        self.inner.replace(kind, record, |_| Ok(()))
    }
}

struct Store {
    chain: DirectoryChain,
    lock: File,
}

impl Store {
    fn open(path: &Path, owner: u32, system: bool) -> Result<Self, StoreError> {
        let chain = DirectoryChain::open(path, owner, system)?;
        let lock = create_or_open_lock(chain.directory()?)?;
        check_file(&lock, owner, &chain.path().join(LOCK_NAME))?;
        if lock.metadata()?.len() != 0 {
            return Err(StoreError::Refused("writer lock must be empty"));
        }
        lock.try_lock().map_err(|_| StoreError::WriterBusy)?;
        let store = Self { chain, lock };
        store.recheck()?;
        Ok(store)
    }

    fn recheck(&self) -> Result<(), StoreError> {
        self.chain.recheck()?;
        check_file(
            &self.lock,
            self.chain.owner,
            &self.chain.path().join(LOCK_NAME),
        )?;
        let current: File = openat(
            self.chain.directory()?,
            LOCK_NAME,
            file_flags(),
            Mode::empty(),
        )?
        .into();
        if identity(&current.metadata()?) != identity(&self.lock.metadata()?) {
            return Err(StoreError::Refused("writer lock was replaced"));
        }
        Ok(())
    }

    fn read(&self, kind: RecordKind) -> Result<Option<StoredRecord>, StoreError> {
        self.recheck()?;
        let mut file: File = match openat(
            self.chain.directory()?,
            kind.file_name(),
            file_flags(),
            Mode::empty(),
        ) {
            Ok(fd) => fd.into(),
            Err(Errno::ENOENT) => {
                self.recheck()?;
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        let path = self.chain.path().join(kind.file_name());
        check_file(&file, self.chain.owner, &path)?;
        let before = file.metadata()?;
        if before.len() > MAX_RECORD_BYTES as u64 {
            return Err(StoreError::InvalidRecord("record exceeds its byte limit"));
        }
        let mut bytes = Vec::with_capacity(MAX_RECORD_BYTES);
        (&mut file)
            .take(MAX_RECORD_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(StoreError::InvalidRecord("record exceeds its byte limit"));
        }
        check_file(&file, self.chain.owner, &path)?;
        if identity(&before) != identity(&file.metadata()?)
            || before.len() != file.metadata()?.len()
        {
            return Err(StoreError::Refused("record changed while reading"));
        }
        self.recheck()?;
        decode(kind, &bytes).map(Some)
    }

    fn replace(
        &mut self,
        kind: RecordKind,
        record: &StoredRecord,
        mut fault: impl FnMut(CommitStage) -> io::Result<()>,
    ) -> Result<(), StoreError> {
        let prepare = || -> Result<_, StoreError> {
            self.read(kind)?; // Do not overwrite an unreadable or corrupt last record.
            let bytes = encode(kind, record);
            let temporary: File = openat(
                self.chain.directory()?,
                kind.temporary_name(),
                file_flags() | OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL,
                Mode::S_IRUSR | Mode::S_IWUSR,
            )?
            .into();
            fchmod(&temporary, Mode::S_IRUSR | Mode::S_IWUSR)?;
            check_file(
                &temporary,
                self.chain.owner,
                &self.chain.path().join(kind.temporary_name()),
            )?;
            Ok((temporary, bytes))
        };
        let (mut temporary, bytes) =
            prepare().map_err(|error| before(CommitStage::Prepare, error))?;
        let unpublished = (|| -> Result<(), StoreError> {
            fault(CommitStage::Write)?;
            temporary.write_all(&bytes)?;
            fault(CommitStage::FileSync)
                .map_err(|error| before(CommitStage::FileSync, error.into()))?;
            temporary
                .sync_all()
                .map_err(|error| before(CommitStage::FileSync, error.into()))?;
            self.recheck()
                .map_err(|error| before(CommitStage::Prepare, error))?;
            check_file(
                &temporary,
                self.chain.owner,
                &self.chain.path().join(kind.temporary_name()),
            )
            .map_err(|error| before(CommitStage::Prepare, error))?;
            Ok(())
        })();
        if let Err(error) = unpublished {
            // Keep the temporary when the lock, parent chain or held-file identity changed.
            if self.recheck().is_ok()
                && check_file(
                    &temporary,
                    self.chain.owner,
                    &self.chain.path().join(kind.temporary_name()),
                )
                .is_ok()
            {
                let _ = unlinkat(
                    self.chain.directory()?,
                    kind.temporary_name(),
                    UnlinkatFlags::NoRemoveDir,
                );
            }
            return Err(match error {
                StoreError::BeforeRename { .. } => error,
                error => before(CommitStage::Write, error),
            });
        }
        fault(CommitStage::Rename).map_err(|error| unknown(CommitStage::Rename, error.into()))?;
        renameat(
            self.chain.directory()?,
            kind.temporary_name(),
            self.chain.directory()?,
            kind.file_name(),
        )
        .map_err(|error| unknown(CommitStage::Rename, error.into()))?;
        fault(CommitStage::DirectorySync)
            .map_err(|error| unknown(CommitStage::DirectorySync, error.into()))?;
        self.chain
            .directory()?
            .sync_all()
            .map_err(|error| unknown(CommitStage::DirectorySync, error.into()))?;
        self.recheck()
            .map_err(|error| unknown(CommitStage::DirectorySync, error))?;
        check_file(
            &temporary,
            self.chain.owner,
            &self.chain.path().join(kind.file_name()),
        )
        .map_err(|error| unknown(CommitStage::DirectorySync, error))?;
        Ok(())
    }
}

fn before(stage: CommitStage, error: StoreError) -> StoreError {
    StoreError::BeforeRename {
        stage,
        source: Box::new(error),
    }
}

fn unknown(stage: CommitStage, error: StoreError) -> StoreError {
    StoreError::CommitUnknown {
        stage,
        source: Box::new(error),
    }
}

fn file_flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC
}

fn create_or_open_lock(directory: &File) -> Result<File, StoreError> {
    let flags = file_flags() | OFlag::O_RDWR;
    match openat(
        directory,
        LOCK_NAME,
        flags | OFlag::O_CREAT | OFlag::O_EXCL,
        Mode::S_IRUSR | Mode::S_IWUSR,
    ) {
        Ok(fd) => {
            let file: File = fd.into();
            fchmod(&file, Mode::S_IRUSR | Mode::S_IWUSR)?;
            Ok(file)
        }
        Err(Errno::EEXIST) => Ok(openat(directory, LOCK_NAME, flags, Mode::empty())?.into()),
        Err(error) => Err(error.into()),
    }
}

struct DirectoryChain {
    directories: Vec<(PathBuf, File)>,
    owner: u32,
    system: bool,
}

impl DirectoryChain {
    fn open(path: &Path, owner: u32, system: bool) -> Result<Self, StoreError> {
        if !path.is_absolute() || path.as_os_str().len() > 1024 {
            return Err(StoreError::Refused(
                "store requires a bounded absolute path",
            ));
        }
        let flags = file_flags() | OFlag::O_DIRECTORY;
        let root: File = open(Path::new("/"), flags, Mode::empty())?.into();
        let mut chain = Self {
            directories: vec![(PathBuf::from("/"), root)],
            owner,
            system,
        };
        for component in path.components().skip(1) {
            let Component::Normal(name) = component else {
                return Err(StoreError::Refused(
                    "store path contains noncanonical components",
                ));
            };
            if chain.directories.len() >= 32 {
                return Err(StoreError::Refused("store directory chain is too deep"));
            }
            let next = openat(chain.directory()?, name, flags, Mode::empty())?;
            chain
                .directories
                .push((chain.path().join(name), next.into()));
        }
        if chain.path().as_os_str() != path.as_os_str() {
            return Err(StoreError::Refused(
                "store path must have canonical component spelling",
            ));
        }
        chain.recheck()?;
        Ok(chain)
    }

    fn directory(&self) -> Result<&File, StoreError> {
        self.directories
            .last()
            .map(|(_, file)| file)
            .ok_or(StoreError::Refused("empty directory chain"))
    }

    fn path(&self) -> &Path {
        self.directories
            .last()
            .map_or(Path::new("/"), |(path, _)| path.as_path())
    }

    fn recheck(&self) -> Result<(), StoreError> {
        for (index, (path, file)) in self.directories.iter().enumerate() {
            let metadata = file.metadata()?;
            let leaf = index + 1 == self.directories.len();
            check_directory(&metadata, self.owner, self.system, path, leaf)?;
            check_empty_acl(file, path)?;
            if index > 0 {
                let parent = &self.directories[index - 1].1;
                let name = path
                    .file_name()
                    .ok_or(StoreError::Refused("missing directory leaf"))?;
                let reopened: File = openat(
                    parent,
                    name,
                    file_flags() | OFlag::O_DIRECTORY,
                    Mode::empty(),
                )?
                .into();
                if inode_identity(&metadata) != inode_identity(&reopened.metadata()?) {
                    return Err(StoreError::Refused("store directory chain was replaced"));
                }
            }
            if path == Path::new("/private/tmp") && !self.system {
                let next = self.directories.get(index + 1).ok_or(StoreError::Refused(
                    "shared temporary parent is not a store",
                ))?;
                let child = next.1.metadata()?;
                if child.uid() != self.owner || child.mode() & 0o7777 != 0o700 {
                    return Err(StoreError::Refused(
                        "shared parent requires a private directly owned child",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn check_directory(
    metadata: &Metadata,
    owner: u32,
    system: bool,
    path: &Path,
    leaf: bool,
) -> Result<(), StoreError> {
    if !metadata.is_dir() || (metadata.uid() != 0 && (system || metadata.uid() != owner)) {
        return Err(StoreError::Refused("directory has the wrong type or owner"));
    }
    if leaf {
        if metadata.uid() != owner || metadata.mode() & 0o7777 != 0o700 {
            return Err(StoreError::Refused(
                "store directory must be owned and exactly 0700",
            ));
        }
    } else if path == Path::new("/private/tmp") && !system {
        if metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o1777 {
            return Err(StoreError::Refused(
                "shared temporary parent must be root-owned 01777",
            ));
        }
    } else if metadata.mode() & 0o022 != 0 {
        return Err(StoreError::Refused(
            "store ancestor permits group or other writes",
        ));
    }
    Ok(())
}

fn identity(metadata: &Metadata) -> (u64, u64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn inode_identity(metadata: &Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn acl_identity(metadata: &Metadata) -> (u64, u64, u32, u32, Option<(i64, i64)>) {
    // A shared sticky parent's ctime changes whenever another user creates a sibling. It is
    // not directory identity or evidence that its ACL changed. Trusted ownership and parent
    // write policy are checked separately; malicious owner/root ACL ABA remains out of scope.
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode(),
        (!metadata.is_dir()).then(|| (metadata.ctime(), metadata.ctime_nsec())),
    )
}

fn check_file(file: &File, owner: u32, path: &Path) -> Result<(), StoreError> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(StoreError::Refused(
            "record files must be regular, single-link, owned and exactly 0600",
        ));
    }
    check_empty_acl(file, path)
}

fn check_empty_acl(file: &File, expected_path: &Path) -> Result<(), StoreError> {
    let mut path = PathBuf::new();
    fcntl(file, FcntlArg::F_GETPATH(&mut path))?;
    if path != expected_path {
        return Err(StoreError::Refused(
            "held object no longer has its checked path",
        ));
    }
    let before: File = open(&path, file_flags(), Mode::empty())?.into();
    let stamp = acl_identity(&file.metadata()?);
    if acl_identity(&before.metadata()?) != stamp {
        return Err(StoreError::Refused(
            "ACL path does not identify the held object",
        ));
    }
    if !exacl::getfacl(&path, None)?.is_empty() {
        return Err(StoreError::Refused(
            "store paths and records must have empty ACLs",
        ));
    }
    let after: File = open(&path, file_flags(), Mode::empty())?.into();
    if acl_identity(&after.metadata()?) != stamp || acl_identity(&file.metadata()?) != stamp {
        return Err(StoreError::Refused("ACL path changed while observing"));
    }
    Ok(())
}

fn encode(kind: RecordKind, record: &StoredRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES + record.payload.len());
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&[kind.tag(), 0]);
    // The private constructor bounds payloads to 65,536, within u32 on every supported target.
    bytes.extend_from_slice(&(record.payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(record.identity.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(b"tunlatch-store-record-v1\0");
    hasher.update(&bytes);
    hasher.update(&record.payload);
    bytes.extend_from_slice(&hasher.finalize());
    bytes.extend_from_slice(&record.payload);
    bytes
}

fn decode(kind: RecordKind, bytes: &[u8]) -> Result<StoredRecord, StoreError> {
    let invalid = StoreError::InvalidRecord;
    if bytes.len() < HEADER_BYTES || &bytes[..8] != MAGIC {
        return Err(invalid("missing or truncated header"));
    }
    if u16::from_be_bytes([bytes[8], bytes[9]]) != VERSION {
        return Err(invalid("unsupported record version"));
    }
    if bytes[10] != kind.tag() || bytes[11] != 0 {
        return Err(invalid("wrong slot kind or unsupported header fields"));
    }
    let length = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    if length > MAX_RECORD_PAYLOAD_BYTES || bytes.len() != HEADER_BYTES + length {
        return Err(invalid("truncated, oversized or extra record bytes"));
    }
    let mut digest = [0; 32];
    digest.copy_from_slice(&bytes[16..48]);
    let identity = RecordIdentity::new(digest).map_err(|_| invalid("unset record identity"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"tunlatch-store-record-v1\0");
    hasher.update(&bytes[..48]);
    hasher.update(&bytes[HEADER_BYTES..]);
    if hasher.finalize().as_slice() != &bytes[48..HEADER_BYTES] {
        return Err(invalid("record content digest mismatch"));
    }
    StoredRecord::new(identity, bytes[HEADER_BYTES..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn fixture()
    -> Result<(tempfile::TempDir, UserRecordStore, StoredRecord), Box<dyn std::error::Error>> {
        let directory = tempfile::Builder::new()
            .prefix("tunlatch-store-fault-")
            .tempdir_in("/private/tmp")?;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
        let store = UserRecordStore::open(&directory.path().canonicalize()?)?;
        let record = StoredRecord::new(RecordIdentity::new([1; 32])?, b"enabled".to_vec())?;
        Ok((directory, store, record))
    }

    #[test]
    fn injected_write_and_file_sync_failures_preserve_the_old_record() -> TestResult {
        for failure in [CommitStage::Write, CommitStage::FileSync] {
            let (_directory, mut store, old) = fixture()?;
            store.replace(RecordKind::Policy, &old)?;
            let new = StoredRecord::new(RecordIdentity::new([2; 32])?, b"replacement".to_vec())?;
            let error = store
                .inner
                .replace(RecordKind::Policy, &new, |stage| {
                    if stage == failure {
                        Err(io::Error::other("injected storage failure"))
                    } else {
                        Ok(())
                    }
                })
                .err()
                .ok_or("injected fault was accepted")?;
            assert!(matches!(error, StoreError::BeforeRename { stage, .. } if stage == failure));
            assert!(!error.is_commit_unknown());
            assert_eq!(store.read(RecordKind::Policy)?, Some(old));
            store.replace(RecordKind::Policy, &new)?;
            assert_eq!(store.read(RecordKind::Policy)?, Some(new));
        }
        Ok(())
    }

    #[test]
    fn injected_rename_and_directory_sync_failures_report_unknown_with_valid_old_or_new()
    -> TestResult {
        for failure in [CommitStage::Rename, CommitStage::DirectorySync] {
            let (_directory, mut store, old) = fixture()?;
            store.replace(RecordKind::Policy, &old)?;
            let new = StoredRecord::new(RecordIdentity::new([2; 32])?, b"replacement".to_vec())?;
            let error = store
                .inner
                .replace(RecordKind::Policy, &new, |stage| {
                    if stage == failure {
                        Err(io::Error::other("injected storage failure"))
                    } else {
                        Ok(())
                    }
                })
                .err()
                .ok_or("injected fault was accepted")?;
            assert!(matches!(error, StoreError::CommitUnknown { stage, .. } if stage == failure));
            assert!(error.is_commit_unknown());
            assert_eq!(
                store.read(RecordKind::Policy)?,
                Some(if failure == CommitStage::Rename {
                    old
                } else {
                    new
                })
            );
        }
        Ok(())
    }

    #[test]
    fn a_replaced_name_is_neither_cleaned_up_nor_acknowledged_as_ours() -> TestResult {
        for stage_to_replace in [CommitStage::FileSync, CommitStage::DirectorySync] {
            let (directory, mut store, record) = fixture()?;
            let kind = RecordKind::Recovery;
            let name = if stage_to_replace == CommitStage::FileSync {
                kind.temporary_name()
            } else {
                kind.file_name()
            };
            let path = directory.path().join(name);
            let result = store.inner.replace(kind, &record, |stage| {
                if stage == stage_to_replace {
                    std::fs::rename(&path, directory.path().join("moved"))?;
                    std::fs::write(&path, b"replacement")?;
                    if stage == CommitStage::FileSync {
                        return Err(io::Error::other("injected replacement"));
                    }
                }
                Ok(())
            });
            assert_eq!(std::fs::read(&path)?, b"replacement");
            match stage_to_replace {
                CommitStage::FileSync => {
                    assert!(matches!(result, Err(StoreError::BeforeRename { .. })))
                }
                _ => assert!(matches!(result, Err(StoreError::CommitUnknown { .. }))),
            }
        }
        Ok(())
    }

    #[test]
    fn wrong_expected_owner_and_untrusted_sticky_ancestors_are_refused() -> TestResult {
        let (_directory, store, _old) = fixture()?;
        let path = store.inner.chain.path().join(LOCK_NAME);
        assert!(check_file(&store.inner.lock, Uid::effective().as_raw() ^ 1, &path).is_err());
        let metadata = store.inner.chain.directory()?.metadata()?;
        assert!(
            check_directory(
                &metadata,
                Uid::effective().as_raw() ^ 1,
                false,
                Path::new("/other"),
                true
            )
            .is_err()
        );
        let shared = std::fs::metadata("/private/tmp")?;
        assert!(check_directory(&shared, 0, true, Path::new("/private/tmp"), false).is_err());
        assert!(
            check_directory(
                &shared,
                Uid::effective().as_raw(),
                false,
                Path::new("/other"),
                false
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn held_directory_and_lock_descriptors_are_close_on_exec() -> TestResult {
        let (_directory, store, _old) = fixture()?;
        for file in store
            .inner
            .chain
            .directories
            .iter()
            .map(|(_, file)| file)
            .chain([&store.inner.lock])
        {
            let flags = fcntl(file, FcntlArg::F_GETFD)?;
            assert_ne!(flags & nix::libc::FD_CLOEXEC, 0);
            assert!(file.as_raw_fd() >= 0);
        }
        Ok(())
    }
}
