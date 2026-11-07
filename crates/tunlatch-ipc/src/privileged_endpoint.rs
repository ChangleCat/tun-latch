//! Fixed system socket client and transport peer checks for a future privileged service.
//!
//! These checks do not establish human authorization. ACL inspection is path-based and cannot
//! exclude a trusted root actor performing an ABA replacement. Native filesystem calls are
//! synchronous and cannot be hard-cancelled by the asynchronous connection deadline.

use std::fs::File;
use std::num::NonZeroU32;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{AtFlags, FcntlArg, OFlag, fcntl, open, openat};
use nix::sys::stat::{FchmodatFlags, Mode, SFlag, fchmodat, fstatat};
use nix::unistd::{UnlinkatFlags, unlinkat};
use tokio::net::{UnixListener, UnixStream};
use tunlatch_platform::launchd::{
    CONTROL_DIRECTORY_NAME, CONTROL_SOCKET_NAME, QUERY_SOCKET_NAME, SYSTEM_RUNTIME_DIRECTORY,
};

use crate::{IpcError, REQUEST_TIMEOUT};

fn refused(message: &'static str) -> IpcError {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message).into()
}

fn flags() -> OFlag {
    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK
}

/// Connect to the fixed public query socket, verifying the root peer before returning it.
pub async fn connect_query() -> Result<UnixStream, IpcError> {
    connect(
        Path::new(SYSTEM_RUNTIME_DIRECTORY),
        QUERY_SOCKET_NAME,
        false,
        Policy::system(),
    )
    .await
}

/// Connect to the fixed root-only control socket. Actual effective UID must already be zero.
pub async fn connect_control() -> Result<UnixStream, IpcError> {
    if !nix::unistd::geteuid().is_root() {
        return Err(refused("control endpoint requires effective UID 0"));
    }
    connect(
        &Path::new(SYSTEM_RUNTIME_DIRECTORY).join(CONTROL_DIRECTORY_NAME),
        CONTROL_SOCKET_NAME,
        true,
        Policy::system(),
    )
    .await
}

/// Check an accepted query connection against the configured non-root owner or root.
/// This only authenticates the kernel-reported transport peer, not a human action.
pub fn verify_query_client(stream: &UnixStream, owner: NonZeroU32) -> Result<(), IpcError> {
    let actual = stream.peer_cred()?.uid();
    if actual != 0 && actual != owner.get() {
        return Err(IpcError::Peer {
            expected: owner.get(),
            actual,
        });
    }
    Ok(())
}

/// Check that an accepted control connection has a root kernel-reported peer.
/// This is not proof of an administrator's confirmation.
pub fn verify_control_client(stream: &UnixStream) -> Result<(), IpcError> {
    verify_uid(stream, 0)
}

fn verify_uid(stream: &UnixStream, expected: u32) -> Result<(), IpcError> {
    let actual = stream.peer_cred()?.uid();
    if actual != expected {
        return Err(IpcError::Peer { expected, actual });
    }
    Ok(())
}

/// The two fixed listeners for the future privileged service.
///
/// Directories must already exist and satisfy the system policy. Transport peer
/// authentication does not establish human approval. Cleanup rechecks the entries
/// created by this instance and assumes exclusive writes by the trusted directory owner.
pub struct SystemListeners {
    query: OwnedListener,
    control: OwnedListener,
    owner: NonZeroU32,
}

impl SystemListeners {
    /// Bind both fixed sockets in a Tokio I/O runtime, requiring effective UID and GID zero.
    /// An uncertain failure after bind can leave an entry for explicit operator inspection.
    pub fn bind(owner: NonZeroU32) -> Result<Self, IpcError> {
        if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
            return Err(refused("system listeners require effective UID and GID 0"));
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| refused("system listeners require a Tokio runtime"))?;
        Self::bind_at(
            Path::new(SYSTEM_RUNTIME_DIRECTORY),
            owner,
            Policy::system(),
            OwnedListener::bind,
        )
    }

    fn bind_at(
        runtime: &Path,
        owner: NonZeroU32,
        policy: Policy,
        mut bind: impl FnMut(Chain, &'static str, bool) -> Result<OwnedListener, IpcError>,
    ) -> Result<Self, IpcError> {
        let query = Chain::open(runtime, policy, false)?;
        let control = Chain::open(&runtime.join(CONTROL_DIRECTORY_NAME), policy, true)?;
        query.absent(QUERY_SOCKET_NAME)?;
        control.absent(CONTROL_SOCKET_NAME)?;
        let query = bind(query, QUERY_SOCKET_NAME, false)?;
        let control = bind(control, CONTROL_SOCKET_NAME, true)?;
        Ok(Self {
            query,
            control,
            owner,
        })
    }

    /// Accept a connection only if its kernel-reported peer is the owner or root.
    pub async fn accept_query(&self) -> Result<UnixStream, IpcError> {
        let (stream, _) = self.query.listener.accept().await?;
        verify_query_client(&stream, self.owner)?;
        Ok(stream)
    }

    /// Accept a connection only if its kernel-reported peer is root.
    pub async fn accept_control(&self) -> Result<UnixStream, IpcError> {
        let (stream, _) = self.control.listener.accept().await?;
        verify_control_client(&stream)?;
        Ok(stream)
    }
}

struct OwnedListener {
    listener: UnixListener,
    chain: Chain,
    name: &'static str,
    stamp: SocketStamp,
}

impl OwnedListener {
    fn bind(chain: Chain, name: &'static str, control: bool) -> Result<Self, IpcError> {
        chain.absent(name)?;
        let listener = UnixListener::bind(chain.path().join(name))?;
        // The bound descriptor's inode is not the filesystem entry's inode on Darwin.
        // Infer ownership from bind in the protected directory and validate before changing
        // permissions. Preserve the entry if this setup cannot establish a final stamp.
        let before = chain.checked_socket(name, None)?;
        fchmodat(
            chain.last()?,
            name,
            Mode::from_bits_truncate(if control { 0o600 } else { 0o666 }),
            FchmodatFlags::NoFollowSymlink,
        )
        .map_err(std::io::Error::from)?;
        let after = chain.socket(name, control)?;
        if (after.0, after.1) != (before.0, before.1) {
            return Err(refused("created endpoint replaced"));
        }
        Ok(Self {
            listener,
            chain,
            name,
            stamp: after,
        })
    }
}

impl Drop for OwnedListener {
    fn drop(&mut self) {
        // A failure to prove identity or directory integrity leaves the entry intact.
        if !self
            .chain
            .socket(self.name, self.chain.control)
            .is_ok_and(|current| current == self.stamp)
        {
            return;
        }
        if let Ok(dir) = self.chain.last() {
            let _ = unlinkat(dir, self.name, UnlinkatFlags::NoRemoveDir);
        }
    }
}

#[derive(Clone, Copy)]
struct Policy {
    owner: u32,
    group: u32,
    #[cfg(test)]
    fixture: bool,
}
impl Policy {
    fn system() -> Self {
        Self {
            owner: 0,
            group: 0,
            #[cfg(test)]
            fixture: false,
        }
    }
}

struct Chain {
    directories: Vec<(PathBuf, File)>,
    policy: Policy,
    control: bool,
}

impl Chain {
    fn open(path: &Path, policy: Policy, control: bool) -> Result<Self, IpcError> {
        if !path.is_absolute() || path.as_os_str().len() > 1024 {
            return Err(refused("invalid endpoint path"));
        }
        let root: File = open(Path::new("/"), flags(), Mode::empty())
            .map_err(std::io::Error::from)?
            .into();
        let mut chain = Self {
            directories: vec![(PathBuf::from("/"), root)],
            policy,
            control,
        };
        for component in path.components().skip(1) {
            let Component::Normal(name) = component else {
                return Err(refused("invalid endpoint component"));
            };
            if chain.directories.len() >= 32 {
                return Err(refused("endpoint path too deep"));
            }
            chain.recheck(false)?;
            let next: File = openat(chain.last()?, name, flags(), Mode::empty())
                .map_err(std::io::Error::from)?
                .into();
            let next_path = chain.path().join(name);
            chain.directories.push((next_path, next));
        }
        if chain.path() != path {
            return Err(refused("noncanonical endpoint path"));
        }
        chain.recheck(true)?;
        Ok(chain)
    }
    fn last(&self) -> Result<&File, IpcError> {
        self.directories
            .last()
            .map(|(_, file)| file)
            .ok_or_else(|| refused("empty endpoint chain"))
    }
    fn path(&self) -> &Path {
        self.directories
            .last()
            .map_or(Path::new("/"), |(path, _)| path)
    }
    fn recheck(&self, final_chain: bool) -> Result<(), IpcError> {
        for (index, (path, file)) in self.directories.iter().enumerate() {
            let metadata = file.metadata()?;
            let leaf = final_chain && index + 1 == self.directories.len();
            let runtime = final_chain && self.control && index + 2 == self.directories.len();
            #[cfg(test)]
            let shared_tmp = self.policy.fixture && path == Path::new("/private/tmp");
            #[cfg(not(test))]
            let shared_tmp = false;
            #[cfg(test)]
            let fixture_owned = self.policy.fixture
                && path != Path::new("/private/tmp")
                && path.starts_with("/private/tmp");
            #[cfg(not(test))]
            let fixture_owned = false;
            let expected_owner = if leaf || runtime || fixture_owned {
                self.policy.owner
            } else {
                0
            };
            if !metadata.is_dir() || metadata.uid() != expected_owner {
                return Err(refused("endpoint directory type or owner mismatch"));
            }
            if leaf || runtime {
                let mode = if leaf && self.control { 0o700 } else { 0o755 };
                if metadata.gid() != self.policy.group || metadata.mode() & 0o7777 != mode {
                    return Err(refused("endpoint directory group or mode mismatch"));
                }
            } else if shared_tmp {
                if metadata.mode() & 0o7777 != 0o1777 {
                    return Err(refused("invalid temporary parent"));
                }
            } else if metadata.mode() & 0o022 != 0 {
                return Err(refused("endpoint ancestor is writable"));
            }
            let mut actual_path = PathBuf::new();
            fcntl(file, FcntlArg::F_GETPATH(&mut actual_path)).map_err(std::io::Error::from)?;
            if actual_path != *path {
                return Err(refused("endpoint directory moved"));
            }
            let before = metadata_stamp(&metadata);
            if index > 0 {
                let parent = &self.directories[index - 1].1;
                let name = path
                    .file_name()
                    .ok_or_else(|| refused("missing directory name"))?;
                let reopened: File = openat(parent, name, flags(), Mode::empty())
                    .map_err(std::io::Error::from)?
                    .into();
                if inode(&reopened.metadata()?) != inode(&metadata) {
                    return Err(refused("endpoint directory replaced"));
                }
            }
            if !exacl::getfacl(path, Some(exacl::AclOption::SYMLINK_ACL))?.is_empty() {
                return Err(refused("endpoint directory has an ACL"));
            }
            if metadata_stamp(&file.metadata()?) != before {
                return Err(refused("endpoint directory changed"));
            }
        }
        Ok(())
    }
    fn socket(&self, name: &str, control: bool) -> Result<SocketStamp, IpcError> {
        self.checked_socket(name, Some(if control { 0o600 } else { 0o666 }))
    }
    fn checked_socket(&self, name: &str, mode: Option<u16>) -> Result<SocketStamp, IpcError> {
        self.recheck(true)?;
        let before = self.socket_stat(name)?;
        if SFlag::from_bits_truncate(before.st_mode & SFlag::S_IFMT.bits()) != SFlag::S_IFSOCK
            || before.st_uid != self.policy.owner
            || before.st_gid != self.policy.group
            || mode.is_some_and(|mode| before.st_mode & 0o7777 != mode)
            || before.st_nlink != 1
        {
            return Err(refused("endpoint socket attributes mismatch"));
        }
        let path = self.path().join(name);
        if !exacl::getfacl(&path, Some(exacl::AclOption::SYMLINK_ACL))?.is_empty() {
            return Err(refused("endpoint socket has an ACL"));
        }
        let stamp = socket_stamp(&before);
        if socket_stamp(&self.socket_stat(name)?) != stamp {
            return Err(refused("endpoint socket changed"));
        }
        self.recheck(true)?;
        Ok(stamp)
    }
    fn absent(&self, name: &str) -> Result<(), IpcError> {
        self.recheck(true)?;
        match fstatat(self.last()?, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Err(nix::errno::Errno::ENOENT) => Ok(()),
            Ok(_) => Err(refused("endpoint slot already exists")),
            Err(error) => Err(std::io::Error::from(error).into()),
        }
    }
    fn socket_stat(&self, name: &str) -> Result<nix::sys::stat::FileStat, IpcError> {
        fstatat(self.last()?, name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|e| std::io::Error::from(e).into())
    }
}

fn inode(meta: &std::fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}
fn metadata_stamp(meta: &std::fs::Metadata) -> (u64, u64, u32, u32, u32) {
    (meta.dev(), meta.ino(), meta.uid(), meta.gid(), meta.mode())
}
type SocketStamp = (u64, u64, u32, u32, u16, u16, i64, i64);
fn socket_stamp(stat: &nix::sys::stat::FileStat) -> SocketStamp {
    (
        stat.st_dev as u64,
        stat.st_ino,
        stat.st_uid,
        stat.st_gid,
        stat.st_mode,
        stat.st_nlink,
        stat.st_ctime,
        stat.st_ctime_nsec,
    )
}

async fn connect(
    path: &Path,
    name: &str,
    control: bool,
    policy: Policy,
) -> Result<UnixStream, IpcError> {
    let deadline = tokio::time::Instant::now() + REQUEST_TIMEOUT;
    tokio::time::timeout_at(deadline, async {
        let chain = Chain::open(path, policy, control)?;
        let before = chain.socket(name, control)?;
        if tokio::time::Instant::now() >= deadline {
            return Err(IpcError::Timeout);
        }
        let stream = UnixStream::connect(path.join(name)).await?;
        verify_uid(&stream, 0)?;
        if chain.socket(name, control)? != before {
            return Err(refused("endpoint socket replaced during connect"));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(IpcError::Timeout);
        }
        Ok(stream)
    })
    .await
    .map_err(|_| IpcError::Timeout)?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tokio::net::UnixListener;

    fn policy(runtime: &Path) -> Result<Policy, std::io::Error> {
        Ok(Policy {
            owner: nix::unistd::geteuid().as_raw(),
            group: runtime.metadata()?.gid(),
            fixture: true,
        })
    }

    fn fixture() -> Result<(tempfile::TempDir, PathBuf), Box<dyn std::error::Error>> {
        let base = tempfile::Builder::new()
            .prefix("tunlatch-endpoint-")
            .tempdir_in("/private/tmp")?;
        std::fs::set_permissions(base.path(), std::fs::Permissions::from_mode(0o700))?;
        let runtime = base.path().join("runtime");
        std::fs::create_dir(&runtime)?;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755))?;
        Ok((base, runtime))
    }

    #[tokio::test]
    async fn listener_modes_and_replacement_cleanup() -> Result<(), Box<dyn std::error::Error>> {
        let (_base, runtime) = fixture()?;
        let control = runtime.join(CONTROL_DIRECTORY_NAME);
        std::fs::create_dir(&control)?;
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700))?;
        let owner =
            NonZeroU32::new(nix::unistd::geteuid().as_raw()).ok_or("requires non-root fixture")?;
        let listeners =
            SystemListeners::bind_at(&runtime, owner, policy(&runtime)?, OwnedListener::bind)?;
        let query_path = runtime.join(QUERY_SOCKET_NAME);
        let control_path = control.join(CONTROL_SOCKET_NAME);
        assert_eq!(query_path.metadata()?.mode() & 0o7777, 0o666);
        assert_eq!(control_path.metadata()?.mode() & 0o7777, 0o600);
        std::fs::rename(&query_path, runtime.join("old.sock"))?;
        let replacement = UnixListener::bind(&query_path)?;
        drop(listeners);
        assert!(query_path.exists());
        assert!(!control_path.exists());
        drop(replacement);
        Ok(())
    }

    #[tokio::test]
    async fn existing_control_slot_prevents_any_binding() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_base, runtime) = fixture()?;
        let control = runtime.join(CONTROL_DIRECTORY_NAME);
        std::fs::create_dir(&control)?;
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700))?;
        let occupied = control.join(CONTROL_SOCKET_NAME);
        std::fs::write(&occupied, b"preserve")?;
        let owner =
            NonZeroU32::new(nix::unistd::geteuid().as_raw()).ok_or("requires non-root fixture")?;
        assert!(
            SystemListeners::bind_at(&runtime, owner, policy(&runtime)?, OwnedListener::bind)
                .is_err()
        );
        assert_eq!(std::fs::read(occupied)?, b"preserve");
        assert!(!runtime.join(QUERY_SOCKET_NAME).exists());
        Ok(())
    }

    #[tokio::test]
    async fn partial_startup_removes_only_owned_socket() -> Result<(), Box<dyn std::error::Error>> {
        let (_base, runtime) = fixture()?;
        let control = runtime.join(CONTROL_DIRECTORY_NAME);
        std::fs::create_dir(&control)?;
        std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700))?;
        let occupied = control.join(CONTROL_SOCKET_NAME);
        let owner =
            NonZeroU32::new(nix::unistd::geteuid().as_raw()).ok_or("requires non-root fixture")?;
        let result = SystemListeners::bind_at(
            &runtime,
            owner,
            policy(&runtime)?,
            |chain, name, control| {
                if control {
                    std::fs::write(&occupied, b"preserve")?;
                }
                OwnedListener::bind(chain, name, control)
            },
        );
        assert!(result.is_err());
        assert!(!runtime.join(QUERY_SOCKET_NAME).exists());
        assert_eq!(std::fs::read(occupied)?, b"preserve");
        Ok(())
    }

    #[tokio::test]
    async fn system_binding_rejects_non_root() -> Result<(), Box<dyn std::error::Error>> {
        if !nix::unistd::geteuid().is_root() {
            let owner = NonZeroU32::new(nix::unistd::geteuid().as_raw()).ok_or("nonzero uid")?;
            assert!(SystemListeners::bind(owner).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_wrong_peer_and_accepts_configured_query_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let (a, b) = UnixStream::pair()?;
        let uid = nix::unistd::geteuid().as_raw();
        if let Some(owner) = NonZeroU32::new(uid) {
            verify_query_client(&a, owner)?;
            assert!(
                matches!(verify_control_client(&b), Err(IpcError::Peer { expected: 0, actual }) if actual == uid)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn validates_socket_and_detects_replacement() -> Result<(), Box<dyn std::error::Error>> {
        let (_base, runtime) = fixture()?;
        let path = runtime.join("query.sock");
        let listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        let chain = Chain::open(&runtime, policy(&runtime)?, false)?;
        let old = chain.socket("query.sock", false)?;
        std::fs::rename(&path, runtime.join("old.sock"))?;
        let replacement = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        assert_ne!(old, chain.socket("query.sock", false)?);
        drop((listener, replacement));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_symlink_writable_and_wrong_socket_mode()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_base, runtime) = fixture()?;
        let path = runtime.join("query.sock");
        symlink("missing", &path)?;
        let chain = Chain::open(&runtime, policy(&runtime)?, false)?;
        assert!(chain.socket("query.sock", false).is_err());
        std::fs::remove_file(&path)?;
        let _listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        assert!(chain.socket("query.sock", false).is_err());
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o777))?;
        assert!(Chain::open(&runtime, policy(&runtime)?, false).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn rejects_acl_and_replaced_directory() -> Result<(), Box<dyn std::error::Error>> {
        let (base, runtime) = fixture()?;
        let chain = Chain::open(&runtime, policy(&runtime)?, false)?;
        let entry = exacl::AclEntry::allow_user("nobody", exacl::Perm::READ, None);
        exacl::setfacl(&[&runtime], &[entry], None)?;
        assert!(chain.recheck(true).is_err());
        exacl::setfacl(&[&runtime], &[], None)?;
        chain.recheck(true)?;
        std::fs::rename(&runtime, base.path().join("moved"))?;
        std::fs::create_dir(&runtime)?;
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755))?;
        assert!(chain.recheck(true).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn rejects_ordinary_server_before_returning_stream()
    -> Result<(), Box<dyn std::error::Error>> {
        if nix::unistd::geteuid().is_root() {
            return Ok(());
        }
        let (_base, runtime) = fixture()?;
        let path = runtime.join("query.sock");
        let _listener = UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
        let result = connect(&runtime, "query.sock", false, policy(&runtime)?).await;
        assert!(matches!(result, Err(IpcError::Peer { expected: 0, .. })));
        assert!(connect_control().await.is_err());
        Ok(())
    }
}
