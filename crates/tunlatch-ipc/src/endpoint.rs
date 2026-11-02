//! Development socket lifecycle. This is a same-user observer, not the future privileged endpoint.

use std::fs;
use std::io;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use tokio::net::UnixListener;

/// Only socket name used inside the explicit private runtime directory.
pub const SOCKET_NAME: &str = "control.sock";

fn denied(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

/// Require an existing, non-symlink directory owned by this user and inaccessible to other users.
///
/// All current endpoints are unprivileged and same-user. Ancestor trust and root/client separation
/// must be designed before reusing any of this for a privileged LaunchDaemon.
pub fn validate_runtime_dir(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(denied("runtime path must be a real directory"));
    }
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(denied(
            "runtime directory must be owned by this user with mode 0700",
        ));
    }
    if metadata.mode() & 0o700 != 0o700 {
        return Err(denied(
            "runtime directory requires owner read/write/search permissions",
        ));
    }
    Ok(())
}

/// Reject non-socket paths, foreign owners and group/world-accessible socket files.
pub fn validate_socket(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(denied(
            "endpoint must be a private socket owned by this user",
        ));
    }
    Ok(())
}

/// Owns a listener and removes only the exact socket inode it created.
///
/// Existing paths are never removed at startup. Cleanup has no firewall side effects.
pub struct ServerSocket {
    listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl ServerSocket {
    /// Bind inside a validated private directory; an existing endpoint is a startup error.
    pub fn bind(runtime_dir: &Path) -> io::Result<Self> {
        validate_runtime_dir(runtime_dir)?;
        let path = runtime_dir.join(SOCKET_NAME);
        let listener = UnixListener::bind(&path)?;
        let metadata = fs::symlink_metadata(&path)?;
        let socket = Self {
            listener,
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600))?;
        Ok(socket)
    }

    /// Accept the next connection; peer authorization is performed separately before reading input.
    pub async fn accept(&self) -> io::Result<tokio::net::UnixStream> {
        self.listener
            .accept()
            .await
            .map(|(stream, _address)| stream)
    }
}

impl Drop for ServerSocket {
    fn drop(&mut self) {
        // Best-effort diagnostic cleanup. It must never delete another listener's replacement path.
        let result = (|| {
            let metadata = match fs::symlink_metadata(&self.path) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error),
            };
            if metadata.dev() != self.device || metadata.ino() != self.inode {
                return Err(denied("endpoint path was replaced; refusing cleanup"));
            }
            fs::remove_file(&self.path)
        })();
        if let Err(error) = result {
            tracing::warn!(%error, "socket cleanup failed; firewall state is unaffected");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_public_directory_and_symlink() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))?;
        assert!(ServerSocket::bind(dir.path()).is_err());
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(dir.path(), &link)?;
        assert!(ServerSocket::bind(&link).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn startup_preserves_existing_endpoint_and_cleanup_preserves_replacement()
    -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
        let socket = ServerSocket::bind(dir.path())?;
        let path = dir.path().join(SOCKET_NAME);
        assert!(ServerSocket::bind(dir.path()).is_err());
        validate_socket(&path)?;
        fs::remove_file(&path)?;
        fs::write(&path, "replacement")?;
        drop(socket);
        assert_eq!(fs::read_to_string(path)?, "replacement");
        Ok(())
    }
}
