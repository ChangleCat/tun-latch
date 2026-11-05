//! Native macOS path ACL and held parent-chain inspection. No privilege or PF operations.
//!
//! exacl's published 0.13.0 API is path-based. Resolve the held descriptor's current path,
//! compare opened objects before/after, and refuse changes. This cannot detect an owner/root
//! ABA replacement during the call and is NOT a descriptor ACL or launch attestation.

use std::fs::File;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use nix::fcntl::{FcntlArg, OFlag, fcntl, open, openat};
use nix::sys::stat::Mode;

use super::bootstrap::{Acl, Ancestor, Error, Result, check_ancestors};

pub(crate) struct NativePathInspection;

// Deliberately does NOT implement bootstrap::Inspection: that contract requires the ACL of
// the held object itself. A path-associated observation cannot be silently promoted to it.
impl NativePathInspection {
    pub(crate) fn acl(&mut self, file: &File) -> Acl {
        match path_acl(file) {
            Ok(entries) if entries.is_empty() => Acl::Empty,
            Ok(_) => Acl::Present,
            Err(_) => Acl::Unknown,
        }
    }
}

fn path_acl(file: &File) -> std::io::Result<Vec<exacl::AclEntry>> {
    let mut path = PathBuf::new();
    fcntl(file, FcntlArg::F_GETPATH(&mut path))?;
    let flags = OFlag::O_RDONLY | OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK;
    let before: File = open(&path, flags, Mode::empty())?.into();
    let held = file.metadata()?;
    let a = before.metadata()?;
    if (held.dev(), held.ino(), held.ctime(), held.ctime_nsec())
        != (a.dev(), a.ino(), a.ctime(), a.ctime_nsec())
    {
        return Err(std::io::Error::other(
            "ACL locator differs from held object",
        ));
    }
    let entries = exacl::getfacl(&path, None)?;
    let after: File = open(&path, flags, Mode::empty())?.into();
    let b = after.metadata()?;
    let c = file.metadata()?;
    if (a.dev(), a.ino(), a.ctime(), a.ctime_nsec())
        != (b.dev(), b.ino(), b.ctime(), b.ctime_nsec())
        || (a.dev(), a.ino(), a.ctime(), a.ctime_nsec())
            != (c.dev(), c.ino(), c.ctime(), c.ctime_nsec())
    {
        return Err(std::io::Error::other("ACL object changed while observing"));
    }
    Ok(entries)
}

/// Holds every directory opened from `/`. This is a filesystem observation, never a launch
/// attestation or evidence that an administrative exclusive window currently exists.
pub(crate) struct ObservedChain {
    directories: Vec<File>,
    owner: u32,
}

impl ObservedChain {
    pub(crate) fn open(path: &Path) -> Result<Self> {
        Self::open_owned(path, 0)
    }

    fn open_owned(path: &Path, owner: u32) -> Result<Self> {
        if !path.is_absolute() || path.as_os_str().len() > 1024 {
            return Err(Error::Refused(
                "requires a bounded absolute directory chain",
            ));
        }
        let flags = OFlag::O_RDONLY
            | OFlag::O_DIRECTORY
            | OFlag::O_NOFOLLOW
            | OFlag::O_CLOEXEC
            | OFlag::O_NONBLOCK;
        let root: File = open(Path::new("/"), flags, Mode::empty())?.into();
        let mut result = Self {
            directories: vec![root],
            owner,
        };
        for component in path.components().skip(1) {
            // Parent traversal is never normalized away, even when it would return to `/`.
            let Component::Normal(name) = component else {
                return Err(Error::Refused("noncanonical directory component"));
            };
            if result.directories.len() >= 32 {
                return Err(Error::Refused("excessive directory depth"));
            }
            // Check the current parent before using it to resolve the next component.
            result.recheck()?;
            let next = openat(result.directory()?, name, flags, Mode::empty())?;
            result.directories.push(next.into());
        }
        result.recheck()?;
        Ok(result)
    }

    pub(crate) fn recheck(&self) -> Result<()> {
        let mut inspection = NativePathInspection;
        let observations = self
            .directories
            .iter()
            .map(|file| {
                let metadata = file.metadata()?;
                Ok(Ancestor {
                    owner: metadata.uid(),
                    mode: metadata.mode(),
                    directory: metadata.is_dir(),
                    acl: inspection.acl(file),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        check_ancestors(&observations, self.owner)
    }

    pub(crate) fn directory(&self) -> Result<&File> {
        self.directories
            .last()
            .ok_or(Error::Refused("empty directory chain"))
    }
}
