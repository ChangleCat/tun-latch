//! Independent read-only qualification of the root filter adapter.
//!
//! A matching result is only a prerequisite for later writes. It does not prove ownership,
//! effective filtering, or that another writer cannot change PF immediately afterwards.

use std::fs::File;

use nix::fcntl::{OFlag, open};
use nix::sys::stat::Mode;

use super::{native_hook, snapshot};

/// Failure to qualify the private native PF interface on this host.
#[derive(Debug, thiserror::Error)]
pub enum QualificationError {
    /// A fixed system query failed or returned incomplete output.
    #[error("PF qualification query failed: {0}")]
    Query(#[from] snapshot::SnapshotError),
    /// The caller lacks permission to inspect PF or the device could not be opened.
    #[error("cannot open PF device: {0}")]
    Device(#[from] nix::errno::Errno),
    /// The host, native PF response, or cross-check did not meet the adapter's requirements.
    #[error("PF native qualification failed: {0}")]
    Refused(&'static str),
}

/// Number of root filter entries seen by both independent readers.
#[derive(Debug, Eq, PartialEq)]
pub struct Qualification {
    /// Number of filter entries, excluding the separately displayed scrub anchor.
    pub filter_rules: usize,
}

/// Compare a native root filter enumeration with independent `pfctl` reads on a qualified host.
///
/// Requires an already-root caller and opens `/dev/pf` read-only. The native transport rejects
/// write operations even though Darwin may accept them on read-only descriptors. Observations
/// are not atomic and this function does not authorize PF changes or establish protection.
pub fn check_root_filter() -> Result<Qualification, QualificationError> {
    if !nix::unistd::geteuid().is_root() {
        return Err(QualificationError::Refused("root is required"));
    }
    let (build, kernel) = snapshot::host_identity()?;
    native_hook::check_host(&build, &kernel)
        .map_err(|_| QualificationError::Refused("unqualified host"))?;
    let device: File = open(
        "/dev/pf",
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )?
    .into();
    let before = snapshot::query(snapshot::Query::RootRules)?;
    let native = native_hook::readonly_rules(&device, &build, &kernel)
        .map_err(|_| QualificationError::Refused("native root filter read failed"))?;
    let after = snapshot::query(snapshot::Query::RootRules)?;
    compare(&before, &native, &after)
}

fn compare(
    before: &[u8],
    native: &[native_hook::ReadonlyRule],
    after: &[u8],
) -> Result<Qualification, QualificationError> {
    if before != after {
        return Err(QualificationError::Refused(
            "root filter changed during inspection",
        ));
    }
    let textual = native_hook::parse_rules(before)
        .map_err(|_| QualificationError::Refused("unsupported root filter output"))?;
    if textual != native {
        return Err(QualificationError::Refused(
            "native and pfctl root filters disagree",
        ));
    }
    Ok(Qualification {
        filter_rules: native.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_stable_matching_independent_reads() {
        let before = b"pass out all\nanchor \"com.apple/*\" all\n";
        let native = vec![
            native_hook::ReadonlyRule {
                class: "pass",
                call: String::new(),
            },
            native_hook::ReadonlyRule {
                class: "anchor",
                call: "com.apple/*".to_owned(),
            },
        ];
        assert_eq!(
            compare(before, &native, before).ok(),
            Some(Qualification { filter_rules: 2 })
        );
        assert!(compare(before, &native, b"block out all\n").is_err());
        assert!(compare(before, &native[..1], before).is_err());
        assert!(compare(b"unsupported\n", &native, b"unsupported\n").is_err());
    }
}
