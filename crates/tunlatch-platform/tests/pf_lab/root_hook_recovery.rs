//! Offline root call lifecycle using the real journal and a simulated PF boundary.

use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU64;
use std::os::unix::fs::MetadataExt;

use nix::errno::Errno;
use nix::fcntl::{AtFlags, OFlag, openat};
use nix::sys::stat::{Mode, fstatat, mkdirat};
use sha2::{Digest, Sha256};

use super::bootstrap::{Acl, Error, Result};
use super::driver::{Guard, Observation};
use super::ledger::{Ledger, Operation};
use super::native_files::NativePathInspection;
use super::root_hook_readback::{self as readback, Observation as RuleBytes};

const RECEIPT: &str = "root-call.receipt";
const SIZE: usize = 8 + 8 + 4 + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Receipt {
    pub(crate) ticket: NonZeroU64,
    pub(crate) index: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Leaf {
    Absent,
    Empty,
    Other,
}

pub(crate) struct View {
    pub(crate) observation: Observation,
    pub(crate) root_rules: Vec<u8>,
    pub(crate) foreign: [u8; 32],
    pub(crate) hook: Option<(String, Receipt)>,
    pub(crate) leaf: Leaf,
}

pub(crate) trait Boundary {
    fn observe(&mut self) -> Result<View>;
    fn insert(&mut self, anchor: &str) -> Result<NonZeroU64>;
    fn remove(&mut self, anchor: &str, ticket: NonZeroU64) -> Result<()>;
}

pub(crate) struct Trial<'a> {
    guard: Guard,
    anchor: &'a str,
    root_before: &'a [u8],
    index: u32,
    foreign: [u8; 32],
    binding: [u8; 32],
}

impl<'a> Trial<'a> {
    pub(crate) fn new(
        guard: Guard,
        anchor: &'a str,
        root_before: &'a [u8],
        index: u32,
        foreign: [u8; 32],
    ) -> Result<Self> {
        readback::validate_index(bytes(root_before), anchor, index as usize)
            .map_err(Error::Refused)?;
        if foreign == [0; 32] {
            return Err(Error::Refused(
                "foreign baseline or intended root index invalid",
            ));
        }
        let identity = guard.identity();
        let mut hash = Sha256::new();
        hash.update(b"tunlatch-lab-root-call\0");
        hash.update(identity.boot);
        hash.update(identity.session);
        hash.update(identity.plan);
        hash.update(identity.controller_birth.to_be_bytes());
        hash.update(identity.lock_inode.to_be_bytes());
        hash.update(index.to_be_bytes());
        hash.update(foreign);
        hash.update(anchor);
        hash.update(root_before);
        Ok(Self {
            guard,
            anchor,
            root_before,
            index,
            foreign,
            binding: hash.finalize().into(),
        })
    }

    fn observe(&mut self, boundary: &mut impl Boundary) -> Result<View> {
        let view = boundary.observe()?;
        self.guard
            .check(view.observation)
            .map_err(|err| Error::Refused(err.0))?;
        if view.foreign != self.foreign {
            return Err(Error::Refused("foreign PF baseline changed"));
        }
        Ok(view)
    }

    fn detached(&mut self, boundary: &mut impl Boundary, fresh: bool) -> Result<()> {
        let view = self.observe(boundary)?;
        if view.hook.is_some() || view.leaf == Leaf::Other || (fresh && view.leaf != Leaf::Absent) {
            return Err(Error::Refused(
                "expected detached empty or fresh absent slot",
            ));
        }
        readback::verify_detached(
            bytes(self.root_before),
            bytes(&view.root_rules),
            self.anchor,
        )
        .map_err(Error::Refused)
    }

    fn attached(&mut self, boundary: &mut impl Boundary, ticket: NonZeroU64) -> Result<Receipt> {
        let view = self.observe(boundary)?;
        let (owner, receipt) = view.hook.ok_or(Error::Refused("root call missing"))?;
        if owner != self.anchor
            || receipt.ticket != ticket
            || receipt.index != self.index
            || view.leaf != Leaf::Empty
        {
            return Err(Error::Refused(
                "root call instance or empty leaf did not match",
            ));
        }
        readback::verify(
            bytes(self.root_before),
            bytes(&view.root_rules),
            self.anchor,
            receipt.index as usize,
        )
        .map_err(Error::Refused)?;
        Ok(receipt)
    }

    /// Fresh stage only. An inserted call with an unknown result is never removed here.
    pub(crate) fn attach(&mut self, directory: &File, boundary: &mut impl Boundary) -> Result<()> {
        self.detached(boundary, true)?;
        require_no_receipts(directory)?;
        let mut stage = Ledger::create(
            directory.try_clone()?,
            self.guard.identity().session,
            self.binding,
        )?;
        stage.begin(Operation::ChangeHook)?;
        let result = (|| {
            self.detached(boundary, true)?;
            stage.check_named_objects()?;
            require_no_receipts(directory)?;
            let ticket = boundary.insert(self.anchor)?;
            let receipt = self.attached(boundary, ticket)?;
            let record = receipt_bytes(self.binding, receipt);
            let mut file = open_receipt(directory, true)?;
            file.write_all(&record)?;
            file.sync_all()?;
            directory.sync_all()?;
            if read_receipt(directory, self.binding)? != receipt {
                return Err(Error::Refused("root call receipt readback changed"));
            }
            Ok(())
        })();
        finish(stage, result)
    }

    /// Reopens the original journal and uses a separate one-shot removal ledger. The supplied
    /// boundary must attest continuity of the original exclusive window and writer termination.
    pub(crate) fn detach(&mut self, directory: &File, boundary: &mut impl Boundary) -> Result<()> {
        let stage = Ledger::reopen(directory.try_clone()?)?;
        if stage.identity() != (self.guard.identity().session, self.binding)
            || !stage.is_single_closed_operation(Operation::ChangeHook)?
        {
            return Err(Error::Refused("original root call stage not verified"));
        }
        let receipt = read_receipt(directory, self.binding)?;
        if self.attached(boundary, receipt.ticket)? != receipt {
            return Err(Error::Refused("root call position changed"));
        }
        mkdirat(directory, "remove", Mode::from_bits_truncate(0o700))?;
        directory.sync_all()?;
        let open_removal = || -> Result<File> {
            Ok(openat(
                directory,
                "remove",
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?
            .into())
        };
        let dir = open_removal()?;
        let mut removal = Ledger::create(
            dir.try_clone()?,
            self.guard.identity().session,
            self.binding,
        )?;
        removal.begin(Operation::ChangeHook)?;
        let result = (|| {
            if read_receipt(directory, self.binding)? != receipt
                || self.attached(boundary, receipt.ticket)? != receipt
            {
                return Err(Error::Refused(
                    "root call receipt or position changed before removal",
                ));
            }
            stage.check_named_objects()?;
            removal.check_named_objects()?;
            let held = dir.metadata()?;
            let named = open_removal()?.metadata()?;
            if (held.dev(), held.ino()) != (named.dev(), named.ino()) {
                return Err(Error::Refused("removal directory replaced"));
            }
            boundary.remove(self.anchor, receipt.ticket)?;
            self.detached(boundary, false)
        })();
        finish(removal, result)
    }
}

fn bytes(raw: &[u8]) -> RuleBytes<'_> {
    RuleBytes {
        bytes: raw,
        complete: true,
    }
}

fn require_no_receipts(directory: &File) -> Result<()> {
    for name in [RECEIPT, "remove"] {
        match fstatat(directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
            Ok(_) => return Err(Error::Refused("prior root call evidence exists")),
            Err(Errno::ENOENT) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn finish(mut ledger: Ledger, result: Result<()>) -> Result<()> {
    if let Err(error) = result {
        let _ = ledger.unknown();
        return Err(error);
    }
    ledger.observed()?;
    ledger.close()
}

fn receipt_bytes(binding: [u8; 32], receipt: Receipt) -> [u8; SIZE] {
    let mut bytes = [0; SIZE];
    bytes[..8].copy_from_slice(b"TLROOT01");
    bytes[8..16].copy_from_slice(&receipt.ticket.get().to_be_bytes());
    bytes[16..20].copy_from_slice(&receipt.index.to_be_bytes());
    let mut hash = Sha256::new();
    hash.update(binding);
    hash.update(&bytes[..20]);
    bytes[20..].copy_from_slice(&hash.finalize());
    bytes
}

fn open_receipt(directory: &File, create: bool) -> Result<File> {
    let flags = if create {
        OFlag::O_WRONLY | OFlag::O_EXCL | OFlag::O_CREAT
    } else {
        OFlag::O_RDONLY
    };
    let file: File = openat(
        directory,
        RECEIPT,
        flags | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::from_bits_truncate(0o600),
    )?
    .into();
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.mode() & 0o7777 != 0o600
        || meta.uid() != nix::unistd::geteuid().as_raw()
        || NativePathInspection.acl(&file) != Acl::Empty
    {
        return Err(Error::Refused("unsafe root call receipt"));
    }
    Ok(file)
}

fn read_receipt(directory: &File, binding: [u8; 32]) -> Result<Receipt> {
    let mut raw = Vec::new();
    let file = open_receipt(directory, false)?;
    let before = file.metadata()?;
    (&file).take(SIZE as u64 + 1).read_to_end(&mut raw)?;
    let named = open_receipt(directory, false)?.metadata()?;
    if raw.len() != SIZE
        || before.len() != SIZE as u64
        || before.len() != named.len()
        || (before.dev(), before.ino()) != (named.dev(), named.ino())
        || (
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            named.mtime(),
            named.mtime_nsec(),
            named.ctime(),
            named.ctime_nsec(),
        )
    {
        return Err(Error::Refused("incomplete or replaced root call receipt"));
    }
    let ticket = u64::from_be_bytes(
        raw[8..16]
            .try_into()
            .map_err(|_| Error::Refused("invalid root ticket"))?,
    );
    let index = u32::from_be_bytes(
        raw[16..20]
            .try_into()
            .map_err(|_| Error::Refused("invalid root position"))?,
    );
    let ticket = NonZeroU64::new(ticket).ok_or(Error::Refused("zero root call ticket"))?;
    let receipt = Receipt { ticket, index };
    if raw != receipt_bytes(binding, receipt) {
        return Err(Error::Refused("root call receipt does not match its trial"));
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::driver::Identity;
    use crate::ledger::State;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const ANCHOR: &str = "tunlatch-lab-0123456789abcdef0123456789abcdef";
    const ROOT: &[u8] = b"anchor \"com.apple/*\" all\n";
    const FOREIGN: [u8; 32] = [4; 32];
    const IDENTITY: Identity = Identity {
        boot: [1; 32],
        session: [2; 32],
        plan: [3; 32],
        controller_birth: 4,
        lock_inode: 5,
    };

    struct Fake {
        sequence: u64,
        root: Vec<u8>,
        owner: String,
        receipt: Option<Receipt>,
        foreign: [u8; 32],
        leaf: Leaf,
        inserted: usize,
        removed: usize,
        wrong_delta: bool,
        lose_insert_reply: bool,
        lose_remove_reply: bool,
    }

    impl Default for Fake {
        fn default() -> Self {
            Self {
                sequence: 0,
                root: ROOT.to_vec(),
                owner: ANCHOR.to_owned(),
                receipt: None,
                foreign: FOREIGN,
                leaf: Leaf::Absent,
                inserted: 0,
                removed: 0,
                wrong_delta: false,
                lose_insert_reply: false,
                lose_remove_reply: false,
            }
        }
    }

    impl Boundary for Fake {
        fn observe(&mut self) -> Result<View> {
            self.sequence += 1;
            Ok(View {
                observation: Observation {
                    identity: IDENTITY,
                    sequence: self.sequence,
                    at_ms: self.sequence,
                    complete: true,
                    exclusive: true,
                    writers_reclaimed: true,
                },
                root_rules: self.root.clone(),
                foreign: self.foreign,
                hook: self.receipt.map(|receipt| (self.owner.clone(), receipt)),
                leaf: self.leaf,
            })
        }

        fn insert(&mut self, anchor: &str) -> Result<NonZeroU64> {
            self.inserted += 1;
            let ticket = NonZeroU64::new(71).ok_or(Error::Refused("test ticket"))?;
            self.receipt = Some(Receipt { ticket, index: 1 });
            let qualifiers = if self.wrong_delta { "quick all" } else { "all" };
            self.root
                .extend(format!("anchor \"{anchor}\" {qualifiers}\n").as_bytes());
            self.leaf = Leaf::Empty;
            if self.lose_insert_reply {
                return Err(Error::Refused("injected lost insertion reply"));
            }
            Ok(ticket)
        }

        fn remove(&mut self, anchor: &str, ticket: NonZeroU64) -> Result<()> {
            if self.owner != anchor || self.receipt.map(|r| r.ticket) != Some(ticket) {
                return Err(Error::Refused("wrong fixture removal target"));
            }
            self.removed += 1;
            self.receipt = None;
            self.root = ROOT.to_vec();
            self.leaf = Leaf::Absent;
            if self.lose_remove_reply {
                return Err(Error::Refused("injected lost removal reply"));
            }
            Ok(())
        }
    }

    fn trial(identity: Identity) -> Result<Trial<'static>> {
        let guard = Guard::new(identity, 0).map_err(|err| Error::Refused(err.0))?;
        Trial::new(guard, ANCHOR, ROOT, 1, FOREIGN)
    }

    fn private_directory() -> Result<(tempfile::TempDir, File)> {
        let temp = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()?;
        let directory = File::open(temp.path())?;
        Ok((temp, directory))
    }

    #[test]
    fn independent_recovery_reads_the_creation_receipt_and_checks_final_baseline() -> Result<()> {
        let (temp, directory) = private_directory()?;
        let mut fake = Fake::default();
        trial(IDENTITY)?.attach(&directory, &mut fake)?;
        let mut recovery = trial(IDENTITY)?;
        let held = Ledger::reopen(directory.try_clone()?)?;
        assert!(recovery.detach(&directory, &mut fake).is_err());
        assert_eq!(fake.removed, 0);
        drop(held);
        recovery.detach(&directory, &mut fake)?;
        assert_eq!(fake.root, ROOT);
        assert_eq!((fake.inserted, fake.removed), (1, 1));
        assert_eq!(
            Ledger::reopen(File::open(temp.path().join("remove"))?)?.state(),
            State::Closed
        );
        assert!(recovery.detach(&directory, &mut fake).is_err());
        assert_eq!(fake.removed, 1);
        Ok(())
    }

    #[test]
    fn preexisting_receipt_stops_before_insertion() -> Result<()> {
        let (temp, directory) = private_directory()?;
        fs::write(temp.path().join(RECEIPT), b"prior evidence")?;
        let mut fake = Fake::default();
        assert!(trial(IDENTITY)?.attach(&directory, &mut fake).is_err());
        assert_eq!(fake.inserted, 0);
        assert_eq!(fs::read(temp.path().join(RECEIPT))?, b"prior evidence");
        Ok(())
    }

    #[test]
    fn insertion_error_or_wrong_semantics_leaves_intent_unrecoverable() -> Result<()> {
        for wrong_delta in [false, true] {
            let (_temp, directory) = private_directory()?;
            let mut fake = Fake {
                wrong_delta,
                lose_insert_reply: !wrong_delta,
                ..Fake::default()
            };
            assert!(trial(IDENTITY)?.attach(&directory, &mut fake).is_err());
            assert!(trial(IDENTITY)?.detach(&directory, &mut fake).is_err());
            assert_eq!(
                Ledger::reopen(directory)?.state(),
                State::Unknown(Operation::ChangeHook)
            );
            assert_eq!((fake.inserted, fake.removed), (1, 0));
        }
        Ok(())
    }

    #[test]
    fn refusal_preserves_hook_on_invalid_receipt_window_or_live_view() -> Result<()> {
        for failure in [
            "boot",
            "receipt",
            "ticket",
            "owner",
            "index",
            "foreign",
            "leaf",
            "absent-leaf",
        ] {
            let (temp, directory) = private_directory()?;
            let mut fake = Fake::default();
            trial(IDENTITY)?.attach(&directory, &mut fake)?;
            let mut identity = IDENTITY;
            match failure {
                "boot" => identity.boot = [7; 32],
                "receipt" => fs::write(temp.path().join(RECEIPT), b"invalid")?,
                "ticket" => {
                    fake.receipt = NonZeroU64::new(72).map(|ticket| Receipt { ticket, index: 1 })
                }
                "owner" => fake.owner = "other-owner".to_owned(),
                "index" => {
                    if let Some(receipt) = &mut fake.receipt {
                        receipt.index = 0;
                    }
                    let original = fake.root.split_off(ROOT.len());
                    fake.root = [original.as_slice(), ROOT].concat();
                }
                "foreign" => fake.foreign = [5; 32],
                "absent-leaf" => fake.leaf = Leaf::Absent,
                _ => fake.leaf = Leaf::Other,
            }
            assert!(
                trial(identity)?.detach(&directory, &mut fake).is_err(),
                "{failure}"
            );
            assert_eq!(fake.removed, 0, "{failure}");
            assert!(!temp.path().join("remove").exists());
        }
        Ok(())
    }

    #[test]
    fn unrelated_closed_journal_cannot_use_a_matching_receipt() -> Result<()> {
        for operation in [None, Some(Operation::WriteFilter)] {
            let (temp, directory) = private_directory()?;
            let mut candidate = trial(IDENTITY)?;
            let mut fake = Fake::default();
            fake.insert(ANCHOR)?;
            let receipt = fake
                .receipt
                .ok_or(Error::Refused("fixture receipt missing"))?;
            fs::write(
                temp.path().join(RECEIPT),
                receipt_bytes(candidate.binding, receipt),
            )?;
            fs::set_permissions(temp.path().join(RECEIPT), fs::Permissions::from_mode(0o600))?;
            let mut stage =
                Ledger::create(directory.try_clone()?, IDENTITY.session, candidate.binding)?;
            if let Some(operation) = operation {
                stage.begin(operation)?;
                stage.observed()?;
            }
            stage.close()?;
            drop(stage);
            assert!(candidate.detach(&directory, &mut fake).is_err());
            assert_eq!(fake.removed, 0);
            assert!(!temp.path().join("remove").exists());
        }
        Ok(())
    }

    #[test]
    fn lost_removal_reply_keeps_unknown_even_when_root_is_restored() -> Result<()> {
        let (temp, directory) = private_directory()?;
        let mut fake = Fake {
            lose_remove_reply: true,
            ..Fake::default()
        };
        trial(IDENTITY)?.attach(&directory, &mut fake)?;
        assert!(trial(IDENTITY)?.detach(&directory, &mut fake).is_err());
        assert_eq!(fake.root, ROOT);
        assert_eq!(
            Ledger::reopen(File::open(temp.path().join("remove"))?)?.state(),
            State::Unknown(Operation::ChangeHook)
        );
        assert!(trial(IDENTITY)?.detach(&directory, &mut fake).is_err());
        assert_eq!(fake.removed, 1);
        Ok(())
    }
}
