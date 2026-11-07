//! Ordinary-user real filesystem checks. These do not establish cross-UID or root protection.

use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use nix::unistd::Uid;
use tempfile::TempDir;
use tunlatch_platform::store::{
    MAX_RECORD_PAYLOAD_BYTES, RecordIdentity, RecordKind, StoreError, StoredRecord,
    SystemRecordStore, UserRecordStore,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn directory() -> Result<(TempDir, PathBuf), Box<dyn std::error::Error>> {
    let directory = tempfile::Builder::new()
        .prefix("tunlatch-store-")
        .tempdir_in("/private/tmp")?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().canonicalize()?;
    Ok((directory, path))
}

fn record(byte: u8, payload: &[u8]) -> Result<StoredRecord, StoreError> {
    StoredRecord::new(RecordIdentity::new([byte; 32])?, payload.to_vec())
}

fn mode(path: &Path, mode: u32) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[test]
fn atomically_replaces_records_while_old_descriptor_retains_complete_old_bytes() -> TestResult {
    let (_directory, path) = directory()?;
    let old = record(1, b"enabled: original policy")?;
    let new = record(2, b"enabled: replacement policy")?;
    let mut store = UserRecordStore::open(&path)?;
    assert_eq!(store.read(RecordKind::Policy)?, None);
    store.replace(RecordKind::Policy, &old)?;
    let file_path = path.join(RecordKind::Policy.file_name());
    let bytes = fs::read(&file_path)?;
    let mut held_old = File::open(&file_path)?;
    let inode = held_old.metadata()?.ino();
    store.replace(RecordKind::Policy, &new)?;
    let mut still_old = Vec::new();
    held_old.read_to_end(&mut still_old)?;
    assert_eq!(still_old, bytes);
    assert_ne!(fs::metadata(&file_path)?.ino(), inode);
    assert_eq!(store.read(RecordKind::Policy)?, Some(new.clone()));
    let metadata = fs::metadata(&file_path)?;
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.uid(), Uid::effective().as_raw());
    assert_eq!(metadata.nlink(), 1);
    assert!(exacl::getfacl(&file_path, None)?.is_empty());
    drop(store);
    assert_eq!(
        UserRecordStore::open(&path)?.read(RecordKind::Policy)?,
        Some(new)
    );
    Ok(())
}

#[test]
fn exclusive_writer_lock_survives_operations_and_releases_only_with_its_owner() -> TestResult {
    let (_directory, path) = directory()?;
    let mut store = UserRecordStore::open(&path)?;
    assert!(matches!(
        UserRecordStore::open(&path),
        Err(StoreError::WriterBusy)
    ));
    store.replace(RecordKind::Policy, &record(1, b"policy")?)?;
    assert!(matches!(
        UserRecordStore::open(&path),
        Err(StoreError::WriterBusy)
    ));
    drop(store);
    assert!(UserRecordStore::open(&path).is_ok());
    Ok(())
}

#[test]
fn refuses_substituted_lock_files_and_preserves_an_existing_pending_file() -> TestResult {
    for change in 0..3 {
        let (_directory, path) = directory()?;
        let lock = path.join("writer.lock");
        fs::write(&lock, b"")?;
        mode(&lock, 0o600)?;
        match change {
            0 => {
                fs::rename(&lock, path.join("original"))?;
                symlink(path.join("original"), &lock)?;
            }
            1 => fs::hard_link(&lock, path.join("alias"))?,
            _ => mode(&lock, 0o640)?,
        }
        assert!(UserRecordStore::open(&path).is_err());
    }
    let (_directory, path) = directory()?;
    let mut store = UserRecordStore::open(&path)?;
    let old = record(1, b"enabled")?;
    store.replace(RecordKind::Policy, &old)?;
    fs::write(path.join("policy.pending"), b"unresolved prior attempt")?;
    assert!(matches!(
        store.replace(RecordKind::Policy, &record(2, b"new")?),
        Err(StoreError::BeforeRename { .. })
    ));
    assert_eq!(store.read(RecordKind::Policy)?, Some(old));
    assert_eq!(
        fs::read(path.join("policy.pending"))?,
        b"unresolved prior attempt"
    );
    Ok(())
}

#[test]
fn policy_and_recovery_slots_preserve_identity_and_reject_cross_slot_copies() -> TestResult {
    let (_directory, path) = directory()?;
    let mut store = UserRecordStore::open(&path)?;
    let policy = record(1, b"opaque draft")?;
    let recovery = record(1, b"opaque recovery intent")?;
    store.replace(RecordKind::Policy, &policy)?;
    store.replace(RecordKind::Recovery, &recovery)?;
    assert_eq!(store.read(RecordKind::Policy)?, Some(policy));
    assert_eq!(store.read(RecordKind::Recovery)?, Some(recovery));
    fs::copy(
        path.join(RecordKind::Policy.file_name()),
        path.join(RecordKind::Recovery.file_name()),
    )?;
    assert!(matches!(
        store.read(RecordKind::Recovery),
        Err(StoreError::InvalidRecord(_))
    ));
    Ok(())
}

#[test]
fn corrupted_truncated_extended_unknown_and_oversized_records_never_become_disabled() -> TestResult
{
    for change in 0..8 {
        let (_directory, path) = directory()?;
        let mut store = UserRecordStore::open(&path)?;
        let enabled = record(1, b"enabled")?;
        store.replace(RecordKind::Policy, &enabled)?;
        let file_path = path.join(RecordKind::Policy.file_name());
        let mut bytes = fs::read(&file_path)?;
        match change {
            0 => bytes.truncate(7),
            1 => bytes[9] = 2,
            2 => bytes.push(0),
            3 => {
                bytes.pop();
            }
            4 => bytes[16] ^= 1,
            5 => bytes[48] ^= 1,
            6 => bytes[11] = 1,
            _ => bytes = vec![0; MAX_RECORD_PAYLOAD_BYTES + 81],
        }
        fs::write(&file_path, &bytes)?;
        assert!(matches!(
            store.read(RecordKind::Policy),
            Err(StoreError::InvalidRecord(_))
        ));
        let failure = store
            .replace(RecordKind::Policy, &record(2, b"disabled")?)
            .err()
            .ok_or("corrupt existing record was overwritten")?;
        assert!(matches!(failure, StoreError::BeforeRename { .. }));
        assert!(!failure.is_commit_unknown());
        assert_eq!(fs::read(&file_path)?, bytes);
    }
    assert!(RecordIdentity::new([0; 32]).is_err());
    assert!(
        StoredRecord::new(
            RecordIdentity::new([1; 32])?,
            vec![0; MAX_RECORD_PAYLOAD_BYTES + 1]
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn rejects_leaf_and_parent_symlinks_and_public_or_writable_parent_modes() -> TestResult {
    let (_directory, path) = directory()?;
    let child = path.join("child");
    fs::create_dir(&child)?;
    mode(&child, 0o700)?;
    symlink(&child, path.join("link"))?;
    assert!(UserRecordStore::open(&path.join("link")).is_err());
    assert!(UserRecordStore::open(&path.join("link/child")).is_err());
    mode(&child, 0o750)?;
    assert!(UserRecordStore::open(&child).is_err());
    mode(&child, 0o700)?;
    mode(&path, 0o770)?;
    assert!(UserRecordStore::open(&child).is_err());
    mode(&path, 0o700)?;
    assert!(UserRecordStore::open(Path::new("/private/tmp")).is_err());
    assert!(UserRecordStore::open(Path::new("relative-store")).is_err());
    Ok(())
}

#[test]
fn rejects_record_symlinks_hardlinks_wrong_modes_and_non_regular_files() -> TestResult {
    for change in 0..4 {
        let (_directory, path) = directory()?;
        let mut store = UserRecordStore::open(&path)?;
        store.replace(RecordKind::Policy, &record(1, b"enabled")?)?;
        let file_path = path.join(RecordKind::Policy.file_name());
        match change {
            0 => {
                fs::rename(&file_path, path.join("original"))?;
                symlink(path.join("original"), &file_path)?;
            }
            1 => fs::hard_link(&file_path, path.join("alias"))?,
            2 => mode(&file_path, 0o640)?,
            _ => {
                fs::remove_file(&file_path)?;
                nix::unistd::mkfifo(
                    &file_path,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )?;
            }
        }
        assert!(store.read(RecordKind::Policy).is_err());
        assert!(matches!(
            store.replace(RecordKind::Policy, &record(2, b"new")?),
            Err(StoreError::BeforeRename { .. })
        ));
    }
    Ok(())
}

#[test]
fn rejects_acl_grants_on_store_parent_and_records() -> TestResult {
    for target in 0..3 {
        let (_directory, path) = directory()?;
        let child = path.join("child");
        fs::create_dir(&child)?;
        mode(&child, 0o700)?;
        let mut store = UserRecordStore::open(&child)?;
        store.replace(RecordKind::Policy, &record(1, b"enabled")?)?;
        let target_path = match target {
            0 => path.clone(),
            1 => child.clone(),
            _ => child.join(RecordKind::Policy.file_name()),
        };
        let entry = exacl::AclEntry::allow_user("nobody", exacl::Perm::READ, None);
        exacl::setfacl(&[&target_path], &[entry], None)?;
        assert!(store.read(RecordKind::Policy).is_err());
        assert!(UserRecordStore::open(&child).is_err());
        exacl::setfacl(&[&target_path], &[], None)?;
    }
    Ok(())
}

#[test]
fn parent_replacement_and_lock_replacement_invalidate_an_open_store() -> TestResult {
    for replacement in 0..3 {
        let (_directory, path) = directory()?;
        let parent = path.join("parent");
        fs::create_dir(&parent)?;
        mode(&parent, 0o700)?;
        let child = parent.join("child");
        fs::create_dir(&child)?;
        mode(&child, 0o700)?;
        let mut store = UserRecordStore::open(&child)?;
        store.replace(RecordKind::Policy, &record(1, b"enabled")?)?;
        if replacement == 0 {
            fs::rename(child.join("writer.lock"), child.join("old.lock"))?;
            fs::write(child.join("writer.lock"), b"")?;
            mode(&child.join("writer.lock"), 0o600)?;
        } else if replacement == 1 {
            fs::rename(&child, path.join("old"))?;
            fs::create_dir(&child)?;
            mode(&child, 0o700)?;
        } else {
            fs::rename(&parent, path.join("old-parent"))?;
            fs::create_dir(&parent)?;
            mode(&parent, 0o700)?;
            fs::create_dir(&child)?;
            mode(&child, 0o700)?;
        }
        assert!(store.read(RecordKind::Policy).is_err());
        assert!(matches!(
            store.replace(RecordKind::Policy, &record(2, b"new")?),
            Err(StoreError::BeforeRename { .. })
        ));
    }
    Ok(())
}

#[test]
fn fixed_system_entry_refuses_ordinary_users_before_reading_its_path() -> TestResult {
    assert!(
        !Uid::effective().is_root(),
        "routine tests must not run as root"
    );
    assert!(matches!(
        SystemRecordStore::open(),
        Err(StoreError::Refused(_))
    ));
    Ok(())
}
