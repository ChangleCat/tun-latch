//! Actual ordinary-user descriptor copies plus explicitly simulated security observations.
#[path = "pf_lab/bootstrap.rs"]
mod bootstrap;

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use bootstrap::{Acl, Ancestor, Inspection, LaunchObservation, ReviewedContent, Sandbox};
use sha2::{Digest, Sha256};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const DATA: &[u8] = b"reviewed executable content treated only as data\n";
struct SimulatedAcl(Acl);
impl Inspection for SimulatedAcl {
    fn acl(&mut self, _: &File) -> Acl {
        self.0
    }
}
fn review() -> bootstrap::Result<ReviewedContent> {
    ReviewedContent::sandbox_review(
        Sha256::digest(DATA).into(),
        DATA.len() as u64,
        [1; 32],
        [2; 32],
        3,
    )
}
fn directory() -> Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    Ok(dir)
}
fn source() -> Result<File> {
    let mut f = tempfile::tempfile()?;
    f.write_all(DATA)?;
    f.seek(SeekFrom::Start(0))?;
    Ok(f)
}
fn observation() -> LaunchObservation {
    LaunchObservation {
        session: [1; 32],
        boot: [2; 32],
        generation: 3,
        birth: 11,
        launch_sequence: 7,
        observed_sequence: 7,
        loaded_digest: Some(Sha256::digest(DATA).into()),
        inherited_fds: 0,
        fixed_entry: true,
    }
}

#[test]
fn copies_verified_data_to_a_distinct_inode_without_executing_it() -> Result {
    let dir = directory()?;
    let mut acl = SimulatedAcl(Acl::Empty);
    let mut sandbox = Sandbox::initialize(File::open(dir.path())?, &mut acl)?;
    let mut input = source()?;
    let mut ready = sandbox.stage(&mut input, &review()?, &mut acl)?;
    assert_eq!(ready.bytes()?, DATA);
    assert_ne!(
        input.metadata()?.ino(),
        fs::metadata(dir.path().join("program"))?.ino()
    );
    assert_eq!(
        fs::metadata(dir.path().join("program"))?.mode() & 0o777,
        0o500
    );
    assert!(bootstrap::close_on_exec(&input)?);
    assert!(ready.check_launch(observation()).is_ok());
    assert!(sandbox.stage(&mut input, &review()?, &mut acl).is_err());
    assert!(fs::read_to_string(dir.path().join("index"))?.contains("published"));
    Ok(())
}

#[test]
fn held_candidate_survives_path_replacement_and_old_writable_fd_cannot_modify_copy() -> Result {
    let dir = directory()?;
    let source_dir = directory()?;
    let path = source_dir.path().join("input");
    fs::write(&path, DATA)?;
    let mut held = bootstrap::open_candidate(&path)?;
    let mut old_writer = fs::OpenOptions::new().write(true).open(&path)?;
    fs::rename(&path, source_dir.path().join("old"))?;
    fs::write(&path, b"replacement")?;
    let mut acl = SimulatedAcl(Acl::Empty);
    let mut sandbox = Sandbox::initialize(File::open(dir.path())?, &mut acl)?;
    let mut ready = sandbox.stage(&mut held, &review()?, &mut acl)?;
    old_writer.write_all(b"attacker")?;
    assert_eq!(ready.bytes()?, DATA);
    assert_eq!(fs::read(&path)?, b"replacement");
    Ok(())
}

#[test]
fn symbolic_candidate_and_lock_are_not_followed() -> Result {
    let dir = directory()?;
    let real = dir.path().join("real");
    fs::write(&real, DATA)?;
    let alias = dir.path().join("alias");
    symlink(&real, &alias)?;
    assert!(bootstrap::open_candidate(&alias).is_err());
    symlink(&real, dir.path().join("lock"))?;
    assert!(Sandbox::reopen(File::open(dir.path())?, &mut SimulatedAcl(Acl::Empty)).is_err());
    assert_eq!(fs::read(real)?, DATA);
    Ok(())
}

#[test]
fn unknown_and_nonempty_acls_and_unprotected_parent_chain_are_refused() -> Result {
    let dir = directory()?;
    for acl in [Acl::Unknown, Acl::Present] {
        assert!(Sandbox::initialize(File::open(dir.path())?, &mut SimulatedAcl(acl)).is_err());
        assert!(!dir.path().join("lock").exists());
    }
    let uid = nix::unistd::geteuid().as_raw();
    let node = Ancestor {
        owner: uid,
        mode: 0o755,
        directory: true,
        acl: Acl::Empty,
    };
    bootstrap::check_ancestors(&[node], uid)?;
    for bad in [
        Ancestor {
            owner: uid.wrapping_add(1),
            ..node
        },
        Ancestor {
            mode: 0o777,
            ..node
        },
        Ancestor {
            directory: false,
            ..node
        },
        Ancestor {
            acl: Acl::Present,
            ..node
        },
        Ancestor {
            acl: Acl::Unknown,
            ..node
        },
    ] {
        assert!(bootstrap::check_ancestors(&[node, bad], uid).is_err());
    }
    assert!(bootstrap::check_ancestors(&[], uid).is_err());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755))?;
    assert!(Sandbox::initialize(File::open(dir.path())?, &mut SimulatedAcl(Acl::Empty)).is_err());
    Ok(())
}

#[test]
fn wrong_digest_short_copy_and_preexisting_publication_preserve_unresolved_intent() -> Result {
    for failure in ["digest", "short", "foreign", "staging-link"] {
        let dir = directory()?;
        let mut acl = SimulatedAcl(Acl::Empty);
        let mut sandbox = Sandbox::initialize(File::open(dir.path())?, &mut acl)?;
        let mut input = source()?;
        let mut approved = review()?;
        match failure {
            "digest" => {
                approved = ReviewedContent::sandbox_review(
                    [3; 32],
                    DATA.len() as u64,
                    [1; 32],
                    [2; 32],
                    3,
                )?
            }
            "short" => input.set_len(3)?,
            "foreign" => fs::write(dir.path().join("program"), b"foreign")?,
            _ => symlink("unrelated", dir.path().join("candidate"))?,
        }
        assert!(sandbox.stage(&mut input, &approved, &mut acl).is_err());
        drop(sandbox);
        if failure == "short" {
            // No copy was started; the fresh ledger is still clean.
            assert_eq!(fs::read(dir.path().join("index"))?, b"clean\n");
        } else {
            assert!(Sandbox::reopen(File::open(dir.path())?, &mut acl).is_err());
        }
        if failure == "foreign" {
            assert_eq!(fs::read(dir.path().join("program"))?, b"foreign");
        }
    }
    Ok(())
}

#[test]
fn lock_contention_replacement_and_hard_links_do_not_create_ownership() -> Result {
    let dir = directory()?;
    let mut acl = SimulatedAcl(Acl::Empty);
    let mut sandbox = Sandbox::initialize(File::open(dir.path())?, &mut acl)?;
    assert!(Sandbox::reopen(File::open(dir.path())?, &mut acl).is_err());
    assert!(Sandbox::initialize(File::open(dir.path())?, &mut acl).is_err());
    fs::rename(dir.path().join("lock"), dir.path().join("old-lock"))?;
    fs::write(dir.path().join("lock"), b"replacement")?;
    assert!(sandbox.stage(&mut source()?, &review()?, &mut acl).is_err());
    drop(sandbox);
    fs::remove_file(dir.path().join("lock"))?;
    fs::hard_link(dir.path().join("old-lock"), dir.path().join("lock"))?;
    assert!(Sandbox::reopen(File::open(dir.path())?, &mut acl).is_err());
    Ok(())
}

#[test]
fn missing_corrupt_excessive_and_unsettled_indices_block_admission() -> Result {
    for content in [
        None,
        Some(Vec::new()),
        Some(b"intent old\n".to_vec()),
        Some(vec![b'x'; 1024]),
    ] {
        let dir = directory()?;
        let mut acl = SimulatedAcl(Acl::Empty);
        drop(Sandbox::initialize(File::open(dir.path())?, &mut acl)?);
        match content {
            Some(bytes) => fs::write(dir.path().join("index"), bytes)?,
            None => fs::remove_file(dir.path().join("index"))?,
        };
        assert!(Sandbox::reopen(File::open(dir.path())?, &mut acl).is_err());
        assert!(Sandbox::initialize(File::open(dir.path())?, &mut acl).is_err());
    }
    Ok(())
}

#[test]
fn disk_digest_does_not_authenticate_a_running_image_or_an_old_session() -> Result {
    let dir = directory()?;
    let mut acl = SimulatedAcl(Acl::Empty);
    let mut sandbox = Sandbox::initialize(File::open(dir.path())?, &mut acl)?;
    let ready = sandbox.stage(&mut source()?, &review()?, &mut acl)?;
    let base = observation();
    for wrong in [
        LaunchObservation {
            loaded_digest: None,
            ..base
        },
        LaunchObservation {
            loaded_digest: Some([9; 32]),
            ..base
        },
        LaunchObservation {
            session: [9; 32],
            ..base
        },
        LaunchObservation {
            boot: [9; 32],
            ..base
        },
        LaunchObservation {
            generation: 4,
            ..base
        },
        LaunchObservation { birth: 0, ..base },
        LaunchObservation {
            observed_sequence: 8,
            ..base
        },
        LaunchObservation {
            launch_sequence: 0,
            ..base
        },
        LaunchObservation {
            inherited_fds: 1,
            ..base
        },
        LaunchObservation {
            fixed_entry: false,
            ..base
        },
    ] {
        assert!(ready.check_launch(wrong).is_err());
    }
    Ok(())
}

#[test]
fn invalid_review_bounds_and_modified_published_bytes_are_rejected() -> Result {
    assert!(ReviewedContent::sandbox_review([0; 32], 1, [1; 32], [2; 32], 1).is_err());
    assert!(ReviewedContent::sandbox_review([1; 32], 0, [1; 32], [2; 32], 1).is_err());
    assert!(
        ReviewedContent::sandbox_review([1; 32], 64 * 1024 * 1024 + 1, [1; 32], [2; 32], 1)
            .is_err()
    );
    assert!(ReviewedContent::sandbox_review([1; 32], 1, [0; 32], [2; 32], 1).is_err());
    assert!(ReviewedContent::sandbox_review([1; 32], 1, [1; 32], [0; 32], 1).is_err());
    assert!(ReviewedContent::sandbox_review([1; 32], 1, [1; 32], [2; 32], 0).is_err());
    let dir = directory()?;
    let mut acl = SimulatedAcl(Acl::Empty);
    let mut sandbox = Sandbox::initialize(File::open(dir.path())?, &mut acl)?;
    let mut ready = sandbox.stage(&mut source()?, &review()?, &mut acl)?;
    fs::set_permissions(
        dir.path().join("program"),
        fs::Permissions::from_mode(0o700),
    )?;
    fs::write(dir.path().join("program"), b"changed")?;
    assert!(ready.bytes().is_err());
    Ok(())
}

#[test]
fn partial_copy_is_recorded_and_cannot_be_reopened_as_a_clean_session() -> Result {
    struct ShortenDuringCopy {
        source: File,
        armed: bool,
    }
    impl Inspection for ShortenDuringCopy {
        fn acl(&mut self, file: &File) -> Acl {
            if self.armed && file.metadata().is_ok_and(|m| m.is_file()) {
                // This callback occurs after the candidate size check, when staging is created.
                self.armed = false;
                if self.source.set_len(3).is_err() {
                    return Acl::Unknown;
                }
            }
            Acl::Empty
        }
    }
    let dir = directory()?;
    let mut input = source()?;
    let mut inspect = ShortenDuringCopy {
        source: input.try_clone()?,
        armed: false,
    };
    let mut sandbox = Sandbox::initialize(File::open(dir.path())?, &mut inspect)?;
    inspect.armed = true;
    assert!(sandbox.stage(&mut input, &review()?, &mut inspect).is_err());
    assert_eq!(fs::metadata(dir.path().join("candidate"))?.len(), 3);
    assert!(!dir.path().join("program").exists());
    drop(sandbox);
    assert!(Sandbox::reopen(File::open(dir.path())?, &mut inspect).is_err());
    Ok(())
}
