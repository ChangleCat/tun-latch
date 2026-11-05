//! Complete offline lifecycle and injected failures. No native PF adapter is linked.
#[path = "pf_lab/bootstrap.rs"]
mod bootstrap;
#[path = "pf_lab/hook.rs"]
mod hook;
#[path = "pf_lab/preflight.rs"]
mod preflight;

use hook::{Boundary, Error, Filter, Object, Phase, Scene, Session, Window};
use preflight::{Anchor, CheckedBoundary, Output, Query, ReadBoundary};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Queries(u64);
impl ReadBoundary for Queries {
    fn query(&mut self, q: Query) -> preflight::Result<Output> {
        assert_eq!(q.executable(), "/sbin/pfctl");
        assert!(q.argv().contains(&"-s"));
        self.0 += 1;
        let bytes = match q {
            Query::Anchors => b"project\n".to_vec(),
            Query::Rules(None) => b"anchor \"project/*\" all\n".to_vec(),
            Query::Interfaces => b"lo0 (skip)\nen0\n".to_vec(),
            Query::References => b"No pf_enabled references\n".to_vec(),
            _ => Vec::new(),
        };
        Ok(Output {
            bytes,
            stderr: Vec::new(),
            success: true,
            truncated: false,
            started_ms: 100 + self.0,
            ended_ms: 100 + self.0,
            sequence: self.0,
            boot: [1; 32],
        })
    }
}
fn checked() -> preflight::Result<CheckedBoundary> {
    let boundary = preflight::inspect(
        &mut Queries(0),
        Anchor::new("project/session")?,
        [1; 32],
        100,
    )?;
    assert_eq!(boundary.existing_references(), 0);
    Ok(boundary)
}
fn window() -> Window {
    Window {
        boot: [1; 32],
        session: [2; 32],
        controller_birth: 7,
        lock_device: 1,
        lock_inode: 2,
        deployment_generation: 3,
    }
}
struct Fake {
    scene: Scene,
    calls: Vec<&'static str>,
    records: Vec<Phase>,
    fault: Option<(&'static str, usize)>,
    foreign_rules: Vec<&'static str>,
    cancelled: bool,
    lose_commit_reply: bool,
}
impl Fake {
    fn new(boundary: &CheckedBoundary) -> Self {
        Self {
            scene: Scene {
                window: window(),
                exclusive_controller: Some(7),
                all_writers_reclaimed: true,
                foreign_boundary: boundary.fingerprint(),
                hook: None,
                leaf: None,
                now_ms: 114,
                sequence: 0,
            },
            calls: Vec::new(),
            records: Vec::new(),
            fault: None,
            foreign_rules: vec![
                "foreign root call",
                "foreign child filter",
                "foreign NAT/table",
                "foreign reference/state",
            ],
            cancelled: false,
            lose_commit_reply: false,
        }
    }
    fn call(&mut self, name: &'static str) -> hook::Result<()> {
        self.calls.push(name);
        if self.fault.is_some_and(|(what, at)| {
            what == name && self.calls.iter().filter(|n| **n == name).count() == at
        }) {
            return Err(Error::Unknown);
        }
        Ok(())
    }
}
impl Boundary for Fake {
    fn observe(&mut self) -> hook::Result<Scene> {
        self.call("observe")?;
        self.scene.sequence += 1;
        self.scene.now_ms += 1;
        Ok(self.scene.clone())
    }
    fn persist(&mut self, phase: Phase) -> hook::Result<()> {
        self.call("persist")?;
        self.records.push(phase);
        if phase == Phase::Stopping {
            self.cancelled = true;
        }
        Ok(())
    }
    fn insert_own_hook(&mut self, anchor: &Anchor, session: [u8; 32]) -> hook::Result<Object> {
        self.call("insert")?;
        if self.scene.hook.is_some() || self.cancelled {
            return Err(Error::Unknown);
        }
        let object = Object {
            instance: 11,
            session,
            anchor: anchor.clone(),
            filter: Filter::Empty,
        };
        self.scene.hook = Some(object.clone());
        Ok(object)
    }
    fn replace_own_filter(&mut self, hook: &Object, filter: Filter) -> hook::Result<Object> {
        self.call(if filter == Filter::Empty {
            "clear"
        } else {
            "commit"
        })?;
        if self.scene.hook.as_ref() != Some(hook) || (self.cancelled && filter != Filter::Empty) {
            return Err(Error::Unknown);
        }
        let leaf = Object {
            instance: 21,
            filter,
            ..hook.clone()
        };
        self.scene.leaf = Some(leaf.clone());
        if self.lose_commit_reply {
            return Err(Error::Unknown);
        }
        Ok(leaf)
    }
    fn remove_own_hook(&mut self, hook: &Object) -> hook::Result<()> {
        self.call("remove")?;
        if self.scene.hook.as_ref() != Some(hook)
            || !self
                .scene
                .leaf
                .as_ref()
                .is_some_and(|l| l.filter == Filter::Empty)
        {
            return Err(Error::Unknown);
        }
        self.scene.hook = None;
        self.scene.leaf = None;
        Ok(())
    }
}
fn active() -> Result<(Session, Fake)> {
    let checked = checked()?;
    let mut fake = Fake::new(&checked);
    let mut session = Session::admit(checked, window(), &mut fake)?;
    session.load(&mut fake)?;
    assert_eq!(session.phase(), Phase::Active);
    Ok((session, fake))
}

#[test]
fn complete_load_cancel_reap_clear_remove_and_verify_preserve_every_foreign_resource() -> Result {
    let (mut session, mut fake) = active()?;
    let foreign = fake.foreign_rules.clone();
    session.recover(&mut fake)?;
    assert_eq!(session.phase(), Phase::Closed);
    assert_eq!(fake.foreign_rules, foreign);
    assert!(fake.scene.hook.is_none());
    assert!(fake.scene.leaf.is_none());
    assert!(fake.cancelled);
    assert_eq!(
        fake.records,
        [
            Phase::Admitted,
            Phase::HookIntent,
            Phase::HookObserved,
            Phase::FilterIntent,
            Phase::Active,
            Phase::Stopping,
            Phase::ClearIntent,
            Phase::RemoveIntent,
            Phase::Closed
        ]
    );
    assert_eq!(
        fake.calls
            .iter()
            .filter(|n| matches!(**n, "insert" | "commit" | "clear" | "remove"))
            .copied()
            .collect::<Vec<_>>(),
        ["insert", "commit", "clear", "remove"]
    );
    Ok(())
}

#[test]
fn admission_requires_identity_exclusivity_empty_namespace_and_fresh_complete_observation() -> Result
{
    for kind in [
        "boot",
        "session",
        "birth",
        "lock",
        "generation",
        "foreign",
        "hook",
        "writers",
        "exclusive",
        "late",
    ] {
        let checked = checked()?;
        let mut fake = Fake::new(&checked);
        let mut w = window();
        match kind {
            "boot" => w.boot = [3; 32],
            "session" => w.session = [0; 32],
            "birth" => w.controller_birth = 0,
            "lock" => w.lock_inode = 0,
            "generation" => w.deployment_generation = 0,
            "foreign" => fake.scene.foreign_boundary = [9; 32],
            "hook" => {
                fake.scene.hook = Some(Object {
                    instance: 11,
                    session: [2; 32],
                    anchor: Anchor::new("project/session")?,
                    filter: Filter::Empty,
                })
            }
            "writers" => fake.scene.all_writers_reclaimed = false,
            "exclusive" => fake.scene.exclusive_controller = None,
            _ => fake.scene.now_ms = 3000,
        }
        assert!(Session::admit(checked, w, &mut fake).is_err(), "{kind}");
        assert!(
            !fake
                .calls
                .iter()
                .any(|n| matches!(*n, "insert" | "commit" | "clear" | "remove"))
        );
    }
    Ok(())
}

#[test]
fn every_load_boundary_failure_retains_unknown_without_automatic_cleanup_or_retry() -> Result {
    for fault in [
        ("persist", 2),
        ("insert", 1),
        ("observe", 3),
        ("persist", 3),
        ("persist", 4),
        ("commit", 1),
        ("observe", 4),
        ("persist", 5),
    ] {
        let checked = checked()?;
        let mut fake = Fake::new(&checked);
        let foreign = fake.foreign_rules.clone();
        let mut session = Session::admit(checked, window(), &mut fake)?;
        fake.fault = Some(fault);
        assert_eq!(session.load(&mut fake), Err(Error::Unknown), "{fault:?}");
        assert_eq!(session.phase(), Phase::Unknown);
        let calls = fake.calls.len();
        assert!(session.load(&mut fake).is_err());
        assert!(session.recover(&mut fake).is_err());
        assert_eq!(fake.calls.len(), calls);
        assert_eq!(fake.foreign_rules, foreign);
        assert!(!fake.calls.iter().any(|n| matches!(*n, "clear" | "remove")));
    }
    Ok(())
}

#[test]
fn recovery_failures_preserve_unknown_and_never_widen_to_global_cleanup() -> Result {
    for fault in [
        ("persist", 6),
        ("observe", 5),
        ("persist", 7),
        ("clear", 1),
        ("observe", 6),
        ("persist", 8),
        ("remove", 1),
        ("observe", 7),
        ("persist", 9),
    ] {
        let (mut session, mut fake) = active()?;
        let foreign = fake.foreign_rules.clone();
        fake.fault = Some(fault);
        assert_eq!(session.recover(&mut fake), Err(Error::Unknown), "{fault:?}");
        assert_eq!(session.phase(), Phase::Unknown);
        let calls = fake.calls.len();
        assert!(session.recover(&mut fake).is_err());
        assert_eq!(fake.calls.len(), calls);
        assert_eq!(fake.foreign_rules, foreign);
    }
    Ok(())
}

#[test]
fn foreign_replacement_lock_loss_reboot_or_unreaped_writers_stop_before_cleanup() -> Result {
    for change in [
        "same-bytes-foreign-instance",
        "foreign-session",
        "foreign-boundary",
        "lock",
        "boot",
        "controller",
        "writers",
        "sequence",
        "stale",
    ] {
        let (mut session, mut fake) = active()?;
        match change {
            "same-bytes-foreign-instance" => {
                if let Some(h) = &mut fake.scene.hook {
                    h.instance = 99;
                }
            }
            "foreign-session" => {
                if let Some(h) = &mut fake.scene.hook {
                    h.session = [9; 32];
                }
            }
            "foreign-boundary" => fake.scene.foreign_boundary = [9; 32],
            "lock" => fake.scene.window.lock_inode = 99,
            "boot" => fake.scene.window.boot = [9; 32],
            "controller" => fake.scene.exclusive_controller = Some(99),
            "writers" => fake.scene.all_writers_reclaimed = false,
            "sequence" => fake.scene.sequence = 0,
            _ => fake.scene.now_ms = 0,
        }
        let calls = fake.calls.len();
        assert_eq!(session.recover(&mut fake), Err(Error::Unknown), "{change}");
        assert!(
            !fake.calls[calls..]
                .iter()
                .any(|n| matches!(*n, "clear" | "remove"))
        );
    }
    Ok(())
}

#[test]
fn dropping_a_controller_neither_cleans_pf_nor_makes_a_new_controller_owner() -> Result {
    let (session, mut fake) = active()?;
    let calls = fake.calls.clone();
    drop(session);
    assert_eq!(fake.calls, calls);
    let next = checked()?;
    assert!(Session::admit(next, window(), &mut fake).is_err());
    assert!(fake.scene.hook.is_some());
    assert!(fake.scene.leaf.is_some());
    Ok(())
}

#[test]
fn lost_reply_after_committed_change_retains_scene_and_never_blindly_retries() -> Result {
    let checked = checked()?;
    let mut fake = Fake::new(&checked);
    let mut session = Session::admit(checked, window(), &mut fake)?;
    fake.lose_commit_reply = true;
    assert_eq!(session.load(&mut fake), Err(Error::Unknown));
    assert_eq!(session.phase(), Phase::Unknown);
    assert!(
        fake.scene
            .leaf
            .as_ref()
            .is_some_and(|l| l.filter == Filter::BlockProbe)
    );
    let count = fake.calls.len();
    assert!(session.load(&mut fake).is_err());
    assert!(session.recover(&mut fake).is_err());
    assert_eq!(count, fake.calls.len());
    assert_eq!(fake.records.last(), Some(&Phase::FilterIntent));
    Ok(())
}

#[test]
fn staging_preflight_and_owned_hook_recovery_form_one_ordinary_user_pipeline() -> Result {
    use bootstrap::{Acl, Ancestor, Inspection, LaunchObservation, ReviewedContent, Sandbox};
    use sha2::{Digest, Sha256};
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    struct SimulatedInspection;
    impl Inspection for SimulatedInspection {
        fn acl(&mut self, _: &File) -> Acl {
            Acl::Empty
        }
    }
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))?;
    let mut inspection = SimulatedInspection;
    let owner = nix::unistd::geteuid().as_raw();
    let ancestor = Ancestor {
        owner,
        mode: 0o700,
        directory: true,
        acl: Acl::Empty,
    };
    bootstrap::check_ancestors(&[ancestor], owner)?;
    for acl in [Acl::Present, Acl::Unknown] {
        assert!(bootstrap::check_ancestors(&[Ancestor { acl, ..ancestor }], owner).is_err());
    }
    drop(Sandbox::initialize(
        File::open(dir.path())?,
        &mut inspection,
    )?);
    let mut sandbox = Sandbox::reopen(File::open(dir.path())?, &mut inspection)?;
    let source = dir.path().join("review-input");
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source)?
        .write_all(b"data only")?;
    let digest: [u8; 32] = Sha256::digest(b"data only").into();
    let w = window();
    let review =
        ReviewedContent::sandbox_review(digest, 9, w.session, w.boot, w.deployment_generation)?;
    let mut input = bootstrap::open_candidate(&source)?;
    assert!(bootstrap::close_on_exec(&input)?);
    let mut prepared = sandbox.stage(&mut input, &review, &mut inspection)?;
    assert_eq!(prepared.bytes()?, b"data only");
    prepared.check_launch(LaunchObservation {
        session: w.session,
        boot: w.boot,
        generation: w.deployment_generation,
        birth: w.controller_birth,
        launch_sequence: 1,
        observed_sequence: 1,
        loaded_digest: Some(digest),
        inherited_fds: 0,
        fixed_entry: true,
    })?;
    let boundary = checked()?;
    let mut fake = Fake::new(&boundary);
    let mut session = Session::admit(boundary, w, &mut fake)?;
    session.load(&mut fake)?;
    session.recover(&mut fake)?;
    assert_eq!(session.phase(), Phase::Closed);
    // Native file data and simulated observations stay separate: closing the PF double does
    // not silently erase the durable staging journal or claim a real deployment was removed.
    assert_eq!(prepared.bytes()?, b"data only");
    drop(sandbox);
    assert!(Sandbox::reopen(File::open(dir.path())?, &mut inspection).is_err());
    Ok(())
}
