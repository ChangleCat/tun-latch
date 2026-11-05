//! Transaction fault injections distinguish instrumented doubles from opaque real submission.
#[path = "pf_lab/driver.rs"]
mod driver;
#[path = "pf_lab/transaction.rs"]
mod transaction;
use driver::{Error, Guard, Identity, Observation, Result};
use transaction::{Boundary, Fault, Image, Payload, Phase, Reply, Snapshot, Surface, Transaction};
fn id() -> Identity {
    Identity {
        boot: [1; 32],
        session: [2; 32],
        plan: [3; 32],
        controller_birth: 7,
        lock_inode: 9,
    }
}
struct Fake {
    surface: Surface,
    image: Image,
    staged: Option<Payload>,
    seq: u64,
    calls: Vec<&'static str>,
    records: Vec<Phase>,
    fault: Option<&'static str>,
}
impl Fake {
    fn new(surface: Surface) -> Self {
        Self {
            surface,
            image: Image {
                payload: Payload::Empty,
                foreign_digest: [8; 32],
                generation: 1,
            },
            staged: None,
            seq: 0,
            calls: Vec::new(),
            records: Vec::new(),
            fault: None,
        }
    }
}
impl Boundary for Fake {
    fn surface(&self) -> Surface {
        self.surface
    }
    fn snapshot(&mut self) -> Result<Snapshot> {
        self.seq += 1;
        Ok(Snapshot {
            observation: Observation {
                identity: id(),
                sequence: self.seq,
                at_ms: self.seq,
                complete: true,
                exclusive: true,
                writers_reclaimed: true,
            },
            image: self.image,
        })
    }
    fn persist(&mut self, p: Phase) -> Result<()> {
        if self.fault == Some("disk") && p == Phase::Observed {
            return Err(Error("disk after commit"));
        }
        self.records.push(p);
        Ok(())
    }
    fn begin(&mut self) -> Result<u64> {
        self.calls.push("begin");
        Ok(1)
    }
    fn stage(&mut self, ticket: u64, p: Payload) -> Result<()> {
        if ticket != 1 {
            return Err(Error("ticket"));
        }
        self.calls.push("stage");
        self.staged = Some(p);
        Ok(())
    }
    fn commit(&mut self, ticket: u64) -> Result<Reply> {
        if ticket != 1 {
            return Err(Error("ticket"));
        }
        self.calls.push("commit");
        let p = self.staged.ok_or(Error("no staged payload"))?;
        self.submit(p, false)
    }
    fn submit(&mut self, p: Payload, cancel: bool) -> Result<Reply> {
        self.calls.push("submit");
        self.image.payload = p;
        self.image.generation += 1;
        if self.fault == Some("lost-reply") {
            return Err(Error("committed, reply lost"));
        }
        if self.fault == Some("foreign") {
            self.image.foreign_digest = [9; 32];
        }
        Ok(Reply {
            success: true,
            all_writers_reclaimed: !cancel,
        })
    }
}
#[test]
fn instrumented_and_opaque_normal_paths_restore_only_the_owned_filter() -> Result<()> {
    for surface in [Surface::OpaqueSubmit, Surface::InstrumentedDouble] {
        let mut f = Fake::new(surface);
        let mut run = Transaction::new(Guard::new(id(), 0)?);
        run.run(&mut f, Payload::BlockProbe, Fault::None)?;
        assert_eq!(run.phase(), Phase::Observed);
        assert_eq!(run.session(), id().session);
        run.restore(&mut f)?;
        assert_eq!(run.phase(), Phase::Restored);
        assert_eq!(f.image.payload, Payload::Empty);
        assert_eq!(f.image.foreign_digest, [8; 32]);
        if surface == Surface::OpaqueSubmit {
            assert!(!f.calls.contains(&"begin"));
            assert!(!f.calls.contains(&"stage"));
        }
    }
    Ok(())
}
#[test]
fn before_submit_failure_is_proved_without_a_write() -> Result<()> {
    let mut f = Fake::new(Surface::OpaqueSubmit);
    let mut r = Transaction::new(Guard::new(id(), 0)?);
    assert!(
        r.run(&mut f, Payload::BlockProbe, Fault::BeforeSubmit)
            .is_err()
    );
    assert_eq!(r.phase(), Phase::Rejected);
    assert!(f.calls.is_empty());
    assert_eq!(f.image.generation, 1);
    Ok(())
}
#[test]
fn every_internal_fault_is_explicitly_double_only_and_preserves_unknown() -> Result<()> {
    for fault in [Fault::AfterBegin, Fault::AfterStage, Fault::BeforeCommit] {
        let mut f = Fake::new(Surface::InstrumentedDouble);
        let mut r = Transaction::new(Guard::new(id(), 0)?);
        assert!(r.run(&mut f, Payload::BlockProbe, fault).is_err());
        assert_eq!(r.phase(), Phase::Unknown);
        assert_eq!(f.image.payload, Payload::Empty);
        let count = f.calls.len();
        assert!(r.restore(&mut f).is_err());
        assert!(r.run(&mut f, Payload::BlockProbe, Fault::None).is_err());
        assert_eq!(f.calls.len(), count);
        let mut f = Fake::new(Surface::OpaqueSubmit);
        let mut r = Transaction::new(Guard::new(id(), 0)?);
        assert!(r.run(&mut f, Payload::BlockProbe, fault).is_err());
        assert!(f.calls.is_empty());
        assert_eq!(r.phase(), Phase::Rejected);
    }
    Ok(())
}
#[test]
fn waiter_cancellation_and_post_reply_interruption_do_not_mean_kernel_rollback() -> Result<()> {
    for fault in [Fault::CancelDuringSubmit, Fault::AfterReply] {
        let mut f = Fake::new(Surface::OpaqueSubmit);
        let mut r = Transaction::new(Guard::new(id(), 0)?);
        assert!(r.run(&mut f, Payload::BlockProbe, fault).is_err());
        assert_eq!(r.phase(), Phase::Unknown);
        assert_eq!(f.image.payload, Payload::BlockProbe);
        assert!(r.restore(&mut f).is_err());
    }
    Ok(())
}
#[test]
fn committed_lost_reply_disk_error_or_foreign_change_blocks_cleanup() -> Result<()> {
    for fault in ["lost-reply", "disk", "foreign"] {
        let mut f = Fake::new(Surface::OpaqueSubmit);
        f.fault = Some(fault);
        let mut r = Transaction::new(Guard::new(id(), 0)?);
        assert!(r.run(&mut f, Payload::BlockProbe, Fault::None).is_err());
        assert_eq!(r.phase(), Phase::Unknown);
        assert_eq!(f.image.payload, Payload::BlockProbe);
        assert!(r.restore(&mut f).is_err());
    }
    Ok(())
}
#[test]
fn restoration_lost_reply_is_retained_without_a_second_submit() -> Result<()> {
    let mut f = Fake::new(Surface::OpaqueSubmit);
    let mut r = Transaction::new(Guard::new(id(), 0)?);
    r.run(&mut f, Payload::BlockProbe, Fault::None)?;
    f.fault = Some("lost-reply");
    assert!(r.restore(&mut f).is_err());
    let count = f.calls.len();
    assert_eq!(r.phase(), Phase::Unknown);
    assert!(r.restore(&mut f).is_err());
    assert_eq!(f.calls.len(), count);
    Ok(())
}
#[test]
fn candidate_payloads_are_closed_and_digested_not_imported() {
    assert_eq!(
        transaction::command_candidate(),
        ["-a", "tunlatch-lab/session", "-f", "-"]
    );
    assert_ne!(Payload::Empty.digest(), Payload::BlockProbe.digest());
    assert!(
        Payload::BlockProbe
            .bytes()
            .starts_with(b"block drop out quick")
    );
}
