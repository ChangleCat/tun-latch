//! TUN owned-instance experiment tests; no interface is created.
#[path = "pf_lab/driver.rs"]
mod driver;
#[path = "pf_lab/utun.rs"]
mod utun;
use driver::{Error, Guard, Identity, Observation, Result};
use utun::{Boundary, Connection, Entry, Instance, PauseAck, Reuse, Slot};
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
    sequence: u64,
    allocation: u64,
    held: Option<Instance>,
    paused: bool,
    leak: bool,
    fault: Option<&'static str>,
    closed: Vec<Instance>,
}
impl Fake {
    fn new() -> Self {
        Self {
            sequence: 0,
            allocation: 0,
            held: None,
            paused: false,
            leak: true,
            fault: None,
            closed: Vec::new(),
        }
    }
}
impl Boundary for Fake {
    fn observe(&mut self) -> Result<Observation> {
        self.sequence += 1;
        Ok(Observation {
            identity: id(),
            sequence: self.sequence,
            at_ms: self.sequence,
            complete: true,
            exclusive: self.fault != Some("foreign"),
            writers_reclaimed: true,
        })
    }
    fn create_owned(&mut self, slot: Slot) -> Result<Instance> {
        if self.fault == Some("create") {
            return Err(Error("injected create failure"));
        }
        self.allocation += 1;
        let i = Instance {
            slot,
            if_index: 42,
            allocation: self.allocation,
            holder_birth: 10 + self.allocation,
            fd_instance: 20 + self.allocation,
            session: id().session,
        };
        self.held = Some(i);
        Ok(i)
    }
    fn close_owned(&mut self, i: Instance) -> Result<()> {
        if self.held != Some(i) || self.fault == Some("close") {
            return Err(Error("close not owned"));
        }
        self.closed.push(i);
        self.held = None;
        Ok(())
    }
    fn pause_own_worker(&mut self, request: u64) -> Result<PauseAck> {
        self.paused = true;
        Ok(PauseAck {
            worker_birth: 7,
            request,
            queue_closed: true,
            all_writers_reclaimed: self.fault != Some("pause"),
        })
    }
    fn resume_own_worker(&mut self, _: PauseAck) -> Result<()> {
        if self.fault == Some("resume") {
            return Err(Error("resume failure"));
        }
        self.paused = false;
        Ok(())
    }
    fn probe(&mut self, nonce: [u8; 16], _: Connection) -> Result<Entry> {
        Ok(Entry {
            nonce,
            entered: if !self.paused || self.leak {
                self.held
            } else {
                None
            },
            capture_complete: self.fault != Some("capture"),
        })
    }
}
#[test]
fn same_name_and_index_do_not_excuse_new_or_existing_flow_into_replacement() -> Result<()> {
    let mut f = Fake::new();
    let mut run = Reuse::new(Guard::new(id(), 0)?);
    let witness = run.run(&mut f, Slot::new(123)?)?;
    assert_eq!(witness.old.slot, witness.replacement.slot);
    assert_eq!(witness.old.if_index, witness.replacement.if_index);
    assert_ne!(witness.old.fd_instance, witness.replacement.fd_instance);
    assert!(witness.new_connection_leaked && witness.existing_connection_leaked);
    assert!(!run.quarantined());
    assert_eq!(f.closed.len(), 2);
    assert!(!f.paused);
    assert!(run.run(&mut f, Slot::new(123)?).is_err());
    Ok(())
}
#[test]
fn blocked_replacement_is_distinct_from_missing_capture() -> Result<()> {
    let mut f = Fake::new();
    f.leak = false;
    let w = Reuse::new(Guard::new(id(), 0)?).run(&mut f, Slot::new(123)?)?;
    assert!(!w.new_connection_leaked && !w.existing_connection_leaked);
    Ok(())
}
#[test]
fn failure_quarantines_without_closing_by_name_or_hiding_a_live_handle() -> Result<()> {
    for fault in ["create", "close", "pause", "capture", "foreign", "resume"] {
        let mut f = Fake::new();
        f.fault = Some(fault);
        let mut run = Reuse::new(Guard::new(id(), 0)?);
        assert!(run.run(&mut f, Slot::new(123)?).is_err(), "{fault}");
        assert!(run.quarantined());
        let count = f.closed.len();
        assert!(run.run(&mut f, Slot::new(123)?).is_err());
        assert_eq!(count, f.closed.len());
    }
    Ok(())
}
#[test]
fn safe_library_creation_path_compiles_but_no_interface_is_created() -> Result<()> {
    let slot = Slot::new(123)?;
    assert_eq!(slot.name(), "utun123");
    let _builder = utun::native_builder(slot);
    let _entry: fn(&utun::LivePermit, Slot) -> std::io::Result<tun_rs::SyncDevice> =
        utun::create_native;
    assert!(Slot::new(65535).is_err());
    assert!(Slot::new(u32::MAX).is_err());
    Ok(())
}
#[test]
fn family_framing_never_silently_accepts_unknown_or_short_packets() -> Result<()> {
    let mut v4 = vec![0; 24];
    v4[3] = 2;
    v4[4] = 0x45;
    v4[6..8].copy_from_slice(&20_u16.to_be_bytes());
    assert_eq!(utun::decode_frame(&v4)?, &v4[4..]);
    let mut v6 = vec![0; 44];
    v6[3] = 30;
    v6[4] = 0x60;
    assert_eq!(utun::decode_frame(&v6)?, &v6[4..]);
    v4[3] = 30;
    assert!(utun::decode_frame(&v4).is_err());
    for frame in [
        &[][..],
        &[0, 0, 0, 2][..],
        &[0, 0, 0, 2, 0x60][..],
        &[0, 0, 0, 99, 0x45][..],
    ] {
        assert!(utun::decode_frame(frame).is_err());
    }
    Ok(())
}
#[test]
fn rejects_declared_ip_header_truncation_in_utun_frames() {
    assert!(utun::decode_frame(&[0, 0, 0, 2, 0x45]).is_err());
    let mut v4 = vec![0; 24];
    v4[3] = 2;
    v4[4] = 0x45;
    v4[6..8].copy_from_slice(&40_u16.to_be_bytes());
    assert!(utun::decode_frame(&v4).is_err());
    let mut v6 = vec![0; 44];
    v6[3] = 30;
    v6[4] = 0x60;
    v6[8..10].copy_from_slice(&8_u16.to_be_bytes());
    assert!(utun::decode_frame(&v6).is_err());
}
#[test]
fn shared_guard_rejects_unknown_identity_replays_deadlines_and_incomplete_reclamation() -> Result<()>
{
    let base = Observation {
        identity: id(),
        sequence: 1,
        at_ms: 1,
        complete: true,
        exclusive: true,
        writers_reclaimed: true,
    };
    for bad in [
        Observation {
            complete: false,
            ..base
        },
        Observation {
            exclusive: false,
            ..base
        },
        Observation {
            writers_reclaimed: false,
            ..base
        },
        Observation {
            sequence: 0,
            ..base
        },
        Observation {
            at_ms: 10001,
            ..base
        },
        Observation {
            identity: Identity {
                lock_inode: 10,
                ..id()
            },
            ..base
        },
    ] {
        assert!(Guard::new(id(), 0)?.check(bad).is_err());
    }
    assert!(
        Guard::new(
            Identity {
                boot: [0; 32],
                ..id()
            },
            0
        )
        .is_err()
    );
    let mut g = Guard::new(id(), 0)?;
    g.check(base)?;
    assert!(g.check(base).is_err());
    for sequence in 2..=128 {
        g.check(Observation {
            sequence,
            at_ms: sequence,
            ..base
        })?;
    }
    assert!(
        g.check(Observation {
            sequence: 129,
            at_ms: 129,
            ..base
        })
        .is_err()
    );
    Ok(())
}
