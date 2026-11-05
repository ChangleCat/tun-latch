//! Offline state selector counterexamples with explicit impact; no state-table mutation.
#[path = "pf_lab/driver.rs"]
mod driver;
#[path = "pf_lab/states.rs"]
mod states;
use driver::{Error, Guard, Identity, Observation, Result};
use states::{Boundary, Experiment, Protocol, Selector, Snapshot, State};
fn id() -> Identity {
    Identity {
        boot: [1; 32],
        session: [2; 32],
        plan: [3; 32],
        controller_birth: 7,
        lock_inode: 9,
    }
}
fn state(id: u128, port: u16) -> State {
    State {
        id,
        source: ([192, 0, 2, 1], port).into(),
        destination: ([192, 0, 2, 2], 443).into(),
        protocol: Protocol::Tcp,
        interface: "lab0".into(),
        translated: false,
    }
}
struct Fake {
    states: Vec<State>,
    sequence: u64,
    calls: usize,
    fault: Option<&'static str>,
}
impl Fake {
    fn new() -> Self {
        let mut other = state(3, 50003);
        other.destination = ([192, 0, 2, 3], 443).into();
        Self {
            states: vec![state(1, 50001), state(2, 50002), other],
            sequence: 0,
            calls: 0,
            fault: None,
        }
    }
}
impl Boundary for Fake {
    fn snapshot(&mut self) -> Result<Snapshot> {
        self.sequence += 1;
        Ok(Snapshot {
            observation: Observation {
                identity: id(),
                sequence: self.sequence,
                at_ms: self.sequence,
                complete: self.fault != Some("partial"),
                exclusive: true,
                writers_reclaimed: true,
            },
            states: self.states.clone(),
        })
    }
    fn exercise_selector(&mut self, selector: &Selector) -> Result<usize> {
        self.calls += 1;
        let before = self.states.len();
        self.states.retain(|s| !selector.matches(s));
        if self.fault == Some("lost-reply") {
            return Err(Error("result lost after mutation"));
        }
        if self.fault == Some("foreign") {
            self.states.clear();
        }
        Ok(before - self.states.len())
    }
}
#[test]
fn host_pair_deletes_other_ports_and_reports_collateral_instead_of_precision() -> Result<()> {
    let mut f = Fake::new();
    let selector = Selector::host_pair(
        "192.0.2.1".parse().map_err(|_| Error("IP"))?,
        "192.0.2.2".parse().map_err(|_| Error("IP"))?,
    )?;
    let study =
        Experiment::new(Guard::new(id(), 0)?).run(&mut f, selector, [1].into(), [1, 2].into())?;
    assert_eq!(study.collateral, [2].into());
    assert!(study.missed.is_empty());
    assert_eq!(study.removed, [1, 2].into());
    assert_eq!(f.states.iter().map(|s| s.id).collect::<Vec<_>>(), [3]);
    Ok(())
}
#[test]
fn audited_library_zero_masks_can_reach_all_same_family_protocol_interface_states() -> Result<()> {
    let mut f = Fake::new();
    let selector = Selector::LibraryFamilyProtocolInterface {
        ipv6: false,
        protocol: Protocol::Tcp,
        interface: "lab0".into(),
    };
    assert!(selector.command_candidate().is_err());
    let study = Experiment::new(Guard::new(id(), 0)?).run(
        &mut f,
        selector,
        [1].into(),
        [1, 2, 3].into(),
    )?;
    assert_eq!(study.collateral, [2, 3].into());
    Ok(())
}
#[test]
fn unapproved_collateral_and_partial_or_duplicate_inventory_refuse_before_delete() -> Result<()> {
    for fault in ["impact", "partial", "duplicate", "nat"] {
        let mut f = Fake::new();
        match fault {
            "partial" => f.fault = Some("partial"),
            "duplicate" => f.states.push(state(1, 50004)),
            "nat" => f.states[0].translated = true,
            _ => {}
        }
        let selector = Selector::HostPair {
            source: f.states[0].source.ip(),
            destination: f.states[0].destination.ip(),
        };
        assert!(
            Experiment::new(Guard::new(id(), 0)?)
                .run(&mut f, selector, [1].into(), [1].into())
                .is_err()
        );
        assert_eq!(f.calls, 0);
    }
    Ok(())
}
#[test]
fn lost_result_and_unrelated_state_change_never_trigger_retry_or_global_flush() -> Result<()> {
    for fault in ["lost-reply", "foreign"] {
        let mut f = Fake::new();
        f.fault = Some(fault);
        let selector = Selector::HostPair {
            source: f.states[0].source.ip(),
            destination: f.states[0].destination.ip(),
        };
        let mut run = Experiment::new(Guard::new(id(), 0)?);
        assert!(
            run.run(&mut f, selector.clone(), [1].into(), [1, 2].into())
                .is_err()
        );
        assert!(run.unknown());
        assert!(
            run.run(&mut f, selector, [1].into(), [1, 2].into())
                .is_err()
        );
        assert_eq!(f.calls, 1);
    }
    Ok(())
}
#[test]
fn no_uid_or_pid_guess_and_closed_host_commands() -> Result<()> {
    assert!(states::uid_selector(0).is_err());
    assert!(states::uid_selector(501).is_err());
    assert_eq!(states::required_changes().len(), 5);
    let selector = Selector::host_pair(
        "2001:db8::1".parse().map_err(|_| Error("IP"))?,
        "2001:db8::2".parse().map_err(|_| Error("IP"))?,
    )?;
    assert_eq!(
        selector.command_candidate()?,
        ["-k", "2001:db8::1", "-k", "2001:db8::2"]
    );
    let mut udp = state(1, 12345);
    udp.protocol = Protocol::Udp;
    assert!(!selector.matches(&udp));
    assert!(
        Selector::host_pair(
            "0.0.0.0".parse().map_err(|_| Error("IP"))?,
            udp.destination.ip()
        )
        .is_err()
    );
    Ok(())
}
