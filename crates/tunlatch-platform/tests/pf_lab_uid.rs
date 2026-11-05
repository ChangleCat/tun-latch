//! Closed UID/capture/state lifecycle doubles plus real same-user Unix FD handoff mechanics.
#[path = "pf_lab/driver.rs"]
mod driver;
#[path = "pf_lab/uid.rs"]
mod uid;
use driver::{Error, Guard, Identity, Observation, Result};
use std::collections::BTreeMap;
use uid::{
    Boundary, Case, Convergence, Experiment, Family, Kind, Outcome, Profile, Protocol, Report,
    Scope, Socket, SocketUid,
};
fn id() -> Identity {
    Identity {
        boot: [1; 32],
        session: [2; 32],
        plan: [3; 32],
        controller_birth: 7,
        lock_inode: 9,
    }
}
fn scope() -> Scope {
    Scope {
        physical: "lab0".into(),
        other_exit: "other0".into(),
        other_tun: "utun123".into(),
        instance: 99,
        other_instance: 100,
        tun_instance: 101,
        target_v4: std::net::Ipv4Addr::new(192, 0, 2, 2),
        target_v6: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        port: 45000,
        other_uid: 501,
    }
}
struct Fake {
    seq: u64,
    next: u64,
    profile: Profile,
    sockets: BTreeMap<u64, Socket>,
    states: BTreeMap<u64, bool>,
    probes: usize,
    stopped: bool,
    loads: usize,
    fault: Option<&'static str>,
}
impl Fake {
    fn new() -> Self {
        Self {
            seq: 0,
            next: 0,
            profile: Profile::Empty,
            sockets: BTreeMap::new(),
            states: [(999, true)].into(),
            probes: 0,
            stopped: false,
            loads: 0,
            fault: None,
        }
    }
    fn allowed(&self, case: Case, socket: Socket) -> bool {
        if self.profile == Profile::Empty {
            return true;
        }
        if matches!(
            case.kind,
            Kind::UnapprovedExit | Kind::OtherTun | Kind::OtherProtocol
        ) {
            return false;
        }
        let uid = if self.fault == Some("current-uid") {
            SocketUid::Known(socket.process_uid)
        } else {
            socket.creation_uid
        };
        match self.profile {
            Profile::GrantRoot => uid == SocketUid::Known(0),
            Profile::GrantOther => uid == SocketUid::Known(501),
            _ => false,
        }
    }
}
impl Boundary for Fake {
    fn observe(&mut self) -> Result<Observation> {
        self.seq += 1;
        Ok(Observation {
            identity: id(),
            sequence: self.seq,
            at_ms: self.seq,
            complete: true,
            exclusive: true,
            writers_reclaimed: true,
        })
    }
    fn install(&mut self, profile: Profile, rules: &str) -> Result<()> {
        if rules != scope().rules(profile)? {
            return Err(Error("candidate bytes mismatch"));
        }
        self.profile = profile;
        self.loads += 1;
        Ok(())
    }
    fn open(&mut self, case: Case) -> Result<Socket> {
        self.next += 1;
        let creation_uid = match case.kind {
            Kind::Other | Kind::BeforeEnable => SocketUid::Known(501),
            Kind::Unknown | Kind::OtherProtocol => SocketUid::Unknown,
            _ => SocketUid::Known(0),
        };
        let socket = Socket {
            instance: self.next,
            creation_uid,
            process_uid: if creation_uid == SocketUid::Known(501) {
                501
            } else {
                0
            },
            holder_birth: 20 + self.next,
            fd_instance: 100 + self.next,
            case: case.number,
        };
        self.sockets.insert(socket.instance, socket);
        self.states.insert(socket.instance, false);
        Ok(socket)
    }
    fn drop_credentials(&mut self, mut socket: Socket, other: u32) -> Result<Socket> {
        socket.process_uid = other;
        if self.fault == Some("replace-on-drop") {
            socket.instance += 1000;
        }
        self.sockets.insert(socket.instance, socket);
        Ok(socket)
    }
    fn transfer_fd(&mut self, mut socket: Socket, other: u32) -> Result<Socket> {
        socket.process_uid = other;
        socket.holder_birth += 100;
        socket.fd_instance += 100;
        self.sockets.insert(socket.instance, socket);
        Ok(socket)
    }
    fn probe(&mut self, case: Case, socket: Socket, nonce: [u8; 16]) -> Result<Report> {
        self.probes += 1;
        if self.sockets.get(&socket.instance) != Some(&socket) {
            return Err(Error("not the owned socket"));
        }
        let delivered = self.states.get(&socket.instance).copied().unwrap_or(false)
            || self.allowed(case, socket)
            || self.fault == Some("leak");
        if delivered {
            self.states.insert(socket.instance, true);
        }
        Ok(Report {
            socket,
            case: case.number,
            physical_instance: match case.kind {
                Kind::UnapprovedExit => 100,
                Kind::OtherTun => 101,
                _ => 99,
            },
            nonce,
            sent: true,
            delivered,
            capture_complete: self.fault != Some("capture"),
            positive_before: true,
            positive_after: true,
            capture_drops: 0,
        })
    }
    fn converge(&mut self, socket: Socket) -> Result<Convergence> {
        if self.fault != Some("old-state") {
            self.states.insert(socket.instance, false);
        }
        if self.fault == Some("collateral") {
            self.states.remove(&999);
        }
        Ok(Convergence {
            selector_qualified: self.fault != Some("selector"),
            old_states_gone: self.states.get(&socket.instance) == Some(&false),
            unrelated_preserved: self.states.get(&999) == Some(&true),
        })
    }
    fn close_owned(&mut self, socket: Socket) -> Result<()> {
        if self.sockets.remove(&socket.instance) != Some(socket) {
            return Err(Error("foreign socket close"));
        }
        self.states.remove(&socket.instance);
        Ok(())
    }
    fn stop_senders(&mut self) -> Result<()> {
        if self.fault == Some("stop") {
            return Err(Error("stop acknowledgement lost"));
        }
        self.stopped = true;
        Ok(())
    }
}
fn case(kind: Kind) -> Result<Case> {
    uid::matrix()
        .into_iter()
        .find(|c| c.kind == kind)
        .ok_or(Error("missing case"))
}
#[test]
fn all_sixty_dual_stack_tcp_udp_credential_scope_and_state_cases_run_offline() -> Result<()> {
    let cases = uid::matrix();
    assert_eq!(cases.len(), 60);
    for family in [Family::V4, Family::V6] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            assert!(
                cases
                    .iter()
                    .any(|c| c.family == family && c.protocol == protocol && c.kind == Kind::Root)
            );
        }
    }
    for case in cases {
        let mut fake = Fake::new();
        let mut run = Experiment::new(Guard::new(id(), 0)?);
        assert_eq!(
            run.run(&mut fake, &scope(), case)?,
            Outcome::MatchedExpectation,
            "{case:?}"
        );
        assert!(!run.unknown());
        assert!(fake.sockets.is_empty());
        assert_eq!(fake.states.get(&999), Some(&true));
        assert!(fake.stopped);
        assert_eq!(fake.profile, Profile::Empty);
        if matches!(
            case.kind,
            Kind::BeforeEnable | Kind::Revoke | Kind::ChangeUid | Kind::OrdinaryBlock
        ) {
            assert_eq!(fake.probes, 3);
        }
    }
    Ok(())
}
#[test]
fn current_process_uid_cannot_replace_socket_creation_uid_after_drop_or_transfer() -> Result<()> {
    for kind in [Kind::RootDrops, Kind::RootTransfers] {
        let mut fake = Fake::new();
        fake.fault = Some("current-uid");
        let outcome =
            Experiment::new(Guard::new(id(), 0)?).run(&mut fake, &scope(), case(kind)?)?;
        assert_eq!(
            outcome,
            Outcome::Violation {
                expected_allow: true,
                delivered: false
            }
        );
        assert!(fake.stopped);
        assert_eq!(fake.profile, Profile::GrantRoot);
    }
    Ok(())
}
#[test]
fn actual_delivery_on_negative_case_is_reported_as_violation_and_keeps_scene() -> Result<()> {
    for kind in [
        Kind::Other,
        Kind::Unknown,
        Kind::UnapprovedExit,
        Kind::OtherTun,
        Kind::OtherProtocol,
    ] {
        let mut fake = Fake::new();
        fake.fault = Some("leak");
        assert_eq!(
            Experiment::new(Guard::new(id(), 0)?).run(&mut fake, &scope(), case(kind)?)?,
            Outcome::Violation {
                expected_allow: false,
                delivered: true
            }
        );
        assert!(fake.stopped);
        assert!(!fake.sockets.is_empty());
        assert_ne!(fake.profile, Profile::Empty);
    }
    Ok(())
}
#[test]
fn old_state_precision_collateral_and_capture_failures_cannot_be_waived_by_new_connections()
-> Result<()> {
    for fault in ["selector", "old-state", "collateral", "capture", "stop"] {
        let mut fake = Fake::new();
        fake.fault = Some(fault);
        let mut run = Experiment::new(Guard::new(id(), 0)?);
        assert!(run.run(&mut fake, &scope(), case(Kind::Revoke)?).is_err());
        assert!(run.unknown());
        if fault != "stop" {
            assert!(fake.stopped);
        }
        assert!(!fake.sockets.is_empty());
        let probes = fake.probes;
        assert!(run.run(&mut fake, &scope(), case(Kind::Revoke)?).is_err());
        assert_eq!(fake.probes, probes);
    }
    Ok(())
}
#[test]
fn altered_socket_drop_chain_and_unknown_case_are_rejected() -> Result<()> {
    let mut fake = Fake::new();
    fake.fault = Some("replace-on-drop");
    assert!(
        Experiment::new(Guard::new(id(), 0)?)
            .run(&mut fake, &scope(), case(Kind::RootDrops)?)
            .is_err()
    );
    let mut invalid = case(Kind::Root)?;
    invalid.number = 999;
    let mut fake = Fake::new();
    assert!(
        Experiment::new(Guard::new(id(), 0)?)
            .run(&mut fake, &scope(), invalid)
            .is_err()
    );
    assert_eq!(fake.loads, 0);
    Ok(())
}
#[test]
fn rules_have_four_explicit_protocol_family_uid_equalities_and_block_priority() -> Result<()> {
    let scope = scope();
    let rules = scope.rules(Profile::GrantRoot)?;
    let passes: Vec<_> = rules.lines().filter(|l| l.starts_with("pass")).collect();
    assert_eq!(passes.len(), 4);
    for line in passes {
        assert!(line.contains("user = 0"));
        assert!(line.contains("on lab0"));
        assert!(line.contains("proto tcp") || line.contains("proto udp"));
        assert!(line.contains("inet ") || line.contains("inet6 "));
        assert!(line.contains("if-bound"));
        assert!(!line.contains("group"));
    }
    assert_eq!(rules.matches("user = 0").count(), 4);
    assert!(!rules.contains("wheel"));
    let blocked = scope.rules(Profile::BlockTarget)?;
    assert!(blocked.starts_with("block drop out quick"));
    assert!(blocked.find("tunlatch-lab:block") < blocked.find("tunlatch-lab:uid"));
    assert!(!scope.rules(Profile::Revoked)?.contains("pass"));
    assert!(!scope.rules(Profile::PlainAllowOnly)?.contains("user ="));
    assert_ne!(
        scope.rules_digest(Profile::GrantRoot)?,
        scope.rules_digest(Profile::Revoked)?
    );
    Ok(())
}
#[test]
fn scope_rejects_injection_alias_collisions_and_unapproved_implicit_values() -> Result<()> {
    for kind in ["name", "alias", "instance", "uid", "port"] {
        let mut s = scope();
        match kind {
            "name" => s.physical = "en0; -d".into(),
            "alias" => s.other_exit = s.physical.clone(),
            "instance" => s.instance = 0,
            "uid" => s.other_uid = 0,
            _ => s.port = 0,
        };
        assert!(s.rules(Profile::GrantRoot).is_err());
    }
    Ok(())
}
type NativeResult = std::result::Result<(), Box<dyn std::error::Error>>;
#[test]
fn real_same_user_fd_handoff_retains_inode_and_returns_only_cloexec_owned_fd() -> NativeResult {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    let (sender, receiver) = std::os::unix::net::UnixDatagram::pair()?;
    let mut source = tempfile::tempfile()?;
    source.write_all(b"controlled-fd")?;
    source.seek(SeekFrom::Start(0))?;
    uid::send_fd(&sender, source.as_fd(), [7; 16])?;
    let fd = uid::receive_fd(&receiver, [7; 16])?;
    assert!(rustix::io::fcntl_getfd(&fd)?.contains(rustix::io::FdFlags::CLOEXEC));
    let mut received = std::fs::File::from(fd);
    assert_eq!(source.metadata()?.ino(), received.metadata()?.ino());
    let mut data = Vec::new();
    Read::by_ref(&mut received)
        .take(32)
        .read_to_end(&mut data)?;
    assert_eq!(data, b"controlled-fd");
    let _drop_entry: fn(&uid::PrivilegePermit, u32) -> Result<()> = uid::change_uid_native;
    Ok(())
}
#[test]
fn fd_handoff_rejects_wrong_nonce_missing_fd_and_extra_bytes_without_blocking() -> NativeResult {
    use std::os::fd::AsFd;
    let (sender, receiver) = std::os::unix::net::UnixDatagram::pair()?;
    assert!(uid::receive_fd(&receiver, [1; 16]).is_err());
    let source = tempfile::tempfile()?;
    uid::send_fd(&sender, source.as_fd(), [1; 16])?;
    assert!(uid::receive_fd(&receiver, [2; 16]).is_err());
    sender.send(&[1; 16])?;
    assert!(uid::receive_fd(&receiver, [1; 16]).is_err());
    sender.send(&[1; 17])?;
    assert!(uid::receive_fd(&receiver, [1; 16]).is_err());
    assert!(source.metadata()?.is_file());
    Ok(())
}
#[test]
fn review_bundle_is_generated_from_the_same_closed_rule_and_case_functions() -> Result<()> {
    let s = scope();
    let rules = s.rules(Profile::GrantRoot)?;
    assert_eq!(uid::matrix().len(), 60);
    let rows:Vec<_>=uid::matrix().iter().map(|c|serde_json::json!({"case":c.number,"family":format!("{:?}",c.family),"protocol":format!("{:?}",c.protocol),"kind":format!("{:?}",c.kind)})).collect();
    let mut profiles = serde_json::Map::new();
    for profile in [
        Profile::Empty,
        Profile::GrantRoot,
        Profile::Revoked,
        Profile::GrantOther,
        Profile::BlockTarget,
        Profile::PlainAllowOnly,
    ] {
        profiles.insert(format!("{profile:?}"),serde_json::json!({"rules":s.rules(profile)?,"sha256":s.rules_digest(profile)?.iter().map(|b|format!("{b:02x}")).collect::<String>()}));
    }
    let bundle = serde_json::json!({"result":"offline_candidate_not_authorized","fixture_only":true,"frozen_for_live":false,"host_binding":null,"deployed_programs":null,"targets":[s.target_v4.to_string(),s.target_v6.to_string()],"target_port":s.port,"interfaces":[s.physical,s.other_exit,s.other_tun],"grant_uid":0,"other_uid":s.other_uid,"rules":rules,"rules_sha256":s.rules_digest(Profile::GrantRoot)?.iter().map(|b|format!("{b:02x}")).collect::<String>(),"profiles":profiles,"cases":rows,"native_entrypoints":["utun::create_native","traffic::native_exchange","uid::change_uid_native","uid::send_fd/receive_fd"],"live_pf":"not_run","cross_uid":"not_run","quic_dns":"not_run"});
    println!("B02_REVIEW_BUNDLE={bundle}");
    Ok(())
}
#[test]
fn multiple_received_descriptors_are_rejected_as_ambiguous_handoff() -> NativeResult {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    use std::os::fd::AsFd;
    let (sender, receiver) = std::os::unix::net::UnixDatagram::pair()?;
    let one = tempfile::tempfile()?;
    let two = tempfile::tempfile()?;
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [one.as_fd(), two.as_fd()];
    assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
    sendmsg(
        &sender,
        &[std::io::IoSlice::new(&[1; 16])],
        &mut control,
        SendFlags::DONTWAIT,
    )?;
    assert!(uid::receive_fd(&receiver, [1; 16]).is_err());
    assert!(one.metadata()?.is_file());
    assert!(two.metadata()?.is_file());
    Ok(())
}
