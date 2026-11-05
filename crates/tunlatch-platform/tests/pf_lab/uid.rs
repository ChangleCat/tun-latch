//! Closed UID experiment matrix, generated numeric user rules and controlled socket lifecycle.
//! No live PF/privilege entrypoint. IPC FD handoff is tested as the ordinary user; cross-UID
//! ownership semantics require the later approved kernel experiment, never current process UID.
use super::driver::{Error, Guard, Observation, Result};
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Family {
    V4,
    V6,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketUid {
    Known(u32),
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    Root,
    Other,
    Unknown,
    IndependentRoot,
    RootDrops,
    RootTransfers,
    UdpConnected,
    UdpUnconnected,
    UnapprovedExit,
    OrdinaryBlock,
    BeforeEnable,
    Revoke,
    ChangeUid,
    AllowWithoutGrant,
    OtherTun,
    OtherProtocol,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Case {
    pub(crate) number: u16,
    pub(crate) family: Family,
    pub(crate) protocol: Protocol,
    pub(crate) kind: Kind,
}
pub(crate) fn matrix() -> Vec<Case> {
    let mut cases = Vec::new();
    for family in [Family::V4, Family::V6] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for kind in [
                Kind::Root,
                Kind::Other,
                Kind::Unknown,
                Kind::IndependentRoot,
                Kind::RootDrops,
                Kind::RootTransfers,
                Kind::UnapprovedExit,
                Kind::OrdinaryBlock,
                Kind::BeforeEnable,
                Kind::Revoke,
                Kind::ChangeUid,
                Kind::AllowWithoutGrant,
                Kind::OtherTun,
                Kind::OtherProtocol,
            ] {
                cases.push(Case {
                    number: cases.len() as u16 + 1,
                    family,
                    protocol,
                    kind,
                });
            }
            if protocol == Protocol::Udp {
                for kind in [Kind::UdpConnected, Kind::UdpUnconnected] {
                    cases.push(Case {
                        number: cases.len() as u16 + 1,
                        family,
                        protocol,
                        kind,
                    });
                }
            }
        }
    }
    cases
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Profile {
    Empty,
    GrantRoot,
    Revoked,
    GrantOther,
    BlockTarget,
    PlainAllowOnly,
}
#[derive(Clone, Debug)]
pub(crate) struct Scope {
    pub(crate) physical: String,
    pub(crate) other_exit: String,
    pub(crate) other_tun: String,
    pub(crate) instance: u64,
    pub(crate) other_instance: u64,
    pub(crate) tun_instance: u64,
    pub(crate) target_v4: Ipv4Addr,
    pub(crate) target_v6: Ipv6Addr,
    pub(crate) port: u16,
    pub(crate) other_uid: u32,
}
impl Scope {
    pub(crate) fn validate(&self) -> Result<()> {
        let names = [&self.physical, &self.other_exit, &self.other_tun];
        if names.iter().any(|n| {
            n.is_empty()
                || n.len() > 15
                || !n.bytes().all(|b| b.is_ascii_alphanumeric())
                || *n == "lo0"
        }) || names[0] == names[1]
            || names[0] == names[2]
            || names[1] == names[2]
            || self.instance == 0
            || self.other_instance == 0
            || self.tun_instance == 0
            || self.instance == self.other_instance
            || self.instance == self.tun_instance
            || self.other_instance == self.tun_instance
            || self.port == 0
            || self.other_uid == 0
            || self.target_v4.is_unspecified()
            || self.target_v4.is_multicast()
            || self.target_v6.is_unspecified()
            || self.target_v6.is_multicast()
        {
            return Err(Error("invalid UID experiment scope"));
        }
        Ok(())
    }
    /// Numeric UID equality only; TCP and UDP are separately generated, never group/wheel OR.
    /// This is a bounded test target, not a hardcoded proxy endpoint or a full product compiler.
    pub(crate) fn rules(&self, profile: Profile) -> Result<String> {
        self.validate()?;
        if profile == Profile::Empty {
            return Ok(String::new());
        }
        let mut rules = String::new();
        for (family, target) in [
            ("inet", self.target_v4.to_string()),
            ("inet6", self.target_v6.to_string()),
        ] {
            for protocol in ["tcp", "udp"] {
                if profile == Profile::BlockTarget {
                    rules.push_str(&format!("block drop out quick on {} {family} proto {protocol} from any to {target} port {} label \"tunlatch-lab:block\"\n",self.physical,self.port));
                }
                let uid = match profile {
                    Profile::GrantRoot | Profile::BlockTarget => Some(0),
                    Profile::GrantOther => Some(self.other_uid),
                    _ => None,
                };
                if let Some(uid) = uid {
                    rules.push_str(&format!("pass out quick on {} {family} proto {protocol} from any to {target} port {} user = {uid} keep state (if-bound) label \"tunlatch-lab:uid\"\n",self.physical,self.port));
                }
                if profile == Profile::PlainAllowOnly {
                    rules.push_str(&format!("pass out on {} {family} proto {protocol} from any to {target} port {} label \"tunlatch-lab:ordinary-allow\"\n",self.physical,self.port));
                }
                rules.push_str(&format!("block drop out quick on {{ {}, {}, {} }} {family} proto {protocol} from any to {target} port {} label \"tunlatch-lab:deny\"\n",self.physical,self.other_exit,self.other_tun,self.port));
            }
        }
        // Non TCP/UDP test packets to the controlled peer cannot borrow account authorization.
        for (family, target) in [
            ("inet", self.target_v4.to_string()),
            ("inet6", self.target_v6.to_string()),
        ] {
            rules.push_str(&format!("block drop out quick on {{ {}, {}, {} }} {family} from any to {target} label \"tunlatch-lab:other-proto\"\n",self.physical,self.other_exit,self.other_tun));
        }
        if rules.len() > 8192 {
            return Err(Error("UID candidate rules budget"));
        }
        Ok(rules)
    }
    pub(crate) fn rules_digest(&self, profile: Profile) -> Result<[u8; 32]> {
        Ok(Sha256::digest(self.rules(profile)?.as_bytes()).into())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Socket {
    pub(crate) instance: u64,
    pub(crate) creation_uid: SocketUid,
    pub(crate) process_uid: u32,
    pub(crate) holder_birth: u64,
    pub(crate) fd_instance: u64,
    pub(crate) case: u16,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Report {
    pub(crate) socket: Socket,
    pub(crate) case: u16,
    pub(crate) physical_instance: u64,
    pub(crate) nonce: [u8; 16],
    pub(crate) sent: bool,
    pub(crate) delivered: bool,
    pub(crate) capture_complete: bool,
    pub(crate) positive_before: bool,
    pub(crate) positive_after: bool,
    pub(crate) capture_drops: u64,
}
pub(crate) struct Convergence {
    pub(crate) selector_qualified: bool,
    pub(crate) old_states_gone: bool,
    pub(crate) unrelated_preserved: bool,
}
pub(crate) trait Boundary {
    fn observe(&mut self) -> Result<Observation>;
    fn install(&mut self, profile: Profile, rules: &str) -> Result<()>;
    fn open(&mut self, case: Case) -> Result<Socket>;
    fn drop_credentials(&mut self, socket: Socket, other_uid: u32) -> Result<Socket>;
    fn transfer_fd(&mut self, socket: Socket, other_uid: u32) -> Result<Socket>;
    fn probe(&mut self, case: Case, socket: Socket, nonce: [u8; 16]) -> Result<Report>;
    fn converge(&mut self, socket: Socket) -> Result<Convergence>;
    fn close_owned(&mut self, socket: Socket) -> Result<()>;
    fn stop_senders(&mut self) -> Result<()>;
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    MatchedExpectation,
    Violation {
        expected_allow: bool,
        delivered: bool,
    },
}
pub(crate) struct Experiment {
    guard: Guard,
    consumed: bool,
    unknown: bool,
}
impl Experiment {
    pub(crate) fn new(guard: Guard) -> Self {
        Self {
            guard,
            consumed: false,
            unknown: false,
        }
    }
    pub(crate) fn unknown(&self) -> bool {
        self.unknown
    }
    fn install(&mut self, b: &mut impl Boundary, scope: &Scope, profile: Profile) -> Result<()> {
        self.guard.check(b.observe()?)?;
        b.install(profile, &scope.rules(profile)?)?;
        self.guard.check(b.observe()?)
    }
    fn probe(
        &mut self,
        b: &mut impl Boundary,
        scope: &Scope,
        case: Case,
        socket: Socket,
        phase: u8,
        expected: bool,
    ) -> Result<Outcome> {
        self.guard.check(b.observe()?)?;
        let mut hash = Sha256::new();
        hash.update(self.guard.identity().session);
        hash.update(self.guard.identity().plan);
        hash.update(case.number.to_be_bytes());
        hash.update([phase]);
        let digest = hash.finalize();
        let mut nonce = [0; 16];
        nonce.copy_from_slice(&digest[..16]);
        let report = b.probe(case, socket, nonce)?;
        let instance = match case.kind {
            Kind::UnapprovedExit => scope.other_instance,
            Kind::OtherTun => scope.tun_instance,
            _ => scope.instance,
        };
        if report.socket != socket
            || report.case != case.number
            || report.physical_instance != instance
            || report.nonce != nonce
            || !report.sent
            || !report.capture_complete
            || !report.positive_before
            || !report.positive_after
            || report.capture_drops != 0
        {
            return Err(Error("UID flow/socket/capture evidence incomplete"));
        }
        if report.delivered == expected {
            Ok(Outcome::MatchedExpectation)
        } else {
            b.stop_senders()?;
            Ok(Outcome::Violation {
                expected_allow: expected,
                delivered: report.delivered,
            })
        }
    }
    pub(crate) fn run(
        &mut self,
        b: &mut impl Boundary,
        scope: &Scope,
        case: Case,
    ) -> Result<Outcome> {
        if self.consumed {
            return Err(Error("UID case is one-shot"));
        }
        self.consumed = true;
        let result = self.inner(b, scope, case);
        if result.is_err() {
            self.unknown = true;
            // Request cancellation of this controller's owned senders; this is not a claim
            // that they are reaped and never authorizes PF/file/FD cleanup.
            if b.stop_senders().is_err() {
                return Err(Error("UID failure; owned sender stop also unconfirmed"));
            }
        }
        result
    }
    fn inner(&mut self, b: &mut impl Boundary, scope: &Scope, case: Case) -> Result<Outcome> {
        scope.validate()?;
        if !matrix().contains(&case) {
            return Err(Error("case outside closed UID matrix"));
        }
        let before_enable = case.kind == Kind::BeforeEnable;
        let changing = matches!(
            case.kind,
            Kind::Revoke | Kind::ChangeUid | Kind::OrdinaryBlock | Kind::BeforeEnable
        );
        let initial = if before_enable {
            Profile::Empty
        } else if case.kind == Kind::AllowWithoutGrant {
            Profile::PlainAllowOnly
        } else {
            Profile::GrantRoot
        };
        self.install(b, scope, initial)?;
        let original = b.open(case)?;
        if original.instance == 0
            || original.holder_birth == 0
            || original.fd_instance == 0
            || original.case != case.number
        {
            return Err(Error("socket creation ownership missing"));
        }
        let expected_uid = if matches!(case.kind, Kind::Other | Kind::BeforeEnable) {
            SocketUid::Known(scope.other_uid)
        } else if matches!(case.kind, Kind::Unknown | Kind::OtherProtocol) {
            SocketUid::Unknown
        } else {
            SocketUid::Known(0)
        };
        if original.creation_uid != expected_uid {
            return Err(Error("socket creation credential not established"));
        }
        let socket = match case.kind {
            Kind::RootDrops => {
                let changed = b.drop_credentials(original, scope.other_uid)?;
                if changed.instance != original.instance
                    || changed.creation_uid != original.creation_uid
                    || changed.fd_instance != original.fd_instance
                    || changed.holder_birth != original.holder_birth
                    || changed.process_uid != scope.other_uid
                {
                    return Err(Error("drop handshake changed or lost original socket"));
                }
                changed
            }
            Kind::RootTransfers => {
                let changed = b.transfer_fd(original, scope.other_uid)?;
                if changed.instance != original.instance
                    || changed.creation_uid != original.creation_uid
                    || changed.fd_instance == original.fd_instance
                    || changed.holder_birth == original.holder_birth
                    || changed.process_uid != scope.other_uid
                {
                    return Err(Error("FD transfer chain not independently established"));
                }
                changed
            }
            _ => original,
        };
        if case.kind == Kind::IndependentRoot
            && socket.holder_birth == self.guard.identity().controller_birth
        {
            return Err(Error("independent root control is same actor"));
        }
        if changing {
            let baseline = self.probe(b, scope, case, socket, 1, true)?;
            if baseline != Outcome::MatchedExpectation {
                return Ok(baseline);
            }
            let profile = match case.kind {
                Kind::Revoke => Profile::Revoked,
                Kind::ChangeUid => Profile::GrantOther,
                Kind::OrdinaryBlock => Profile::BlockTarget,
                _ => Profile::GrantRoot,
            };
            self.install(b, scope, profile)?;
            let convergence = b.converge(socket)?;
            if !convergence.selector_qualified
                || !convergence.old_states_gone
                || !convergence.unrelated_preserved
            {
                return Err(Error(
                    "old-state convergence not qualified; no UID guessing or flush fallback",
                ));
            }
            let outcome = self.probe(b, scope, case, socket, 2, false)?;
            if outcome != Outcome::MatchedExpectation {
                return Ok(outcome);
            }
            // Existing and fresh sockets must both obey the changed policy.
            let fresh = b.open(case)?;
            if fresh.instance == socket.instance
                || fresh.case != case.number
                || fresh.creation_uid != socket.creation_uid
            {
                return Err(Error("fresh socket not independently created"));
            }
            let outcome = self.probe(b, scope, case, fresh, 3, false)?;
            if outcome != Outcome::MatchedExpectation {
                return Ok(outcome);
            }
            b.close_owned(fresh)?;
        } else {
            let allow = matches!(
                case.kind,
                Kind::Root
                    | Kind::IndependentRoot
                    | Kind::RootDrops
                    | Kind::RootTransfers
                    | Kind::UdpConnected
                    | Kind::UdpUnconnected
            );
            let outcome = self.probe(b, scope, case, socket, 1, allow)?;
            if outcome != Outcome::MatchedExpectation {
                return Ok(outcome);
            }
        }
        b.stop_senders()?;
        self.guard.check(b.observe()?)?;
        b.close_owned(socket)?;
        self.install(b, scope, Profile::Empty)?;
        Ok(Outcome::MatchedExpectation)
    }
}

/// Cross-UID execution is disabled. This native path is compiled, not executed in tests.
pub(crate) enum PrivilegePermit {}
/// Change real/effective UID for a FIXED socket test, checking real/effective GID unchanged.
/// Supplementary groups are NOT qualified: macOS nix has no getgroups/setgroups API.
/// This is not full privilege isolation or proof of an unprivileged execution context.
/// A future trusted single-purpose helper must not execute arbitrary code after this step.
pub(crate) fn change_uid_native(_: &PrivilegePermit, uid: u32) -> Result<()> {
    use nix::unistd::{Uid, getegid, geteuid, getgid, getuid, setuid};
    if uid == 0 || !geteuid().is_root() {
        return Err(Error(
            "controlled non-root target and privileged helper required",
        ));
    }
    let groups = (getgid(), getegid());
    setuid(Uid::from_raw(uid)).map_err(|_| Error("UID drop failed"))?;
    if getuid().as_raw() != uid || geteuid().as_raw() != uid || (getgid(), getegid()) != groups {
        return Err(Error("UID/group transition not independently observed"));
    }
    Ok(())
}

/// One datagram + exactly one owned FD. Uses the safe OwnedFd ancillary API; no project unsafe.
pub(crate) fn send_fd(
    socket: &std::os::unix::net::UnixDatagram,
    fd: std::os::fd::BorrowedFd<'_>,
    nonce: [u8; 16],
) -> Result<()> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags, sendmsg};
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    let fds = [fd];
    if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
        return Err(Error("FD send control buffer"));
    }
    let count = sendmsg(
        socket,
        &[std::io::IoSlice::new(&nonce)],
        &mut control,
        SendFlags::DONTWAIT,
    )
    .map_err(|_| Error("FD handoff send unknown"))?;
    if count != 16 {
        return Err(Error("partial handoff datagram"));
    }
    Ok(())
}
pub(crate) fn receive_fd(
    socket: &std::os::unix::net::UnixDatagram,
    nonce: [u8; 16],
) -> Result<std::os::fd::OwnedFd> {
    use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let mut bytes = [0; 17];
    let reply = recvmsg(
        socket,
        &mut [std::io::IoSliceMut::new(&mut bytes)],
        &mut control,
        RecvFlags::DONTWAIT,
    )
    .map_err(|_| Error("FD handoff receive unavailable"))?;
    let mut fds = Vec::new();
    for item in control.drain() {
        match item {
            RecvAncillaryMessage::ScmRights(received) => fds.extend(received),
            _ => return Err(Error("unexpected ancillary record")),
        }
    }
    if reply
        .flags
        .intersects(ReturnFlags::CTRUNC | ReturnFlags::TRUNC)
        || reply.bytes != 16
        || bytes[..16] != nonce
        || fds.len() != 1
    {
        return Err(Error("truncated, replayed or ambiguous FD handoff"));
    }
    let fd = fds.pop().ok_or(Error("FD missing"))?;
    // macOS lacks atomic MSG_CMSG_CLOEXEC. The future helper must serialize handoff against
    // exec/spawn. Return only a CLOEXEC duplicate; dropping the received OwnedFd closes it.
    rustix::io::fcntl_dupfd_cloexec(&fd, 3).map_err(|_| Error("CLOEXEC handoff duplication failed"))
}
