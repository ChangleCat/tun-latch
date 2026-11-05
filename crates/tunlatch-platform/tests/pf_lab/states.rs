//! Selector impact/counterexample driver. Study results never mint a product deletion capability.
//! Kernel states expose no socket UID through the audited public library. No UID/PID guesswork.
use super::driver::{Error, Guard, Observation, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct State {
    pub(crate) id: u128,
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    pub(crate) protocol: Protocol,
    pub(crate) interface: String,
    pub(crate) translated: bool,
}
#[derive(Clone, Debug)]
pub(crate) enum Selector {
    /// Audited pfctl 0.7.0 kill_state leaves address masks/port operations zero. This explicitly
    /// models its broad risk; it is not relabeled as an exact tuple or unique-ID selector.
    LibraryFamilyProtocolInterface {
        ipv6: bool,
        protocol: Protocol,
        interface: String,
    },
    HostPair {
        source: IpAddr,
        destination: IpAddr,
    },
}
impl Selector {
    pub(crate) fn matches(&self, state: &State) -> bool {
        match self {
            Self::LibraryFamilyProtocolInterface {
                ipv6,
                protocol,
                interface,
            } => {
                state.source.is_ipv6() == *ipv6
                    && state.protocol == *protocol
                    && state.interface == *interface
            }
            Self::HostPair {
                source,
                destination,
            } => state.source.ip() == *source && state.destination.ip() == *destination,
        }
    }
    pub(crate) fn host_pair(source: IpAddr, destination: IpAddr) -> Result<Self> {
        if source.is_ipv6() != destination.is_ipv6()
            || source.is_unspecified()
            || destination.is_unspecified()
            || source.is_multicast()
            || destination.is_multicast()
        {
            return Err(Error("invalid state selector host pair"));
        }
        Ok(Self::HostPair {
            source,
            destination,
        })
    }
    pub(crate) fn command_candidate(&self) -> Result<Vec<String>> {
        match self {
            Self::HostPair {
                source,
                destination,
            } => Ok(vec![
                "-k".into(),
                source.to_string(),
                "-k".into(),
                destination.to_string(),
            ]),
            Self::LibraryFamilyProtocolInterface { .. } => {
                Err(Error("unsafe library selector has no approved command"))
            }
        }
    }
}
pub(crate) fn uid_selector(_: u32) -> Result<Selector> {
    Err(Error("no audited exact socket-UID state selector"))
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Change {
    ExistingBeforeEnable,
    RevokeUid,
    ReplaceUid,
    RevokeTarget,
    AllowToBlock,
}
pub(crate) fn required_changes() -> [Change; 5] {
    [
        Change::ExistingBeforeEnable,
        Change::RevokeUid,
        Change::ReplaceUid,
        Change::RevokeTarget,
        Change::AllowToBlock,
    ]
}
pub(crate) struct Snapshot {
    pub(crate) observation: Observation,
    pub(crate) states: Vec<State>,
}
pub(crate) trait Boundary {
    fn snapshot(&mut self) -> Result<Snapshot>;
    /// Only an explicitly approved controlled experiment may call this. No global fallback.
    fn exercise_selector(&mut self, selector: &Selector) -> Result<usize>;
}
fn inventory(states: Vec<State>) -> Result<BTreeMap<u128, State>> {
    if states.len() > 256 {
        return Err(Error("state enumeration limit"));
    }
    let mut result = BTreeMap::new();
    for state in states {
        if state.id == 0
            || state.source.is_ipv6() != state.destination.is_ipv6()
            || state.source.port() == 0
            || state.destination.port() == 0
            || state.interface.is_empty()
            || state.interface.len() > 15
            || state.translated
            || result.insert(state.id, state).is_some()
        {
            return Err(Error("ambiguous, translated or incomplete state inventory"));
        }
    }
    Ok(result)
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Study {
    pub(crate) session: [u8; 32],
    pub(crate) removed: BTreeSet<u128>,
    pub(crate) collateral: BTreeSet<u128>,
    pub(crate) missed: BTreeSet<u128>,
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
    pub(crate) fn run(
        &mut self,
        b: &mut impl Boundary,
        selector: Selector,
        targets: BTreeSet<u128>,
        approved_impact: BTreeSet<u128>,
    ) -> Result<Study> {
        if self.consumed {
            return Err(Error("state experiment not repeatable"));
        }
        self.consumed = true;
        let result = self.inner(b, selector, targets, approved_impact);
        if result.is_err() {
            self.unknown = true;
        }
        result
    }
    fn inner(
        &mut self,
        b: &mut impl Boundary,
        selector: Selector,
        targets: BTreeSet<u128>,
        approved_impact: BTreeSet<u128>,
    ) -> Result<Study> {
        if targets.is_empty() || targets.len() > 16 || approved_impact.len() > 32 {
            return Err(Error("invalid controlled state impact bounds"));
        }
        let before = b.snapshot()?;
        self.guard.check(before.observation)?;
        let before = inventory(before.states)?;
        if !targets.iter().all(|id| before.contains_key(id)) {
            return Err(Error("target state missing"));
        }
        let affected: BTreeSet<_> = before
            .values()
            .filter(|state| selector.matches(state))
            .map(|s| s.id)
            .collect();
        if affected.is_empty() || affected != approved_impact {
            return Err(Error("selector reaches beyond explicit experiment impact"));
        }
        let count = b.exercise_selector(&selector)?;
        let after = b.snapshot()?;
        self.guard.check(after.observation)?;
        let after = inventory(after.states)?;
        let expected: BTreeMap<_, _> = before
            .into_iter()
            .filter(|(id, _)| !affected.contains(id))
            .collect();
        if count != affected.len() || after != expected {
            return Err(Error(
                "state effect or unrelated control not independently confirmed",
            ));
        }
        Ok(Study {
            session: self.guard.identity().session,
            collateral: affected.difference(&targets).copied().collect(),
            missed: targets.difference(&affected).copied().collect(),
            removed: affected,
        })
    }
}
