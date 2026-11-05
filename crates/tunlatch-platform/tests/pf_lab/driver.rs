//! Shared offline-driver bounds. Observations come from trusted test adapters, never client DTOs.
//! These checks do not authenticate an administrator or create a live execution capability.
use thiserror::Error;

#[derive(Debug, Error, Clone, Eq, PartialEq)]
#[error("experiment refused or result unknown: {0}")]
pub(crate) struct Error(pub(crate) &'static str);
pub(crate) type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub(crate) boot: [u8; 32],
    pub(crate) session: [u8; 32],
    pub(crate) plan: [u8; 32],
    pub(crate) controller_birth: u64,
    pub(crate) lock_inode: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Observation {
    pub(crate) identity: Identity,
    pub(crate) sequence: u64,
    pub(crate) at_ms: u64,
    pub(crate) complete: bool,
    pub(crate) exclusive: bool,
    pub(crate) writers_reclaimed: bool,
}
pub(crate) struct Guard {
    identity: Identity,
    sequence: u64,
    now_ms: u64,
    deadline: u64,
    operations: u16,
}
impl Guard {
    pub(crate) fn new(identity: Identity, now_ms: u64) -> Result<Self> {
        if nix::unistd::geteuid().is_root()
            || identity.boot == [0; 32]
            || identity.session == [0; 32]
            || identity.plan == [0; 32]
            || identity.controller_birth == 0
            || identity.lock_inode == 0
        {
            return Err(Error("missing ordinary-user session identity"));
        }
        Ok(Self {
            identity,
            sequence: 0,
            now_ms,
            deadline: now_ms.checked_add(10_000).ok_or(Error("time overflow"))?,
            operations: 0,
        })
    }
    pub(crate) fn check(&mut self, observation: Observation) -> Result<()> {
        if observation.identity != self.identity
            || !observation.complete
            || !observation.exclusive
            || !observation.writers_reclaimed
            || observation.sequence <= self.sequence
            || observation.at_ms < self.now_ms
            || observation.at_ms > self.deadline
            || self.operations >= 128
        {
            return Err(Error("stale, incomplete, unowned or exhausted experiment"));
        }
        self.operations += 1;
        self.sequence = observation.sequence;
        self.now_ms = observation.at_ms;
        Ok(())
    }
    pub(crate) fn identity(&self) -> Identity {
        self.identity
    }
}
