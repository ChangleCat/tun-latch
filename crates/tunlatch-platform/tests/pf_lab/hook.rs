//! Closed offline hook/filter lifecycle. The only adapter supplied is an in-memory test double.
//! No live command, PF device, root reload, flush, enable-reference or state deletion exists.
//! Operation return values and repeated reads DO NOT establish ownership against foreign root.

use super::preflight::{Anchor, CheckedBoundary};
use thiserror::Error;

/// Fixed synthetic filter payload; never imported PF text or arbitrary command arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Filter {
    Empty,
    BlockProbe,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Window {
    pub(crate) boot: [u8; 32],
    pub(crate) session: [u8; 32],
    pub(crate) controller_birth: u64,
    pub(crate) lock_device: u64,
    pub(crate) lock_inode: u64,
    pub(crate) deployment_generation: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Object {
    pub(crate) instance: u64,
    pub(crate) session: [u8; 32],
    pub(crate) anchor: Anchor,
    pub(crate) filter: Filter,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Scene {
    pub(crate) window: Window,
    pub(crate) exclusive_controller: Option<u64>,
    pub(crate) all_writers_reclaimed: bool,
    pub(crate) foreign_boundary: [u8; 32],
    pub(crate) hook: Option<Object>,
    pub(crate) leaf: Option<Object>,
    pub(crate) now_ms: u64,
    pub(crate) sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Admitted,
    HookIntent,
    HookObserved,
    FilterIntent,
    Active,
    Stopping,
    ClearIntent,
    RemoveIntent,
    Closed,
    Unknown,
}
#[derive(Debug, Error, Eq, PartialEq)]
pub(crate) enum Error {
    #[error("offline hook protocol refuses: {0}")]
    Refused(&'static str),
    #[error("operation result unknown; retain scene for administrator takeover")]
    Unknown,
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

/// Native candidates are safe public add_anchor/filter transaction/remove_anchor APIs, under
/// the accepted continuous exclusive window. Their actual instance/selector precision remains
/// unqualified. This trait is NOT implemented for a system library or a subprocess executor.
pub(crate) trait Boundary {
    fn observe(&mut self) -> Result<Scene>;
    fn persist(&mut self, phase: Phase) -> Result<()>;
    fn insert_own_hook(&mut self, anchor: &Anchor, session: [u8; 32]) -> Result<Object>;
    fn replace_own_filter(&mut self, hook: &Object, filter: Filter) -> Result<Object>;
    fn remove_own_hook(&mut self, hook: &Object) -> Result<()>;
}

/// Retains the baseline and exact created objects. Not serializable or importable from a receipt.
pub(crate) struct Session {
    checked: CheckedBoundary,
    window: Window,
    sequence: u64,
    observed_ms: u64,
    phase: Phase,
    hook: Option<Object>,
    leaf: Option<Object>,
}
impl Session {
    pub(crate) fn admit(
        checked: CheckedBoundary,
        window: Window,
        boundary: &mut impl Boundary,
    ) -> Result<Self> {
        if window.boot != checked.boot
            || window.session == [0; 32]
            || window.controller_birth == 0
            || window.lock_inode == 0
            || window.deployment_generation == 0
            || !checked.empty_owned_leaf()
        {
            return Err(Error::Refused("missing session or deployment identity"));
        }
        let observed_ms = checked.observed_ms;
        let mut session = Self {
            checked,
            window,
            sequence: 0,
            observed_ms,
            phase: Phase::Admitted,
            hook: None,
            leaf: None,
        };
        session.check(boundary)?;
        boundary.persist(Phase::Admitted)?;
        Ok(session)
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    fn check(&mut self, boundary: &mut impl Boundary) -> Result<()> {
        let scene = boundary.observe()?;
        if scene.window != self.window
            || scene.exclusive_controller != Some(self.window.controller_birth)
            || !scene.all_writers_reclaimed
            || scene.foreign_boundary != self.checked.fingerprint()
            || scene.sequence <= self.sequence
            || scene.now_ms < self.observed_ms
            || scene.now_ms.saturating_sub(self.checked.observed_ms) > 2000
            || scene.hook != self.hook
            || scene.leaf != self.leaf
        {
            return Err(Error::Refused(
                "ownership, completeness, freshness or exclusivity lost",
            ));
        }
        self.sequence = scene.sequence;
        self.observed_ms = scene.now_ms;
        Ok(())
    }
    fn record(&mut self, boundary: &mut impl Boundary, phase: Phase) -> Result<()> {
        boundary.persist(phase)?;
        self.phase = phase;
        Ok(())
    }
    fn object(&self, object: &Object, filter: Filter) -> Result<()> {
        if object.instance == 0
            || object.session != self.window.session
            || object.anchor != *self.checked.own()
            || object.filter != filter
        {
            return Err(Error::Refused("unrecognized creation result"));
        }
        Ok(())
    }
    /// Failure leaves Unknown, retains all known object records, and never guesses rollback.
    pub(crate) fn load(&mut self, boundary: &mut impl Boundary) -> Result<()> {
        if self.phase != Phase::Admitted {
            return Err(Error::Refused("load not admissible"));
        }
        let outcome = self.load_inner(boundary);
        if outcome.is_err() {
            self.phase = Phase::Unknown;
            return Err(Error::Unknown);
        }
        Ok(())
    }
    fn load_inner(&mut self, boundary: &mut impl Boundary) -> Result<()> {
        self.check(boundary)?;
        self.record(boundary, Phase::HookIntent)?;
        let hook = boundary.insert_own_hook(self.checked.own(), self.window.session)?;
        self.object(&hook, Filter::Empty)?;
        self.hook = Some(hook.clone());
        self.check(boundary)?;
        self.record(boundary, Phase::HookObserved)?;
        self.record(boundary, Phase::FilterIntent)?;
        let leaf = boundary.replace_own_filter(&hook, Filter::BlockProbe)?;
        self.object(&leaf, Filter::BlockProbe)?;
        self.leaf = Some(leaf);
        self.check(boundary)?;
        self.record(boundary, Phase::Active)
    }
    /// Recovery is explicit, not Drop. Unknown sessions cannot be adopted by a new controller.
    pub(crate) fn recover(&mut self, boundary: &mut impl Boundary) -> Result<()> {
        if self.phase != Phase::Active {
            return Err(Error::Refused("recovery requires known active ownership"));
        }
        let outcome = self.recover_inner(boundary);
        if outcome.is_err() {
            self.phase = Phase::Unknown;
            return Err(Error::Unknown);
        }
        Ok(())
    }
    fn recover_inner(&mut self, boundary: &mut impl Boundary) -> Result<()> {
        self.record(boundary, Phase::Stopping)?;
        self.check(boundary)?; // includes cancellation/reaping and continuous lock/controller checks
        self.record(boundary, Phase::ClearIntent)?;
        let hook = self.hook.clone().ok_or(Error::Unknown)?;
        let leaf = boundary.replace_own_filter(&hook, Filter::Empty)?;
        self.object(&leaf, Filter::Empty)?;
        self.leaf = Some(leaf);
        self.check(boundary)?;
        self.record(boundary, Phase::RemoveIntent)?;
        boundary.remove_own_hook(&hook)?;
        self.hook = None;
        self.leaf = None;
        self.check(boundary)?;
        self.record(boundary, Phase::Closed)
    }
}
