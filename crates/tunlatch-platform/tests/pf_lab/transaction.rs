//! Closed transaction experiment with honest opaque-vs-instrumented stage evidence.
//! Real-tool cancellation cannot identify an internal kernel phase or imply rollback.
use super::driver::{Error, Guard, Observation, Result};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Payload {
    Empty,
    BlockProbe,
}
impl Payload {
    pub(crate) fn bytes(self) -> &'static [u8] {
        match self {
            Self::Empty => b"",
            Self::BlockProbe => b"block drop out quick all label \"tunlatch-lab:probe\"\n",
        }
    }
    pub(crate) fn digest(self) -> [u8; 32] {
        Sha256::digest(self.bytes()).into()
    }
}
pub(crate) fn command_candidate() -> [&'static str; 4] {
    ["-a", "tunlatch-lab/session", "-f", "-"]
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Surface {
    OpaqueSubmit,
    InstrumentedDouble,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Fault {
    None,
    BeforeSubmit,
    AfterBegin,
    AfterStage,
    BeforeCommit,
    CancelDuringSubmit,
    AfterReply,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Admitted,
    BeginIntent,
    Staged,
    CommitIntent,
    Observed,
    RestoreIntent,
    Restored,
    Rejected,
    Unknown,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Image {
    pub(crate) payload: Payload,
    pub(crate) foreign_digest: [u8; 32],
    pub(crate) generation: u64,
}
pub(crate) struct Snapshot {
    pub(crate) observation: Observation,
    pub(crate) image: Image,
}
pub(crate) struct Reply {
    pub(crate) success: bool,
    pub(crate) all_writers_reclaimed: bool,
}
pub(crate) trait Boundary {
    fn surface(&self) -> Surface;
    fn snapshot(&mut self) -> Result<Snapshot>;
    fn persist(&mut self, phase: Phase) -> Result<()>;
    fn begin(&mut self) -> Result<u64>;
    fn stage(&mut self, ticket: u64, payload: Payload) -> Result<()>;
    fn commit(&mut self, ticket: u64) -> Result<Reply>;
    /// Opaque maps to ONE fixed public set_rules/commit or fixed pfctl operation. No forged
    /// begin/stage callbacks are emitted for a backend that cannot observe those boundaries.
    fn submit(&mut self, payload: Payload, cancel_waiter: bool) -> Result<Reply>;
}
pub(crate) struct Transaction {
    guard: Guard,
    phase: Phase,
    baseline: Option<Image>,
    current: Option<Image>,
    consumed: bool,
}
impl Transaction {
    pub(crate) fn new(guard: Guard) -> Self {
        Self {
            guard,
            phase: Phase::Admitted,
            baseline: None,
            current: None,
            consumed: false,
        }
    }
    pub(crate) fn phase(&self) -> Phase {
        self.phase
    }
    fn record(&mut self, b: &mut impl Boundary, phase: Phase) -> Result<()> {
        b.persist(phase)?;
        self.phase = phase;
        Ok(())
    }
    fn observe(&mut self, b: &mut impl Boundary) -> Result<Image> {
        let snap = b.snapshot()?;
        self.guard.check(snap.observation)?;
        if snap.image.generation == 0 || snap.image.foreign_digest == [0; 32] {
            return Err(Error("incomplete filter image"));
        }
        Ok(snap.image)
    }
    pub(crate) fn run(&mut self, b: &mut impl Boundary, new: Payload, fault: Fault) -> Result<()> {
        if self.consumed {
            return Err(Error("transaction experiment is one-shot"));
        }
        self.consumed = true;
        if b.surface() == Surface::OpaqueSubmit
            && matches!(
                fault,
                Fault::AfterBegin | Fault::AfterStage | Fault::BeforeCommit
            )
        {
            self.phase = Phase::Rejected;
            return Err(Error("opaque backend cannot prove internal fault phase"));
        }
        let result = self.inner(b, new, fault);
        if result.is_err() && self.phase != Phase::Rejected {
            self.phase = Phase::Unknown;
        }
        result
    }
    fn inner(&mut self, b: &mut impl Boundary, new: Payload, fault: Fault) -> Result<()> {
        let old = self.observe(b)?;
        self.baseline = Some(old);
        self.record(b, Phase::Admitted)?;
        if fault == Fault::BeforeSubmit {
            self.record(b, Phase::Rejected)?;
            return Err(Error("injected failure before any submission"));
        }
        let reply = match b.surface() {
            Surface::InstrumentedDouble => {
                self.record(b, Phase::BeginIntent)?;
                let ticket = b.begin()?;
                if ticket == 0 || fault == Fault::AfterBegin {
                    return Err(Error("injected/unknown begin result"));
                }
                b.stage(ticket, new)?;
                self.record(b, Phase::Staged)?;
                if fault == Fault::AfterStage {
                    return Err(Error("injected after staging"));
                }
                self.record(b, Phase::CommitIntent)?;
                if fault == Fault::BeforeCommit {
                    return Err(Error("injected before commit"));
                }
                let mut reply = b.commit(ticket)?;
                if fault == Fault::CancelDuringSubmit {
                    reply.all_writers_reclaimed = false;
                }
                reply
            }
            Surface::OpaqueSubmit => {
                self.record(b, Phase::CommitIntent)?;
                b.submit(new, fault == Fault::CancelDuringSubmit)?
            }
        };
        if !reply.success || !reply.all_writers_reclaimed || fault == Fault::AfterReply {
            return Err(Error(
                "submission not independently reclaimed or reply interrupted",
            ));
        }
        let after = self.observe(b)?;
        if after.payload != new
            || after.foreign_digest != old.foreign_digest
            || after.generation <= old.generation
        {
            return Err(Error("submitted filter or foreign control differs"));
        }
        self.current = Some(after);
        self.record(b, Phase::Observed)
    }
    pub(crate) fn restore(&mut self, b: &mut impl Boundary) -> Result<()> {
        if self.phase != Phase::Observed {
            return Err(Error("unknown transaction cannot automatically restore"));
        }
        let result = (|| {
            let current = self.current.ok_or(Error("current image missing"))?;
            if self.observe(b)? != current {
                return Err(Error("active filter changed before restoration"));
            }
            let old = self.baseline.ok_or(Error("baseline missing"))?;
            self.record(b, Phase::RestoreIntent)?;
            let reply = b.submit(old.payload, false)?;
            if !reply.success || !reply.all_writers_reclaimed {
                return Err(Error("restore result unknown"));
            }
            let restored = self.observe(b)?;
            if restored.payload != old.payload
                || restored.foreign_digest != old.foreign_digest
                || restored.generation <= current.generation
            {
                return Err(Error("restoration not independently observed"));
            }
            self.record(b, Phase::Restored)
        })();
        if result.is_err() {
            self.phase = Phase::Unknown;
        }
        result
    }
    pub(crate) fn session(&self) -> [u8; 32] {
        self.guard.identity().session
    }
}
