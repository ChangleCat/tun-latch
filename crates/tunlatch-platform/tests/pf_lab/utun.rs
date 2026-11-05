//! Owned-handle reuse experiment, not a TUN trust mechanism. Native creation is capability-
//! gated and never invoked by tests. Only the project's fixed worker has a pause/resume protocol.
use super::driver::{Error, Guard, Observation, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Slot(u16);
impl Slot {
    pub(crate) fn new(value: u32) -> Result<Self> {
        if value > 65534 {
            return Err(Error("utun slot out of review bounds"));
        }
        Ok(Self(value as u16))
    }
    pub(crate) fn name(self) -> String {
        format!("utun{}", self.0)
    }
}
/// No live authority is currently constructible. A future trusted administrator bootstrap must
/// supply a separately reviewed capability, not a flag or a deserialized client boolean.
pub(crate) enum LivePermit {}
pub(crate) fn native_builder(slot: Slot) -> tun_rs::DeviceBuilder {
    tun_rs::DeviceBuilder::new()
        .name(slot.name())
        .layer(tun_rs::Layer::L3)
        .associate_route(false)
        .enable(false)
        .packet_information(true)
}
pub(crate) fn create_native(_: &LivePermit, slot: Slot) -> std::io::Result<tun_rs::SyncDevice> {
    let device = native_builder(slot).build_sync()?;
    device.set_nonblocking(true)?;
    Ok(device)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Instance {
    pub(crate) slot: Slot,
    pub(crate) if_index: u32,
    pub(crate) allocation: u64,
    pub(crate) holder_birth: u64,
    pub(crate) fd_instance: u64,
    pub(crate) session: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PauseAck {
    pub(crate) worker_birth: u64,
    pub(crate) request: u64,
    pub(crate) queue_closed: bool,
    pub(crate) all_writers_reclaimed: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Connection {
    New,
    Existing,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) nonce: [u8; 16],
    pub(crate) entered: Option<Instance>,
    pub(crate) capture_complete: bool,
}
pub(crate) trait Boundary {
    fn observe(&mut self) -> Result<Observation>;
    fn create_owned(&mut self, slot: Slot) -> Result<Instance>;
    fn close_owned(&mut self, instance: Instance) -> Result<()>;
    fn pause_own_worker(&mut self, request: u64) -> Result<PauseAck>;
    fn resume_own_worker(&mut self, ack: PauseAck) -> Result<()>;
    fn probe(&mut self, nonce: [u8; 16], connection: Connection) -> Result<Entry>;
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct Witness {
    pub(crate) old: Instance,
    pub(crate) replacement: Instance,
    pub(crate) new_connection_leaked: bool,
    pub(crate) existing_connection_leaked: bool,
}
pub(crate) struct Reuse {
    guard: Guard,
    quarantined: bool,
    consumed: bool,
}
impl Reuse {
    pub(crate) fn new(guard: Guard) -> Self {
        Self {
            guard,
            quarantined: false,
            consumed: false,
        }
    }
    pub(crate) fn quarantined(&self) -> bool {
        self.quarantined
    }
    pub(crate) fn run(&mut self, b: &mut impl Boundary, slot: Slot) -> Result<Witness> {
        if self.consumed {
            return Err(Error("reuse experiment is one-shot"));
        }
        self.consumed = true;
        let outcome = self.inner(b, slot);
        if outcome.is_err() {
            self.quarantined = true;
        }
        outcome
    }
    fn check_instance(&self, i: Instance, slot: Slot) -> Result<()> {
        if i.slot != slot
            || i.if_index == 0
            || i.allocation == 0
            || i.holder_birth == 0
            || i.fd_instance == 0
            || i.session != self.guard.identity().session
        {
            return Err(Error("unrecognized owned FD/holder instance"));
        }
        Ok(())
    }
    fn inner(&mut self, b: &mut impl Boundary, slot: Slot) -> Result<Witness> {
        self.guard.check(b.observe()?)?;
        let old = b.create_owned(slot)?;
        self.check_instance(old, slot)?;
        let positive = b.probe([1; 16], Connection::Existing)?;
        if positive.nonce != [1; 16] || !positive.capture_complete || positive.entered != Some(old)
        {
            return Err(Error("missing positive TUN capture control"));
        }
        let ack = b.pause_own_worker(1)?;
        if ack.worker_birth != self.guard.identity().controller_birth
            || ack.request != 1
            || !ack.queue_closed
            || !ack.all_writers_reclaimed
        {
            return Err(Error("worker pause not acknowledged and reclaimed"));
        }
        self.guard.check(b.observe()?)?;
        b.close_owned(old)?;
        let replacement = b.create_owned(slot)?;
        self.check_instance(replacement, slot)?;
        if replacement.allocation == old.allocation
            || replacement.fd_instance == old.fd_instance
            || replacement.holder_birth == old.holder_birth
        {
            return Err(Error(
                "new interface identity not independently established",
            ));
        }
        self.guard.check(b.observe()?)?;
        let mut leaked = [false; 2];
        for (index, connection) in [Connection::New, Connection::Existing]
            .into_iter()
            .enumerate()
        {
            let nonce = [index as u8 + 2; 16];
            let entry = b.probe(nonce, connection)?;
            if entry.nonce != nonce
                || !entry.capture_complete
                || entry.entered.is_some_and(|i| i != replacement)
            {
                return Err(Error("unrelated or incomplete TUN capture"));
            }
            leaked[index] = entry.entered == Some(replacement);
        }
        self.guard.check(b.observe()?)?;
        b.close_owned(replacement)?;
        b.resume_own_worker(ack)?;
        self.guard.check(b.observe()?)?;
        Ok(Witness {
            old,
            replacement,
            new_connection_leaked: leaked[0],
            existing_connection_leaked: leaked[1],
        })
    }
}

/// Packet-information family is network byte order. Validate the declared IP header/frame
/// length; this framing check alone is not transport/checksum/capture qualification.
pub(crate) fn decode_frame(frame: &[u8]) -> Result<&[u8]> {
    if frame.len() < 5 || frame.len() > 65539 {
        return Err(Error("invalid utun frame length"));
    }
    let family = u32::from_be_bytes(frame[..4].try_into().map_err(|_| Error("missing family"))?);
    if !matches!((family, frame[4] >> 4), (2, 4) | (30, 6)) {
        return Err(Error("utun family/header mismatch"));
    }
    let packet = &frame[4..];
    let complete = match family {
        2 => {
            packet.len() >= 20
                && usize::from(packet[0] & 15) * 4 >= 20
                && usize::from(packet[0] & 15) * 4 <= packet.len()
                && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        }
        30 => {
            packet.len() >= 40
                && 40 + usize::from(u16::from_be_bytes([packet[4], packet[5]])) == packet.len()
        }
        _ => false,
    };
    if !complete {
        return Err(Error("IP header or declared utun frame is truncated"));
    }
    Ok(&frame[4..])
}
