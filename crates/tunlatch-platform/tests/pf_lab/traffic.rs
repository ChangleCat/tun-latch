//! Controlled native probe candidates and strict offline pcap/positive-control adjudication.
//! No packet capture or network probe is executed by the ordinary test suite.
use super::driver::{Error, Guard, Observation, Result};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Application {
    Probe,
    Dns,
    Quic,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Flow {
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
    pub(crate) protocol: Protocol,
}
impl Flow {
    fn validate(self) -> Result<()> {
        if self.source.is_ipv6() != self.destination.is_ipv6()
            || self.source.port() == 0
            || self.destination.port() == 0
            || self.source.ip().is_unspecified()
            || self.destination.ip().is_unspecified()
            || self.source.ip().is_multicast()
            || self.destination.ip().is_multicast()
            || [self.source, self.destination].iter().any(|address| {
                matches!(address, SocketAddr::V6(v6) if v6.scope_id() != 0 || v6.flowinfo() != 0)
            })
            || self.source == self.destination
        {
            return Err(Error("invalid controlled flow"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub(crate) case_id: u32,
    pub(crate) interface: String,
    pub(crate) before_control: Flow,
    pub(crate) negative: Flow,
    pub(crate) after_control: Flow,
    pub(crate) application: Application,
}
impl Plan {
    pub(crate) fn validate(&self) -> Result<()> {
        self.negative.validate()?;
        for control in [self.before_control, self.after_control] {
            control.validate()?;
            if control == self.negative
                || control.protocol != self.negative.protocol
                || control.source.ip() != self.negative.source.ip()
                || control.destination != self.negative.destination
            {
                return Err(Error(
                    "positive control does not qualify the negative probe",
                ));
            }
        }
        if self.case_id == 0
            || self.before_control == self.after_control
            || self.interface.is_empty()
            || self.interface.len() > 15
            || !self.interface.bytes().all(|b| b.is_ascii_alphanumeric())
        {
            return Err(Error("ambiguous capture scope"));
        }
        Ok(())
    }
    pub(crate) fn capture_argv(&self) -> Result<Vec<String>> {
        self.validate()?;
        let expression = |f: Flow| {
            format!(
                "(src host {} and dst host {} and src port {} and dst port {} and {})",
                f.source.ip(),
                f.destination.ip(),
                f.source.port(),
                f.destination.port(),
                match f.protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                }
            )
        };
        Ok(vec![
            "-i".into(),
            self.interface.clone(),
            "-n".into(),
            "-U".into(),
            "-s".into(),
            "65535".into(),
            "-c".into(),
            "128".into(),
            "-w".into(),
            "-".into(),
            format!(
                "{} or {} or {}",
                expression(self.before_control),
                expression(self.negative),
                expression(self.after_control)
            ),
        ])
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Packet {
    pub(crate) flow: Flow,
    pub(crate) at_us: u64,
    pub(crate) payload: Vec<u8>,
}
fn u16be(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}
fn ip_packet(raw: &[u8], at_us: u64) -> Result<Packet> {
    let first = *raw.first().ok_or(Error("empty network packet"))?;
    let (source, destination, protocol, transport) = match first >> 4 {
        4 => {
            if raw.len() < 20 {
                return Err(Error("short IPv4 header"));
            }
            let header = usize::from(first & 15) * 4;
            let length = usize::from(u16be(&raw[2..4]));
            if header < 20
                || header > raw.len()
                || length < header
                || length > raw.len()
                || u16be(&raw[6..8]) & 0x3fff != 0
            {
                return Err(Error("truncated/fragmented IPv4 packet"));
            }
            let mut sum = 0_u32;
            for word in raw[..header].as_chunks::<2>().0 {
                sum += u32::from(u16be(word));
            }
            while sum > 0xffff {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            if sum != 0xffff {
                return Err(Error("IPv4 header checksum invalid"));
            }
            (
                std::net::IpAddr::V4([raw[12], raw[13], raw[14], raw[15]].into()),
                std::net::IpAddr::V4([raw[16], raw[17], raw[18], raw[19]].into()),
                raw[9],
                &raw[header..length],
            )
        }
        6 => {
            if raw.len() < 40 {
                return Err(Error("short IPv6 header"));
            }
            let length = usize::from(u16be(&raw[4..6]));
            if length == 0 || 40 + length > raw.len() {
                return Err(Error("truncated IPv6 or unsupported jumbo payload"));
            }
            let source = <[u8; 16]>::try_from(&raw[8..24]).map_err(|_| Error("source IPv6"))?;
            let destination =
                <[u8; 16]>::try_from(&raw[24..40]).map_err(|_| Error("destination IPv6"))?;
            (
                std::net::IpAddr::V6(source.into()),
                std::net::IpAddr::V6(destination.into()),
                raw[6],
                &raw[40..40 + length],
            )
        }
        _ => return Err(Error("unsupported network layer")),
    };
    let (protocol, payload) = match protocol {
        6 => {
            if transport.len() < 20 {
                return Err(Error("short TCP packet"));
            }
            let header = usize::from(transport[12] >> 4) * 4;
            if header < 20 || header > transport.len() {
                return Err(Error("invalid TCP data offset"));
            }
            (Protocol::Tcp, &transport[header..])
        }
        17 => {
            if transport.len() < 8 || usize::from(u16be(&transport[4..6])) != transport.len() {
                return Err(Error("invalid UDP length"));
            }
            (Protocol::Udp, &transport[8..])
        }
        _ => return Err(Error("unsupported extension, fragment or transport")),
    };
    let flow = Flow {
        source: SocketAddr::new(source, u16be(transport)),
        destination: SocketAddr::new(destination, u16be(&transport[2..4])),
        protocol,
    };
    flow.validate()?;
    Ok(Packet {
        flow,
        at_us,
        payload: payload.to_vec(),
    })
}
/// Classic pcap 2.4, microseconds, LINKTYPE_ETHERNET(1), NULL(0), RAW(101). Unknown link,
/// nanosecond captures, fragments/extensions and truncated frames invalidate the verdict.
pub(crate) fn parse_pcap(bytes: &[u8]) -> Result<Vec<Packet>> {
    if bytes.len() < 24 || bytes.len() > 1024 * 1024 {
        return Err(Error("pcap byte budget/header"));
    }
    let little = match &bytes[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] => false,
        _ => return Err(Error("unsupported pcap format")),
    };
    let number = |b: &[u8]| -> u32 {
        let v = [b[0], b[1], b[2], b[3]];
        if little {
            u32::from_le_bytes(v)
        } else {
            u32::from_be_bytes(v)
        }
    };
    let short = |b: &[u8]| -> u16 {
        if little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16be(b)
        }
    };
    let snaplen = number(&bytes[16..20]);
    let link = number(&bytes[20..24]);
    if short(&bytes[4..6]) != 2
        || short(&bytes[6..8]) != 4
        || !(64..=65535).contains(&snaplen)
        || !matches!(link, 0 | 1 | 101)
    {
        return Err(Error("unqualified pcap header"));
    }
    let mut offset = 24;
    let mut packets = Vec::new();
    let mut previous = 0;
    while offset < bytes.len() {
        if packets.len() >= 512 || bytes.len() - offset < 16 {
            return Err(Error("excessive or partial pcap records"));
        }
        let header = &bytes[offset..offset + 16];
        let sec = number(header);
        let micros = number(&header[4..8]);
        let incl = number(&header[8..12]);
        let original = number(&header[12..16]);
        if micros >= 1_000_000 || incl == 0 || incl > snaplen || incl != original {
            return Err(Error("dropped/truncated pcap frame"));
        }
        offset += 16;
        let end = offset
            .checked_add(incl as usize)
            .ok_or(Error("pcap size overflow"))?;
        let frame = bytes.get(offset..end).ok_or(Error("partial pcap frame"))?;
        offset = end;
        let at_us = u64::from(sec) * 1_000_000 + u64::from(micros);
        if at_us < previous {
            return Err(Error("capture timestamps reversed"));
        }
        previous = at_us;
        let raw = match link {
            101 => frame,
            0 => {
                if frame.len() < 5 {
                    return Err(Error("short NULL packet"));
                }
                let family = number(frame);
                if !matches!((family, frame[4] >> 4), (2, 4) | (30, 6)) {
                    return Err(Error("NULL family mismatch"));
                }
                &frame[4..]
            }
            1 => {
                if frame.len() < 14 {
                    return Err(Error("short Ethernet header"));
                }
                let eth = u16be(&frame[12..14]);
                if !matches!(eth, 0x0800 | 0x86dd) {
                    return Err(Error("unsupported Ethernet/VLAN payload"));
                }
                if frame.len() < 15 || !matches!((eth, frame[14] >> 4), (0x0800, 4) | (0x86dd, 6)) {
                    return Err(Error("Ethernet/IP family mismatch"));
                }
                &frame[14..]
            }
            _ => return Err(Error("unknown link type")),
        };
        packets.push(ip_packet(raw, at_us)?);
    }
    Ok(packets)
}

/// No live capability exists. Function bodies compile real bounded TCP/UDP sender/responder
/// paths, but routine tests use doubles and never bind/connect/send on the network.
pub(crate) enum NetworkPermit {}
#[derive(Clone, Copy)]
pub(crate) enum Role {
    Sender,
    Receiver,
}
#[path = "peer_transport.rs"]
mod peer_transport;
pub(crate) fn native_exchange(
    _: &NetworkPermit,
    role: Role,
    flow: Flow,
    payload: &[u8],
) -> std::io::Result<Vec<u8>> {
    flow.validate().map_err(std::io::Error::other)?;
    peer_transport::exchange(
        matches!(role, Role::Sender),
        matches!(flow.protocol, Protocol::Tcp),
        flow.source,
        flow.destination,
        payload,
        std::time::Duration::from_millis(500),
        || Ok(()),
    )
}
pub(crate) fn dns_query(nonce: u16, tcp: bool) -> Vec<u8> {
    let mut query = vec![
        (nonce >> 8) as u8,
        nonce as u8,
        1,
        0,
        0,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let label = format!("tl{nonce:04x}");
    query.push(label.len() as u8);
    query.extend(label.bytes());
    query.extend([7]);
    query.extend(b"invalid");
    query.extend([0, 0, 1, 0, 1]);
    if tcp {
        let mut framed = (query.len() as u16).to_be_bytes().to_vec();
        framed.extend(query);
        framed
    } else {
        query
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CaptureHandle {
    pub(crate) instance: u64,
    pub(crate) birth: u64,
}
pub(crate) struct Sent {
    pub(crate) flow: Flow,
    pub(crate) nonce: [u8; 16],
    pub(crate) sent: bool,
    pub(crate) receiver_ack: bool,
}
pub(crate) struct Capture {
    pub(crate) handle: CaptureHandle,
    pub(crate) interface: String,
    pub(crate) pcap: Vec<u8>,
    pub(crate) dropped: u64,
    pub(crate) complete: bool,
    pub(crate) start_us: u64,
    pub(crate) end_us: u64,
}
pub(crate) trait Boundary {
    fn observe(&mut self) -> Result<Observation>;
    fn start_capture(&mut self, plan: &Plan) -> Result<CaptureHandle>;
    fn exchange(&mut self, flow: Flow, nonce: [u8; 16]) -> Result<Sent>;
    fn stop_probes(&mut self) -> Result<()>;
    fn finish_capture(&mut self, handle: CaptureHandle) -> Result<Capture>;
}
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Verdict {
    NoObservedLeak {
        session: [u8; 32],
        case_id: u32,
    },
    Leak {
        session: [u8; 32],
        case_id: u32,
        packets: usize,
    },
    NotRun(&'static str),
}

/// Classifies only the declared, complete set of offline case results.
/// This does not authorize a live run or establish protection.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum BatchVerdict {
    NoObservedLeak,
    Leak,
    Incomplete,
}
pub(crate) fn classify_batch(
    session: [u8; 32],
    expected: &[u32],
    results: &[(u32, Result<Verdict>)],
) -> Result<BatchVerdict> {
    use std::collections::BTreeSet;
    if session == [0; 32] || expected.is_empty() || expected.len() > 32 {
        return Err(Error("invalid batch scope"));
    }
    let expected_ids: BTreeSet<_> = expected.iter().copied().collect();
    if expected_ids.len() != expected.len() || expected_ids.contains(&0) || results.len() > 32 {
        return Err(Error("invalid batch case identifiers"));
    }
    let mut seen = BTreeSet::new();
    let mut incomplete = false;
    let mut leak = false;
    for (case_id, result) in results {
        if !expected_ids.contains(case_id) || !seen.insert(*case_id) {
            return Err(Error("unexpected or repeated batch case"));
        }
        match result {
            Ok(Verdict::NoObservedLeak {
                session: actual,
                case_id: actual_case,
            }) if *actual == session && actual_case == case_id => {}
            Ok(Verdict::Leak {
                session: actual,
                case_id: actual_case,
                packets,
            }) if *actual == session && actual_case == case_id && *packets > 0 => leak = true,
            _ => incomplete = true,
        }
    }
    if leak {
        Ok(BatchVerdict::Leak)
    } else if incomplete || seen.len() != expected_ids.len() {
        Ok(BatchVerdict::Incomplete)
    } else {
        Ok(BatchVerdict::NoObservedLeak)
    }
}

pub(crate) struct Experiment {
    guard: Guard,
    consumed: bool,
    unknown: bool,
}
pub(crate) fn nonce(identity: super::driver::Identity, case_id: u32, phase: u8) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(b"tunlatch-controlled-probe");
    digest.update(identity.boot);
    digest.update(identity.session);
    digest.update(identity.plan);
    digest.update(case_id.to_be_bytes());
    digest.update([phase]);
    let digest = digest.finalize();
    let mut result = [0; 16];
    result.copy_from_slice(&digest[..16]);
    result
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
    pub(crate) fn run(&mut self, b: &mut impl Boundary, plan: &Plan) -> Result<Verdict> {
        if self.consumed {
            return Err(Error("traffic experiment not repeatable"));
        }
        self.consumed = true;
        plan.validate()?;
        if plan.application == Application::Quic {
            return Ok(Verdict::NotRun(
                "no qualified QUIC sender/receiver; UDP:443 is not QUIC evidence",
            ));
        }
        if plan.application == Application::Dns {
            return Ok(Verdict::NotRun(
                "DNS wire query prepared; no qualified DNS responder receipt",
            ));
        }
        let result = self.inner(b, plan);
        if result.is_err() {
            self.unknown = true;
            if b.stop_probes().is_err() {
                return Err(Error("capture failure; owned probe stop also unconfirmed"));
            }
        }
        result
    }
    fn inner(&mut self, b: &mut impl Boundary, plan: &Plan) -> Result<Verdict> {
        self.guard.check(b.observe()?)?;
        let handle = b.start_capture(plan)?;
        if handle.instance == 0 || handle.birth == 0 {
            return Err(Error("capture ownership missing"));
        }
        let pre = nonce(self.guard.identity(), plan.case_id, 1);
        let negative = nonce(self.guard.identity(), plan.case_id, 2);
        let post = nonce(self.guard.identity(), plan.case_id, 3);
        let mut negative_acknowledged = false;
        for (flow, nonce, positive) in [
            (plan.before_control, pre, true),
            (plan.negative, negative, false),
            (plan.after_control, post, true),
        ] {
            let sent = b.exchange(flow, nonce)?;
            if sent.flow != flow
                || sent.nonce != nonce
                || !sent.sent
                || (positive && !sent.receiver_ack)
            {
                return Err(Error("probe not sent or positive receiver unavailable"));
            }
            negative_acknowledged |= !positive && sent.receiver_ack;
        }
        b.stop_probes()?;
        let capture = b.finish_capture(handle)?;
        self.guard.check(b.observe()?)?;
        if capture.handle != handle
            || capture.interface != plan.interface
            || capture.dropped != 0
            || !capture.complete
            || capture.end_us <= capture.start_us
        {
            return Err(Error("capture wrong, dropped, premature or incomplete"));
        }
        let packets = parse_pcap(&capture.pcap)?;
        if packets
            .iter()
            .any(|p| p.at_us < capture.start_us || p.at_us > capture.end_us)
        {
            return Err(Error("packet outside approved observation window"));
        }
        let before = packets
            .iter()
            .position(|p| p.flow == plan.before_control && p.payload.windows(16).any(|w| w == pre))
            .ok_or(Error("missing initial positive capture control"))?;
        let after = packets
            .iter()
            .rposition(|p| p.flow == plan.after_control && p.payload.windows(16).any(|w| w == post))
            .ok_or(Error("missing final positive capture control"))?;
        if after <= before {
            return Err(Error("capture positive controls reversed"));
        }
        let leaked = packets.iter().filter(|p| p.flow == plan.negative).count();
        if leaked > 0 {
            Ok(Verdict::Leak {
                session: self.guard.identity().session,
                case_id: plan.case_id,
                packets: leaked,
            })
        } else if negative_acknowledged {
            Err(Error(
                "negative receiver acknowledged without matching capture",
            ))
        } else {
            Ok(Verdict::NoObservedLeak {
                session: self.guard.identity().session,
                case_id: plan.case_id,
            })
        }
    }
}
