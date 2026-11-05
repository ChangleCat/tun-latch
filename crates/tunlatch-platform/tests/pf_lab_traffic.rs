//! Offline pcap fixtures and controlled-send/capture doubles. No network is used.
#[path = "pf_lab/driver.rs"]
mod driver;
#[path = "pf_lab/traffic.rs"]
mod traffic;
use driver::{Error, Guard, Identity, Observation, Result};
use traffic::{
    Application, Boundary, Capture, CaptureHandle, Experiment, Flow, Plan, Protocol, Sent, Verdict,
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
fn flow(ipv6: bool, protocol: Protocol, port: u16) -> Flow {
    let source = if ipv6 {
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into()
    } else {
        std::net::Ipv4Addr::new(192, 0, 2, 1).into()
    };
    let dest = if ipv6 {
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2).into()
    } else {
        std::net::Ipv4Addr::new(192, 0, 2, 2).into()
    };
    Flow {
        source: std::net::SocketAddr::new(source, port),
        destination: std::net::SocketAddr::new(dest, 45000),
        protocol,
    }
}
fn plan(ipv6: bool, protocol: Protocol) -> Plan {
    Plan {
        interface: "lab0".into(),
        control: flow(ipv6, protocol, 45001),
        negative: flow(ipv6, protocol, 45002),
        application: Application::Probe,
    }
}
fn packet(flow: Flow, payload: &[u8]) -> Vec<u8> {
    let transport_len = match flow.protocol {
        Protocol::Tcp => 20,
        Protocol::Udp => 8,
    };
    let mut transport = vec![0; transport_len];
    transport[..2].copy_from_slice(&flow.source.port().to_be_bytes());
    transport[2..4].copy_from_slice(&flow.destination.port().to_be_bytes());
    match flow.protocol {
        Protocol::Tcp => {
            transport[12] = 0x50;
            transport[13] = 0x18;
        }
        Protocol::Udp => {
            transport[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes())
        }
    }
    transport.extend(payload);
    let proto = if flow.protocol == Protocol::Tcp {
        6
    } else {
        17
    };
    match (flow.source.ip(), flow.destination.ip()) {
        (std::net::IpAddr::V4(source), std::net::IpAddr::V4(dest)) => {
            let mut ip = vec![0; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
            ip[8] = 64;
            ip[9] = proto;
            ip[12..16].copy_from_slice(&source.octets());
            ip[16..20].copy_from_slice(&dest.octets());
            let mut sum = ip
                .as_chunks::<2>()
                .0
                .iter()
                .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
                .sum::<u32>();
            while sum > 65535 {
                sum = (sum & 65535) + (sum >> 16);
            }
            ip[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            ip.extend(transport);
            ip
        }
        (std::net::IpAddr::V6(source), std::net::IpAddr::V6(dest)) => {
            let mut ip = vec![0; 40];
            ip[0] = 0x60;
            ip[4..6].copy_from_slice(&(transport.len() as u16).to_be_bytes());
            ip[6] = proto;
            ip[7] = 64;
            ip[8..24].copy_from_slice(&source.octets());
            ip[24..40].copy_from_slice(&dest.octets());
            ip.extend(transport);
            ip
        }
        _ => Vec::new(),
    }
}
fn pcap(packets: &[Vec<u8>], link: u32) -> Vec<u8> {
    let mut file = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    file.extend(65535_u32.to_le_bytes());
    file.extend(link.to_le_bytes());
    for (i, p) in packets.iter().enumerate() {
        let frame = match link {
            0 => {
                let mut f = if p[0] >> 4 == 4 { 2_u32 } else { 30_u32 }
                    .to_le_bytes()
                    .to_vec();
                f.extend(p);
                f
            }
            1 => {
                let mut f = vec![0; 12];
                f.extend(
                    if p[0] >> 4 == 4 {
                        0x0800_u16
                    } else {
                        0x86dd_u16
                    }
                    .to_be_bytes(),
                );
                f.extend(p);
                f
            }
            _ => p.clone(),
        };
        file.extend(0_u32.to_le_bytes());
        file.extend((i as u32 + 1).to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend((frame.len() as u32).to_le_bytes());
        file.extend(frame);
    }
    file
}
struct Fake {
    seq: u64,
    packets: Vec<Vec<u8>>,
    leak: bool,
    fault: Option<&'static str>,
    calls: usize,
    stopped: bool,
}
impl Fake {
    fn new() -> Self {
        Self {
            seq: 0,
            packets: Vec::new(),
            leak: false,
            fault: None,
            calls: 0,
            stopped: false,
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
    fn start_capture(&mut self, _: &Plan) -> Result<CaptureHandle> {
        self.calls += 1;
        Ok(CaptureHandle {
            instance: 1,
            birth: 2,
        })
    }
    fn exchange(&mut self, flow: Flow, nonce: [u8; 16]) -> Result<Sent> {
        self.calls += 1;
        if (nonce != traffic::nonce(id(), 2) || self.leak)
            && !(self.fault == Some("missing-post") && nonce == traffic::nonce(id(), 3))
        {
            let payload = if self.fault == Some("old-session") {
                let phase = if nonce == traffic::nonce(id(), 1) {
                    1
                } else {
                    3
                };
                traffic::nonce(
                    Identity {
                        session: [9; 32],
                        ..id()
                    },
                    phase,
                )
            } else {
                nonce
            };
            self.packets.push(packet(flow, &payload));
        }
        Ok(Sent {
            flow,
            nonce,
            sent: self.fault != Some("not-sent"),
            receiver_ack: self.fault != Some("disconnected"),
        })
    }
    fn stop_probes(&mut self) -> Result<()> {
        if self.fault == Some("stop") {
            return Err(Error("stop acknowledgement lost"));
        }
        self.stopped = true;
        Ok(())
    }
    fn finish_capture(&mut self, handle: CaptureHandle) -> Result<Capture> {
        if !self.stopped {
            return Err(Error("probes not stopped"));
        }
        Ok(Capture {
            handle,
            interface: if self.fault == Some("wrong-interface") {
                "other0"
            } else {
                "lab0"
            }
            .into(),
            pcap: pcap(&self.packets, 101),
            dropped: u64::from(self.fault == Some("drop")),
            complete: self.fault != Some("partial"),
            start_us: 0,
            end_us: 10_000,
        })
    }
}
#[test]
fn dual_stack_tcp_udp_parser_round_trips_all_qualified_link_types() -> Result<()> {
    for ipv6 in [false, true] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            for link in [0, 1, 101] {
                let flow = flow(ipv6, protocol, 45001);
                let parsed = traffic::parse_pcap(&pcap(&[packet(flow, &[1; 16])], link))?;
                assert_eq!(parsed.len(), 1);
                assert_eq!(parsed[0].flow, flow);
                assert_eq!(parsed[0].payload, [1; 16]);
            }
        }
    }
    Ok(())
}
#[test]
fn negative_absence_requires_before_after_capture_and_receiver_positive_controls() -> Result<()> {
    for ipv6 in [false, true] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let mut fake = Fake::new();
            let mut run = Experiment::new(Guard::new(id(), 0)?);
            assert_eq!(
                run.run(&mut fake, &plan(ipv6, protocol))?,
                Verdict::NoObservedLeak {
                    session: id().session
                }
            );
            assert!(!run.unknown());
            assert!(fake.stopped);
        }
    }
    Ok(())
}
#[test]
fn any_negative_tuple_packet_is_a_leak_even_without_payload_nonce() -> Result<()> {
    let p = plan(false, Protocol::Tcp);
    let mut fake = Fake::new();
    fake.packets.push(packet(p.negative, &[]));
    assert_eq!(
        Experiment::new(Guard::new(id(), 0)?).run(&mut fake, &p)?,
        Verdict::Leak { packets: 1 }
    );
    Ok(())
}
#[test]
fn wrong_interface_drops_partial_capture_disconnection_or_unsent_probe_never_pass() -> Result<()> {
    for fault in [
        "wrong-interface",
        "drop",
        "partial",
        "disconnected",
        "not-sent",
        "missing-post",
        "old-session",
        "stop",
    ] {
        let mut fake = Fake::new();
        fake.fault = Some(fault);
        let mut run = Experiment::new(Guard::new(id(), 0)?);
        assert!(
            run.run(&mut fake, &plan(false, Protocol::Udp)).is_err(),
            "{fault}"
        );
        assert!(run.unknown());
        if fault != "stop" {
            assert!(fake.stopped);
        }
        let count = fake.calls;
        assert!(run.run(&mut fake, &plan(false, Protocol::Udp)).is_err());
        assert_eq!(count, fake.calls);
    }
    Ok(())
}
#[test]
fn pcap_partial_records_formats_snaplen_and_length_mismatch_are_refused() {
    let good = pcap(&[packet(flow(false, Protocol::Udp, 45001), &[1; 16])], 101);
    for size in [0, 3, 23, 25, 39, good.len() - 1] {
        assert!(traffic::parse_pcap(&good[..size]).is_err());
    }
    for (offset, value) in [
        (0, 0),
        (4, 3),
        (18, 1),
        (20, 99),
        (30, 255),
        (32, 0),
        (36, 1),
    ] {
        let mut bad = good.clone();
        bad[offset] = value;
        assert!(traffic::parse_pcap(&bad).is_err(), "{offset}");
    }
    assert!(traffic::parse_pcap(&vec![0; 1024 * 1024 + 1]).is_err());
}
#[test]
fn malformed_ip_transport_fragments_and_unknown_extension_headers_invalidate_capture() {
    for ipv6 in [false, true] {
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let good = packet(flow(ipv6, protocol, 45001), &[1; 16]);
            let mut bad = good.clone();
            if ipv6 {
                bad[6] = 44;
            } else {
                bad[6] = 0x20;
            }
            assert!(traffic::parse_pcap(&pcap(&[bad], 101)).is_err());
            let mut bad = good.clone();
            if ipv6 {
                bad[4] = 255;
            } else {
                bad[10] ^= 1;
            }
            assert!(traffic::parse_pcap(&pcap(&[bad], 101)).is_err());
            let mut bad = good;
            let offset = if ipv6 { 40 } else { 20 };
            if protocol == Protocol::Tcp {
                bad[offset + 12] = 0xf0;
            } else {
                bad[offset + 4] = 255;
            }
            assert!(traffic::parse_pcap(&pcap(&[bad], 101)).is_err());
        }
    }
}
#[test]
fn missing_dns_or_quic_implementation_is_not_run_and_udp443_is_never_quic_evidence() -> Result<()> {
    for application in [Application::Dns, Application::Quic] {
        let mut p = plan(false, Protocol::Udp);
        p.application = application;
        let mut fake = Fake::new();
        assert!(matches!(
            Experiment::new(Guard::new(id(), 0)?).run(&mut fake, &p)?,
            Verdict::NotRun(_)
        ));
        assert_eq!(fake.calls, 0);
    }
    let udp = traffic::dns_query(0x1234, false);
    let tcp = traffic::dns_query(0x1234, true);
    assert_eq!(&udp[..2], [0x12, 0x34]);
    assert_eq!(&tcp[2..], udp);
    assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]) as usize, udp.len());
    Ok(())
}
#[test]
fn fixed_capture_scope_and_native_sender_receiver_compile_without_network_execution() -> Result<()>
{
    let p = plan(false, Protocol::Udp);
    let args = p.capture_argv()?;
    assert_eq!(&args[..4], ["-i", "lab0", "-n", "-U"]);
    assert!(args.last().is_some_and(|s| s.contains("src port 45002")));
    let _sender = traffic::Role::Sender;
    let _receiver = traffic::Role::Receiver;
    let _entry = traffic::native_exchange;
    let mut bad = p;
    bad.interface = "lab0; command".into();
    assert!(bad.capture_argv().is_err());
    Ok(())
}
