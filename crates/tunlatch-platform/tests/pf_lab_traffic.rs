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
        case_id: 1,
        interface: "lab0".into(),
        before_control: flow(ipv6, protocol, 45001),
        negative: flow(ipv6, protocol, 45002),
        after_control: flow(ipv6, protocol, 45003),
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
    case_id: u32,
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
            case_id: 1,
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
    fn start_capture(&mut self, plan: &Plan) -> Result<CaptureHandle> {
        self.calls += 1;
        self.case_id = plan.case_id;
        Ok(CaptureHandle {
            instance: 1,
            birth: 2,
        })
    }
    fn exchange(&mut self, flow: Flow, nonce: [u8; 16]) -> Result<Sent> {
        self.calls += 1;
        let negative = nonce == traffic::nonce(id(), self.case_id, 2);
        if (!negative || self.leak)
            && !(self.fault == Some("missing-post")
                && nonce == traffic::nonce(id(), self.case_id, 3))
        {
            let payload = if self.fault == Some("old-session") {
                let phase = if nonce == traffic::nonce(id(), self.case_id, 1) {
                    1
                } else {
                    3
                };
                traffic::nonce(
                    Identity {
                        session: [9; 32],
                        ..id()
                    },
                    self.case_id,
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
            receiver_ack: self.fault != Some("disconnected")
                && (!negative || self.leak || self.fault == Some("unseen-negative-ack")),
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
                    session: id().session,
                    case_id: 1,
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
        Verdict::Leak {
            session: id().session,
            case_id: 1,
            packets: 1
        }
    );
    Ok(())
}
#[test]
fn positive_controls_must_use_the_same_protocol_and_destination_with_distinct_flows() {
    let p = plan(false, Protocol::Tcp);
    for negative in [
        Flow {
            protocol: Protocol::Udp,
            ..p.negative
        },
        Flow {
            destination: std::net::SocketAddr::new(p.negative.destination.ip(), 45010),
            ..p.negative
        },
        Flow {
            source: std::net::SocketAddr::from(([192, 0, 2, 3], 45002)),
            ..p.negative
        },
    ] {
        let changed = Plan {
            negative,
            ..p.clone()
        };
        assert!(changed.capture_argv().is_err());
    }
    for after_control in [p.before_control, p.negative] {
        let reused = Plan {
            after_control,
            ..p.clone()
        };
        assert!(reused.capture_argv().is_err());
    }
    let mut scoped = plan(true, Protocol::Tcp);
    if let std::net::SocketAddr::V6(mut source) = scoped.negative.source {
        source.set_scope_id(1);
        scoped.negative.source = source.into();
    }
    assert!(scoped.capture_argv().is_err());
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
        "unseen-negative-ack",
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
    assert!(args.last().is_some_and(|s| {
        [45001, 45002, 45003]
            .iter()
            .all(|port| s.contains(&format!("src port {port}")))
    }));
    let _sender = traffic::Role::Sender;
    let _receiver = traffic::Role::Receiver;
    let _entry = traffic::native_exchange;
    let mut bad = p;
    bad.interface = "lab0; command".into();
    assert!(bad.capture_argv().is_err());
    Ok(())
}

#[test]
fn batch_requires_every_unique_correlated_case_and_preserves_leak() -> Result<()> {
    use traffic::{BatchVerdict, classify_batch};
    let clean = |case_id| {
        Ok(Verdict::NoObservedLeak {
            session: id().session,
            case_id,
        })
    };
    assert_eq!(
        classify_batch(id().session, &[1, 2], &[(1, clean(1)), (2, clean(2))])?,
        BatchVerdict::NoObservedLeak
    );
    assert_eq!(
        classify_batch(id().session, &[1, 2], &[(1, clean(1))])?,
        BatchVerdict::Incomplete
    );
    assert_eq!(
        classify_batch(id().session, &[1, 2], &[(1, clean(1)), (2, clean(1))])?,
        BatchVerdict::Incomplete
    );
    assert_eq!(
        classify_batch(
            id().session,
            &[1, 2],
            &[(1, clean(1)), (2, Err(Error("missing control")))]
        )?,
        BatchVerdict::Incomplete
    );
    assert_eq!(
        classify_batch(
            id().session,
            &[1, 2],
            &[(1, clean(1)), (2, Ok(Verdict::NotRun("unsupported")))]
        )?,
        BatchVerdict::Incomplete
    );
    assert_eq!(
        classify_batch(
            id().session,
            &[1, 2],
            &[(
                1,
                Ok(Verdict::Leak {
                    session: id().session,
                    case_id: 1,
                    packets: 1
                })
            )]
        )?,
        BatchVerdict::Leak
    );
    assert!(classify_batch(id().session, &[1, 1], &[]).is_err());
    assert!(classify_batch(id().session, &[1, 2], &[(1, clean(1)), (1, clean(1))]).is_err());
    assert!(classify_batch(id().session, &[1], &[(2, clean(2))]).is_err());
    Ok(())
}

#[test]
fn distinct_cases_have_distinct_controls_and_results() -> Result<()> {
    assert_ne!(traffic::nonce(id(), 1, 1), traffic::nonce(id(), 2, 1));
    let mut p = plan(false, Protocol::Tcp);
    p.case_id = 2;
    let verdict = Experiment::new(Guard::new(id(), 0)?).run(&mut Fake::new(), &p)?;
    assert_eq!(
        verdict,
        Verdict::NoObservedLeak {
            session: id().session,
            case_id: 2
        }
    );
    p.case_id = 0;
    assert!(p.validate().is_err());
    Ok(())
}

#[allow(dead_code)]
#[path = "pf_lab/exact_filter.rs"]
mod exact_filter;
#[path = "pf_lab/offline_capture.rs"]
mod offline_capture;

#[test]
fn offline_batch_uses_four_cases_controls_and_direct_evidence()
-> std::result::Result<(), Box<dyn std::error::Error>> {
    use serde_json::{Value, json};
    let mut phases = [Vec::new(), Vec::new(), Vec::new()];
    let mut controls = [Vec::new(), Vec::new()];
    let mut evidences = Vec::new();
    let suffix = "0123456789abcdef0123456789abcdef";
    let mut rules = String::new();
    let mut labels_before = String::new();
    let mut labels_after = String::new();
    for (index, (ipv6, protocol)) in [
        (false, Protocol::Tcp),
        (false, Protocol::Udp),
        (true, Protocol::Tcp),
        (true, Protocol::Udp),
    ]
    .into_iter()
    .enumerate()
    {
        let family = if ipv6 { "ipv6" } else { "ipv4" };
        let proto = if protocol == Protocol::Tcp {
            "tcp"
        } else {
            "udp"
        };
        for (phase, cases) in phases.iter_mut().enumerate() {
            let f = flow(ipv6, protocol, 45001 + phase as u16);
            let byte = (index * 3 + phase + 1) as u8;
            cases.push(json!({"family":family,"protocol":proto,"source":f.source.to_string(),"destination":f.destination.to_string(),"nonce":format!("{:02x}", byte).repeat(16)}));
            if phase != 1 {
                controls[if phase == 0 { 0 } else { 1 }].push(packet(f, &[byte; 16]));
            }
        }
        evidences.push(json!({"family":family,"protocol":proto,"sent":true}));
        let f = flow(ipv6, protocol, 45002);
        let af = if ipv6 { "inet6" } else { "inet" };
        let label = format!("tunlatch-lab:{suffix}-{index}");
        use std::fmt::Write as _;
        writeln!(
            rules,
            "block drop out quick on en0 {af} proto {proto} from {} port {} to {} port {} label \"{label}\"",
            f.source.ip(),
            f.source.port(),
            f.destination.ip(),
            f.destination.port()
        )?;
        writeln!(labels_before, "{label} 0 0 0 0 0 0 0")?;
        writeln!(labels_after, "{label} 1 1 40 0 0 1 40")?;
    }
    let report = |phase: usize| json!({"role":"receiver", "helper_sha256":"a".repeat(64), "status":if phase == 1 {"incomplete"} else {"completed"}, "pf_verdict":"not_evaluated", "cases":phases[phase].iter().cloned().map(|mut c| { c["result"] = json!(if phase == 1 { "unavailable" } else { "nonce_received_and_echoed" }); if phase == 1 { c["stage"] = json!("accept"); c["error_kind"] = json!("TimedOut"); c["errno"] = Value::Null; } c }).collect::<Vec<_>>()});
    let reports = json!({"before":report(0),"blocked":report(1),"after":report(2)});
    let mut manifest = json!({"plan":{"before":{"cases":phases[0]},"blocked":{"cases":phases[1]},"after":{"cases":phases[2]}},"interface":"en0","capture_complete":true,"capture_dropped":0,"capture_start_us":1,"capture_end_us":20,"windows":{"before":{"start_us":1,"end_us":4},"blocked":{"start_us":5,"end_us":9},"after":{"start_us":10,"end_us":20}},"evidence":evidences,"reports":reports,"pf":{"anchor_suffix":suffix,"rules_before":rules,"rules_after":rules,"labels_before":labels_before,"labels_after":labels_after}});
    let checked = serde_json::from_value::<offline_capture::FrozenPlan>(manifest["plan"].clone())?
        .checked("en0")?;
    let before_packets = traffic::parse_pcap(&pcap(&controls[0], 1))?;
    assert!(checked.iter().all(|case| {
        before_packets
            .iter()
            .any(|packet| case.before_control_matches(packet))
    }));
    for index in 0..before_packets.len() {
        let mut wrong_nonce = before_packets.clone();
        wrong_nonce[index].payload.fill(0);
        assert!(!checked.iter().all(|case| {
            wrong_nonce
                .iter()
                .any(|packet| case.before_control_matches(packet))
        }));
    }
    let after_packets = traffic::parse_pcap(&pcap(&controls[1], 1))?;
    assert!(checked.iter().all(|case| {
        !after_packets
            .iter()
            .any(|packet| case.before_control_matches(packet))
    }));
    let mut frames = controls[0].clone();
    // Supply five neutral blocked-window packets on a control flow, then four post controls.
    frames.extend((0..5).map(|_| packet(flow(false, Protocol::Tcp, 45001), &[])));
    frames.extend(controls[1].clone());
    let capture = pcap(&frames, 101);
    let evaluate =
        |v: &Value, p: &[u8]| -> std::result::Result<Value, Box<dyn std::error::Error>> {
            Ok(offline_capture::evaluate(
                serde_json::from_value(v.clone())?,
                p,
            )?)
        };
    assert_eq!(
        evaluate(&manifest, &capture)?["verdict"],
        "no_observed_leak"
    );
    let raw = serde_json::to_string(&manifest)?;
    let duplicate = raw.replacen("\"helper_sha256\":", "\"helper_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"helper_sha256\":", 1);
    assert_ne!(raw, duplicate);
    assert!(serde_json::from_str::<offline_capture::Manifest>(&duplicate).is_err());
    let duplicate_null = raw.replacen("\"errno\":null", "\"errno\":null,\"errno\":null", 1);
    assert_ne!(raw, duplicate_null);
    assert!(serde_json::from_str::<offline_capture::Manifest>(&duplicate_null).is_err());
    let mut inconsistent = manifest.clone();
    inconsistent["reports"]["blocked"]["status"] = json!("completed");
    assert!(evaluate(&inconsistent, &capture).is_err());
    inconsistent["reports"]["blocked"]["status"] = json!("incomplete");
    inconsistent["reports"]["blocked"]["unexpected"] = json!(true);
    assert!(evaluate(&inconsistent, &capture).is_err());
    assert_eq!(
        evaluate(&manifest, &capture)?["cases"][0]["pf_rule_hit_delta"],
        1
    );
    manifest["pf"]["labels_after"] =
        json!(labels_after.replacen("1 1 40 0 0 1 40", "0 0 0 0 0 0 0", 1));
    assert_eq!(evaluate(&manifest, &capture)?["verdict"], "incomplete");
    manifest["pf"]["labels_after"] = json!(labels_after);
    let mut changed = manifest.clone();
    changed["pf"]["rules_after"] = json!(rules.replacen("quick", "log", 1));
    assert_eq!(evaluate(&changed, &capture)?["verdict"], "incomplete");
    assert_eq!(
        evaluate(&changed, &capture)?["cases"][0]["pf_rule_hit_delta"],
        Value::Null
    );
    manifest["evidence"][0]["sent"] = json!(false);
    assert_eq!(evaluate(&manifest, &capture)?["verdict"], "incomplete");
    // SYN-like blocked TCP packet has no nonce: tuple alone preserves the potential leak.
    frames[5] = packet(flow(false, Protocol::Tcp, 45002), &[]);
    let leaked = evaluate(&manifest, &pcap(&frames, 101))?;
    assert_eq!(leaked["verdict"], "potential_leak");
    assert_eq!(leaked["cases"][0]["matching_blocked_packets"], 1);
    assert_eq!(
        evaluate(&changed, &pcap(&frames, 101))?["verdict"],
        "potential_leak"
    );
    let mut bad_report = manifest.clone();
    // Change to a value guaranteed not to match its frozen nonce.
    bad_report["reports"]["before"]["cases"][0]["nonce"] =
        json!("ffffffffffffffffffffffffffffffff");
    assert!(evaluate(&bad_report, &capture).is_err());
    let mut missing_control = frames.clone();
    missing_control[0] = packet(flow(false, Protocol::Tcp, 45001), &[]);
    // Restore the blocked tuple before checking missing control alone.
    missing_control[5] = packet(flow(false, Protocol::Tcp, 45001), &[]);
    assert_eq!(
        evaluate(&manifest, &pcap(&missing_control, 101))?["verdict"],
        "incomplete"
    );
    manifest["capture_dropped"] = json!(1);
    assert_eq!(evaluate(&manifest, &capture)?["verdict"], "incomplete");
    manifest["windows"]["after"]["start_us"] = json!(4);
    assert!(evaluate(&manifest, &capture).is_err());
    Ok(())
}
