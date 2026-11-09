//! Fixed-command, bounded collector for a separately authorized physical-interface experiment.
//! It does not authorize traffic, PF changes, or execution of an experiment.
use super::traffic::{self, Flow, Plan, Protocol};
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, geteuid};
use std::collections::BTreeSet;
use std::fs::{File, metadata};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TCPDUMP: &str = "/usr/sbin/tcpdump";
const MAX_PCAP: u64 = 1024 * 1024;
const MAX_ERR: usize = 16 * 1024;
const MAX_RUN: Duration = Duration::from_secs(120);
const START_TIMEOUT: Duration = Duration::from_secs(5);
const STOP_TIMEOUT: Duration = Duration::from_secs(3);
fn error(s: &'static str) -> io::Error {
    io::Error::other(s)
}

pub(crate) struct CapturePlan {
    interface: String,
    filter: String,
}
impl CapturePlan {
    pub(crate) fn new(interface: &str, plans: [Plan; 4]) -> io::Result<Self> {
        let mut families = BTreeSet::new();
        let mut tuples = BTreeSet::new();
        let mut expressions = Vec::new();
        for plan in plans {
            plan.validate().map_err(|_| error("invalid phase plan"))?;
            if plan.interface != interface {
                return Err(error("interface mismatch"));
            }
            let flow = plan.negative;
            let proto = match flow.protocol {
                Protocol::Tcp => "tcp",
                Protocol::Udp => "udp",
            };
            if !families.insert((flow.source.is_ipv6(), proto)) {
                return Err(error("duplicate family/protocol"));
            }
            for Flow {
                source,
                destination,
                protocol,
            } in [plan.before_control, flow, plan.after_control]
            {
                let protocol = match protocol {
                    Protocol::Tcp => "tcp",
                    Protocol::Udp => "udp",
                };
                if !tuples.insert((source, destination, protocol)) {
                    return Err(error("reused capture tuple"));
                }
                expressions.push(format!(
                    "(src host {} and dst host {} and src port {} and dst port {} and {})",
                    source.ip(),
                    destination.ip(),
                    source.port(),
                    destination.port(),
                    protocol
                ));
            }
        }
        if families.len() != 4 || expressions.len() != 12 {
            return Err(error("twelve flows required"));
        }
        Ok(Self {
            interface: interface.into(),
            filter: expressions.join(" or "),
        })
    }
}

pub(crate) struct CaptureEvidence {
    pub(crate) pcap: Vec<u8>,
    pub(crate) start_us: u64,
    pub(crate) end_us: u64,
    pub(crate) dropped: u64,
}
pub(crate) struct Capture {
    stop: Sender<()>,
    result: Receiver<io::Result<CaptureEvidence>>,
}
fn now_us() -> io::Result<u64> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| error("clock before epoch"))?
            .as_micros(),
    )
    .map_err(|_| error("clock overflow"))
}
fn count_line(line: &str, suffix: &str) -> Option<u64> {
    let n = line.strip_suffix(suffix)?;
    if n.is_empty() || !n.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    n.parse().ok()
}
fn diagnostics(data: &[u8], interface: &str) -> io::Result<u64> {
    let text = std::str::from_utf8(data).map_err(|_| error("non-UTF8 tcpdump diagnostics"))?;
    if !text.ends_with('\n') {
        return Err(error("partial tcpdump diagnostics"));
    }
    let mut lines = text.lines().filter(|line| !line.is_empty());
    let prefix = format!("tcpdump: listening on {interface}, link-type ");
    let first = lines.next().ok_or_else(|| error("missing readiness"))?;
    if !first.starts_with(&prefix) || !first.ends_with(", snapshot length 4096 bytes") {
        return Err(error("unexpected readiness"));
    }
    let captured = lines
        .next()
        .and_then(|s| count_line(s, " packets captured"))
        .ok_or_else(|| error("missing captured count"))?;
    let _received = lines
        .next()
        .and_then(|s| count_line(s, " packets received by filter"))
        .ok_or_else(|| error("missing received count"))?;
    let dropped = lines
        .next()
        .and_then(|s| count_line(s, " packets dropped by kernel"))
        .ok_or_else(|| error("missing drop count"))?;
    if lines.next().is_some() || captured >= 128 {
        return Err(error("unexpected diagnostics or packet limit reached"));
    }
    Ok(dropped)
}
fn signal(child: &Child, sig: Signal) -> io::Result<()> {
    let pid = i32::try_from(child.id()).map_err(|_| error("invalid child identity"))?;
    // The Child is owned here and is not reaped before this signal; the PID cannot be reused.
    kill(Pid::from_raw(pid), sig).map_err(io::Error::other)
}
fn worker(
    mut child: Child,
    mut file: File,
    interface: String,
    start: u64,
    stop: Receiver<()>,
    ready: Sender<io::Result<()>>,
) -> io::Result<CaptureEvidence> {
    let mut err = child
        .stderr
        .take()
        .ok_or_else(|| error("missing diagnostic pipe"))?;
    if fcntl(&err, FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error("cannot configure diagnostic pipe"));
    }
    let start_instant = Instant::now();
    let mut stderr = Vec::new();
    let mut announced = false;
    let mut stopped = None;
    let mut forced = false;
    let mut failure = None;
    loop {
        let mut buf = [0_u8; 1024];
        loop {
            match err.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stderr.len() + n > MAX_ERR {
                        failure = Some("diagnostics exceed limit");
                        break;
                    }
                    stderr.extend_from_slice(&buf[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    failure = Some("diagnostic read failed");
                    break;
                }
            }
        }
        if !announced && stderr.contains(&b'\n') {
            let line = stderr.split(|b| *b == b'\n').next().unwrap_or_default();
            let prefix = format!("tcpdump: listening on {interface}, link-type ");
            if std::str::from_utf8(line).is_ok_and(|s| {
                s.starts_with(&prefix) && s.ends_with(", snapshot length 4096 bytes")
            }) {
                announced = true;
                if ready.send(Ok(())).is_err() {
                    failure = Some("caller disappeared");
                }
            } else {
                failure = Some("unexpected readiness");
            }
        }
        let elapsed = start_instant.elapsed();
        if !announced && elapsed >= START_TIMEOUT {
            failure = Some("readiness timeout");
        }
        if elapsed >= MAX_RUN {
            failure = Some("capture deadline exceeded");
        }
        let stop_requested = match stop.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => true,
            Err(mpsc::TryRecvError::Empty) => false,
        };
        if stopped.is_none() && (stop_requested || failure.is_some()) {
            if signal(&child, Signal::SIGINT).is_err() {
                failure = Some("cannot signal owned capture");
            }
            stopped = Some(Instant::now());
        }
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(_) => {
                failure = Some("capture wait failed");
                let _ = child.kill();
                forced = true;
                None
            }
        };
        if let Some(status) = status {
            // Drain anything written between the last read and process exit.
            loop {
                let mut buf = [0_u8; 1024];
                match err.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) if stderr.len() + n <= MAX_ERR => stderr.extend_from_slice(&buf[..n]),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    _ => return Err(error("incomplete or excessive diagnostic output")),
                }
            }
            if !announced {
                let _ = ready.send(Err(error("capture did not become ready")));
            }
            if let Some(message) = failure {
                return Err(error(message));
            }
            if stopped.is_none() || forced || !status.success() {
                return Err(error("capture exited prematurely or unsuccessfully"));
            }
            let end = now_us()?;
            if end <= start {
                return Err(error("wall clock reversed"));
            }
            let dropped = diagnostics(&stderr, &interface)?;
            if file.metadata()?.len() > MAX_PCAP {
                return Err(error("pcap exceeds limit"));
            }
            file.seek(SeekFrom::Start(0))?;
            let mut pcap = Vec::new();
            file.take(MAX_PCAP + 1).read_to_end(&mut pcap)?;
            if pcap.len() as u64 > MAX_PCAP {
                return Err(error("pcap exceeds limit"));
            }
            traffic::parse_pcap(&pcap).map_err(|_| error("invalid or truncated pcap"))?;
            return Ok(CaptureEvidence {
                pcap,
                start_us: start,
                end_us: end,
                dropped,
            });
        }
        if stopped.is_some_and(|at| at.elapsed() >= STOP_TIMEOUT) && !forced {
            let _ = child.kill();
            forced = true;
            failure = Some("capture did not stop gracefully");
        }
        thread::sleep(Duration::from_millis(10));
    }
}
impl Capture {
    /// The file must be a new, empty, root-owned 0600 regular file already opened for read/write.
    /// Its parent and exclusive ownership remain the privileged caller's responsibility.
    pub(crate) fn start(plan: CapturePlan, mut file: File) -> io::Result<Self> {
        if !geteuid().is_root() {
            return Err(error("capture requires root"));
        }
        let m = file.metadata()?;
        if !m.is_file()
            || m.uid() != 0
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
            || m.len() != 0
        {
            return Err(error("invalid capture file"));
        }
        file.seek(SeekFrom::Start(0))?;
        let binary = metadata(TCPDUMP)?;
        if !binary.is_file() || binary.uid() != 0 || binary.mode() & 0o022 != 0 {
            return Err(error("untrusted tcpdump"));
        }
        let start = now_us()?;
        let child = Command::new(TCPDUMP)
            .env_clear()
            .env("LC_ALL", "C")
            .args([
                "-i",
                &plan.interface,
                "-n",
                "--micro",
                "-U",
                "-s",
                "4096",
                "-c",
                "128",
                "-w",
                "-",
                &plan.filter,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::from(file.try_clone()?))
            .stderr(Stdio::piped())
            .spawn()?;
        let (stop_tx, stop_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = result_tx.send(worker(
                child,
                file,
                plan.interface,
                start,
                stop_rx,
                ready_tx,
            ));
        });
        match ready_rx.recv_timeout(START_TIMEOUT + Duration::from_secs(1)) {
            Ok(Ok(())) => Ok(Self {
                stop: stop_tx,
                result: result_rx,
            }),
            _ => {
                let _ = stop_tx.send(());
                Err(error("capture readiness failed"))
            }
        }
    }
    pub(crate) fn finish(self) -> io::Result<CaptureEvidence> {
        self.stop
            .send(())
            .map_err(|_| error("capture already stopped"))?;
        self.result
            .recv_timeout(STOP_TIMEOUT + Duration::from_secs(1))
            .map_err(|_| error("capture reaping unconfirmed"))?
    }
}
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = self.stop.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::super::traffic::Application;
    use super::*;
    use std::net::SocketAddr;

    fn plans() -> io::Result<[Plan; 4]> {
        let mut plans = Vec::new();
        for (v6, protocol) in [
            (false, Protocol::Tcp),
            (false, Protocol::Udp),
            (true, Protocol::Tcp),
            (true, Protocol::Udp),
        ] {
            let ip = if v6 { "2001:db8::1" } else { "192.0.2.1" };
            let destination: SocketAddr = if v6 {
                "[2001:db8::2]:443"
            } else {
                "192.0.2.2:443"
            }
            .parse()
            .map_err(io::Error::other)?;
            let flow = |port| -> io::Result<Flow> {
                Ok(Flow {
                    source: SocketAddr::new(ip.parse().map_err(io::Error::other)?, port),
                    destination,
                    protocol,
                })
            };
            plans.push(Plan {
                case_id: 1,
                interface: "en0".into(),
                before_control: flow(50001)?,
                negative: flow(50002)?,
                after_control: flow(50003)?,
                application: Application::Probe,
            });
        }
        plans.try_into().map_err(|_| error("fixture count"))
    }
    #[test]
    fn derives_only_the_twelve_validated_outbound_tuples() -> io::Result<()> {
        let plan = CapturePlan::new("en0", plans()?)?;
        assert_eq!(plan.filter.matches("src host").count(), 12);
        assert!(plan.filter.contains(
            "src host 192.0.2.1 and dst host 192.0.2.2 and src port 50002 and dst port 443 and tcp"
        ));
        assert!(CapturePlan::new("en1", plans()?).is_err());
        let mut duplicate = plans()?;
        duplicate[1] = duplicate[0].clone();
        assert!(CapturePlan::new("en0", duplicate).is_err());
        Ok(())
    }
    #[test]
    fn strict_diagnostics_require_complete_drop_statistics() {
        let good = b"tcpdump: listening on en0, link-type EN10MB (Ethernet), snapshot length 4096 bytes\n\n3 packets captured\n4 packets received by filter\n0 packets dropped by kernel\n";
        assert_eq!(diagnostics(good, "en0").ok(), Some(0));
        assert!(diagnostics(good, "en1").is_err());
        assert!(diagnostics(&good[..good.len() - 1], "en0").is_err());
        assert!(diagnostics(&good[..good.len() - 28], "en0").is_err());
    }
}
