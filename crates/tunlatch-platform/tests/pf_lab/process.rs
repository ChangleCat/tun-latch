//! Ordinary-user supervisor. Fixed administrator read queries use system sudo/env/pfctl only.
//!
//! The bounded registry, rather than a waiting client, owns each worker/child/pipe. Deadline
//! expiry changes the observation to Unsettled; it cannot manufacture process reclamation.
//! Pipes are nonblocking and pumped fairly without reader threads or blocking joins/waits.
//! This is not a descendant containment mechanism or a crash-persistent privileged ledger.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use thiserror::Error;

const CAPACITY: usize = 4;
const MAX_INPUT: usize = 8192;
const MAX_OUTPUT: usize = 65536;
const TICK: Duration = Duration::from_millis(2);
static JOBS: Mutex<Vec<Arc<Job>>> = Mutex::new(Vec::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    run: Duration,
    reclaim: Duration,
    output: usize,
}
impl Limits {
    pub(crate) fn new(run: Duration, reclaim: Duration, output: usize) -> Result<Self, Error> {
        if run.is_zero()
            || run > Duration::from_secs(10)
            || reclaim.is_zero()
            || reclaim > Duration::from_secs(2)
            || output == 0
            || output > MAX_OUTPUT
        {
            return Err(Error::InvalidLimits);
        }
        Ok(Self {
            run,
            reclaim,
            output,
        })
    }
}

/// Closed operations. The supervisor itself always refuses root. Privileged reads launch only
/// fixed system binaries; no PF writer, caller-supplied argv or elevated project binary exists.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Probe {
    Echo,
    PrivilegedRead(ReadQuery),
    #[cfg(test)]
    Fixture(Fixture),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReadQuery {
    Rules,
    Nat,
    RecursiveRules,
    Anchors,
    Interfaces,
    Info,
    References,
    AnchorRules(ReadAnchor),
    AnchorTables(ReadAnchor),
    AnchorNat(ReadAnchor),
}

/// Literal PF name, never a wildcard, filesystem path, option or shell fragment.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct ReadAnchor {
    bytes: [u8; 128],
    length: u8,
}
impl ReadAnchor {
    pub(crate) fn new(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() > 128
            || name.split('/').count() > 8
            || name.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.starts_with('-')
                    || !part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid literal PF anchor",
            ));
        }
        let mut result = Self {
            bytes: [0; 128],
            length: name.len() as u8,
        };
        result.bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(result)
    }
    pub(crate) fn name(self) -> String {
        self.bytes[..usize::from(self.length)]
            .iter()
            .map(|b| char::from(*b))
            .collect()
    }
}
impl std::fmt::Debug for ReadAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Literal").field(&self.name()).finish()
    }
}

impl ReadQuery {
    pub(crate) fn args(self) -> Vec<String> {
        let words: &[&str] = match self {
            Self::Rules => &["-s", "rules"],
            Self::Nat => &["-s", "nat"],
            Self::RecursiveRules => &["-a", "*", "-s", "rules"],
            Self::Anchors => &["-v", "-s", "Anchors"],
            Self::Interfaces => &["-v", "-s", "Interfaces"],
            Self::Info => &["-s", "info"],
            Self::References => &["-s", "References"],
            Self::AnchorRules(anchor) => {
                return vec!["-a".into(), anchor.name(), "-s".into(), "rules".into()];
            }
            Self::AnchorTables(anchor) => {
                return vec!["-a".into(), anchor.name(), "-s".into(), "Tables".into()];
            }
            Self::AnchorNat(anchor) => {
                return vec!["-a".into(), anchor.name(), "-s".into(), "nat".into()];
            }
        };
        words.iter().map(|word| (*word).into()).collect()
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Fixture {
    FloodOut,
    FloodErr,
    FloodBoth,
    Wait,
    Fail,
    Binary,
    CloseInput,
    CloseOutput,
    CleanEnvironment,
    InheritedPipe,
    PipeHolder,
    SpawnFailure,
}

impl Probe {
    fn command(self) -> io::Result<Command> {
        let mut c = match self {
            Self::Echo => Command::new("/bin/cat"),
            Self::PrivilegedRead(query) => {
                let mut command = Command::new("/usr/bin/sudo");
                command.args([
                    "-n",
                    "-u",
                    "root",
                    "--",
                    "/usr/bin/env",
                    "-i",
                    "LC_ALL=C",
                    "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                    "/sbin/pfctl",
                ]);
                command.args(query.args());
                command
            }
            #[cfg(test)]
            Self::Fixture(Fixture::SpawnFailure) => Command::new("/dev/null"),
            #[cfg(test)]
            Self::Fixture(_) => {
                let mut c = Command::new(std::env::current_exe()?);
                c.args(["--exact", "controlled_fixture", "--nocapture"]);
                c
            }
        };
        // Environment reset must precede the private fixture selection.
        let fixture: Option<&str> = match self {
            Self::Echo | Self::PrivilegedRead(_) => None,
            #[cfg(test)]
            Self::Fixture(mode) => Some(mode.name()),
        };
        c.env_clear()
            .env("LC_ALL", "C")
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(mode) = fixture {
            c.env("TUNLATCH_LAB_CHILD", mode);
        }
        Ok(c)
    }
    fn known_leaf(self) -> bool {
        match self {
            Self::Echo => true,
            // sudo may have a monitor and a command child. Cancellation/EOF alone never
            // proves their termination. Only an un-cancelled normal sudo return is accepted
            // below, under sudo's command-wait contract and the fixed leaf pfctl invocation.
            Self::PrivilegedRead(_) => false,
            #[cfg(test)]
            Self::Fixture(Fixture::InheritedPipe) => false,
            #[cfg(test)]
            Self::Fixture(_) => true,
        }
    }

    fn natural_command_return(self, normal_exit: bool, stopping: bool) -> bool {
        self.known_leaf() || (matches!(self, Self::PrivilegedRead(_)) && normal_exit && !stopping)
    }
}

#[cfg(test)]
impl Fixture {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::FloodOut => "flood-out",
            Self::FloodErr => "flood-err",
            Self::FloodBoth => "flood-both",
            Self::Wait => "wait",
            Self::Fail => "fail",
            Self::Binary => "binary",
            Self::CloseInput => "close-input",
            Self::CloseOutput => "close-output",
            Self::CleanEnvironment => "clean-environment",
            Self::InheritedPipe => "inherited-pipe",
            Self::PipeHolder => "pipe-holder",
            Self::SpawnFailure => "spawn-failure",
        }
    }
}

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error("ordinary-user preparation only")]
    Root,
    #[error("invalid process limits or input size")]
    InvalidLimits,
    #[error("supervisor capacity exhausted or briefly busy")]
    Busy,
    #[error("unknown operation")]
    Unknown,
    #[error("operation is not fully reclaimed")]
    Unsettled,
    #[error("cannot start supervisor worker")]
    WorkerStart,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reason {
    Success,
    ExitFailure,
    Cancelled,
    Timeout,
    OutputLimit,
    InputFailure,
    IoFailure,
    SpawnFailure,
    DescendantsUnproven,
}
#[derive(Clone, Copy)]
struct Stop {
    reason: Reason,
    at: Instant,
}

/// Bytes are untrusted output, never PF input or instructions. stdout+stderr share one cap.
#[derive(Clone, Debug)]
pub(crate) struct Completion {
    pub(crate) reason: Reason,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) input_written: usize,
    pub(crate) truncated: bool,
    pub(crate) capture_failed: bool,
    pub(crate) kill_failed: bool,
    pub(crate) child_started: bool,
    pub(crate) parent_reaped: bool,
    pub(crate) pipes_closed: bool,
    pub(crate) descendants_known_leaf: bool,
}
impl Completion {
    fn reclaimed(&self) -> bool {
        self.parent_reaped && self.pipes_closed && self.descendants_known_leaf
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    Starting,
    Running,
    Stopping,
    Finished,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Observation {
    Pending(Stage),
    Unsettled(Stage),
    Reclaimed,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Id(u64);

struct Job {
    id: Id,
    began: Instant,
    limits: Limits,
    stop: OnceLock<Stop>,
    stage: AtomicU8,
    done: AtomicBool,
    completion: Mutex<Option<Completion>>,
    worker: Mutex<Option<JoinHandle<()>>>,
}
impl Job {
    fn stop(&self, reason: Reason) {
        let _ = self.stop.set(Stop {
            reason,
            at: Instant::now(),
        });
    }
    fn stage(&self) -> Stage {
        match self.stage.load(Ordering::Acquire) {
            0 => Stage::Starting,
            1 => Stage::Running,
            2 => Stage::Stopping,
            _ => Stage::Finished,
        }
    }
    fn budget_expired(&self) -> bool {
        if self.began.elapsed() >= self.limits.run {
            self.stop(Reason::Timeout);
        }
        self.began.elapsed() >= self.limits.run + self.limits.reclaim
            || self
                .stop
                .get()
                .is_some_and(|s| s.at.elapsed() >= self.limits.reclaim)
    }
}

/// Dropping a waiting ticket requests cancellation; ownership stays in the bounded registry.
pub(crate) struct Ticket {
    job: Arc<Job>,
}
impl Ticket {
    pub(crate) fn id(&self) -> Id {
        self.job.id
    }
    pub(crate) fn cancel(&self) {
        self.job.stop(Reason::Cancelled);
    }
    pub(crate) fn observe(&self) -> Result<Observation, Error> {
        observe_job(&self.job)
    }
    /// Wait at most the caller's budget; OS startup/kill may remain owned after this returns.
    pub(crate) fn wait(&self, budget: Duration) -> Result<Observation, Error> {
        let began = Instant::now();
        loop {
            let observation = self.observe()?;
            if !matches!(observation, Observation::Pending(_)) {
                return Ok(observation);
            }
            let remaining = budget.saturating_sub(began.elapsed());
            if remaining.is_zero() {
                return Ok(observation);
            }
            thread::park_timeout(TICK.min(remaining));
        }
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Reserve before any spawn. No caller-supplied program, argv, environment or working directory.
pub(crate) fn start(probe: Probe, input: Vec<u8>, limits: Limits) -> Result<Ticket, Error> {
    start_inner(probe, input, limits, Hooks::default())
}
fn start_inner(
    probe: Probe,
    input: Vec<u8>,
    limits: Limits,
    hooks: Hooks,
) -> Result<Ticket, Error> {
    if nix::unistd::geteuid().is_root() {
        return Err(Error::Root);
    }
    if input.len() > MAX_INPUT || (matches!(probe, Probe::PrivilegedRead(_)) && !input.is_empty()) {
        return Err(Error::InvalidLimits);
    }
    let mut jobs = JOBS.try_lock().map_err(|_| Error::Busy)?;
    if jobs.len() >= CAPACITY {
        return Err(Error::Busy);
    }
    let id = NEXT_ID
        .try_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_add(1))
        .map(Id)
        .map_err(|_| Error::Busy)?;
    let job = Arc::new(Job {
        id,
        began: Instant::now(),
        limits,
        stop: OnceLock::new(),
        stage: AtomicU8::new(0),
        done: AtomicBool::new(false),
        completion: Mutex::new(None),
        worker: Mutex::new(None),
    });
    let owner = Arc::clone(&job);
    jobs.push(Arc::clone(&job));
    // Hold the registry only over thread creation, never over a child/pipe or OS process call.
    let worker = thread::Builder::new()
        .name("tunlatch-lab-process".into())
        .spawn(move || supervise(owner, probe, input, hooks));
    match worker {
        Ok(worker) => {
            *job.worker.try_lock().map_err(|_| Error::Busy)? = Some(worker);
            Ok(Ticket { job })
        }
        Err(_) => {
            jobs.retain(|j| j.id != id);
            Err(Error::WorkerStart)
        }
    }
}

#[cfg(test)]
mod closed_read_tests {
    use super::{Probe, ReadAnchor, ReadQuery};

    #[test]
    fn privileged_queries_have_only_fixed_system_programs_and_read_flags() -> std::io::Result<()> {
        for query in [
            ReadQuery::Rules,
            ReadQuery::Nat,
            ReadQuery::RecursiveRules,
            ReadQuery::Anchors,
            ReadQuery::Interfaces,
            ReadQuery::Info,
            ReadQuery::References,
            ReadQuery::AnchorRules(ReadAnchor::new("com.apple/200.AirDrop")?),
            ReadQuery::AnchorTables(ReadAnchor::new("foreign.testing")?),
            ReadQuery::AnchorNat(ReadAnchor::new("foreign.testing")?),
        ] {
            let command = Probe::PrivilegedRead(query).command()?;
            assert_eq!(command.get_program(), "/usr/bin/sudo");
            let args = command
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert_eq!(
                &args[..9],
                [
                    "-n",
                    "-u",
                    "root",
                    "--",
                    "/usr/bin/env",
                    "-i",
                    "LC_ALL=C",
                    "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
                    "/sbin/pfctl"
                ]
            );
            assert_eq!(&args[9..], query.args());
            assert!(!args.iter().any(|s| {
                ["-f", "-F", "-k", "-K", "-E", "-X", "-e", "-d", "-z"].contains(&s.as_str())
            }));
            assert_eq!(
                command.get_envs().collect::<Vec<_>>(),
                [(
                    std::ffi::OsStr::new("LC_ALL"),
                    Some(std::ffi::OsStr::new("C"))
                )]
            );
        }
        Ok(())
    }

    #[test]
    fn anchor_operands_reject_globs_options_control_and_path_traversal() {
        for name in [
            "",
            "-f",
            "*",
            "com.apple/*",
            "../root",
            "a//b",
            "a/..",
            "a\nb",
            "a b",
            "a;sh",
            "$(x)",
            "é",
        ] {
            assert!(ReadAnchor::new(name).is_err());
        }
        assert!(ReadAnchor::new(&"x".repeat(129)).is_err());
        assert!(ReadAnchor::new("a/b/c/d/e/f/g/h/i").is_err());
        assert!(ReadAnchor::new("pfctl-rs.integration.testing.1234").is_ok());
    }

    #[test]
    fn sudo_eof_signal_or_cancel_cannot_claim_command_tree_reclamation() {
        let probe = Probe::PrivilegedRead(ReadQuery::Rules);
        assert!(!probe.known_leaf());
        assert!(!probe.natural_command_return(false, false));
        assert!(!probe.natural_command_return(true, true));
        assert!(!probe.natural_command_return(false, true));
        assert!(probe.natural_command_return(true, false));
    }
}

fn lookup(id: Id) -> Result<Arc<Job>, Error> {
    JOBS.try_lock()
        .map_err(|_| Error::Busy)?
        .iter()
        .find(|j| j.id == id)
        .cloned()
        .ok_or(Error::Unknown)
}
pub(crate) fn observe(id: Id) -> Result<Observation, Error> {
    observe_job(lookup(id)?.as_ref())
}
fn observe_job(job: &Job) -> Result<Observation, Error> {
    let expired = job.budget_expired();
    if job.done.load(Ordering::Acquire) {
        let finished = job
            .worker
            .try_lock()
            .map_err(|_| Error::Busy)?
            .as_ref()
            .is_some_and(JoinHandle::is_finished);
        if finished {
            let result = job.completion.try_lock().map_err(|_| Error::Busy)?;
            if result.as_ref().is_some_and(Completion::reclaimed) {
                return Ok(Observation::Reclaimed);
            }
            return Ok(Observation::Unsettled(Stage::Finished));
        }
    }
    Ok(if expired {
        Observation::Unsettled(job.stage())
    } else {
        Observation::Pending(job.stage())
    })
}

/// Only terminal, observed, reclaimed work can leave the registry. There is no force-forget.
pub(crate) fn collect(id: Id) -> Result<Completion, Error> {
    let mut jobs = JOBS.try_lock().map_err(|_| Error::Busy)?;
    let index = jobs.iter().position(|j| j.id == id).ok_or(Error::Unknown)?;
    if observe_job(&jobs[index])? != Observation::Reclaimed {
        return Err(Error::Unsettled);
    }
    let result = jobs[index]
        .completion
        .try_lock()
        .map_err(|_| Error::Busy)?
        .as_ref()
        .cloned()
        .ok_or(Error::Unsettled)?;
    // The worker has acknowledged relinquishing all process/pipe ownership and its function
    // has finished. No blocking join is performed, including on a cancelled caller path.
    jobs.remove(index);
    Ok(result)
}
pub(crate) fn retained_count() -> Result<usize, Error> {
    Ok(JOBS.try_lock().map_err(|_| Error::Busy)?.len())
}
/// Diagnostic data only; unlike collect, this never releases registry ownership.
pub(crate) fn report(id: Id) -> Result<Completion, Error> {
    let job = lookup(id)?;
    let result = job.completion.try_lock().map_err(|_| Error::Busy)?;
    result.as_ref().cloned().ok_or(Error::Unsettled)
}

#[derive(Default)]
struct Hooks {
    #[cfg(test)]
    gate: Option<(
        GatePoint,
        std::sync::mpsc::SyncSender<()>,
        std::sync::mpsc::Receiver<()>,
    )>,
}
impl Hooks {
    fn visit(&mut self, _point: GatePoint) {
        #[cfg(test)]
        if self
            .gate
            .as_ref()
            .is_some_and(|(point, _, _)| *point == _point)
            && let Some((_, ready, release)) = self.gate.take()
        {
            let _ = ready.try_send(());
            let _ = release.recv(); // Test-only controllable stand-in for a blocked OS call.
        }
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum GatePoint {
    BeforeSpawn,
    AfterSpawn,
}
#[cfg(test)]
pub(crate) fn start_gated(
    probe: Probe,
    limits: Limits,
    point: GatePoint,
    ready: std::sync::mpsc::SyncSender<()>,
    release: std::sync::mpsc::Receiver<()>,
) -> Result<Ticket, Error> {
    start_inner(
        probe,
        Vec::new(),
        limits,
        Hooks {
            gate: Some((point, ready, release)),
        },
    )
}

fn nonblocking(fd: &impl AsFd) -> io::Result<()> {
    let flags = fcntl(fd, FcntlArg::F_GETFL).map_err(io::Error::from)?;
    fcntl(
        fd,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK),
    )
    .map_err(io::Error::from)?;
    Ok(())
}
fn publish(job: &Job, result: Completion) {
    // This cell is written only by the owner. Readers use try_lock, so no OS work is held
    // behind them and a poisoned/contended cell cannot become a successful observation.
    loop {
        if let Ok(mut cell) = job.completion.try_lock() {
            *cell = Some(result);
            job.stage.store(3, Ordering::Release);
            job.done.store(true, Ordering::Release);
            return;
        }
        thread::park_timeout(TICK);
    }
}
fn no_child(job: &Job, reason: Reason) {
    publish(
        job,
        Completion {
            reason,
            stdout: Vec::new(),
            stderr: Vec::new(),
            input_written: 0,
            truncated: false,
            capture_failed: false,
            kill_failed: false,
            child_started: false,
            parent_reaped: true,
            pipes_closed: true,
            descendants_known_leaf: true,
        },
    );
}

fn supervise(job: Arc<Job>, probe: Probe, input: Vec<u8>, mut hooks: Hooks) {
    hooks.visit(GatePoint::BeforeSpawn);
    if job.began.elapsed() >= job.limits.run {
        job.stop(Reason::Timeout);
    }
    if let Some(stop) = job.stop.get() {
        no_child(&job, stop.reason);
        return;
    }
    let mut child = match probe.command().and_then(|mut c| c.spawn()) {
        Ok(child) => child,
        Err(_) => {
            no_child(&job, Reason::SpawnFailure);
            return;
        }
    };
    job.stage.store(1, Ordering::Release);
    hooks.visit(GatePoint::AfterSpawn);
    pump(job, &mut child, probe, input);
}

fn pump(job: Arc<Job>, child: &mut Child, probe: Probe, input: Vec<u8>) {
    let mut result = Completion {
        reason: Reason::Success,
        stdout: Vec::new(),
        stderr: Vec::new(),
        input_written: 0,
        truncated: false,
        capture_failed: false,
        kill_failed: false,
        child_started: true,
        parent_reaped: false,
        pipes_closed: false,
        descendants_known_leaf: probe.known_leaf(),
    };
    let mut stdin = child.stdin.take();
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    if stdin.as_ref().is_some_and(|f| nonblocking(f).is_err()) {
        stdin = None;
        job.stop(Reason::IoFailure);
    }
    if stdout.as_ref().is_some_and(|f| nonblocking(f).is_err()) {
        stdout = None;
        result.capture_failed = true;
        job.stop(Reason::IoFailure);
    }
    if stderr.as_ref().is_some_and(|f| nonblocking(f).is_err()) {
        stderr = None;
        result.capture_failed = true;
        job.stop(Reason::IoFailure);
    }
    let mut killed = false;
    let mut exit = None;
    loop {
        if job.began.elapsed() >= job.limits.run {
            job.stop(Reason::Timeout);
        }
        // try_wait reaps the direct child. After a reaped or uncertain identity, never send
        // a raw-PID/group signal; EOF is not evidence that descendants were contained.
        if exit.is_none() {
            match child.try_wait() {
                Ok(status) => {
                    exit = status;
                    result.parent_reaped = exit.is_some();
                }
                Err(_) => {
                    job.stop(Reason::IoFailure);
                    job.stage.store(2, Ordering::Release);
                    loop {
                        std::hint::black_box(&child);
                        thread::park_timeout(Duration::from_millis(50));
                    }
                }
            }
        }
        if job.stop.get().is_some() {
            job.stage.store(2, Ordering::Release);
            stdin = None;
            if exit.is_none() && !killed {
                result.kill_failed = child.kill().is_err();
                killed = true;
            }
        }
        if let Some(pipe) = &mut stdin {
            let remaining = &input[result.input_written..];
            if remaining.is_empty() {
                stdin = None;
            } else {
                match pipe.write(&remaining[..remaining.len().min(4096)]) {
                    Ok(0) => {
                        job.stop(Reason::InputFailure);
                        stdin = None;
                    }
                    Ok(n) => result.input_written += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => {
                        job.stop(Reason::InputFailure);
                        stdin = None;
                    }
                }
            }
        }
        drain(
            &job,
            &mut stdout,
            &mut result.stdout,
            &result.stderr,
            &mut result.truncated,
            &mut result.capture_failed,
        );
        drain(
            &job,
            &mut stderr,
            &mut result.stderr,
            &result.stdout,
            &mut result.truncated,
            &mut result.capture_failed,
        );
        if result.parent_reaped && stdout.is_none() && stderr.is_none() {
            drop(stdin);
            result.pipes_closed = true;
            if result.input_written != input.len() {
                job.stop(Reason::InputFailure);
            }
            let reclaimed = probe.natural_command_return(
                exit.is_some_and(|status| status.code().is_some()),
                job.stop.get().is_some(),
            );
            result.descendants_known_leaf = reclaimed;
            result.reason = job.stop.get().map_or_else(
                || {
                    if !reclaimed {
                        Reason::DescendantsUnproven
                    } else if exit.is_some_and(|s| s.success()) {
                        Reason::Success
                    } else {
                        Reason::ExitFailure
                    }
                },
                |s| s.reason,
            );
            publish(&job, result);
            return;
        }
        thread::park_timeout(TICK);
    }
}

fn drain<R: Read>(
    job: &Job,
    pipe: &mut Option<R>,
    output: &mut Vec<u8>,
    other: &[u8],
    truncated: &mut bool,
    failed: &mut bool,
) {
    let mut buffer = [0; 4096];
    // Fixed per-turn work prevents an always-readable stream from starving cancellation.
    for _ in 0..4 {
        let Some(reader) = pipe else {
            return;
        };
        match reader.read(&mut buffer) {
            Ok(0) => {
                *pipe = None;
                return;
            }
            Ok(n) => {
                let keep = n.min(job.limits.output.saturating_sub(output.len() + other.len()));
                output.extend_from_slice(&buffer[..keep]);
                if keep < n {
                    *truncated = true;
                    job.stop(Reason::OutputLimit);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                *pipe = None;
                *failed = true;
                job.stop(Reason::IoFailure);
                return;
            }
        }
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    fn old_job() -> Result<Job, Box<dyn std::error::Error>> {
        Ok(Job {
            id: Id(0),
            began: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .ok_or_else(|| io::Error::other("monotonic clock too young"))?,
            limits: Limits::new(Duration::from_millis(100), Duration::from_millis(100), 4096)?,
            stop: OnceLock::new(),
            stage: AtomicU8::new(0),
            done: AtomicBool::new(false),
            completion: Mutex::new(None),
            worker: Mutex::new(None),
        })
    }

    #[test]
    fn late_first_observation_does_not_restart_reclaim_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let job = old_job()?;
        assert_eq!(observe_job(&job)?, Observation::Unsettled(Stage::Starting));
        Ok(())
    }

    #[test]
    fn late_cancellation_cannot_extend_the_total_operation_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        let job = old_job()?;
        job.stop(Reason::Cancelled);
        assert_eq!(observe_job(&job)?, Observation::Unsettled(Stage::Starting));
        Ok(())
    }
}
