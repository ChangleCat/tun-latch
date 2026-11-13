//! Protected controller for the disabled-PF setup and cleanup of the first physical flow batch.
#![allow(dead_code)]
#[path = "../tests/pf_lab/attached_reference.rs"]
mod attached_reference;
#[path = "../tests/pf_lab/attached_snapshot.rs"]
mod attached_snapshot;
#[path = "../tests/pf_lab/bootstrap.rs"]
mod bootstrap;
#[path = "../tests/pf_lab/driver.rs"]
mod driver;
#[path = "../tests/pf_lab/exact_filter.rs"]
mod exact_filter;
#[path = "../tests/pf_lab/ledger.rs"]
mod ledger;
#[path = "../tests/pf_lab/native_files.rs"]
mod native_files;
#[path = "../src/pf/native_hook.rs"]
mod native_hook;
#[path = "../tests/pf_lab/offline_capture.rs"]
mod offline_capture;
#[path = "../tests/pf_lab/references.rs"]
mod references;
#[path = "../tests/pf_lab/root_hook_readback.rs"]
mod root_hook_readback;
#[path = "../tests/pf_lab/root_hook_recovery.rs"]
mod root_hook_recovery;
#[path = "../tests/pf_lab/sync_observe.rs"]
mod sync_observe;
#[path = "../tests/pf_lab/sync_storage.rs"]
mod sync_storage;
#[path = "../tests/pf_lab/traffic.rs"]
mod traffic;

use attached_snapshot::Snapshot;
use bootstrap::{Error, Result};
use driver::{Guard, Identity, Observation};
use exact_filter::{ExactFilter, Flow};
use ledger::{Ledger, Operation, State};
use nix::fcntl::{Flock, FlockArg, OFlag, open};
use nix::sys::stat::Mode;
use root_hook_recovery::{Leaf, Receipt, Trial, View};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::num::NonZeroU64;
use std::os::unix::fs::MetadataExt;
use std::process::ExitCode;
use std::time::{Duration, Instant};
use sync_observe::Slot;
use sync_storage::Storage;

const MODE: &str = "pf-first-flow-trial";
const PROGRAM: &str = "/private/var/root/tunlatch-pf-first-flow/pf-lab-first-flow";
const PLAN_LIMIT: usize = 16 * 1024;
const SESSION_LIMIT: usize = 512 * 1024;

#[derive(Clone, Copy)]
enum Action {
    Prepare,
    Status,
    Stage,
    Activate,
    CountersBefore,
    CountersAfter,
    Recover,
}

impl Action {
    fn parse(mut args: impl Iterator<Item = std::ffi::OsString>) -> Result<Self> {
        let action = match args.next().as_deref().and_then(|arg| arg.to_str()) {
            Some("prepare") => Self::Prepare,
            Some("status") => Self::Status,
            Some("stage") => Self::Stage,
            Some("activate") => Self::Activate,
            Some("counters-before") => Self::CountersBefore,
            Some("counters-after") => Self::CountersAfter,
            Some("recover") => Self::Recover,
            _ => return Err(Error::Refused("expected one fixed batch action")),
        };
        if args.next().is_some() {
            return Err(Error::Refused("extra arguments"));
        }
        Ok(action)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    mode: String,
    boot: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanInput {
    interface: String,
    phases: offline_capture::FrozenPlan,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Session {
    boot: String,
    helper: [u8; 32],
    nonce: [u8; 32],
    plan: [u8; 32],
    lock_inode: u64,
    controller_birth: u64,
    prepared_ms: u64,
    root: Vec<u8>,
    index: u32,
    foreign: [u8; 32],
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ReferenceReturn {
    binding: [u8; 32],
    returned: attached_reference::Return,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CounterRecord {
    binding: [u8; 32],
    observed_us: u64,
    rules: String,
    labels: String,
}

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(output, "{b:02x}");
    }
    output
}

fn now_ms() -> Result<u64> {
    let time = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
    let sec = u64::try_from(time.tv_sec()).map_err(io::Error::other)?;
    let nanos = u64::try_from(time.tv_nsec()).map_err(io::Error::other)?;
    sec.checked_mul(1000)
        .and_then(|ms| ms.checked_add(nanos / 1_000_000))
        .ok_or(Error::Refused("invalid monotonic clock"))
}

fn epoch_us() -> Result<u64> {
    let elapsed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?;
    u64::try_from(elapsed.as_micros()).map_err(|error| io::Error::other(error).into())
}

fn birth() -> Result<u64> {
    let pid = nix::unistd::getpid().as_raw();
    let info = libproc::proc_pid::pidinfo::<libproc::bsd_info::BSDInfo>(pid, 0)
        .map_err(|_| Error::Refused("controller birth unavailable"))?;
    if info.pbi_pid != pid as u32
        || info.pbi_uid != 0
        || info.pbi_start_tvsec == 0
        || info.pbi_start_tvusec >= 1_000_000
    {
        return Err(Error::Refused("controller process identity invalid"));
    }
    info.pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|value| value.checked_add(info.pbi_start_tvusec))
        .ok_or(Error::Refused("invalid controller birth timestamp"))
}

fn read_input(input: impl Read, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    input.take(max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(Error::Refused("batch input exceeds bound"));
    }
    Ok(bytes)
}

fn decode<T: serde::de::DeserializeOwned>(raw: &[u8]) -> Result<T> {
    serde_json::from_slice(raw).map_err(|_| Error::Refused("invalid protected JSON"))
}

fn plan(raw: &[u8], suffix: &str) -> Result<ExactFilter> {
    let PlanInput { interface, phases } = decode(raw)?;
    let cases = phases
        .checked(&interface)
        .map_err(|e| Error::Refused(e.0))?;
    let flows = cases.map(|case| Flow {
        source: case.plan.negative.source,
        destination: case.plan.negative.destination,
    });
    ExactFilter::new(suffix, &interface, flows).map_err(|_| Error::Refused("invalid exact filter"))
}

fn lock(storage: &Storage, create: bool) -> Result<Flock<File>> {
    let lock = Flock::lock(
        storage.subdir("flow-lock", create)?,
        FlockArg::LockExclusiveNonblock,
    )
    .map_err(|(_, error)| Error::System(error))?;
    check_lock(storage, &lock)?;
    Ok(lock)
}

fn check_lock(storage: &Storage, lock: &File) -> Result<u64> {
    let held = lock.metadata()?;
    let named = storage.subdir("flow-lock", false)?.metadata()?;
    if (held.dev(), held.ino()) != (named.dev(), named.ino()) || held.ino() == 0 {
        return Err(Error::Refused("batch lock directory changed"));
    }
    Ok(held.ino())
}

fn system_line(program: &str, args: &[&str]) -> Result<String> {
    let (bytes, _) =
        sync_observe::execute_program(program, args, Instant::now() + Duration::from_secs(3))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Error::Refused("invalid system output"))?;
    let line = text
        .strip_suffix('\n')
        .ok_or(Error::Refused("partial system output"))?;
    if line.is_empty() || !line.is_ascii() || line.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(Error::Refused("invalid system line"));
    }
    Ok(line.to_owned())
}

struct Host {
    device: File,
    build: String,
    kernel: String,
}

impl Host {
    fn open() -> Result<Self> {
        let build = system_line("/usr/bin/sw_vers", &["-buildVersion"])?;
        let kernel = system_line("/usr/sbin/sysctl", &["-n", "kern.version"])?;
        native_hook::check_host(&build, &kernel)
            .map_err(|_| Error::Refused("PF ABI not qualified"))?;
        let device = open(
            "/dev/pf",
            OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
            Mode::empty(),
        )?
        .into();
        Ok(Self {
            device,
            build,
            kernel,
        })
    }

    fn read(&self, anchor: &str, boot: &str) -> Result<Snapshot> {
        let snap = attached_snapshot::read(anchor, boot)?;
        let expected = native_hook::parse_rules(&snap.root_rules)
            .map_err(|_| Error::Refused("unsupported root filter display"))?;
        let native = native_hook::readonly_rules(&self.device, &self.build, &self.kernel)
            .map_err(|_| Error::Refused("native root filter read failed"))?;
        let (after, _) = sync_observe::execute_program(
            "/sbin/pfctl",
            &["-s", "rules"],
            Instant::now() + Duration::from_secs(3),
        )?;
        if native != expected || after != snap.root_rules {
            return Err(Error::Refused(
                "native and independent root filter readbacks disagree",
            ));
        }
        Ok(snap)
    }

    fn writer(&self, suffix: &str) -> Result<native_hook::Writer<'_>> {
        native_hook::Writer::new(&self.device, &self.build, &self.kernel, suffix)
            .map_err(|_| Error::Refused("native writer scope invalid"))
    }
}

impl Session {
    fn suffix(&self) -> String {
        hex(&self.nonce[..16])
    }
    fn identity(&self) -> Identity {
        Identity {
            boot: sha(self.boot.as_bytes()),
            session: self.nonce,
            plan: self.plan,
            controller_birth: self.controller_birth,
            lock_inode: self.lock_inode,
        }
    }
    fn phase_hash(&self, name: &str) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"tunlatch-first-flow\0");
        hash.update(self.boot.as_bytes());
        hash.update(self.nonce);
        hash.update(self.plan);
        hash.update(self.helper);
        hash.update(self.foreign);
        hash.update(self.lock_inode.to_be_bytes());
        hash.update(name);
        hash.finalize().into()
    }
    fn report(&self, filter: &ExactFilter, phase: &'static str) -> Value {
        json!({"scope":"first_physical_flow_batch","phase":phase,"anchor":filter.anchor(),
            "actual_protection":"unknown","plan_sha256":hex(&self.plan)})
    }
}

struct Boundary<'a> {
    storage: &'a Storage,
    lock: &'a File,
    host: &'a Host,
    session: &'a Session,
    anchor: String,
    writer: native_hook::Writer<'a>,
    sequence: u64,
    attended_until_ms: Option<u64>,
}

impl Boundary<'_> {
    fn attended(&self) -> Result<()> {
        if self
            .attended_until_ms
            .is_none_or(|deadline| now_ms().map_or(true, |now| now >= deadline))
        {
            return Err(Error::Refused(
                "attended exclusive window unavailable or expired",
            ));
        }
        Ok(())
    }

    fn recheck(&self) -> Result<()> {
        if check_lock(self.storage, self.lock)? != self.session.lock_inode {
            return Err(Error::Refused("original protected lock changed"));
        }
        self.storage.recheck()
    }

    fn snapshot(&self) -> Result<Snapshot> {
        self.recheck()?;
        let snap = self.host.read(&self.anchor, &self.session.boot)?;
        if snap.foreign != self.session.foreign {
            return Err(Error::Refused("foreign PF baseline changed"));
        }
        self.recheck()?;
        Ok(snap)
    }

    fn filter_change(
        &self,
        name: &str,
        filter: &ExactFilter,
        hook: Receipt,
        stage: bool,
    ) -> Result<()> {
        let before = self.snapshot()?;
        self.match_root(&before.root_rules, hook)?;
        let permitted = match &before.leaf {
            Slot::Empty => true,
            Slot::Active(raw) => !stage && filter.matches_observed(raw),
            Slot::Absent => false,
        };
        if !permitted
            || !before.states_and_sources_empty
            || (stage && !before.enable_baseline_clear)
        {
            return Err(Error::Refused(
                "filter slot or activation baseline is unsafe",
            ));
        }
        let mut journal = Ledger::create(
            self.storage.subdir(name, true)?,
            self.session.nonce,
            self.session.phase_hash(name),
        )?;
        let transaction = filter
            .transaction(stage)
            .map_err(|_| Error::Refused("invalid exact filter transaction"))?;
        journal.apply_and_observe::<Error>(
            Operation::WriteFilter,
            || {
                if self.snapshot()? != before || !self.same_hook(hook)? {
                    return Err(Error::Refused(
                        "PF baseline changed before filter transaction",
                    ));
                }
                self.attended()?;
                transaction
                    .commit()
                    .map_err(|_| Error::Refused("filter transaction result unknown"))
            },
            || {
                let after = self.snapshot()?;
                let matched = match after.leaf {
                    Slot::Active(raw) => stage && filter.matches_observed(&raw),
                    Slot::Empty => !stage,
                    Slot::Absent => false,
                };
                if !matched
                    || after.root_rules != before.root_rules
                    || !after.states_and_sources_empty
                    || !self.same_hook(hook)?
                {
                    return Err(Error::Refused("filter transaction readback mismatch"));
                }
                Ok(())
            },
        )?;
        journal.close()
    }

    fn journal(&self, name: &str) -> Result<Ledger> {
        let journal = Ledger::reopen(self.storage.subdir(name, false)?)?;
        if journal.identity() != (self.session.nonce, self.session.phase_hash(name)) {
            return Err(Error::Refused("filter journal is from another batch"));
        }
        Ok(journal)
    }

    fn same_hook(&self, hook: Receipt) -> Result<bool> {
        Ok(self
            .writer
            .observe()
            .map_err(|_| Error::Refused("native hook read failed"))?
            == Some(native_hook::Hook {
                index: hook.index,
                ticket: hook.ticket,
            }))
    }

    fn match_root(&self, raw: &[u8], hook: Receipt) -> Result<()> {
        let baseline = root_hook_readback::Observation {
            bytes: &self.session.root,
            complete: true,
        };
        let current = root_hook_readback::Observation {
            bytes: raw,
            complete: true,
        };
        root_hook_readback::verify(baseline, current, &self.anchor, hook.index as usize)
            .map_err(Error::Refused)
    }

    fn persist_reference(
        &self,
        phase: &str,
        name: &str,
        returned: &attached_reference::Return,
    ) -> io::Result<()> {
        let record = ReferenceReturn {
            binding: self.session.phase_hash(phase),
            returned: returned.clone(),
        };
        let bytes = serde_json::to_vec(&record)?;
        self.storage.write(name, &bytes).map_err(io::Error::other)
    }

    fn recorded_reference(&self) -> Result<attached_reference::Owned> {
        let record: ReferenceReturn = decode(&self.storage.read("enable-return.json", 8192)?)?;
        if record.binding != self.session.phase_hash("enable") {
            return Err(Error::Refused(
                "enable return belongs to a different session",
            ));
        }
        Ok(attached_reference::Owned::from_return(&record.returned)?)
    }

    fn enabled(&self, owner: attached_reference::Owned) -> Result<()> {
        self.recheck()?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let (info, _) = sync_observe::execute_program("/sbin/pfctl", &["-s", "info"], deadline)?;
        if !info.starts_with(b"Status: Enabled ") || sync_observe::boot()? != self.session.boot {
            return Err(Error::Refused("enabled status or boot is unconfirmed"));
        }
        attached_reference::read_owned(owner)?;
        self.recheck()
    }

    fn activate(&self, filter: &ExactFilter, hook: Receipt) -> Result<()> {
        self.attended()?;
        if self.storage.exists("enable")? || self.storage.exists("release")? {
            return Err(Error::Refused("enable already attempted"));
        }
        let stage = self.journal("stage")?;
        if !stage.is_single_closed_operation(Operation::WriteFilter)? {
            return Err(Error::Refused("filter staging is unconfirmed"));
        }
        let snap = self.snapshot()?;
        self.match_root(&snap.root_rules, hook)?;
        if !snap.enable_baseline_clear
            || !self.same_hook(hook)?
            || !matches!(&snap.leaf, Slot::Active(rules) if filter.matches_observed(rules))
        {
            return Err(Error::Refused("PF activation baseline changed"));
        }
        let mut journal = Ledger::create(
            self.storage.subdir("enable", true)?,
            self.session.nonce,
            self.session.phase_hash("enable"),
        )?;
        let result = attached_reference::acquire_once(
            || {
                self.attended().map_err(io::Error::other)?;
                if self.snapshot().map_err(io::Error::other)? != snap
                    || !self.same_hook(hook).map_err(io::Error::other)?
                {
                    return Err(io::Error::other(
                        "activation baseline changed before acquire",
                    ));
                }
                stage.check_named_objects().map_err(io::Error::other)?;
                self.attended().map_err(io::Error::other)?;
                journal
                    .begin(Operation::AcquireReference)
                    .map_err(io::Error::other)
            },
            |returned| self.persist_reference("enable", "enable-return.json", returned),
        )
        .map_err(Error::from)
        .and_then(|owner| self.enabled(owner));
        if let Err(error) = result {
            let _ = journal.unknown();
            return Err(error);
        }
        journal.observed()?;
        journal.close()
    }

    fn counters(&self, filter: &ExactFilter, hook: Receipt, before: bool) -> Result<()> {
        if self.storage.exists("release")?
            || !self
                .journal("enable")?
                .is_single_closed_operation(Operation::AcquireReference)?
        {
            return Err(Error::Refused(
                "requires the verified active trial reference",
            ));
        }
        let owner = self.recorded_reference()?;
        let read = || -> Result<Snapshot> {
            let snap = attached_snapshot::read_with_status(
                &self.anchor,
                &self.session.boot,
                |info, refs| {
                    info.starts_with(b"Status: Enabled ")
                        && attached_reference::singleton(refs, owner).is_ok()
                },
            )?;
            self.match_root(&snap.root_rules, hook)?;
            if snap.foreign != self.session.foreign
                || !snap.enable_baseline_clear
                || !matches!(&snap.leaf, Slot::Active(raw) if filter.matches_observed(raw))
                || !self.same_hook(hook)?
            {
                return Err(Error::Refused(
                    "enabled PF rules or foreign baseline changed",
                ));
            }
            Ok(snap)
        };
        let first = read()?;
        let at = epoch_us()?;
        let (labels, _) = sync_observe::execute_program(
            "/sbin/pfctl",
            &["-a", &self.anchor, "-s", "labels"],
            Instant::now() + Duration::from_secs(3),
        )?;
        if read()? != first {
            return Err(Error::Refused("PF changed across counter read"));
        }
        self.recheck()?;
        let Slot::Active(rules) = first.leaf else {
            return Err(Error::Refused("exact flow rules unavailable"));
        };
        let binding = self.session.phase_hash("active-counters");
        if !before {
            let old: CounterRecord = decode(&self.storage.read("counters-before.json", 16384)?)?;
            if old.binding != binding
                || old.observed_us >= at
                || old.rules.as_bytes() != rules
                || filter
                    .outbound_deltas(old.labels.as_bytes(), &labels)
                    .is_none()
            {
                return Err(Error::Refused(
                    "counter baseline missing, changed or regressed",
                ));
            }
        } else if filter.outbound_deltas(&labels, &labels).is_none() {
            return Err(Error::Refused("initial labels do not match the four rules"));
        }
        let record = CounterRecord {
            binding,
            observed_us: at,
            rules: String::from_utf8(rules).map_err(io::Error::other)?,
            labels: String::from_utf8(labels).map_err(io::Error::other)?,
        };
        let name = if before {
            "counters-before.json"
        } else {
            "counters-after.json"
        };
        self.storage.write(
            name,
            &serde_json::to_vec(&record).map_err(io::Error::other)?,
        )
    }

    fn release(&self) -> Result<()> {
        if !self.storage.exists("enable")? {
            return Ok(());
        }
        if self.storage.exists("release")? {
            let previous = self.journal("release")?;
            if previous.is_single_closed_operation(Operation::ReleaseReference)? {
                self.snapshot()?;
                return Ok(());
            }
            return Err(Error::Refused("previous reference release is unconfirmed"));
        }
        let enable = self.journal("enable")?;
        if enable.state() == State::Ready && !self.storage.exists("enable-return.json")? {
            // A fresh journal with no mutation intent cannot have started pfctl.
            self.snapshot()?;
            return Ok(());
        }
        if !matches!(
            enable.state(),
            State::Intent(Operation::AcquireReference)
                | State::Unknown(Operation::AcquireReference)
        ) && !enable.is_single_closed_operation(Operation::AcquireReference)?
        {
            return Err(Error::Refused(
                "reference acquisition journal is unconfirmed",
            ));
        }
        let owner = self.recorded_reference()?;
        self.enabled(owner)?;
        let mut journal = Ledger::create(
            self.storage.subdir("release", true)?,
            self.session.nonce,
            self.session.phase_hash("release"),
        )?;
        let result = attached_reference::release_once(
            owner,
            || {
                self.attended().map_err(io::Error::other)?;
                self.recheck().map_err(io::Error::other)?;
                enable.check_named_objects().map_err(io::Error::other)?;
                journal
                    .begin(Operation::ReleaseReference)
                    .map_err(io::Error::other)
            },
            |returned| self.persist_reference("release", "release-return.json", returned),
        )
        .map_err(Error::from)
        .and_then(|()| self.snapshot().map(|_| ()));
        if let Err(error) = result {
            let _ = journal.unknown();
            return Err(error);
        }
        journal.observed()?;
        journal.close()
    }
}

impl root_hook_recovery::Boundary for Boundary<'_> {
    fn observe(&mut self) -> Result<View> {
        self.attended()?;
        let snap = self.snapshot()?;
        let hook = self
            .writer
            .observe()
            .map_err(|_| Error::Refused("native hook read failed"))?;
        let (after, _) = sync_observe::execute_program(
            "/sbin/pfctl",
            &["-s", "rules"],
            Instant::now() + Duration::from_secs(3),
        )?;
        if after != snap.root_rules {
            return Err(Error::Refused("hook and system readbacks changed"));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Error::Refused("observation sequence exhausted"))?;
        let leaf = match snap.leaf {
            Slot::Absent => Leaf::Absent,
            Slot::Empty => Leaf::Empty,
            Slot::Active(_) => Leaf::Other,
        };
        Ok(View {
            observation: Observation {
                identity: self.session.identity(),
                sequence: self.sequence,
                at_ms: now_ms()?,
                complete: true,
                // The local administrator attests continuous external exclusivity.
                // Held lock covers cooperating helpers. This controller performs all
                // mutations synchronously and its query children are read-only.
                exclusive: self.attended_until_ms.is_some(),
                writers_reclaimed: self.attended_until_ms.is_some(),
            },
            root_rules: snap.root_rules,
            foreign: snap.foreign,
            hook: hook.map(|row| {
                (
                    self.anchor.clone(),
                    Receipt {
                        index: row.index,
                        ticket: row.ticket,
                    },
                )
            }),
            leaf,
            states_and_sources_empty: snap.states_and_sources_empty,
        })
    }

    fn insert(&mut self, anchor: &str) -> Result<NonZeroU64> {
        self.attended()?;
        self.recheck()?;
        if anchor != self.anchor {
            return Err(Error::Refused("unexpected hook scope"));
        }
        self.writer
            .insert(self.session.index)
            .map_err(|_| Error::Refused("hook insert result unknown"))
    }

    fn remove(&mut self, anchor: &str, ticket: NonZeroU64) -> Result<()> {
        self.attended()?;
        self.recheck()?;
        if anchor != self.anchor {
            return Err(Error::Refused("unexpected hook scope"));
        }
        self.writer
            .remove(self.session.index, ticket)
            .map_err(|_| Error::Refused("hook remove result unknown"))
    }
}

fn operator(storage: &Storage) -> Result<(String, [u8; 32])> {
    if storage.executable() != PROGRAM {
        return Err(Error::Refused("wrong protected deployment"));
    }
    let manifest: Manifest = decode(&storage.read("operator-manifest.json", 512)?)?;
    let boot = sync_observe::boot()?;
    let helper = storage.program_digest()?;
    if manifest.mode != MODE || manifest.boot != boot || manifest.sha256 != hex(&helper) {
        return Err(Error::Refused(
            "operator manifest does not match boot or helper",
        ));
    }
    Ok((boot, helper))
}

fn prepare(storage: &Storage, raw: &[u8], boot: String, helper: [u8; 32]) -> Result<Value> {
    let mut nonce = [0; 32];
    File::open("/dev/urandom")?.read_exact(&mut nonce)?;
    let suffix = hex(&nonce[..16]);
    let filter = plan(raw, &suffix)?;
    for name in [
        "flow-plan.json",
        "session.json",
        "flow-lock",
        "hook",
        "stage",
        "recovery",
    ] {
        if storage.exists(name)? {
            return Err(Error::Refused("protected batch already has records"));
        }
    }
    let lock = lock(storage, true)?;
    let host = Host::open()?;
    let first = host.read(&filter.anchor(), &boot)?;
    if first.leaf != Slot::Absent
        || !first.enable_baseline_clear
        || host
            .writer(&suffix)?
            .observe()
            .map_err(|_| Error::Refused("hook read failed"))?
            .is_some()
    {
        return Err(Error::Refused("initial PF or leaf baseline is unsafe"));
    }
    let index = host
        .writer(&suffix)?
        .index()
        .map_err(|_| Error::Refused("root insertion position unavailable"))?;
    root_hook_readback::validate_index(
        root_hook_readback::Observation {
            bytes: &first.root_rules,
            complete: true,
        },
        &filter.anchor(),
        index as usize,
    )
    .map_err(Error::Refused)?;
    let session = Session {
        boot,
        helper,
        nonce,
        plan: sha(raw),
        lock_inode: check_lock(storage, &lock)?,
        controller_birth: birth()?,
        prepared_ms: now_ms()?,
        root: first.root_rules,
        index,
        foreign: first.foreign,
    };
    storage.write("flow-plan.json", raw)?;
    storage.write(
        "session.json",
        &serde_json::to_vec(&session).map_err(io::Error::other)?,
    )?;
    Ok(session.report(&filter, "prepared"))
}

fn run_action(storage: &Storage, action: Action, input: impl Read) -> Result<Value> {
    let (boot, helper) = operator(storage)?;
    if matches!(action, Action::Prepare) {
        return prepare(storage, &read_input(input, PLAN_LIMIT)?, boot, helper);
    }
    let confirm: &[u8] = match action {
        Action::Stage => b"STAGE-PF-FIRST-FLOW\n",
        Action::Activate => b"ACTIVATE-PF-FIRST-FLOW\n",
        Action::Recover => b"RECOVER-PF-FIRST-FLOW\n",
        _ => b"",
    };
    let attended_until_ms = if confirm.is_empty() {
        None
    } else {
        if read_input(input, confirm.len())? != confirm {
            return Err(Error::Refused("missing attended batch confirmation"));
        }
        Some(
            now_ms()?
                .checked_add(90_000)
                .ok_or(Error::Refused("invalid action deadline"))?,
        )
    };
    let held = lock(storage, false)?;
    let session: Session = decode(&storage.read("session.json", SESSION_LIMIT)?)?;
    let raw = storage.read("flow-plan.json", PLAN_LIMIT)?;
    if session.boot != boot
        || session.helper != helper
        || session.plan != sha(&raw)
        || session.lock_inode != check_lock(storage, &held)?
    {
        return Err(Error::Refused("protected batch identity changed"));
    }
    let suffix = session.suffix();
    let filter = plan(&raw, &suffix)?;
    let host = Host::open()?;
    let mut boundary = Boundary {
        storage,
        lock: &held,
        host: &host,
        session: &session,
        anchor: filter.anchor(),
        writer: host.writer(&suffix)?,
        sequence: 0,
        attended_until_ms,
    };
    let anchor = filter.anchor();
    let mut trial = Trial::new(
        Guard::protected(session.identity(), now_ms()?).map_err(|e| Error::Refused(e.0))?,
        &anchor,
        &session.root,
        session.index,
        session.foreign,
    )?;
    if matches!(action, Action::Recover) {
        boundary.release()?;
    }
    if matches!(action, Action::Status)
        && storage.exists("enable")?
        && !storage.exists("release")?
        && let Ok(owner) = boundary.recorded_reference()
        && boundary.enabled(owner).is_ok()
    {
        return Ok(session.report(&filter, "reference_held"));
    }
    if matches!(action, Action::CountersBefore | Action::CountersAfter) {
        let directory = storage.subdir("hook", false)?;
        let (_hook_stage, hook) = trial.creation_record(&directory)?;
        let before = matches!(action, Action::CountersBefore);
        boundary.counters(&filter, hook, before)?;
        return Ok(session.report(
            &filter,
            if before {
                "counters_before_recorded"
            } else {
                "counters_after_recorded"
            },
        ));
    }
    let initial = boundary.snapshot()?;
    let phase = match action {
        Action::Stage => {
            if now_ms()?
                .checked_sub(session.prepared_ms)
                .is_none_or(|age| age >= 300_000)
                || storage.exists("hook")?
                || storage.exists("stage")?
                || storage.exists("recovery")?
                || !initial.enable_baseline_clear
                || initial.root_rules != session.root
            {
                return Err(Error::Refused(
                    "batch staging window or PF baseline changed",
                ));
            }
            let directory = storage.subdir("hook", true)?;
            trial.attach(&directory, &mut boundary)?;
            let (hook_stage, hook) = trial.verified_creation(&directory, &mut boundary, true)?;
            boundary.filter_change("stage", &filter, hook, true)?;
            hook_stage.check_named_objects()?;
            "hook_and_filter_verified"
        }
        Action::Activate => {
            let directory = storage.subdir("hook", false)?;
            let (_hook_stage, hook) = trial.creation_record(&directory)?;
            boundary.activate(&filter, hook)?;
            "reference_held"
        }
        Action::Recover => {
            let directory = storage.subdir("hook", false)?;
            let (hook_stage, hook) = trial.verified_creation(&directory, &mut boundary, false)?;
            if storage.exists("stage")? {
                let filter_stage = boundary.journal("stage")?;
                if !matches!(
                    filter_stage.state(),
                    State::Intent(Operation::WriteFilter) | State::Unknown(Operation::WriteFilter)
                ) && !filter_stage.is_single_closed_operation(Operation::WriteFilter)?
                {
                    return Err(Error::Refused("filter stage has no recoverable intent"));
                }
                if storage.exists("recovery")? {
                    let previous = boundary.journal("recovery")?;
                    if !previous.is_single_closed_operation(Operation::WriteFilter)?
                        || initial.leaf != Slot::Empty
                    {
                        return Err(Error::Refused("previous filter recovery is unconfirmed"));
                    }
                } else {
                    boundary.filter_change("recovery", &filter, hook, false)?;
                }
                filter_stage.check_named_objects()?;
            } else if initial.leaf != Slot::Empty {
                return Err(Error::Refused("unjournaled leaf change"));
            }
            hook_stage.check_named_objects()?;
            drop(hook_stage);
            trial.detach(&directory, &mut boundary)?;
            "restored"
        }
        Action::Status => {
            if !storage.exists("hook")? {
                if initial.leaf != Slot::Absent || initial.root_rules != session.root {
                    return Err(Error::Refused("prepared PF baseline changed"));
                }
                "prepared"
            } else {
                let directory = storage.subdir("hook", false)?;
                if initial.root_rules == session.root
                    && matches!(initial.leaf, Slot::Absent | Slot::Empty)
                    && initial.states_and_sources_empty
                    && trial.removal_verified(&directory)?
                {
                    "restored"
                } else if matches!(initial.leaf, Slot::Active(ref raw) if filter.matches_observed(raw))
                    && !storage.exists("recovery")?
                    && trial
                        .creation_record(&directory)
                        .and_then(|(_, hook)| {
                            boundary.match_root(&initial.root_rules, hook)?;
                            boundary.same_hook(hook)
                        })
                        .unwrap_or(false)
                    && boundary
                        .journal("stage")
                        .and_then(|ledger| {
                            ledger.is_single_closed_operation(Operation::WriteFilter)
                        })
                        .unwrap_or(false)
                {
                    "hook_and_filter_verified"
                } else {
                    "unsettled"
                }
            }
        }
        Action::Prepare | Action::CountersBefore | Action::CountersAfter => {
            return Err(Error::Refused("unexpected batch action"));
        }
    };
    Ok(session.report(&filter, phase))
}

fn run() -> Result<Value> {
    let action = Action::parse(std::env::args_os().skip(1))?;
    run_action(&Storage::open()?, action, io::stdin().lock())
}

fn main() -> ExitCode {
    match run() {
        Ok(report) => {
            println!("{report}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            let reason: String = error
                .to_string()
                .chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect();
            println!("{}", json!({"result":"refused","reason":reason}));
            ExitCode::FAILURE
        }
    }
}
