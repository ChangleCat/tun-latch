//! Ordinary-user operator tool. Only system sudo/env/pfctl receive elevation, with closed
//! read-only arguments. This is not a privileged project helper or PF recovery authority.

use std::collections::{BTreeSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::process::{self, Completion, Limits, Observation, Probe, ReadAnchor, ReadQuery, Reason};

#[derive(Debug, Error)]
pub(crate) enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Process(#[from] process::Error),
    #[error("read-only preflight refused: {0}")]
    Refused(&'static str),
}
pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) const QUERIES: [ReadQuery; 10] = [
    ReadQuery::Rules,
    ReadQuery::Nat,
    ReadQuery::Anchors,
    ReadQuery::Interfaces,
    ReadQuery::Info,
    ReadQuery::References,
    ReadQuery::Rules,
    ReadQuery::Nat,
    ReadQuery::References,
    ReadQuery::Anchors,
];
const MAX_ANCHORS: usize = 16;
const MAX_QUERIES: usize = 58;
const ALTQ_NOTICE: &[u8] = b"No ALTQ support in kernel\nALTQ related functions disabled\n";

pub(crate) fn plan() -> Value {
    json!({
        "purpose": "readonly_pf_preflight", "pf_write_operations": 0,
        "network_changes": false, "captures_or_probes": false,
        "privileged_programs": ["/usr/bin/sudo", "/usr/bin/env", "/sbin/pfctl"],
        "queries": QUERIES.iter().map(|q| json!({"query": format!("{q:?}"), "pfctl_argv": q.args()})).collect::<Vec<_>>(),
        "literal_anchor_reads": {"max_anchors": MAX_ANCHORS, "max_total_queries": MAX_QUERIES,
            "action": "Read rules, nat and Tables for each validated literal in the first Anchors inventory; require final inventory equal.",
            "wildcards": false, "unknown_stderr": "incomplete and stop; the exact recorded ALTQ notice is preserved as a notice"},
        "per_query_limits": {"run_seconds": 3, "reclaim_seconds": 1, "combined_output_bytes": 65536},
        "limits": ["Independent reads are not an atomic PF snapshot.", "No PF feasibility, no-leak, ownership or recovery qualification.", "sudo natural-return contract is trusted for the fixed pfctl child; cancellation leaves reclamation unknown."]
    })
}

pub(crate) fn anchor_inventory(bytes: &[u8]) -> Result<BTreeSet<ReadAnchor>> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::Refused("non UTF-8 anchor inventory"))?;
    if bytes.len() > 65536 || (!text.is_empty() && !text.ends_with('\n')) {
        return Err(Error::Refused("incomplete anchor inventory"));
    }
    let mut names = BTreeSet::new();
    for line in text.lines() {
        let name = ReadAnchor::new(line.trim_ascii())?;
        if !names.insert(name) || names.len() > MAX_ANCHORS {
            return Err(Error::Refused("duplicate or excessive anchor inventory"));
        }
    }
    for name in &names {
        if let Some((parent, _)) = name.name().rsplit_once('/')
            && !names.contains(&ReadAnchor::new(parent)?)
        {
            return Err(Error::Refused("missing parent in anchor inventory"));
        }
    }
    Ok(names)
}

pub(crate) trait Reader {
    fn read(&mut self, query: ReadQuery) -> Result<Completion>;
}

pub(crate) struct SystemReader;
impl Reader for SystemReader {
    fn read(&mut self, query: ReadQuery) -> Result<Completion> {
        let limits = Limits::new(Duration::from_secs(3), Duration::from_secs(1), 65536)?;
        let ticket = process::start(Probe::PrivilegedRead(query), Vec::new(), limits)?;
        let observation = ticket.wait(Duration::from_secs(5))?;
        if observation != Observation::Reclaimed {
            ticket.cancel();
            return Err(Error::Refused(
                "query cancellation/reclamation unknown; no further queries",
            ));
        }
        Ok(process::collect(ticket.id())?)
    }
}

fn hash(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn executable_snapshot() -> Result<Value> {
    let path = std::env::current_exe()?;
    file_snapshot(&path)
}

fn file_snapshot(path: &Path) -> Result<Value> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > 64 * 1024 * 1024 {
        return Err(Error::Refused("invalid candidate executable snapshot"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(before.len() + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || (before.ctime(), before.ctime_nsec()) != (after.ctime(), after.ctime_nsec())
    {
        return Err(Error::Refused("candidate path changed while reading"));
    }
    Ok(json!({"path": path, "path_snapshot_sha256": hash(&bytes), "loaded_image_attested": false}))
}

fn system_tool_snapshot(path: &Path) -> Value {
    match file_snapshot(path) {
        Ok(snapshot) => snapshot,
        Err(_) => {
            json!({"path": path, "path_snapshot_status": "unavailable_without_extra_authority", "loaded_image_attested": false})
        }
    }
}

fn write_new(dir: &File, name: &str, value: &Value) -> Result<()> {
    let flags =
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut file: File = openat(dir, name, flags, Mode::from_bits_truncate(0o600))
        .map_err(std::io::Error::from)?
        .into();
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(Error::Refused("new report owner/type/links/mode mismatch"));
    }
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    dir.sync_all()?;
    Ok(())
}

pub(crate) fn collect(path: &Path, reader: &mut impl Reader) -> Result<Value> {
    if nix::unistd::geteuid().is_root() || !path.is_absolute() {
        return Err(Error::Refused(
            "run as the ordinary user with an absolute private directory",
        ));
    }
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = dir.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o7777 != 0o700
        || !exacl::getfacl(path, None)?.is_empty()
        || std::fs::read_dir(path)?.next().is_some()
    {
        return Err(Error::Refused(
            "existing empty, owned 0700 real directory required",
        ));
    }
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Refused("clock before epoch"))?
        .as_secs();
    let mut system_file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open("/System/Library/CoreServices/SystemVersion.plist")?;
    let mut system_version = Vec::new();
    Read::by_ref(&mut system_file)
        .take(16385)
        .read_to_end(&mut system_version)?;
    if system_version.len() > 16384 {
        return Err(Error::Refused("system version metadata exceeds limit"));
    }
    write_new(
        &dir,
        "collection-intent.json",
        &json!({"started_unix": started, "plan": plan(), "candidate": executable_snapshot()?,
            "uid": nix::unistd::geteuid().as_raw(), "compiled_arch": std::env::consts::ARCH,
            "system_version_plist": String::from_utf8_lossy(&system_version), "system_version_sha256": hash(&system_version),
            "system_tools": [system_tool_snapshot(Path::new("/usr/bin/sudo")), system_tool_snapshot(Path::new("/usr/bin/env")), system_tool_snapshot(Path::new("/sbin/pfctl"))]}),
    )?;
    let mut outcomes = Vec::new();
    let mut complete = true;
    let mut saw_warnings = false;
    let mut pending: VecDeque<_> = QUERIES.into_iter().collect();
    let mut inventory: Option<BTreeSet<ReadAnchor>> = None;
    for index in 0..MAX_QUERIES {
        let Some(query) = pending.pop_front() else {
            break;
        };
        match reader.read(query) {
            Ok(result) => {
                let transport_complete =
                    matches!(result.reason, Reason::Success | Reason::ExitFailure)
                        && !result.truncated
                        && !result.capture_failed
                        && !result.kill_failed
                        && result.parent_reaped
                        && result.pipes_closed
                        && result.descendants_known_leaf
                        && result.input_written == 0
                        && std::str::from_utf8(&result.stdout).is_ok()
                        && std::str::from_utf8(&result.stderr).is_ok()
                        && result.stdout.len().saturating_add(result.stderr.len()) <= 65536;
                let known_notice = result.stderr == ALTQ_NOTICE;
                let stderr_ok = result.stderr.is_empty() || known_notice;
                let mut valid = transport_complete && result.reason == Reason::Success && stderr_ok;
                // A fully returned, bounded pfctl error is diagnostic data. Continue other
                // independent READS, never promote a failed ruleset to empty/success.
                // Authentication, transport and inventory errors stop the batch.
                let reported_pf_error = result
                    .stderr
                    .strip_prefix(ALTQ_NOTICE)
                    .unwrap_or(&result.stderr)
                    .starts_with(b"pfctl: ");
                let continue_independent_reads =
                    transport_complete && reported_pf_error && query != ReadQuery::Anchors;
                let mut diagnostic = if !transport_complete {
                    "transport_incomplete"
                } else if result.reason != Reason::Success {
                    "command_failed"
                } else if !stderr_ok {
                    "unrecognized_stderr"
                } else {
                    "captured"
                };
                saw_warnings |= !result.stderr.is_empty();
                if valid && query == ReadQuery::Anchors {
                    match anchor_inventory(&result.stdout) {
                        Ok(names) => {
                            if let Some(before) = &inventory {
                                if before != &names {
                                    valid = false;
                                    diagnostic = "anchor_inventory_changed";
                                }
                            } else {
                                let mut details = Vec::new();
                                for anchor in &names {
                                    details.extend([
                                        ReadQuery::AnchorRules(*anchor),
                                        ReadQuery::AnchorNat(*anchor),
                                        ReadQuery::AnchorTables(*anchor),
                                    ]);
                                }
                                for detail in details.into_iter().rev() {
                                    pending.push_front(detail);
                                }
                                inventory = Some(names);
                            }
                        }
                        Err(_) => {
                            valid = false;
                            diagnostic = "anchor_inventory_invalid";
                        }
                    }
                }
                let raw = json!({"query": format!("{query:?}"), "pfctl_argv": query.args(),
                    "reason": format!("{:?}", result.reason), "stdout": String::from_utf8_lossy(&result.stdout),
                    "stderr": String::from_utf8_lossy(&result.stderr), "truncated": result.truncated,
                    "capture_failed": result.capture_failed, "parent_reaped": result.parent_reaped,
                    "pipes_closed": result.pipes_closed, "command_tree_reclaimed": result.descendants_known_leaf,
                    "diagnostic": diagnostic, "recognized_altq_notice": known_notice,
                    "stdout_sha256": hash(&result.stdout), "stderr_sha256": hash(&result.stderr)});
                let name = format!("query-{:02}.json", index + 1);
                write_new(&dir, &name, &raw)?;
                outcomes.push(json!({"query": format!("{query:?}"), "file": name,
                    "status": if valid { "captured" } else { "incomplete" }, "diagnostic": diagnostic,
                    "stderr_present": !result.stderr.is_empty(), "recognized_altq_notice": known_notice,
                    "stdout_bytes": result.stdout.len(), "stderr_bytes": result.stderr.len()}));
                if !valid {
                    complete = false;
                    if !continue_independent_reads {
                        break;
                    }
                }
            }
            Err(_) => {
                complete = false;
                outcomes.push(json!({"query": format!("{query:?}"), "status": "unknown_stopped",
                    "details": "No further query or PF cleanup attempted; retain the collection directory."}));
                break;
            }
        }
    }
    if !pending.is_empty() {
        complete = false;
    }
    let summary = json!({"purpose": "readonly_pf_preflight", "result": if complete { "captured_requires_review" } else { "incomplete" },
        "output_directory": path, "started_unix": started, "queries": outcomes,
        "literal_anchor_count": inventory.as_ref().map(BTreeSet::len),
        "stderr_requires_review": saw_warnings, "pf_write_operations": 0, "network_changes": false,
        "PF_feasibility_passed": false, "recovery_qualified": false,
        "sharing": "Summary omits raw rules, addresses and enable tokens. Raw query files stay local.",
        "limitations": "Reads are non-atomic; this is not PF protection, a privileged writer or a recovery tool."});
    write_new(&dir, "summary.json", &summary)?;
    Ok(summary)
}
