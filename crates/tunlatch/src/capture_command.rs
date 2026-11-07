//! Compare a bounded ordinary-user capture directory with an offline PF candidate.

use std::{
    fs::File,
    io::Read,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, bail};
use nix::{
    fcntl::{OFlag, openat},
    sys::stat::Mode,
};
use serde::Deserialize;
use serde_json::json;
use tunlatch_platform::{
    pf_observe::{
        LiteralAnchor, MAX_CAPTURE_FILE_BYTES, MAX_CAPTURE_QUERIES, MAX_CAPTURE_TOTAL_BYTES,
        verify_readonly_captures,
    },
    policy_compile::compile_candidate,
};

#[derive(Deserialize)]
struct Summary {
    purpose: String,
    started_unix: u64,
    queries: Vec<QueryFile>,
}

#[derive(Deserialize)]
struct QueryFile {
    file: String,
}

fn read_at(directory: &File, name: &str, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let file: File = openat(
        directory,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .with_context(|| format!("cannot open capture file {name}"))?
    .into();
    if !file.metadata()?.is_file() {
        bail!("capture file must be regular: {name}");
    }
    let mut bytes = Vec::new();
    file.take(max_bytes as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        bail!("capture file exceeds its byte limit: {name}");
    }
    Ok(bytes)
}

/// Inspect existing captures and return a nonzero status for unknown or mismatched evidence.
pub fn verify(
    source: &Path,
    capture_dir: &Path,
    anchor: &str,
    max_age_secs: u64,
    json_output: bool,
) -> anyhow::Result<()> {
    if nix::unistd::Uid::effective().is_root() {
        bail!("capture verification requires an ordinary user");
    }
    let anchor = LiteralAnchor::new(anchor)?;
    let candidate = compile_candidate(&crate::config_command::draft(source)?)?;
    let directory = File::options()
        .read(true)
        .custom_flags(
            nix::libc::O_DIRECTORY
                | nix::libc::O_NOFOLLOW
                | nix::libc::O_NONBLOCK
                | nix::libc::O_CLOEXEC,
        )
        .open(capture_dir)
        .context("cannot open real capture directory")?;
    // Summary is only an index and untrusted time label. The platform adapter validates each
    // raw query and the complete fixed schedule independently.
    let summary: Summary = serde_json::from_slice(&read_at(&directory, "summary.json", 65_536)?)?;
    if summary.purpose != "readonly_pf_preflight" || summary.queries.len() > MAX_CAPTURE_QUERIES {
        bail!("unsupported capture summary");
    }
    let mut files = Vec::new();
    let mut remaining = MAX_CAPTURE_TOTAL_BYTES;
    for (index, query) in summary.queries.iter().enumerate() {
        let name = format!("query-{:02}.json", index + 1);
        if query.file != name {
            bail!("capture summary has an unexpected query filename");
        }
        let bytes = read_at(&directory, &name, remaining.min(MAX_CAPTURE_FILE_BYTES))?;
        remaining -= bytes.len();
        files.push(bytes);
    }
    let file_slices: Vec<_> = files.iter().map(Vec::as_slice).collect();
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let report = verify_readonly_captures(
        &candidate,
        &anchor,
        &file_slices,
        summary.started_unix,
        now,
        max_age_secs,
    )?;
    let output = json!({
        "observation": report, "actual_protection": "unknown", "authorization": "none",
        "pf_operations": 0, "network_changes": false,
    });
    if !json_output {
        println!("Offline PF capture comparison.");
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    bail!("capture provides no current enforcement verification");
}
