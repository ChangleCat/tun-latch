//! Explicit, ordinary-user process diagnostics, never TUN ownership or authorization.

use anyhow::bail;
use tunlatch_platform::identity::{
    ProcessInspection, RawInspection, inspect_process, inspect_selected_process,
};

pub(crate) async fn inspect(pid: u32, json: bool, fd_details: bool) -> anyhow::Result<()> {
    if fd_details {
        return inspect_fds(pid, json).await;
    }
    let inspection = tokio::task::spawn_blocking(move || inspect_process(pid)).await?;
    match inspection {
        ProcessInspection::Partial(process) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "result": "partial", "process": {
                            "pid": process.pid, "effective_uid": process.uid,
                            "birth_seconds": process.birth_seconds,
                            "birth_microseconds": process.birth_microseconds,
                        }, "tun_ownership": "unknown", "loaded_image": "unverified",
                        "actual_protection": "unknown",
                    }))?
                );
            } else {
                println!(
                    "Process {}: UID {}; born {}.{:06}",
                    process.pid, process.uid, process.birth_seconds, process.birth_microseconds
                );
                println!(
                    "Partial observation only. TUN ownership and actual protection remain UNKNOWN."
                );
            }
            Ok(())
        }
        ProcessInspection::Unavailable(failure) | ProcessInspection::Error(failure) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "result": "unavailable", "stage": format!("{:?}", failure.stage),
                        "problem": format!("{:?}", failure.problem), "errno": failure.errno,
                        "tun_ownership": "unknown", "actual_protection": "unknown",
                    }))?
                );
            }
            bail!("process inspection incomplete: {failure}; TUN ownership remains unknown")
        }
    }
}

async fn inspect_fds(pid: u32, json: bool) -> anyhow::Result<()> {
    let inspection = tokio::task::spawn_blocking(move || inspect_selected_process(pid)).await?;
    match inspection {
        RawInspection::CompleteRaw(raw) => {
            if json {
                let fds: Vec<_> = raw
                    .fds
                    .iter()
                    .map(|fd| serde_json::json!({"fd":fd.fd,"kind":fd.kind}))
                    .collect();
                let controls: Vec<_> = raw
                    .controls
                    .iter()
                    .map(|ctl| {
                        serde_json::json!({
                            "fd":ctl.fd,"name":ctl.name,"id":ctl.id,"unit":ctl.unit,
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "result":"complete_raw", "process": {
                            "pid":raw.process.pid,"effective_uid":raw.process.uid,
                            "birth_seconds":raw.process.birth_seconds,
                            "birth_microseconds":raw.process.birth_microseconds,
                        }, "fds":fds,"controls":controls,
                        "sampling_milliseconds":raw.finished_at.saturating_duration_since(raw.started_at).as_millis(),
                        "tun_ownership":"unknown","loaded_image":"unverified",
                        "actual_protection":"unknown","opaque_kernel_values_omitted":true,
                    }))?
                );
            } else {
                println!(
                    "Process {}: UID {}; {} descriptors, {} kernel-control records",
                    raw.process.pid,
                    raw.process.uid,
                    raw.fds.len(),
                    raw.controls.len()
                );
                for descriptor in &raw.fds {
                    println!("  FD {}: native type {}", descriptor.fd, descriptor.kind);
                }
                for control in &raw.controls {
                    println!(
                        "  Control FD {}: name {:?}; id {}; unit {}",
                        control.fd, control.name, control.id, control.unit
                    );
                }
                println!(
                    "Raw sampling completed. TUN ownership and actual protection remain UNKNOWN."
                );
            }
            Ok(())
        }
        RawInspection::Unavailable(failure)
        | RawInspection::Partial(failure)
        | RawInspection::Error(failure) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "result":"incomplete","stage":format!("{:?}",failure.stage),
                        "problem":format!("{:?}",failure.problem),"errno":failure.errno,
                        "tun_ownership":"unknown","actual_protection":"unknown",
                    }))?
                );
            }
            bail!("raw inspection incomplete: {failure}; no trusted identity established")
        }
    }
}
