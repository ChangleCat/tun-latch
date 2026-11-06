//! Single-PID read-only diagnostic, intended only for a separately protected staging path.

use std::{ffi::OsStr, io::Write, process::ExitCode};

use serde_json::{Value, json};
use tunlatch_platform::identity::{RawInspection, inspect_selected_process_privileged};

fn main() -> ExitCode {
    let mut args = std::env::args_os();
    let _program = args.next();
    let pid = match (args.next(), args.next(), args.next()) {
        (Some(flag), Some(value), None) if flag == OsStr::new("--pid") => value
            .to_str()
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|pid| *pid > 0 && i32::try_from(*pid).is_ok()),
        _ => None,
    };
    let (response, success) = match pid {
        Some(pid) => render(inspect_selected_process_privileged(pid)),
        None => (
            json!({"result":"incomplete", "stage":"Input", "problem":"InvalidArguments",
                "errno":null, "actual_protection":"unknown", "tun_ownership":"unknown"}),
            false,
        ),
    };
    let mut output = std::io::stdout().lock();
    if serde_json::to_writer(&mut output, &response).is_err() || writeln!(output).is_err() {
        return ExitCode::FAILURE;
    }
    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn render(inspection: RawInspection) -> (Value, bool) {
    match inspection {
        RawInspection::CompleteRaw(raw) => {
            let fds: Vec<_> = raw
                .fds
                .iter()
                .map(|fd| json!({"fd":fd.fd,"kind":fd.kind}))
                .collect();
            let controls: Vec<_> = raw
                .controls
                .iter()
                .map(|control| {
                    json!({
                        "fd":control.fd,"name":control.name,"id":control.id,"unit":control.unit,
                    })
                })
                .collect();
            (
                json!({
                    "result":"complete_raw", "process":{
                        "pid":raw.process.pid, "effective_uid":raw.process.uid,
                        "birth_seconds":raw.process.birth_seconds,
                        "birth_microseconds":raw.process.birth_microseconds,
                    }, "fds":fds, "controls":controls,
                    "actual_protection":"unknown", "tun_ownership":"unknown",
                }),
                true,
            )
        }
        RawInspection::Unavailable(failure)
        | RawInspection::Partial(failure)
        | RawInspection::Error(failure) => (
            json!({"result":"incomplete", "stage":format!("{:?}",failure.stage),
                "problem":format!("{:?}",failure.problem), "errno":failure.errno,
                "actual_protection":"unknown", "tun_ownership":"unknown"}),
            false,
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use tunlatch_platform::identity::{ProcessIdentity, RawControl, RawFd, RawObservation};

    #[test]
    fn complete_output_omits_opaque_values() {
        let now = Instant::now();
        let (output, success) = render(RawInspection::CompleteRaw(RawObservation {
            process: ProcessIdentity {
                pid: 42,
                uid: 0,
                birth_seconds: 10,
                birth_microseconds: 20,
            },
            fds: vec![RawFd { fd: 3, kind: 2 }],
            controls: vec![RawControl {
                fd: 3,
                name: "com.example.control".into(),
                id: 7,
                unit: 8,
                socket: 123456789,
                pcb: 987654321,
            }],
            started_at: now,
            finished_at: now,
            expires_at: now + Duration::from_secs(1),
        }));
        assert!(success);
        assert_eq!(output["result"], "complete_raw");
        assert_eq!(
            output["controls"][0],
            json!({"fd":3,"name":"com.example.control","id":7,"unit":8})
        );
        assert_eq!(output["actual_protection"], "unknown");
        assert_eq!(output["tun_ownership"], "unknown");
        let encoded = output.to_string();
        assert!(!encoded.contains("123456789"));
        assert!(!encoded.contains("987654321"));
    }
}
