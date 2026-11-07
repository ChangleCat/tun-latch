//! Explicit, ordinary-user process diagnostics, never TUN ownership or authorization.

use anyhow::bail;
use tunlatch_core::binding::CodeIdentity;
use tunlatch_platform::identity::{
    ImageInspection, ProcessInspection, RawInspection, TunnelCandidate, inspect_expected_cdhash,
    inspect_process, inspect_selected_process, inspect_tunnel_candidate,
};

pub(crate) fn parse_cdhash(text: &str) -> Result<[u8; 20], String> {
    let invalid = || "CDHash must contain exactly 40 hexadecimal digits and be nonzero".to_owned();
    if text.len() != 40 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let digit = |byte: u8| match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0, // ASCII hexadecimal input was checked before decoding.
    };
    let mut expected = [0; 20];
    for (out, pair) in expected.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *out = digit(pair[0]) * 16 + digit(pair[1]);
    }
    if expected == [0; 20] {
        return Err(invalid());
    }
    Ok(expected)
}

pub(crate) async fn correlate(pid: u32, expected: [u8; 20], json: bool) -> anyhow::Result<()> {
    let candidate =
        match tokio::task::spawn_blocking(move || inspect_tunnel_candidate(pid, expected)).await {
            Ok(result) => result.map_err(|error| error.kind()),
            Err(_) => Err("worker_unavailable"),
        };
    let (success, result) = correlation_result(candidate, expected);
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if success {
        println!(
            "Candidate: process {}; FD {}; interface {} (index {}); control ID {}; unit {}",
            result["process"]["pid"],
            result["fd"],
            result["ifname"].as_str().unwrap_or(""),
            result["ifindex"],
            result["control_id"],
            result["unit"]
        );
        println!("Basis: utun control unit minus one; expected CDHash matched.");
        println!("TUN ownership and actual protection remain UNKNOWN; authorization: none.");
    } else {
        println!(
            "Candidate unavailable: {}",
            result["reason"].as_str().unwrap_or("unknown")
        );
        println!("TUN ownership and actual protection remain UNKNOWN; authorization: none.");
    }
    if !success {
        bail!("candidate correlation unavailable; no trust granted");
    }
    Ok(())
}

fn correlation_result(
    candidate: Result<TunnelCandidate, &'static str>,
    expected: [u8; 20],
) -> (bool, serde_json::Value) {
    let candidate = match candidate {
        Ok(candidate) => candidate,
        Err(reason) => {
            return (
                false,
                serde_json::json!({
                    "result": "unavailable", "reason": reason,
                    "tun_ownership": "unknown", "actual_protection": "unknown", "authorization": "none",
                }),
            );
        }
    };
    (
        true,
        serde_json::json!({
            "result": "candidate", "basis": "utun_control_unit_minus_one",
            "process": {"pid": candidate.process.pid, "effective_uid": candidate.process.uid,
                "birth_seconds": candidate.process.birth_seconds,
                "birth_microseconds": candidate.process.birth_microseconds},
            "fd": candidate.fd, "control_id": candidate.control_id, "unit": candidate.unit,
            "ifname": candidate.ifname, "ifindex": candidate.ifindex,
            "sampling_milliseconds": candidate.elapsed.as_millis(),
            "matched_expected_code_identity": CodeIdentity::CodeDirectoryHash(expected),
            "tun_ownership": "unknown", "actual_protection": "unknown", "authorization": "none",
        }),
    )
}

pub(crate) async fn check_image(pid: u32, expected: [u8; 20], json: bool) -> anyhow::Result<()> {
    let inspection =
        tokio::task::spawn_blocking(move || inspect_expected_cdhash(pid, expected)).await?;
    let (matched, result) = image_result(inspection);
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Running code requirement: {}", result["result"]);
        println!("Diagnostic only. TUN ownership and actual protection remain UNKNOWN.");
    }
    if !matched {
        bail!("running code requirement did not match or could not be checked; no trust granted");
    }
    Ok(())
}

fn image_result(inspection: ImageInspection) -> (bool, serde_json::Value) {
    let matched = matches!(&inspection, ImageInspection::Matched { .. });
    let mut result = serde_json::json!({
        "actual_protection": "unknown", "tun_ownership": "unknown",
        "authorization": "none", "continuous_image_identity": "unverified",
        "fingerprint_kind": "cdhash_20_bytes",
    });
    if let ImageInspection::Matched {
        expected_cdhash, ..
    } = &inspection
    {
        result["matched_expected_code_identity"] =
            serde_json::json!(CodeIdentity::CodeDirectoryHash(*expected_cdhash));
    }
    let matched = match inspection {
        ImageInspection::Matched { process, .. } | ImageInspection::Mismatched { process } => {
            result["result"] = if matched { "matched" } else { "mismatched" }.into();
            result["process"] = serde_json::json!({
                "pid": process.pid, "effective_uid": process.uid,
                "birth_seconds": process.birth_seconds,
                "birth_microseconds": process.birth_microseconds,
            });
            matched
        }
        ImageInspection::Unavailable { problem, status } => {
            result["result"] = "unavailable".into();
            result["problem"] = format!("{problem:?}").into();
            result["security_status"] = status.into();
            false
        }
    };
    (matched, result)
}

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

#[cfg(test)]
mod image_tests {
    use super::*;
    use tunlatch_platform::identity::{ImageProblem, ProcessIdentity};

    #[test]
    fn correlation_output_preserves_candidate_and_unavailable_boundaries() {
        let candidate = TunnelCandidate {
            process: ProcessIdentity {
                pid: 42,
                uid: 501,
                birth_seconds: 1,
                birth_microseconds: 2,
            },
            fd: 3,
            control_id: 4,
            unit: 5,
            ifname: "utun4".into(),
            ifindex: 6,
            elapsed: std::time::Duration::from_millis(7),
        };
        let (success, result) = correlation_result(Ok(candidate), [1; 20]);
        assert!(success);
        assert_eq!(result["result"], "candidate");
        assert_eq!(result["basis"], "utun_control_unit_minus_one");
        assert_eq!(
            result["matched_expected_code_identity"],
            serde_json::json!(CodeIdentity::CodeDirectoryHash([1; 20]))
        );
        assert_eq!(result["ifname"], "utun4");
        let (success, unavailable) = correlation_result(Err("image_mismatch"), [1; 20]);
        assert!(!success);
        assert_eq!(unavailable["result"], "unavailable");
        assert_eq!(unavailable["reason"], "image_mismatch");
        for output in [result, unavailable] {
            assert_eq!(output["tun_ownership"], "unknown");
            assert_eq!(output["actual_protection"], "unknown");
            assert_eq!(output["authorization"], "none");
            assert!(output.get("path").is_none());
            assert!(output.get("addresses").is_none());
            assert!(output.get("controls").is_none());
        }
    }

    #[test]
    fn rejects_unbounded_nonhex_zero_and_whole_file_digest_inputs() {
        for invalid in [
            "",
            "01",
            &"0".repeat(40),
            &"1".repeat(64),
            &"g".repeat(40),
            &"é".repeat(20),
            &"1".repeat(4096),
            "00112233445566778899aabbccddeeff0011223 ",
        ] {
            assert!(parse_cdhash(invalid).is_err());
        }
        let expected = [
            0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0, 0x11, 0x22, 0x33,
        ];
        assert_eq!(
            parse_cdhash("00112233445566778899aabbccddeeff00112233"),
            Ok(expected)
        );
        assert_eq!(
            parse_cdhash("00112233445566778899AABBCCDDEEFF00112233"),
            Ok(expected)
        );
    }

    #[test]
    fn only_a_match_succeeds_and_every_result_preserves_the_trust_boundary() {
        let process = ProcessIdentity {
            pid: 42,
            uid: 501,
            birth_seconds: 1,
            birth_microseconds: 0,
        };
        for (inspection, expected_success, expected_result) in [
            (
                ImageInspection::Matched {
                    process: process.clone(),
                    expected_cdhash: [1; 20],
                },
                true,
                "matched",
            ),
            (ImageInspection::Mismatched { process }, false, "mismatched"),
            (
                ImageInspection::Unavailable {
                    problem: ImageProblem::SecurityUnavailable,
                    status: Some(-1),
                },
                false,
                "unavailable",
            ),
        ] {
            let (success, result) = image_result(inspection);
            assert_eq!(success, expected_success);
            assert_eq!(result["result"], expected_result);
            assert_eq!(result["actual_protection"], "unknown");
            assert_eq!(result["tun_ownership"], "unknown");
            assert_eq!(result["authorization"], "none");
            assert!(result.get("loaded_image_sha256").is_none());
            assert!(result.get("path").is_none());
            if expected_success {
                assert_eq!(
                    result["matched_expected_code_identity"],
                    serde_json::json!(CodeIdentity::CodeDirectoryHash([1; 20])),
                );
            } else {
                assert!(result.get("matched_expected_code_identity").is_none());
            }
            if expected_result == "unavailable" {
                assert!(result.get("process").is_none());
            }
        }
    }
}
