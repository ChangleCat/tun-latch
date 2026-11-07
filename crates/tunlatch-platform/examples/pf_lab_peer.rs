//! Ordinary-user controlled single-nonce TCP/UDP peer. No PF or capture operations.
#[path = "../tests/pf_lab/peer_transport.rs"]
mod peer_transport;

use nix::unistd::Uid;
use std::io::Write;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

const USAGE: &str = "usage: pf_lab_peer plan|run --role sender|receiver --protocol tcp|udp --source IP:PORT --destination IP:PORT --nonce 32_HEX_DIGITS [--ack CONTROLLED-PROBE]";
#[derive(Debug, PartialEq, Eq)]
struct Plan {
    run: bool,
    sender: bool,
    tcp: bool,
    source: SocketAddr,
    destination: SocketAddr,
    nonce: [u8; 16],
}
fn eligible(address: SocketAddr) -> bool {
    match address {
        SocketAddr::V4(v) => {
            !v.ip().is_unspecified() && !v.ip().is_multicast() && !v.ip().is_broadcast()
        }
        SocketAddr::V6(v) => {
            v.scope_id() == 0
                && !v.ip().is_unspecified()
                && !v.ip().is_multicast()
                && !v.ip().is_unicast_link_local()
                && v.ip().to_ipv4_mapped().is_none()
        }
    }
}
fn parse(args: &[String], root: bool) -> Result<Option<Plan>, &'static str> {
    if args == ["--help"] {
        return Ok(None);
    }
    if root {
        return Err("ordinary user required");
    }
    if args.len() != 11 && args.len() != 13 {
        return Err("invalid arguments");
    }
    let run = match args[0].as_str() {
        "plan" => false,
        "run" => true,
        _ => return Err("invalid action"),
    };
    if args[1] != "--role"
        || args[3] != "--protocol"
        || args[5] != "--source"
        || args[7] != "--destination"
        || args[9] != "--nonce"
    {
        return Err("invalid arguments");
    }
    if (run && (args.len() != 13 || args[11] != "--ack" || args[12] != "CONTROLLED-PROBE"))
        || (!run && args.len() != 11)
    {
        return Err("invalid acknowledgement");
    }
    let sender = match args[2].as_str() {
        "sender" => true,
        "receiver" => false,
        _ => return Err("invalid role"),
    };
    let tcp = match args[4].as_str() {
        "tcp" => true,
        "udp" => false,
        _ => return Err("invalid protocol"),
    };
    let source: SocketAddr = args[6].parse().map_err(|_| "invalid source")?;
    let destination: SocketAddr = args[8].parse().map_err(|_| "invalid destination")?;
    if source.is_ipv6() != destination.is_ipv6()
        || source == destination
        || source.port() == 0
        || destination.port() == 0
        || !eligible(source)
        || !eligible(destination)
    {
        return Err("invalid controlled flow");
    }
    let raw = args[10].as_bytes();
    if raw.len() != 32 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return Err("invalid nonce");
    }
    let mut nonce = [0; 16];
    for (i, pair) in raw.as_chunks::<2>().0.iter().enumerate() {
        let digit = |b: u8| (b as char).to_digit(16).ok_or("invalid nonce");
        nonce[i] = ((digit(pair[0])? << 4) | digit(pair[1])?) as u8;
    }
    if nonce == [0; 16] {
        return Err("zero nonce");
    }
    Ok(Some(Plan {
        run,
        sender,
        tcp,
        source,
        destination,
        nonce,
    }))
}
fn status(plan: &Plan, name: &str, detail: &str) -> serde_json::Value {
    serde_json::json!({
        "status": name, "detail": detail,
        "role": if plan.sender { "sender" } else { "receiver" },
        "protocol": if plan.tcp { "tcp" } else { "udp" },
        "source": plan.source.to_string(), "destination": plan.destination.to_string(),
        "nonce": plan.nonce, "effective_uid": Uid::effective().as_raw(),
        "pf_verdict": "not_evaluated",
    })
}
fn main() -> ExitCode {
    let args: Result<Vec<String>, _> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect();
    let plan = match args
        .map_err(|_| "invalid arguments")
        .and_then(|args| parse(&args, Uid::effective().is_root()))
    {
        Ok(None) => {
            println!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Some(plan)) => plan,
        Err(reason) => {
            eprintln!("status=unavailable detail={reason}");
            return ExitCode::from(2);
        }
    };
    if !plan.run {
        println!("{}", status(&plan, "planned", "no sockets opened"));
        return ExitCode::SUCCESS;
    }
    let result = peer_transport::exchange(
        plan.sender,
        plan.tcp,
        plan.source,
        plan.destination,
        &plan.nonce,
        Duration::from_secs(30),
        || {
            println!("{}", status(&plan, "ready", "receiver bound"));
            std::io::stdout().flush()
        },
    );
    match result {
        Ok(_) => {
            let detail = if plan.sender {
                "matching echo received"
            } else {
                "matching nonce received and echoed"
            };
            println!("{}", status(&plan, "completed", detail));
            ExitCode::SUCCESS
        }
        Err(_) => {
            eprintln!(
                "{}",
                status(&plan, "unavailable", "exchange failed or timed out")
            );
            ExitCode::FAILURE
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn args() -> Vec<String> {
        "run --role sender --protocol tcp --source 192.0.2.1:1234 --destination 192.0.2.2:2345 --nonce 01010101010101010101010101010101 --ack CONTROLLED-PROBE".split_whitespace().map(str::to_owned).collect()
    }
    #[test]
    fn requires_explicit_ack_and_ordinary_user() {
        let a = args();
        assert!(parse(&a, false).is_ok());
        assert!(parse(&a, true).is_err());
        let mut b = a;
        b[12] = "wrong".into();
        assert!(parse(&b, false).is_err());
    }
    #[test]
    fn rejects_bad_flows_and_nonce() {
        for (index, value) in [
            (6, "0.0.0.0:1"),
            (6, "255.255.255.255:1"),
            (6, "[::1]:1"),
            (6, "[::ffff:192.0.2.1]:1"),
            (6, "192.0.2.2:2345"),
            (8, "192.0.2.2:0"),
            (10, "00000000000000000000000000000000"),
            (10, "not-hex"),
        ] {
            let mut a = args();
            a[index] = value.into();
            assert!(parse(&a, false).is_err());
        }
    }
    #[test]
    fn plan_and_help_are_nonexecuting_and_output_is_typed() -> Result<(), &'static str> {
        let mut a = args();
        a[0] = "plan".into();
        a.truncate(11);
        let plan = parse(&a, false)?.ok_or("missing plan")?;
        assert!(!plan.run);
        assert!(matches!(parse(&["--help".into()], false), Ok(None)));
        let output = status(&plan, "ready", "receiver bound");
        assert_eq!(output["status"], "ready");
        assert_eq!(output["destination"], "192.0.2.2:2345");
        assert_eq!(output["pf_verdict"], "not_evaluated");
        Ok(())
    }
}
