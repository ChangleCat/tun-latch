//! Offline only: no PF, traffic, privileges, or system changes.
#[path = "pf_lab/exact_filter.rs"]
mod exact_filter;
use exact_filter::{ExactFilter, Flow};
use std::net::SocketAddr;

fn flows() -> Result<[Flow; 4], Box<dyn std::error::Error>> {
    Ok([
        Flow {
            source: "192.0.2.1:50001".parse()?,
            destination: "192.0.2.2:51001".parse()?,
        },
        Flow {
            source: "192.0.2.1:50002".parse()?,
            destination: "192.0.2.2:51002".parse()?,
        },
        Flow {
            source: "[2001:db8::1]:50003".parse()?,
            destination: "[2001:db8::2]:51003".parse()?,
        },
        Flow {
            source: "[2001:db8::1]:50004".parse()?,
            destination: "[2001:db8::2]:51004".parse()?,
        },
    ])
}
const SUFFIX: &str = "0123456789abcdef0123456789abcdef";
fn canonical() -> String {
    [
        "inet proto tcp from 192.0.2.1 port = 50001 to 192.0.2.2 port = 51001",
        "inet proto udp from 192.0.2.1 port = 50002 to 192.0.2.2 port = 51002",
        "inet6 proto tcp from 2001:db8::1 port = 50003 to 2001:db8::2 port = 51003",
        "inet6 proto udp from 2001:db8::1 port = 50004 to 2001:db8::2 port = 51004",
    ]
    .iter()
    .enumerate()
    .map(|(i, part)| {
        format!("block drop out quick on en0 {part} no state label \"tunlatch-lab:{SUFFIX}-{i}\"\n")
    })
    .collect()
}

#[test]
fn labels_require_four_unique_complete_monotonic_counter_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let plan = ExactFilter::new(SUFFIX, "en0", flows()?)?;
    let before: String = (0..4)
        .map(|i| format!("tunlatch-lab:{SUFFIX}-{i} 5 2 100 0 0 2 100\n"))
        .collect();
    let after = before.replacen("5 2 100 0 0 2 100", "7 3 160 0 0 3 160", 1);
    assert_eq!(
        plan.outbound_deltas(before.as_bytes(), after.as_bytes()),
        Some([1, 0, 0, 0])
    );
    for bad in [
        after.replacen("-1 ", "-0 ", 1),
        after.replacen("-1 ", "-9 ", 1),
        after.replacen("7 3 160 0 0 3 160", "4 3 160 0 0 3 160", 1),
        after.replacen("7 3 160 0 0 3 160", "7 3 160 0 0 2 160", 1),
        after.replacen("7 3 160 0 0 3 160", "7 +3 160 0 0 3 160", 1),
        after.replacen("7 3 160 0 0 3 160", "7 3 160 0 0 3 160 0", 1),
        after.trim_end().to_owned(),
    ] {
        assert_eq!(
            plan.outbound_deltas(before.as_bytes(), bad.as_bytes()),
            None
        );
    }
    Ok(())
}
#[test]
fn builds_both_transactions_and_compares_only_exact_rules() -> Result<(), Box<dyn std::error::Error>>
{
    let plan = ExactFilter::new(SUFFIX, "en0", flows()?)?;
    assert_eq!(plan.anchor(), format!("tunlatch-lab-{SUFFIX}"));
    drop((plan.transaction(true)?, plan.transaction(false)?));
    let good = canonical();
    assert!(plan.matches_observed(good.as_bytes()));
    assert!(
        plan.matches_observed(
            good.replace(" no state", "")
                .replace("192.0.2.1", "192.0.2.1/32")
                .as_bytes()
        )
    );
    for bad in [
        good.replacen("50001", "50005", 1),
        good.replacen("51001", "51005", 1),
        good.replacen("en0", "en1", 1),
        good.replacen("192.0.2.1", "192.0.2.1/24", 1),
        good.replacen("no state", "keep state", 1),
        good.replacen("quick", "", 1),
        good.replacen("drop", "return", 1),
        format!("{good}pass all\n"),
    ] {
        assert!(!plan.matches_observed(bad.as_bytes()));
    }
    Ok(())
}
#[test]
fn rejects_unscoped_parameters() -> Result<(), Box<dyn std::error::Error>> {
    let f = flows()?;
    for suffix in [
        "00000000000000000000000000000000",
        "0123456789ABCDEF0123456789abcdef",
        "bad",
    ] {
        assert!(ExactFilter::new(suffix, "en0", f).is_err());
    }
    for interface in ["lo0", "utun0", "en", "en0/evil", "en999999"] {
        assert!(ExactFilter::new(SUFFIX, interface, f).is_err());
    }
    let mut invalid = f;
    invalid[0].source = "127.0.0.1:1234".parse::<SocketAddr>()?;
    assert!(ExactFilter::new(SUFFIX, "en0", invalid).is_err());
    invalid = f;
    invalid[0].destination = "[2001:db8::1]:1".parse()?;
    assert!(ExactFilter::new(SUFFIX, "en0", invalid).is_err());
    invalid = f;
    invalid[0].source.set_port(0);
    assert!(ExactFilter::new(SUFFIX, "en0", invalid).is_err());
    invalid = f;
    invalid[0].destination.set_ip(f[0].source.ip());
    assert!(ExactFilter::new(SUFFIX, "en0", invalid).is_err());
    Ok(())
}
