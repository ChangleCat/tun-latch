//! Construct fixed filter transactions only. No transaction is submitted here.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pfctl::{
    AddrFamily, AnchorChange, Direction, DropAction, Endpoint, FilterRuleAction, FilterRuleBuilder,
    Proto, StatePolicy, Transaction,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("expected an eight-character ASCII alphanumeric slot suffix")]
    InvalidSuffix,
    #[error(transparent)]
    Rule(#[from] pfctl::Error),
}

#[derive(Clone, Copy)]
pub(crate) enum Replacement {
    Stage,
    Empty,
}

fn check_suffix(suffix: &str) -> Result<(), Error> {
    if suffix.len() != 8 || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(Error::InvalidSuffix);
    }
    Ok(())
}

pub(crate) fn transaction(suffix: &str, replacement: Replacement) -> Result<Transaction, Error> {
    check_suffix(suffix)?;
    let anchor = format!("tunlatch-lab-{suffix}");
    let mut rules = Vec::new();
    if matches!(replacement, Replacement::Stage) {
        let label = format!("tunlatch-lab:{suffix}");
        for (family, address) in [
            (AddrFamily::Ipv4, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            (AddrFamily::Ipv6, IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ] {
            for proto in [Proto::Tcp, Proto::Udp] {
                rules.push(
                    FilterRuleBuilder::default()
                        .action(FilterRuleAction::Drop(DropAction::Drop))
                        .direction(Direction::Out)
                        .quick(true)
                        .interface("lo0")
                        .af(family)
                        .proto(proto)
                        .from(Endpoint::from(address))
                        .to(Endpoint::new(address, 55000_u16))
                        .keep_state(StatePolicy::None)
                        .label(label.clone())
                        .build()?,
                );
            }
        }
    }
    let mut change = AnchorChange::new();
    change.set_filter_rules(rules);
    let mut transaction = Transaction::new();
    transaction.add_change(&anchor, change);
    Ok(transaction)
}

/// Exact canonical text expected from the independent system rule reader.
#[cfg(test)]
pub(crate) fn expected_rules(suffix: &str) -> Result<Vec<u8>, Error> {
    check_suffix(suffix)?;
    let mut rules = String::new();
    for (family, address) in [("inet", "127.0.0.1"), ("inet6", "::1")] {
        for protocol in ["tcp", "udp"] {
            rules.push_str(&format!(
                "block drop out quick on lo0 {family} proto {protocol} from {address} to {address} \
                 port = 55000 label \"tunlatch-lab:{suffix}\"\n"
            ));
        }
    }
    Ok(rules.into_bytes())
}

/// Match only the fixed four-rule profile while accepting harmless pfctl display variants.
pub(crate) fn matches_observed(suffix: &str, raw: &[u8]) -> Result<bool, Error> {
    check_suffix(suffix)?;
    if raw.len() > 2048
        || !raw.ends_with(b"\n")
        || !raw.is_ascii()
        || raw
            .iter()
            .any(|byte| byte.is_ascii_control() && !matches!(byte, b'\n' | b'\t'))
    {
        return Ok(false);
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        return Ok(false);
    };
    let lines: Vec<_> = text.lines().collect();
    if lines.len() != 4 {
        return Ok(false);
    }
    let label = format!("\"tunlatch-lab:{suffix}\"");
    for (line, (family, protocol, address, mask)) in lines.iter().zip([
        ("inet", "tcp", IpAddr::V4(Ipv4Addr::LOCALHOST), "32"),
        ("inet", "udp", IpAddr::V4(Ipv4Addr::LOCALHOST), "32"),
        ("inet6", "tcp", IpAddr::V6(Ipv6Addr::LOCALHOST), "128"),
        ("inet6", "udp", IpAddr::V6(Ipv6Addr::LOCALHOST), "128"),
    ]) {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        if words.len() < 16
            || words[..10]
                != [
                    "block", "drop", "out", "quick", "on", "lo0", family, "proto", protocol, "from",
                ]
            || words[11] != "to"
            || !host_matches(words[10], address, mask)
            || !host_matches(words[12], address, mask)
            || words[13] != "port"
        {
            return Ok(false);
        }
        let mut rest = &words[14..];
        if rest.first() == Some(&"=") {
            rest = &rest[1..];
        }
        if rest.first() != Some(&"55000") {
            return Ok(false);
        }
        rest = &rest[1..];
        if rest.starts_with(&["no", "state"]) {
            rest = &rest[2..];
        }
        if rest != ["label", label.as_str()] {
            return Ok(false);
        }
    }
    Ok(true)
}

fn host_matches(text: &str, expected: IpAddr, mask: &str) -> bool {
    let (address, prefix) = text
        .split_once('/')
        .map_or((text, None), |(a, p)| (a, Some(p)));
    prefix.is_none_or(|value| value == mask) && address.parse::<IpAddr>() == Ok(expected)
}

#[test]
fn matches_only_safe_display_variations() -> Result<(), Error> {
    let canonical = expected_rules("1234abcd")?;
    assert!(matches_observed("1234abcd", &canonical)?);
    let variant = String::from_utf8(canonical)
        .map_err(|_| Error::InvalidSuffix)?
        .replace(" ", "\t")
        .replace("127.0.0.1", "127.0.0.1/32")
        .replace("::1", "0:0:0:0:0:0:0:1/128")
        .replace("port\t=\t55000", "port\t55000\tno\tstate");
    assert!(matches_observed("1234abcd", variant.as_bytes())?);
    Ok(())
}

#[test]
fn rejects_unsafe_or_ambiguous_rule_variations() -> Result<(), Error> {
    let canonical =
        String::from_utf8(expected_rules("1234abcd")?).map_err(|_| Error::InvalidSuffix)?;
    for altered in [
        canonical.replacen("block drop", "pass", 1),
        canonical.replacen("block drop", "block", 1),
        canonical.replacen("quick", "", 1),
        canonical.replacen("lo0", "en0", 1),
        canonical.replacen("127.0.0.1", "127.0.0.1/24", 1),
        canonical.replacen("::1", "::1/64", 1),
        canonical.replacen("55000", "55001", 1),
        canonical.replacen("label", "keep state label", 1),
        canonical.replacen("label", "flags S/SA label", 1),
        canonical.replacen("1234abcd", "1234abce", 1),
        format!("{canonical}block drop all\n"),
        canonical.replacen('\n', "\r\n", 1),
        canonical.replacen("lo0", "lö0", 1),
    ] {
        assert!(
            !matches_observed("1234abcd", altered.as_bytes())?,
            "accepted {altered:?}"
        );
    }
    assert!(matches_observed("bad", canonical.as_bytes()).is_err());
    Ok(())
}

#[test]
fn constructs_fixed_stage_and_empty_transactions_without_submitting() -> Result<(), Error> {
    let stage = transaction("Abc123XY", Replacement::Stage)?;
    let empty = transaction("Abc123XY", Replacement::Empty)?;
    let _commit: fn(Transaction) -> pfctl::Result<()> = Transaction::commit;
    assert_eq!(
        expected_rules("Abc123XY")?.split(|b| *b == b'\n').count(),
        5
    );
    drop((stage, empty));
    Ok(())
}

#[test]
fn rejects_invalid_suffixes_for_both_replacements() {
    for suffix in [
        "",
        "1234567",
        "123456789",
        "abc/1234",
        "abc-1234",
        "é1234567",
    ] {
        for replacement in [Replacement::Stage, Replacement::Empty] {
            assert!(matches!(
                transaction(suffix, replacement),
                Err(Error::InvalidSuffix)
            ));
        }
    }
}
