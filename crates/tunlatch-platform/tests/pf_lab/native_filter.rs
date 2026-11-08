//! Construct fixed filter transactions only. No transaction is submitted here.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pfctl::{
    AddrFamily, AnchorChange, Direction, DropAction, Endpoint, FilterRuleAction, FilterRuleBuilder,
    Proto, StatePolicy, Transaction,
};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("expected an eight-character ASCII alphanumeric slot suffix")]
    InvalidSuffix,
    #[error(transparent)]
    Rule(#[from] pfctl::Error),
}

#[derive(Clone, Copy)]
enum Replacement {
    Stage,
    Empty,
}

fn transaction(suffix: &str, replacement: Replacement) -> Result<Transaction, Error> {
    if suffix.len() != 8 || !suffix.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(Error::InvalidSuffix);
    }
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

#[test]
fn constructs_fixed_stage_and_empty_transactions_without_submitting() -> Result<(), Error> {
    let stage = transaction("Abc123XY", Replacement::Stage)?;
    let empty = transaction("Abc123XY", Replacement::Empty)?;
    let _commit: fn(Transaction) -> pfctl::Result<()> = Transaction::commit;
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
