//! Offline construction and strict comparison for four explicitly scoped probe flows.
//! An en name alone does not establish physical identity, approval, or anchor freshness.
use std::net::{IpAddr, SocketAddr};

use pfctl::{
    AddrFamily, AnchorChange, Direction, DropAction, Endpoint, FilterRuleAction, FilterRuleBuilder,
    Proto, StatePolicy, Transaction,
};

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
    #[error("invalid exact-flow experiment parameters")]
    Invalid,
    #[error(transparent)]
    Rule(#[from] pfctl::Error),
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Flow {
    pub(crate) source: SocketAddr,
    pub(crate) destination: SocketAddr,
}

pub(crate) struct ExactFilter {
    suffix: String,
    interface: String,
    flows: [Flow; 4],
}

impl ExactFilter {
    /// Flow order is IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP.
    /// The caller must independently verify interface identity and the fresh random anchor.
    pub(crate) fn new(suffix: &str, interface: &str, flows: [Flow; 4]) -> Result<Self, Error> {
        let Some(index) = interface.strip_prefix("en") else {
            return Err(Error::Invalid);
        };
        if suffix.len() != 32
            || !suffix
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || suffix.bytes().all(|b| b == b'0')
            || index.is_empty()
            || index.len() > 5
            || !index.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Error::Invalid);
        }
        for (i, flow) in flows.iter().enumerate() {
            if flow.source.ip() == flow.destination.ip() {
                return Err(Error::Invalid);
            }
            for endpoint in [flow.source, flow.destination] {
                if endpoint.port() == 0 || endpoint.is_ipv4() != (i < 2) || !usable(endpoint) {
                    return Err(Error::Invalid);
                }
            }
        }
        Ok(Self {
            suffix: suffix.to_owned(),
            interface: interface.to_owned(),
            flows,
        })
    }

    pub(crate) fn anchor(&self) -> String {
        format!("tunlatch-lab-{}", self.suffix)
    }

    /// Builds an in-memory transaction; does not submit it or access PF.
    pub(crate) fn transaction(&self, stage: bool) -> Result<Transaction, Error> {
        let mut rules = Vec::new();
        if stage {
            for (i, flow) in self.flows.iter().enumerate() {
                rules.push(
                    FilterRuleBuilder::default()
                        .action(FilterRuleAction::Drop(DropAction::Drop))
                        .direction(Direction::Out)
                        .quick(true)
                        .interface(&self.interface)
                        .af(if i < 2 {
                            AddrFamily::Ipv4
                        } else {
                            AddrFamily::Ipv6
                        })
                        .proto(if i % 2 == 0 { Proto::Tcp } else { Proto::Udp })
                        .from(Endpoint::new(flow.source.ip(), flow.source.port()))
                        .to(Endpoint::new(
                            flow.destination.ip(),
                            flow.destination.port(),
                        ))
                        .keep_state(StatePolicy::None)
                        .label(format!("tunlatch-lab:{}", self.suffix))
                        .build()?,
                );
            }
        }
        let mut change = AnchorChange::new();
        change.set_filter_rules(rules);
        let mut transaction = Transaction::new();
        transaction.add_change(&self.anchor(), change);
        Ok(transaction)
    }

    /// Accept only the ordered, exact four-rule display profile; no arbitrary PF syntax.
    pub(crate) fn matches_observed(&self, raw: &[u8]) -> bool {
        if raw.len() > 4096
            || !raw.ends_with(b"\n")
            || !raw.is_ascii()
            || raw
                .iter()
                .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\t'))
        {
            return false;
        }
        let Ok(text) = std::str::from_utf8(raw) else {
            return false;
        };
        let lines: Vec<_> = text.lines().collect();
        if lines.len() != 4 {
            return false;
        }
        let label = format!("\"tunlatch-lab:{}\"", self.suffix);
        lines.iter().enumerate().all(|(i, line)| {
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            let flow = self.flows[i];
            let prefix = [
                "block",
                "drop",
                "out",
                "quick",
                "on",
                self.interface.as_str(),
                if i < 2 { "inet" } else { "inet6" },
                "proto",
                if i % 2 == 0 { "tcp" } else { "udp" },
                "from",
            ];
            if !words.starts_with(&prefix) {
                return false;
            }
            let mut rest = &words[prefix.len()..];
            if !take_host(&mut rest, flow.source.ip())
                || !take_port(&mut rest, flow.source.port())
                || rest.first() != Some(&"to")
            {
                return false;
            }
            rest = &rest[1..];
            if !take_host(&mut rest, flow.destination.ip())
                || !take_port(&mut rest, flow.destination.port())
            {
                return false;
            }
            if rest.starts_with(&["no", "state"]) {
                rest = &rest[2..];
            }
            rest == ["label", label.as_str()]
        })
    }
}

fn usable(endpoint: SocketAddr) -> bool {
    match endpoint {
        SocketAddr::V4(v) => {
            !v.ip().is_unspecified()
                && !v.ip().is_loopback()
                && !v.ip().is_multicast()
                && !v.ip().is_broadcast()
        }
        SocketAddr::V6(v) => {
            v.scope_id() == 0
                && v.flowinfo() == 0
                && !v.ip().is_unspecified()
                && !v.ip().is_loopback()
                && !v.ip().is_multicast()
                && !v.ip().is_unicast_link_local()
                && v.ip().to_ipv4_mapped().is_none()
        }
    }
}

fn take_host<'a>(rest: &mut &'a [&'a str], expected: IpAddr) -> bool {
    let Some((first, tail)) = rest.split_first() else {
        return false;
    };
    let (address, mask) = first
        .split_once('/')
        .map_or((*first, None), |(a, m)| (a, Some(m)));
    if address.parse::<IpAddr>() != Ok(expected)
        || mask.is_some_and(|m| m != if expected.is_ipv4() { "32" } else { "128" })
    {
        return false;
    }
    *rest = tail;
    true
}

fn take_port<'a>(rest: &mut &'a [&'a str], expected: u16) -> bool {
    if rest.first() != Some(&"port") {
        return false;
    }
    *rest = &rest[1..];
    if rest.first() == Some(&"=") {
        *rest = &rest[1..];
    }
    if rest.first().and_then(|p| p.parse::<u16>().ok()) != Some(expected) {
        return false;
    }
    *rest = &rest[1..];
    true
}
