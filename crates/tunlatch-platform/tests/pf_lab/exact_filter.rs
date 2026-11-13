//! Offline construction and strict comparison for four explicitly scoped probe flows.
//! An en name alone does not establish physical identity, approval, or anchor freshness.
use std::net::{IpAddr, SocketAddr};

use pfctl::{
    AddrFamily, AnchorChange, Direction, DropAction, Endpoint, FilterRule, FilterRuleAction,
    FilterRuleBuilder, Proto, StatePolicy, Transaction,
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
    fn label(&self, index: usize, root_pass: bool) -> String {
        let kind = if root_pass { "-uid0" } else { "" };
        format!("tunlatch-lab:{}-{index}{kind}", self.suffix)
    }

    fn rule(&self, index: usize, root_pass: bool) -> Result<FilterRule, Error> {
        let flow = self.flows[index];
        let mut rule = FilterRuleBuilder::default();
        rule.action(if root_pass {
            FilterRuleAction::Pass
        } else {
            FilterRuleAction::Drop(DropAction::Drop)
        })
        .direction(Direction::Out)
        .quick(true)
        .interface(&self.interface)
        .af(if index < 2 {
            AddrFamily::Ipv4
        } else {
            AddrFamily::Ipv6
        })
        .proto(if index.is_multiple_of(2) {
            Proto::Tcp
        } else {
            Proto::Udp
        })
        .from(Endpoint::new(flow.source.ip(), flow.source.port()))
        .to(Endpoint::new(
            flow.destination.ip(),
            flow.destination.port(),
        ))
        .keep_state(StatePolicy::None)
        .label(self.label(index, root_pass));
        if root_pass {
            rule.user(0_u32);
        }
        Ok(rule.build()?)
    }

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
        let rules = if stage {
            (0..self.flows.len())
                .map(|index| self.rule(index, false))
                .collect::<Result<_, _>>()?
        } else {
            Vec::new()
        };
        Ok(self.transaction_with(rules))
    }

    /// Builds the stateless UID-matching trial. Stateful revocation needs its own experiment.
    pub(crate) fn root_uid_transaction(&self) -> Result<Transaction, Error> {
        let mut rules = Vec::with_capacity(8);
        for index in 0..self.flows.len() {
            rules.push(self.rule(index, true)?);
            rules.push(self.rule(index, false)?);
        }
        Ok(self.transaction_with(rules))
    }

    fn transaction_with(&self, rules: Vec<FilterRule>) -> Transaction {
        let mut change = AnchorChange::new();
        change.set_filter_rules(rules);
        let mut transaction = Transaction::new();
        transaction.add_change(&self.anchor(), change);
        transaction
    }

    /// Accept only the ordered, exact four-rule display profile; no arbitrary PF syntax.
    pub(crate) fn matches_observed(&self, raw: &[u8]) -> bool {
        self.matches_rules(raw, false)
    }

    /// Accepts a root-only pass immediately followed by an unconditional drop on each tuple.
    pub(crate) fn matches_root_uid_rules(&self, raw: &[u8]) -> bool {
        self.matches_rules(raw, true)
    }

    fn matches_rules(&self, raw: &[u8], root_uid: bool) -> bool {
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
        let rules_per_flow = if root_uid { 2 } else { 1 };
        if lines.len() != self.flows.len() * rules_per_flow {
            return false;
        }
        lines.iter().enumerate().all(|(i, line)| {
            let index = i / rules_per_flow;
            let root_pass = root_uid && i % 2 == 0;
            let label = format!("\"{}\"", self.label(index, root_pass));
            let words: Vec<_> = line.split_ascii_whitespace().collect();
            let action: &[_] = if root_pass {
                &["pass"]
            } else {
                &["block", "drop"]
            };
            let Some(rest) = words.strip_prefix(action) else {
                return false;
            };
            let flow = self.flows[index];
            let prefix = [
                "out",
                "quick",
                "on",
                self.interface.as_str(),
                if index < 2 { "inet" } else { "inet6" },
                "proto",
                if index % 2 == 0 { "tcp" } else { "udp" },
                "from",
            ];
            let Some(mut rest) = rest.strip_prefix(&prefix) else {
                return false;
            };
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
            if root_pass {
                let Some(tail) = rest.strip_prefix(&["user", "=", "0", "no", "state"]) else {
                    return false;
                };
                rest = tail;
            } else if rest.starts_with(&["no", "state"]) {
                rest = &rest[2..];
            }
            rest == ["label", label.as_str()]
        })
    }

    /// Returns per-case outbound packet deltas only for two complete, matching snapshots.
    /// Counter changes alone do not establish that the test packet caused the change.
    pub(crate) fn outbound_deltas(&self, before: &[u8], after: &[u8]) -> Option<[u64; 4]> {
        self.counter_deltas::<4>(before, after, false)
    }

    /// Returns separate outbound deltas for the UID pass and fallback drop of each tuple.
    pub(crate) fn root_uid_deltas(&self, before: &[u8], after: &[u8]) -> Option<[(u64, u64); 4]> {
        let rows = self.counter_deltas::<8>(before, after, true)?;
        Some(std::array::from_fn(|i| (rows[2 * i], rows[2 * i + 1])))
    }

    fn counter_deltas<const N: usize>(
        &self,
        before: &[u8],
        after: &[u8],
        root_uid: bool,
    ) -> Option<[u64; N]> {
        let labels: [String; N] = std::array::from_fn(|i| {
            if root_uid {
                self.label(i / 2, i % 2 == 0)
            } else {
                self.label(i, false)
            }
        });
        let before = Self::label_counters(before, &labels)?;
        let after = Self::label_counters(after, &labels)?;
        let mut result = [0; N];
        for (index, (before, after)) in before.into_iter().zip(after).enumerate() {
            for (before, after) in before.into_iter().zip(after) {
                after.checked_sub(before)?;
            }
            result[index] = after[5] - before[5];
        }
        Some(result)
    }

    fn label_counters<const N: usize>(raw: &[u8], labels: &[String; N]) -> Option<[[u64; 7]; N]> {
        if raw.len() > 4096
            || !raw.ends_with(b"\n")
            || !raw.is_ascii()
            || raw
                .iter()
                .any(|b| b.is_ascii_control() && !matches!(b, b'\n' | b'\t'))
        {
            return None;
        }
        let mut rows = [None; N];
        for line in std::str::from_utf8(raw).ok()?.lines() {
            let mut fields = line.split_ascii_whitespace();
            let label = fields.next()?;
            let index = labels.iter().position(|candidate| label == candidate)?;
            if rows[index].is_some() {
                return None;
            }
            let mut counters = [0_u64; 7];
            for counter in &mut counters {
                let field = fields.next()?;
                if field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                *counter = field.parse().ok()?;
            }
            if fields.next().is_some()
                || counters[1] != counters[3].checked_add(counters[5])?
                || counters[2] != counters[4].checked_add(counters[6])?
            {
                return None;
            }
            rows[index] = Some(counters);
        }
        let mut result = [[0; 7]; N];
        for (value, row) in result.iter_mut().zip(rows) {
            *value = row?;
        }
        Some(result)
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
