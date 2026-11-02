//! Ordinary filtering only. This module has no trusted-interface or exception-approval constructor.

use std::net::IpAddr;

use super::{
    ConfigV2, DirectException, PolicyError, PolicyErrorCode, PolicyId, PortRange, Protocol, Rule,
    RuleAction,
};
use crate::config::DesiredProtection;

/// Complete transport fields of a hypothetical packet, without any egress trust information.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketProtocol {
    /// TCP source/destination numerical ports.
    Tcp {
        /// Source transport port.
        source_port: u16,
        /// Destination transport port.
        destination_port: u16,
    },
    /// UDP source/destination ports; includes QUIC without application classification.
    Udp {
        /// Source transport port.
        source_port: u16,
        /// Destination transport port.
        destination_port: u16,
    },
    /// Complete IPv4 ICMP fields.
    Icmp {
        /// Numerical message type, not an assertion of IANA assignment.
        message_type: u8,
        /// Numerical message code.
        code: u8,
    },
    /// Complete IPv6 ICMP fields.
    Icmpv6 {
        /// Numerical message type, not implicit permission for Neighbor Discovery.
        message_type: u8,
        /// Numerical message code.
        code: u8,
    },
    /// Another identified IP protocol; 1/6/17/58 cannot be disguised as other.
    Other(u8),
}

/// Validated packet description for pure matching, with no interface, grant or PF observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketDescriptor {
    destination: IpAddr,
    protocol: PacketProtocol,
}

impl PacketDescriptor {
    /// Validate address-family/transport consistency; incomplete packets must instead use None.
    pub fn new(destination: IpAddr, protocol: PacketProtocol) -> Result<Self, PolicyError> {
        if matches!(destination, IpAddr::V6(value) if value.to_ipv4_mapped().is_some()) {
            return Err(PolicyError::new(
                PolicyErrorCode::InvalidDestination,
                "packet.destination",
            ));
        }
        if (matches!(protocol, PacketProtocol::Icmp { .. }) && !destination.is_ipv4())
            || (matches!(protocol, PacketProtocol::Icmpv6 { .. }) && !destination.is_ipv6())
        {
            return Err(PolicyError::new(
                PolicyErrorCode::AddressFamilyMismatch,
                "packet.protocol",
            ));
        }
        if matches!(protocol, PacketProtocol::Other(1 | 6 | 17 | 58)) {
            return Err(PolicyError::new(
                PolicyErrorCode::InvalidValue,
                "packet.protocol",
            ));
        }
        Ok(Self {
            destination,
            protocol,
        })
    }

    /// Hypothetical packet's destination address.
    pub fn destination(&self) -> IpAddr {
        self.destination
    }
    /// Complete hypothetical transport descriptor.
    pub fn protocol(&self) -> PacketProtocol {
        self.protocol
    }
}

/// Intended ordinary filtering result. There is deliberately no unconditional Allow variant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OrdinaryDecision<'a> {
    /// Intent is disabled; this does not disable PF or establish any observed system state.
    Unmanaged,
    /// Deny; None identifies an incomplete packet instead of a user rule.
    Block {
        /// The first matching rule, when a complete packet matched an explicit block.
        rule_id: Option<&'a PolicyId>,
    },
    /// Continue to a separately proven egress boundary; never permission to send directly.
    NeedsEgressAuthorization {
        /// First matching allow rule, or None for default allow within the egress boundary.
        rule_id: Option<&'a PolicyId>,
    },
}

impl ConfigV2 {
    /// Apply deterministic ordinary rules only. Loopback, live grants and PF enforcement are not
    /// represented here and must be established separately before any traffic could be allowed.
    pub fn ordinary_decision(&self, packet: Option<&PacketDescriptor>) -> OrdinaryDecision<'_> {
        if self.desired == DesiredProtection::Disabled {
            return OrdinaryDecision::Unmanaged;
        }
        let Some(packet) = packet else {
            return OrdinaryDecision::Block { rule_id: None };
        };
        match self.rules.iter().find(|rule| rule.matches(packet)) {
            Some(rule) if rule.action == RuleAction::Block => OrdinaryDecision::Block {
                rule_id: Some(&rule.id),
            },
            Some(rule) => OrdinaryDecision::NeedsEgressAuthorization {
                rule_id: Some(&rule.id),
            },
            None => OrdinaryDecision::NeedsEgressAuthorization { rule_id: None },
        }
    }

    /// Enumerate matching candidate data after ordinary filtering. An explicit block suppresses
    /// every candidate; returned values still carry no profile validity or approval capability.
    pub fn matching_direct_candidates<'a>(
        &'a self,
        packet: &'a PacketDescriptor,
    ) -> impl Iterator<Item = &'a DirectException> {
        let eligible = matches!(
            self.ordinary_decision(Some(packet)),
            OrdinaryDecision::NeedsEgressAuthorization { .. }
        );
        self.direct_exceptions
            .iter()
            .filter(move |candidate| eligible && candidate.matches_candidate(packet))
    }
}

impl Rule {
    /// Test only this rule's selectors, without evaluating priority, egress or protection status.
    pub fn matches(&self, packet: &PacketDescriptor) -> bool {
        self.destination.contains(packet.destination)
            && matches_fields(
                self.protocol,
                self.source_ports.as_deref(),
                self.destination_ports.as_deref(),
                self.icmp_type,
                self.icmp_code,
                packet.protocol,
            )
    }
}

impl DirectException {
    /// Match candidate selectors only; true never means this traffic is authorized for direct use.
    pub fn matches_candidate(&self, packet: &PacketDescriptor) -> bool {
        self.destination.contains(packet.destination)
            && matches_fields(
                self.protocol,
                self.source_ports.as_deref(),
                self.destination_ports.as_deref(),
                self.icmp_type,
                self.icmp_code,
                packet.protocol,
            )
    }
}

fn ports_match(ranges: Option<&[PortRange]>, port: u16) -> bool {
    ranges.is_none_or(|ranges| ranges.iter().any(|range| range.contains(port)))
}

fn matches_fields(
    protocol: Protocol,
    source: Option<&[PortRange]>,
    destination: Option<&[PortRange]>,
    icmp_type: Option<u8>,
    icmp_code: Option<u8>,
    actual: PacketProtocol,
) -> bool {
    match (protocol, actual) {
        (Protocol::Any, _) => true,
        (
            Protocol::Tcp,
            PacketProtocol::Tcp {
                source_port,
                destination_port,
            },
        )
        | (
            Protocol::Udp,
            PacketProtocol::Udp {
                source_port,
                destination_port,
            },
        ) => ports_match(source, source_port) && ports_match(destination, destination_port),
        (Protocol::Icmp, PacketProtocol::Icmp { message_type, code })
        | (Protocol::Icmpv6, PacketProtocol::Icmpv6 { message_type, code }) => {
            icmp_type.is_none_or(|value| value == message_type)
                && icmp_code.is_none_or(|value| value == code)
        }
        _ => false,
    }
}
