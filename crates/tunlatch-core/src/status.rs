//! Read-only status contracts. Discovered interfaces carry no trust or policy authority.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config::DesiredProtection;

/// Policy known to have been committed by TunLatch.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommittedPolicy {
    /// This framework has no PF writer and has committed no policy.
    Unmanaged,
}

/// Evidence from the enforcement adapter, separate from requested intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedProtection {
    /// Protection cannot be established from available evidence.
    Unknown {
        /// Machine-readable reason for unavailable evidence.
        reason: UnknownReason,
    },
}

/// Reasons the framework cannot claim protection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    /// PF integration has not been implemented or validated.
    BackendNotImplemented,
}

/// Collection method; no method here provides continuous interface identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCollection {
    /// One ordinary-user rescan performed for this status request.
    OnDemandRescan,
}

/// Diagnostics about one scan. The generation is local to the service process.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkObservation {
    /// Service-local scan generation, never an interface identity or approval.
    pub generation: u64,
    /// How the interfaces were obtained.
    pub collection: NetworkCollection,
}

/// An interface address, retaining IPv6 scope for link-local diagnostics.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceAddress {
    /// Local address, never interpreted as a proxy upstream endpoint.
    pub address: IpAddr,
    /// IPv6 scope identifier, zero when not applicable.
    pub scope_id: u32,
}

/// A discovered interface; name and index do not establish a persistent identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterface {
    /// Current interface name, useful only for discovery and diagnostics.
    pub name: String,
    /// Current kernel interface index. It can be reused by another tunnel.
    pub index: u32,
    /// Interface is administratively up.
    pub up: bool,
    /// Interface is a loopback interface.
    pub loopback: bool,
    /// All discovered IPv4 and IPv6 addresses, including IPv6-only interfaces.
    pub addresses: Vec<InterfaceAddress>,
}

impl NetworkInterface {
    /// A display hint only. This method must never authorize traffic or trusted rebinding.
    pub fn is_tun_candidate(&self) -> bool {
        self.name.strip_prefix("utun").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        })
    }
}

/// A point-in-time response; clients must discard it after disconnect or refresh failure.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    /// What the loaded configuration requests.
    pub desired: DesiredProtection,
    /// What TunLatch has successfully committed.
    pub committed: CommittedPolicy,
    /// What has actually been verified.
    pub observed: ObservedProtection,
    /// Interfaces from one discovery pass. This is not a trusted binding list.
    pub interfaces: Vec<NetworkInterface>,
    /// Scan diagnostics, absent when talking to an older observer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_observation: Option<NetworkObservation>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_only_interface_is_a_candidate_without_granting_trust()
    -> Result<(), Box<dyn std::error::Error>> {
        let interface = NetworkInterface {
            name: "utun7".into(),
            index: 8,
            up: true,
            loopback: false,
            addresses: vec![InterfaceAddress {
                address: "fe80::1".parse()?,
                scope_id: 8,
            }],
        };
        assert!(interface.is_tun_candidate());
        for name in ["utun", "utunnel1", "en0"] {
            assert!(
                !NetworkInterface {
                    name: name.into(),
                    ..interface.clone()
                }
                .is_tun_candidate()
            );
        }
        Ok(())
    }
}
