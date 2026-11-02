//! Native address enumeration. Snapshots do not prove tunnel ownership or route coverage.

use std::collections::BTreeMap;
use std::net::IpAddr;

use nix::ifaddrs::{InterfaceAddress as NativeAddress, getifaddrs};
use nix::net::if_::{InterfaceFlags, if_nametoindex};
use tunlatch_core::status::{InterfaceAddress, NetworkInterface};

/// Enumerate and group native IPv4/IPv6 addresses, retaining interfaces without IPv4.
///
/// An interface disappearing during enumeration is an error, never an empty successful snapshot.
pub fn snapshot() -> Result<Vec<NetworkInterface>, nix::Error> {
    collect(getifaddrs()?)
}

fn collect(
    addresses: impl Iterator<Item = NativeAddress>,
) -> Result<Vec<NetworkInterface>, nix::Error> {
    let mut interfaces = BTreeMap::<String, NetworkInterface>::new();
    for address in addresses {
        let entry = match interfaces.entry(address.interface_name.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                let index = if_nametoindex(address.interface_name.as_str())?;
                entry.insert(NetworkInterface {
                    name: address.interface_name,
                    index,
                    up: address.flags.contains(InterfaceFlags::IFF_UP),
                    loopback: address.flags.contains(InterfaceFlags::IFF_LOOPBACK),
                    addresses: Vec::new(),
                })
            }
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
        };
        if let Some(storage) = address.address {
            let item = if let Some(ipv4) = storage.as_sockaddr_in() {
                Some(InterfaceAddress {
                    address: IpAddr::V4(ipv4.ip()),
                    scope_id: 0,
                })
            } else {
                storage.as_sockaddr_in6().map(|ipv6| InterfaceAddress {
                    address: IpAddr::V6(ipv6.ip()),
                    scope_id: ipv6.scope_id(),
                })
            };
            if let Some(item) = item
                && !entry.addresses.contains(&item)
            {
                entry.addresses.push(item);
            }
        }
    }
    Ok(interfaces.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_snapshot_preserves_loopback_and_both_address_families() -> Result<(), nix::Error> {
        let interfaces = snapshot()?;
        let loopback = interfaces.iter().find(|interface| interface.name == "lo0");
        assert!(loopback.is_some_and(|interface| {
            interface.loopback
                && interface
                    .addresses
                    .iter()
                    .any(|address| address.address.is_ipv4())
                && interface
                    .addresses
                    .iter()
                    .any(|address| address.address.is_ipv6())
        }));
        Ok(())
    }
}
