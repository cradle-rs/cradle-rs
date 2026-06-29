//! Derive connected and local routes for an L3 port from the kernel's interface
//! addresses (`getifaddrs`).
//!
//! Two things fall out of each IPv4 address `A/p` on a routed port:
//!  - a **local** route `A/32` flagged `FIB_F_LOCAL`, so packets addressed to
//!    the router itself are punted to the host stack instead of being forwarded
//!    (essential now that L3 uses `bpf_redirect_neigh` — without it, a packet to
//!    our own address would try to resolve us as a neighbor and be dropped);
//!  - a **connected** route `A&mask/p` pointing at a connected nexthop on the
//!    port, so on-link destinations are forwarded with the kernel resolving the
//!    neighbor.
//!
//! This means a routed port needs no manual route/neighbor configuration.

use std::net::Ipv4Addr;

use anyhow::Result;
use nix::ifaddrs::getifaddrs;
use tracing::info;

use crate::dataplane::Dataplane;
use cradle_common::FIB_F_LOCAL;

/// Connected nexthops get ids in a high range keyed by ifindex, so they never
/// collide with control-plane-assigned ids (zebra-rs tee starts at 1).
const CONNECTED_NH_BASE: u32 = 1_000_000;

/// Install local + connected routes for `name` (ifindex `ifindex`) from its
/// current kernel addresses.
pub fn derive_port(dp: &mut Dataplane, name: &str, ifindex: u32) -> Result<()> {
    for ifa in getifaddrs()? {
        if ifa.interface_name != name {
            continue;
        }
        let (Some(addr), Some(mask)) = (ifa.address, ifa.netmask) else {
            continue;
        };
        let (Some(sin), Some(min)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) else {
            continue;
        };
        // `s_addr` is network byte order; `to_be()` gives the host-order u32
        // that `Ipv4Addr::from` expects (on this little-endian host).
        let ip = Ipv4Addr::from(sin.as_ref().sin_addr.s_addr.to_be());
        let plen = min.as_ref().sin_addr.s_addr.count_ones() as u8;

        // Local: deliver to the host stack.
        dp.route4_add(ip, 32, 0, FIB_F_LOCAL)?;

        // Connected: forward on-link via a connected nexthop on this port.
        if plen < 32 {
            let mask_bits = if plen == 0 { 0 } else { u32::MAX << (32 - plen as u32) };
            let net = Ipv4Addr::from(u32::from(ip) & mask_bits);
            let nh = CONNECTED_NH_BASE + ifindex;
            dp.nexthop_set(nh, None, ifindex)?;
            dp.route4_add(net, plen, nh, 0)?;
            info!("port {name}: derived local {ip}/32 and connected {net}/{plen}");
        } else {
            info!("port {name}: derived local {ip}/32");
        }
    }
    Ok(())
}
