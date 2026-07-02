//! Derive connected and local routes for an L3 port from the kernel's interface
//! addresses (`getifaddrs`), for both IPv4 and IPv6.
//!
//! Per address `A/p` on a routed port we install:
//!  - a host (`/32` or `/128`) **local** route flagged `FIB_F_LOCAL`, so packets
//!    addressed to the router itself are punted to the host stack instead of
//!    forwarded (essential with `bpf_redirect_neigh`: a packet to our own
//!    address would otherwise try to resolve us as a neighbor and be dropped);
//!  - a **connected** route for the subnet via a connected nexthop on the port.
//!
//! A routed port therefore needs no manual route/neighbor configuration.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{Context as _, Result};
use nix::ifaddrs::getifaddrs;
use tracing::info;

use crate::dataplane::Dataplane;
use cradle_common::FIB_F_LOCAL;

/// Connected nexthops get ids in high ranges keyed by ifindex, so they never
/// collide with control-plane-assigned ids (zebra-rs tee starts at 1).
const CONNECTED_NH_BASE_V4: u32 = 1_000_000;
const CONNECTED_NH_BASE_V6: u32 = 2_000_000;

/// Install local + connected routes for `name` (ifindex `ifindex`) from its
/// current kernel addresses (IPv4 and global IPv6).
pub fn derive_port(dp: &mut Dataplane, name: &str, ifindex: u32) -> Result<()> {
    for ifa in getifaddrs()? {
        if ifa.interface_name != name {
            continue;
        }
        let (Some(addr), Some(mask)) = (ifa.address, ifa.netmask) else {
            continue;
        };

        if let (Some(sin), Some(min)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) {
            // `s_addr` is network byte order; `to_be()` yields the host-order
            // u32 that `Ipv4Addr::from` expects (on this little-endian host).
            let ip = Ipv4Addr::from(sin.as_ref().sin_addr.s_addr.to_be());
            let plen = min.as_ref().sin_addr.s_addr.count_ones() as u8;
            dp.route4_add(ip, 32, 0, FIB_F_LOCAL)?;
            if plen < 32 {
                let mask_bits = if plen == 0 { 0 } else { u32::MAX << (32 - plen as u32) };
                let net = Ipv4Addr::from(u32::from(ip) & mask_bits);
                let nh = CONNECTED_NH_BASE_V4 + ifindex;
                dp.nexthop_set(nh, None, ifindex, &[])?;
                dp.route4_add(net, plen, nh, 0)?;
            }
            info!("port {name}: derived v4 {ip}/{plen}");
        } else if let (Some(sin6), Some(min6)) = (addr.as_sockaddr_in6(), mask.as_sockaddr_in6()) {
            let ip = Ipv6Addr::from(sin6.as_ref().sin6_addr.s6_addr);
            // Skip loopback and link-local (fe80::/10); those don't participate
            // in global forwarding here.
            if ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80 {
                continue;
            }
            let plen: u8 = min6
                .as_ref()
                .sin6_addr
                .s6_addr
                .iter()
                .map(|b| b.count_ones() as u8)
                .sum();
            dp.route6_add(ip, 128, 0, FIB_F_LOCAL)?;
            if plen < 128 {
                let net = mask_v6(ip, plen);
                let nh = CONNECTED_NH_BASE_V6 + ifindex;
                dp.nexthop_set_v6(nh, None, ifindex, &[])?;
                dp.route6_add(net, plen, nh, 0)?;
            }
            info!("port {name}: derived v6 {ip}/{plen}");
        }
    }
    Ok(())
}

/// Install a kernel `local` route for an L7 VIP, so packets steered to the
/// user-space transparent proxy by `bpf_sk_assign` are delivered to that local
/// socket rather than forwarded.
///
/// TPROXY subtlety: `bpf_sk_assign` sets `skb->sk`, but the kernel still runs a
/// routing lookup afterward. Without a matching `local` route the non-local VIP
/// is classified for forwarding and dropped (there is no route, or forwarding is
/// off). A `local <vip>/32 dev lo` entry makes the lookup return `RTN_LOCAL`, so
/// the packet is delivered locally to the assigned socket.
///
/// Equivalent to `ip route replace local <vip>/32 dev lo`, run in cradle's
/// current network namespace. Idempotent (`replace`); needs CAP_NET_ADMIN, which
/// cradle already holds to load the datapath.
pub fn add_local_route_v4(vip: Ipv4Addr) -> Result<()> {
    let dst = format!("{vip}/32");
    let out = Command::new("ip")
        .args(["route", "replace", "local", &dst, "dev", "lo"])
        .output()
        .with_context(|| format!("running `ip route replace local {dst} dev lo`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`ip route replace local {dst} dev lo` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    info!("installed local route {dst} dev lo (L7 VIP delivery)");
    Ok(())
}

/// Mask an IPv6 address to its `prefix_len`-bit network address.
fn mask_v6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len as u32)
    };
    Ipv6Addr::from(bits & mask)
}
