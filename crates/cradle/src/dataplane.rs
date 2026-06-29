//! The user-space view of the eBPF data plane: typed handles to the BPF maps
//! plus the operations that program them.
//!
//! This is the seam the zebra-rs control plane will eventually drive — the
//! method surface intentionally mirrors zebra-rs's `FibHandle`
//! (`route_*_add/del`, nexthop sync, neighbor updates), plus L2 domain setup.
//!
//! The `FDB` map is intentionally *not* taken here: it is populated by the eBPF
//! data plane via MAC learning, not by user space.

use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context as _, Result};
use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap, MapData,
    },
    Ebpf,
};
use cradle_common::{
    Backend, Backend6, BackendKey, FibEntry, L2MemberKey, Neigh4Key, NeighEntry, NextHop,
    NhGroupKey, PortConfig, ServiceInfo, ServiceKey, ServiceKey6, LB_ALGO_RANDOM,
    NEIGH_STATE_REACHABLE, NH_F_V6,
};

use crate::util;

pub struct Dataplane {
    fib4: LpmTrie<MapData, [u8; 4], FibEntry>,
    fib6: LpmTrie<MapData, [u8; 16], FibEntry>,
    nexthops: HashMap<MapData, u32, NextHop>,
    nhgroup: HashMap<MapData, u32, u32>,
    nhgroup_member: HashMap<MapData, NhGroupKey, u32>,
    neigh4: HashMap<MapData, Neigh4Key, NeighEntry>,
    ports: HashMap<MapData, u32, PortConfig>,
    l2_members: HashMap<MapData, L2MemberKey, u32>,
    l2_count: HashMap<MapData, u16, u32>,
    services: HashMap<MapData, ServiceKey, ServiceInfo>,
    backends: HashMap<MapData, BackendKey, Backend>,
    services6: HashMap<MapData, ServiceKey6, ServiceInfo>,
    backends6: HashMap<MapData, BackendKey, Backend6>,
}

impl Dataplane {
    /// Take ownership of the data-plane maps from a loaded eBPF object.
    ///
    /// Call this *after* the program is loaded and attached, so map relocations
    /// have already been resolved.
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        Ok(Self {
            fib4: LpmTrie::try_from(bpf.take_map("FIB4").context("map FIB4 missing")?)?,
            fib6: LpmTrie::try_from(bpf.take_map("FIB6").context("map FIB6 missing")?)?,
            nexthops: HashMap::try_from(bpf.take_map("NEXTHOPS").context("map NEXTHOPS missing")?)?,
            nhgroup: HashMap::try_from(bpf.take_map("NHGROUP").context("map NHGROUP missing")?)?,
            nhgroup_member: HashMap::try_from(
                bpf.take_map("NHGROUP_MEMBER").context("map NHGROUP_MEMBER missing")?,
            )?,
            neigh4: HashMap::try_from(bpf.take_map("NEIGH4").context("map NEIGH4 missing")?)?,
            ports: HashMap::try_from(bpf.take_map("PORTS").context("map PORTS missing")?)?,
            l2_members: HashMap::try_from(
                bpf.take_map("L2_MEMBERS").context("map L2_MEMBERS missing")?,
            )?,
            l2_count: HashMap::try_from(bpf.take_map("L2_COUNT").context("map L2_COUNT missing")?)?,
            services: HashMap::try_from(bpf.take_map("SERVICES").context("map SERVICES missing")?)?,
            backends: HashMap::try_from(bpf.take_map("BACKENDS").context("map BACKENDS missing")?)?,
            services6: HashMap::try_from(
                bpf.take_map("SERVICES6").context("map SERVICES6 missing")?,
            )?,
            backends6: HashMap::try_from(
                bpf.take_map("BACKENDS6").context("map BACKENDS6 missing")?,
            )?,
        })
    }

    /// Install an L4 service VIP and its backend set. `svc_id` namespaces the
    /// backend slots; the data plane picks a backend at random per new flow and
    /// connection-tracks it.
    pub fn service_add(
        &mut self,
        svc_id: u32,
        vip: std::net::Ipv4Addr,
        port: u16,
        proto: u8,
        backends: &[(std::net::Ipv4Addr, u16)],
    ) -> Result<()> {
        self.services.insert(
            ServiceKey {
                vip: util::ipv4_to_map(vip),
                port: util::port_to_map(port),
                proto,
                _pad: 0,
            },
            ServiceInfo {
                backend_count: backends.len() as u16,
                lb_algo: LB_ALGO_RANDOM,
                flags: 0,
                svc_id,
            },
            0,
        )?;
        for (slot, (ip, p)) in backends.iter().enumerate() {
            self.backends.insert(
                BackendKey {
                    svc_id,
                    slot: slot as u16,
                    _pad: 0,
                },
                Backend {
                    addr: util::ipv4_to_map(*ip),
                    port: util::port_to_map(*p),
                    flags: 0,
                },
                0,
            )?;
        }
        Ok(())
    }

    /// Install an IPv6 service VIP and its backend set.
    pub fn service6_add(
        &mut self,
        svc_id: u32,
        vip: Ipv6Addr,
        port: u16,
        proto: u8,
        backends: &[(Ipv6Addr, u16)],
    ) -> Result<()> {
        self.services6.insert(
            ServiceKey6 {
                vip: vip.octets(),
                port: util::port_to_map(port),
                proto,
                _pad: 0,
            },
            ServiceInfo {
                backend_count: backends.len() as u16,
                lb_algo: LB_ALGO_RANDOM,
                flags: 0,
                svc_id,
            },
            0,
        )?;
        for (slot, (ip, p)) in backends.iter().enumerate() {
            self.backends6.insert(
                BackendKey {
                    svc_id,
                    slot: slot as u16,
                    _pad: 0,
                },
                Backend6 {
                    addr: ip.octets(),
                    port: util::port_to_map(*p),
                    flags: 0,
                },
                0,
            )?;
        }
        Ok(())
    }

    /// Register an interface (by ifindex) with its MAC, `PORT_F_*` flags, and
    /// L2 VLAN/bridge domain.
    pub fn port_set(&mut self, ifindex: u32, mac: [u8; 6], flags: u32, vlan: u16) -> Result<()> {
        self.ports
            .insert(ifindex, PortConfig { mac, vlan, flags }, 0)?;
        Ok(())
    }

    /// Define the member ports of an L2 (VLAN/bridge) domain. Frames are flooded
    /// to these ports (minus the ingress) on BUM / unknown unicast.
    pub fn l2_domain_set(&mut self, vlan: u16, members: &[u32]) -> Result<()> {
        self.l2_count.insert(vlan, members.len() as u32, 0)?;
        for (slot, &ifindex) in members.iter().enumerate() {
            self.l2_members.insert(
                L2MemberKey {
                    vlan,
                    slot: slot as u16,
                },
                ifindex,
                0,
            )?;
        }
        Ok(())
    }

    /// Install/replace a nexthop. `gateway == None` means an on-link/connected
    /// nexthop (the neighbor is resolved by the packet's destination).
    pub fn nexthop_set(&mut self, id: u32, gateway: Option<Ipv4Addr>, oif: u32) -> Result<()> {
        let gateway_v4 = gateway.map(|a| u32::from_be_bytes(a.octets())).unwrap_or(0);
        let nh = NextHop {
            gateway_v4,
            gateway_v6: [0; 16],
            oif,
            flags: 0,
        };
        self.nexthops.insert(id, nh, 0)?;
        Ok(())
    }

    /// Define a nexthop group (for ECMP): `group_id` -> ordered member nexthop
    /// ids. A route flagged `FIB_F_ECMP` whose `nexthop_id` is `group_id` then
    /// hashes each flow onto one member.
    pub fn nexthop_group_set(&mut self, group_id: u32, members: &[u32]) -> Result<()> {
        self.nhgroup.insert(group_id, members.len() as u32, 0)?;
        for (slot, &nh_id) in members.iter().enumerate() {
            self.nhgroup_member.insert(
                NhGroupKey {
                    group_id,
                    slot: slot as u32,
                },
                nh_id,
                0,
            )?;
        }
        Ok(())
    }

    /// Install an IPv4 route `addr/prefix_len` pointing at `nexthop_id`.
    pub fn route4_add(
        &mut self,
        addr: Ipv4Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib4.insert(&key, FibEntry { nexthop_id, flags }, 0)?;
        Ok(())
    }

    /// Remove an IPv4 route.
    pub fn route4_del(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib4.remove(&key)?;
        Ok(())
    }

    /// Install/replace an IPv6 nexthop. `gateway == None` means on-link.
    pub fn nexthop_set_v6(&mut self, id: u32, gateway: Option<Ipv6Addr>, oif: u32) -> Result<()> {
        let nh = NextHop {
            gateway_v4: 0,
            gateway_v6: gateway.map(|a| a.octets()).unwrap_or([0; 16]),
            oif,
            flags: NH_F_V6,
        };
        self.nexthops.insert(id, nh, 0)?;
        Ok(())
    }

    /// Install an IPv6 route `addr/prefix_len` pointing at `nexthop_id`.
    pub fn route6_add(
        &mut self,
        addr: Ipv6Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib6.insert(&key, FibEntry { nexthop_id, flags }, 0)?;
        Ok(())
    }

    /// Remove an IPv6 route.
    pub fn route6_del(&mut self, addr: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib6.remove(&key)?;
        Ok(())
    }

    /// Set the neighbor (ARP) entry for `ip` reachable out `ifindex`.
    pub fn neigh4_set(&mut self, ifindex: u32, ip: Ipv4Addr, mac: [u8; 6]) -> Result<()> {
        let key = Neigh4Key {
            ifindex,
            addr: u32::from_be_bytes(ip.octets()),
        };
        self.neigh4.insert(
            key,
            NeighEntry {
                mac,
                state: NEIGH_STATE_REACHABLE,
                _pad: 0,
            },
            0,
        )?;
        Ok(())
    }
}
