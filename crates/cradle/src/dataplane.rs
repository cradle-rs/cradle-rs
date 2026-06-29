//! The user-space view of the eBPF data plane: typed handles to the BPF maps
//! plus the operations that program them.
//!
//! This is the seam the zebra-rs control plane will eventually drive — the
//! method surface intentionally mirrors zebra-rs's `FibHandle`
//! (`route_*_add/del`, nexthop sync, neighbor updates).

use std::net::Ipv4Addr;

use anyhow::{Context as _, Result};
use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        HashMap, MapData,
    },
    Ebpf,
};
use cradle_common::{
    FibEntry, Neigh4Key, NeighEntry, NextHop, PortConfig, NEIGH_STATE_REACHABLE,
};

pub struct Dataplane {
    fib4: LpmTrie<MapData, [u8; 4], FibEntry>,
    nexthops: HashMap<MapData, u32, NextHop>,
    neigh4: HashMap<MapData, Neigh4Key, NeighEntry>,
    ports: HashMap<MapData, u32, PortConfig>,
}

impl Dataplane {
    /// Take ownership of the data-plane maps from a loaded eBPF object.
    ///
    /// Call this *after* the program is loaded and attached, so map relocations
    /// have already been resolved.
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self> {
        Ok(Self {
            fib4: LpmTrie::try_from(bpf.take_map("FIB4").context("map FIB4 missing")?)?,
            nexthops: HashMap::try_from(bpf.take_map("NEXTHOPS").context("map NEXTHOPS missing")?)?,
            neigh4: HashMap::try_from(bpf.take_map("NEIGH4").context("map NEIGH4 missing")?)?,
            ports: HashMap::try_from(bpf.take_map("PORTS").context("map PORTS missing")?)?,
        })
    }

    /// Register an interface (by ifindex) with its MAC and `PORT_F_*` flags.
    pub fn port_set(&mut self, ifindex: u32, mac: [u8; 6], flags: u32) -> Result<()> {
        self.ports
            .insert(ifindex, PortConfig { mac, vlan: 0, flags }, 0)?;
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

    /// Install an IPv4 route `addr/prefix_len` pointing at `nexthop_id`.
    pub fn route4_add(
        &mut self,
        addr: Ipv4Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib4
            .insert(&key, FibEntry { nexthop_id, flags }, 0)?;
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
