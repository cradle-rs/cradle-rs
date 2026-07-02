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
        Array, HashMap, MapData, PerCpuArray,
    },
    Ebpf,
};
use cradle_common::{
    Backend, Backend6, BackendKey, FibEntry, FibWord, L2MemberKey, MplsEntry, Neigh4Key,
    Neigh6Key, NeighEntry, NextHop, NhGroupKey, PortConfig, ServiceInfo, ServiceKey, ServiceKey6,
    DIR24_TBL8_GROUPS, DPC_FIB4_DIR24, LB_ALGO_RANDOM, MAX_LABELS, NEIGH_STATE_REACHABLE,
    NH_F_MPLS, NH_F_V6, STAT_MAX,
};

use crate::{
    dir24::{Dir24Engine, SlotWrite},
    util,
};

pub struct Dataplane {
    fib4: LpmTrie<MapData, [u8; 4], FibEntry>,
    fib6: LpmTrie<MapData, [u8; 16], FibEntry>,
    tbl24: Array<MapData, FibWord>,
    tbl8: Array<MapData, FibWord>,
    default4: Array<MapData, FibWord>,
    dp_config: Array<MapData, u32>,
    /// DIR-24-8 expansion engine — `Some` when the dir24 v4 engine is active;
    /// `route4_add/del` dispatch on it internally so callers are agnostic.
    dir24: Option<Dir24Engine>,
    nexthops: HashMap<MapData, u32, NextHop>,
    nhgroup: HashMap<MapData, u32, u32>,
    nhgroup_member: HashMap<MapData, NhGroupKey, u32>,
    neigh4: HashMap<MapData, Neigh4Key, NeighEntry>,
    neigh6: HashMap<MapData, Neigh6Key, NeighEntry>,
    mpls_fib: HashMap<MapData, u32, MplsEntry>,
    ports: HashMap<MapData, u32, PortConfig>,
    l2_members: HashMap<MapData, L2MemberKey, u32>,
    l2_count: HashMap<MapData, u16, u32>,
    services: HashMap<MapData, ServiceKey, ServiceInfo>,
    backends: HashMap<MapData, BackendKey, Backend>,
    services6: HashMap<MapData, ServiceKey6, ServiceInfo>,
    backends6: HashMap<MapData, BackendKey, Backend6>,
    stats: PerCpuArray<MapData, u64>,
    l7_services: HashMap<MapData, ServiceKey, u8>,
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
            tbl24: Array::try_from(bpf.take_map("TBL24").context("map TBL24 missing")?)?,
            tbl8: Array::try_from(bpf.take_map("TBL8").context("map TBL8 missing")?)?,
            default4: Array::try_from(bpf.take_map("DEFAULT4").context("map DEFAULT4 missing")?)?,
            dp_config: Array::try_from(
                bpf.take_map("DP_CONFIG").context("map DP_CONFIG missing")?,
            )?,
            dir24: None,
            nexthops: HashMap::try_from(bpf.take_map("NEXTHOPS").context("map NEXTHOPS missing")?)?,
            nhgroup: HashMap::try_from(bpf.take_map("NHGROUP").context("map NHGROUP missing")?)?,
            nhgroup_member: HashMap::try_from(
                bpf.take_map("NHGROUP_MEMBER").context("map NHGROUP_MEMBER missing")?,
            )?,
            neigh4: HashMap::try_from(bpf.take_map("NEIGH4").context("map NEIGH4 missing")?)?,
            neigh6: HashMap::try_from(bpf.take_map("NEIGH6").context("map NEIGH6 missing")?)?,
            mpls_fib: HashMap::try_from(
                bpf.take_map("MPLS_FIB").context("map MPLS_FIB missing")?,
            )?,
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
            stats: PerCpuArray::try_from(bpf.take_map("STATS").context("map STATS missing")?)?,
            l7_services: HashMap::try_from(
                bpf.take_map("L7_SERVICES").context("map L7_SERVICES missing")?,
            )?,
        })
    }

    /// Mark `(vip, port)/tcp` as an L7 service: the datapath steers its flows to
    /// the user-space transparent proxy. Path routing lives in user space.
    pub fn l7_service_add(&mut self, vip: Ipv4Addr, port: u16) -> Result<()> {
        self.l7_services.insert(
            ServiceKey {
                vip: util::ipv4_to_map(vip),
                port: util::port_to_map(port),
                proto: 6,
                _pad: 0,
            },
            1,
            0,
        )?;
        Ok(())
    }

    /// Read the per-CPU datapath packet counters, summed across CPUs and indexed
    /// by the `STAT_*` constants (see `cradle_common`).
    pub fn stats(&self) -> Result<Vec<u64>> {
        let mut out = Vec::with_capacity(STAT_MAX as usize);
        for i in 0..STAT_MAX {
            let per_cpu = self.stats.get(&i, 0)?;
            out.push(per_cpu.iter().copied().sum());
        }
        Ok(out)
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
    /// A non-empty `labels` is the MPLS out-label stack (swap value /
    /// imposition stack, `[0]` = outermost).
    pub fn nexthop_set(
        &mut self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: u32,
        labels: &[u32],
    ) -> Result<()> {
        let gateway_v4 = gateway.map(|a| u32::from_be_bytes(a.octets())).unwrap_or(0);
        let (labels, num_labels, flags) = pack_labels(labels)?;
        let nh = NextHop {
            gateway_v4,
            gateway_v6: [0; 16],
            oif,
            flags,
            labels,
            num_labels,
            _pad: [0; 3],
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

    /// Switch the v4 FIB to the DIR-24-8 engine. Load-time only: the maps
    /// must have been sized by the loader (`--fib4-mode dir24`) and no v4
    /// routes may have been installed yet.
    pub fn set_fib4_mode_dir24(&mut self) -> Result<()> {
        self.dir24 = Some(Dir24Engine::new(DIR24_TBL8_GROUPS));
        self.dp_config.set(0, DPC_FIB4_DIR24, 0)?;
        Ok(())
    }

    /// Apply a DIR-24-8 slot-write plan. Plan order is the readers' safety
    /// (fill-then-flip); `Array::set` is a per-element atomic word store.
    fn dir24_apply(&mut self, plan: &[SlotWrite]) -> Result<()> {
        for w in plan {
            match *w {
                SlotWrite::Tbl24 { idx, word } => self.tbl24.set(idx, word, 0)?,
                SlotWrite::Tbl8 { idx, word } => self.tbl8.set(idx, word, 0)?,
                SlotWrite::Default(word) => self.default4.set(0, word, 0)?,
            }
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
        if let Some(eng) = self.dir24.as_mut() {
            let plan = eng.route_add(u32::from(addr), prefix_len, FibEntry { nexthop_id, flags })?;
            self.dir24_apply(&plan)?;
            return Ok(());
        }
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib4.insert(&key, FibEntry { nexthop_id, flags }, 0)?;
        Ok(())
    }

    /// Remove an IPv4 route.
    pub fn route4_del(&mut self, addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
        if let Some(eng) = self.dir24.as_mut() {
            let plan = eng.route_del(u32::from(addr), prefix_len)?;
            self.dir24_apply(&plan)?;
            return Ok(());
        }
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib4.remove(&key)?;
        Ok(())
    }

    /// Install many IPv4 routes at once — the bulk initial-load path.
    /// `(addr, prefix_len, nexthop_id, flags)` per route.
    pub fn route4_add_bulk(&mut self, routes: &[(Ipv4Addr, u8, u32, u32)]) -> Result<()> {
        if let Some(eng) = self.dir24.as_mut() {
            let batch: Vec<(u32, u8, FibEntry)> = routes
                .iter()
                .map(|&(addr, len, nexthop_id, flags)| {
                    (u32::from(addr), len, FibEntry { nexthop_id, flags })
                })
                .collect();
            let plan = eng.route_add_bulk(&batch)?;
            self.dir24_apply(&plan)?;
            return Ok(());
        }
        for &(addr, len, nexthop_id, flags) in routes {
            let key = Key::new(len as u32, addr.octets());
            self.fib4.insert(&key, FibEntry { nexthop_id, flags }, 0)?;
        }
        Ok(())
    }

    /// IPv4 FIB engine state: `(mode, routes, tbl8_used, tbl8_free)`.
    pub fn fib_summary(&self) -> (&'static str, u64, u32, u32) {
        match &self.dir24 {
            Some(eng) => (
                "dir24",
                eng.route_count() as u64,
                eng.groups_in_use() as u32,
                eng.tbl8_free() as u32,
            ),
            None => ("lpm", 0, 0, 0),
        }
    }

    /// Install/replace an IPv6 nexthop. `gateway == None` means on-link.
    pub fn nexthop_set_v6(
        &mut self,
        id: u32,
        gateway: Option<Ipv6Addr>,
        oif: u32,
        labels: &[u32],
    ) -> Result<()> {
        let (labels, num_labels, label_flags) = pack_labels(labels)?;
        let nh = NextHop {
            gateway_v4: 0,
            gateway_v6: gateway.map(|a| a.octets()).unwrap_or([0; 16]),
            oif,
            flags: NH_F_V6 | label_flags,
            labels,
            num_labels,
            _pad: [0; 3],
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

    /// Set the neighbor (ND) entry for `ip` reachable out `ifindex`.
    pub fn neigh6_set(&mut self, ifindex: u32, ip: Ipv6Addr, mac: [u8; 6]) -> Result<()> {
        let key = Neigh6Key {
            ifindex,
            addr: ip.octets(),
        };
        self.neigh6.insert(
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

    /// Install/replace an incoming-label map (ILM) entry: frames arriving with
    /// top label `in_label` get `op` applied via `nexthop_id`.
    pub fn ilm_add(&mut self, in_label: u32, nexthop_id: u32, op: u8, vrf_id: u32) -> Result<()> {
        if in_label >= 1 << 20 {
            anyhow::bail!("MPLS label {in_label} exceeds 20 bits");
        }
        self.mpls_fib.insert(
            in_label,
            MplsEntry {
                nexthop_id,
                vrf_id,
                op,
                _pad: [0; 3],
            },
            0,
        )?;
        Ok(())
    }

    /// Remove an ILM entry.
    pub fn ilm_del(&mut self, in_label: u32) -> Result<()> {
        self.mpls_fib.remove(&in_label)?;
        Ok(())
    }
}

/// Validate and pack an out-label stack into the fixed `NextHop` fields:
/// `(labels array, num_labels, NH_F_MPLS-or-0)`.
fn pack_labels(labels: &[u32]) -> Result<([u32; MAX_LABELS], u8, u32)> {
    if labels.len() > MAX_LABELS {
        anyhow::bail!("label stack too deep: {} > {}", labels.len(), MAX_LABELS);
    }
    for &l in labels {
        if l >= 1 << 20 {
            anyhow::bail!("MPLS label {l} exceeds 20 bits");
        }
    }
    let mut arr = [0u32; MAX_LABELS];
    arr[..labels.len()].copy_from_slice(labels);
    let flags = if labels.is_empty() { 0 } else { NH_F_MPLS };
    Ok((arr, labels.len() as u8, flags))
}
