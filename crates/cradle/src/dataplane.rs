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
    Backend, Backend6, BackendKey, Dx2vKey, FdbEntry, FdbKey, FibEntry, FibWord, GtpEncap, GtpPdr,
    GtpPdrKey, L2MemberKey, LocalSid, MirrorEntry, MirrorKey, MplsEntry, Neigh4Key, Neigh6Key,
    NeighEntry, NextHop, NhGroupKey, PortConfig, ServiceInfo, ServiceKey, ServiceKey6, Srv6Encap,
    Vrf4Key, Vrf6Key, DIR24_TBL8_GROUPS, DPC_FIB4_DIR24, FDB_F_REMOTE, LB_ALGO_RANDOM, MAX_LABELS,
    NEIGH_STATE_REACHABLE, NH_F_GTP, NH_F_MPLS, NH_F_SRV6, NH_F_V6, STAT_FDB_AGED, STAT_MAX,
};

use crate::{
    dir24::{Dir24Engine, SlotWrite},
    util,
};

pub struct Dataplane {
    fib4: LpmTrie<MapData, [u8; 4], FibEntry>,
    fib6: LpmTrie<MapData, [u8; 16], FibEntry>,
    fib4_vrf: LpmTrie<MapData, Vrf4Key, FibEntry>,
    fib6_vrf: LpmTrie<MapData, Vrf6Key, FibEntry>,
    srv6_localsid: LpmTrie<MapData, [u8; 16], LocalSid>,
    srv6_encap: HashMap<MapData, u32, Srv6Encap>,
    gtp_encap: HashMap<MapData, u32, GtpEncap>,
    gtp_pdr: HashMap<MapData, GtpPdrKey, GtpPdr>,
    srv6_encap_src: Array<MapData, [u8; 16]>,
    meta_cookie: Array<MapData, u32>,
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
    /// Links whose carrier/admin state is down — the datapath fails over to
    /// nexthop `backup_id`s while an ifindex is present here.
    link_down: HashMap<MapData, u32, u8>,
    /// Static overlay FDB entries (EVPN over SRv6). Local MACs are still learned
    /// in the eBPF datapath; this only programs remote (`FDB_F_REMOTE`) entries.
    fdb: HashMap<MapData, FdbKey, FdbEntry>,
    /// BUM ingress-replication slots (EVPN over SRv6): ifindex → remote
    /// `End.DT2M` SID, both ends of each slot's veth pair.
    repl_sid: HashMap<MapData, u32, [u8; 16]>,
    xconnect: HashMap<MapData, u32, [u8; 16]>,
    dx2v: HashMap<MapData, Dx2vKey, u32>,
    /// Egress-protection mirror contexts (`End.M`): protected SID space →
    /// local DT-style reproduction.
    mirror: LpmTrie<MapData, MirrorKey, MirrorEntry>,
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
            fib4_vrf: LpmTrie::try_from(bpf.take_map("FIB4_VRF").context("map FIB4_VRF missing")?)?,
            fib6_vrf: LpmTrie::try_from(bpf.take_map("FIB6_VRF").context("map FIB6_VRF missing")?)?,
            srv6_localsid: LpmTrie::try_from(
                bpf.take_map("SRV6_LOCALSID")
                    .context("map SRV6_LOCALSID missing")?,
            )?,
            srv6_encap: HashMap::try_from(
                bpf.take_map("SRV6_ENCAP")
                    .context("map SRV6_ENCAP missing")?,
            )?,
            gtp_encap: HashMap::try_from(
                bpf.take_map("GTP_ENCAP").context("map GTP_ENCAP missing")?,
            )?,
            gtp_pdr: HashMap::try_from(bpf.take_map("GTP_PDR").context("map GTP_PDR missing")?)?,
            srv6_encap_src: Array::try_from(
                bpf.take_map("SRV6_ENCAP_SRC")
                    .context("map SRV6_ENCAP_SRC missing")?,
            )?,
            meta_cookie: Array::try_from(
                bpf.take_map("META_COOKIE")
                    .context("map META_COOKIE missing")?,
            )?,
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
                bpf.take_map("NHGROUP_MEMBER")
                    .context("map NHGROUP_MEMBER missing")?,
            )?,
            neigh4: HashMap::try_from(bpf.take_map("NEIGH4").context("map NEIGH4 missing")?)?,
            neigh6: HashMap::try_from(bpf.take_map("NEIGH6").context("map NEIGH6 missing")?)?,
            mpls_fib: HashMap::try_from(bpf.take_map("MPLS_FIB").context("map MPLS_FIB missing")?)?,
            ports: HashMap::try_from(bpf.take_map("PORTS").context("map PORTS missing")?)?,
            l2_members: HashMap::try_from(
                bpf.take_map("L2_MEMBERS")
                    .context("map L2_MEMBERS missing")?,
            )?,
            l2_count: HashMap::try_from(bpf.take_map("L2_COUNT").context("map L2_COUNT missing")?)?,
            link_down: HashMap::try_from(
                bpf.take_map("LINK_DOWN").context("map LINK_DOWN missing")?,
            )?,
            fdb: HashMap::try_from(bpf.take_map("FDB").context("map FDB missing")?)?,
            repl_sid: HashMap::try_from(bpf.take_map("REPL_SID").context("map REPL_SID missing")?)?,
            xconnect: HashMap::try_from(
                bpf.take_map("XCONNECT").context("map XCONNECT missing")?,
            )?,
            dx2v: HashMap::try_from(bpf.take_map("DX2V").context("map DX2V missing")?)?,
            mirror: LpmTrie::try_from(bpf.take_map("MIRROR").context("map MIRROR missing")?)?,
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
                bpf.take_map("L7_SERVICES")
                    .context("map L7_SERVICES missing")?,
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

    /// Register an interface (by ifindex) with its MAC, `PORT_F_*` flags,
    /// L2 VLAN/bridge domain, and (for L3 ports) VRF binding (0 = global).
    pub fn port_set(
        &mut self,
        ifindex: u32,
        mac: [u8; 6],
        flags: u32,
        vlan: u16,
        vrf_id: u32,
    ) -> Result<()> {
        self.ports.insert(
            ifindex,
            PortConfig {
                mac,
                vlan,
                flags,
                vrf_id,
            },
            0,
        )?;
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

    /// Program a static overlay FDB entry (EVPN over SRv6): the MAC `mac` in
    /// bridge domain `bd` sits behind `remote_sid` (the remote PE's `End.DT2U`
    /// SID), reached via underlay nexthop `nexthop_id`. Frames to `mac` are
    /// MAC-in-SRv6 encapsulated in the XDP stage.
    pub fn fdb_remote_add(
        &mut self,
        mac: [u8; 6],
        bd: u16,
        remote_sid: Ipv6Addr,
        nexthop_id: u32,
    ) -> Result<()> {
        self.fdb.insert(
            FdbKey { mac, vlan: bd },
            FdbEntry {
                oif: nexthop_id,
                flags: FDB_F_REMOTE,
                remote_sid: remote_sid.octets(),
                last_seen: 0,
            },
            0,
        )?;
        Ok(())
    }

    /// Remove an overlay FDB entry — but only if it still IS one. After a
    /// MAC moves to a local port, the datapath learn overwrites the remote
    /// entry with a local one; the previous owner's Type-2 withdraw then
    /// arrives and must not clobber the fresh local learn (RFC 7432 §7.7 —
    /// the station is here now; the withdraw refers to a superseded remote
    /// binding).
    pub fn fdb_remote_del(&mut self, mac: [u8; 6], bd: u16) -> Result<()> {
        let key = FdbKey { mac, vlan: bd };
        if matches!(self.fdb.get(&key, 0), Ok(e) if e.flags & FDB_F_REMOTE == 0) {
            return Ok(());
        }
        self.fdb.remove(&key)?;
        Ok(())
    }

    /// Append one member to an L2 (VLAN/bridge) domain's flood list without
    /// rewriting it (dynamic replication-slot management). No-op if already
    /// a member.
    pub fn l2_member_add(&mut self, vlan: u16, ifindex: u32) -> Result<()> {
        let count = self.l2_count.get(&vlan, 0).unwrap_or(0);
        for slot in 0..count {
            let member = self.l2_members.get(
                &L2MemberKey {
                    vlan,
                    slot: slot as u16,
                },
                0,
            );
            if matches!(member, Ok(m) if m == ifindex) {
                return Ok(());
            }
        }
        self.l2_members.insert(
            L2MemberKey {
                vlan,
                slot: count as u16,
            },
            ifindex,
            0,
        )?;
        self.l2_count.insert(vlan, count + 1, 0)?;
        Ok(())
    }

    /// Remove one member from an L2 domain's flood list, compacting the
    /// dense slot array. No-op if not a member.
    pub fn l2_member_remove(&mut self, vlan: u16, ifindex: u32) -> Result<()> {
        let count = self.l2_count.get(&vlan, 0).unwrap_or(0);
        let mut members: Vec<u32> = Vec::with_capacity(count as usize);
        for slot in 0..count {
            if let Ok(m) = self.l2_members.get(
                &L2MemberKey {
                    vlan,
                    slot: slot as u16,
                },
                0,
            ) {
                members.push(m);
            }
        }
        let before = members.len();
        members.retain(|&m| m != ifindex);
        if members.len() == before {
            return Ok(());
        }
        self.l2_domain_set(vlan, &members)?;
        // Drop the now-stale tail slot.
        let _ = self.l2_members.remove(&L2MemberKey {
            vlan,
            slot: members.len() as u16,
        });
        Ok(())
    }

    /// Install an egress-protection mirror route: End.M-exposed traffic to
    /// `prefix` (the protected egress's SID space, context `ctx`) is served
    /// with `behavior` (`SRV6_BH_END_DT*`) into local table `vrf_id`.
    pub fn mirror_route_add(
        &mut self,
        ctx: u32,
        prefix: Ipv6Addr,
        prefix_len: u8,
        behavior: u8,
        vrf_id: u32,
    ) -> Result<()> {
        let key = Key::new(
            32 + prefix_len as u32,
            MirrorKey {
                ctx,
                addr: prefix.octets(),
            },
        );
        self.mirror.insert(
            &key,
            MirrorEntry {
                behavior,
                _pad: [0; 3],
                vrf_id,
            },
            0,
        )?;
        Ok(())
    }

    /// Remove a mirror route.
    pub fn mirror_route_del(&mut self, ctx: u32, prefix: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let key = Key::new(
            32 + prefix_len as u32,
            MirrorKey {
                ctx,
                addr: prefix.octets(),
            },
        );
        self.mirror.remove(&key)?;
        Ok(())
    }

    /// Remove a replication-slot SID binding.
    /// Bind an attachment circuit to a remote End.DX2/DX2V SID (VPWS):
    /// every frame arriving on `ifindex` encapsulates toward `remote_sid`.
    pub fn xconnect_add(&mut self, ifindex: u32, remote_sid: Ipv6Addr) -> Result<()> {
        self.xconnect.insert(ifindex, remote_sid.octets(), 0)?;
        Ok(())
    }

    pub fn xconnect_del(&mut self, ifindex: u32) -> Result<()> {
        self.xconnect.remove(&ifindex)?;
        Ok(())
    }

    /// End.DX2V VLAN-table entry: (table, vid) → AC ifindex.
    pub fn dx2v_add(&mut self, table: u32, vid: u16, oif: u32) -> Result<()> {
        let key = Dx2vKey {
            table,
            vid,
            _pad: [0; 2],
        };
        self.dx2v.insert(key, oif, 0)?;
        Ok(())
    }

    pub fn dx2v_del(&mut self, table: u32, vid: u16) -> Result<()> {
        let key = Dx2vKey {
            table,
            vid,
            _pad: [0; 2],
        };
        self.dx2v.remove(&key)?;
        Ok(())
    }

    pub fn repl_sid_del(&mut self, ifindex: u32) -> Result<()> {
        self.repl_sid.remove(&ifindex)?;
        Ok(())
    }

    /// Register a BUM replication slot (EVPN ingress replication): frames
    /// flooded to `flood_ifindex` (the slot veth's A end, a bridge-domain
    /// member) arrive on `encap_ifindex` (the B end), where the datapath
    /// MAC-in-SRv6 encapsulates them toward `remote_sid` (a remote PE's
    /// `End.DT2M`). Both ends are keyed so `flood()` can exclude the slot
    /// on overlay-received frames (split horizon).
    pub fn repl_slot_add(
        &mut self,
        flood_ifindex: u32,
        encap_ifindex: u32,
        remote_sid: Ipv6Addr,
    ) -> Result<()> {
        self.repl_sid
            .insert(flood_ifindex, remote_sid.octets(), 0)?;
        self.repl_sid
            .insert(encap_ifindex, remote_sid.octets(), 0)?;
        Ok(())
    }

    /// Mark a link down/up for fast-reroute (`LINK_DOWN`): while down, the
    /// datapath swaps protected nexthops to their `backup_id`.
    pub fn link_state_set(&mut self, ifindex: u32, down: bool) -> Result<()> {
        if down {
            self.link_down.insert(ifindex, 1, 0)?;
        } else {
            let _ = self.link_down.remove(&ifindex);
        }
        Ok(())
    }

    /// Expire idle locally-learned FDB entries: remove every local
    /// (`flags == 0`) entry whose `last_seen` is older than `max_idle` and
    /// bump `STAT_FDB_AGED` per removal. Returns the number aged out.
    /// Entries with `last_seen == 0` (installed before stamping, or by
    /// control planes) are left alone. `WatchFdb` subscribers observe the
    /// disappearance in their next scan and report an age event upstream.
    pub fn fdb_age_sweep(&mut self, max_idle: std::time::Duration) -> Result<usize> {
        let now = nix::time::clock_gettime(nix::time::ClockId::CLOCK_MONOTONIC)?;
        let now_ns = now.tv_sec() as u64 * 1_000_000_000 + now.tv_nsec() as u64;
        let max_idle_ns = max_idle.as_nanos() as u64;
        let mut stale = Vec::new();
        for item in self.fdb.iter() {
            let Ok((k, v)) = item else { continue };
            if v.flags != 0 || v.last_seen == 0 {
                continue;
            }
            if now_ns.saturating_sub(v.last_seen) > max_idle_ns {
                stale.push(k);
            }
        }
        let aged = stale.len();
        for k in stale {
            let _ = self.fdb.remove(&k);
            self.stat_bump(STAT_FDB_AGED)?;
        }
        Ok(aged)
    }

    /// Bump a datapath stat counter from user space (cpu-0 slot of the
    /// per-CPU array) — used by control-plane-side events like FDB aging.
    fn stat_bump(&mut self, idx: u32) -> Result<()> {
        let values = self.stats.get(&idx, 0)?;
        let mut v: Vec<u64> = values.iter().copied().collect();
        if let Some(first) = v.first_mut() {
            *first += 1;
        }
        self.stats
            .set(idx, aya::maps::PerCpuValues::try_from(v)?, 0)?;
        Ok(())
    }

    /// Locally-learned FDB entries (datapath MAC learning): every unicast MAC
    /// in a bridge domain learned on a local port — `flags == 0`, so never
    /// overlay (`FDB_F_REMOTE`) entries or the all-ones BUM sentinel. The
    /// `WatchFdb` stream diffs successive snapshots to report EVPN Type-2
    /// candidates to the control plane.
    pub fn fdb_local_entries(&self) -> Vec<([u8; 6], u16)> {
        let mut out = Vec::new();
        for item in self.fdb.iter() {
            let Ok((k, v)) = item else { continue };
            if v.flags != 0 || k.mac[0] & 0x01 != 0 {
                continue;
            }
            out.push((k.mac, k.vlan));
        }
        out
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
        backup_id: u32,
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
            backup_id,
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
    /// `vrf != 0` targets that VRF's table (the vrf-prefixed LPM trie —
    /// never the DIR-24-8 engine, which is global-only).
    pub fn route4_add(
        &mut self,
        vrf: u32,
        addr: Ipv4Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        if vrf != 0 {
            let key = Key::new(
                32 + prefix_len as u32,
                Vrf4Key {
                    vrf_id: vrf,
                    addr: addr.octets(),
                },
            );
            self.fib4_vrf
                .insert(&key, FibEntry { nexthop_id, flags }, 0)?;
            return Ok(());
        }
        if let Some(eng) = self.dir24.as_mut() {
            let plan =
                eng.route_add(u32::from(addr), prefix_len, FibEntry { nexthop_id, flags })?;
            self.dir24_apply(&plan)?;
            return Ok(());
        }
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib4.insert(&key, FibEntry { nexthop_id, flags }, 0)?;
        Ok(())
    }

    /// Remove an IPv4 route.
    pub fn route4_del(&mut self, vrf: u32, addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
        if vrf != 0 {
            let key = Key::new(
                32 + prefix_len as u32,
                Vrf4Key {
                    vrf_id: vrf,
                    addr: addr.octets(),
                },
            );
            self.fib4_vrf.remove(&key)?;
            return Ok(());
        }
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
    /// `(vrf, addr, prefix_len, nexthop_id, flags)` per route; the global
    /// subset (`vrf == 0`) rides the dir24 bulk plan when that engine is on.
    pub fn route4_add_bulk(&mut self, routes: &[(u32, Ipv4Addr, u8, u32, u32)]) -> Result<()> {
        for &(vrf, addr, len, nexthop_id, flags) in routes.iter().filter(|r| r.0 != 0) {
            self.route4_add(vrf, addr, len, nexthop_id, flags)?;
        }
        if let Some(eng) = self.dir24.as_mut() {
            let batch: Vec<(u32, u8, FibEntry)> = routes
                .iter()
                .filter(|r| r.0 == 0)
                .map(|&(_, addr, len, nexthop_id, flags)| {
                    (u32::from(addr), len, FibEntry { nexthop_id, flags })
                })
                .collect();
            if !batch.is_empty() {
                let plan = eng.route_add_bulk(&batch)?;
                self.dir24_apply(&plan)?;
            }
            return Ok(());
        }
        for &(vrf, addr, len, nexthop_id, flags) in routes.iter().filter(|r| r.0 == 0) {
            let _ = vrf;
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
        backup_id: u32,
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
            backup_id,
        };
        self.nexthops.insert(id, nh, 0)?;
        Ok(())
    }

    /// Install/replace an SRv6-encap nexthop: an IPv6 underlay nexthop
    /// (`gateway`/`oif`) that imposes the segment list `segs` (H.Encaps).
    pub fn nexthop_set_srv6(
        &mut self,
        id: u32,
        gateway: Option<Ipv6Addr>,
        oif: u32,
        segs: &[Ipv6Addr],
        mode: u8,
    ) -> Result<()> {
        if segs.is_empty() || segs.len() > cradle_common::MAX_SEGS {
            anyhow::bail!("SRv6 segment list must be 1..={}", cradle_common::MAX_SEGS);
        }
        let nh = NextHop {
            gateway_v4: 0,
            gateway_v6: gateway.map(|a| a.octets()).unwrap_or([0; 16]),
            oif,
            flags: NH_F_V6 | NH_F_SRV6,
            labels: [0; MAX_LABELS],
            num_labels: 0,
            _pad: [0; 3],
            backup_id: 0,
        };
        self.nexthops.insert(id, nh, 0)?;
        let mut enc = Srv6Encap {
            num_segs: segs.len() as u8,
            mode,
            _pad: [0; 2],
            segs: [[0u8; 16]; cradle_common::MAX_SEGS],
        };
        for (i, s) in segs.iter().enumerate() {
            enc.segs[i] = s.octets();
        }
        self.srv6_encap.insert(id, enc, 0)?;
        Ok(())
    }

    /// Install/replace a GTP-U-encap nexthop (`GTP4.E`): an IPv4 underlay
    /// nexthop (`gateway`/`oif`) that imposes an outer IPv4 + UDP(2152) + GTP-U
    /// header. `src`/`dst` are the tunnel endpoints and `teid` the GTP-U TEID
    /// (stored as on-wire bytes in the `GTP_ENCAP` side table, keyed by id).
    pub fn nexthop_set_gtp(
        &mut self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: u32,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        teid: u32,
    ) -> Result<()> {
        let gateway_v4 = gateway.map(|a| u32::from_be_bytes(a.octets())).unwrap_or(0);
        let nh = NextHop {
            gateway_v4,
            gateway_v6: [0; 16],
            oif,
            flags: NH_F_GTP,
            labels: [0; MAX_LABELS],
            num_labels: 0,
            _pad: [0; 3],
            backup_id: 0,
        };
        self.nexthops.insert(id, nh, 0)?;
        let enc = GtpEncap {
            src: src.octets(),
            dst: dst.octets(),
            teid: teid.to_be_bytes(),
            qfi: 0,
            _pad: [0; 3],
        };
        self.gtp_encap.insert(id, enc, 0)?;
        Ok(())
    }

    /// Install a GTP-U decap PDR: a received G-PDU on (`dst`, `teid`) is
    /// stripped and its inner packet forwarded in `vrf` (0 = global).
    pub fn gtp_pdr_add(&mut self, dst: Ipv4Addr, teid: u32, vrf: u32) -> Result<()> {
        let key = GtpPdrKey {
            dst: dst.octets(),
            teid: teid.to_be_bytes(),
        };
        self.gtp_pdr.insert(key, GtpPdr { vrf_id: vrf }, 0)?;
        Ok(())
    }

    /// Remove a GTP-U decap PDR (idempotent).
    pub fn gtp_pdr_del(&mut self, dst: Ipv4Addr, teid: u32) -> Result<()> {
        let key = GtpPdrKey {
            dst: dst.octets(),
            teid: teid.to_be_bytes(),
        };
        let _ = self.gtp_pdr.remove(&key);
        Ok(())
    }

    /// Set the SRv6 H.Encaps outer source address.
    /// Seed the per-instance metadata cookie: skb metadata survives a veth
    /// hop into the neighbour's TC stage, so the XDP→TC magic must differ
    /// per cradle instance or one node's End.T/DT table id would steer the
    /// next node's lookup. Random, non-zero.
    pub fn meta_cookie_seed(&mut self) -> Result<()> {
        use std::io::Read;
        let mut buf = [0u8; 4];
        let filled = std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut buf))
            .is_ok();
        if !filled {
            let pid = std::process::id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            buf = (pid ^ now).to_ne_bytes();
        }
        let cookie = u32::from_ne_bytes(buf) | 1; // never zero
        self.meta_cookie.set(0, cookie, 0)?;
        Ok(())
    }

    pub fn srv6_encap_source_set(&mut self, addr: Ipv6Addr) -> Result<()> {
        self.srv6_encap_src.set(0, addr.octets(), 0)?;
        Ok(())
    }

    /// Install/replace a local SID (seg6local). Phase 1 executes the
    /// `End.DT4/DT6/DT46` behaviors; others are stored and punted.
    #[allow(clippy::too_many_arguments)]
    pub fn localsid_add(
        &mut self,
        sid: Ipv6Addr,
        prefix_len: u8,
        behavior: u8,
        vrf_id: u32,
        nexthop_id: u32,
        block_bits: u8,
        node_bits: u8,
        fun_bits: u8,
        flavors: u8,
    ) -> Result<()> {
        let key = Key::new(prefix_len as u32, sid.octets());
        self.srv6_localsid.insert(
            &key,
            LocalSid {
                behavior,
                flavors,
                _pad: [0; 2],
                vrf_id,
                nexthop_id,
                block_bits,
                node_bits,
                fun_bits,
                _pad2: [0; 1],
            },
            0,
        )?;
        Ok(())
    }

    /// Remove a local SID.
    pub fn localsid_del(&mut self, sid: Ipv6Addr, prefix_len: u8) -> Result<()> {
        let key = Key::new(prefix_len as u32, sid.octets());
        self.srv6_localsid.remove(&key)?;
        Ok(())
    }

    /// Install an IPv6 route `addr/prefix_len` pointing at `nexthop_id`.
    /// `vrf != 0` targets that VRF's IPv6 table.
    pub fn route6_add(
        &mut self,
        vrf: u32,
        addr: Ipv6Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        if vrf != 0 {
            let key = Key::new(
                32 + prefix_len as u32,
                Vrf6Key {
                    vrf_id: vrf,
                    addr: addr.octets(),
                },
            );
            self.fib6_vrf
                .insert(&key, FibEntry { nexthop_id, flags }, 0)?;
            return Ok(());
        }
        let key = Key::new(prefix_len as u32, addr.octets());
        self.fib6.insert(&key, FibEntry { nexthop_id, flags }, 0)?;
        Ok(())
    }

    /// Remove an IPv6 route.
    pub fn route6_del(&mut self, vrf: u32, addr: Ipv6Addr, prefix_len: u8) -> Result<()> {
        if vrf != 0 {
            let key = Key::new(
                32 + prefix_len as u32,
                Vrf6Key {
                    vrf_id: vrf,
                    addr: addr.octets(),
                },
            );
            self.fib6_vrf.remove(&key)?;
            return Ok(());
        }
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
