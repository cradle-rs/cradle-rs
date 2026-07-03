#![no_std]
#![no_main]

//! cradle-rs eBPF data plane — integrated L2 switch / L3 router / L4 load balancer.
//!
//! Attached at TC ingress on each managed port. The ingress port's mode (in
//! `PORTS`) selects the path:
//!
//! * **L2 (`PORT_F_L2`)** — MAC learning into `FDB`, then forward by destination
//!   MAC: known unicast → `bpf_redirect`; BUM / unknown unicast → flood the
//!   VLAN's members via `bpf_clone_redirect`.
//! * **L3 (`PORT_F_L3`)** — an L4 NAT pre-stage (service DNAT + connection
//!   tracking, reverse SNAT) followed by IPv4 routing: LPM `FIB4` → nexthop →
//!   neighbor → MAC rewrite + TTL decrement → `bpf_redirect`.
//!
//! Address/port encoding in the maps is "memory order": an IPv4 address is the
//! `u32` whose little-endian bytes are the network octets (exactly what
//! `ctx.load::<u32>()` yields), and a port is the wire bytes read as a native
//! `u16`. `bpf_l3/l4_csum_replace` consume `from`/`to` in this same order.

use aya_ebpf::{
    bindings::{
        bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, bpf_redir_neigh, bpf_redir_neigh__bindgen_ty_1,
        bpf_sock_tuple, bpf_sock_tuple__bindgen_ty_1, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1,
        xdp_action, TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT,
    },
    helpers::generated::{
        bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh, bpf_sk_assign,
        bpf_sk_release, bpf_skc_lookup_tcp, bpf_xdp_adjust_head, bpf_xdp_adjust_meta,
    },
    macros::{classifier, map, xdp},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, LruHashMap, PerCpuArray},
    programs::{TcContext, XdpContext},
};
use cradle_common::{
    fibw_unpack, mpls_lse, mpls_lse_unpack, Backend, Backend6, BackendKey, CradleXdpMeta, CtEntry,
    CtEntry6, CtKey, CtKey6, FdbEntry, FdbKey, FibEntry, FibWord, L2MemberKey, LocalSid, MplsEntry,
    Neigh4Key, Neigh6Key, NeighEntry, NextHop, NhGroupKey, PortConfig, ServiceInfo, ServiceKey,
    ServiceKey6, Srv6Encap, Vrf4Key, Vrf6Key, CT_F_DNAT, CT_F_SNAT, DPC_FIB4_DIR24, FIBW_ID_MASK,
    FIBW_TBL8, FIBW_VALID, FIB_F_BLACKHOLE, FIB_F_ECMP, FIB_F_LOCAL, L7_PROXY_PORT, MAX_LABELS,
    MAX_SEGS, MPLS_OP_POP, MPLS_OP_POP_L3, MPLS_OP_SWAP, NH_F_MPLS, NH_F_SRV6, NH_F_V6, PORT_F_L2,
    PORT_F_L3,
    SRV6_BH_END, SRV6_BH_END_DT4, SRV6_BH_END_DT46, SRV6_BH_END_DT6, SRV6_BH_END_X, STAT_DROP,
    STAT_FIB4_DEFAULT, STAT_FIB4_TBL24_HIT, STAT_FIB4_TBL8_HIT, STAT_FIB4_VRF_HIT,
    STAT_FIB6_VRF_HIT, STAT_L2_FLOOD, STAT_L2_FORWARD, STAT_L3V4_FORWARD, STAT_L3V6_FORWARD,
    STAT_L3_LOCAL, STAT_L4_DNAT, STAT_L4_SNAT, STAT_L7_REDIRECT, STAT_MAX, STAT_MPLS_POP,
    STAT_MPLS_PUSH, STAT_MPLS_SWAP, STAT_SRV6_DECAP, STAT_SRV6_ENCAP, STAT_SRV6_END, XDP_META_MAGIC,
};
use network_types::eth::EthHdr;

// --- shared ---
#[map]
static PORTS: HashMap<u32, PortConfig> = HashMap::with_max_entries(256, 0);

// --- L3 ---
#[map]
static FIB4: LpmTrie<[u8; 4], FibEntry> = LpmTrie::with_max_entries(4096, 0);
#[map]
static FIB6: LpmTrie<[u8; 16], FibEntry> = LpmTrie::with_max_entries(4096, 0);

// --- L3 per-VRF v4 FIB: one LPM trie holds every VRF table via the
// vrf-prefixed key (mpls.md Phase 3; shared seam with SRv6/EVPN designs). ---
#[map]
static FIB4_VRF: LpmTrie<Vrf4Key, FibEntry> = LpmTrie::with_max_entries(4096, 0);
#[map]
static FIB6_VRF: LpmTrie<Vrf6Key, FibEntry> = LpmTrie::with_max_entries(4096, 0);

// --- SRv6 (srv6.md): local SID table (probed before FIB6), the per-nexthop
// segment list for H.Encaps, and the encap source address. ---
#[map]
static SRV6_LOCALSID: LpmTrie<[u8; 16], LocalSid> = LpmTrie::with_max_entries(4096, 0);
#[map]
static SRV6_ENCAP: HashMap<u32, Srv6Encap> = HashMap::with_max_entries(4096, 0);
#[map]
static SRV6_ENCAP_SRC: Array<[u8; 16]> = Array::with_max_entries(1, 0);

// --- L3 DIR-24-8 v4 engine (large-fib.md). Declared at 1 entry; the loader
// upsizes them (TBL24 → 2^24, TBL8 → groups*256) only in dir24 mode, so
// lpm-mode loads never pay the memory. ---
#[map]
static TBL24: Array<FibWord> = Array::with_max_entries(1, 0);
#[map]
static TBL8: Array<FibWord> = Array::with_max_entries(1, 0);
#[map]
static DEFAULT4: Array<FibWord> = Array::with_max_entries(1, 0);
// Datapath configuration word(s), written by user space: DPC_* bits.
#[map]
static DP_CONFIG: Array<u32> = Array::with_max_entries(1, 0);
#[map]
static NEXTHOPS: HashMap<u32, NextHop> = HashMap::with_max_entries(4096, 0);
// Nexthop groups for ECMP: group_id -> member count, and (group_id, slot) -> nexthop id.
#[map]
static NHGROUP: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);
#[map]
static NHGROUP_MEMBER: HashMap<NhGroupKey, u32> = HashMap::with_max_entries(8192, 0);
#[map]
static NEIGH4: HashMap<Neigh4Key, NeighEntry> = HashMap::with_max_entries(4096, 0);
#[map]
static NEIGH6: HashMap<Neigh6Key, NeighEntry> = HashMap::with_max_entries(4096, 0);

// --- MPLS: incoming-label map (ILM), keyed by the 20-bit top label ---
#[map]
static MPLS_FIB: HashMap<u32, MplsEntry> = HashMap::with_max_entries(4096, 0);

// --- L2 ---
#[map]
static FDB: HashMap<FdbKey, FdbEntry> = HashMap::with_max_entries(8192, 0);
#[map]
static L2_MEMBERS: HashMap<L2MemberKey, u32> = HashMap::with_max_entries(4096, 0);
#[map]
static L2_COUNT: HashMap<u16, u32> = HashMap::with_max_entries(256, 0);

// --- L4 ---
#[map]
static SERVICES: HashMap<ServiceKey, ServiceInfo> = HashMap::with_max_entries(1024, 0);
#[map]
static BACKENDS: HashMap<BackendKey, Backend> = HashMap::with_max_entries(8192, 0);
#[map]
static CT: LruHashMap<CtKey, CtEntry> = LruHashMap::with_max_entries(65536, 0);
// L4 IPv6
#[map]
static SERVICES6: HashMap<ServiceKey6, ServiceInfo> = HashMap::with_max_entries(1024, 0);
#[map]
static BACKENDS6: HashMap<BackendKey, Backend6> = HashMap::with_max_entries(8192, 0);
#[map]
static CT6: LruHashMap<CtKey6, CtEntry6> = LruHashMap::with_max_entries(65536, 0);

// --- observability: per-CPU packet counters, indexed by STAT_* ---
#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(STAT_MAX, 0);

// --- L7: VIP:port/proto flows steered to the user-space transparent proxy ---
#[map]
static L7_SERVICES: HashMap<ServiceKey, u8> = HashMap::with_max_entries(1024, 0);

/// Upper bound on flood fan-out per VLAN (also bounds the verifier's loop).
const MAX_L2_MEMBERS: u16 = 64;

const ETH_P_IP: u16 = 0x0800;
const ETH_P_MPLS_UC: u16 = 0x8847;
const ETH_TYPE_OFF: usize = 12;
const ETH_DST_OFF: usize = 0;
const ETH_SRC_OFF: usize = 6;

const IP_VER_IHL_OFF: usize = EthHdr::LEN;
const IP_TTL_OFF: usize = EthHdr::LEN + 8;
const IP_PROTO_OFF: usize = EthHdr::LEN + 9;
const IP_CSUM_OFF: usize = EthHdr::LEN + 10;
const IP_SRC_OFF: usize = EthHdr::LEN + 12;
const IP_DST_OFF: usize = EthHdr::LEN + 16;
/// L4 header start, assuming no IPv4 options (IHL == 5).
const L4_OFF: usize = EthHdr::LEN + 20;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;
const ETH_P_IPV6: u16 = 0x86dd;
const IP6_NEXTHDR_OFF: usize = EthHdr::LEN + 6;
const IP6_HOP_OFF: usize = EthHdr::LEN + 7;
const IP6_SRC_OFF: usize = EthHdr::LEN + 8;
const IP6_DST_OFF: usize = EthHdr::LEN + 24;
/// L4 header start for IPv6, assuming no extension headers.
const IP6_L4_OFF: usize = EthHdr::LEN + 40;
const BPF_F_PSEUDO_HDR: u64 = 16;
const BPF_F_MARK_MANGLED_0: u64 = 32;
/// `bpf_*_lookup_tcp` netns selector: look up sockets in the skb's own netns.
const BPF_F_CURRENT_NETNS: u64 = -1i64 as u64;
/// `bpf_sock.state` value for a listening TCP socket (kernel `BPF_TCP_LISTEN`).
const TCP_LISTEN: u32 = 10;

#[classifier]
pub fn cradle_tc(ctx: TcContext) -> i32 {
    match try_main(&ctx) {
        Ok(act) => act,
        Err(_) => TC_ACT_PIPE as i32,
    }
}

#[inline(always)]
fn ingress_ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ingress_ifindex }
}

/// Bump a per-CPU datapath counter (best-effort; never affects forwarding).
#[inline(always)]
fn stat_inc(idx: u32) {
    if let Some(c) = STATS.get_ptr_mut(idx) {
        unsafe { *c += 1 };
    }
}

/// Build an IPv4 `bpf_sock_tuple` (addresses/ports already in network order).
#[inline(always)]
fn sock_tuple(saddr: u32, daddr: u32, sport: u16, dport: u16) -> bpf_sock_tuple {
    bpf_sock_tuple {
        __bindgen_anon_1: bpf_sock_tuple__bindgen_ty_1 {
            ipv4: bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1 {
                saddr,
                daddr,
                sport,
                dport,
            },
        },
    }
}

/// Steer an L7-marked TCP flow to the user-space transparent proxy
/// (`L7_PROXY_PORT`) via `bpf_sk_assign`. Returns `Some(TC_ACT_OK)` when the
/// packet was assigned to a local socket, else `None` (fall through to routing).
///
/// For an established proxy connection the packet's own 4-tuple resolves the
/// socket; a fresh SYN finds the proxy's wildcard listener. The proxy binds
/// `IP_TRANSPARENT`, so the accepted socket's local address is the original VIP.
#[inline(always)]
fn l7_redirect(ctx: &TcContext) -> Option<i32> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).ok()?;
    if u16::from_be(ethertype) != ETH_P_IP {
        return None;
    }
    let ver_ihl: u8 = ctx.load(IP_VER_IHL_OFF).ok()?;
    if ver_ihl & 0x0f != 5 {
        return None; // IPv4 options present: skip
    }
    let proto: u8 = ctx.load(IP_PROTO_OFF).ok()?;
    if proto != IPPROTO_TCP {
        return None;
    }
    let src_ip: u32 = ctx.load(IP_SRC_OFF).ok()?;
    let dst_ip: u32 = ctx.load(IP_DST_OFF).ok()?;
    let sport: u16 = ctx.load(L4_OFF).ok()?;
    let dport: u16 = ctx.load(L4_OFF + 2).ok()?;

    // Only steer flows whose (VIP, port) is a configured L7 service.
    let key = ServiceKey {
        vip: dst_ip,
        port: dport,
        proto,
        _pad: 0,
    };
    L7_SERVICES.get_ptr(&key)?;

    let skb = ctx.skb.skb;
    let tlen = core::mem::size_of::<bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1>() as u32;

    // 1. Established proxy connection for this 4-tuple? Reuse it.
    let mut conn = sock_tuple(src_ip, dst_ip, sport, dport);
    let sk = unsafe { bpf_skc_lookup_tcp(skb as *mut _, &mut conn, tlen, BPF_F_CURRENT_NETNS, 0) };
    if !sk.is_null() {
        let state = unsafe { (*sk).state };
        if state != TCP_LISTEN {
            let r = unsafe { bpf_sk_assign(skb as *mut _, sk as *mut _, 0) };
            unsafe { bpf_sk_release(sk as *mut _) };
            if r == 0 {
                stat_inc(STAT_L7_REDIRECT);
                return Some(TC_ACT_OK as i32);
            }
            return None;
        }
        unsafe { bpf_sk_release(sk as *mut _) };
    }

    // 2. Fresh SYN: assign the proxy's wildcard listener (*:L7_PROXY_PORT).
    let mut lst = sock_tuple(0, dst_ip, 0, L7_PROXY_PORT.to_be());
    let psk = unsafe { bpf_skc_lookup_tcp(skb as *mut _, &mut lst, tlen, BPF_F_CURRENT_NETNS, 0) };
    if psk.is_null() {
        return None;
    }
    let r = unsafe { bpf_sk_assign(skb as *mut _, psk as *mut _, 0) };
    unsafe { bpf_sk_release(psk as *mut _) };
    if r == 0 {
        stat_inc(STAT_L7_REDIRECT);
        return Some(TC_ACT_OK as i32);
    }
    None
}

#[inline(always)]
fn try_main(ctx: &TcContext) -> Result<i32, ()> {
    let iif = ingress_ifindex(ctx);
    let port: PortConfig = match PORTS.get_ptr(&iif) {
        Some(p) => unsafe { *p },
        None => return Ok(TC_ACT_PIPE as i32),
    };

    if port.flags & PORT_F_L2 != 0 {
        l2_switch(ctx, iif, port.vlan)
    } else if port.flags & PORT_F_L3 != 0 {
        // L7: a TCP flow to an L7-marked VIP is steered to the user-space
        // transparent proxy via bpf_sk_assign (TC_ACT_OK = deliver locally).
        if let Some(act) = l7_redirect(ctx) {
            return Ok(act);
        }
        // L4 NAT is a best-effort pre-routing stage; it rewrites the packet in
        // place (service DNAT / reverse SNAT) so routing then targets the real
        // endpoint. Failures fall through to plain routing.
        let _ = l4_nat(ctx);
        l3_forward(ctx, port.vrf_id)
    } else {
        Ok(TC_ACT_PIPE as i32)
    }
}

// ============================== L2 switching ===============================

#[inline(always)]
fn l2_switch(ctx: &TcContext, iif: u32, vlan: u16) -> Result<i32, ()> {
    let dst: [u8; 6] = ctx.load(ETH_DST_OFF).map_err(|_| ())?;
    let src: [u8; 6] = ctx.load(ETH_SRC_OFF).map_err(|_| ())?;

    let _ = FDB.insert(
        &FdbKey { mac: src, vlan },
        &FdbEntry { oif: iif, flags: 0 },
        0,
    );

    if dst[0] & 0x01 != 0 {
        return Ok(flood(ctx, iif, vlan)); // broadcast / multicast
    }

    match FDB.get_ptr(&FdbKey { mac: dst, vlan }) {
        Some(e) => {
            let oif = unsafe { (*e).oif };
            if oif == iif {
                Ok(TC_ACT_SHOT as i32) // hairpin to the same port
            } else {
                stat_inc(STAT_L2_FORWARD);
                Ok(unsafe { bpf_redirect(oif, 0) } as i32)
            }
        }
        None => Ok(flood(ctx, iif, vlan)),
    }
}

#[inline(always)]
fn flood(ctx: &TcContext, iif: u32, vlan: u16) -> i32 {
    stat_inc(STAT_L2_FLOOD);
    let count = match L2_COUNT.get_ptr(&vlan) {
        Some(c) => unsafe { *c },
        None => 0,
    };
    let mut slot: u16 = 0;
    while slot < MAX_L2_MEMBERS {
        if slot as u32 >= count {
            break;
        }
        if let Some(p) = L2_MEMBERS.get_ptr(&L2MemberKey { vlan, slot }) {
            let oif = unsafe { *p };
            if oif != iif {
                let _ = ctx.clone_redirect(oif, 0);
            }
        }
        slot += 1;
    }
    TC_ACT_SHOT as i32
}

// ================================ L4 NAT ===================================

#[inline(always)]
fn l4_nat(ctx: &TcContext) -> Result<(), ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    match u16::from_be(ethertype) {
        ETH_P_IP => l4_nat_v4(ctx),
        ETH_P_IPV6 => l4_nat_v6(ctx),
        _ => Ok(()),
    }
}

#[inline(always)]
fn l4_nat_v4(ctx: &TcContext) -> Result<(), ()> {
    let ver_ihl: u8 = ctx.load(IP_VER_IHL_OFF).map_err(|_| ())?;
    if ver_ihl & 0x0f != 5 {
        return Ok(()); // IPv4 options present: skip NAT
    }
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Ok(());
    }

    let src_ip: u32 = ctx.load(IP_SRC_OFF).map_err(|_| ())?;
    let dst_ip: u32 = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    let sport: u16 = ctx.load(L4_OFF).map_err(|_| ())?;
    let dport: u16 = ctx.load(L4_OFF + 2).map_err(|_| ())?;

    let key = CtKey {
        src: src_ip,
        dst: dst_ip,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    };

    // Established flow: apply the recorded translation.
    if let Some(ct) = CT.get_ptr(&key) {
        let ct = unsafe { *ct };
        if ct.flags & CT_F_DNAT != 0 {
            dnat(ctx, proto, dst_ip, dport, ct.rev_addr, ct.rev_port)?;
        } else if ct.flags & CT_F_SNAT != 0 {
            snat(ctx, proto, src_ip, sport, ct.rev_addr, ct.rev_port)?;
        }
        return Ok(());
    }

    // New flow: is the destination a service VIP?
    let svc = match SERVICES.get_ptr(&ServiceKey {
        vip: dst_ip,
        port: dport,
        proto,
        _pad: 0,
    }) {
        Some(s) => unsafe { *s },
        None => return Ok(()),
    };
    if svc.backend_count == 0 {
        return Ok(());
    }
    let slot = (unsafe { bpf_get_prandom_u32() } % svc.backend_count as u32) as u16;
    let be = match BACKENDS.get_ptr(&BackendKey {
        svc_id: svc.svc_id,
        slot,
        _pad: 0,
    }) {
        Some(b) => unsafe { *b },
        None => return Ok(()),
    };

    let now = unsafe { bpf_ktime_get_ns() };
    // Forward: client->VIP rewrites the destination to the chosen backend.
    let _ = CT.insert(
        &key,
        &CtEntry {
            rev_addr: be.addr,
            rev_port: be.port,
            flags: CT_F_DNAT,
            last_seen: now,
        },
        0,
    );
    // Reverse: backend->client rewrites the source back to the VIP.
    let rkey = CtKey {
        src: be.addr,
        dst: src_ip,
        src_port: be.port,
        dst_port: sport,
        proto,
        _pad: [0; 3],
    };
    let _ = CT.insert(
        &rkey,
        &CtEntry {
            rev_addr: dst_ip,
            rev_port: dport,
            flags: CT_F_SNAT,
            last_seen: now,
        },
        0,
    );

    dnat(ctx, proto, dst_ip, dport, be.addr, be.port)
}

#[inline(always)]
fn l4_csum_off(proto: u8) -> usize {
    // TCP checksum is at offset 16, UDP at offset 6.
    L4_OFF + if proto == IPPROTO_TCP { 16 } else { 6 }
}

/// Rewrite the destination address+port and fix the IPv4 and L4 checksums.
#[inline(always)]
fn dnat(
    ctx: &TcContext,
    proto: u8,
    old_ip: u32,
    old_port: u16,
    new_ip: u32,
    new_port: u16,
) -> Result<(), ()> {
    let csum = l4_csum_off(proto);
    let mangled = if proto == IPPROTO_UDP {
        BPF_F_MARK_MANGLED_0
    } else {
        0
    };
    ctx.l3_csum_replace(IP_CSUM_OFF, old_ip as u64, new_ip as u64, 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, old_ip as u64, new_ip as u64, BPF_F_PSEUDO_HDR | mangled | 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, old_port as u64, new_port as u64, mangled | 2)
        .map_err(|_| ())?;
    ctx.store(IP_DST_OFF, &new_ip, 0).map_err(|_| ())?;
    ctx.store(L4_OFF + 2, &new_port, 0).map_err(|_| ())?;
    stat_inc(STAT_L4_DNAT);
    Ok(())
}

/// Rewrite the source address+port and fix the IPv4 and L4 checksums.
#[inline(always)]
fn snat(
    ctx: &TcContext,
    proto: u8,
    old_ip: u32,
    old_port: u16,
    new_ip: u32,
    new_port: u16,
) -> Result<(), ()> {
    let csum = l4_csum_off(proto);
    let mangled = if proto == IPPROTO_UDP {
        BPF_F_MARK_MANGLED_0
    } else {
        0
    };
    ctx.l3_csum_replace(IP_CSUM_OFF, old_ip as u64, new_ip as u64, 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, old_ip as u64, new_ip as u64, BPF_F_PSEUDO_HDR | mangled | 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, old_port as u64, new_port as u64, mangled | 2)
        .map_err(|_| ())?;
    ctx.store(IP_SRC_OFF, &new_ip, 0).map_err(|_| ())?;
    ctx.store(L4_OFF, &new_port, 0).map_err(|_| ())?;
    stat_inc(STAT_L4_SNAT);
    Ok(())
}

// ------------------------------ L4 IPv6 ------------------------------------

#[inline(always)]
fn l4_nat_v6(ctx: &TcContext) -> Result<(), ()> {
    let proto: u8 = ctx.load(IP6_NEXTHDR_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Ok(());
    }
    let src: [u8; 16] = ctx.load(IP6_SRC_OFF).map_err(|_| ())?;
    let dst: [u8; 16] = ctx.load(IP6_DST_OFF).map_err(|_| ())?;
    let sport: u16 = ctx.load(IP6_L4_OFF).map_err(|_| ())?;
    let dport: u16 = ctx.load(IP6_L4_OFF + 2).map_err(|_| ())?;

    let key = CtKey6 {
        src,
        dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    };
    if let Some(ct) = CT6.get_ptr(&key) {
        let ct = unsafe { *ct };
        if ct.flags & CT_F_DNAT != 0 {
            dnat6(ctx, proto, dst, ct.rev_addr, dport, ct.rev_port)?;
        } else if ct.flags & CT_F_SNAT != 0 {
            snat6(ctx, proto, src, ct.rev_addr, sport, ct.rev_port)?;
        }
        return Ok(());
    }

    let svc = match SERVICES6.get_ptr(&ServiceKey6 {
        vip: dst,
        port: dport,
        proto,
        _pad: 0,
    }) {
        Some(s) => unsafe { *s },
        None => return Ok(()),
    };
    if svc.backend_count == 0 {
        return Ok(());
    }
    let slot = (unsafe { bpf_get_prandom_u32() } % svc.backend_count as u32) as u16;
    let be = match BACKENDS6.get_ptr(&BackendKey {
        svc_id: svc.svc_id,
        slot,
        _pad: 0,
    }) {
        Some(b) => unsafe { *b },
        None => return Ok(()),
    };

    let now = unsafe { bpf_ktime_get_ns() };
    let _ = CT6.insert(
        &key,
        &CtEntry6 {
            rev_addr: be.addr,
            rev_port: be.port,
            flags: CT_F_DNAT,
            last_seen: now,
        },
        0,
    );
    let rkey = CtKey6 {
        src: be.addr,
        dst: src,
        src_port: be.port,
        dst_port: sport,
        proto,
        _pad: [0; 3],
    };
    let _ = CT6.insert(
        &rkey,
        &CtEntry6 {
            rev_addr: dst,
            rev_port: dport,
            flags: CT_F_SNAT,
            last_seen: now,
        },
        0,
    );

    dnat6(ctx, proto, dst, be.addr, dport, be.port)
}

/// Rewrite the IPv6 destination address+port and fix the L4 checksum (IPv6 has
/// no header checksum; the pseudo-header covers the 16-byte address).
#[inline(always)]
fn dnat6(
    ctx: &TcContext,
    proto: u8,
    old_ip: [u8; 16],
    new_ip: [u8; 16],
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    v6_csum_fixup(ctx, proto, old_ip, new_ip, old_port, new_port)?;
    ctx.store(IP6_DST_OFF, &new_ip, 0).map_err(|_| ())?;
    ctx.store(IP6_L4_OFF + 2, &new_port, 0).map_err(|_| ())?;
    stat_inc(STAT_L4_DNAT);
    Ok(())
}

/// Rewrite the IPv6 source address+port and fix the L4 checksum.
#[inline(always)]
fn snat6(
    ctx: &TcContext,
    proto: u8,
    old_ip: [u8; 16],
    new_ip: [u8; 16],
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    v6_csum_fixup(ctx, proto, old_ip, new_ip, old_port, new_port)?;
    ctx.store(IP6_SRC_OFF, &new_ip, 0).map_err(|_| ())?;
    ctx.store(IP6_L4_OFF, &new_port, 0).map_err(|_| ())?;
    stat_inc(STAT_L4_SNAT);
    Ok(())
}

/// Patch the L4 checksum for a 16-byte address change (4 pseudo-header words)
/// plus a port change. Shared by dnat6/snat6 — the checksum is updated by the
/// delta of whichever fields changed, regardless of src vs dst.
#[inline(always)]
fn v6_csum_fixup(
    ctx: &TcContext,
    proto: u8,
    old_ip: [u8; 16],
    new_ip: [u8; 16],
    old_port: u16,
    new_port: u16,
) -> Result<(), ()> {
    let csum = IP6_L4_OFF + if proto == IPPROTO_TCP { 16 } else { 6 };
    let mangled = if proto == IPPROTO_UDP {
        BPF_F_MARK_MANGLED_0
    } else {
        0
    };
    let ow: [u32; 4] = unsafe { core::mem::transmute(old_ip) };
    let nw: [u32; 4] = unsafe { core::mem::transmute(new_ip) };
    ctx.l4_csum_replace(csum, ow[0] as u64, nw[0] as u64, BPF_F_PSEUDO_HDR | 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, ow[1] as u64, nw[1] as u64, BPF_F_PSEUDO_HDR | 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, ow[2] as u64, nw[2] as u64, BPF_F_PSEUDO_HDR | 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, ow[3] as u64, nw[3] as u64, BPF_F_PSEUDO_HDR | 4)
        .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, old_port as u64, new_port as u64, mangled | 2)
        .map_err(|_| ())?;
    Ok(())
}

// ============================== L3 forwarding ==============================

#[inline(always)]
fn l3_forward(ctx: &TcContext, port_vrf: u32) -> Result<i32, ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    match u16::from_be(ethertype) {
        ETH_P_IP => l3_forward_v4(ctx, port_vrf),
        ETH_P_IPV6 => l3_forward_v6(ctx, port_vrf),
        ETH_P_MPLS_UC => mpls_forward(ctx),
        _ => Ok(TC_ACT_PIPE as i32), // ARP, ... -> stack
    }
}

/// VRF context attached by the XDP MPLS stage (VPN-label decap): read from
/// the skb's `data_meta..data` window, guarded by the magic. 0 = none.
#[inline(always)]
fn tc_meta_vrf(ctx: &TcContext) -> u32 {
    let skb = ctx.skb.skb;
    let meta = unsafe { (*skb).data_meta } as usize;
    let data = unsafe { (*skb).data } as usize;
    if meta + core::mem::size_of::<CradleXdpMeta>() > data {
        return 0;
    }
    let m = meta as *const CradleXdpMeta;
    unsafe {
        if (*m).magic != XDP_META_MAGIC {
            return 0;
        }
        (*m).vrf_id
    }
}

/// Resolve a nexthop-group member by hashing the flow onto `0..count`.
#[inline(always)]
fn ecmp_member(group_id: u32, hash: u32) -> Option<u32> {
    let count = unsafe { *NHGROUP.get_ptr(&group_id)? };
    if count == 0 {
        return None;
    }
    let slot = hash % count;
    Some(unsafe { *NHGROUP_MEMBER.get_ptr(&NhGroupKey { group_id, slot })? })
}

/// Murmur3 32-bit finalizer — good avalanche so the low bits used for member
/// selection depend on every input bit (inputs often differ only in high bits).
#[inline(always)]
fn fmix32(mut h: u32) -> u32 {
    h ^= h >> 16;
    h = h.wrapping_mul(0x85eb_ca6b);
    h ^= h >> 13;
    h = h.wrapping_mul(0xc2b2_ae35);
    h ^= h >> 16;
    h
}

/// Per-flow hash for ECMP member selection (consistent within a flow/direction).
#[inline(always)]
fn flow_hash_v4(ctx: &TcContext, src: u32, dst: u32) -> u32 {
    let proto: u8 = ctx.load(IP_PROTO_OFF).unwrap_or(0);
    let mut h = src ^ dst.rotate_left(16) ^ (proto as u32);
    if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        if let Ok(ports) = ctx.load::<u32>(L4_OFF) {
            h ^= ports;
        }
    }
    fmix32(h)
}

/// Per-flow hash for IPv6 ECMP member selection.
#[inline(always)]
fn flow_hash_v6(ctx: &TcContext, src: &[u8; 16], dst: &[u8; 16]) -> u32 {
    let sw: [u32; 4] = unsafe { core::mem::transmute(*src) };
    let dw: [u32; 4] = unsafe { core::mem::transmute(*dst) };
    let mut h = (sw[0] ^ sw[1] ^ sw[2] ^ sw[3])
        ^ (dw[0] ^ dw[1] ^ dw[2] ^ dw[3]).rotate_left(16);
    let nexthdr: u8 = ctx.load(IP6_NEXTHDR_OFF).unwrap_or(0);
    h ^= nexthdr as u32;
    if nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP {
        if let Ok(ports) = ctx.load::<u32>(IP6_L4_OFF) {
            h ^= ports;
        }
    }
    fmix32(h)
}

/// v4 route lookup. A non-zero `vrf_id` (from the ingress port's binding or
/// the XDP decap metadata) selects the per-VRF LPM table; the global table
/// is the DIR-24-8 arrays when enabled in `DP_CONFIG` (1–2 flat array loads
/// + a `DEFAULT4` fallthrough), else the LPM trie.
#[inline(always)]
fn fib4_lookup(vrf_id: u32, dst: [u8; 4]) -> Option<FibEntry> {
    if vrf_id != 0 {
        let key = Key::new(64, Vrf4Key { vrf_id, addr: dst });
        let fib = FIB4_VRF.get(&key).copied();
        if fib.is_some() {
            stat_inc(STAT_FIB4_VRF_HIT);
        }
        return fib;
    }
    let dir24 = match DP_CONFIG.get(0) {
        Some(w) => *w & DPC_FIB4_DIR24 != 0,
        None => false,
    };
    if !dir24 {
        return FIB4.get(Key::new(32, dst)).copied();
    }

    let idx24 = u32::from_be_bytes(dst) >> 8;
    let mut w: FibWord = *TBL24.get(idx24)?;
    if w & FIBW_TBL8 != 0 {
        let group = w & FIBW_ID_MASK;
        w = *TBL8.get(group * 256 + dst[3] as u32)?;
        if w & FIBW_VALID != 0 {
            stat_inc(STAT_FIB4_TBL8_HIT);
        }
    } else if w & FIBW_VALID != 0 {
        stat_inc(STAT_FIB4_TBL24_HIT);
    }
    if w & FIBW_VALID == 0 {
        // No covering route: the default route lives outside the table
        // (never expanded into 16.7M slots).
        w = *DEFAULT4.get(0)?;
        if w & FIBW_VALID == 0 {
            return None;
        }
        stat_inc(STAT_FIB4_DEFAULT);
    }
    let (nexthop_id, flags) = fibw_unpack(w);
    Some(FibEntry { nexthop_id, flags })
}

#[inline(always)]
fn l3_forward_v4(ctx: &TcContext, port_vrf: u32) -> Result<i32, ()> {
    let dst: [u8; 4] = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    // Port binding wins; else VRF context from a VPN-label decap (XDP meta).
    let vrf_id = if port_vrf != 0 { port_vrf } else { tc_meta_vrf(ctx) };
    let fib = match fib4_lookup(vrf_id, dst) {
        Some(fib) => fib,
        None => return Ok(TC_ACT_PIPE as i32),
    };

    if fib.flags & FIB_F_BLACKHOLE != 0 {
        stat_inc(STAT_DROP);
        return Ok(TC_ACT_SHOT as i32);
    }
    if fib.flags & FIB_F_LOCAL != 0 {
        stat_inc(STAT_L3_LOCAL);
        return Ok(TC_ACT_PIPE as i32); // destined to us
    }

    // ECMP: hash the flow to a group member; otherwise a single nexthop.
    let nh_id = if fib.flags & FIB_F_ECMP != 0 {
        let src: [u8; 4] = ctx.load(IP_SRC_OFF).map_err(|_| ())?;
        let hash = flow_hash_v4(ctx, u32::from_ne_bytes(src), u32::from_ne_bytes(dst));
        match ecmp_member(fib.nexthop_id, hash) {
            Some(id) => id,
            None => return Ok(TC_ACT_PIPE as i32),
        }
    } else {
        fib.nexthop_id
    };

    let nh: NextHop = unsafe { *NEXTHOPS.get_ptr(&nh_id).ok_or(())? };
    let oif = nh.oif;

    // SRv6 imposition (H.Encaps) of a v4-inner packet: impose an outer IPv6
    // header toward the SID. Pipe-model — the inner IPv4 TTL is left as-is.
    if nh.flags & NH_F_SRV6 != 0 {
        let ttl: u8 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
        if ttl <= 1 {
            return Ok(TC_ACT_PIPE as i32);
        }
        return srv6_encap(ctx, nh_id, &nh, ETH_P_IP);
    }

    // MPLS imposition (ingress LER): a labeled nexthop pushes its out-label
    // stack and egresses MPLS. Pipe-model TTL — the inner IP TTL is left
    // untouched; the label TTL is seeded from it (a dying packet still punts
    // for the ICMP first).
    if nh.flags & NH_F_MPLS != 0 && nh.num_labels > 0 {
        let ttl: u8 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
        if ttl <= 1 {
            return Ok(TC_ACT_PIPE as i32);
        }
        return mpls_push(ctx, &nh, ttl);
    }

    // Decrement TTL and patch the IPv4 header checksum (RFC 1624 incremental).
    // The 16-bit word at IP offset 8 is [ttl, proto]; on the little-endian BPF
    // target it loads as `ttl | (proto << 8)`, so decrementing the whole word
    // by one decrements the TTL byte. `bpf_l3_csum_replace` consumes `from`/`to`
    // in this little-endian memory order, so we pass the raw words.
    let ttl: u8 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
    if ttl <= 1 {
        return Ok(TC_ACT_PIPE as i32);
    }
    let old_word: u16 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
    let new_word: u16 = old_word - 1;
    ctx.store(IP_TTL_OFF, &new_word, 0).map_err(|_| ())?;
    ctx.l3_csum_replace(IP_CSUM_OFF, old_word as u64, new_word as u64, 2)
        .map_err(|_| ())?;

    // Let the kernel resolve the L2 neighbor for the next hop and rewrite the
    // ethernet header for the egress link. The data plane therefore needs no
    // static ARP table — the kernel's neighbor subsystem (which the kernel and
    // zebra-rs already populate) supplies the MACs. The next hop is the gateway
    // for via-routes, or the destination itself for connected routes. The
    // address bytes are network order; `from_ne_bytes` on the little-endian BPF
    // target lays them out as the `__be32` the helper expects.
    let nh_octets: [u8; 4] = if nh.gateway_v4 != 0 {
        nh.gateway_v4.to_be_bytes()
    } else {
        dst
    };
    stat_inc(STAT_L3V4_FORWARD);
    let mut params = bpf_redir_neigh {
        nh_family: AF_INET,
        __bindgen_anon_1: bpf_redir_neigh__bindgen_ty_1 {
            ipv4_nh: u32::from_ne_bytes(nh_octets),
        },
    };
    let ret = unsafe {
        bpf_redirect_neigh(
            oif,
            &mut params,
            core::mem::size_of::<bpf_redir_neigh>() as i32,
            0,
        )
    };
    Ok(ret as i32)
}

/// v6 route lookup — the per-VRF LPM table when `vrf_id != 0`, else global.
#[inline(always)]
fn fib6_lookup(vrf_id: u32, dst: [u8; 16]) -> Option<FibEntry> {
    if vrf_id != 0 {
        let key = Key::new(32 + 128, Vrf6Key { vrf_id, addr: dst });
        let fib = FIB6_VRF.get(&key).copied();
        if fib.is_some() {
            stat_inc(STAT_FIB6_VRF_HIT);
        }
        return fib;
    }
    FIB6.get(Key::new(128, dst)).copied()
}

#[inline(always)]
fn l3_forward_v6(ctx: &TcContext, port_vrf: u32) -> Result<i32, ()> {
    let dst: [u8; 16] = ctx.load(IP6_DST_OFF).map_err(|_| ())?;

    // A local SID pre-empts the FIB (an SRv6 endpoint address is not an
    // ordinary local address). Safety net for when the XDP decap stage is
    // bypassed (generic XDP / not attached): punt so the host stack — or a
    // re-run — handles it rather than mis-forwarding by the outer DA.
    if SRV6_LOCALSID.get(Key::new(128, dst)).is_some() {
        return Ok(TC_ACT_PIPE as i32);
    }

    // Port binding wins; else VRF context from a VPN-label / SRv6 decap.
    let vrf_id = if port_vrf != 0 { port_vrf } else { tc_meta_vrf(ctx) };
    let fib = match fib6_lookup(vrf_id, dst) {
        Some(fib) => fib,
        None => return Ok(TC_ACT_PIPE as i32),
    };
    if fib.flags & FIB_F_BLACKHOLE != 0 {
        stat_inc(STAT_DROP);
        return Ok(TC_ACT_SHOT as i32);
    }
    if fib.flags & FIB_F_LOCAL != 0 {
        stat_inc(STAT_L3_LOCAL);
        return Ok(TC_ACT_PIPE as i32); // destined to us
    }

    let nh_id = if fib.flags & FIB_F_ECMP != 0 {
        let src: [u8; 16] = ctx.load(IP6_SRC_OFF).map_err(|_| ())?;
        let hash = flow_hash_v6(ctx, &src, &dst);
        match ecmp_member(fib.nexthop_id, hash) {
            Some(id) => id,
            None => return Ok(TC_ACT_PIPE as i32),
        }
    } else {
        fib.nexthop_id
    };
    let nh: NextHop = unsafe { *NEXTHOPS.get_ptr(&nh_id).ok_or(())? };
    let oif = nh.oif;

    // SRv6 imposition (H.Encaps): impose an outer IPv6 header toward the SID.
    if nh.flags & NH_F_SRV6 != 0 {
        let hop: u8 = ctx.load(IP6_HOP_OFF).map_err(|_| ())?;
        if hop <= 1 {
            return Ok(TC_ACT_PIPE as i32);
        }
        return srv6_encap(ctx, nh_id, &nh, ETH_P_IPV6);
    }

    // MPLS imposition — as in the v4 path; the label TTL seeds from the
    // hop limit.
    if nh.flags & NH_F_MPLS != 0 && nh.num_labels > 0 {
        let hop: u8 = ctx.load(IP6_HOP_OFF).map_err(|_| ())?;
        if hop <= 1 {
            return Ok(TC_ACT_PIPE as i32);
        }
        return mpls_push(ctx, &nh, hop);
    }

    // Decrement the hop limit (IPv6 has no header checksum to patch).
    let hop: u8 = ctx.load(IP6_HOP_OFF).map_err(|_| ())?;
    if hop <= 1 {
        return Ok(TC_ACT_PIPE as i32);
    }
    let new_hop = hop - 1;
    ctx.store(IP6_HOP_OFF, &new_hop, 0).map_err(|_| ())?;

    // Next hop = gateway for via-routes, destination for connected ones; the
    // kernel resolves the neighbor (NDP) and rewrites the ethernet header.
    let nh6: [u8; 16] = if nh.gateway_v6 != [0u8; 16] {
        nh.gateway_v6
    } else {
        dst
    };
    stat_inc(STAT_L3V6_FORWARD);
    let mut params = bpf_redir_neigh {
        nh_family: AF_INET6,
        __bindgen_anon_1: bpf_redir_neigh__bindgen_ty_1 {
            ipv6_nh: unsafe { core::mem::transmute::<[u8; 16], [u32; 4]>(nh6) },
        },
    };
    let ret = unsafe {
        bpf_redirect_neigh(
            oif,
            &mut params,
            core::mem::size_of::<bpf_redir_neigh>() as i32,
            0,
        )
    };
    Ok(ret as i32)
}

// ============================= MPLS forwarding =============================

/// Offset of the top MPLS label stack entry (right after the Ethernet header).
const MPLS_LSE_OFF: usize = EthHdr::LEN;

/// Forward an MPLS frame (EtherType 0x8847): look up the top label in the
/// ILM (`MPLS_FIB`) and swap / pop / pop-to-IP per the entry's operation.
/// Unknown labels and TTL expiry punt to the host stack (`TC_ACT_PIPE`).
#[inline(always)]
fn mpls_forward(ctx: &TcContext) -> Result<i32, ()> {
    let lse_be: u32 = ctx.load(MPLS_LSE_OFF).map_err(|_| ())?;
    let (label, tc, s, ttl) = mpls_lse_unpack(u32::from_be(lse_be));
    if ttl <= 1 {
        return Ok(TC_ACT_PIPE as i32); // host generates the TTL-exceeded
    }

    let ent: MplsEntry = match MPLS_FIB.get_ptr(&label) {
        Some(e) => unsafe { *e },
        None => return Ok(TC_ACT_PIPE as i32), // unknown label: punt
    };
    let nh: NextHop = unsafe { *NEXTHOPS.get_ptr(&ent.nexthop_id).ok_or(())? };

    match ent.op {
        // Single-label swap: in-place LSE rewrite, no length change — TC's
        // one MPLS job. Everything that resizes an MPLS frame lives in the
        // XDP stage (`cradle_mpls`): pops/PHP shrink (bpf_skb_adjust_room is
        // -ENOTSUPP for non-IP skbs) and multi-label SR swaps grow. A frame
        // reaching here for those ops means XDP isn't attached — punt.
        MPLS_OP_SWAP if nh.num_labels == 1 => {
            let new_lse = mpls_lse(nh.labels[0], tc, s, ttl - 1).to_be();
            ctx.store(MPLS_LSE_OFF, &new_lse, 0).map_err(|_| ())?;
            stat_inc(STAT_MPLS_SWAP);
            mpls_l2_xmit(ctx, &nh)
        }
        _ => Ok(TC_ACT_PIPE as i32),
    }
}

/// Impose the nexthop's out-label stack on an IP packet (ingress LER) and
/// egress it as MPLS. The skb is still IPv4/IPv6 here, so the MAC-level
/// `adjust_room` *grow* passes the kernel's protocol gate — unlike pops,
/// which must run at XDP (see the hook matrix in docs/design/mpls.md).
#[inline(always)]
fn mpls_push(ctx: &TcContext, nh: &NextHop, ttl: u8) -> Result<i32, ()> {
    let n = nh.num_labels as usize;
    if n == 0 || n > MAX_LABELS {
        return Ok(TC_ACT_PIPE as i32);
    }
    ctx.skb
        .adjust_room((4 * n) as i32, BPF_ADJ_ROOM_MAC, 0)
        .map_err(|_| ())?;
    // Outermost first; BOS on the innermost; TC bits 0.
    for i in 0..MAX_LABELS {
        if i >= n {
            break;
        }
        let s = if i == n - 1 { 1 } else { 0 };
        let lse = mpls_lse(nh.labels[i], 0, s, ttl).to_be();
        ctx.store(MPLS_LSE_OFF + 4 * i, &lse, 0).map_err(|_| ())?;
    }
    let ethertype = ETH_P_MPLS_UC.to_be();
    ctx.store(ETH_TYPE_OFF, &ethertype, 0).map_err(|_| ())?;
    stat_inc(STAT_MPLS_PUSH);
    mpls_l2_xmit(ctx, nh)
}

/// Egress a (still-)labeled MPLS frame. `bpf_redirect_neigh` cannot build an
/// MPLS Ethernet header (there is no MPLS `nh_family`), so the rewrite is
/// explicit: destination MAC from the control-plane-fed neighbor maps, source
/// MAC from the egress port, EtherType 0x8847, then a plain redirect. A
/// neighbor/port miss punts to the host, which resolves the neighbor and (via
/// the control plane) backfills the map — the LSP "warms up" like a connected
/// route.
#[inline(always)]
fn mpls_l2_xmit(ctx: &TcContext, nh: &NextHop) -> Result<i32, ()> {
    l2_xmit(ctx, nh, ETH_P_MPLS_UC)
}

/// Explicit L2 rewrite + `bpf_redirect` for a frame whose egress EtherType
/// is `ethertype`. Used by any path where `bpf_redirect_neigh` can't build
/// the header from `skb->protocol`: MPLS (no IP nh_family) and SRv6 encap
/// (the skb protocol still reads as the *inner* family while the frame is
/// IPv6). Destination MAC from the control-plane neighbor maps, source from
/// the egress port. A neighbor/port miss punts to the host (which resolves
/// it and, via the tee, backfills the map).
#[inline(always)]
fn l2_xmit(ctx: &TcContext, nh: &NextHop, ethertype: u16) -> Result<i32, ()> {
    let dst_mac = if nh.flags & NH_F_V6 != 0 {
        match NEIGH6.get_ptr(&Neigh6Key {
            ifindex: nh.oif,
            addr: nh.gateway_v6,
        }) {
            Some(e) => unsafe { (*e).mac },
            None => return Ok(TC_ACT_PIPE as i32),
        }
    } else {
        match NEIGH4.get_ptr(&Neigh4Key {
            ifindex: nh.oif,
            addr: nh.gateway_v4,
        }) {
            Some(e) => unsafe { (*e).mac },
            None => return Ok(TC_ACT_PIPE as i32),
        }
    };
    let src_mac = match PORTS.get_ptr(&nh.oif) {
        Some(p) => unsafe { (*p).mac },
        None => return Ok(TC_ACT_PIPE as i32),
    };
    ctx.store(ETH_DST_OFF, &dst_mac, 0).map_err(|_| ())?;
    ctx.store(ETH_SRC_OFF, &src_mac, 0).map_err(|_| ())?;
    ctx.store(ETH_TYPE_OFF, &ethertype.to_be(), 0).map_err(|_| ())?;
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as i32)
}

// =============================== SRv6 encap =================================

const IP6_HDR_LEN: usize = 40;
const IP6_PAYLOAD_LEN_OFF: usize = EthHdr::LEN + 4;
const IP6_VER_TC_FL: u32 = 0x6000_0000; // version 6, TC 0, flow-label 0
const IPPROTO_IPIP: u8 = 4; // inner IPv4
const IPPROTO_IPV6: u8 = 41; // inner IPv6
const IPPROTO_ROUTING: u8 = 43; // IPv6 Routing header (SRH is type 4)
/// SRH offsets relative to the outer IPv6 header start (`EthHdr::LEN`).
const SRH_OFF: usize = EthHdr::LEN + IP6_HDR_LEN; // outer SRH start
const SRH_SL_OFF: usize = SRH_OFF + 3; // Segments Left byte
const SRH_SEGLIST_OFF: usize = SRH_OFF + 8; // first segment entry

/// H.Encaps.Red (single-SID, reduced — no SRH): impose an outer IPv6 header
/// whose DA is the SID and forward toward the underlay nexthop. Phase 1
/// handles `num_segs == 1`; a longer segment list (needing an SRH) punts.
///
/// `inner_ethertype` is the frame's current EtherType (0x0800 / 0x86dd),
/// which selects the outer Next Header. The inner skb is IP, so the
/// `adjust_room` *grow* is allowed (unlike the MPLS-shrink case), and the
/// egress uses the explicit `l2_xmit` — after the grow `skb->protocol` still
/// reads as the inner family, so `bpf_redirect_neigh` would build the wrong
/// L2 header.
#[inline(always)]
fn srv6_encap(ctx: &TcContext, nh_id: u32, nh: &NextHop, inner_ethertype: u16) -> Result<i32, ()> {
    let enc: Srv6Encap = match SRV6_ENCAP.get_ptr(&nh_id) {
        Some(e) => unsafe { *e },
        None => return Ok(TC_ACT_PIPE as i32),
    };
    let n = enc.num_segs as usize;
    if n == 0 || n > MAX_SEGS {
        return Ok(TC_ACT_PIPE as i32);
    }
    let src: [u8; 16] = match SRV6_ENCAP_SRC.get(0) {
        Some(s) => *s,
        None => return Ok(TC_ACT_PIPE as i32),
    };
    let inner_proto: u8 = if inner_ethertype == ETH_P_IPV6 {
        IPPROTO_IPV6
    } else {
        IPPROTO_IPIP
    };
    // Reduced encap: a single SID needs no SRH (DA is the SID); >1 SIDs ride
    // an SRH carrying segs[1..] (segs[0] is the DA). srh_len = 8 + 16*(n-1).
    let srh_len = if n == 1 { 0 } else { 8 + 16 * (n - 1) };
    let hdr_len = IP6_HDR_LEN + srh_len;
    // Outer payload = the SRH (if any) plus everything after the MAC header.
    let payload_len = ((ctx.len() as usize).saturating_sub(EthHdr::LEN) + srh_len) as u16;

    ctx.skb
        .adjust_room(hdr_len as i32, BPF_ADJ_ROOM_MAC, 0)
        .map_err(|_| ())?;

    // Outer IPv6 header. next_header points at the SRH (43) when present,
    // else directly at the inner packet.
    let outer_nh = if n == 1 { inner_proto } else { IPPROTO_ROUTING };
    ctx.store(EthHdr::LEN, &IP6_VER_TC_FL.to_be(), 0).map_err(|_| ())?;
    ctx.store(IP6_PAYLOAD_LEN_OFF, &payload_len.to_be(), 0).map_err(|_| ())?;
    ctx.store(IP6_NEXTHDR_OFF, &outer_nh, 0).map_err(|_| ())?;
    ctx.store(IP6_HOP_OFF, &64u8, 0).map_err(|_| ())?;
    ctx.store(IP6_SRC_OFF, &src, 0).map_err(|_| ())?;
    ctx.store(IP6_DST_OFF, &enc.segs[0], 0).map_err(|_| ())?;

    if n > 1 {
        // SRH: [next_header, hdr_ext_len, routing_type=4, segments_left,
        //       last_entry, flags, tag(2)] then the reversed segment list.
        ctx.store(SRH_OFF, &inner_proto, 0).map_err(|_| ())?;
        ctx.store(SRH_OFF + 1, &(2 * (n as u8 - 1)), 0).map_err(|_| ())?; // hdr_ext_len
        ctx.store(SRH_OFF + 2, &4u8, 0).map_err(|_| ())?; // routing type 4 = SRH
        ctx.store(SRH_SL_OFF, &(n as u8 - 1), 0).map_err(|_| ())?; // segments_left
        ctx.store(SRH_OFF + 4, &(n as u8 - 2), 0).map_err(|_| ())?; // last_entry
        ctx.store(SRH_OFF + 5, &0u8, 0).map_err(|_| ())?; // flags
        ctx.store(SRH_OFF + 6, &0u16, 0).map_err(|_| ())?; // tag
        // Reversed list, omitting segs[0]: segment_list[i] = segs[n-1-i].
        for i in 0..MAX_SEGS {
            if i >= n - 1 {
                break;
            }
            ctx.store(SRH_SEGLIST_OFF + 16 * i, &enc.segs[n - 1 - i], 0)
                .map_err(|_| ())?;
        }
    }

    stat_inc(STAT_SRV6_ENCAP);
    l2_xmit(ctx, nh, ETH_P_IPV6)
}

// ============================ MPLS XDP stage ===============================
//
// Every MPLS operation that changes the frame's length lives here —
// `bpf_skb_adjust_room` is -ENOTSUPP for non-IP skbs, so a TC classifier can
// neither shrink nor grow an MPLS frame, while `bpf_xdp_adjust_head` is
// unrestricted:
//
// * **pops** (explicit POP / POP_L3, and zebra-shaped PHP: a SWAP with an
//   empty out stack, dispatched on the incoming S bit) shrink the frame.
//   They run in a bounded loop so chained pops (PHP + stacked labels)
//   resolve in one pass, then XDP_PASS — the veth native-XDP receive path
//   re-runs eth_type_trans, so the frame enters TC as plain IP (routed by
//   the FIB path) or as MPLS with the next label on top.
// * **multi-label SR swaps** grow the frame; they complete entirely in XDP
//   (imposed stack + L2 rewrite + bpf_redirect), because passing a
//   swapped frame up would make TC re-look-up the *outgoing* label.
//
// Single-label swaps don't resize and stay in TC; pushes grow *IP* skbs,
// which adjust_room does allow, and stay in TC too.

/// Bounds-checked pointer into XDP packet data.
#[inline(always)]
fn xdp_ptr<T>(ctx: &XdpContext, off: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    if start + off + core::mem::size_of::<T>() > ctx.data_end() {
        return Err(());
    }
    Ok((start + off) as *mut T)
}

#[xdp]
pub fn cradle_xdp(ctx: XdpContext) -> u32 {
    match try_xdp(&ctx) {
        Ok(act) => act,
        Err(()) => xdp_action::XDP_PASS,
    }
}

/// The XDP stage hosts the two overlays whose frame-resizing the TC stage
/// can't do on a non-IP or would-mis-forward skb: MPLS (pops/grow-swaps) and
/// SRv6 (End.DT* decap). Dispatch on the outer EtherType.
#[inline(always)]
fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let ethertype = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? });
    match ethertype {
        ETH_P_MPLS_UC => try_mpls_xdp(ctx),
        ETH_P_IPV6 => try_srv6_xdp(ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn try_mpls_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    // Only *local* label chains loop (nexthop-less pops: this node owns the
    // label underneath — UHP/egress stacks). Everything else exits directly.
    for _ in 0..=MAX_LABELS {
        let ethertype = unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? };
        if u16::from_be(ethertype) != ETH_P_MPLS_UC {
            return Ok(xdp_action::XDP_PASS); // popped to IP (or never MPLS)
        }
        let lse = u32::from_be(unsafe { *xdp_ptr::<u32>(ctx, MPLS_LSE_OFF)? });
        let (label, _tc, s, ttl) = mpls_lse_unpack(lse);
        if ttl <= 1 {
            return Ok(xdp_action::XDP_PASS);
        }
        let ent: MplsEntry = match MPLS_FIB.get_ptr(&label) {
            Some(e) => unsafe { *e },
            None => return Ok(xdp_action::XDP_PASS), // unknown label: not ours
        };
        let nh: NextHop = match NEXTHOPS.get_ptr(&ent.nexthop_id) {
            Some(n) => unsafe { *n },
            None => return Ok(xdp_action::XDP_PASS),
        };

        match ent.op {
            // Explicit decap (gRPC / zebra DecapVrf): pop to IP and route
            // locally — in the entry's VRF when set — whatever the nexthop.
            MPLS_OP_POP_L3 if s == 1 => return pop_decap_local(ctx, ent.vrf_id),
            // PHP shapes — a pop with a *real* nexthop means "pop and
            // forward the remaining stack there". The labels underneath
            // belong to the next hop (label spaces are per-node): they must
            // never be looked up here.
            MPLS_OP_SWAP | MPLS_OP_POP if nh.num_labels == 0 && nh.oif != 0 => {
                return pop_and_forward(ctx, &nh, s);
            }
            // Nexthop-less pops: this node owns whatever is underneath.
            MPLS_OP_SWAP | MPLS_OP_POP if nh.num_labels == 0 => {
                if s == 1 {
                    return pop_decap_local(ctx, ent.vrf_id);
                }
                pop_head(ctx, ETH_P_MPLS_UC)?; // and loop: the next label is ours
            }
            // SR stack: pop the incoming label, impose N > 1 labels — the
            // frame grows, so it completes here (L2 rewrite + redirect).
            MPLS_OP_SWAP if nh.num_labels > 1 => return grow_swap(ctx, &nh, s, ttl),
            // Single-label swap (TC's in-place job) or a depth-mismatched
            // explicit op: hand the frame up.
            _ => return Ok(xdp_action::XDP_PASS),
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// EtherType the pop would expose, from the payload's version nibble.
#[inline(always)]
fn popped_ethertype(ctx: &XdpContext) -> Result<u16, ()> {
    let ver = unsafe { *xdp_ptr::<u8>(ctx, MPLS_LSE_OFF + 4)? };
    match ver >> 4 {
        4 => Ok(ETH_P_IP),
        6 => Ok(ETH_P_IPV6),
        _ => Err(()),
    }
}

/// Resolve the egress L2 addresses for a nexthop from the control-plane
/// neighbor/port state. `None` = miss (caller punts, frame untouched).
#[inline(always)]
fn xdp_resolve_l2(nh: &NextHop) -> Option<([u8; 6], [u8; 6])> {
    let dst_mac = if nh.flags & NH_F_V6 != 0 {
        unsafe {
            (*NEIGH6.get_ptr(&Neigh6Key {
                ifindex: nh.oif,
                addr: nh.gateway_v6,
            })?)
            .mac
        }
    } else {
        unsafe {
            (*NEIGH4.get_ptr(&Neigh4Key {
                ifindex: nh.oif,
                addr: nh.gateway_v4,
            })?)
            .mac
        }
    };
    let src_mac = unsafe { (*PORTS.get_ptr(&nh.oif)?).mac };
    Some((dst_mac, src_mac))
}

/// Bounds-checked pointer into the XDP metadata area.
#[inline(always)]
fn xdp_meta_ptr(ctx: &XdpContext) -> Result<*mut CradleXdpMeta, ()> {
    let meta = unsafe { (*ctx.ctx).data_meta } as usize;
    let data = unsafe { (*ctx.ctx).data } as usize;
    if meta + core::mem::size_of::<CradleXdpMeta>() > data {
        return Err(());
    }
    Ok(meta as *mut CradleXdpMeta)
}

/// Pop the bottom-of-stack label to IP for *local* routing. A VRF-scoped
/// decap (L3VPN) attaches the VRF id as XDP metadata, which the TC FIB
/// stage reads — failure to attach drops rather than mis-routing a VPN
/// packet in the global table.
#[inline(always)]
fn pop_decap_local(ctx: &XdpContext, vrf_id: u32) -> Result<u32, ()> {
    let et = match popped_ethertype(ctx) {
        Ok(et) => et,
        Err(()) => {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    pop_head(ctx, et)?;
    if vrf_id != 0 {
        if unsafe {
            bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32))
        } != 0
        {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        let meta = xdp_meta_ptr(ctx)?;
        unsafe {
            (*meta).magic = XDP_META_MAGIC;
            (*meta).vrf_id = vrf_id;
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// SRv6 `End.DT4/DT6/DT46` decap: the outer IPv6 DA matched a local SID, so
/// strip the outer IPv6 header (and one *exhausted* SRH if present — segment
/// walking is Phase 2) and hand the inner packet to the TC FIB stage,
/// carrying the SID's VRF as metadata. `End`/`End.X` (segment transit) and
/// the encap/other behaviors are not handled here (PASS).
#[inline(always)]
fn try_srv6_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let dst = unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? };
    let sid: LocalSid = match SRV6_LOCALSID.get(&Key::new(128, dst)) {
        Some(s) => *s,
        None => return Ok(xdp_action::XDP_PASS), // not a local SID — normal fwd
    };
    match sid.behavior {
        SRV6_BH_END | SRV6_BH_END_X => return srv6_end(ctx, &sid),
        SRV6_BH_END_DT4 | SRV6_BH_END_DT6 | SRV6_BH_END_DT46 => {}
        _ => return Ok(xdp_action::XDP_PASS), // uN/uA/B6 — later phases
    }

    // Reach the inner packet: outer next-header is the inner proto directly,
    // or one Routing header (SRH) to skip. Phase 1 only accepts an already
    // exhausted SRH (Segments Left == 0); a live SRH means transit, punt.
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    let (inner_proto, strip) = if outer_nh == IPPROTO_ROUTING {
        let srh_nh = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN)? };
        let ext_len = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN + 1)? };
        let sl = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN + 3)? };
        if sl != 0 || ext_len > 12 {
            return Ok(xdp_action::XDP_PASS); // live/oversized SRH — Phase 2
        }
        (srh_nh, IP6_HDR_LEN + 8 * (ext_len as usize + 1))
    } else {
        (outer_nh, IP6_HDR_LEN)
    };

    // Family must match the behavior (DT46 accepts either).
    let inner_et = match (inner_proto, sid.behavior) {
        (IPPROTO_IPIP, SRV6_BH_END_DT4) | (IPPROTO_IPIP, SRV6_BH_END_DT46) => ETH_P_IP,
        (IPPROTO_IPV6, SRV6_BH_END_DT6) | (IPPROTO_IPV6, SRV6_BH_END_DT46) => ETH_P_IPV6,
        _ => {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
    };

    decap_head(ctx, strip, inner_et)?;
    stat_inc(STAT_SRV6_DECAP);
    if sid.vrf_id != 0 {
        if unsafe {
            bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32))
        } != 0
        {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        let meta = xdp_meta_ptr(ctx)?;
        unsafe {
            (*meta).magic = XDP_META_MAGIC;
            (*meta).vrf_id = sid.vrf_id;
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// SRv6 `End` / `End.X` transit: the outer IPv6 DA matched a local endpoint
/// SID, so walk the SRH — decrement Segments Left and copy the next segment
/// into the DA — then forward. `End` hands the rewritten packet to the TC
/// FIB stage (`XDP_PASS`, which decrements the hop limit); `End.X` forwards
/// straight out the SID's adjacency (and decrements the hop limit itself,
/// since it bypasses the TC forward).
#[inline(always)]
fn srv6_end(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    // Require an SRH with an active segment (SL > 0). An End SID reached with
    // no SRH or SL == 0 is a misconfiguration — pass to the stack.
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    if outer_nh != IPPROTO_ROUTING {
        return Ok(xdp_action::XDP_PASS);
    }
    let sl = unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? };
    if sl == 0 || sl as usize > MAX_SEGS {
        return Ok(xdp_action::XDP_PASS);
    }
    let new_sl = sl - 1;
    // segment_list[new_sl] becomes the new destination.
    let next_seg = unsafe { *xdp_ptr::<[u8; 16]>(ctx, SRH_SEGLIST_OFF + 16 * new_sl as usize)? };
    unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? = new_sl };
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? = next_seg };
    stat_inc(STAT_SRV6_END);

    if sid.behavior == SRV6_BH_END {
        // Forward by the new DA — the TC FIB stage does the redirect + hop
        // limit decrement.
        return Ok(xdp_action::XDP_PASS);
    }

    // End.X: forward to the SID's cross-connect adjacency directly.
    let nh: NextHop = match NEXTHOPS.get_ptr(&sid.nexthop_id) {
        Some(n) => unsafe { *n },
        None => return Ok(xdp_action::XDP_PASS),
    };
    let Some((dst_mac, src_mac)) = xdp_resolve_l2(&nh) else {
        return Ok(xdp_action::XDP_PASS);
    };
    // Decrement the outer hop limit (this path skips the TC forward).
    let hop = unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? };
    if hop <= 1 {
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? = hop - 1 };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? = dst_mac };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? = src_mac };
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as u32)
}

/// Remove `strip` bytes of outer header(s) between the Ethernet header and
/// the inner packet: slide the 12 Ethernet address bytes forward over them,
/// write the inner EtherType, then trim `strip` leading bytes. Bounded for
/// the verifier (`strip` covers a 40-byte IPv6 header plus at most a
/// 104-byte SRH).
#[inline(always)]
fn decap_head(ctx: &XdpContext, strip: usize, new_ethertype: u16) -> Result<(), ()> {
    if !(IP6_HDR_LEN..=IP6_HDR_LEN + 104).contains(&strip) {
        return Err(());
    }
    let macs = unsafe { *xdp_ptr::<[u8; 12]>(ctx, 0)? };
    unsafe { *xdp_ptr::<[u8; 12]>(ctx, strip)? = macs };
    unsafe { *xdp_ptr::<u16>(ctx, strip + ETH_TYPE_OFF)? = new_ethertype.to_be() };
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, strip as i32) } != 0 {
        return Err(());
    }
    Ok(())
}

/// PHP: pop one label and forward the remaining frame — still-MPLS or the
/// exposed IP — via the ILM's nexthop. Pipe-model TTL: nothing inner is
/// touched.
#[inline(always)]
fn pop_and_forward(ctx: &XdpContext, nh: &NextHop, s: u8) -> Result<u32, ()> {
    // Resolve egress L2 first: a miss punts with the frame untouched.
    let Some((dst_mac, src_mac)) = xdp_resolve_l2(nh) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let et = if s == 0 {
        ETH_P_MPLS_UC
    } else {
        match popped_ethertype(ctx) {
            Ok(et) => et,
            Err(()) => {
                stat_inc(STAT_DROP);
                return Ok(xdp_action::XDP_DROP);
            }
        }
    };
    pop_head(ctx, et)?;
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? = dst_mac };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? = src_mac };
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as u32)
}

/// Remove the top label stack entry: move the 12 Ethernet address bytes over
/// it, write the EtherType the pop exposes, then trim the 4 leading bytes.
#[inline(always)]
fn pop_head(ctx: &XdpContext, new_ethertype: u16) -> Result<(), ()> {
    let macs = unsafe { *xdp_ptr::<[u8; 12]>(ctx, 0)? };
    unsafe { *xdp_ptr::<[u8; 12]>(ctx, 4)? = macs };
    unsafe { *xdp_ptr::<u16>(ctx, 4 + ETH_TYPE_OFF)? = new_ethertype.to_be() };
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, 4) } != 0 {
        return Err(());
    }
    stat_inc(STAT_MPLS_POP);
    Ok(())
}

/// SR transit: pop the incoming label and impose the nexthop's multi-label
/// stack. The frame grows at the head (`adjust_head` with a negative delta —
/// veth native XDP guarantees XDP_PACKET_HEADROOM), the Ethernet header is
/// rebuilt from the control-plane neighbor/port state, and the frame is
/// redirected out — it never re-enters the stack.
#[inline(always)]
fn grow_swap(ctx: &XdpContext, nh: &NextHop, s_in: u8, ttl_in: u8) -> Result<u32, ()> {
    let n = nh.num_labels as usize;
    if n < 2 || n > MAX_LABELS {
        return Ok(xdp_action::XDP_PASS);
    }
    // Resolve egress L2 first: a neighbor/port miss punts before mutation
    // (TC then sees the untouched frame and punts to the host).
    let Some((dst_mac, src_mac)) = xdp_resolve_l2(nh) else {
        return Ok(xdp_action::XDP_PASS);
    };

    let grow = 4 * (n as i32 - 1);
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -grow) } != 0 {
        return Ok(xdp_action::XDP_PASS); // no headroom: punt untouched
    }
    // New layout: [eth 14][labels[0..n] 4n][payload] — the innermost imposed
    // entry lands on the old top-LSE slot, so only the Ethernet header and
    // the imposed entries need writing.
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? = dst_mac };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? = src_mac };
    unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? = ETH_P_MPLS_UC.to_be() };
    for i in 0..MAX_LABELS {
        if i >= n {
            break;
        }
        // BOS only on the innermost, and only if the incoming label was BOS
        // (the imposed stack sits atop whatever remained under it).
        let s = if i == n - 1 { s_in } else { 0 };
        let lse = mpls_lse(nh.labels[i], 0, s, ttl_in - 1).to_be();
        unsafe { *xdp_ptr::<u32>(ctx, MPLS_LSE_OFF + 4 * i)? = lse };
    }
    stat_inc(STAT_MPLS_SWAP);
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as u32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
