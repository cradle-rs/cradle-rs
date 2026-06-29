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
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::generated::{bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect},
    macros::{classifier, map},
    maps::{lpm_trie::Key, HashMap, LpmTrie, LruHashMap},
    programs::TcContext,
};
use cradle_common::{
    Backend, BackendKey, CtEntry, CtKey, FdbEntry, FdbKey, FibEntry, L2MemberKey, Neigh4Key,
    NeighEntry, NextHop, PortConfig, ServiceInfo, ServiceKey, CT_F_DNAT, CT_F_SNAT, FIB_F_BLACKHOLE,
    FIB_F_LOCAL, PORT_F_L2, PORT_F_L3,
};
use network_types::eth::EthHdr;

// --- shared ---
#[map]
static PORTS: HashMap<u32, PortConfig> = HashMap::with_max_entries(256, 0);

// --- L3 ---
#[map]
static FIB4: LpmTrie<[u8; 4], FibEntry> = LpmTrie::with_max_entries(4096, 0);
#[map]
static NEXTHOPS: HashMap<u32, NextHop> = HashMap::with_max_entries(4096, 0);
#[map]
static NEIGH4: HashMap<Neigh4Key, NeighEntry> = HashMap::with_max_entries(4096, 0);

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

/// Upper bound on flood fan-out per VLAN (also bounds the verifier's loop).
const MAX_L2_MEMBERS: u16 = 64;

const ETH_P_IP: u16 = 0x0800;
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
const BPF_F_PSEUDO_HDR: u64 = 16;
const BPF_F_MARK_MANGLED_0: u64 = 32;

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
        // L4 NAT is a best-effort pre-routing stage; it rewrites the packet in
        // place (service DNAT / reverse SNAT) so routing then targets the real
        // endpoint. Failures fall through to plain routing.
        let _ = l4_nat(ctx);
        l3_forward(ctx)
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
                Ok(unsafe { bpf_redirect(oif, 0) } as i32)
            }
        }
        None => Ok(flood(ctx, iif, vlan)),
    }
}

#[inline(always)]
fn flood(ctx: &TcContext, iif: u32, vlan: u16) -> i32 {
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
    if u16::from_be(ethertype) != ETH_P_IP {
        return Ok(());
    }
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
    Ok(())
}

// ============================== L3 forwarding ==============================

#[inline(always)]
fn l3_forward(ctx: &TcContext) -> Result<i32, ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    if u16::from_be(ethertype) != ETH_P_IP {
        return Ok(TC_ACT_PIPE as i32); // ARP, IPv6, ... -> stack
    }

    let dst: [u8; 4] = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    let fib = match FIB4.get(Key::new(32, dst)) {
        Some(fib) => *fib,
        None => return Ok(TC_ACT_PIPE as i32),
    };

    if fib.flags & FIB_F_BLACKHOLE != 0 {
        return Ok(TC_ACT_SHOT as i32);
    }
    if fib.flags & FIB_F_LOCAL != 0 {
        return Ok(TC_ACT_PIPE as i32); // destined to us
    }

    let nh: NextHop = unsafe { *NEXTHOPS.get_ptr(&fib.nexthop_id).ok_or(())? };
    let oif = nh.oif;

    let neigh_addr = if nh.gateway_v4 != 0 {
        nh.gateway_v4
    } else {
        u32::from_be_bytes(dst)
    };
    let neigh: NeighEntry = unsafe {
        *NEIGH4
            .get_ptr(&Neigh4Key {
                ifindex: oif,
                addr: neigh_addr,
            })
            .ok_or(())?
    };
    let port: PortConfig = unsafe { *PORTS.get_ptr(&oif).ok_or(())? };

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

    ctx.store(ETH_DST_OFF, &neigh.mac, 0).map_err(|_| ())?;
    ctx.store(ETH_SRC_OFF, &port.mac, 0).map_err(|_| ())?;

    Ok(unsafe { bpf_redirect(oif, 0) } as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
