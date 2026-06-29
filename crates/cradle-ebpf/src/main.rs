#![no_std]
#![no_main]

//! cradle-rs eBPF data plane — integrated L2 switch / L3 router.
//!
//! Attached at TC ingress on each managed port. The ingress port's mode (in
//! `PORTS`) selects the path:
//!
//! * **L2 (`PORT_F_L2`)** — learn the source MAC into `FDB`, then forward by
//!   destination MAC: known unicast → `bpf_redirect`; broadcast/multicast or
//!   unknown unicast → flood to the VLAN's member ports via `bpf_clone_redirect`.
//! * **L3 (`PORT_F_L3`)** — IPv4 longest-prefix-match in `FIB4` → nexthop →
//!   neighbor → MAC rewrite + TTL decrement → `bpf_redirect`.
//!
//! Anything not fully resolved is handed back to the kernel with `TC_ACT_PIPE`.
//! Later phases add IPv6 and an L4 stage.

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::generated::bpf_redirect,
    macros::{classifier, map},
    maps::{lpm_trie::Key, HashMap, LpmTrie},
    programs::TcContext,
};
use cradle_common::{
    FdbEntry, FdbKey, FibEntry, L2MemberKey, Neigh4Key, NeighEntry, NextHop, PortConfig,
    FIB_F_BLACKHOLE, FIB_F_LOCAL, PORT_F_L2, PORT_F_L3,
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

/// Upper bound on flood fan-out per VLAN (also bounds the verifier's loop).
const MAX_L2_MEMBERS: u16 = 64;

const ETH_P_IP: u16 = 0x0800;
const ETH_TYPE_OFF: usize = 12;
const ETH_DST_OFF: usize = 0;
const ETH_SRC_OFF: usize = 6;
const IP_TTL_OFF: usize = EthHdr::LEN + 8;
const IP_CSUM_OFF: usize = EthHdr::LEN + 10;
const IP_DST_OFF: usize = EthHdr::LEN + 16;

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

    // Learn the source MAC -> ingress port.
    let _ = FDB.insert(
        &FdbKey { mac: src, vlan },
        &FdbEntry {
            oif: iif,
            flags: 0,
        },
        0,
    );

    // Broadcast / multicast (group bit of the first octet) -> flood.
    if dst[0] & 0x01 != 0 {
        return Ok(flood(ctx, iif, vlan));
    }

    // Known unicast -> redirect; unknown unicast -> flood.
    match FDB.get_ptr(&FdbKey { mac: dst, vlan }) {
        Some(e) => {
            let oif = unsafe { (*e).oif };
            if oif == iif {
                Ok(TC_ACT_SHOT as i32) // hairpin to the same port: drop
            } else {
                Ok(unsafe { bpf_redirect(oif, 0) } as i32)
            }
        }
        None => Ok(flood(ctx, iif, vlan)),
    }
}

/// Replicate the frame to every member of `vlan` except the ingress port, then
/// drop the original.
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
                // Clone keeps the original intact; we drop it below.
                let _ = ctx.clone_redirect(oif, 0);
            }
        }
        slot += 1;
    }
    TC_ACT_SHOT as i32
}

// ============================== L3 forwarding ==============================

#[inline(always)]
fn l3_forward(ctx: &TcContext) -> Result<i32, ()> {
    // Only IPv4 for now; everything else (ARP, IPv6, ...) goes to the stack.
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    if u16::from_be(ethertype) != ETH_P_IP {
        return Ok(TC_ACT_PIPE as i32);
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

    // Neighbor key: gateway for next-hop routes, destination for connected ones.
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
    // target that loads as `ttl | (proto << 8)`, so decrementing the whole word
    // by one decrements the TTL byte. `bpf_l3_csum_replace` likewise consumes
    // `from`/`to` in this little-endian memory order, so we pass the raw words.
    let ttl: u8 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
    if ttl <= 1 {
        return Ok(TC_ACT_PIPE as i32); // let the kernel emit ICMP time-exceeded
    }
    let old_word: u16 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
    let new_word: u16 = old_word - 1;
    ctx.store(IP_TTL_OFF, &new_word, 0).map_err(|_| ())?;
    ctx.l3_csum_replace(IP_CSUM_OFF, old_word as u64, new_word as u64, 2)
        .map_err(|_| ())?;

    // Rewrite L2 and redirect out the egress interface.
    ctx.store(ETH_DST_OFF, &neigh.mac, 0).map_err(|_| ())?;
    ctx.store(ETH_SRC_OFF, &port.mac, 0).map_err(|_| ())?;

    Ok(unsafe { bpf_redirect(oif, 0) } as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
