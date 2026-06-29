#![no_std]
#![no_main]

//! cradle-rs eBPF data plane.
//!
//! Phase 1: an L3 IPv4 forwarder attached at TC ingress. For each IPv4 packet:
//!   1. longest-prefix-match the destination in `FIB4`,
//!   2. resolve the chosen `NEXTHOPS` entry (gateway + output interface),
//!   3. look up the neighbor MAC in `NEIGH4` (by gateway, or by destination for
//!      on-link/connected routes),
//!   4. rewrite source/destination MAC, decrement TTL (fixing the checksum), and
//!   5. `bpf_redirect` out the output interface.
//!
//! Anything we cannot fully resolve (non-IPv4, FIB miss, unresolved neighbor,
//! local/blackhole route, expiring TTL) is handed back to the kernel stack with
//! `TC_ACT_PIPE`. Later phases add IPv6, an L2 switching stage, and L4.

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    helpers::generated::bpf_redirect,
    macros::{classifier, map},
    maps::{lpm_trie::Key, HashMap, LpmTrie},
    programs::TcContext,
};
use cradle_common::{
    FibEntry, Neigh4Key, NeighEntry, NextHop, PortConfig, FIB_F_BLACKHOLE, FIB_F_LOCAL,
};
use network_types::eth::EthHdr;

// --- map ABI (shared with user space via the map *names*) ---

#[map]
static FIB4: LpmTrie<[u8; 4], FibEntry> = LpmTrie::with_max_entries(4096, 0);

#[map]
static NEXTHOPS: HashMap<u32, NextHop> = HashMap::with_max_entries(4096, 0);

#[map]
static NEIGH4: HashMap<Neigh4Key, NeighEntry> = HashMap::with_max_entries(4096, 0);

#[map]
static PORTS: HashMap<u32, PortConfig> = HashMap::with_max_entries(256, 0);

// --- packet offsets (no VLAN tag, no IPv4 options; IHL assumed 5) ---

const ETH_P_IP: u16 = 0x0800;
const ETH_TYPE_OFF: usize = 12;
const ETH_DST_OFF: usize = 0;
const ETH_SRC_OFF: usize = 6;
const IP_TTL_OFF: usize = EthHdr::LEN + 8;
const IP_CSUM_OFF: usize = EthHdr::LEN + 10;
const IP_DST_OFF: usize = EthHdr::LEN + 16;

#[classifier]
pub fn cradle_tc(ctx: TcContext) -> i32 {
    match try_forward(&ctx) {
        Ok(act) => act,
        // Anything unexpected: don't drop, let the kernel stack decide.
        Err(_) => TC_ACT_PIPE as i32,
    }
}

#[inline(always)]
fn try_forward(ctx: &TcContext) -> Result<i32, ()> {
    // Only IPv4 for now; everything else (ARP, IPv6, ...) goes to the stack.
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    if u16::from_be(ethertype) != ETH_P_IP {
        return Ok(TC_ACT_PIPE as i32);
    }

    // Destination address (network-order octets) -> FIB longest-prefix match.
    let dst: [u8; 4] = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    let fib = match FIB4.get(Key::new(32, dst)) {
        Some(fib) => *fib,
        None => return Ok(TC_ACT_PIPE as i32),
    };

    if fib.flags & FIB_F_BLACKHOLE != 0 {
        return Ok(TC_ACT_SHOT as i32);
    }
    if fib.flags & FIB_F_LOCAL != 0 {
        // Destined to us — deliver locally.
        return Ok(TC_ACT_PIPE as i32);
    }

    // Resolve the nexthop.
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

    // Source MAC = the output port's MAC.
    let port: PortConfig = unsafe { *PORTS.get_ptr(&oif).ok_or(())? };

    // Decrement TTL and patch the IPv4 header checksum (RFC 1624 incremental).
    // The 16-bit word at IP offset 8 is [ttl, proto]; on the little-endian BPF
    // target that loads as `ttl | (proto << 8)`, so decrementing the whole word
    // by one decrements the TTL byte. `bpf_l3_csum_replace` likewise consumes
    // `from`/`to` in this little-endian memory order, so we pass the raw words.
    let ttl: u8 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
    if ttl <= 1 {
        // Let the kernel generate ICMP time-exceeded.
        return Ok(TC_ACT_PIPE as i32);
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
