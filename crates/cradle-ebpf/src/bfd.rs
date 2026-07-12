//! BFD Echo reflector + in-kernel expiration watchdog, folded into `cradle_xdp`.
//!
//! Ported verbatim (mechanism-wise) from the standalone `xdp-bfd-echo` offload —
//! see `docs/design/bfd-echo-absorption.md`. `cradle_xdp`'s dispatcher validates
//! IPv4/IPv6 + UDP + destination port, then calls the entry functions here:
//! [`reflect_v4`]/[`reflect_v6`] for BFD Echo (udp/3785), [`observe_ctrl_v4`]/
//! [`observe_ctrl_v6`] for BFD control (udp/3784, watchdog observation only —
//! the caller always `XDP_PASS`es the control frame).
//!
//! BFD Echo (RFC 5880 §6.4 / RFC 5881 §4) is a stateless data-plane hairpin: a
//! peer sends an Echo frame to udp/3785 crafted so our forwarding plane loops it
//! back, and the peer alone times the round trip. The reflect swaps the Ethernet
//! MACs, decrements the IPv4 TTL (checksum patched, RFC 1141) or IPv6 Hop Limit,
//! and `XDP_TX`es. The TTL decrement is REQUIRED: the loop is a hop, and FRR's
//! fp-echo receiver drops any looped frame whose TTL isn't 254. IPv6 Echo is
//! peer-addressed (FRR loops it in software), so the reflect also swaps the IPv6
//! src/dst to retarget the frame at the originator; the Hop Limit decrement
//! (255→254) is what stops the mutual-reflection ping-pong.
//!
//! When zebra-rs also *originates* Echo, cradle's control loop fills
//! [`OUR_LOCAL_IPS`]. An inbound Echo sourced from one of our own addresses is
//! our frame returning; rather than re-reflect it (infinite loop) the program
//! arms a per-session `bpf_timer` (re-armed on every return) and `XDP_DROP`s it.
//! If returns stop for `echo-interval × detect-mult`, the timer fires in softirq
//! and sets a `down` flag that cradle polls → `WatchBfd` echo-down. The control
//! watchdog ([`CONTROL_TIMERS`]) is the same mechanism for standard async BFD
//! (RFC 5880 §6.8.4): observe udp/3784 at TTL 255 (GTSM), re-arm, always PASS.

use aya_ebpf::{
    bindings::{bpf_timer, xdp_action},
    btf_maps::HashMap as BtfHashMap,
    cty::c_void,
    helpers::{bpf_timer_init, bpf_timer_set_callback, bpf_timer_start},
    macros::{btf_map, map},
    maps::HashMap,
    programs::XdpContext,
};

/// Local IPv4 addresses (big-endian numeric, as read off the wire) of sessions
/// for which *we* originate Echo. cradle's control loop fills this. An inbound
/// Echo whose source is one of these is our own Echo looped back — it feeds the
/// in-kernel detector and is dropped, never re-reflected. Empty for pure
/// responders.
#[map]
static OUR_LOCAL_IPS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// IPv6 analogue of [`OUR_LOCAL_IPS`], keyed by the 16-byte wire-order address.
#[map]
static OUR_LOCAL_IPS_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);

/// Per-session in-kernel detection state, keyed by our local BFD discriminator.
/// One layout serves both Echo-return timing ([`ECHO_TIMERS`]) and
/// control-packet expiration ([`CONTROL_TIMERS`]).
///
/// Lives in a **BTF** map because the kernel locates the embedded
/// `struct bpf_timer` by its BTF; the timer is field 0 (offset 0) — the address
/// [`kick_timer`] passes to `bpf_timer_init`. `align_of` is 8 (the timer's
/// `[u64; 2]`), within the BTF hash map's 8-byte value-alignment ceiling.
#[repr(C)]
pub struct DetectState {
    /// Kernel-managed one-shot timer; `bpf_timer_init`'d lazily in-kernel on the
    /// first observed packet (userspace can't init it).
    timer: bpf_timer,
    /// Re-arm delay in nanoseconds; set by cradle at arm time.
    detect_ns: u64,
    /// 0 until the kernel has init'd + callback-set the timer, then 1.
    armed: u8,
    /// Set to 1 by the timer callback when tracked packets stopped; polled and
    /// cleared by cradle, which then emits echo-down / detect-down.
    down: u8,
    _pad: [u8; 6],
}

/// Echo-return detection state per originating session (256 single-hop echo
/// sessions per interface is far beyond any real deployment).
#[btf_map]
static ECHO_TIMERS: BtfHashMap<u32, DetectState, 256> = BtfHashMap::new();

/// Control-packet expiration state per Up session (RFC 5880 §6.8.4).
#[btf_map]
static CONTROL_TIMERS: BtfHashMap<u32, DetectState, 256> = BtfHashMap::new();

// Frame offsets. Base = EthHdr::LEN (14); these match cradle's shared IP_*/IP6_*
// constants but are redefined locally to keep this transplant self-contained and
// byte-identical to the verifier-proven standalone program.
const ETH_HLEN: usize = 14;
const ETH_DST_OFF: usize = 0;
const ETH_SRC_OFF: usize = 6;

const IP_OFF: usize = ETH_HLEN;
const IP_TTL_OFF: usize = IP_OFF + 8;
const IP_CHECK_OFF: usize = IP_OFF + 10; // u16 (big-endian) header checksum
const IP_SRC_OFF: usize = IP_OFF + 12;

const UDP_OFF: usize = IP_OFF + 20; // 20-byte IPv4 header (IHL=5)
/// BFD control header (RFC 5880 §4.1), right after the 8-byte UDP header.
const CTRL_OFF: usize = UDP_OFF + 8;
const CTRL_VERS_DIAG: usize = 0;
const CTRL_YOUR_DISC: usize = 8;
const BFD_VERSION: u8 = 1;
/// TTL / Hop Limit required on a received single-hop control packet (GTSM).
const CTRL_TTL: u8 = 255;

/// Echo payload `{ magic:u32, discr:u32, seq:u32, tx_ts:u64 }` big-endian right
/// after the UDP header. Must match the userspace `build_echo` layout.
const PAYLOAD_OFF: usize = UDP_OFF + 8;
const PL_MAGIC_OFF: usize = PAYLOAD_OFF;
const PL_DISCR_OFF: usize = PAYLOAD_OFF + 4;
/// ASCII "zbfd" — tags our own Echo payload.
const ECHO_MAGIC: u32 = 0x7a62_6664;

const IP6_OFF: usize = ETH_HLEN;
const IP6_HOPLIMIT_OFF: usize = IP6_OFF + 7;
const IP6_SRC_OFF: usize = IP6_OFF + 8;
const IP6_DST_OFF: usize = IP6_OFF + 24;
const IP6_HLEN: usize = 40;

const UDP6_OFF: usize = IP6_OFF + IP6_HLEN;
const PAYLOAD6_OFF: usize = UDP6_OFF + 8;
const PL6_MAGIC_OFF: usize = PAYLOAD6_OFF;
const PL6_DISCR_OFF: usize = PAYLOAD6_OFF + 4;
const CTRL6_OFF: usize = UDP6_OFF + 8;

/// Read a `u8` at `off` with a verifier-friendly bounds check.
#[inline(always)]
unsafe fn load_u8(ctx: &XdpContext, off: usize) -> Result<u8, ()> {
    let ptr = ctx.data() + off;
    if ptr + 1 > ctx.data_end() {
        return Err(());
    }
    Ok(unsafe { *(ptr as *const u8) })
}

/// Read a big-endian `u32` at `off`, with bounds check. Matches
/// `u32::from(Ipv4Addr)` so it keys [`OUR_LOCAL_IPS`] directly.
#[inline(always)]
unsafe fn load_u32_be(ctx: &XdpContext, off: usize) -> Result<u32, ()> {
    let ptr = ctx.data() + off;
    if ptr + 4 > ctx.data_end() {
        return Err(());
    }
    unsafe {
        let b0 = *(ptr as *const u8) as u32;
        let b1 = *((ptr + 1) as *const u8) as u32;
        let b2 = *((ptr + 2) as *const u8) as u32;
        let b3 = *((ptr + 3) as *const u8) as u32;
        Ok((b0 << 24) | (b1 << 16) | (b2 << 8) | b3)
    }
}

/// Read the 16-byte IPv6 address at `off`: one bounds check, then 16
/// constant-offset byte reads (wire order, ready to key [`OUR_LOCAL_IPS_V6`]).
#[inline(always)]
unsafe fn load_ip6(ctx: &XdpContext, off: usize) -> Result<[u8; 16], ()> {
    let ptr = ctx.data() + off;
    if ptr + 16 > ctx.data_end() {
        return Err(());
    }
    unsafe {
        Ok([
            *(ptr as *const u8),
            *((ptr + 1) as *const u8),
            *((ptr + 2) as *const u8),
            *((ptr + 3) as *const u8),
            *((ptr + 4) as *const u8),
            *((ptr + 5) as *const u8),
            *((ptr + 6) as *const u8),
            *((ptr + 7) as *const u8),
            *((ptr + 8) as *const u8),
            *((ptr + 9) as *const u8),
            *((ptr + 10) as *const u8),
            *((ptr + 11) as *const u8),
            *((ptr + 12) as *const u8),
            *((ptr + 13) as *const u8),
            *((ptr + 14) as *const u8),
            *((ptr + 15) as *const u8),
        ])
    }
}

/// Swap two packet bytes via volatile reads/writes — per byte, not a value-copy,
/// because an array copy can lower to a memcpy that computes a pointer
/// difference the BPF verifier rejects ("R4 pointer -= pointer prohibited").
#[inline(always)]
unsafe fn swap_byte(a: *mut u8, b: *mut u8) {
    unsafe {
        let tmp = core::ptr::read_volatile(a);
        core::ptr::write_volatile(a, core::ptr::read_volatile(b));
        core::ptr::write_volatile(b, tmp);
    }
}

/// Decrement the IPv4 TTL by one and patch the header checksum (RFC 1141:
/// += 0x0100 with end-around carry). Returns Err on a truncated header or TTL 0.
#[inline(always)]
unsafe fn decrement_ttl(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    if start + IP_CHECK_OFF + 2 > ctx.data_end() {
        return Err(());
    }
    let ttl_ptr = (start + IP_TTL_OFF) as *mut u8;
    let sum_ptr = (start + IP_CHECK_OFF) as *mut u8;
    unsafe {
        let ttl = core::ptr::read_volatile(ttl_ptr);
        if ttl == 0 {
            return Err(());
        }
        core::ptr::write_volatile(ttl_ptr, ttl - 1);

        let hi = core::ptr::read_volatile(sum_ptr) as u32;
        let lo = core::ptr::read_volatile(sum_ptr.add(1)) as u32;
        let mut sum = ((hi << 8) | lo) + 0x0100;
        sum = (sum & 0xffff) + (sum >> 16);
        core::ptr::write_volatile(sum_ptr, (sum >> 8) as u8);
        core::ptr::write_volatile(sum_ptr.add(1), (sum & 0xff) as u8);
    }
    Ok(())
}

/// Decrement the IPv6 Hop Limit by one (no header checksum to patch). Returns
/// Err on a truncated header or Hop Limit 0.
#[inline(always)]
unsafe fn decrement_hop_limit(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    if start + IP6_HOPLIMIT_OFF + 1 > ctx.data_end() {
        return Err(());
    }
    let hl_ptr = (start + IP6_HOPLIMIT_OFF) as *mut u8;
    unsafe {
        let hl = core::ptr::read_volatile(hl_ptr);
        if hl == 0 {
            return Err(());
        }
        core::ptr::write_volatile(hl_ptr, hl - 1);
    }
    Ok(())
}

/// `bpf_timer` callback (kernel ABI `(map, key, value)`): fires `detect_ns` after
/// the last observed packet. One-shot — sets the `down` flag for userspace; the
/// next observed packet re-arms via [`kick_timer`].
unsafe extern "C" fn detect_timeout(
    _map: *mut c_void,
    _key: *mut c_void,
    value: *mut c_void,
) -> i32 {
    if !value.is_null() {
        let st = value as *mut DetectState;
        unsafe { core::ptr::write_volatile(core::ptr::addr_of_mut!((*st).down), 1) };
    }
    0
}

/// A tracked packet for `st` arrived: arm (first time) or re-arm the timer.
/// `map` must be the pointer of the map `st` lives in — `bpf_timer_init` binds
/// the timer to its owning map.
#[inline(always)]
unsafe fn kick_timer(st: *mut DetectState, map: *mut c_void) {
    unsafe {
        let timer = core::ptr::addr_of_mut!((*st).timer);
        if core::ptr::read_volatile(core::ptr::addr_of!((*st).armed)) == 0 {
            if bpf_timer_init(timer, map, 0) == 0 {
                let cb: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut c_void) -> i32 =
                    detect_timeout;
                bpf_timer_set_callback(timer, cb as *mut c_void);
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*st).armed), 1);
            }
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*st).down), 0);
        let detect = core::ptr::read_volatile(core::ptr::addr_of!((*st).detect_ns));
        bpf_timer_start(timer, detect, 0);
    }
}

/// Our own Echo, looped back by the peer, arrived. Verify the payload magic, then
/// arm/re-arm the per-session detection timer.
#[inline(always)]
unsafe fn record_return(ctx: &XdpContext, magic_off: usize, discr_off: usize) -> Result<(), ()> {
    if unsafe { load_u32_be(ctx, magic_off)? } != ECHO_MAGIC {
        return Ok(());
    }
    let discr = unsafe { load_u32_be(ctx, discr_off)? };
    let Some(st) = ECHO_TIMERS.get_ptr_mut(&discr) else {
        return Ok(());
    };
    let map = core::ptr::from_ref(&ECHO_TIMERS)
        .cast_mut()
        .cast::<c_void>();
    unsafe { kick_timer(st, map) };
    Ok(())
}

/// A BFD *control* packet is passing through: re-arm the session's expiration
/// watchdog. Observation only — the caller always `XDP_PASS`es. Matched by TTL
/// 255 (GTSM), version, and Your Discriminator (non-zero, seeded at detect-add).
#[inline(always)]
unsafe fn observe_control(ctx: &XdpContext, ttl_off: usize, ctrl_off: usize) -> Result<(), ()> {
    if unsafe { load_u8(ctx, ttl_off)? } != CTRL_TTL {
        return Ok(());
    }
    if unsafe { load_u8(ctx, ctrl_off + CTRL_VERS_DIAG)? } >> 5 != BFD_VERSION {
        return Ok(());
    }
    let discr = unsafe { load_u32_be(ctx, ctrl_off + CTRL_YOUR_DISC)? };
    if discr == 0 {
        return Ok(());
    }
    let Some(st) = CONTROL_TIMERS.get_ptr_mut(&discr) else {
        return Ok(());
    };
    let map = core::ptr::from_ref(&CONTROL_TIMERS)
        .cast_mut()
        .cast::<c_void>();
    unsafe { kick_timer(st, map) };
    Ok(())
}

/// Swap the Ethernet source/destination MAC in place (byte-by-byte, see
/// [`swap_byte`]).
#[inline(always)]
unsafe fn swap_macs(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    if start + ETH_HLEN > ctx.data_end() {
        return Err(());
    }
    unsafe {
        let dst = (start + ETH_DST_OFF) as *mut u8;
        let src = (start + ETH_SRC_OFF) as *mut u8;
        swap_byte(dst, src);
        swap_byte(dst.add(1), src.add(1));
        swap_byte(dst.add(2), src.add(2));
        swap_byte(dst.add(3), src.add(3));
        swap_byte(dst.add(4), src.add(4));
        swap_byte(dst.add(5), src.add(5));
    }
    Ok(())
}

/// Swap the IPv6 source/destination in place — required for FRR-style
/// peer-addressed IPv6 Echo (retarget the reflected frame at the originator). No
/// checksum fix-up (the UDP pseudo-header sum src+dst is invariant).
#[inline(always)]
unsafe fn swap_ip6(ctx: &XdpContext) -> Result<(), ()> {
    let start = ctx.data();
    if start + IP6_DST_OFF + 16 > ctx.data_end() {
        return Err(());
    }
    unsafe {
        let src = (start + IP6_SRC_OFF) as *mut u8;
        let dst = (start + IP6_DST_OFF) as *mut u8;
        swap_byte(src, dst);
        swap_byte(src.add(1), dst.add(1));
        swap_byte(src.add(2), dst.add(2));
        swap_byte(src.add(3), dst.add(3));
        swap_byte(src.add(4), dst.add(4));
        swap_byte(src.add(5), dst.add(5));
        swap_byte(src.add(6), dst.add(6));
        swap_byte(src.add(7), dst.add(7));
        swap_byte(src.add(8), dst.add(8));
        swap_byte(src.add(9), dst.add(9));
        swap_byte(src.add(10), dst.add(10));
        swap_byte(src.add(11), dst.add(11));
        swap_byte(src.add(12), dst.add(12));
        swap_byte(src.add(13), dst.add(13));
        swap_byte(src.add(14), dst.add(14));
        swap_byte(src.add(15), dst.add(15));
    }
    Ok(())
}

/// BFD Echo (udp/3785) over IPv4. Caller has validated IPv4 / IHL=5 / UDP /
/// dport. Our own looped-back Echo (source ∈ [`OUR_LOCAL_IPS`]) feeds the
/// detector and is dropped; a peer's Echo is reflected (`XDP_TX`, TTL 254).
#[inline(always)]
pub fn reflect_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let src_ip = unsafe { load_u32_be(ctx, IP_SRC_OFF)? };
    if unsafe { OUR_LOCAL_IPS.get(&src_ip) }.is_some() {
        unsafe { record_return(ctx, PL_MAGIC_OFF, PL_DISCR_OFF)? };
        return Ok(xdp_action::XDP_DROP);
    }
    unsafe { decrement_ttl(ctx)? };
    unsafe { swap_macs(ctx)? };
    Ok(xdp_action::XDP_TX)
}

/// BFD control (udp/3784) over IPv4: feed the expiration watchdog. The caller
/// `XDP_PASS`es the frame regardless (the daemon runs the full FSM).
#[inline(always)]
pub fn observe_ctrl_v4(ctx: &XdpContext) {
    let _ = unsafe { observe_control(ctx, IP_TTL_OFF, CTRL_OFF) };
}

/// BFD Echo (udp/3785) over IPv6. Caller has validated IPv6 / UDP / dport. Our
/// own looped-back Echo feeds the detector and is dropped; a peer's Echo is
/// reflected with the IPv6 src/dst swap + Hop Limit 254 (`XDP_TX`).
#[inline(always)]
pub fn reflect_v6(ctx: &XdpContext) -> Result<u32, ()> {
    let src = unsafe { load_ip6(ctx, IP6_SRC_OFF)? };
    if unsafe { OUR_LOCAL_IPS_V6.get(&src) }.is_some() {
        unsafe { record_return(ctx, PL6_MAGIC_OFF, PL6_DISCR_OFF)? };
        return Ok(xdp_action::XDP_DROP);
    }
    unsafe { decrement_hop_limit(ctx)? };
    unsafe { swap_ip6(ctx)? };
    unsafe { swap_macs(ctx)? };
    Ok(xdp_action::XDP_TX)
}

/// BFD control (udp/3784) over IPv6: feed the expiration watchdog (Hop Limit
/// takes the GTSM role). The caller `XDP_PASS`es the frame.
#[inline(always)]
pub fn observe_ctrl_v6(ctx: &XdpContext) {
    let _ = unsafe { observe_control(ctx, IP6_HOPLIMIT_OFF, CTRL6_OFF) };
}
