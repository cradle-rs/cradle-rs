#![cfg_attr(not(test), no_std)]
//! cradle-common — the cradle-rs **data-plane contract**.
//!
//! Plain-old-data types used as eBPF map keys/values by *both* the kernel
//! data plane (`cradle-ebpf`, `no_std`) and the user-space control plane
//! (`cradle`). Keeping them in one crate guarantees the two sides agree on
//! byte layout. `aya::Pod` impls (which let user space read/write the maps)
//! are gated behind the `user` feature so the `no_std` eBPF build never links
//! `aya`.
//!
//! Layout rules for everything here:
//! * `#[repr(C)]` and `Copy`.
//! * No implicit padding — pad explicitly so hash-map key comparison (which is
//!   byte-wise in the kernel) is deterministic.
//! * IPv4 addresses are carried as a `u32` built with `u32::from_be_bytes(octets)`
//!   (i.e. network-byte-order octets). Both the eBPF data plane and user space
//!   are little-endian here, so this representation is identical on both sides;
//!   IPv4 LPM keys instead use `[u8; 4]` octets directly to avoid any ambiguity.

#![allow(clippy::missing_safety_doc)]

// ============================ L3: routing / FIB ============================

/// Longest-prefix-match result: a route pointing at a nexthop.
///
/// Stored in an LPM trie keyed by destination prefix (`u32` for IPv4,
/// `[u8; 16]` for IPv6, both in network byte order).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FibEntry {
    /// Index into the `NEXTHOPS` map.
    pub nexthop_id: u32,
    /// `FIB_F_*` flags.
    pub flags: u32,
}

pub const FIB_F_BLACKHOLE: u32 = 1 << 0;
/// Destination is local — punt to the host stack instead of forwarding.
pub const FIB_F_LOCAL: u32 = 1 << 1;
/// On-link / connected route — resolve the neighbor by the packet's
/// destination address rather than a gateway.
pub const FIB_F_CONNECTED: u32 = 1 << 2;
/// Multipath: `FibEntry.nexthop_id` is a *group* id (into the nexthop-group
/// maps), not a single nexthop. The data plane hashes the flow to pick a member.
pub const FIB_F_ECMP: u32 = 1 << 3;

/// Member of a nexthop group, keyed by `(group_id, slot)` with a dense slot
/// index `0..count`. The value is a nexthop id (into the per-nexthop map).
/// The member count per group lives in a separate `group_id -> count` map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NhGroupKey {
    pub group_id: u32,
    pub slot: u32,
}

/// A single nexthop. Keyed by `nexthop_id`. (Nexthop *groups* / multipath are
/// modelled in a later phase as a group table over these ids.)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NextHop {
    /// Gateway IPv4 (network byte order; `0` means on-link).
    pub gateway_v4: u32,
    /// Gateway IPv6 (network byte order).
    pub gateway_v6: [u8; 16],
    /// Output interface index.
    pub oif: u32,
    /// `NH_F_*` flags.
    pub flags: u32,
    /// MPLS out-label stack, index 0 = top/outermost. For a transit swap the
    /// swap value is `labels[0]`; for imposition (Phase 2) the whole stack is
    /// pushed. Values are bare 20-bit labels (no TC/S/TTL bits).
    pub labels: [u32; MAX_LABELS],
    /// Number of valid entries in `labels`; 0 = no label operation.
    pub num_labels: u8,
    pub _pad: [u8; 3],
}

pub const NH_F_V6: u32 = 1 << 0;
pub const NH_F_ONLINK: u32 = 1 << 1;
/// Nexthop imposes/swaps an MPLS label stack (`labels`/`num_labels`).
pub const NH_F_MPLS: u32 = 1 << 2;

/// Maximum out-label stack depth (bounds the datapath's parse/push loops for
/// the verifier). Covers SR-MPLS depths seen in practice; deeper is rejected
/// by the control plane.
pub const MAX_LABELS: usize = 3;

/// Neighbor (L2 resolution) key for IPv4: (interface, gateway/dst address).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Neigh4Key {
    pub ifindex: u32,
    pub addr: u32,
}

/// Neighbor (L2 resolution) key for IPv6: (interface, gateway/dst address).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Neigh6Key {
    pub ifindex: u32,
    pub addr: [u8; 16],
}

/// Neighbor entry: the resolved destination MAC.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NeighEntry {
    pub mac: [u8; 6],
    pub state: u8,
    pub _pad: u8,
}

pub const NEIGH_STATE_REACHABLE: u8 = 1;

// ============================== MPLS: label FIB =============================

/// Incoming-label map (ILM) entry: the operation applied to a frame whose top
/// label matched the `MPLS_FIB` key (the 20-bit label value in a `u32`).
///
/// Deliberately small — the out-label stack lives on the nexthop
/// (`NextHop.labels`), so one labeled nexthop is shared by every ILM entry
/// and IP route imposing the same stack.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MplsEntry {
    /// Index into the `NEXTHOPS` map. For `MPLS_OP_SWAP` the nexthop's
    /// `labels[0]` is the swap value.
    pub nexthop_id: u32,
    /// VRF/table id for `MPLS_OP_POP_L3` disposition (0 = global; per-VRF
    /// lookup is Phase 3).
    pub vrf_id: u32,
    /// `MPLS_OP_*`.
    pub op: u8,
    pub _pad: [u8; 3],
}

/// Pop the incoming label, impose the nexthop's out-label stack, stay MPLS.
pub const MPLS_OP_SWAP: u8 = 0;
/// Pop to IP and forward (PHP-to-IP / L3VPN egress).
pub const MPLS_OP_POP_L3: u8 = 1;
/// Pop one label, forward the remaining (still labeled) stack.
pub const MPLS_OP_POP: u8 = 2;

/// Pack an MPLS label stack entry: Label(20) | TC(3) | S(1) | TTL(8).
/// Returns the host-order `u32` whose big-endian bytes are the wire LSE.
#[inline]
pub const fn mpls_lse(label: u32, tc: u8, s: u8, ttl: u8) -> u32 {
    (label & 0xf_ffff) << 12 | ((tc as u32) & 0x7) << 9 | ((s as u32) & 0x1) << 8 | ttl as u32
}

/// Unpack an MPLS label stack entry (host-order value of the big-endian wire
/// word) into `(label, tc, s, ttl)`.
#[inline]
pub const fn mpls_lse_unpack(lse: u32) -> (u32, u8, u8, u8) {
    (
        lse >> 12,
        (lse >> 9 & 0x7) as u8,
        (lse >> 8 & 0x1) as u8,
        (lse & 0xff) as u8,
    )
}

// ============================ L2: switching / FDB ==========================

/// Forwarding-database key: destination MAC within a VLAN/bridge domain.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FdbKey {
    pub mac: [u8; 6],
    pub vlan: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FdbEntry {
    pub oif: u32,
    pub flags: u32,
}

/// This MAC is one of ours — punt the frame up to L3 / the host stack.
pub const FDB_F_LOCAL: u32 = 1 << 0;

/// Membership of an L2 (VLAN/bridge) domain — enumerates the ports a BUM or
/// unknown-unicast frame is flooded to. Keyed by `(vlan, slot)` where `slot` is
/// a dense index `0..count` (the count is held in a separate per-VLAN map).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct L2MemberKey {
    pub vlan: u16,
    pub slot: u16,
}

/// Per-port configuration (keyed by ifindex), shared by the L2 and L3 stages.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PortConfig {
    /// This interface's MAC — used as the source MAC when the L3 stage forwards
    /// a packet *out* of this port.
    pub mac: [u8; 6],
    /// Access/PVID VLAN for L2 ports.
    pub vlan: u16,
    /// `PORT_F_*` flags.
    pub flags: u32,
}

/// Participate in L2 switching.
pub const PORT_F_L2: u32 = 1 << 0;
/// Routed (L3) port.
pub const PORT_F_L3: u32 = 1 << 1;

// ======================= L4: load balancing / conntrack ====================

/// Service frontend (VIP:port/proto).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ServiceKey {
    /// VIP, network byte order.
    pub vip: u32,
    /// Port, network byte order.
    pub port: u16,
    /// IP protocol (TCP/UDP).
    pub proto: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ServiceInfo {
    pub backend_count: u16,
    /// `LB_ALGO_*`.
    pub lb_algo: u8,
    pub flags: u8,
    /// Namespaces the backend slots in the `BACKENDS` map.
    pub svc_id: u32,
}

pub const LB_ALGO_RANDOM: u8 = 0;
pub const LB_ALGO_MAGLEV: u8 = 1;

/// Backend slot key: (svc_id, slot).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct BackendKey {
    pub svc_id: u32,
    pub slot: u16,
    pub _pad: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Backend {
    pub addr: u32,
    pub port: u16,
    pub flags: u16,
}

/// Connection-tracking key: a normalised IPv4 5-tuple.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CtKey {
    pub src: u32,
    pub dst: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CtEntry {
    /// Reverse-NAT / chosen-backend target.
    pub rev_addr: u32,
    pub rev_port: u16,
    /// `CT_F_*`.
    pub flags: u16,
    /// `bpf_ktime_get_ns()` of last packet.
    pub last_seen: u64,
}

/// Rewrite the destination to `(rev_addr, rev_port)` (forward / DNAT direction).
pub const CT_F_DNAT: u16 = 1 << 0;
/// Rewrite the source to `(rev_addr, rev_port)` (reverse / SNAT direction).
pub const CT_F_SNAT: u16 = 1 << 1;

// --- L4 IPv6 (mirrors the IPv4 types with 16-byte addresses) ---

/// IPv6 service frontend (VIP:port/proto).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ServiceKey6 {
    pub vip: [u8; 16],
    pub port: u16,
    pub proto: u8,
    pub _pad: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Backend6 {
    pub addr: [u8; 16],
    pub port: u16,
    pub flags: u16,
}

/// Connection-tracking key: a normalised IPv6 5-tuple. (Reuses `ServiceInfo`
/// and `BackendKey` from the v4 types — those are address-family agnostic.)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CtKey6 {
    pub src: [u8; 16],
    pub dst: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CtEntry6 {
    pub rev_addr: [u8; 16],
    pub rev_port: u16,
    /// `CT_F_*`.
    pub flags: u16,
    pub last_seen: u64,
}

// ============================ observability stats ==========================

// Indices into the per-CPU `STATS` array (u64 packet counters), bumped at each
// datapath decision point. Keep in sync with `STAT_NAMES` in the cradle crate.
pub const STAT_L2_FORWARD: u32 = 0;
pub const STAT_L2_FLOOD: u32 = 1;
pub const STAT_L3V4_FORWARD: u32 = 2;
pub const STAT_L3V6_FORWARD: u32 = 3;
pub const STAT_L3_LOCAL: u32 = 4;
pub const STAT_L4_DNAT: u32 = 5;
pub const STAT_L4_SNAT: u32 = 6;
pub const STAT_DROP: u32 = 7;
pub const STAT_L7_REDIRECT: u32 = 8;
pub const STAT_MPLS_SWAP: u32 = 9;
pub const STAT_MPLS_POP: u32 = 10;
/// Reserved for Phase 2 imposition (ingress LER push).
pub const STAT_MPLS_PUSH: u32 = 11;
/// Number of stat slots (the `STATS` map's `max_entries`).
pub const STAT_MAX: u32 = 12;

// ============================== L7 proxy ===================================

/// TCP port the user-space L7 proxy listens on (transparently). The eBPF
/// datapath steers L7-marked service flows to this local listener via
/// `bpf_sk_assign`.
pub const L7_PROXY_PORT: u16 = 18000;

// ============================ user-space Pod impls =========================

#[cfg(feature = "user")]
mod user {
    use super::*;

    macro_rules! pod {
        ($($t:ty),* $(,)?) => {
            $( unsafe impl aya::Pod for $t {} )*
        };
    }

    pod!(
        FibEntry, NextHop, Neigh4Key, Neigh6Key, NeighEntry, NhGroupKey,
        MplsEntry,
        FdbKey, FdbEntry, PortConfig, L2MemberKey,
        ServiceKey, ServiceInfo, BackendKey, Backend, CtKey, CtEntry,
        ServiceKey6, Backend6, CtKey6, CtEntry6,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lse_round_trip() {
        for (label, tc, s, ttl) in [
            (16, 0, 1, 64),
            (0xf_ffff, 7, 1, 255),
            (0, 0, 0, 0),
            (17, 3, 0, 1),
        ] {
            let lse = mpls_lse(label, tc, s, ttl);
            assert_eq!(mpls_lse_unpack(lse), (label, tc, s, ttl));
        }
    }

    #[test]
    fn lse_wire_layout() {
        // RFC 3032: label 16, TC 0, S 1, TTL 64 => 0x00 01 01 40 on the wire.
        assert_eq!(mpls_lse(16, 0, 1, 64).to_be_bytes(), [0x00, 0x01, 0x01, 0x40]);
        // Label field is masked to 20 bits.
        assert_eq!(mpls_lse(0x1f_ffff, 0, 0, 0) >> 12, 0xf_ffff);
    }
}
