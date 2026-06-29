#![no_std]
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
}

pub const NH_F_V6: u32 = 1 << 0;
pub const NH_F_ONLINK: u32 = 1 << 1;

/// Neighbor (L2 resolution) key for IPv4: (interface, gateway/dst address).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Neigh4Key {
    pub ifindex: u32,
    pub addr: u32,
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
        FibEntry, NextHop, Neigh4Key, NeighEntry, NhGroupKey,
        FdbKey, FdbEntry, PortConfig, L2MemberKey,
        ServiceKey, ServiceInfo, BackendKey, Backend, CtKey, CtEntry,
        ServiceKey6, Backend6, CtKey6, CtEntry6,
    );
}
