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

// ------------------------- DIR-24-8 packed FIB word ------------------------

/// Packed DIR-24-8 slot — `FibEntry` compressed into 4 bytes so `TBL24`
/// stays at 64 MiB. Layout (bit 31 .. bit 0):
///
/// ```text
///   [31]     FIBW_VALID
///   [30]     FIBW_TBL8    — low bits are a TBL8 group index, not a nexthop
///   [29:26]  flags        — FIB_F_* (4 bits)
///   [25:0]   nexthop_id (or group index when FIBW_TBL8)
/// ```
pub type FibWord = u32;

pub const FIBW_VALID: u32 = 1 << 31;
pub const FIBW_TBL8: u32 = 1 << 30;
pub const FIBW_FLAGS_SHIFT: u32 = 26;
pub const FIBW_FLAGS_MASK: u32 = 0xf;
pub const FIBW_ID_MASK: u32 = (1 << 26) - 1;

/// Pack a resolved route into a valid `FibWord`. `flags` must fit the 4-bit
/// field (`FIB_F_*` do) and `nexthop_id` the 26-bit field — both are masked.
#[inline]
pub const fn fibw_entry(nexthop_id: u32, flags: u32) -> FibWord {
    FIBW_VALID | (flags & FIBW_FLAGS_MASK) << FIBW_FLAGS_SHIFT | (nexthop_id & FIBW_ID_MASK)
}

/// Pack a `TBL8` group pointer.
#[inline]
pub const fn fibw_group(group_idx: u32) -> FibWord {
    FIBW_VALID | FIBW_TBL8 | (group_idx & FIBW_ID_MASK)
}

/// Unpack a valid, non-group word into `(nexthop_id, flags)`.
#[inline]
pub const fn fibw_unpack(w: FibWord) -> (u32, u32) {
    (w & FIBW_ID_MASK, w >> FIBW_FLAGS_SHIFT & FIBW_FLAGS_MASK)
}

/// Number of `TBL8` groups sized at load time in dir24 mode (each group is
/// 256 `FibWord` slots). One group is consumed per /24 that contains a
/// longer-than-/24 route.
pub const DIR24_TBL8_GROUPS: u32 = 4096;

/// `DP_CONFIG[0]` bits — datapath configuration word, written by user space.
/// Bit 0: the DIR-24-8 v4 engine is active (else the LPM trie).
pub const DPC_FIB4_DIR24: u32 = 1 << 0;

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
    /// Fast-reroute: the nexthop to use when this one's `oif` is down
    /// (`LINK_DOWN`), typically carrying a TI-LFA SRv6 repair (segs +
    /// `SRV6_ENCAP_MODE_INSERT`). 0 = unprotected.
    pub backup_id: u32,
}

pub const NH_F_V6: u32 = 1 << 0;
pub const NH_F_ONLINK: u32 = 1 << 1;
/// Nexthop imposes/swaps an MPLS label stack (`labels`/`num_labels`).
pub const NH_F_MPLS: u32 = 1 << 2;
/// Nexthop imposes an SRv6 encap (`SRV6_ENCAP[nexthop_id]`).
pub const NH_F_SRV6: u32 = 1 << 3;
/// Nexthop imposes a GTP-U encap (`GTP_ENCAP[nexthop_id]`) — outer IPv4 + UDP
/// (2152) + GTP-U(TEID) around the packet (draft-ietf-dmm-srv6-mobile-uplane
/// `GTP4.E`, the downlink toward a gNB / peer UPF).
pub const NH_F_GTP: u32 = 1 << 4;

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

/// Per-VRF IPv4 LPM key: the VRF id prefixes the address, so one trie holds
/// every VRF table — a route `addr/len` in VRF `v` is inserted with
/// `prefix_len = 32 + len` (the VRF bits always match exactly).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Vrf4Key {
    pub vrf_id: u32,
    pub addr: [u8; 4],
}

/// XDP→TC metadata: VRF context attached by the XDP MPLS stage when a
/// VPN-label decap selects a VRF table (`bpf_xdp_adjust_meta`; TC reads the
/// `data_meta..data` window). `magic` guards against foreign metadata.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CradleXdpMeta {
    pub magic: u32,
    /// L3 decap (`XDP_META_MAGIC`): the VRF table for the inner IP lookup.
    /// L2 decap (`XDP_META_MAGIC_L2`): the bridge domain for the inner frame.
    pub vrf_id: u32,
}

/// L3 (`End.DT4/6/46`) decap: TC routes the inner IP packet in `vrf_id`.
pub const XDP_META_MAGIC: u32 = 0xC7AD_1E01;
/// L2 (`End.DT2U`) decap: TC bridges the inner Ethernet frame in `vrf_id`
/// (reused as the bridge domain), regardless of the underlay port's type.
pub const XDP_META_MAGIC_L2: u32 = 0xC7AD_1E02;
/// DX cross-connect metadata: `vrf_id` carries the *nexthop id* the TC
/// stage must forward the decapped packet to — no FIB lookup (End.DX4/DX6,
/// RFC 8986 §4.5/§4.4). XDP can't `bpf_redirect` toward a CE veth whose
/// peer runs no NAPI, so the skb-path TC redirect finishes the job.
pub const XDP_META_MAGIC_DX: u32 = 0xC7AD_1E03;
/// DX2 cross-connect metadata: `vrf_id` carries the *AC ifindex* the TC
/// stage must emit the decapped Ethernet frame out of — raw, no MAC
/// rewrite (End.DX2/DX2V, RFC 8986 §4.9/§4.10).
pub const XDP_META_MAGIC_DX2: u32 = 0xC7AD_1E04;

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

// ============================== SRv6 =======================================

/// Local SID table entry (`SRV6_LOCALSID`, LPM by the IPv6 destination):
/// the behavior this node executes when a packet's DA matches the SID.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct LocalSid {
    /// `SRV6_BH_*` behavior.
    pub behavior: u8,
    /// `SRV6_FLAVOR_*` bitmask (RFC 8986 §4.16). PSP applies to
    /// End/End.X/uN/uA; USP/USD are honored for End/uN only (the End.X
    /// variants would need an adjacency-forward decap — not implemented).
    pub flavors: u8,
    pub _pad: [u8; 2],
    /// VRF/table id for `End.DT4/DT6/DT46` (0 = global).
    pub vrf_id: u32,
    /// Nexthop id for `End.X` / `uA` (adjacency cross-connect); 0 otherwise.
    pub nexthop_id: u32,
    /// uSID locator-block / node bit lengths (NEXT-C-SID shift; later phase).
    pub block_bits: u8,
    pub node_bits: u8,
    /// Function bit length. Only REPLACE-C-SID reads it: the replaced C-SID
    /// is `node_bits + fun_bits` wide (RFC 9800 LNFL, 16 or 32).
    pub fun_bits: u8,
    pub _pad2: [u8; 1],
}

// Behaviors mirror zebra-rs's live `SidBehavior` set (RFC 8986 + NEXT-C-SID).
pub const SRV6_BH_END: u8 = 0;
pub const SRV6_BH_END_X: u8 = 1;
pub const SRV6_BH_END_DT4: u8 = 2;
pub const SRV6_BH_END_DT6: u8 = 3;
pub const SRV6_BH_END_DT46: u8 = 4;
/// `End.B6.Encaps` (RFC 8986 §4.13): the SRv6 Binding SID. Run the End walk
/// on the received SRH, then push a new outer IPv6 (+SRH) carrying the bound
/// SR Policy's segment list — `nexthop_id` points at the `SRV6_ENCAP` entry
/// holding it. Emits the Reduced form (§4.14) like `apply_hencap`.
pub const SRV6_BH_END_B6: u8 = 5;
pub const SRV6_BH_UN: u8 = 6;
/// `uA`: classic End.X adjacency at /128 (no NEXT-C-SID shift).
pub const SRV6_BH_UA: u8 = 7;
/// `uALib`: the compressed-carrier adjacency form — shift the uSID container,
/// then forward out the cross-connect adjacency (matched at a block+function
/// prefix, mid-carrier after a uN shift).
pub const SRV6_BH_UALIB: u8 = 8;
/// `End.DT2U`: decapsulate + unicast L2 (EVPN-over-SRv6) — the SID's `vrf_id`
/// carries the bridge domain the inner Ethernet frame is switched in.
pub const SRV6_BH_END_DT2U: u8 = 9;
/// `End.DT2M`: decapsulate + BUM L2 flood (EVPN-over-SRv6). Slice 2.
pub const SRV6_BH_END_DT2M: u8 = 10;
/// `End.M`: the egress-protection mirror (draft-ietf-rtgwg-srv6-egress-
/// protection). Decapsulate, then look the exposed packet's destination —
/// the *failed* egress PE's service SID — up in the mirror-context table
/// (`vrf_id` = the context id) via the `MIRROR` trie, reproducing that
/// egress's decap locally.
pub const SRV6_BH_END_M: u8 = 11;
/// `End with REPLACE-C-SID` (RFC 9800 §4.2.1): rewrite only the C-SID bits
/// of the DA from the packed container at `Segment List[SL]`, driven by the
/// index argument in the DA's last bits. Matched at a block+C-SID prefix.
pub const SRV6_BH_END_REP: u8 = 12;
/// `End.X with REPLACE-C-SID` (RFC 9800 §4.2.2): as `End` with REPLACE-C-SID,
/// then forward out the SID's cross-connect adjacency.
pub const SRV6_BH_END_X_REP: u8 = 13;
/// `End.T` (RFC 8986 §4.3): the End walk, then the egress lookup scoped to
/// the SID's table (`vrf_id`) via the XDP→TC metadata channel. A `uN` whose
/// `vrf_id` is set behaves the same at end-of-carrier — that is zebra's uT.
pub const SRV6_BH_END_T: u8 = 14;
/// `End.DX4` (RFC 8986 §4.5): decapsulate and cross-connect the inner IPv4
/// packet straight to the SID's adjacency (`nexthop_id`) — the per-CE VPN
/// form; no FIB lookup, no TTL decrement (the tunnel charged it at ingress).
pub const SRV6_BH_END_DX4: u8 = 15;
/// `End.DX6` (RFC 8986 §4.4): as `End.DX4` for an inner IPv6 packet.
pub const SRV6_BH_END_DX6: u8 = 16;
/// `End.DX2` (RFC 8986 §4.9): decapsulate and emit the inner **Ethernet
/// frame** raw out the attachment circuit — `vrf_id` carries the AC
/// ifindex. The EVPN VPWS (E-Line) egress; no FDB, no learning, no MAC
/// rewrite.
pub const SRV6_BH_END_DX2: u8 = 17;
/// `End.DX2V` (RFC 8986 §4.10): as `End.DX2`, but the inner frame's
/// 802.1Q VID selects the AC via the `DX2V` table — `vrf_id` is the
/// VLAN-table id.
pub const SRV6_BH_END_DX2V: u8 = 18;

/// SRv6 endpoint flavors (RFC 8986 §4.16), OR-able in `LocalSid::flavors`.
/// PSP: pop the SRH at the penultimate segment (this node's decrement hits
/// `SL == 0`), handing the last hop a clean packet.
pub const SRV6_FLAVOR_PSP: u8 = 1;
/// USP: pop the exhausted SRH (`SL == 0` on arrival) before local delivery.
pub const SRV6_FLAVOR_USP: u8 = 2;
/// USD: decapsulate the outer IPv6 (+SRH) at the ultimate segment and
/// forward the inner packet (main-table lookup).
pub const SRV6_FLAVOR_USD: u8 = 4;

/// Mirror-context LPM key (`MIRROR`): the protected egress's SID space,
/// scoped by the End.M SID's context id — a route `addr/len` in context
/// `c` is inserted with `prefix_len = 32 + len` (like `Vrf6Key`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MirrorKey {
    pub ctx: u32,
    pub addr: [u8; 16],
}

/// Mirror-context entry: how to reproduce the failed egress's behavior —
/// a DT-style decap into a local table.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MirrorEntry {
    /// `SRV6_BH_END_DT4/DT6/DT46` semantics applied to the exposed packet.
    pub behavior: u8,
    pub _pad: [u8; 3],
    /// Local VRF table the inner packet is looked up in.
    pub vrf_id: u32,
}

/// `DX2V` VLAN-table key (RFC 8986 §4.10): the End.DX2V SID's table id
/// (`LocalSid::vrf_id`) plus the inner frame's 802.1Q VID.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Dx2vKey {
    pub table: u32,
    pub vid: u16,
    pub _pad: [u8; 2],
}

/// Maximum SIDs in an imposed segment list (bounds the encap/SRH loops).
pub const MAX_SEGS: usize = 6;

/// Segment list imposed by an `NH_F_SRV6` nexthop (`SRV6_ENCAP`, keyed by
/// nexthop id — SIDs are 16 bytes, too big to inline on `NextHop`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Srv6Encap {
    /// 1 = reduced single-SID (no SRH); >1 = SRH carried (later phase).
    pub num_segs: u8,
    /// `SRV6_ENCAP_MODE_*`: how the segments are imposed.
    pub mode: u8,
    pub _pad: [u8; 2],
    /// `[0]` = first SID = the outer destination.
    pub segs: [[u8; 16]; MAX_SEGS],
}

/// H.Encaps / H.Encaps.Red — outer IPv6 (+SRH when >1 seg) around the packet.
pub const SRV6_ENCAP_MODE_ENCAPS: u8 = 0;
/// H.Insert — insert an SRH into the *existing* IPv6 packet: the original
/// destination rides as the SRH's final segment and takes over at SL 0
/// (TI-LFA repair; RFC 8986 §5.2 deprecated-but-deployed form). v6-only.
pub const SRV6_ENCAP_MODE_INSERT: u8 = 2;

/// GTP-U tunnel imposed by an `NH_F_GTP` nexthop (`GTP_ENCAP`, keyed by nexthop
/// id — the side table to `NEXTHOPS`, mirroring `Srv6Encap`). The downlink
/// `GTP4.E` behaviour wraps the (v4 or v6) inner packet in an outer IPv4 header,
/// UDP dport 2152, and an 8-byte GTP-U G-PDU header carrying `teid`. Addresses
/// and TEID are stored as their on-wire bytes so the datapath writes them
/// directly (no endianness juggling).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GtpEncap {
    /// Outer IPv4 source — the local N3/N9 tunnel address (wire bytes).
    pub src: [u8; 4],
    /// Outer IPv4 destination — the peer (gNB / peer UPF) tunnel address.
    pub dst: [u8; 4],
    /// GTP-U TEID, big-endian wire bytes.
    pub teid: [u8; 4],
    /// QFI for a PDU Session Container extension header; 0 = none (the MVP
    /// writes a plain G-PDU and ignores this).
    pub qfi: u8,
    pub _pad: [u8; 3],
}

/// GTP-U decap match (a PDR), keyed exactly by the local tunnel endpoint +
/// TEID a received G-PDU carries — the `GTP_PDR` hash probed in XDP before the
/// FIB, mirroring the role of `SRV6_LOCALSID`. The `H.M.GTP4.D`-style uplink:
/// a G-PDU on `(dst, teid)` is stripped and the inner packet forwarded in
/// `vrf_id`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GtpPdrKey {
    /// Local outer IPv4 destination the G-PDU arrived on (wire bytes).
    pub dst: [u8; 4],
    /// GTP-U TEID, big-endian wire bytes (as read off the packet).
    pub teid: [u8; 4],
}

/// The action bound to a [`GtpPdrKey`]: forward the decapped inner packet in
/// this VRF table (0 = global), handed to TC via `CradleXdpMeta` exactly like
/// an `End.DT*` decap.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct GtpPdr {
    pub vrf_id: u32,
}

/// EVPN/VXLAN L2VNI binding — the decap direction of the VNI ↔ bridge-domain
/// mapping (`VNI_INFO[vni]`; the encap direction is the `VLAN_VNI` map). A
/// received VXLAN frame's VNI selects the bridge domain its inner Ethernet
/// frame is switched in. Phase-3 symmetric IRB grows this struct (vrf_id,
/// flags, rmac) — maps are unpinned, so the ABI can extend freely.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VniInfo {
    /// Access bridge domain of this L2VNI.
    pub vlan: u16,
    pub _pad: [u8; 2],
}

/// A BUM ingress-replication slot's target — the remote PE one flooded copy
/// is tunneled toward, by overlay kind (the `REPL_SID` map's value).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ReplTarget {
    /// `REPL_KIND_*`. The zero value is SRv6, preserving the pre-`ReplTarget`
    /// semantic of the map.
    pub kind: u32,
    /// L2VNI stamped into the outer header (`REPL_KIND_VXLAN` only; 0 for
    /// SRv6, where the remote SID implies the bridge domain).
    pub vni: u32,
    /// `REPL_KIND_SRV6`: the remote `End.DT2M` SID. `REPL_KIND_VXLAN`: the
    /// remote VTEP IPv4, v4-mapped (bytes 12..16 are the wire address).
    pub addr: [u8; 16],
}

/// [`ReplTarget::addr`] is a remote `End.DT2M` SID (MAC-in-SRv6 per copy).
pub const REPL_KIND_SRV6: u32 = 0;
/// [`ReplTarget::addr`] is a remote VTEP IPv4 (VXLAN per copy, `vni` set).
pub const REPL_KIND_VXLAN: u32 = 1;

/// Per-VRF IPv6 LPM key — the v6 mirror of `Vrf4Key`: a route `addr/len` in
/// VRF `v` is inserted with `prefix_len = 32 + len`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Vrf6Key {
    pub vrf_id: u32,
    pub addr: [u8; 16],
}

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
    /// Local egress ifindex; for an `FDB_F_REMOTE` entry this is instead the
    /// underlay nexthop id used to reach `remote_sid`.
    pub oif: u32,
    pub flags: u32,
    /// EVPN-over-SRv6 overlay target: the remote PE's `End.DT2U` service SID
    /// this MAC sits behind (`FDB_F_REMOTE` only; zero otherwise).
    pub remote_sid: [u8; 16],
    /// `bpf_ktime_get_ns()` of the last frame that learned/refreshed this
    /// entry (local learns only; 0 on control-plane-installed entries).
    /// The user-space aging sweep expires idle local entries against it.
    pub last_seen: u64,
}

/// This MAC is one of ours — punt the frame up to L3 / the host stack.
pub const FDB_F_LOCAL: u32 = 1 << 0;
/// This MAC is behind an SRv6 overlay: `remote_sid` is its `End.DT2U` SID and
/// `oif` is the underlay nexthop id (EVPN over SRv6).
pub const FDB_F_REMOTE: u32 = 1 << 1;
/// This MAC is behind a VXLAN overlay (set together with `FDB_F_REMOTE`):
/// `remote_sid` holds the remote VTEP's IPv4 v4-mapped (`::ffff:a.b.c.d` —
/// bytes 12..16 are the wire address) and `oif` is the underlay nexthop id
/// (0 = resolve by FIB4 lookup on the VTEP).
pub const FDB_F_VXLAN: u32 = 1 << 2;

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
    /// VRF table this L3 port belongs to (0 = global): ingress lookups use
    /// the per-VRF FIB instead of the global one.
    pub vrf_id: u32,
}

/// Participate in L2 switching.
pub const PORT_F_L2: u32 = 1 << 0;
/// Routed (L3) port.
pub const PORT_F_L3: u32 = 1 << 1;
/// A pod endpoint's host-side veth: packets arriving here are pod egress —
/// tracked in `PCT` so replies pass ingress policy (stateful semantics).
pub const PORT_F_ENDPOINT: u32 = 1 << 2;

// ============================ network policy ===============================

/// Reserved identity: the node itself (kubelet probes etc.). Follows
/// Cilium's reserved numbering.
pub const IDENTITY_HOST: u32 = 1;
/// Reserved identity: any source with no `IDENTITY` entry.
pub const IDENTITY_WORLD: u32 = 2;

/// Policy rule direction: traffic delivered *to* the endpoint.
pub const POLICY_DIR_INGRESS: u8 = 0;
/// Policy rule direction: traffic initiated *by* the endpoint.
pub const POLICY_DIR_EGRESS: u8 = 1;
/// `PolicyKey.dir` bit 1: the rule's A/B generation. Policy replacement
/// inserts the new rule set under the flipped generation, then atomically
/// switches the endpoint via the `EP_F_GEN` bit — packets never see a
/// half-replaced table. (The map-in-map inner-swap design is deferred until
/// aya-ebpf can declare BTF maps; see docs/design/policy-multitenant.md.)
pub const POLICY_KEY_GEN: u8 = 1 << 1;

/// `EP_POLICY` value bit: enforce ingress rules for this endpoint.
pub const EP_F_INGRESS: u8 = 1 << 0;
/// `EP_POLICY` value bit: enforce egress rules for this endpoint.
pub const EP_F_EGRESS: u8 = 1 << 1;
/// `EP_POLICY` value bit: audit mode — denied verdicts are counted and
/// reported (Hubble) but the packet is forwarded.
pub const EP_F_AUDIT: u8 = 1 << 2;
/// `EP_POLICY` value bit: the endpoint's active rule generation
/// (`POLICY_KEY_GEN` in the keys that apply).
pub const EP_F_GEN: u8 = 1 << 3;

/// `PCT` value: flow initiated by the local pod (recorded at pod egress,
/// pre-NAT) — its replies bypass the pod's ingress policy.
pub const PCT_POD_INITIATED: u8 = 1;
/// `PCT` value: admitted flow initiated from outside the pod (recorded at
/// ingress delivery, post-NAT) — its replies bypass the pod's egress policy.
pub const PCT_INBOUND: u8 = 2;

/// VRF-scoped identity key: tenants may reuse addresses, so "who is
/// talking" is `(vrf, ip)` (docs/design/policy-multitenant.md phase 4).
/// VRF 0 is the global table — single-tenant deployments never see another.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VrfIdKey {
    pub vrf_id: u32,
    /// IPv4, map-encoded (`u32::from_be_bytes(octets)`).
    pub addr: u32,
}

/// v6 sibling of `VrfIdKey`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VrfId6Key {
    pub vrf_id: u32,
    pub addr: [u8; 16],
}

/// `POLICY` value: allow the matched traffic.
pub const POLICY_ALLOW: u8 = 1;
/// `POLICY` value: deny the matched traffic. Deny wins over allow at *any*
/// specificity (Cilium deny-rule semantics): the verdict walks all probes,
/// returns denied on the first deny hit, and otherwise allows iff some
/// probe hit an allow.
pub const POLICY_DENY: u8 = 2;

/// Policy allow-rule key: `(endpoint oif, peer identity, proto, dport,
/// direction)`. The peer is the source for ingress rules and the destination
/// for egress rules. `identity`, `proto`, and `port` may each be 0 =
/// wildcard; the datapath probes most-specific-first (docs/design/policy.md).
/// Present in `POLICY` ⇒ allow.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PolicyKey {
    /// The enforced endpoint: the pod's host-side veth ifindex.
    pub ep: u32,
    /// Peer identity (label-set hash; 1 = host, 2 = world, 0 = any).
    pub identity: u32,
    /// Destination L4 port, network byte order (0 = any).
    pub port: u16,
    /// IP protocol (0 = any).
    pub proto: u8,
    /// Bit 0: `POLICY_DIR_*`; bit 1: `POLICY_KEY_GEN` (A/B generation).
    pub dir: u8,
}

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

/// `ServiceInfo.flags`: `sessionAffinity: ClientIP` — a client sticks to one
/// backend (see `AFFINITY`).
pub const SVC_F_AFFINITY: u8 = 1 << 0;

/// Session-affinity map key: (service, client IPv4).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AffinityKey {
    pub svc_id: u32,
    /// Client IPv4, map-encoded.
    pub client: u32,
}

/// Session-affinity value: the sticky backend slot + last-use timestamp.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AffinityVal {
    pub slot: u16,
    pub _pad: u16,
    pub last_ns: u64,
}

/// ClientIP affinity idle timeout (Kubernetes default 10800s = 3h), in ns.
pub const AFFINITY_TIMEOUT_NS: u64 = 10_800 * 1_000_000_000;

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
/// DIR-24-8: resolved in one `TBL24` lookup.
pub const STAT_FIB4_TBL24_HIT: u32 = 12;
/// DIR-24-8: resolved through a `TBL8` group (two lookups).
pub const STAT_FIB4_TBL8_HIT: u32 = 13;
/// DIR-24-8: fell through to the `DEFAULT4` route.
pub const STAT_FIB4_DEFAULT: u32 = 14;
/// Resolved in a per-VRF FIB table.
pub const STAT_FIB4_VRF_HIT: u32 = 15;
/// SRv6: outer IPv6 imposed (ingress PE, H.Encaps).
pub const STAT_SRV6_ENCAP: u32 = 16;
/// SRv6: End.DT* decapsulation (egress PE).
pub const STAT_SRV6_DECAP: u32 = 17;
/// Resolved in a per-VRF IPv6 FIB table.
pub const STAT_FIB6_VRF_HIT: u32 = 18;
/// SRv6: End / End.X segment transit (Segments Left walk).
pub const STAT_SRV6_END: u32 = 19;
/// SRv6 uSID: uN NEXT-C-SID transit (micro-SID container shift).
pub const STAT_SRV6_USID: u32 = 20;
/// EVPN over SRv6: MAC-in-SRv6 L2 encapsulation (ingress PE).
pub const STAT_SRV6_L2_ENCAP: u32 = 21;
/// EVPN over SRv6: `End.DT2U`/`End.DT2M` L2 decapsulation (egress PE).
pub const STAT_SRV6_L2_DECAP: u32 = 22;
/// EVPN over SRv6: BUM (broadcast/multicast/unknown) MAC-in-SRv6 encap toward
/// the bridge domain's `End.DT2M` SID (ingress PE).
pub const STAT_SRV6_L2_BUM: u32 = 23;
/// FDB entries expired by the user-space aging sweep (idle local MACs).
pub const STAT_FDB_AGED: u32 = 24;
/// SRv6 H.Insert impositions (TI-LFA repair onto the backup path).
pub const STAT_SRV6_HINSERT: u32 = 25;
/// Forwards that switched to a backup nexthop (primary's link down).
pub const STAT_NH_BACKUP: u32 = 26;
/// `End.M` mirror decaps (egress protection served on the protector).
pub const STAT_SRV6_ENDM: u32 = 27;
/// PSP flavor pops (SRH removed at the penultimate segment).
pub const STAT_SRV6_PSP: u32 = 28;
/// USP flavor pops (exhausted SRH removed before local delivery).
pub const STAT_SRV6_USP: u32 = 29;
/// USD flavor decaps (outer IPv6+SRH removed, inner forwarded).
pub const STAT_SRV6_USD: u32 = 30;
/// REPLACE-C-SID transits (C-SID rewrite or container-to-container advance).
pub const STAT_SRV6_REPLACE: u32 = 31;
/// End.B6.Encaps binds (inner End walk + policy encapsulation pushed).
pub const STAT_SRV6_B6: u32 = 32;
/// End.T table-scoped forwards (the End walk's lookup moved to table T).
pub const STAT_SRV6_ENDT: u32 = 33;
/// End.DX4/DX6 decap + cross-connect forwards (per-CE VPN egress).
pub const STAT_SRV6_DX: u32 = 34;
/// GTP-U encaps (`GTP4.E`: outer IPv4+UDP+GTP-U imposed on a downlink packet).
pub const STAT_GTP_ENCAP: u32 = 35;
/// GTP-U decaps (`H.M.GTP4.D`: a G-PDU stripped, inner forwarded in its VRF).
pub const STAT_GTP_DECAP: u32 = 36;
/// End.DX2/DX2V decaps (EVPN VPWS egress — frame emitted raw on the AC).
pub const STAT_SRV6_DX2: u32 = 37;
/// Ingress network-policy drops (enforced endpoint, no PCT/POLICY match).
pub const STAT_POLICY_DROP: u32 = 38;
/// Egress masquerade: a pod→outside-the-cluster flow SNAT'd to the node IP.
pub const STAT_MASQ: u32 = 39;
/// Policy verdicts that would have dropped but the endpoint is in audit
/// mode (`EP_F_AUDIT`) — the packet was forwarded.
pub const STAT_POLICY_AUDIT: u32 = 40;
/// EVPN/VXLAN: outer Eth+IPv4+UDP+VXLAN imposed on an L2 frame (ingress VTEP).
pub const STAT_VXLAN_ENCAP: u32 = 41;
/// EVPN/VXLAN: outer encapsulation stripped, inner frame bridged (egress VTEP).
pub const STAT_VXLAN_DECAP: u32 = 42;
/// EVPN/VXLAN: BUM (broadcast/multicast/unknown) frame VXLAN-encapsulated
/// toward a remote VTEP (sentinel tunnel or ingress-replication copy).
pub const STAT_VXLAN_FLOOD: u32 = 43;
/// Number of stat slots (the `STATS` map's `max_entries`).
pub const STAT_MAX: u32 = 44;

// ====================== Hubble flow events (docs/design/hubble.md) ==========

/// Flow verdicts, mapped in user space to the Hubble `Verdict` enum.
pub const FLOW_FORWARDED: u8 = 1;
pub const FLOW_DROPPED: u8 = 2;
pub const FLOW_TRANSLATED: u8 = 3;
/// Denied by policy but forwarded — the endpoint is in audit mode.
pub const FLOW_AUDITED: u8 = 4;

/// Traffic direction (Hubble `TrafficDirection`).
pub const FLOW_DIR_UNKNOWN: u8 = 0;
pub const FLOW_DIR_INGRESS: u8 = 1;
pub const FLOW_DIR_EGRESS: u8 = 2;

/// A datapath flow event pushed onto the `FLOWS` ring buffer at a forwarding
/// verdict point (H1 = IPv4). User space enriches it into a Hubble `Flow`.
/// `saddr`/`daddr` are the network-order octets as loaded; `sport`/`dport`
/// are network-order 16-bit (user space applies `u16::from_be`).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FlowRecord {
    /// `bpf_ktime_get_ns()` when the verdict was reached.
    pub time_ns: u64,
    /// The local pod endpoint's host-veth ifindex (0 = none) — enrichment key.
    pub ep_ifindex: u32,
    pub saddr: [u8; 4],
    pub daddr: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    /// `FLOW_FORWARDED` / `FLOW_DROPPED` / `FLOW_TRANSLATED` / `FLOW_AUDITED`.
    pub verdict: u8,
    /// `FLOW_DIR_*`.
    pub dir: u8,
    pub _pad: u8,
    /// Policy verdicts (`FLOW_DROPPED`/`FLOW_AUDITED` from the policy
    /// engine): the peer identity the rules were matched against (source
    /// identity for ingress, destination for egress). 0 = not a policy
    /// verdict / unknown.
    pub peer_identity: u32,
}

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
        MirrorKey,
        MirrorEntry,
        FibEntry,
        NextHop,
        Neigh4Key,
        Neigh6Key,
        NeighEntry,
        NhGroupKey,
        MplsEntry,
        Vrf4Key,
        VrfIdKey,
        VrfId6Key,
        Vrf6Key,
        LocalSid,
        Srv6Encap,
        GtpEncap,
        GtpPdrKey,
        GtpPdr,
        VniInfo,
        ReplTarget,
        FdbKey,
        FdbEntry,
        Dx2vKey,
        PortConfig,
        L2MemberKey,
        ServiceKey,
        ServiceInfo,
        BackendKey,
        Backend,
        CtKey,
        CtEntry,
        PolicyKey,
        AffinityKey,
        AffinityVal,
        ServiceKey6,
        Backend6,
        CtKey6,
        CtEntry6,
        FlowRecord,
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
    fn fibw_round_trip() {
        for (nh, flags) in [
            (0, 0),
            (1, FIB_F_LOCAL),
            (0x3ff_ffff, 0xf),
            (42, FIB_F_ECMP),
        ] {
            let w = fibw_entry(nh, flags);
            assert_ne!(w & FIBW_VALID, 0);
            assert_eq!(w & FIBW_TBL8, 0);
            assert_eq!(fibw_unpack(w), (nh, flags));
        }
        let g = fibw_group(4095);
        assert_ne!(g & FIBW_VALID, 0);
        assert_ne!(g & FIBW_TBL8, 0);
        assert_eq!(g & FIBW_ID_MASK, 4095);
        // All current FIB_F_* flags fit the 4-bit field.
        assert_eq!(
            (FIB_F_BLACKHOLE | FIB_F_LOCAL | FIB_F_CONNECTED | FIB_F_ECMP) & !FIBW_FLAGS_MASK,
            0
        );
        // Zero is the invalid word: VALID is a real, non-zero bit.
        assert_ne!(FIBW_VALID, 0);
    }

    #[test]
    fn lse_wire_layout() {
        // RFC 3032: label 16, TC 0, S 1, TTL 64 => 0x00 01 01 40 on the wire.
        assert_eq!(
            mpls_lse(16, 0, 1, 64).to_be_bytes(),
            [0x00, 0x01, 0x01, 0x40]
        );
        // Label field is masked to 20 bits.
        assert_eq!(mpls_lse(0x1f_ffff, 0, 0, 0) >> 12, 0xf_ffff);
    }
}
