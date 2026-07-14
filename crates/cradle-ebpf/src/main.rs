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

// BFD Echo reflector + in-kernel watchdog, called from `cradle_xdp`'s UDP
// dispatch (absorbed from the standalone xdp-bfd-echo offload — Phase 2).
mod bfd;

use aya_ebpf::{
    bindings::{
        TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT,
        bpf_adj_room_mode::{BPF_ADJ_ROOM_MAC, BPF_ADJ_ROOM_NET},
        bpf_redir_neigh, bpf_redir_neigh__bindgen_ty_1, bpf_sock_tuple,
        bpf_sock_tuple__bindgen_ty_1, bpf_sock_tuple__bindgen_ty_1__bindgen_ty_1, xdp_action,
    },
    helpers::generated::{
        bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_redirect, bpf_redirect_neigh, bpf_sk_assign,
        bpf_sk_release, bpf_skb_load_bytes, bpf_skc_lookup_tcp, bpf_xdp_adjust_head,
        bpf_xdp_adjust_meta,
    },
    macros::{classifier, map, xdp},
    maps::{Array, HashMap, LpmTrie, LruHashMap, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::{TcContext, XdpContext},
};
use cradle_common::{
    AFFINITY_TIMEOUT_NS, AffinityKey, AffinityVal, Backend, Backend6, BackendKey, CT_F_DNAT,
    CT_F_SNAT, CradleXdpMeta, CtEntry, CtEntry6, CtKey, CtKey6, DPC_FIB4_DIR24, DPC_L3_ONLY,
    Dx2vKey,
    EP_F_AUDIT, EP_F_EGRESS, EP_F_GEN, EP_F_INGRESS, FDB_F_REMOTE, FDB_F_VXLAN, FIB_F_BLACKHOLE,
    FIB_F_ECMP, FIB_F_LOCAL, FIBW_ID_MASK, FIBW_TBL8, FIBW_VALID, FLOW_AUDITED, FLOW_DIR_EGRESS,
    FLOW_DIR_INGRESS, FLOW_DROPPED, FLOW_FORWARDED, FLOW_TRANSLATED, FdbEntry, FdbKey, FibEntry,
    FibWord, FlowRecord, GtpEncap, GtpPdr, GtpPdrKey, IDENTITY_WORLD, L2MemberKey, L7_PROXY_PORT,
    LocalSid, MAX_LABELS, MAX_REPL_BRANCHES, MAX_SEGS, MPLS_E_TTL_UNIFORM, MPLS_OP_POP,
    MPLS_OP_POP_L3, MPLS_OP_SWAP, MPLS_PIPE_TTL, MirrorEntry, MirrorKey, MplsEntry, NH_F_GTP,
    NH_F_MPLS, NH_F_MPLS_PIPE, NH_F_SRV6, NH_F_V6, NH_F_VXLAN, Neigh4Key, Neigh6Key, NeighEntry,
    NextHop, NhGroupKey, PCT_INBOUND, PCT_POD_INITIATED, POLICY_DENY, POLICY_DIR_EGRESS,
    POLICY_DIR_INGRESS, POLICY_KEY_GEN, PORT_F_ENDPOINT, PORT_F_L2, PORT_F_L3, PolicyKey,
    PortConfig, REPL_BRANCH_LOCAL, REPL_KIND_VXLAN, ReplBranch, ReplSeg, ReplTarget, SRV6_BH_END,
    SRV6_BH_END_B6, SRV6_BH_END_DT2M, SRV6_BH_END_DT2U, SRV6_BH_END_DT4, SRV6_BH_END_DT6,
    SRV6_BH_END_DT46, SRV6_BH_END_DX2, SRV6_BH_END_DX2V, SRV6_BH_END_DX4, SRV6_BH_END_DX6,
    SRV6_BH_END_M, SRV6_BH_END_REP, SRV6_BH_END_REPLICATE, SRV6_BH_END_T, SRV6_BH_END_X,
    SRV6_BH_END_X_REP, SRV6_BH_UA, SRV6_BH_UALIB, SRV6_BH_UN, SRV6_ENCAP_MODE_INSERT,
    SRV6_FLAVOR_PSP, SRV6_FLAVOR_USD, SRV6_FLAVOR_USP, STAT_DROP, STAT_FIB4_DEFAULT,
    STAT_FIB4_TBL8_HIT, STAT_FIB4_TBL24_HIT, STAT_FIB4_VRF_HIT, STAT_FIB6_VRF_HIT, STAT_GTP_DECAP,
    STAT_GTP_ENCAP, STAT_L2_FLOOD, STAT_L2_FORWARD, STAT_L3_LOCAL, STAT_L3V4_FORWARD,
    STAT_L3V6_FORWARD, STAT_L4_DNAT, STAT_L4_SNAT, STAT_L7_REDIRECT, STAT_MASQ, STAT_MAX,
    STAT_MPLS_POP, STAT_MPLS_PUSH, STAT_MPLS_SWAP, STAT_NH_BACKUP, STAT_POLICY_AUDIT,
    STAT_POLICY_DROP, STAT_SRV6_B6, STAT_SRV6_DECAP, STAT_SRV6_DX, STAT_SRV6_DX2, STAT_SRV6_ENCAP,
    STAT_SRV6_END, STAT_SRV6_ENDM, STAT_SRV6_ENDT, STAT_SRV6_HINSERT, STAT_SRV6_L2_BUM,
    STAT_SRV6_L2_DECAP, STAT_SRV6_L2_ENCAP, STAT_SRV6_PSP, STAT_SRV6_REPLACE, STAT_SRV6_REPLICATE,
    STAT_SRV6_USD, STAT_SRV6_USID, STAT_SRV6_USP, STAT_VXLAN_DECAP, STAT_VXLAN_ENCAP,
    STAT_VXLAN_FLOOD, STAT_XDP_L3_FWD, SVC_F_AFFINITY, ServiceInfo, ServiceKey, ServiceKey6,
    Srv6Encap, VNI_F_L3,
    VniInfo, Vrf4Key, Vrf6Key, VrfId6Key, VrfIdKey, VxlanEncap, XDP_META_MAGIC, XDP_META_MAGIC_DX,
    XDP_META_MAGIC_DX2, XDP_META_MAGIC_L2, XDP_META_MAGIC_REPL, fibw_unpack, mpls_lse,
    mpls_lse_unpack,
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
/// GTP-U encap side table (keyed by nexthop id, the `Srv6Encap` analogue): an
/// `NH_F_GTP` nexthop's outer IPv4 src/dst + TEID.
#[map]
static GTP_ENCAP: HashMap<u32, GtpEncap> = HashMap::with_max_entries(4096, 0);
/// GTP-U decap PDR table: a received G-PDU's (local outer dst, TEID) → decap +
/// forward the inner in `vrf_id` (the `SRV6_LOCALSID` analogue for GTP).
#[map]
static GTP_PDR: HashMap<GtpPdrKey, GtpPdr> = HashMap::with_max_entries(4096, 0);

// --- EVPN/VXLAN (evpn-vxlan.md): the L2VNI ↔ bridge-domain binding in both
// directions, and the local VTEP source address. ---
/// Encap direction: an L2 frame in this bridge domain tunnels with this VNI.
#[map]
static VLAN_VNI: HashMap<u16, u32> = HashMap::with_max_entries(4096, 0);
/// Decap direction: a received VXLAN frame's VNI selects the bridge domain
/// (the `SRV6_LOCALSID`/`GTP_PDR` analogue for VXLAN).
#[map]
static VNI_INFO: HashMap<u32, VniInfo> = HashMap::with_max_entries(4096, 0);
/// Local VTEP source IPv4, wire bytes ([0] — the `SRV6_ENCAP_SRC` analogue).
/// All-zero = VXLAN unconfigured: the decap never claims a packet.
#[map]
static VXLAN_SRC: Array<[u8; 4]> = Array::with_max_entries(1, 0);
/// EVPN symmetric IRB (RFC 9135): per-nexthop VXLAN L3 encap, keyed by
/// nexthop id (the `NH_F_VXLAN` companion to `GTP_ENCAP`).
#[map]
static VXLAN_ENCAP: HashMap<u32, VxlanEncap> = HashMap::with_max_entries(4096, 0);
/// Per-instance random cookie folded into the XDP→TC metadata magic. skb
/// metadata SURVIVES a veth hop into the neighbour's TC stage (and is not
/// even visible to its XDP program on the veth rx path), so a constant
/// magic would let one node's End.T/DT table id steer the NEXT node's
/// lookup. Each cradle instance seeds its own cookie at startup; inherited
/// metadata from any other instance fails the check and is ignored.
#[map]
static META_COOKIE: Array<u32> = Array::with_max_entries(1, 0);

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

/// Test a `DP_CONFIG[0]` datapath-config bit (e.g. `DPC_L3_ONLY`).
#[inline(always)]
fn dpc(flag: u32) -> bool {
    matches!(DP_CONFIG.get(0), Some(w) if *w & flag != 0)
}
#[map]
static NEXTHOPS: HashMap<u32, NextHop> = HashMap::with_max_entries(4096, 0);
/// Links whose carrier/admin state is down (ifindex present = down), written
/// by the user-space link monitor. `resolve_nh` consults it to fail over to a
/// nexthop's `backup_id` (TI-LFA fast-reroute) within the monitor's latency.
#[map]
static LINK_DOWN: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);
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
/// EVPN BUM ingress-replication slots: a per-remote-PE veth pair whose A end
/// sits in the bridge domain's flood list (TC `clone_redirect` gives the
/// per-copy fan-out) and whose B end encapsulates the arriving copy toward
/// this slot's remote PE — MAC-in-SRv6 to an `End.DT2M` SID or VXLAN to a
/// VTEP, per the [`ReplTarget`] kind. Keyed by ifindex with BOTH ends
/// inserted — the A end so `flood()` can exclude slots on overlay-received
/// frames (EVPN split horizon), the B end for the encap lookup in `try_xdp`.
#[map]
static REPL_SID: HashMap<u32, ReplTarget> = HashMap::with_max_entries(256, 0);
/// RFC 9524 Replication segments, keyed by the local `End.Replicate` SID. The
/// value ([`ReplSeg`]) holds the downstream branch list; the TC stage clones
/// the packet to each branch (the XDP stage can't `bpf_clone_redirect`), sets
/// the outer IPv6 DA to the branch's downstream Replication-SID, and forwards
/// each copy over the underlay — a Bud also delivers one locally.
#[map]
static REPL_SEG: HashMap<[u8; 16], ReplSeg> = HashMap::with_max_entries(256, 0);
/// VPWS cross-connect (EVPN E-Line, RFC 8214): AC ingress ifindex → the
/// remote End.DX2/DX2V service SID. Every frame arriving on a bound AC is
/// MAC-in-SRv6 encapsulated toward the SID — no FDB, no learning.
#[map]
static XCONNECT: HashMap<u32, [u8; 16]> = HashMap::with_max_entries(256, 0);
/// VLAN-scoped VPWS cross-connect (RFC 8214 VLAN-based E-Line): (AC ingress
/// ifindex as `table`, 802.1Q VID) → the remote End.DX2V service SID. Only
/// tagged frames with that VID enter the cross-connect; the tag rides
/// inside the encapsulation and the remote End.DX2V demuxes on it.
#[map]
static XCONNECT_VLAN: HashMap<Dx2vKey, [u8; 16]> = HashMap::with_max_entries(1024, 0);
/// End.DX2V VLAN table: (SID's table id, inner 802.1Q VID) → AC ifindex.
#[map]
static DX2V: HashMap<Dx2vKey, u32> = HashMap::with_max_entries(1024, 0);
/// Egress-protection mirror contexts (`End.M`): the protected egress PE's
/// SID space, scoped by context id — how the protector reproduces the
/// failed PE's decap behavior. Keyed like `FIB6_VRF` (`prefix_len =
/// 32 + route_len`).
#[map]
static MIRROR: LpmTrie<MirrorKey, MirrorEntry> = LpmTrie::with_max_entries(1024, 0);
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

/// Session affinity (`sessionAffinity: ClientIP`): a client's chosen backend
/// slot per service, so new flows from the same client stick to it.
#[map]
static AFFINITY: LruHashMap<AffinityKey, AffinityVal> = LruHashMap::with_max_entries(65536, 0);

/// Hubble flow events (docs/design/hubble.md): a verdict record per forwarded
/// or dropped IPv4 flow, drained + enriched in user space and served over the
/// Hubble Observer gRPC API. 4 MiB ring (best-effort; a full ring drops
/// records rather than blocking the datapath).
#[map]
static FLOWS: RingBuf = RingBuf::with_byte_size(1 << 22, 0);

// --- network policy (docs/design/policy.md) ---
/// Peer `(vrf, IPv4)` → identity. Miss = `CIDR_ID` LPM, then world.
#[map]
static IDENTITY: HashMap<VrfIdKey, u32> = HashMap::with_max_entries(65536, 0);
/// Peer CIDR → identity, consulted on `IDENTITY` miss (ipBlock peers; an
/// `except` prefix is a more-specific entry mapping back to world).
#[map]
static CIDR_ID: LpmTrie<Vrf4Key, u32> = LpmTrie::with_max_entries(4096, 0);
/// Peer IPv6 → identity (v6 sibling of `IDENTITY`).
#[map]
static IDENTITY6: HashMap<VrfId6Key, u32> = HashMap::with_max_entries(65536, 0);
/// Peer IPv6 CIDR → identity (v6 sibling of `CIDR_ID`).
#[map]
static CIDR_ID6: LpmTrie<Vrf6Key, u32> = LpmTrie::with_max_entries(4096, 0);
/// Enforced endpoints: host-veth ifindex → `EP_F_*` direction bits.
/// Miss = default-allow.
#[map]
static EP_POLICY: HashMap<u32, u8> = HashMap::with_max_entries(4096, 0);
/// Allow rules; present = allow (wildcard fallback in `policy_denied`).
#[map]
static POLICY: HashMap<PolicyKey, u8> = HashMap::with_max_entries(65536, 0);
/// Policy conntrack (`PCT_*` values): recorded flows whose replies bypass
/// the reverse direction's rules.
#[map]
static PCT: LruHashMap<CtKey, u8> = LruHashMap::with_max_entries(65536, 0);
/// v6 policy conntrack (v6 sibling of `PCT`).
#[map]
static PCT6: LruHashMap<CtKey6, u8> = LruHashMap::with_max_entries(65536, 0);
/// `CIDR_ID6` LPM key with public layout (aya's `Key` fields are private);
/// pointer-cast to `Key<[u8; 16]>` — same `#[repr(C)]` shape.
#[repr(C)]
struct Lpm6 {
    prefix_len: u32,
    vrf_id: u32,
    data: [u8; 16],
}

/// `CIDR_ID` (v4) LPM key with public layout — see `Lpm6`.
#[repr(C)]
struct Lpm4 {
    prefix_len: u32,
    vrf_id: u32,
    data: [u8; 4],
}

/// Policy scratch: the v6 reply-lookup `CtKey6`, both CIDR LPM keys, and
/// the v4 reply/track `CtKey` — everything the policy code would otherwise
/// hold on the stack. `cradle_tc`'s flattened frame must stay ≤ 448 bytes:
/// the verifier's call-chain budget is 512 with 32 bytes charged each for
/// the entry stub and the compiler-emitted `memset`.
#[repr(C)]
struct PolicyScratch6 {
    key: CtKey6,
    lpm: Lpm6,
    /// v6 exact-identity key (`IDENTITY6`), VRF-scoped.
    id6key: VrfId6Key,
    key4: CtKey,
    lpm4: Lpm4,
    /// The peer identity the last `policy_denied*` resolved — read by the
    /// verdict emitters for Hubble policy-verdict flows.
    peer_id: u32,
    /// `l2_xmit`'s v6 neighbor key — not policy state, but its 20 bytes sit
    /// at the bottom of the same over-budget frame; scratch use is strictly
    /// sequential within one invocation (policy verdict, then transmit).
    neigh6: Neigh6Key,
}

/// Most-specific-first policy probe patterns (`policy_denied*`): bit0 = any
/// identity, bit1 = any proto, bit2 = any port. Static so the iteration
/// reads .rodata, not a stack array.
static POLICY_PATS: [u8; 6] = [0, 4, 6, 1, 5, 7];

/// Load a v6 address from the packet straight into (per-CPU) map memory
/// with a *constant* length — `TcContext::load_bytes` computes a bounded
/// length the verifier can't prove non-zero ("invalid zero-sized read"),
/// and a stack-side `ctx.load::<[u8; 16]>` temp is what the scratch map
/// exists to avoid.
#[inline(always)]
fn skb_load_v6(ctx: &TcContext, offset: usize, dst: &mut [u8; 16]) -> Result<(), ()> {
    let ret = unsafe {
        bpf_skb_load_bytes(
            ctx.skb.skb as *const _,
            offset as u32,
            dst.as_mut_ptr() as *mut core::ffi::c_void,
            16,
        )
    };
    if ret == 0 { Ok(()) } else { Err(()) }
}

/// Per-CPU scratch for the v6 policy keys: `cradle_tc`'s flattened frame is
/// ~430 bytes, so a bpf2bpf callee has ~80 bytes of the kernel's 512-byte
/// combined call-chain budget — a 40-byte `CtKey6` and a 20-byte LPM key
/// must live off-stack (docs/design/tailcall-vs-monolithic.md, the Vinbero
/// scratch-ctx pattern).
#[map]
static POL6_SCRATCH: PerCpuArray<PolicyScratch6> = PerCpuArray::with_max_entries(1, 0);

// --- egress masquerade (docs/design/kube-proxy-dualstack.md, K2) ---
/// `[0]` = this node's uplink IPv4 (map-encoded); 0 = masquerade disabled.
#[map]
static MASQ_CFG: Array<u32> = Array::with_max_entries(1, 0);
/// CIDRs never masqueraded (pod CIDR, service CIDR, connected fabric).
#[map]
static NON_MASQ: LpmTrie<[u8; 4], u8> = LpmTrie::with_max_entries(1024, 0);
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
const ETH_P_8021Q: u16 = 0x8100; // 802.1Q tagged frame
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
/// GTP-U over UDP port (3GPP TS 29.281).
const GTP_PORT: u16 = 2152;
/// Bytes a `GTP4.E` encap pushes: outer IPv4(20) + UDP(8) + GTP-U G-PDU(8).
const GTP_ENCAP_HDR_LEN: usize = 36;
/// Offset of the inner packet in a received no-options G-PDU:
/// eth(14) + IPv4(20) + UDP(8) + GTP-U(8).
const GTP_INNER_OFF: usize = L4_OFF + 16;
/// VXLAN over UDP port (RFC 7348).
const VXLAN_PORT: u16 = 4789;
/// BFD Echo (RFC 5881 §4) and single-hop control destination ports. Echo is
/// reflected in XDP; control is only observed (expiration watchdog) and passed.
const BFD_ECHO_PORT: u16 = 3785;
const BFD_CTRL_PORT: u16 = 3784;
/// Bytes a VXLAN encap pushes: outer Eth(14) + IPv4(20) + UDP(8) + VXLAN(8).
const VXLAN_ENCAP_HDR_LEN: usize = 50;
/// Offset of the VXLAN header in a received no-options VXLAN frame.
const VXLAN_HDR_OFF: usize = L4_OFF + 8;
/// Offset of the inner Ethernet header a symmetric-IRB VXLAN L3 encap
/// reserves after the VXLAN header (via `BPF_F_ADJ_ROOM_ENCAP_L2`).
const VXLAN_L3_INNER_OFF: usize = VXLAN_HDR_OFF + 8;
/// Bytes a VXLAN L3 (symmetric-IRB) encap grows: outer IPv4(20) + UDP(8) +
/// VXLAN(8) + the reserved inner Ethernet(14). The pre-existing outer
/// Ethernet is reused (rewritten by `l2_xmit`), so this is 50, not 64.
const VXLAN_L3_GROW: usize = 20 + 8 + 8 + 14;

// `bpf_skb_adjust_room` encap-mode flags (uapi/linux/bpf.h) — not re-exported
// by aya-ebpf. Grow at the MAC layer and lay the new room out as an
// encapsulation: outer IPv4 + UDP + (our VXLAN header) + a reserved inner L2.
const BPF_F_ADJ_ROOM_ENCAP_L3_IPV4: u64 = 1 << 1;
const BPF_F_ADJ_ROOM_ENCAP_L4_UDP: u64 = 1 << 4;
/// Keep skb->csum across the grow — we write the outer headers (and a zero
/// UDP checksum) ourselves.
const BPF_F_ADJ_ROOM_NO_CSUM_RESET: u64 = 1 << 5;
const BPF_F_ADJ_ROOM_ENCAP_L2_ETH: u64 = 1 << 6;
/// Reserve `len` bytes for the inner L2 header (`BPF_ADJ_ROOM_ENCAP_L2_SHIFT`).
const fn bpf_f_adj_room_encap_l2(len: u64) -> u64 {
    len << 56
}

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

/// Egress reverse-NAT (docs/design/kube-proxy-dualstack.md, K4). A service
/// reply from a **host-network / node-local backend** is generated by the
/// node's own stack and leaves toward the client pod without ever crossing a
/// cradle ingress hook — so its source is still the backend address, never
/// rewritten back to the VIP. This clsact-egress stage catches such a packet
/// (its 5-tuple hits a reverse `CT_F_SNAT` entry keyed on the backend) and
/// applies the SNAT here. A *pod*-backed reply is already un-NATed at its own
/// veth ingress (source == VIP), so its egress lookup misses — no double-NAT.
#[classifier]
pub fn cradle_egress(ctx: TcContext) -> i32 {
    let _ = egress_reverse_snat(&ctx);
    // Ingress network policy, enforced at *delivery*: the TC egress hook of
    // the pod's host-veth sees every packet entering the pod — routed,
    // same-node, and node-originated (kubelet probes, which never traverse
    // cradle_tc) — post-NAT, so verdicts apply to the real destination.
    // Living here (not in cradle_tc) also keeps the flattened cradle_tc
    // frame inside the verifier's 512-byte call-chain stack budget
    // (docs/design/tailcall-vs-monolithic.md).
    ingress_policy(&ctx).unwrap_or(TC_ACT_PIPE as i32)
}

/// Ingress-direction policy verdict + inbound-flow tracking for an enforced
/// endpoint, keyed by the packet's egress device (`skb->ifindex` at the TC
/// egress hook = the pod's host-veth).
#[inline(always)]
fn ingress_policy(ctx: &TcContext) -> Result<i32, ()> {
    let oif = unsafe { (*ctx.skb.skb).ifindex };
    let Some(ep_flags) = EP_POLICY.get_ptr(&oif) else {
        return Ok(TC_ACT_PIPE as i32);
    };
    let ep_flags = unsafe { *ep_flags };
    // Identity scope: the endpoint port's VRF (tenants may reuse addresses).
    let vrf = match PORTS.get_ptr(&oif) {
        Some(p) => unsafe { (*p).vrf_id },
        None => 0,
    };
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    match u16::from_be(ethertype) {
        ETH_P_IP => {
            if ep_flags & EP_F_INGRESS != 0
                && policy_denied(ctx, oif, dir_gen(ep_flags, POLICY_DIR_INGRESS), vrf)
                    .unwrap_or(true)
            {
                if ep_flags & EP_F_AUDIT != 0 {
                    // Audit mode: report the verdict, forward the packet.
                    stat_inc(STAT_POLICY_AUDIT);
                    emit_flow_v4(ctx, FLOW_AUDITED, FLOW_DIR_INGRESS, oif, scratch_peer_id());
                } else {
                    stat_inc(STAT_POLICY_DROP);
                    emit_flow_v4(ctx, FLOW_DROPPED, FLOW_DIR_INGRESS, oif, scratch_peer_id());
                    return Ok(TC_ACT_SHOT as i32);
                }
            }
            // Egress statefulness: record the admitted inbound flow so the
            // pod's replies bypass its egress rules.
            if ep_flags & EP_F_EGRESS != 0 {
                let _ = pct_track(ctx, PCT_INBOUND);
            }
        }
        ETH_P_IPV6 => {
            if ep_flags & EP_F_INGRESS != 0
                && policy_denied_v6(ctx, oif, dir_gen(ep_flags, POLICY_DIR_INGRESS), vrf)
                    .unwrap_or(true)
            {
                if ep_flags & EP_F_AUDIT != 0 {
                    stat_inc(STAT_POLICY_AUDIT);
                } else {
                    stat_inc(STAT_POLICY_DROP);
                    return Ok(TC_ACT_SHOT as i32);
                }
            }
            if ep_flags & EP_F_EGRESS != 0 {
                let _ = pct_track6(ctx, PCT_INBOUND);
            }
        }
        _ => {}
    }
    Ok(TC_ACT_PIPE as i32)
}

#[inline(always)]
fn egress_reverse_snat(ctx: &TcContext) -> Result<(), ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    if u16::from_be(ethertype) != ETH_P_IP {
        return Ok(());
    }
    let ver_ihl: u8 = ctx.load(IP_VER_IHL_OFF).map_err(|_| ())?;
    if ver_ihl & 0x0f != 5 {
        return Ok(());
    }
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Ok(());
    }
    let src: u32 = ctx.load(IP_SRC_OFF).map_err(|_| ())?;
    let dst: u32 = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    let sport: u16 = ctx.load(L4_OFF).map_err(|_| ())?;
    let dport: u16 = ctx.load(L4_OFF + 2).map_err(|_| ())?;
    let key = CtKey {
        src,
        dst,
        src_port: sport,
        dst_port: dport,
        proto,
        _pad: [0; 3],
    };
    if let Some(ct) = CT.get_ptr(&key) {
        let ct = unsafe { *ct };
        if ct.flags & CT_F_SNAT != 0 {
            snat(ctx, proto, src, sport, ct.rev_addr, ct.rev_port)?;
        }
    }
    Ok(())
}

#[inline(always)]
fn ingress_ifindex(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).ingress_ifindex }
}

/// Bump a per-CPU datapath counter (best-effort; never affects forwarding).
#[inline(always)]
fn meta_cookie() -> u32 {
    match META_COOKIE.get(0) {
        Some(c) => *c,
        None => 0,
    }
}

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
    // An SRv6 `End.DT2U` decap in the XDP stage tagged the frame with its
    // bridge domain: switch the inner Ethernet frame in that domain, whatever
    // the (underlay) port's own type is.
    // VPWS egress (End.DX2/DX2V): XDP decapped and pinned the AC — emit
    // the Ethernet frame raw, no bridge, no MAC rewrite. An inner 802.1Q
    // tag needs no help here: the kernel RX path pops it into skb vlan
    // metadata (acceleration) between the XDP decap and this hook, and
    // the metadata tag rides the redirect onto the AC intact — do NOT
    // bpf_skb_vlan_push it (the helper re-inlines the metadata tag AND
    // re-sets the metadata: the CE would receive a double tag).
    let dx2_oif = tc_meta_dx2(ctx);
    if dx2_oif != 0 {
        return Ok(unsafe { bpf_redirect(dx2_oif, 0) } as i32);
    }
    if let Some(bd) = tc_meta_l2(ctx) {
        return l2_switch(ctx, iif, bd, true);
    }
    // End.Replicate (RFC 9524): the XDP stage matched a local Replication SID
    // and tagged the (still-encapped) frame; fan it out to the segment's
    // downstream branches — the clone the XDP stage couldn't make.
    if tc_meta_repl(ctx) {
        return srv6_replicate(ctx);
    }
    let port: PortConfig = match PORTS.get_ptr(&iif) {
        Some(p) => unsafe { *p },
        None => return Ok(TC_ACT_PIPE as i32),
    };

    if port.flags & PORT_F_L2 != 0 {
        l2_switch(ctx, iif, port.vlan, false)
    } else if port.flags & PORT_F_L3 != 0 {
        // Single-hook benchmark mode (`--ebpf-mode tc-only`): skip the L7 / NAT
        // / conntrack / egress-policy stages and forward plain IPv4 only, so
        // cradle_tc's per-packet cost is comparable to the xdp-only fast path.
        // Kept as ONE `l3_forward` call site: it is `#[inline(always)]`, and a
        // second inlined copy blows the near-budget cradle_tc verifier stack.
        let from_ep = if dpc(DPC_L3_ONLY) {
            0
        } else {
            // L7: a TCP flow to an L7-marked VIP is steered to the user-space
            // transparent proxy via bpf_sk_assign (TC_ACT_OK = deliver locally).
            if let Some(act) = l7_redirect(ctx) {
                return Ok(act);
            }
            // Pod egress: track the pre-NAT flow so replies pass ingress policy.
            let masq_src = port.flags & PORT_F_ENDPOINT != 0;
            if masq_src {
                // Each tracker no-ops on the other family's ethertype.
                let _ = pct_track(ctx, PCT_POD_INITIATED);
                let _ = pct_track6(ctx, PCT_POD_INITIATED);
            }
            // L4 NAT is a best-effort pre-routing stage; it rewrites the packet
            // in place (service DNAT / reverse SNAT / egress masquerade) so
            // routing then targets the real endpoint. Failures fall through.
            let _ = l4_nat(ctx, masq_src);
            // Pod egress carries the endpoint ifindex (0 = not an endpoint):
            // egress policy enforcement point and the Hubble direction hint.
            if masq_src { iif } else { 0 }
        };
        l3_forward(ctx, port.vrf_id, from_ep)
    } else {
        Ok(TC_ACT_PIPE as i32)
    }
}

// ============================== L2 switching ===============================

/// Bridge a frame in domain `vlan`. `from_overlay` marks a frame that arrived
/// encapsulated (the `End.DT2U`/`End.DT2M` decap path): its source MAC is a
/// remote station reachable over the overlay, not on the underlay port it
/// arrived through — learning it there would blackhole the return path — and
/// flooding it back toward the overlay's replication slots would loop it
/// (EVPN split horizon), so both are suppressed.
#[inline(always)]
fn l2_switch(ctx: &TcContext, iif: u32, vlan: u16, from_overlay: bool) -> Result<i32, ()> {
    let dst: [u8; 6] = ctx.load(ETH_DST_OFF).map_err(|_| ())?;

    if !from_overlay {
        let src: [u8; 6] = ctx.load(ETH_SRC_OFF).map_err(|_| ())?;
        let _ = FDB.insert(
            &FdbKey { mac: src, vlan },
            &FdbEntry {
                oif: iif,
                flags: 0,
                remote_sid: [0; 16],
                last_seen: unsafe { bpf_ktime_get_ns() },
            },
            0,
        );
    }

    if dst[0] & 0x01 != 0 {
        return Ok(flood(ctx, iif, vlan, from_overlay)); // broadcast / multicast
    }

    match FDB.get_ptr(&FdbKey { mac: dst, vlan }) {
        Some(e) => {
            // Remote (overlay) MACs are encapsulated in the XDP stage; if one
            // reaches TC (XDP not attached, or a race) flood rather than
            // redirect to the fake oif that holds the nexthop id.
            if unsafe { (*e).flags } & FDB_F_REMOTE != 0 {
                return Ok(flood(ctx, iif, vlan, from_overlay));
            }
            let oif = unsafe { (*e).oif };
            if oif == iif {
                Ok(TC_ACT_SHOT as i32) // hairpin to the same port
            } else {
                stat_inc(STAT_L2_FORWARD);
                Ok(unsafe { bpf_redirect(oif, 0) } as i32)
            }
        }
        None => Ok(flood(ctx, iif, vlan, from_overlay)),
    }
}

/// Clone the frame to every member of `vlan` except the ingress port.
/// `local_only` additionally skips BUM replication slots (members present in
/// `REPL_SID`) — EVPN split horizon: a frame that already crossed the overlay
/// must never be flooded back into it.
#[inline(always)]
fn flood(ctx: &TcContext, iif: u32, vlan: u16, local_only: bool) -> i32 {
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
            if oif != iif && !(local_only && REPL_SID.get_ptr(&oif).is_some()) {
                let _ = ctx.clone_redirect(oif, 0);
            }
        }
        slot += 1;
    }
    TC_ACT_SHOT as i32
}

// ================================ L4 NAT ===================================

#[inline(always)]
fn l4_nat(ctx: &TcContext, masq_src: bool) -> Result<(), ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    match u16::from_be(ethertype) {
        ETH_P_IP => l4_nat_v4(ctx, masq_src),
        ETH_P_IPV6 => l4_nat_v6(ctx), // v6 masquerade is a K-arc follow-on
        _ => Ok(()),
    }
}

// ============================ network policy ===============================

/// Record a flow 5-tuple in `PCT` — Kubernetes policy is stateful, so a
/// recorded flow's replies bypass the reverse direction's rules. Called with
/// `PCT_POD_INITIATED` on `PORT_F_ENDPOINT` ingress before `l4_nat` (the
/// pre-translation tuple is what the reverse-SNAT'd reply matches), and with
/// `PCT_INBOUND` at ingress delivery to an egress-enforced endpoint
/// (post-NAT: the tuple the pod's reply reverses). The key is built in the
/// `POL6_SCRATCH` per-CPU map, not on the stack — see `PolicyScratch6`.
#[inline(always)]
fn pct_track(ctx: &TcContext, val: u8) -> Result<(), ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    if u16::from_be(ethertype) != ETH_P_IP {
        return Ok(());
    }
    let ver_ihl: u8 = ctx.load(IP_VER_IHL_OFF).map_err(|_| ())?;
    if ver_ihl & 0x0f != 5 {
        return Ok(());
    }
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Ok(());
    }
    let s = POL6_SCRATCH.get_ptr_mut(0).ok_or(())?;
    unsafe {
        let k4 = &mut (*s).key4;
        k4.src = ctx.load(IP_SRC_OFF).map_err(|_| ())?;
        k4.dst = ctx.load(IP_DST_OFF).map_err(|_| ())?;
        k4.src_port = ctx.load(L4_OFF).map_err(|_| ())?;
        k4.dst_port = ctx.load(L4_OFF + 2).map_err(|_| ())?;
        k4.proto = proto;
        k4._pad = [0; 3];
        let _ = PCT.insert(&(*s).key4, &val, 0);
    }
    Ok(())
}

/// v6 sibling of `pct_track`: record a flow 5-tuple in `PCT6`. Base IPv6
/// header only (no extension headers), like the rest of the v6 datapath.
/// Key built in `POL6_SCRATCH`, addresses loaded with `skb_load_v6`.
#[inline(always)]
fn pct_track6(ctx: &TcContext, val: u8) -> Result<(), ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    if u16::from_be(ethertype) != ETH_P_IPV6 {
        return Ok(());
    }
    let proto: u8 = ctx.load(IP6_NEXTHDR_OFF).map_err(|_| ())?;
    if proto != IPPROTO_TCP && proto != IPPROTO_UDP {
        return Ok(());
    }
    let s = POL6_SCRATCH.get_ptr_mut(0).ok_or(())?;
    unsafe {
        let key = &mut (*s).key;
        skb_load_v6(ctx, IP6_SRC_OFF, &mut key.src)?;
        skb_load_v6(ctx, IP6_DST_OFF, &mut key.dst)?;
        key.src_port = ctx.load(IP6_L4_OFF).map_err(|_| ())?;
        key.dst_port = ctx.load(IP6_L4_OFF + 2).map_err(|_| ())?;
        key.proto = proto;
        key._pad = [0; 3];
        let _ = PCT6.insert(&(*s).key, &val, 0);
    }
    Ok(())
}

/// The peer identity resolved by the last `policy_denied*` call (0 when
/// the scratch is unavailable).
#[inline(always)]
fn scratch_peer_id() -> u32 {
    match POL6_SCRATCH.get_ptr_mut(0) {
        Some(s) => unsafe { (*s).peer_id },
        None => 0,
    }
}

/// The `PolicyKey.dir` byte for an enforcement check: the direction bit
/// plus the endpoint's active A/B generation (`EP_F_GEN` → `POLICY_KEY_GEN`).
#[inline(always)]
fn dir_gen(ep_flags: u8, dir: u8) -> u8 {
    dir | if ep_flags & EP_F_GEN != 0 {
        POLICY_KEY_GEN
    } else {
        0
    }
}

/// v6 sibling of `policy_denied` — same `POLICY` rules (identities are
/// address-family-agnostic), v6 peer resolution and conntrack.
///
/// `inline(never)` + `PCT6_KEY` scratch (see `pct_track6`): the reversed
/// reply-lookup tuple is built in per-CPU map memory, the peer address is
/// read back out of it, and the six wildcard probes are built from scalars
/// — no `CtKey6` or probe array on the stack.
#[inline(always)]
fn policy_denied_v6(ctx: &TcContext, ep: u32, dir: u8, vrf: u32) -> Result<bool, ()> {
    let proto: u8 = ctx.load(IP6_NEXTHDR_OFF).map_err(|_| ())?;
    let (sport, dport) = if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
        (
            ctx.load::<u16>(IP6_L4_OFF).map_err(|_| ())?,
            ctx.load::<u16>(IP6_L4_OFF + 2).map_err(|_| ())?,
        )
    } else {
        (0, 0)
    };

    let s = POL6_SCRATCH.get_ptr_mut(0).ok_or(())?;
    unsafe {
        let key = &mut (*s).key;
        // Reversed tuple: a hit = reply to a flow recorded oppositely.
        skb_load_v6(ctx, IP6_DST_OFF, &mut key.src)?;
        skb_load_v6(ctx, IP6_SRC_OFF, &mut key.dst)?;
        key.src_port = dport;
        key.dst_port = sport;
        key.proto = proto;
        key._pad = [0; 3];
        if PCT6.get_ptr(&(*s).key).is_some() {
            return Ok(false);
        }

        // The peer in the *reversed* key: egress peer = packet dst = key.src;
        // ingress peer = packet src = key.dst.
        // Mask the generation bit — `dir` carries `POLICY_KEY_GEN` too.
        let peer: *const [u8; 16] = if dir & POLICY_DIR_EGRESS != 0 {
            &(*s).key.src
        } else {
            &(*s).key.dst
        };
        (*s).id6key.vrf_id = vrf;
        core::ptr::copy_nonoverlapping(peer as *const u8, (*s).id6key.addr.as_mut_ptr(), 16);
        let identity = match IDENTITY6.get(&(*s).id6key) {
            Some(id) => *id,
            None => {
                (*s).lpm.prefix_len = 32 + 128;
                (*s).lpm.vrf_id = vrf;
                core::ptr::copy_nonoverlapping(peer as *const u8, (*s).lpm.data.as_mut_ptr(), 16);
                let lpm = core::ptr::addr_of!((*s).lpm) as *const Key<Vrf6Key>;
                match CIDR_ID6.get(&*lpm) {
                    Some(&id) => id,
                    None => IDENTITY_WORLD,
                }
            }
        };
        (*s).peer_id = identity;
        // Walk every pattern: a deny at any specificity wins over any allow
        // (Cilium deny semantics), so no early exit on allow.
        let mut allowed = false;
        for &pat in POLICY_PATS.iter() {
            let k = PolicyKey {
                ep,
                identity: if pat & 1 != 0 { 0 } else { identity },
                port: if pat & 4 != 0 { 0 } else { dport },
                proto: if pat & 2 != 0 { 0 } else { proto },
                dir,
            };
            if let Some(v) = POLICY.get_ptr(&k) {
                if *v == POLICY_DENY {
                    return Ok(true);
                }
                allowed = true;
            }
        }
        Ok(!allowed)
    }
}

/// Policy verdict for the enforced endpoint veth `ep`: false = allow.
/// `dir` selects the rule direction and which address is the peer: ingress
/// checks the packet's source identity (packet delivered to the pod), egress
/// checks its destination identity (packet initiated by the pod). Allows
/// replies to flows recorded in the opposite direction (`PCT` reverse hit),
/// then probes `POLICY` most-specific-first with wildcard fallback
/// (identity/proto/port each 0 = any). Runs post-NAT, so verdicts apply to
/// the real peer, not a service VIP.
///
#[inline(always)]
fn policy_denied(ctx: &TcContext, ep: u32, dir: u8, vrf: u32) -> Result<bool, ()> {
    let proto: u8 = ctx.load(IP_PROTO_OFF).map_err(|_| ())?;
    let src: u32 = ctx.load(IP_SRC_OFF).map_err(|_| ())?;
    let dst: u32 = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    let ver_ihl: u8 = ctx.load(IP_VER_IHL_OFF).map_err(|_| ())?;
    let (sport, dport) = if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && ver_ihl & 0x0f == 5 {
        (
            ctx.load::<u16>(L4_OFF).map_err(|_| ())?,
            ctx.load::<u16>(L4_OFF + 2).map_err(|_| ())?,
        )
    } else {
        (0, 0)
    };

    // Reply to a flow recorded in the opposite direction? (Ingress: the pod
    // initiated it. Egress: it was admitted inbound.) Reversed key built in
    // scratch — see `PolicyScratch6`.
    let s = POL6_SCRATCH.get_ptr_mut(0).ok_or(())?;
    unsafe {
        let k4 = &mut (*s).key4;
        k4.src = dst;
        k4.dst = src;
        k4.src_port = dport;
        k4.dst_port = sport;
        k4.proto = proto;
        k4._pad = [0; 3];
        if PCT.get_ptr(&(*s).key4).is_some() {
            return Ok(false);
        }
    }

    // The peer whose identity the rules match: the remote end of the flow.
    // Exact (pod/node) binding first, then the CIDR LPM (ipBlock peers);
    // the LPM key is built in scratch.
    // Mask the generation bit — `dir` carries `POLICY_KEY_GEN` too.
    let peer = if dir & POLICY_DIR_EGRESS != 0 {
        dst
    } else {
        src
    };
    let identity = match unsafe {
        IDENTITY.get(&VrfIdKey {
            vrf_id: vrf,
            addr: peer,
        })
    } {
        Some(id) => *id,
        None => unsafe {
            (*s).lpm4.prefix_len = 32 + 32;
            (*s).lpm4.vrf_id = vrf;
            (*s).lpm4.data = peer.to_ne_bytes();
            let lpm = core::ptr::addr_of!((*s).lpm4) as *const Key<Vrf4Key>;
            match CIDR_ID.get(&*lpm) {
                Some(&id) => id,
                None => IDENTITY_WORLD,
            }
        },
    };
    unsafe { (*s).peer_id = identity };
    // Walk every pattern, keys built from scalars (no probe array on the
    // stack). A deny at any specificity wins over any allow (Cilium deny
    // semantics), so no early exit on allow.
    let mut allowed = false;
    for &pat in POLICY_PATS.iter() {
        let k = PolicyKey {
            ep,
            identity: if pat & 1 != 0 { 0 } else { identity },
            port: if pat & 4 != 0 { 0 } else { dport },
            proto: if pat & 2 != 0 { 0 } else { proto },
            dir,
        };
        if let Some(v) = POLICY.get_ptr(&k) {
            if unsafe { *v } == POLICY_DENY {
                return Ok(true);
            }
            allowed = true;
        }
    }
    Ok(!allowed)
}

/// Egress masquerade (docs/design/kube-proxy-dualstack.md, K2): a new pod
/// flow (`masq_src`) to a destination outside the cluster is SNAT'd to the
/// node's uplink IP (source port preserved). Two CT entries fold the reverse
/// into the existing `l4_nat` established branch: the reply arriving on the
/// uplink un-DNATs back to the pod, and a retransmit re-SNATs identically.
/// `dst` in a `NON_MASQ` CIDR (pod/service/fabric) is left untouched.
#[inline(always)]
fn masq_v4(
    ctx: &TcContext,
    masq_src: bool,
    src_ip: u32,
    dst_ip: u32,
    sport: u16,
    dport: u16,
    proto: u8,
) -> Result<(), ()> {
    if !masq_src {
        return Ok(());
    }
    let node = match MASQ_CFG.get(0) {
        Some(&n) if n != 0 => n,
        _ => return Ok(()), // masquerade disabled
    };
    let dst_bytes: [u8; 4] = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    if NON_MASQ.get(&Key::new(32, dst_bytes)).is_some() {
        return Ok(()); // in-cluster / fabric destination — no masquerade
    }
    let now = unsafe { bpf_ktime_get_ns() };
    // Forward: retransmits re-SNAT pod → node (source port preserved).
    let _ = CT.insert(
        &CtKey {
            src: src_ip,
            dst: dst_ip,
            src_port: sport,
            dst_port: dport,
            proto,
            _pad: [0; 3],
        },
        &CtEntry {
            rev_addr: node,
            rev_port: sport,
            flags: CT_F_SNAT,
            last_seen: now,
        },
        0,
    );
    // Reverse: the reply (ext → node:sport) DNATs back to the pod.
    let _ = CT.insert(
        &CtKey {
            src: dst_ip,
            dst: node,
            src_port: dport,
            dst_port: sport,
            proto,
            _pad: [0; 3],
        },
        &CtEntry {
            rev_addr: src_ip,
            rev_port: sport,
            flags: CT_F_DNAT,
            last_seen: now,
        },
        0,
    );
    // Hubble: masquerade is a TRANSLATED flow (pod → outside, captured before
    // the SNAT rewrites the source to the node IP).
    emit_flow_v4(ctx, FLOW_TRANSLATED, FLOW_DIR_EGRESS, 0, 0);
    snat(ctx, proto, src_ip, sport, node, sport)?;
    stat_inc(STAT_MASQ);
    Ok(())
}

/// Emit a Hubble flow event for the current IPv4 packet (best-effort). `dir`
/// is `FLOW_DIR_*`; `ep` is the local endpoint veth ifindex (0 = none, for
/// user-space enrichment). Never affects forwarding.
///
#[inline(always)]
fn emit_flow_v4(ctx: &TcContext, verdict: u8, dir: u8, ep: u32, peer_identity: u32) {
    let (Ok(saddr), Ok(daddr), Ok(proto)) = (
        ctx.load::<[u8; 4]>(IP_SRC_OFF),
        ctx.load::<[u8; 4]>(IP_DST_OFF),
        ctx.load::<u8>(IP_PROTO_OFF),
    ) else {
        return;
    };
    let ver_ihl: u8 = ctx.load(IP_VER_IHL_OFF).unwrap_or(0);
    let (sport, dport) = if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) && ver_ihl & 0x0f == 5 {
        (
            ctx.load::<u16>(L4_OFF).unwrap_or(0),
            ctx.load::<u16>(L4_OFF + 2).unwrap_or(0),
        )
    } else {
        (0, 0)
    };
    let Some(mut slot) = FLOWS.reserve::<FlowRecord>(0) else {
        return;
    };
    slot.write(FlowRecord {
        time_ns: unsafe { bpf_ktime_get_ns() },
        ep_ifindex: ep,
        saddr,
        daddr,
        sport,
        dport,
        proto,
        verdict,
        dir,
        _pad: 0,
        peer_identity,
    });
    slot.submit(0);
}

#[inline(always)]
fn l4_nat_v4(ctx: &TcContext, masq_src: bool) -> Result<(), ()> {
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
        // Not a service — masquerade a pod egress to outside the cluster.
        None => return masq_v4(ctx, masq_src, src_ip, dst_ip, sport, dport, proto),
    };
    if svc.backend_count == 0 {
        return Ok(());
    }
    let now = unsafe { bpf_ktime_get_ns() };
    // Backend pick: random, unless the service has ClientIP affinity — then
    // reuse this client's sticky slot (refreshing its timestamp) if it's live
    // and still in range, else pick fresh and record it.
    let slot = if svc.flags & SVC_F_AFFINITY != 0 {
        let akey = AffinityKey {
            svc_id: svc.svc_id,
            client: src_ip,
        };
        let sticky = match AFFINITY.get_ptr(&akey) {
            Some(a) => {
                let a = unsafe { *a };
                if now.wrapping_sub(a.last_ns) < AFFINITY_TIMEOUT_NS && a.slot < svc.backend_count {
                    Some(a.slot)
                } else {
                    None
                }
            }
            None => None,
        };
        let s = sticky.unwrap_or_else(|| {
            (unsafe { bpf_get_prandom_u32() } % svc.backend_count as u32) as u16
        });
        let _ = AFFINITY.insert(
            &akey,
            &AffinityVal {
                slot: s,
                _pad: 0,
                last_ns: now,
            },
            0,
        );
        s
    } else {
        (unsafe { bpf_get_prandom_u32() } % svc.backend_count as u32) as u16
    };
    let be = match BACKENDS.get_ptr(&BackendKey {
        svc_id: svc.svc_id,
        slot,
        _pad: 0,
    }) {
        Some(b) => unsafe { *b },
        None => return Ok(()),
    };

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

    // Hubble: a service access is a TRANSLATED flow (client → VIP, captured
    // before the DNAT rewrites the destination to the backend).
    emit_flow_v4(ctx, FLOW_TRANSLATED, FLOW_DIR_INGRESS, 0, 0);
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
    ctx.l4_csum_replace(
        csum,
        old_ip as u64,
        new_ip as u64,
        BPF_F_PSEUDO_HDR | mangled | 4,
    )
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
    ctx.l4_csum_replace(
        csum,
        old_ip as u64,
        new_ip as u64,
        BPF_F_PSEUDO_HDR | mangled | 4,
    )
    .map_err(|_| ())?;
    ctx.l4_csum_replace(csum, old_port as u64, new_port as u64, mangled | 2)
        .map_err(|_| ())?;
    ctx.store(IP_SRC_OFF, &new_ip, 0).map_err(|_| ())?;
    ctx.store(L4_OFF, &new_port, 0).map_err(|_| ())?;
    stat_inc(STAT_L4_SNAT);
    Ok(())
}

// ------------------------------ L4 IPv6 ------------------------------------

// NOTE: keep inlined — as a bpf2bpf callee its ~230-byte frame *adds* to
// the call-chain stack, while inlined its slots overlap main's existing
// budget (verified empirically; docs/design/tailcall-vs-monolithic.md).
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

/// Resolve a nexthop id into `(effective id, nexthop)`, failing over to its
/// `backup_id` when the primary's egress link is down (`LINK_DOWN`) — the
/// backup typically carries a TI-LFA SRv6 repair. The effective id matters:
/// `SRV6_ENCAP` is keyed by nexthop id, so the backup's segment list is found
/// under the backup's id.
#[inline(always)]
fn resolve_nh(nh_id: u32) -> Option<(u32, NextHop)> {
    let nh: NextHop = unsafe { *NEXTHOPS.get_ptr(&nh_id)? };
    if nh.backup_id != 0 && LINK_DOWN.get_ptr(&nh.oif).is_some() {
        let b: NextHop = unsafe { *NEXTHOPS.get_ptr(&nh.backup_id)? };
        stat_inc(STAT_NH_BACKUP);
        return Some((nh.backup_id, b));
    }
    Some((nh_id, nh))
}

#[inline(always)]
fn l3_forward(ctx: &TcContext, port_vrf: u32, from_ep: u32) -> Result<i32, ()> {
    let ethertype: u16 = ctx.load(ETH_TYPE_OFF).map_err(|_| ())?;
    match u16::from_be(ethertype) {
        ETH_P_IP => l3_forward_v4(ctx, port_vrf, from_ep),
        ETH_P_IPV6 => l3_forward_v6(ctx, port_vrf, from_ep),
        ETH_P_MPLS_UC => mpls_forward(ctx),
        _ => Ok(TC_ACT_PIPE as i32), // ARP, ... -> stack
    }
}

/// VRF context attached by the XDP MPLS stage (VPN-label decap): read from
/// the skb's `data_meta..data` window, guarded by the magic. 0 = none.
#[inline(always)]
fn tc_meta_dx2(ctx: &TcContext) -> u32 {
    let skb = ctx.skb.skb;
    let meta = unsafe { (*skb).data_meta } as usize;
    let data = unsafe { (*skb).data } as usize;
    if meta + core::mem::size_of::<CradleXdpMeta>() > data {
        return 0;
    }
    let m = meta as *const CradleXdpMeta;
    unsafe {
        if (*m).magic != XDP_META_MAGIC_DX2 ^ meta_cookie() {
            return 0;
        }
        (*m).vrf_id // the attachment-circuit ifindex
    }
}

fn tc_meta_dx(ctx: &TcContext) -> u32 {
    let skb = ctx.skb.skb;
    let meta = unsafe { (*skb).data_meta } as usize;
    let data = unsafe { (*skb).data } as usize;
    if meta + core::mem::size_of::<CradleXdpMeta>() > data {
        return 0;
    }
    let m = meta as *const CradleXdpMeta;
    unsafe {
        if (*m).magic != XDP_META_MAGIC_DX ^ meta_cookie() {
            return 0;
        }
        (*m).vrf_id // the cross-connect nexthop id
    }
}

fn tc_meta_vrf(ctx: &TcContext) -> u32 {
    let skb = ctx.skb.skb;
    let meta = unsafe { (*skb).data_meta } as usize;
    let data = unsafe { (*skb).data } as usize;
    if meta + core::mem::size_of::<CradleXdpMeta>() > data {
        return 0;
    }
    let m = meta as *const CradleXdpMeta;
    unsafe {
        if (*m).magic != XDP_META_MAGIC ^ meta_cookie() {
            return 0;
        }
        (*m).vrf_id
    }
}

/// Bridge domain attached by the XDP `End.DT2U` decap (EVPN over SRv6):
/// `Some(bd)` when the frame is a decapsulated inner Ethernet frame to switch,
/// guarded by the L2 magic. `None` for everything else.
#[inline(always)]
fn tc_meta_l2(ctx: &TcContext) -> Option<u16> {
    let skb = ctx.skb.skb;
    let meta = unsafe { (*skb).data_meta } as usize;
    let data = unsafe { (*skb).data } as usize;
    if meta + core::mem::size_of::<CradleXdpMeta>() > data {
        return None;
    }
    let m = meta as *const CradleXdpMeta;
    unsafe {
        if (*m).magic != XDP_META_MAGIC_L2 ^ meta_cookie() {
            return None;
        }
        Some((*m).vrf_id as u16)
    }
}

/// `true` when the XDP `End.Replicate` stage tagged this frame for the TC
/// clone fan-out (RFC 9524). The frame is still fully SRv6-encapped; TC
/// re-reads the outer DA to key `REPL_SEG`.
#[inline(always)]
fn tc_meta_repl(ctx: &TcContext) -> bool {
    let skb = ctx.skb.skb;
    let meta = unsafe { (*skb).data_meta } as usize;
    let data = unsafe { (*skb).data } as usize;
    if meta + core::mem::size_of::<CradleXdpMeta>() > data {
        return false;
    }
    let m = meta as *const CradleXdpMeta;
    unsafe { (*m).magic == XDP_META_MAGIC_REPL ^ meta_cookie() }
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
    let mut h = (sw[0] ^ sw[1] ^ sw[2] ^ sw[3]) ^ (dw[0] ^ dw[1] ^ dw[2] ^ dw[3]).rotate_left(16);
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
fn l3_forward_v4(ctx: &TcContext, port_vrf: u32, from_ep: u32) -> Result<i32, ()> {
    // End.DX4 hand-off — see the v6 sibling.
    let dx_nh = tc_meta_dx(ctx);
    if dx_nh != 0 {
        if let Some((_, nh)) = resolve_nh(dx_nh) {
            return l2_xmit(ctx, &nh, ETH_P_IP);
        }
        return Ok(TC_ACT_PIPE as i32);
    }

    // Egress network policy: the packet was initiated by a local enforced
    // endpoint — post-NAT (the real peer, not a service VIP), pre-FIB (the
    // verdict must not depend on route presence). docs/design/policy.md.
    if from_ep != 0 {
        if let Some(ep_flags) = EP_POLICY.get_ptr(&from_ep) {
            let ep_flags = unsafe { *ep_flags };
            if ep_flags & EP_F_EGRESS != 0
                && policy_denied(ctx, from_ep, dir_gen(ep_flags, POLICY_DIR_EGRESS), port_vrf)
                    .unwrap_or(true)
            {
                if ep_flags & EP_F_AUDIT != 0 {
                    stat_inc(STAT_POLICY_AUDIT);
                    emit_flow_v4(
                        ctx,
                        FLOW_AUDITED,
                        FLOW_DIR_EGRESS,
                        from_ep,
                        scratch_peer_id(),
                    );
                } else {
                    stat_inc(STAT_POLICY_DROP);
                    emit_flow_v4(
                        ctx,
                        FLOW_DROPPED,
                        FLOW_DIR_EGRESS,
                        from_ep,
                        scratch_peer_id(),
                    );
                    return Ok(TC_ACT_SHOT as i32);
                }
            }
        }
    }

    let dst: [u8; 4] = ctx.load(IP_DST_OFF).map_err(|_| ())?;
    // Port binding wins; else VRF context from a VPN-label decap (XDP meta).
    let vrf_id = if port_vrf != 0 {
        port_vrf
    } else {
        tc_meta_vrf(ctx)
    };
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

    let (nh_id, nh) = resolve_nh(nh_id).ok_or(())?;
    let oif = nh.oif;

    // Ingress network policy toward `oif` is enforced at delivery — the
    // veth's TC *egress* hook (`ingress_policy` in cradle_egress), which
    // also sees node-originated traffic this hook never does.

    // SRv6 imposition (H.Encaps) of a v4-inner packet: impose an outer IPv6
    // header toward the SID. Pipe-model — the inner IPv4 TTL is left as-is.
    if nh.flags & NH_F_SRV6 != 0 {
        let ttl: u8 = ctx.load(IP_TTL_OFF).map_err(|_| ())?;
        if ttl <= 1 {
            return Ok(TC_ACT_PIPE as i32);
        }
        return srv6_encap(ctx, nh_id, &nh, ETH_P_IP);
    }

    // GTP-U imposition (GTP4.E): wrap the inner v4 packet in outer IPv4 + UDP
    // (2152) + GTP-U(TEID). Tunnel/pipe model — the inner TTL is left as-is.
    if nh.flags & NH_F_GTP != 0 {
        return gtp_encap(ctx, nh_id, &nh);
    }

    // EVPN symmetric IRB: VXLAN-encapsulate the routed v4 packet toward the
    // remote PE's VTEP with an L3VNI + RMAC rewrite. Tunnel model — inner
    // TTL kept.
    if nh.flags & NH_F_VXLAN != 0 {
        return vxlan_l3_encap(ctx, nh_id, &nh, ETH_P_IP);
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
    // Hubble: a forwarded flow. Pod egress (from_ep != 0) is EGRESS; a packet
    // being delivered toward a local endpoint is INGRESS. `oif` is the local
    // endpoint veth when this is ingress-to-pod (enrichment key).
    let (dir, ep) = if from_ep != 0 {
        (FLOW_DIR_EGRESS, 0)
    } else {
        (FLOW_DIR_INGRESS, oif)
    };
    emit_flow_v4(ctx, FLOW_FORWARDED, dir, ep, 0);
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
fn l3_forward_v6(ctx: &TcContext, port_vrf: u32, from_ep: u32) -> Result<i32, ()> {
    // End.DX6 hand-off: XDP decapped and pinned the cross-connect
    // adjacency in DX metadata — forward straight to it, no FIB and no
    // hop-limit decrement (RFC 8986 §4.4 S03).
    let dx_nh = tc_meta_dx(ctx);
    if dx_nh != 0 {
        if let Some((_, nh)) = resolve_nh(dx_nh) {
            return l2_xmit(ctx, &nh, ETH_P_IPV6);
        }
        return Ok(TC_ACT_PIPE as i32);
    }

    // Egress network policy — the v4 sibling's comment applies. (No Hubble
    // flow record: v6 flow export doesn't exist yet.)
    if from_ep != 0 {
        if let Some(ep_flags) = EP_POLICY.get_ptr(&from_ep) {
            let ep_flags = unsafe { *ep_flags };
            if ep_flags & EP_F_EGRESS != 0
                && policy_denied_v6(ctx, from_ep, dir_gen(ep_flags, POLICY_DIR_EGRESS), port_vrf)
                    .unwrap_or(true)
            {
                if ep_flags & EP_F_AUDIT != 0 {
                    stat_inc(STAT_POLICY_AUDIT);
                } else {
                    stat_inc(STAT_POLICY_DROP);
                    return Ok(TC_ACT_SHOT as i32);
                }
            }
        }
    }

    let dst: [u8; 16] = ctx.load(IP6_DST_OFF).map_err(|_| ())?;

    // A local SID pre-empts the FIB (an SRv6 endpoint address is not an
    // ordinary local address). Safety net for when the XDP decap stage is
    // bypassed (generic XDP / not attached): punt so the host stack — or a
    // re-run — handles it rather than mis-forwarding by the outer DA.
    if SRV6_LOCALSID.get(Key::new(128, dst)).is_some() {
        return Ok(TC_ACT_PIPE as i32);
    }

    // Port binding wins; else VRF context from a VPN-label / SRv6 decap.
    let vrf_id = if port_vrf != 0 {
        port_vrf
    } else {
        tc_meta_vrf(ctx)
    };
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
    let (nh_id, nh) = resolve_nh(nh_id).ok_or(())?;
    let oif = nh.oif;

    // Ingress network policy toward `oif` is enforced at delivery — see the
    // v4 sibling's comment (`ingress_policy` in cradle_egress).

    // SRv6 imposition (H.Encaps): impose an outer IPv6 header toward the SID.
    if nh.flags & NH_F_SRV6 != 0 {
        let hop: u8 = ctx.load(IP6_HOP_OFF).map_err(|_| ())?;
        if hop <= 1 {
            return Ok(TC_ACT_PIPE as i32);
        }
        return srv6_encap(ctx, nh_id, &nh, ETH_P_IPV6);
    }

    // GTP-U imposition (GTP4.E): an inner v6 packet wrapped in outer IPv4 + UDP
    // (2152) + GTP-U(TEID). Tunnel/pipe model — the inner hop limit is kept.
    if nh.flags & NH_F_GTP != 0 {
        return gtp_encap(ctx, nh_id, &nh);
    }

    // EVPN symmetric IRB: VXLAN-encapsulate the routed v6 packet toward the
    // remote PE's VTEP with an L3VNI + RMAC rewrite (outer is IPv4).
    if nh.flags & NH_F_VXLAN != 0 {
        return vxlan_l3_encap(ctx, nh_id, &nh, ETH_P_IPV6);
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
    // TTL model (RFC 3443). Pipe: seed the outer label TTL with a fixed 255 so
    // the LSP hop count stays hidden from the payload. Uniform (default): seed
    // from the inner IP TTL, exposing the LSP hops end to end.
    let seed_ttl = if nh.flags & NH_F_MPLS_PIPE != 0 {
        MPLS_PIPE_TTL
    } else {
        ttl
    };
    ctx.skb
        .adjust_room((4 * n) as i32, BPF_ADJ_ROOM_MAC, 0)
        .map_err(|_| ())?;
    // Outermost first; BOS on the innermost; TC bits 0.
    for i in 0..MAX_LABELS {
        if i >= n {
            break;
        }
        let s = if i == n - 1 { 1 } else { 0 };
        let lse = mpls_lse(nh.labels[i], 0, s, seed_ttl).to_be();
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
    let Some((dst_mac, src_mac)) = tc_resolve_l2(nh) else {
        return Ok(TC_ACT_PIPE as i32); // neighbor/port miss — punt to the host
    };
    ctx.store(ETH_DST_OFF, &dst_mac, 0).map_err(|_| ())?;
    ctx.store(ETH_SRC_OFF, &src_mac, 0).map_err(|_| ())?;
    ctx.store(ETH_TYPE_OFF, &ethertype.to_be(), 0)
        .map_err(|_| ())?;
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as i32)
}

/// Resolve a nexthop's egress Ethernet header from the control-plane neighbor
/// maps: `(dst_mac, src_mac)`, or `None` on a neighbor/port miss. The
/// destination is the resolved neighbor MAC (`NEIGH6`/`NEIGH4` keyed by the
/// gateway), the source the egress port's MAC.
#[inline(always)]
fn tc_resolve_l2(nh: &NextHop) -> Option<([u8; 6], [u8; 6])> {
    let dst_mac = if nh.flags & NH_F_V6 != 0 {
        // Key built in scratch — see `PolicyScratch6::neigh6`.
        let s = POL6_SCRATCH.get_ptr_mut(0)?;
        let e = unsafe {
            (*s).neigh6.ifindex = nh.oif;
            (*s).neigh6.addr = nh.gateway_v6;
            NEIGH6.get_ptr(&(*s).neigh6)
        };
        unsafe { (*e?).mac }
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

/// `End.Replicate` (RFC 9524 §5.2): fan the frame out to the Replication
/// segment's downstream branches. The frame is still fully SRv6-encapped and
/// its outer DA is this node's Replication SID; for each branch we set the
/// outer DA to the branch's downstream Replication-SID and `bpf_clone_redirect`
/// a copy — a remote branch resolves the underlay adjacency and rewrites the
/// outer Ethernet (`repl_clone_remote`), a local (Bud) branch clones toward
/// this node's own `End.DT2M` leaf veth for local delivery. The Hop Limit is
/// decremented once (all copies inherit it) and the original skb is dropped.
/// All packet access is via skb `store`/`load` so nothing is held across a
/// clone (which invalidates packet pointers); the `REPL_SEG` value is map
/// memory, so the borrow survives the clones.
#[inline(always)]
fn srv6_replicate(ctx: &TcContext) -> Result<i32, ()> {
    let da: [u8; 16] = ctx.load(IP6_DST_OFF).map_err(|_| ())?;
    let rs: &ReplSeg = match REPL_SEG.get_ptr(&da) {
        Some(r) => unsafe { &*r },
        None => return Ok(TC_ACT_SHOT as i32), // no state — RFC: discard
    };
    // RFC 9524 Hop-Limit checks, then one decrement shared by every copy.
    let hl: u8 = ctx.load(IP6_HOP_OFF).map_err(|_| ())?;
    if hl <= 1 || hl < rs.hop_limit_threshold {
        return Ok(TC_ACT_SHOT as i32);
    }
    ctx.store(IP6_HOP_OFF, &(hl - 1), 0).map_err(|_| ())?;

    // Opaque bound so the verifier keeps the constant `MAX_REPL_BRANCHES`
    // latch across the map-value walk (see `apply_hencap`).
    let n = core::hint::black_box(rs.n_branches);
    let mut slot: usize = 0;
    while slot < MAX_REPL_BRANCHES {
        if slot as u32 >= n {
            break;
        }
        let br: &ReplBranch = &rs.branches[slot];
        // Steer this copy: outer DA = the branch's downstream Replication-SID.
        ctx.store(IP6_DST_OFF, &br.sid, 0).map_err(|_| ())?;
        if br.flags & REPL_BRANCH_LOCAL != 0 {
            // Bud local delivery: clone toward the leaf veth, whose peer XDP
            // `End.DT2M`-decaps `br.sid` into the bridge domain. No underlay
            // resolution / Ethernet rewrite (it is a local veth).
            let _ = ctx.clone_redirect(br.local_oif, 0);
        } else {
            let _ = repl_clone_remote(ctx, br);
        }
        slot += 1;
    }
    stat_inc(STAT_SRV6_REPLICATE);
    Ok(TC_ACT_SHOT as i32) // original consumed; copies already sent
}

/// Forward one remote `End.Replicate` branch: resolve the underlay adjacency
/// (an explicit `nexthop_id`, or a FIB6 lookup on the branch SID — the IGP
/// locator route, as `l2_srv6_encap` does), rewrite the outer Ethernet toward
/// it, and `bpf_clone_redirect` one copy out. The caller has already set the
/// outer IPv6 DA to `br.sid`.
#[inline(always)]
fn repl_clone_remote(ctx: &TcContext, br: &ReplBranch) -> Result<(), ()> {
    let nh_id = if br.nexthop_id != 0 {
        br.nexthop_id
    } else {
        let fib = fib6_lookup(0, br.sid).ok_or(())?;
        if fib.flags & (FIB_F_ECMP | FIB_F_BLACKHOLE | FIB_F_LOCAL) != 0 {
            return Err(()); // ECMP/odd shapes: skip (MVP)
        }
        fib.nexthop_id
    };
    let (_, nh) = resolve_nh(nh_id).ok_or(())?;
    let (dst_mac, src_mac) = tc_resolve_l2(&nh).ok_or(())?;
    ctx.store(ETH_DST_OFF, &dst_mac, 0).map_err(|_| ())?;
    ctx.store(ETH_SRC_OFF, &src_mac, 0).map_err(|_| ())?;
    ctx.store(ETH_TYPE_OFF, &(ETH_P_IPV6 as u16).to_be(), 0)
        .map_err(|_| ())?;
    let _ = ctx.clone_redirect(nh.oif, 0);
    Ok(())
}

// =============================== SRv6 encap =================================

const IP6_HDR_LEN: usize = 40;
const IP6_PAYLOAD_LEN_OFF: usize = EthHdr::LEN + 4;
const IP6_VER_TC_FL: u32 = 0x6000_0000; // version 6, TC 0, flow-label 0
const IPPROTO_IPIP: u8 = 4; // inner IPv4
const IPPROTO_IPV6: u8 = 41; // inner IPv6
const IPPROTO_ROUTING: u8 = 43; // IPv6 Routing header (SRH is type 4)
const IPPROTO_ETHERNET: u8 = 143; // inner Ethernet frame (EVPN over SRv6)
/// SRH offsets relative to the outer IPv6 header start (`EthHdr::LEN`).
const SRH_OFF: usize = EthHdr::LEN + IP6_HDR_LEN; // outer SRH start
const SRH_SL_OFF: usize = SRH_OFF + 3; // Segments Left byte
const SRH_LAST_ENTRY_OFF: usize = SRH_OFF + 4; // Last Entry byte
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
    // Read through the map pointer — a stack copy is ~104 bytes and two
    // encap layers would blow the 512-byte stack.
    let enc: &Srv6Encap = match SRV6_ENCAP.get_ptr(&nh_id) {
        Some(e) => unsafe { &*e },
        None => return Ok(TC_ACT_PIPE as i32),
    };
    let n = enc.num_segs as usize;
    if n == 0 || n > MAX_SEGS {
        return Ok(TC_ACT_PIPE as i32);
    }
    if enc.mode == SRV6_ENCAP_MODE_INSERT {
        // H.Insert only applies to IPv6 (there is no header to insert into
        // otherwise); non-v6 punts to the stack.
        if inner_ethertype != ETH_P_IPV6 {
            return Ok(TC_ACT_PIPE as i32);
        }
        return srv6_insert(ctx, enc, nh);
    }
    if apply_hencap(ctx, enc, inner_ethertype)?.is_some() {
        return Ok(TC_ACT_PIPE as i32);
    }
    stat_inc(STAT_SRV6_ENCAP);

    // Kernel-parity post-encap lookup (`seg6_lookup_nexthop`): when the new
    // outer DA itself resolves to an H.Encaps route — the egress-protection
    // retained repair steering a dead egress's locator to the protector's
    // Mirror SID (End.M) — stack the second layer and leave via that route's
    // own nexthop. A plain (or absent) resolution keeps the member's own
    // (gw, oif), so ordinary single-layer encaps are untouched.
    if let Some(fib) = fib6_lookup(0, enc.segs[0]) {
        if fib.flags & (FIB_F_LOCAL | FIB_F_BLACKHOLE | FIB_F_ECMP) == 0 {
            if let Some((nh2_id, nh2)) = resolve_nh(fib.nexthop_id) {
                if nh2.flags & NH_F_SRV6 != 0 {
                    if let Some(e2) = SRV6_ENCAP.get_ptr(&nh2_id) {
                        let enc2: &Srv6Encap = unsafe { &*e2 };
                        let n2 = enc2.num_segs as usize;
                        if enc2.mode != SRV6_ENCAP_MODE_INSERT
                            && n2 >= 1
                            && n2 <= MAX_SEGS
                            && apply_hencap(ctx, enc2, ETH_P_IPV6)?.is_none()
                        {
                            stat_inc(STAT_SRV6_ENCAP);
                            return l2_xmit(ctx, &nh2, ETH_P_IPV6);
                        }
                    }
                }
            }
        }
    }
    l2_xmit(ctx, nh, ETH_P_IPV6)
}

/// Write one H.Encaps layer: grow room at the MAC boundary and store the
/// outer IPv6 header (DA = `segs[0]`) plus, for multi-SID lists, the SRH
/// carrying `segs[1..]` reversed. Returns `Ok(Some(action))` when the caller
/// should bail with that TC action (unresolvable encap source), `Ok(None)`
/// once the layer is written. Factored out of `srv6_encap` so the
/// egress-protection path can stack a second layer.
#[inline(always)]
fn apply_hencap(ctx: &TcContext, enc: &Srv6Encap, inner_ethertype: u16) -> Result<Option<i32>, ()> {
    let n = enc.num_segs as usize;
    if n == 0 || n > MAX_SEGS {
        return Ok(Some(TC_ACT_PIPE as i32));
    }
    // Post-guard optimization barrier: without it LLVM knows `n <= MAX_SEGS`
    // (from the branch above) and rotates the segment loop into a pointer
    // induction bounded only by an `n`-derived counter — whose range the
    // verifier loses across the spill/reload, rejecting the map-value walk.
    // An opaque `n` forces the loop's constant `MAX_SEGS` latch to survive,
    // which is exactly the bound the verifier needs. Runtime value unchanged.
    let n = core::hint::black_box(n);
    let src: [u8; 16] = match SRV6_ENCAP_SRC.get(0) {
        Some(s) => *s,
        None => return Ok(Some(TC_ACT_PIPE as i32)),
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
    ctx.store(EthHdr::LEN, &IP6_VER_TC_FL.to_be(), 0)
        .map_err(|_| ())?;
    ctx.store(IP6_PAYLOAD_LEN_OFF, &payload_len.to_be(), 0)
        .map_err(|_| ())?;
    ctx.store(IP6_NEXTHDR_OFF, &outer_nh, 0).map_err(|_| ())?;
    ctx.store(IP6_HOP_OFF, &64u8, 0).map_err(|_| ())?;
    ctx.store(IP6_SRC_OFF, &src, 0).map_err(|_| ())?;
    ctx.store(IP6_DST_OFF, &enc.segs[0], 0).map_err(|_| ())?;

    if n > 1 {
        // SRH: [next_header, hdr_ext_len, routing_type=4, segments_left,
        //       last_entry, flags, tag(2)] then the reversed segment list.
        ctx.store(SRH_OFF, &inner_proto, 0).map_err(|_| ())?;
        ctx.store(SRH_OFF + 1, &(2 * (n as u8 - 1)), 0)
            .map_err(|_| ())?; // hdr_ext_len
        ctx.store(SRH_OFF + 2, &4u8, 0).map_err(|_| ())?; // routing type 4 = SRH
        ctx.store(SRH_SL_OFF, &(n as u8 - 1), 0).map_err(|_| ())?; // segments_left
        ctx.store(SRH_OFF + 4, &(n as u8 - 2), 0).map_err(|_| ())?; // last_entry
        ctx.store(SRH_OFF + 5, &0u8, 0).map_err(|_| ())?; // flags
        ctx.store(SRH_OFF + 6, &0u16, 0).map_err(|_| ())?; // tag
        // Reversed list, omitting segs[0]: segment_list[n-1-j] = segs[j].
        // Indexed by the loop counter on the stack side (bounded by the
        // constant range, kept alive by the volatile `n` above); the
        // reversal rides in the skb offset, which the store helper
        // validates at runtime.
        for j in 1..MAX_SEGS {
            if j >= n {
                break;
            }
            ctx.store(SRH_SEGLIST_OFF + 16 * (n - 1 - j), &enc.segs[j], 0)
                .map_err(|_| ())?;
        }
    }
    Ok(None)
}

/// One's-complement checksum of the outer IPv4 header a GTP-U encap writes:
/// the fixed words (`0x4500` = version/IHL/TOS, `0x4011` = TTL 64 / proto UDP)
/// plus the total length and the src/dst address words. ID / flags / frag = 0.
#[inline(always)]
fn ipv4_hdr_csum(total_len: u16, src: [u8; 4], dst: [u8; 4]) -> u16 {
    let mut sum: u32 = 0x4500 + total_len as u32 + 0x4011;
    sum += ((src[0] as u32) << 8) | src[1] as u32;
    sum += ((src[2] as u32) << 8) | src[3] as u32;
    sum += ((dst[0] as u32) << 8) | dst[1] as u32;
    sum += ((dst[2] as u32) << 8) | dst[3] as u32;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// `GTP4.E` downlink encap: wrap the inner packet in outer IPv4 + UDP(2152) +
/// an 8-byte GTP-U G-PDU header (`GTP_ENCAP[nh_id]`), then egress via the
/// nexthop's adjacency. UDP checksum left 0 (optional over IPv4). Mirrors
/// `srv6_encap`'s grow-at-MAC-boundary + `l2_xmit` shape.
#[inline(always)]
fn gtp_encap(ctx: &TcContext, nh_id: u32, nh: &NextHop) -> Result<i32, ()> {
    let enc: &GtpEncap = match GTP_ENCAP.get_ptr(&nh_id) {
        Some(e) => unsafe { &*e },
        None => return Ok(TC_ACT_PIPE as i32),
    };
    // Inner IP length, captured before the outer headers grow the frame.
    let inner_len = (ctx.len() as usize).saturating_sub(EthHdr::LEN) as u16;
    let ip_total = inner_len + GTP_ENCAP_HDR_LEN as u16; // outer IPv4 total length
    let udp_len = inner_len + 16; // UDP(8) + GTP-U(8) + inner
    let gtp_len = inner_len; // payload after the 8-byte GTP-U header

    ctx.skb
        .adjust_room(GTP_ENCAP_HDR_LEN as i32, BPF_ADJ_ROOM_MAC, 0)
        .map_err(|_| ())?;

    // Outer IPv4 header.
    let csum = ipv4_hdr_csum(ip_total, enc.src, enc.dst);
    ctx.store(IP_VER_IHL_OFF, &0x45u8, 0).map_err(|_| ())?; // version 4, IHL 5
    ctx.store(IP_VER_IHL_OFF + 1, &0u8, 0).map_err(|_| ())?; // TOS
    ctx.store(IP_VER_IHL_OFF + 2, &ip_total.to_be(), 0)
        .map_err(|_| ())?;
    ctx.store(IP_VER_IHL_OFF + 4, &0u16, 0).map_err(|_| ())?; // identification
    ctx.store(IP_VER_IHL_OFF + 6, &0u16, 0).map_err(|_| ())?; // flags / frag off
    ctx.store(IP_TTL_OFF, &64u8, 0).map_err(|_| ())?;
    ctx.store(IP_PROTO_OFF, &IPPROTO_UDP, 0).map_err(|_| ())?;
    ctx.store(IP_CSUM_OFF, &csum.to_be(), 0).map_err(|_| ())?;
    ctx.store(IP_SRC_OFF, &enc.src, 0).map_err(|_| ())?;
    ctx.store(IP_DST_OFF, &enc.dst, 0).map_err(|_| ())?;

    // UDP header (checksum 0 — optional over IPv4).
    ctx.store(L4_OFF, &GTP_PORT.to_be(), 0).map_err(|_| ())?; // source port
    ctx.store(L4_OFF + 2, &GTP_PORT.to_be(), 0)
        .map_err(|_| ())?; // dest 2152
    ctx.store(L4_OFF + 4, &udp_len.to_be(), 0).map_err(|_| ())?;
    ctx.store(L4_OFF + 6, &0u16, 0).map_err(|_| ())?; // UDP checksum

    // GTP-U header: version 1, PT 1, no optional fields; G-PDU (0xFF).
    ctx.store(L4_OFF + 8, &0x30u8, 0).map_err(|_| ())?; // flags
    ctx.store(L4_OFF + 9, &0xFFu8, 0).map_err(|_| ())?; // message type
    ctx.store(L4_OFF + 10, &gtp_len.to_be(), 0)
        .map_err(|_| ())?;
    ctx.store(L4_OFF + 12, &enc.teid, 0).map_err(|_| ())?; // TEID

    stat_inc(STAT_GTP_ENCAP);
    l2_xmit(ctx, nh, ETH_P_IP)
}

/// EVPN symmetric IRB (RFC 9135): VXLAN-encapsulate a *routed* inner packet
/// toward the remote PE's VTEP with an L3VNI, giving it a fresh inner
/// Ethernet header — dst = the remote PE's router MAC (`VXLAN_ENCAP[nh_id]`),
/// src = this PE's router MAC for the L3VNI (`VNI_INFO[l3vni].rmac`). The
/// remote PE, seeing the inner dst MAC is its own RMAC, routes the inner IP
/// in the L3VNI's VRF. `bpf_skb_adjust_room` in encap mode grows the room and
/// reserves the inner L2; the pre-existing (routed) Ethernet header is reused
/// as the outer and rewritten by `l2_xmit`. UDP checksum 0 (RFC 7348 §4.3).
#[inline(always)]
fn vxlan_l3_encap(ctx: &TcContext, nh_id: u32, nh: &NextHop, inner_et: u16) -> Result<i32, ()> {
    let enc: VxlanEncap = match VXLAN_ENCAP.get_ptr(&nh_id) {
        Some(e) => unsafe { *e },
        None => return Ok(TC_ACT_PIPE as i32),
    };
    // Local router MAC for this L3VNI (the inner source MAC). Absent = the
    // L3VNI was never bound; punt.
    let local_rmac: [u8; 6] = match VNI_INFO.get_ptr(&enc.l3vni) {
        Some(i) => unsafe { (*i).rmac },
        None => return Ok(TC_ACT_PIPE as i32),
    };
    let src4: [u8; 4] = match VXLAN_SRC.get(0) {
        Some(s) if *s != [0; 4] => *s,
        _ => return Ok(TC_ACT_PIPE as i32), // no local VTEP configured
    };
    // Inner IP length (the routed packet), captured before the grow.
    let inner_len = (ctx.len() as usize).saturating_sub(EthHdr::LEN) as u16;
    let ip_total = inner_len + VXLAN_L3_GROW as u16; // 20 IP + 8 UDP + 8 VXLAN + 14 inner eth
    let udp_len = inner_len + (VXLAN_L3_GROW - 20) as u16; // 8 UDP + 8 VXLAN + 14 inner eth

    let flags = BPF_F_ADJ_ROOM_ENCAP_L3_IPV4
        | BPF_F_ADJ_ROOM_ENCAP_L4_UDP
        | BPF_F_ADJ_ROOM_ENCAP_L2_ETH
        | BPF_F_ADJ_ROOM_NO_CSUM_RESET
        | bpf_f_adj_room_encap_l2(EthHdr::LEN as u64);
    ctx.skb
        .adjust_room(VXLAN_L3_GROW as i32, BPF_ADJ_ROOM_MAC, flags)
        .map_err(|_| ())?;

    // Outer IPv4 header.
    let csum = ipv4_hdr_csum(ip_total, src4, enc.vtep);
    ctx.store(IP_VER_IHL_OFF, &0x45u8, 0).map_err(|_| ())?; // version 4, IHL 5
    ctx.store(IP_VER_IHL_OFF + 1, &0u8, 0).map_err(|_| ())?; // TOS
    ctx.store(IP_VER_IHL_OFF + 2, &ip_total.to_be(), 0)
        .map_err(|_| ())?;
    ctx.store(IP_VER_IHL_OFF + 4, &0u16, 0).map_err(|_| ())?; // identification
    ctx.store(IP_VER_IHL_OFF + 6, &0u16, 0).map_err(|_| ())?; // flags / frag off
    ctx.store(IP_TTL_OFF, &64u8, 0).map_err(|_| ())?;
    ctx.store(IP_PROTO_OFF, &IPPROTO_UDP, 0).map_err(|_| ())?;
    ctx.store(IP_CSUM_OFF, &csum.to_be(), 0).map_err(|_| ())?;
    ctx.store(IP_SRC_OFF, &src4, 0).map_err(|_| ())?;
    ctx.store(IP_DST_OFF, &enc.vtep, 0).map_err(|_| ())?;

    // UDP header (source port = dport here; checksum 0 — optional over IPv4).
    ctx.store(L4_OFF, &VXLAN_PORT.to_be(), 0).map_err(|_| ())?;
    ctx.store(L4_OFF + 2, &VXLAN_PORT.to_be(), 0)
        .map_err(|_| ())?;
    ctx.store(L4_OFF + 4, &udp_len.to_be(), 0).map_err(|_| ())?;
    ctx.store(L4_OFF + 6, &0u16, 0).map_err(|_| ())?;

    // VXLAN header: I flag, L3VNI in the upper 24 bits of the second word.
    ctx.store(VXLAN_HDR_OFF, &0x0800_0000u32.to_be(), 0)
        .map_err(|_| ())?;
    ctx.store(VXLAN_HDR_OFF + 4, &(enc.l3vni << 8).to_be(), 0)
        .map_err(|_| ())?;

    // Inner Ethernet: dst = remote RMAC, src = local RMAC, ethertype = inner.
    ctx.store(VXLAN_L3_INNER_OFF, &enc.rmac, 0)
        .map_err(|_| ())?;
    ctx.store(VXLAN_L3_INNER_OFF + 6, &local_rmac, 0)
        .map_err(|_| ())?;
    ctx.store(VXLAN_L3_INNER_OFF + 12, &inner_et.to_be(), 0)
        .map_err(|_| ())?;

    stat_inc(STAT_VXLAN_ENCAP);
    l2_xmit(ctx, nh, ETH_P_IP)
}

/// SRv6 H.Insert (TI-LFA repair): insert an SRH into the *existing* IPv6
/// packet — the original destination becomes the SRH's final segment
/// (`segment_list[0]`), the repair segments ride above it reversed, and the
/// DA is rewritten to the first repair segment. At the repair path's end the
/// SRH walk restores the original destination (`SL → 0`) and the packet
/// continues natively. `BPF_ADJ_ROOM_NET` grows the room right after the
/// IPv6 base header. Decrements the hop limit (this is a forward).
#[inline(always)]
fn srv6_insert(ctx: &TcContext, enc: &Srv6Encap, nh: &NextHop) -> Result<i32, ()> {
    // Barrier for the same reason as in `apply_hencap`: keep the segment
    // loop's constant latch alive for the verifier.
    let n = core::hint::black_box(enc.num_segs as usize);
    let hop: u8 = ctx.load(IP6_HOP_OFF).map_err(|_| ())?;
    if hop <= 1 {
        return Ok(TC_ACT_PIPE as i32);
    }
    let orig_da: [u8; 16] = ctx.load(IP6_DST_OFF).map_err(|_| ())?;
    let orig_nh: u8 = ctx.load(IP6_NEXTHDR_OFF).map_err(|_| ())?;
    let payload_len: u16 = u16::from_be(ctx.load(IP6_PAYLOAD_LEN_OFF).map_err(|_| ())?);
    // SRH sized for the repair segments plus the original destination.
    let srh_len = 8 + 16 * (n + 1);

    ctx.skb
        .adjust_room(srh_len as i32, BPF_ADJ_ROOM_NET, 0)
        .map_err(|_| ())?;

    ctx.store(IP6_NEXTHDR_OFF, &IPPROTO_ROUTING, 0)
        .map_err(|_| ())?;
    ctx.store(
        IP6_PAYLOAD_LEN_OFF,
        &(payload_len + srh_len as u16).to_be(),
        0,
    )
    .map_err(|_| ())?;
    ctx.store(IP6_HOP_OFF, &(hop - 1), 0).map_err(|_| ())?;
    // SRH header.
    ctx.store(SRH_OFF, &orig_nh, 0).map_err(|_| ())?;
    ctx.store(SRH_OFF + 1, &(2 * (n as u8 + 1)), 0)
        .map_err(|_| ())?; // hdr_ext_len
    ctx.store(SRH_OFF + 2, &4u8, 0).map_err(|_| ())?; // routing type 4
    ctx.store(SRH_SL_OFF, &(n as u8), 0).map_err(|_| ())?; // segments_left
    ctx.store(SRH_OFF + 4, &(n as u8), 0).map_err(|_| ())?; // last_entry
    ctx.store(SRH_OFF + 5, &0u8, 0).map_err(|_| ())?; // flags
    ctx.store(SRH_OFF + 6, &0u16, 0).map_err(|_| ())?; // tag
    // segment_list[0] = the original destination (final); repair segments
    // reversed above it so segment_list[n] = segs[0] = the active segment.
    // Indexed forward on the map side (the loop constant bounds the map-value
    // pointer for the verifier); the reversal rides in the skb offset, which
    // the store helper validates at runtime.
    ctx.store(SRH_SEGLIST_OFF, &orig_da, 0).map_err(|_| ())?;
    for j in 0..MAX_SEGS {
        if j >= n {
            break;
        }
        ctx.store(SRH_SEGLIST_OFF + 16 * (n - j), &enc.segs[j], 0)
            .map_err(|_| ())?;
    }
    ctx.store(IP6_DST_OFF, &enc.segs[0], 0).map_err(|_| ())?;

    stat_inc(STAT_SRV6_HINSERT);
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

/// `--ebpf-mode xdp-only`: a dedicated, minimal XDP program attached in place
/// of `cradle_xdp` (and with no TC program) when the operator restricts the
/// datapath to plain IPv4 L3 forwarding for a single-hook benchmark. It is its
/// own BPF program with its own 512-byte verifier stack budget, so it does not
/// share the near-budget `cradle_xdp` monolith. Plain IPv4 is forwarded here
/// entirely in XDP via `xdp_l3_forward_v4`; everything else (ARP, IPv6,
/// non-plain routes) is passed to the kernel stack. No overlay / NAT / policy /
/// L2 — those need the full `cradle_xdp` + `cradle_tc` pipeline.
#[xdp]
pub fn cradle_xdp_l3(ctx: XdpContext) -> u32 {
    let et = match xdp_ptr::<u16>(&ctx, ETH_TYPE_OFF) {
        Ok(p) => u16::from_be(unsafe { *p }),
        Err(()) => return xdp_action::XDP_PASS,
    };
    if et != ETH_P_IP {
        return xdp_action::XDP_PASS;
    }
    match xdp_l3_forward_v4(&ctx) {
        Ok(act) => act,
        Err(()) => xdp_action::XDP_PASS,
    }
}

/// The XDP stage hosts the two overlays whose frame-resizing the TC stage
/// can't do on a non-IP or would-mis-forward skb: MPLS (pops/grow-swaps) and
/// SRv6 (End.DT* decap). Dispatch on the outer EtherType.
#[inline(always)]
fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    // On a CE-facing L2 port, a frame destined to a remote (overlay) MAC is
    // MAC-in-SRv6 encapsulated here — TC's `adjust_room` is -ENOTSUPP for the
    // non-IP frames (ARP) an L2 domain carries, so the grow must run in XDP.
    // Everything else on an L2 port passes to the TC `l2_switch`.
    let iif = unsafe { (*ctx.ctx).ingress_ifindex };
    // A BUM replication slot: the TC flood clone_redirect'ed a bare copy of
    // a BUM frame into this veth; encapsulate it toward the slot's remote
    // PE (per-copy encap — the piece clone_redirect itself can't do) and
    // send it out the underlay via the FIB route to the SID/VTEP.
    if let Some(t) = REPL_SID.get_ptr(&iif) {
        let t = unsafe { &*t };
        let ent = FdbEntry {
            oif: 0, // resolve the underlay adjacency by FIB lookup
            flags: FDB_F_REMOTE,
            remote_sid: t.addr,
            last_seen: 0,
        };
        return if t.kind == REPL_KIND_VXLAN {
            l2_vxlan_encap(ctx, &ent, t.vni, STAT_VXLAN_FLOOD)
        } else {
            l2_srv6_encap(ctx, &ent, STAT_SRV6_L2_BUM)
        };
    }
    // VLAN-scoped VPWS AC (RFC 8214 VLAN-based E-Line, End.DX2V): an
    // 802.1Q-tagged frame picks its E-Line by (AC ifindex, VID) — the tag
    // stays on the frame through the encapsulation and the remote
    // End.DX2V demuxes on it. Untagged frames and unknown VIDs fall
    // through to the port-based XCONNECT, then the L2 bridge dispatch.
    if u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? }) == ETH_P_8021Q {
        let tci = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, EthHdr::LEN)? });
        let key = Dx2vKey {
            table: iif,
            vid: tci & 0x0fff,
            _pad: [0; 2],
        };
        if let Some(sid) = XCONNECT_VLAN.get_ptr(&key) {
            let ent = FdbEntry {
                oif: 0, // resolve the underlay adjacency by FIB6 lookup
                flags: FDB_F_REMOTE,
                remote_sid: unsafe { *sid },
                last_seen: 0,
            };
            return l2_srv6_encap(ctx, &ent, STAT_SRV6_L2_ENCAP);
        }
    }
    // VPWS attachment circuit (RFC 8214 E-Line): every frame from a bound
    // AC — any EtherType, any MAC — encapsulates toward the remote
    // End.DX2/DX2V SID. Checked before the L2 bridge dispatch so the AC
    // never MAC-learns or floods.
    if let Some(sid) = XCONNECT.get_ptr(&iif) {
        let ent = FdbEntry {
            oif: 0, // resolve the underlay adjacency by FIB6 lookup
            flags: FDB_F_REMOTE,
            remote_sid: unsafe { *sid },
            last_seen: 0,
        };
        return l2_srv6_encap(ctx, &ent, STAT_SRV6_L2_ENCAP);
    }
    if let Some(p) = PORTS.get_ptr(&iif) {
        if unsafe { (*p).flags } & PORT_F_L2 != 0 {
            return l2_evpn_xdp(ctx, unsafe { (*p).vlan });
        }
    }
    let ethertype = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? });
    match ethertype {
        ETH_P_MPLS_UC => try_mpls_xdp(ctx),
        // BFD Echo/control over IPv6 (udp/3785/3784, base header) is reflected /
        // watched before SRv6; a non-BFD IPv6 packet falls through to SRv6.
        ETH_P_IPV6 => match try_bfd6(ctx)? {
            Some(action) => Ok(action),
            None => try_srv6_xdp(ctx),
        },
        // UDP tunnel decaps (GTP-U, VXLAN): a packet destined to a local
        // tunnel endpoint is stripped in XDP; anything else falls through to
        // TC. Dispatched on the UDP destination port in one place — a decap's
        // success is XDP_PASS-with-metadata, indistinguishable from "not
        // mine", so the handlers cannot be chained.
        ETH_P_IP => try_udp4_xdp(ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// Route an IPv4 packet to the UDP-tunnel decap owning its destination port:
/// GTP-U (2152) or VXLAN (4789). No-options IPv4 only (the L4 offsets assume
/// IHL == 5); everything else passes to the TC L3 stage untouched.
#[inline(always)]
fn try_udp4_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let ver_ihl = unsafe { *xdp_ptr::<u8>(ctx, IP_VER_IHL_OFF)? };
    if ver_ihl & 0x0f != 5 {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { *xdp_ptr::<u8>(ctx, IP_PROTO_OFF)? } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    match u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, L4_OFF + 2)? }) {
        GTP_PORT => try_gtp_xdp(ctx),
        VXLAN_PORT => try_vxlan_xdp(ctx),
        // BFD Echo: reflect (XDP_TX) or, for our own looped-back Echo, feed the
        // in-kernel detector and drop. BFD control: observe the expiration
        // watchdog, then always pass to the stack (the daemon runs the FSM).
        BFD_ECHO_PORT => bfd::reflect_v4(ctx),
        BFD_CTRL_PORT => {
            bfd::observe_ctrl_v4(ctx);
            Ok(xdp_action::XDP_PASS)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

/// `--ebpf-mode xdp-only` fast path: forward a plain IPv4 UDP packet entirely
/// in XDP, bypassing the (unattached) TC stage. A self-contained twin of
/// `l3_forward_v4`'s plain-unicast path — FIB lookup (LPM or DIR-24-8 via
/// `fib4_lookup`), nexthop + neighbor resolution, a TTL decrement with an
/// incremental IPv4 checksum (RFC 1624), Ethernet rewrite, and `bpf_redirect`.
/// `bpf_redirect_neigh` is a TC-only helper (the XDP verifier rejects it), so
/// the L2 header is built here from cradle's neighbor/port maps
/// (`xdp_resolve_l2`), mirroring `pop_and_forward`. Anything that isn't a plain
/// unicast forward (encap nexthop, local/blackhole/ECMP route, neighbor miss,
/// TTL<=1) punts to `XDP_PASS` so the kernel stack handles it (ARP, ICMP
/// time-exceeded). Works for any IHL — it reads only the fixed IPv4 dst / TTL /
/// checksum offsets, never L4. Called only from the dedicated `cradle_xdp_l3`
/// program (its own stack budget), so it does not touch the near-budget
/// `cradle_xdp` monolith.
#[inline(always)]
fn xdp_l3_forward_v4(ctx: &XdpContext) -> Result<u32, ()> {
    let dst = unsafe { *xdp_ptr::<[u8; 4]>(ctx, IP_DST_OFF)? };
    // Read the DIR-24-8 engine directly (xdp-only defaults to dir24). The
    // generic `fib4_lookup` would also inline the LPM trie + VRF key into this
    // frame and blow the cradle_xdp call-chain stack budget (512 B), so only a
    // few `u32` slots are used here — 1–2 flat array loads, no aggregates.
    let key = u32::from_be_bytes(dst);
    let Some(&w24) = TBL24.get(key >> 8) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let mut w = w24;
    if w & FIBW_TBL8 != 0 {
        let group = w & FIBW_ID_MASK;
        let Some(&w8) = TBL8.get(group * 256 + dst[3] as u32) else {
            return Ok(xdp_action::XDP_PASS);
        };
        w = w8;
    }
    if w & FIBW_VALID == 0 {
        match DEFAULT4.get(0) {
            Some(&wd) if wd & FIBW_VALID != 0 => w = wd,
            _ => return Ok(xdp_action::XDP_PASS),
        }
    }
    let (nexthop_id, flags) = fibw_unpack(w);
    if flags & (FIB_F_BLACKHOLE | FIB_F_LOCAL | FIB_F_ECMP) != 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    // Borrow the nexthop (no 48-byte copy — the flattened cradle_xdp frame is
    // near the verifier stack budget). Fast-reroute (`resolve_nh`'s backup) is
    // not needed on this benchmark path.
    let Some(nh_ptr) = NEXTHOPS.get_ptr(&nexthop_id) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let nh: &NextHop = unsafe { &*nh_ptr };
    if nh.flags & (NH_F_MPLS | NH_F_SRV6 | NH_F_GTP | NH_F_VXLAN) != 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    let Some((dst_mac, src_mac)) = xdp_resolve_l2(nh) else {
        return Ok(xdp_action::XDP_PASS);
    };
    // TTL decrement + incremental IPv4 header checksum. The 16-bit word at
    // IP_TTL_OFF is [TTL, protocol] in network order (see `mpls_uniform_to_ip`).
    let old_word = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, IP_TTL_OFF)? });
    if old_word >> 8 <= 1 {
        return Ok(xdp_action::XDP_PASS); // TTL<=1: let the stack send time-exceeded
    }
    let new_word = old_word - (1 << 8);
    let hc = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, IP_CSUM_OFF)? });
    let new_hc = csum16_update(hc, old_word, new_word);
    unsafe { *xdp_ptr::<u16>(ctx, IP_TTL_OFF)? = new_word.to_be() };
    unsafe { *xdp_ptr::<u16>(ctx, IP_CSUM_OFF)? = new_hc.to_be() };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? = dst_mac };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? = src_mac };
    stat_inc(STAT_XDP_L3_FWD);
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as u32)
}

/// BFD over IPv6 on a base header (no extension headers): `Some(action)` when
/// the frame is BFD Echo (reflect) or control (observe + PASS), `None` when it
/// isn't ours so the caller falls through to the SRv6 handler. Reads the IPv6
/// Next Header + UDP destination port; a chained header (Next Header != UDP)
/// is `None`.
#[inline(always)]
fn try_bfd6(ctx: &XdpContext) -> Result<Option<u32>, ()> {
    if unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? } != IPPROTO_UDP {
        return Ok(None);
    }
    match u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, IP6_L4_OFF + 2)? }) {
        BFD_ECHO_PORT => Ok(Some(bfd::reflect_v6(ctx)?)),
        BFD_CTRL_PORT => {
            bfd::observe_ctrl_v6(ctx);
            Ok(Some(xdp_action::XDP_PASS))
        }
        _ => Ok(None),
    }
}

/// The bridge domain's BUM tunnel: the all-ones-MAC FDB entry (installed by
/// static config or the EVPN Type-3 tee), pointing at the remote `End.DT2M`
/// SID. `None` when the BD has no overlay BUM tunnel. Borrowed from map
/// memory, not copied — a 32-byte `FdbEntry` stack temp is budget the
/// flattened cradle_xdp frame doesn't have (see `PolicyScratch6`), and the
/// copy would be just as unatomic against a concurrent update.
#[inline(always)]
fn l2_evpn_bum_tunnel(bd: u16) -> Option<&'static FdbEntry> {
    let ent = unsafe {
        &*FDB.get_ptr(&FdbKey {
            mac: [0xff; 6],
            vlan: bd,
        })?
    };
    if ent.flags & FDB_F_REMOTE == 0 {
        return None;
    }
    Some(ent)
}

/// EVPN-over-SRv6 ingress. Learns the source MAC first (frames on a local L2
/// port belong to local stations; the TC `l2_switch` learn never sees frames
/// this stage tunnels, and the user-space `WatchFdb` stream reports these
/// entries up to the control plane for EVPN Type-2 origination). Then, by
/// destination: **BUM** — broadcast/multicast *and unknown unicast* — is
/// tunneled to the bridge domain's `End.DT2M` SID via the all-ones-MAC FDB
/// sentinel (in a 2-PE / single-local-CE domain that one remote copy is the
/// whole flood set; local flood + multi-remote replication is a later slice);
/// a **known-remote unicast** (`FDB_F_REMOTE`) is MAC-in-SRv6 encapsulated
/// toward its `End.DT2U` SID. Everything else passes to the TC `l2_switch`.
#[inline(always)]
fn l2_evpn_xdp(ctx: &XdpContext, bd: u16) -> Result<u32, ()> {
    let src = unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? };
    if src[0] & 0x01 == 0 {
        let iif = unsafe { (*ctx.ctx).ingress_ifindex };
        let _ = FDB.insert(
            &FdbKey { mac: src, vlan: bd },
            &FdbEntry {
                oif: iif,
                flags: 0,
                remote_sid: [0; 16],
                last_seen: unsafe { bpf_ktime_get_ns() },
            },
            0,
        );
    }
    // Resolve to one (entry, bum?) pair, then encapsulate at a SINGLE call
    // site — each `l2_overlay_encap` expansion inlines both encap bodies,
    // and three of them push cradle_xdp's flattened frame past the
    // verifier's call-chain stack budget (see `PolicyScratch6`).
    let dst = unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? };
    let (ent, bum): (&FdbEntry, bool) = if dst[0] & 0x01 != 0 {
        match l2_evpn_bum_tunnel(bd) {
            Some(ent) => (ent, true),
            None => return Ok(xdp_action::XDP_PASS), // no BUM tunnel → TC local flood
        }
    } else {
        match FDB.get_ptr(&FdbKey { mac: dst, vlan: bd }) {
            Some(e) => {
                let ent = unsafe { &*e };
                if ent.flags & FDB_F_REMOTE == 0 {
                    return Ok(xdp_action::XDP_PASS); // local → TC forward
                }
                (ent, false)
            }
            None => {
                // Unknown unicast — the "U" in BUM: flood it over the overlay
                // too, so a not-yet-advertised remote station is reachable the
                // moment it exists (its reply seeds both PEs' tables).
                match l2_evpn_bum_tunnel(bd) {
                    Some(ent) => (ent, true),
                    None => return Ok(xdp_action::XDP_PASS), // no tunnel → TC local flood
                }
            }
        }
    };
    l2_overlay_encap(ctx, ent, bd, bum)
}

/// Tunnel an L2 frame toward the remote PE its FDB entry names, by the
/// entry's overlay flavor: VXLAN (`FDB_F_VXLAN`, the VNI from the bridge
/// domain's `VLAN_VNI` binding) or MAC-in-SRv6 (the default). `bum`
/// selects the flood-vs-unicast counter.
#[inline(always)]
fn l2_overlay_encap(ctx: &XdpContext, ent: &FdbEntry, bd: u16, bum: bool) -> Result<u32, ()> {
    if ent.flags & FDB_F_VXLAN != 0 {
        let vni = match VLAN_VNI.get_ptr(&bd) {
            Some(v) => unsafe { *v },
            None => return Ok(xdp_action::XDP_PASS), // BD not VNI-bound
        };
        let stat = if bum {
            STAT_VXLAN_FLOOD
        } else {
            STAT_VXLAN_ENCAP
        };
        l2_vxlan_encap(ctx, ent, vni, stat)
    } else {
        let stat = if bum {
            STAT_SRV6_L2_BUM
        } else {
            STAT_SRV6_L2_ENCAP
        };
        l2_srv6_encap(ctx, ent, stat)
    }
}

/// MAC-in-SRv6 encap: prepend an outer Ethernet + outer IPv6 header
/// (`next_header = 143`, *Ethernet*, DA = the remote `End.DT2U`/`End.DT2M` SID)
/// and redirect out the underlay adjacency. Single service SID ⇒ no SRH. The
/// inner frame is preserved untouched as the IPv6 payload. `ent.oif` is the
/// underlay nexthop id (remote FDB entries reuse the `oif` field for it); `stat`
/// distinguishes unicast (`STAT_SRV6_L2_ENCAP`) from BUM (`STAT_SRV6_L2_BUM`).
#[inline(always)]
fn l2_srv6_encap(ctx: &XdpContext, ent: &FdbEntry, stat: u32) -> Result<u32, ()> {
    // Underlay adjacency: an explicit nexthop id (static config), or — when
    // the entry came from the control-plane tee with nexthop 0 — resolved by
    // a FIB6 lookup on the remote SID (the locator route the IGP installed).
    let nh_id = if ent.oif != 0 {
        ent.oif
    } else {
        let fib: FibEntry = match FIB6.get(Key::new(128, ent.remote_sid)) {
            Some(f) => *f,
            None => return Ok(xdp_action::XDP_PASS), // no underlay route yet
        };
        if fib.flags & (FIB_F_ECMP | FIB_F_BLACKHOLE | FIB_F_LOCAL) != 0 {
            return Ok(xdp_action::XDP_PASS); // ECMP/odd shapes: punt (MVP)
        }
        fib.nexthop_id
    };
    let nh: NextHop = match NEXTHOPS.get_ptr(&nh_id) {
        Some(n) => unsafe { *n },
        None => return Ok(xdp_action::XDP_PASS),
    };
    let Some((dst_mac, src_mac)) = xdp_resolve_l2(&nh) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let src6: [u8; 16] = match SRV6_ENCAP_SRC.get(0) {
        Some(s) => *s,
        None => return Ok(xdp_action::XDP_PASS),
    };
    // The whole inner frame (inner eth + payload) becomes the IPv6 payload.
    let inner_len = (ctx.data_end() - ctx.data()) as u16;
    let grow = (EthHdr::LEN + IP6_HDR_LEN) as i32;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -grow) } != 0 {
        return Err(());
    }
    // Outer Ethernet.
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? = dst_mac };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? = src_mac };
    unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? = (ETH_P_IPV6 as u16).to_be() };
    // Outer IPv6.
    unsafe { *xdp_ptr::<u32>(ctx, EthHdr::LEN)? = IP6_VER_TC_FL.to_be() };
    unsafe { *xdp_ptr::<u16>(ctx, IP6_PAYLOAD_LEN_OFF)? = inner_len.to_be() };
    unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? = IPPROTO_ETHERNET };
    unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? = 64 };
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_SRC_OFF)? = src6 };
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? = ent.remote_sid };
    stat_inc(stat);
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as u32)
}

/// VXLAN encap (RFC 7348): prepend outer Ethernet + IPv4 + UDP(4789) + VXLAN
/// carrying `vni`, toward the remote VTEP the FDB entry names (v4-mapped in
/// `remote_sid`), and redirect out the underlay adjacency. The whole inner
/// frame rides as the VXLAN payload. `l2_srv6_encap`'s shape with GTP's outer
/// IPv4+UDP recipe: header checksum from `ipv4_hdr_csum`, UDP checksum 0
/// (optional over IPv4, RFC 7348 §4.3), UDP source port from the inner MACs
/// for underlay ECMP entropy (§5).
#[inline(always)]
fn l2_vxlan_encap(ctx: &XdpContext, ent: &FdbEntry, vni: u32, stat: u32) -> Result<u32, ()> {
    let vtep: [u8; 4] = [
        ent.remote_sid[12],
        ent.remote_sid[13],
        ent.remote_sid[14],
        ent.remote_sid[15],
    ];
    // Underlay adjacency: an explicit nexthop id (static config), or — when
    // the entry came from the control-plane tee with nexthop 0 — resolved by
    // a FIB4 lookup on the remote VTEP (the underlay route the IGP installed).
    // The LPM trie directly (`l2_srv6_encap`'s FIB6 shape) — the generic
    // `fib4_lookup` would inline the whole DIR-24 engine into cradle_xdp's
    // flattened frame and blow the verifier's stack budget; in dir24 mode a
    // VXLAN FDB entry needs an explicit nexthop id.
    let nh_id = if ent.oif != 0 {
        ent.oif
    } else {
        // Borrow, don't copy: cradle_xdp's flattened frame sits at the
        // verifier's call-chain stack budget (see `PolicyScratch6`), so this
        // whole function avoids aggregate stack temporaries.
        let fib: &FibEntry = match FIB4.get(Key::new(32, vtep)) {
            Some(f) => f,
            None => return Ok(xdp_action::XDP_PASS), // no underlay route yet
        };
        if fib.flags & (FIB_F_ECMP | FIB_F_BLACKHOLE | FIB_F_LOCAL) != 0 {
            return Ok(xdp_action::XDP_PASS); // ECMP/odd shapes: punt (MVP)
        }
        fib.nexthop_id
    };
    let nh: &NextHop = match NEXTHOPS.get_ptr(&nh_id) {
        Some(n) => unsafe { &*n },
        None => return Ok(xdp_action::XDP_PASS),
    };
    let Some((dst_mac, src_mac)) = xdp_resolve_l2(nh) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let src4: &[u8; 4] = match VXLAN_SRC.get(0) {
        Some(s) if *s != [0; 4] => s,
        _ => return Ok(xdp_action::XDP_PASS), // no local VTEP configured
    };
    // Flow entropy for the UDP source port — scalar reads, before the grow.
    let e0 = unsafe { *xdp_ptr::<u8>(ctx, 0)? } ^ unsafe { *xdp_ptr::<u8>(ctx, 6)? };
    let e1 = unsafe { *xdp_ptr::<u8>(ctx, 5)? } ^ unsafe { *xdp_ptr::<u8>(ctx, 11)? };
    let h = e0 as u16 | (e1 as u16) << 8;
    let sport = 0xC000 | (h & 0x3FFF); // the RFC 6335 dynamic range
    // The whole inner frame (inner eth + payload) becomes the VXLAN payload.
    let inner_len = (ctx.data_end() - ctx.data()) as u16;
    let ip_total = inner_len + (VXLAN_ENCAP_HDR_LEN - EthHdr::LEN) as u16;
    let udp_len = inner_len + 16; // UDP(8) + VXLAN(8) + inner
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -(VXLAN_ENCAP_HDR_LEN as i32)) } != 0 {
        return Err(());
    }
    // Outer Ethernet.
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? = dst_mac };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? = src_mac };
    unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? = ETH_P_IP.to_be() };
    // Outer IPv4 (no options; id/flags/frag 0 — the csum helper assumes
    // exactly this header shape).
    let csum = ipv4_hdr_csum(ip_total, *src4, vtep);
    unsafe { *xdp_ptr::<u8>(ctx, IP_VER_IHL_OFF)? = 0x45 };
    unsafe { *xdp_ptr::<u8>(ctx, IP_VER_IHL_OFF + 1)? = 0 }; // TOS
    unsafe { *xdp_ptr::<u16>(ctx, IP_VER_IHL_OFF + 2)? = ip_total.to_be() };
    unsafe { *xdp_ptr::<u16>(ctx, IP_VER_IHL_OFF + 4)? = 0 }; // identification
    unsafe { *xdp_ptr::<u16>(ctx, IP_VER_IHL_OFF + 6)? = 0 }; // flags / frag off
    unsafe { *xdp_ptr::<u8>(ctx, IP_TTL_OFF)? = 64 };
    unsafe { *xdp_ptr::<u8>(ctx, IP_PROTO_OFF)? = IPPROTO_UDP };
    unsafe { *xdp_ptr::<u16>(ctx, IP_CSUM_OFF)? = csum.to_be() };
    unsafe { *xdp_ptr::<[u8; 4]>(ctx, IP_SRC_OFF)? = *src4 };
    unsafe { *xdp_ptr::<[u8; 4]>(ctx, IP_DST_OFF)? = vtep };
    // UDP header (checksum 0 — optional over IPv4).
    unsafe { *xdp_ptr::<u16>(ctx, L4_OFF)? = sport.to_be() };
    unsafe { *xdp_ptr::<u16>(ctx, L4_OFF + 2)? = VXLAN_PORT.to_be() };
    unsafe { *xdp_ptr::<u16>(ctx, L4_OFF + 4)? = udp_len.to_be() };
    unsafe { *xdp_ptr::<u16>(ctx, L4_OFF + 6)? = 0 }; // UDP checksum
    // VXLAN header: I flag, VNI in the upper 24 bits of the second word.
    unsafe { *xdp_ptr::<u32>(ctx, VXLAN_HDR_OFF)? = 0x0800_0000u32.to_be() };
    unsafe { *xdp_ptr::<u32>(ctx, VXLAN_HDR_OFF + 4)? = (vni << 8).to_be() };
    stat_inc(stat);
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as u32)
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

        // Uniform TTL disposition (RFC 3443) is a per-ILM property; `ttl` is
        // the popped label's TTL (>= 2 here, past the `ttl <= 1` guard).
        let uniform = ent.flags & MPLS_E_TTL_UNIFORM != 0;
        match ent.op {
            // Explicit decap (gRPC / zebra DecapVrf): pop to IP and route
            // locally — in the entry's VRF when set — whatever the nexthop.
            MPLS_OP_POP_L3 if s == 1 => return pop_decap_local(ctx, ent.vrf_id, ttl, uniform),
            // PHP shapes — a pop with a *real* nexthop means "pop and
            // forward the remaining stack there". The labels underneath
            // belong to the next hop (label spaces are per-node): they must
            // never be looked up here.
            MPLS_OP_SWAP | MPLS_OP_POP if nh.num_labels == 0 && nh.oif != 0 => {
                return pop_and_forward(ctx, &nh, s, ttl, uniform);
            }
            // Nexthop-less pops: this node owns whatever is underneath.
            MPLS_OP_SWAP | MPLS_OP_POP if nh.num_labels == 0 => {
                if s == 1 {
                    return pop_decap_local(ctx, ent.vrf_id, ttl, uniform);
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
fn pop_decap_local(ctx: &XdpContext, vrf_id: u32, ttl: u8, uniform: bool) -> Result<u32, ()> {
    let et = match popped_ethertype(ctx) {
        Ok(et) => et,
        Err(()) => {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    pop_head(ctx, et)?;
    // Uniform disposition (RFC 3443): expose the LSP hop count by copying the
    // popped label's TTL into the IP header. The TC FIB stage applies the
    // onward-hop decrement, so no `-1` here. Pipe (default) leaves it untouched.
    if uniform {
        mpls_uniform_to_ip(ctx, et, ttl)?;
    }
    if vrf_id != 0 {
        if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) }
            != 0
        {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        let meta = xdp_meta_ptr(ctx)?;
        unsafe {
            (*meta).magic = XDP_META_MAGIC ^ meta_cookie();
            (*meta).vrf_id = vrf_id;
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// GTP-U tunnel decap (`H.M.GTP4.D`): match a received no-options G-PDU on its
/// (local outer dst, TEID) in `GTP_PDR`, strip the 36-byte outer IPv4+UDP+GTP-U,
/// and hand the inner packet to the TC FIB stage (routed in the PDR's VRF via
/// `CradleXdpMeta`, exactly like an `End.DT*` decap). A non-matching or non-GTP
/// v4 packet returns `XDP_PASS` for normal forwarding. Mirrors `try_srv6_xdp`;
/// the 36-byte strip is below `decap_head`'s IPv6 floor so it is inlined here.
#[inline(always)]
fn try_gtp_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    // No-options IPv4 only — the L4 / GTP offsets assume IHL == 5.
    let ver_ihl = unsafe { *xdp_ptr::<u8>(ctx, IP_VER_IHL_OFF)? };
    if ver_ihl & 0x0f != 5 {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { *xdp_ptr::<u8>(ctx, IP_PROTO_OFF)? } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    let dport = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, L4_OFF + 2)? });
    if dport != GTP_PORT {
        return Ok(xdp_action::XDP_PASS);
    }
    // Plain G-PDU only: no S/PN/E optional fields (flags & 0x07 == 0), type 0xFF.
    let gflags = unsafe { *xdp_ptr::<u8>(ctx, L4_OFF + 8)? };
    let mtype = unsafe { *xdp_ptr::<u8>(ctx, L4_OFF + 9)? };
    if gflags & 0x07 != 0 || mtype != 0xFF {
        return Ok(xdp_action::XDP_PASS);
    }
    // PDR lookup keyed by (local tunnel endpoint, TEID) — both on-wire bytes.
    let dst = unsafe { *xdp_ptr::<[u8; 4]>(ctx, IP_DST_OFF)? };
    let teid = unsafe { *xdp_ptr::<[u8; 4]>(ctx, L4_OFF + 12)? };
    let pdr: GtpPdr = match GTP_PDR.get_ptr(&GtpPdrKey { dst, teid }) {
        Some(p) => unsafe { *p },
        None => return Ok(xdp_action::XDP_PASS),
    };
    // Inner ethertype from the decapped packet's IP version nibble.
    let inner_et = match unsafe { *xdp_ptr::<u8>(ctx, GTP_INNER_OFF)? } >> 4 {
        4 => ETH_P_IP,
        6 => ETH_P_IPV6,
        _ => {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    // Strip the 36-byte outer headers: slide the MAC header forward over them
    // and advance `data`, leaving a fresh Ethernet header on the inner packet.
    let macs = unsafe { *xdp_ptr::<[u8; 12]>(ctx, 0)? };
    unsafe { *xdp_ptr::<[u8; 12]>(ctx, GTP_ENCAP_HDR_LEN)? = macs };
    unsafe { *xdp_ptr::<u16>(ctx, GTP_ENCAP_HDR_LEN + ETH_TYPE_OFF)? = inner_et.to_be() };
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, GTP_ENCAP_HDR_LEN as i32) } != 0 {
        return Err(());
    }
    stat_inc(STAT_GTP_DECAP);
    // Route the inner packet in the PDR's VRF (0 = global; no metadata needed).
    if pdr.vrf_id != 0 {
        if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) }
            != 0
        {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        let meta = xdp_meta_ptr(ctx)?;
        unsafe {
            (*meta).magic = XDP_META_MAGIC ^ meta_cookie();
            (*meta).vrf_id = pdr.vrf_id;
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// VXLAN decap (RFC 7348): a VXLAN frame addressed to the local VTEP is
/// stripped of its 50-byte outer encapsulation — the inner Ethernet frame
/// moves to the front intact — and its VNI's bridge domain rides to the TC
/// `l2_switch` as metadata (the `srv6_dt2u` handoff: overlay-received, so
/// split horizon applies and the underlay port never MAC-learns). Anything
/// not ours — a *transit* VXLAN packet routed between other VTEPs, an unknown
/// VNI — passes to the TC L3 stage untouched. The caller (`try_udp4_xdp`)
/// already validated IHL == 5 / UDP / dport 4789.
#[inline(always)]
fn try_vxlan_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let local: &[u8; 4] = match VXLAN_SRC.get(0) {
        Some(s) if *s != [0; 4] => s,
        _ => return Ok(xdp_action::XDP_PASS), // no local VTEP configured
    };
    if unsafe { *xdp_ptr::<[u8; 4]>(ctx, IP_DST_OFF)? } != *local {
        return Ok(xdp_action::XDP_PASS); // transit VXLAN: route it normally
    }
    // Valid-VNI flag (I) must be set; other flag bits are reserved (ignored).
    if unsafe { *xdp_ptr::<u8>(ctx, VXLAN_HDR_OFF)? } & 0x08 == 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    let vni = u32::from_be(unsafe { *xdp_ptr::<u32>(ctx, VXLAN_HDR_OFF + 4)? }) >> 8;
    // An L3VNI (symmetric IRB) routes the inner IP in `vrf_id` — hand it to
    // TC's `l3_forward` with the L3 VRF meta (the End.DT46 pattern); an L2VNI
    // bridges the inner frame in `vlan` via the L2 meta. Both keep the inner
    // Ethernet header intact after the strip: the L3 path reads the inner IP
    // at the normal offset and rewrites the egress MAC via redirect_neigh, so
    // the inner (RMAC) header is simply ignored.
    let info: VniInfo = match VNI_INFO.get_ptr(&vni) {
        Some(i) => unsafe { *i },
        None => return Ok(xdp_action::XDP_PASS), // unknown VNI: not ours
    };
    let (magic, vrf) = if info.flags & VNI_F_L3 != 0 {
        (XDP_META_MAGIC, info.vrf_id)
    } else {
        (XDP_META_MAGIC_L2, info.vlan as u32)
    };
    // Drop the outer headers: the inner Ethernet frame moves to the front.
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, VXLAN_ENCAP_HDR_LEN as i32) } != 0 {
        return Err(());
    }
    stat_inc(STAT_VXLAN_DECAP);
    if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) } != 0
    {
        stat_inc(STAT_DROP);
        return Ok(xdp_action::XDP_DROP);
    }
    let meta = xdp_meta_ptr(ctx)?;
    unsafe {
        (*meta).magic = magic ^ meta_cookie();
        (*meta).vrf_id = vrf;
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
        // uA is classic End.X at /128 (adjacency, SRH walk); uALib is the
        // compressed carrier form (shift + adjacency).
        SRV6_BH_END | SRV6_BH_END_X | SRV6_BH_UA | SRV6_BH_END_T => return srv6_end(ctx, &sid),
        SRV6_BH_UN => return srv6_un(ctx, &sid),
        SRV6_BH_UALIB => return srv6_ua(ctx, &sid),
        SRV6_BH_END_REP | SRV6_BH_END_X_REP => return srv6_replace(ctx, &sid),
        // End.Replicate (RFC 9524): the clone fan-out needs bpf_clone_redirect,
        // a TC-only helper — leave the frame intact and hand it to the TC stage.
        SRV6_BH_END_REPLICATE => return replicate_meta(ctx),
        SRV6_BH_END_DX4 | SRV6_BH_END_DX6 => return srv6_dx(ctx, &sid),
        SRV6_BH_END_DX2 | SRV6_BH_END_DX2V => return srv6_dx2(ctx, &sid),
        SRV6_BH_END_B6 => return srv6_b6_encaps(ctx, &sid),
        // DT2U (unicast) and DT2M (BUM) decap are identical: strip + bridge.
        // The inner frame's dst MAC (unicast vs broadcast) makes l2_switch
        // forward or flood it.
        SRV6_BH_END_DT2U | SRV6_BH_END_DT2M => return srv6_dt2u(ctx, &sid),
        SRV6_BH_END_M => return srv6_endm(ctx, &sid),
        SRV6_BH_END_DT4 | SRV6_BH_END_DT6 | SRV6_BH_END_DT46 => {}
        _ => return Ok(xdp_action::XDP_PASS),
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
        if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) }
            != 0
        {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        let meta = xdp_meta_ptr(ctx)?;
        unsafe {
            (*meta).magic = XDP_META_MAGIC ^ meta_cookie();
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
///
/// Flavors (RFC 8986 §4.16, `sid.flavors`): PSP pops the SRH when this
/// node's decrement exhausts it; USP pops an already-exhausted SRH before
/// local delivery; USD decapsulates the outer IPv6 (+SRH) at the ultimate
/// segment and forwards the inner packet by the main table. USP/USD act on
/// End/uN only — their End.X variants would forward the result via the
/// adjacency (a different code path, incl. an IPv4 adjacency forward) and
/// are not implemented; End.X/uA SIDs carry only the PSP bit.
#[inline(always)]
fn srv6_end(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    let ult_ok = !matches!(sid.behavior, SRV6_BH_END_X | SRV6_BH_UA | SRV6_BH_UALIB);
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    if outer_nh != IPPROTO_ROUTING {
        // No SRH. USD still decapsulates a bare IP-in-IPv6 addressed to the
        // SID (§4.16.3 upper-layer processing); anything else is a
        // misconfiguration — pass to the stack.
        if sid.flavors & SRV6_FLAVOR_USD != 0 && ult_ok {
            let inner_et = match outer_nh {
                IPPROTO_IPIP => ETH_P_IP,
                IPPROTO_IPV6 => ETH_P_IPV6,
                _ => return Ok(xdp_action::XDP_PASS),
            };
            decap_head(ctx, IP6_HDR_LEN, inner_et)?;
            stat_inc(STAT_SRV6_USD);
            return endt_meta(ctx, sid);
        }
        return Ok(xdp_action::XDP_PASS);
    }
    let sl = unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? };
    if sl == 0 {
        // Ultimate segment. USD decapsulates when the payload is IP (tried
        // first, per the RFC's USP&USD composite); USP pops the exhausted
        // SRH so local delivery takes a clean packet (no `seg6_enabled`
        // needed). Without a flavor: pass untouched, today's behavior.
        let ext_len = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 1)? };
        if ext_len > 12 {
            return Ok(xdp_action::XDP_PASS);
        }
        if sid.flavors & SRV6_FLAVOR_USD != 0 && ult_ok {
            let srh_nh = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF)? };
            let inner_et = match srh_nh {
                IPPROTO_IPIP => Some(ETH_P_IP),
                IPPROTO_IPV6 => Some(ETH_P_IPV6),
                _ => None, // non-IP payload — fall through to USP
            };
            if let Some(et) = inner_et {
                decap_head(ctx, IP6_HDR_LEN + 8 * (ext_len as usize + 1), et)?;
                stat_inc(STAT_SRV6_USD);
                return endt_meta(ctx, sid);
            }
        }
        if sid.flavors & SRV6_FLAVOR_USP != 0 && ult_ok {
            pop_srh(ctx)?;
            stat_inc(STAT_SRV6_USP);
        }
        return Ok(xdp_action::XDP_PASS);
    }
    if sl as usize > MAX_SEGS {
        return Ok(xdp_action::XDP_PASS);
    }
    let new_sl = sl - 1;
    // segment_list[new_sl] becomes the new destination.
    let next_seg = unsafe { *xdp_ptr::<[u8; 16]>(ctx, SRH_SEGLIST_OFF + 16 * new_sl as usize)? };
    unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? = new_sl };
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? = next_seg };
    stat_inc(STAT_SRV6_END);

    // PSP: this node's decrement exhausted the SRH — pop it so the final
    // segment receives a clean, SRv6-free packet. Composes with End.X (the
    // pop lands before the adjacency redirect; every access below re-derives
    // its pointers after the adjust_head).
    if new_sl == 0 && sid.flavors & SRV6_FLAVOR_PSP != 0 {
        pop_srh(ctx)?;
        stat_inc(STAT_SRV6_PSP);
    }

    if !matches!(sid.behavior, SRV6_BH_END_X | SRV6_BH_UA) {
        // End (and the uN end-of-carrier fallback): forward by the new DA —
        // the TC FIB stage does the redirect + hop limit decrement. End.T
        // (and a table-bound uN — zebra's uT) scopes that lookup to the
        // SID's table (RFC 8986 §4.3 S15.1).
        return endt_meta(ctx, sid);
    }

    // End.X / uA: forward straight out the SID's cross-connect adjacency.
    srv6_forward_adjacency(ctx, sid.nexthop_id)
}

/// RFC 8986 §4.3 S15.1 — scope the upcoming TC forward to the SID's table.
/// Applies to `End.T` and to a `uN` whose `vrf_id` is set (zebra's uT);
/// everything else (including table 0) passes untouched. Uses the same
/// XDP→TC metadata channel as the DT decap path.
#[inline(always)]
fn endt_meta(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    if sid.vrf_id == 0 || !matches!(sid.behavior, SRV6_BH_END_T | SRV6_BH_UN) {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) } != 0
    {
        stat_inc(STAT_DROP);
        return Ok(xdp_action::XDP_DROP);
    }
    let meta = xdp_meta_ptr(ctx)?;
    unsafe {
        (*meta).magic = XDP_META_MAGIC ^ meta_cookie();
        (*meta).vrf_id = sid.vrf_id;
    }
    stat_inc(STAT_SRV6_ENDT);
    Ok(xdp_action::XDP_PASS)
}

/// Pop the SRH from an IPv6 packet whose Routing header immediately follows
/// the base header (the PSP/USP flavors): patch the base header's
/// next_header / payload_len in place — both sit inside the 54-byte block
/// that slides next, so the patched values move with it — then slide the
/// Ethernet + IPv6 headers forward over the SRH and trim the vacated bytes.
/// The header block is staged through a stack copy: for SRHs shorter than
/// 54 bytes the source and destination ranges overlap, so memmove semantics
/// are mandatory, not stylistic.
#[inline(always)]
fn pop_srh(ctx: &XdpContext) -> Result<(), ()> {
    let srh_nh = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF)? };
    let ext_len = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 1)? };
    if ext_len > 12 {
        return Err(());
    }
    let srh_len = 8 * (ext_len as usize + 1); // [8, 104]
    let payload_len = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, IP6_PAYLOAD_LEN_OFF)? });
    if (payload_len as usize) < srh_len {
        return Err(()); // malformed — the subtraction below would wrap
    }
    unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? = srh_nh };
    unsafe { *xdp_ptr::<u16>(ctx, IP6_PAYLOAD_LEN_OFF)? = (payload_len - srh_len as u16).to_be() };
    let hdr = unsafe { *xdp_ptr::<[u8; 54]>(ctx, 0)? };
    unsafe { *xdp_ptr::<[u8; 54]>(ctx, srh_len)? = hdr };
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, srh_len as i32) } != 0 {
        return Err(());
    }
    Ok(())
}

/// Forward the (rewritten) IPv6 packet out an SRv6 cross-connect adjacency
/// (`End.X` / `uA`): resolve `nexthop_id`'s L2, decrement the outer hop limit
/// (this path skips the TC forward), rewrite the Ethernet header, and redirect
/// out the adjacency's oif. Falls back to `XDP_PASS` if the nexthop or its
/// neighbor is unresolved, or the hop limit is exhausted.
#[inline(always)]
fn srv6_forward_adjacency(ctx: &XdpContext, nexthop_id: u32) -> Result<u32, ()> {
    let nh: NextHop = match NEXTHOPS.get_ptr(&nexthop_id) {
        Some(n) => unsafe { *n },
        None => return Ok(xdp_action::XDP_PASS),
    };
    let Some((dst_mac, src_mac)) = xdp_resolve_l2(&nh) else {
        return Ok(xdp_action::XDP_PASS);
    };
    let hop = unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? };
    if hop <= 1 {
        return Ok(xdp_action::XDP_PASS);
    }
    unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? = hop - 1 };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_DST_OFF)? = dst_mac };
    unsafe { *xdp_ptr::<[u8; 6]>(ctx, ETH_SRC_OFF)? = src_mac };
    Ok(unsafe { bpf_redirect(nh.oif, 0) } as u32)
}

/// Read the C-SID at position `pos` of the packed container `Segment
/// List[sl_idx]` (RFC 9800 §4.2: position `p` occupies bits
/// `[p*LNFL, (p+1)*LNFL)` of the 128-bit entry, bit 0 = MSB). 16-bit C-SIDs
/// zero-extend to u32 so one zero test covers both widths. `idx_mask` is
/// `K - 1` (3 → 32-bit C-SIDs, 7 → 16-bit), doubling as the position bound.
#[inline(always)]
fn replace_pos(ctx: &XdpContext, sl_idx: u8, pos: u8, idx_mask: u8) -> Result<u32, ()> {
    let entry = SRH_SEGLIST_OFF + 16 * (sl_idx & 7) as usize;
    if idx_mask == 3 {
        let b = unsafe { *xdp_ptr::<[u8; 4]>(ctx, entry + 4 * (pos & 3) as usize)? };
        Ok(u32::from_be_bytes(b))
    } else {
        let b = unsafe { *xdp_ptr::<[u8; 2]>(ctx, entry + 2 * (pos & 7) as usize)? };
        Ok(u16::from_be_bytes(b) as u32)
    }
}

/// Write a C-SID into the DA bits `[block, block + LNFL)` (byte-aligned
/// block; RFC 9800 R20 — only the C-SID bits change, Block and Argument
/// stay).
#[inline(always)]
fn write_csid(ctx: &XdpContext, block_bytes: usize, csid: u32, idx_mask: u8) -> Result<(), ()> {
    let off = IP6_DST_OFF + (block_bytes & 15);
    if idx_mask == 3 {
        unsafe { *xdp_ptr::<[u8; 4]>(ctx, off)? = csid.to_be_bytes() };
    } else {
        unsafe { *xdp_ptr::<[u8; 2]>(ctx, off)? = (csid as u16).to_be_bytes() };
    }
    Ok(())
}

/// One `srv6_replace_once` outcome: a final verdict, or "the rewritten DA
/// may be served by this same node — look it up and run again".
enum ReplaceStep {
    Act(u32),
    Redispatch,
}

/// SRv6 `End` / `End.X` with REPLACE-C-SID (RFC 9800 §4.2.1 / §4.2.2). The
/// DA is Block | C-SID | Argument, the argument's last bits indexing the
/// active C-SID within the packed container at `Segment List[SL]`. Non-zero
/// index: decrement it and rewrite only the C-SID bits of the DA from the
/// container (R05/R20); a zero position there means the container ended
/// early and the *next* list entry — a full 128-bit SID — becomes the DA
/// wholesale (R06–R10). Index zero: advance to the next container, SL-- and
/// index := K-1 (R12–R17). PSP composes at both rewrite points with the
/// §4.2.8 condition (last C-SID of the last container — position 0 or zero
/// padding next); USP/USD apply at the ultimate segment, End only, like the
/// classic flavors. Malformed geometry or bounds PASS to the stack instead
/// of raising ICMP errors, consistent with the rest of the datapath.
///
/// The R06 full-DA load can land on a SID of this very node (typically the
/// final destination whose ultimate-segment flavors must still run), so it
/// re-dispatches once — the same-node pattern `srv6_un` uses, mirroring the
/// kernel's local re-input after `seg6_lookup_nexthop`.
#[inline(always)]
fn srv6_replace(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    let mut cur: LocalSid = *sid;
    for _ in 0..2 {
        match srv6_replace_once(ctx, &cur)? {
            ReplaceStep::Act(a) => return Ok(a),
            ReplaceStep::Redispatch => {
                let da = unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? };
                match SRV6_LOCALSID.get(&Key::new(128, da)) {
                    Some(n) if matches!(n.behavior, SRV6_BH_END_REP | SRV6_BH_END_X_REP) => {
                        cur = *n;
                    }
                    _ => {
                        // Not served here — finish this SID's forward.
                        if cur.behavior == SRV6_BH_END_X_REP {
                            return srv6_forward_adjacency(ctx, cur.nexthop_id);
                        }
                        return Ok(xdp_action::XDP_PASS);
                    }
                }
            }
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// A single REPLACE-C-SID endpoint pass — see `srv6_replace`.
#[inline(always)]
fn srv6_replace_once(ctx: &XdpContext, sid: &LocalSid) -> Result<ReplaceStep, ()> {
    use ReplaceStep::Act;
    let is_x = sid.behavior == SRV6_BH_END_X_REP;
    let lb = sid.block_bits as usize;
    let csid_bits = sid.node_bits as usize + sid.fun_bits as usize;
    let idx_mask: u8 = match csid_bits {
        32 => 3, // K = 4 positions per container, 2 index bits
        16 => 7, // K = 8 positions per container, 3 index bits
        _ => return Ok(Act(xdp_action::XDP_PASS)),
    };
    // Byte-aligned Block, C-SID inside the DA and clear of the index bits
    // in its last byte.
    if lb % 8 != 0 || lb + csid_bits > 120 {
        return Ok(Act(xdp_action::XDP_PASS));
    }
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    if outer_nh != IPPROTO_ROUTING {
        // No SRH: the index argument is ignored and upper-layer processing
        // is plain RFC 8986 (§4.2) — USD decapsulates bare IP-in-IPv6.
        if sid.flavors & SRV6_FLAVOR_USD != 0 && !is_x {
            let inner_et = match outer_nh {
                IPPROTO_IPIP => ETH_P_IP,
                IPPROTO_IPV6 => ETH_P_IPV6,
                _ => return Ok(Act(xdp_action::XDP_PASS)),
            };
            decap_head(ctx, IP6_HDR_LEN, inner_et)?;
            stat_inc(STAT_SRV6_USD);
        }
        return Ok(Act(xdp_action::XDP_PASS));
    }
    let ext_len = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 1)? };
    if ext_len > 12 {
        return Ok(Act(xdp_action::XDP_PASS));
    }
    let sl = unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? };
    let idx = unsafe { *xdp_ptr::<u8>(ctx, IP6_DST_OFF + 15)? } & idx_mask;
    if sl == 0 && (idx == 0 || (ext_len >= 2 && replace_pos(ctx, 0, idx - 1, idx_mask)? == 0)) {
        // Ultimate segment (S02): the DA holds the last C-SID of the last
        // container. USD first, then USP, then plain delivery — End only.
        if sid.flavors & SRV6_FLAVOR_USD != 0 && !is_x {
            let srh_nh = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF)? };
            let inner_et = match srh_nh {
                IPPROTO_IPIP => Some(ETH_P_IP),
                IPPROTO_IPV6 => Some(ETH_P_IPV6),
                _ => None, // non-IP payload — fall through to USP
            };
            if let Some(et) = inner_et {
                decap_head(ctx, IP6_HDR_LEN + 8 * (ext_len as usize + 1), et)?;
                stat_inc(STAT_SRV6_USD);
                return Ok(Act(xdp_action::XDP_PASS));
            }
        }
        if sid.flavors & SRV6_FLAVOR_USP != 0 && !is_x {
            pop_srh(ctx)?;
            stat_inc(STAT_SRV6_USP);
        }
        return Ok(Act(xdp_action::XDP_PASS));
    }
    if ext_len < 2 || sl as usize > MAX_SEGS {
        return Ok(Act(xdp_action::XDP_PASS)); // container access needs a real SRH
    }
    let last_entry = unsafe { *xdp_ptr::<u8>(ctx, SRH_LAST_ENTRY_OFF)? };
    let max_le = ext_len / 2 - 1;
    if idx != 0 {
        // R01–R11: consume the next position of the current container.
        if last_entry > max_le || sl > last_entry {
            return Ok(Act(xdp_action::XDP_PASS));
        }
        let nidx = idx - 1;
        let csid = replace_pos(ctx, sl, nidx, idx_mask)?;
        if csid == 0 {
            // R06: zero position — the sequence continues at the next list
            // entry, a full 128-bit SID; load it as the whole DA.
            if sl == 0 {
                return Ok(Act(xdp_action::XDP_PASS)); // unreachable: S02 above
            }
            let new_sl = sl - 1;
            let next =
                unsafe { *xdp_ptr::<[u8; 16]>(ctx, SRH_SEGLIST_OFF + 16 * new_sl as usize)? };
            unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? = new_sl };
            unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? = next };
            stat_inc(STAT_SRV6_REPLACE);
            // The full-DA path keeps the plain RFC 8986 PSP condition.
            if new_sl == 0 && sid.flavors & SRV6_FLAVOR_PSP != 0 {
                pop_srh(ctx)?;
                stat_inc(STAT_SRV6_PSP);
            }
            // The loaded SID may be served by this very node (its
            // ultimate-segment flavors must run) — re-dispatch.
            return Ok(ReplaceStep::Redispatch);
        }
        write_csid(ctx, lb / 8, csid, idx_mask)?;
        let da15 = unsafe { *xdp_ptr::<u8>(ctx, IP6_DST_OFF + 15)? };
        unsafe { *xdp_ptr::<u8>(ctx, IP6_DST_OFF + 15)? = (da15 & !idx_mask) | nidx };
        stat_inc(STAT_SRV6_REPLACE);
        // R20.1: the DA now holds the last C-SID of the last container.
        if sl == 0
            && sid.flavors & SRV6_FLAVOR_PSP != 0
            && (nidx == 0 || replace_pos(ctx, 0, nidx - 1, idx_mask)? == 0)
        {
            pop_srh(ctx)?;
            stat_inc(STAT_SRV6_PSP);
        }
    } else {
        // R12–R17: container exhausted — advance to the next one and
        // restart at its least significant position (K - 1).
        if last_entry > max_le || sl > last_entry + 1 || sl == 0 {
            return Ok(Act(xdp_action::XDP_PASS));
        }
        let new_sl = sl - 1;
        let nidx = idx_mask; // K - 1
        let csid = replace_pos(ctx, new_sl, nidx, idx_mask)?;
        unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? = new_sl };
        write_csid(ctx, lb / 8, csid, idx_mask)?;
        let da15 = unsafe { *xdp_ptr::<u8>(ctx, IP6_DST_OFF + 15)? };
        unsafe { *xdp_ptr::<u8>(ctx, IP6_DST_OFF + 15)? = (da15 & !idx_mask) | nidx };
        stat_inc(STAT_SRV6_REPLACE);
        // R20.1 with index K-1 can only pop via the zero-padding disjunct.
        if new_sl == 0
            && sid.flavors & SRV6_FLAVOR_PSP != 0
            && replace_pos(ctx, 0, nidx - 1, idx_mask)? == 0
        {
            pop_srh(ctx)?;
            stat_inc(STAT_SRV6_PSP);
        }
    }
    if is_x {
        // End.X with REPLACE-C-SID: out the SID's cross-connect adjacency.
        return srv6_forward_adjacency(ctx, sid.nexthop_id).map(Act);
    }
    Ok(Act(xdp_action::XDP_PASS))
}

/// SRv6 `End.B6.Encaps` — the Binding SID (RFC 8986 §4.13). Run the End
/// steps on the received SRH (hop-limit check + decrement, SL--, inner DA
/// from Segment List[new SL]) and then push a new outer IPv6 (+SRH)
/// carrying the bound SR Policy's segment list — read from `SRV6_ENCAP`
/// via `sid.nexthop_id`, the same entry shape the TC H.Encaps path
/// consumes. The pushed SRH is the Reduced form (§4.14: the first policy
/// SID rides only in the outer DA; a single-SID policy omits the SRH
/// entirely), matching `apply_hencap`. The outer source is the global
/// encap source (`SRV6_ENCAP_SRC`) — the RFC's per-SID source A is not
/// modeled. SL == 0 and no-SRH arrivals PASS to the stack (§4.1.1
/// upper-layer processing; the kernel would silently drop them). After
/// the push the packet PASSes to the TC FIB, which forwards by the new
/// outer DA — S19's "egress IPv6 FIB lookup".
#[inline(always)]
fn srv6_b6_encaps(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    if outer_nh != IPPROTO_ROUTING {
        return Ok(xdp_action::XDP_PASS); // no SRH — upper layer (S01 gate)
    }
    let ext_len = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 1)? };
    if !(2..=12).contains(&ext_len) {
        return Ok(xdp_action::XDP_PASS);
    }
    let sl = unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? };
    if sl == 0 || sl as usize > MAX_SEGS {
        return Ok(xdp_action::XDP_PASS); // S02: upper layer
    }
    // S09 bounds (Segments Left ≤ Last Entry + 1 tolerates reduced SRHs).
    let last_entry = unsafe { *xdp_ptr::<u8>(ctx, SRH_LAST_ENTRY_OFF)? };
    let max_le = ext_len / 2 - 1;
    if last_entry > max_le || sl > last_entry + 1 {
        return Ok(xdp_action::XDP_PASS);
    }
    let hop = unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? };
    if hop <= 1 {
        return Ok(xdp_action::XDP_PASS); // S05: hop limit exhausted
    }
    // The bound policy — validated before any packet mutation. Read through
    // the map pointer (the ~104-byte value would strain the stack).
    let enc: &Srv6Encap = match SRV6_ENCAP.get_ptr(&sid.nexthop_id) {
        Some(e) => unsafe { &*e },
        None => return Ok(xdp_action::XDP_PASS),
    };
    let n = enc.num_segs as usize;
    if n == 0 || n > MAX_SEGS || enc.mode == SRV6_ENCAP_MODE_INSERT {
        return Ok(xdp_action::XDP_PASS);
    }
    // Same post-guard barrier as `apply_hencap`: keep the segment loop's
    // constant latch alive for the verifier.
    let n = core::hint::black_box(n);
    let src: [u8; 16] = match SRV6_ENCAP_SRC.get(0) {
        Some(s) => *s,
        None => return Ok(xdp_action::XDP_PASS),
    };

    // S12–S14: the End steps on the received packet.
    let new_sl = sl - 1;
    let next_seg = unsafe { *xdp_ptr::<[u8; 16]>(ctx, SRH_SEGLIST_OFF + 16 * new_sl as usize)? };
    unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? = hop - 1 };
    unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? = new_sl };
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? = next_seg };

    // S15–S18: push the outer IPv6 (+ Reduced SRH) carrying the policy.
    let inner_len = (ctx.data_end() - ctx.data() - EthHdr::LEN) as u16;
    let srh_len = if n == 1 { 0 } else { 8 + 16 * (n - 1) };
    let grow = (IP6_HDR_LEN + srh_len) as i32;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, -grow) } != 0 {
        // No headroom: the walked packet continues un-bound (End result).
        return Ok(xdp_action::XDP_PASS);
    }
    // The original Ethernet header now sits `grow` bytes in; slide it back
    // to the new head (the ethertype stays IPv6).
    let macs = unsafe { *xdp_ptr::<[u8; 12]>(ctx, grow as usize)? };
    unsafe { *xdp_ptr::<[u8; 12]>(ctx, 0)? = macs };
    unsafe { *xdp_ptr::<u16>(ctx, ETH_TYPE_OFF)? = (ETH_P_IPV6 as u16).to_be() };
    let (outer_proto, payload_len) = if n == 1 {
        (IPPROTO_IPV6, inner_len)
    } else {
        (IPPROTO_ROUTING, inner_len + srh_len as u16)
    };
    unsafe { *xdp_ptr::<u32>(ctx, EthHdr::LEN)? = IP6_VER_TC_FL.to_be() };
    unsafe { *xdp_ptr::<u16>(ctx, IP6_PAYLOAD_LEN_OFF)? = payload_len.to_be() };
    unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? = outer_proto };
    unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? = 64 };
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_SRC_OFF)? = src };
    // Stage each SID through the stack: a direct map-value→packet copy at
    // a variable offset gets lowered to a byte loop whose intermediate
    // packet offsets go transiently negative, which the verifier rejects.
    let first_seg: [u8; 16] = enc.segs[0];
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? = first_seg };
    if n > 1 {
        // Reduced SRH (§4.14): segs[0] rides only in the outer DA.
        unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF)? = IPPROTO_IPV6 };
        unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 1)? = 2 * (n as u8 - 1) };
        unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 2)? = 4 }; // routing type 4
        unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? = n as u8 - 1 };
        unsafe { *xdp_ptr::<u8>(ctx, SRH_LAST_ENTRY_OFF)? = n as u8 - 2 };
        unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 5)? = 0 }; // flags
        unsafe { *xdp_ptr::<u16>(ctx, SRH_OFF + 6)? = 0 }; // tag
        // Reversed list, omitting segs[0]: segment_list[n-1-j] = segs[j].
        // The map index rides the constant-bounded loop counter; the
        // reversal lives in the packet offset, MASKED so the address is
        // not affine in `j` — otherwise LLVM rotates the loop into a
        // pointer induction whose reassociated base carries a negative
        // constant offset, which the verifier rejects on either pointer
        // kind (packet and map_value both demand a non-negative minimum).
        for j in 1..MAX_SEGS {
            if j >= n {
                break;
            }
            let seg: [u8; 16] = enc.segs[j];
            let off = (SRH_SEGLIST_OFF + 16 * (n - 1 - j)) & 0x1ff;
            unsafe { *xdp_ptr::<[u8; 16]>(ctx, off)? = seg };
        }
    }
    stat_inc(STAT_SRV6_B6);
    Ok(xdp_action::XDP_PASS)
}

/// SRv6 `End.DX4` / `End.DX6` — decapsulation and cross-connect (RFC 8986
/// §4.5 / §4.4): the per-CE VPN egress. Reach the inner packet (direct
/// proto or one *exhausted* SRH — a live SRH is a §4.4 S02 error, passed
/// to the stack in house style), check the family against the behavior,
/// resolve the SID's adjacency, then decapsulate and hand the exposed
/// packet straight to that adjacency — no FIB lookup and no TTL/hop-limit
/// decrement (the tunnel ingress charged the inner header already). The
/// adjacency is resolved BEFORE any packet mutation: an unresolved
/// nexthop must not leak a decapped packet into the main FIB.
#[inline(always)]
fn srv6_dx(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    let (inner_proto, strip) = if outer_nh == IPPROTO_ROUTING {
        let srh_nh = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF)? };
        let ext_len = unsafe { *xdp_ptr::<u8>(ctx, SRH_OFF + 1)? };
        let sl = unsafe { *xdp_ptr::<u8>(ctx, SRH_SL_OFF)? };
        if sl != 0 || ext_len > 12 {
            return Ok(xdp_action::XDP_PASS); // live/oversized SRH
        }
        (srh_nh, IP6_HDR_LEN + 8 * (ext_len as usize + 1))
    } else {
        (outer_nh, IP6_HDR_LEN)
    };
    let inner_et = match (inner_proto, sid.behavior) {
        (IPPROTO_IPIP, SRV6_BH_END_DX4) => ETH_P_IP,
        (IPPROTO_IPV6, SRV6_BH_END_DX6) => ETH_P_IPV6,
        _ => {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP); // family mismatch (§4.1.1)
        }
    };
    if NEXTHOPS.get_ptr(&sid.nexthop_id).is_none() {
        return Ok(xdp_action::XDP_PASS); // unbound adjacency — leave intact
    }
    decap_head(ctx, strip, inner_et)?;
    // The cross-connect finishes at the TC stage: an XDP `bpf_redirect`
    // toward a CE veth silently drops when the peer runs no NAPI (no XDP
    // program on the host side), while the skb-path TC redirect always
    // works. Hand the adjacency over in DX-typed metadata.
    if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) } != 0
    {
        stat_inc(STAT_DROP);
        return Ok(xdp_action::XDP_DROP);
    }
    let meta = xdp_meta_ptr(ctx)?;
    unsafe {
        (*meta).magic = XDP_META_MAGIC_DX ^ meta_cookie();
        (*meta).vrf_id = sid.nexthop_id;
    }
    stat_inc(STAT_SRV6_DX);
    Ok(xdp_action::XDP_PASS)
}

/// SRv6 `End.DX2` / `End.DX2V` — decapsulation and L2 cross-connect
/// (RFC 8986 §4.9 / §4.10): the EVPN VPWS (E-Line) egress. Strip the
/// outer Ethernet + IPv6 (reduced form, next-header 143 — an SRH-carried
/// inner passes, like End.DT2*), then emit the inner Ethernet frame RAW
/// on the attachment circuit: no FDB, no learning, no MAC rewrite. DX2's
/// AC is `sid.vrf_id` (an ifindex); DX2V reads the inner frame's 802.1Q
/// VID and selects the AC from the `DX2V` table keyed by
/// (`sid.vrf_id` = table id, VID) — the tag stays on the frame. The
/// emit finishes at the TC stage via DX2-typed metadata, like DX4/DX6
/// (an XDP redirect into a NAPI-less CE veth would silently drop).
#[inline(always)]
fn srv6_dx2(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    if outer_nh != IPPROTO_ETHERNET {
        return Ok(xdp_action::XDP_PASS); // SRH-carried L2 not handled yet
    }
    // Resolve the AC before mutating the packet.
    let strip = (EthHdr::LEN + IP6_HDR_LEN) as i32;
    let oif = if sid.behavior == SRV6_BH_END_DX2 {
        sid.vrf_id
    } else {
        // DX2V: the inner frame's 802.1Q VID picks the AC. The inner
        // Ethernet header sits right after the 54 outer bytes.
        let inner_et =
            u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, strip as usize + ETH_TYPE_OFF)? });
        if inner_et != ETH_P_8021Q {
            return Ok(xdp_action::XDP_PASS); // untagged — no VLAN to demux
        }
        let tci = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, strip as usize + EthHdr::LEN)? });
        let key = Dx2vKey {
            table: sid.vrf_id,
            vid: tci & 0x0fff,
            _pad: [0; 2],
        };
        match unsafe { DX2V.get(&key) } {
            Some(o) => *o,
            None => return Ok(xdp_action::XDP_PASS), // unknown VID
        }
    };
    if oif == 0 {
        return Ok(xdp_action::XDP_PASS);
    }
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, strip) } != 0 {
        return Err(());
    }
    stat_inc(STAT_SRV6_DX2);
    if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) } != 0
    {
        stat_inc(STAT_DROP);
        return Ok(xdp_action::XDP_DROP);
    }
    let meta = xdp_meta_ptr(ctx)?;
    unsafe {
        (*meta).magic = XDP_META_MAGIC_DX2 ^ meta_cookie();
        (*meta).vrf_id = oif;
    }
    Ok(xdp_action::XDP_PASS)
}

/// SRv6 `End.M` — the egress-protection mirror (draft-ietf-rtgwg-srv6-
/// egress-protection). The PLR repaired traffic that was headed to a FAILED
/// egress PE by H.Encaps'ing it toward this SID; the exposed packet is the
/// original service packet, still addressed to the dead PE's service SID.
/// Reproduce that PE's behavior locally: strip the repair encap, look the
/// exposed destination up in the mirror context (`sid.vrf_id`), and on a
/// DT-style hit run the service decap into the local VRF — two decaps in
/// one pass.
#[inline(always)]
fn srv6_endm(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    // Strip #1: the repair encap — outer IPv6 plus an exhausted SRH if the
    // PLR's encap carried one. The exposed packet must be IPv6 (the failed
    // PE's service-SID-addressed packet).
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    let (exposed_proto, strip) = if outer_nh == IPPROTO_ROUTING {
        let srh_nh = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN)? };
        let ext_len = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN + 1)? };
        let sl = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN + 3)? };
        if sl != 0 || ext_len > 12 {
            return Ok(xdp_action::XDP_PASS);
        }
        (srh_nh, IP6_HDR_LEN + 8 * (ext_len as usize + 1))
    } else {
        (outer_nh, IP6_HDR_LEN)
    };
    if exposed_proto != IPPROTO_IPV6 {
        return Ok(xdp_action::XDP_PASS);
    }
    // The exposed packet's destination = the protected PE's service SID.
    let exposed_da = unsafe { *xdp_ptr::<[u8; 16]>(ctx, strip + IP6_DST_OFF)? };
    let ment: MirrorEntry = match MIRROR.get(&Key::new(
        160,
        MirrorKey {
            ctx: sid.vrf_id,
            addr: exposed_da,
        },
    )) {
        Some(m) => *m,
        None => return Ok(xdp_action::XDP_PASS), // not a mirrored SID
    };
    decap_head(ctx, strip, ETH_P_IPV6)?;
    // Strip #2: the service encap itself (the dead PE's End.DT* semantics).
    let nh2 = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    let (inner_proto, strip2) = if nh2 == IPPROTO_ROUTING {
        let srh_nh = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN)? };
        let ext_len = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN + 1)? };
        let sl = unsafe { *xdp_ptr::<u8>(ctx, EthHdr::LEN + IP6_HDR_LEN + 3)? };
        if sl != 0 || ext_len > 12 {
            return Ok(xdp_action::XDP_PASS);
        }
        (srh_nh, IP6_HDR_LEN + 8 * (ext_len as usize + 1))
    } else {
        (nh2, IP6_HDR_LEN)
    };
    let inner_et = match (inner_proto, ment.behavior) {
        (IPPROTO_IPIP, SRV6_BH_END_DT4) | (IPPROTO_IPIP, SRV6_BH_END_DT46) => ETH_P_IP,
        (IPPROTO_IPV6, SRV6_BH_END_DT6) | (IPPROTO_IPV6, SRV6_BH_END_DT46) => ETH_P_IPV6,
        _ => {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
    };
    decap_head(ctx, strip2, inner_et)?;
    stat_inc(STAT_SRV6_ENDM);
    if ment.vrf_id != 0 {
        if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) }
            != 0
        {
            stat_inc(STAT_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        let meta = xdp_meta_ptr(ctx)?;
        unsafe {
            (*meta).magic = XDP_META_MAGIC ^ meta_cookie();
            (*meta).vrf_id = ment.vrf_id;
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// Shift the uSID (NEXT-C-SID) container in the IPv6 DA left by one micro-SID:
/// slide the address bytes after the locator block up by `node_bits`, exposing
/// the next micro-SID right after the block and zero-filling the vacated tail.
/// Returns `true` if the shift was applied. Only byte-aligned geometry is
/// handled (micro-SIDs are 16-bit; the block is 16/32/48 — usid locators cap
/// the block at 32, so /48 → block 32, node 16); other geometry returns
/// `false` (the caller passes the packet through). Constant ranges keep the
/// shift verifier-safe. Increments `STAT_SRV6_USID` when it shifts.
#[inline(always)]
fn srv6_usid_shift(ctx: &XdpContext, sid: &LocalSid) -> Result<bool, ()> {
    let da = unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? };
    let mut nda = da;
    match (sid.block_bits, sid.node_bits) {
        (16, 16) => {
            nda[2..14].copy_from_slice(&da[4..16]);
            nda[14] = 0;
            nda[15] = 0;
        }
        (32, 16) => {
            nda[4..14].copy_from_slice(&da[6..16]);
            nda[14] = 0;
            nda[15] = 0;
        }
        (48, 16) => {
            nda[6..14].copy_from_slice(&da[8..16]);
            nda[14] = 0;
            nda[15] = 0;
        }
        _ => return Ok(false), // unsupported uSID geometry
    }
    unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? = nda };
    stat_inc(STAT_SRV6_USID);
    Ok(true)
}

/// SRv6 uSID `uN` (NEXT-C-SID node transit): the DA's active micro-SID matched
/// this node's uN prefix. Shift the container and forward by the new DA
/// (`XDP_PASS` → the TC FIB stage, which decrements the hop limit, as with
/// `End`). No SRH — the whole path rides in the DA carrier.
#[inline(always)]
fn srv6_un(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    // End-of-carrier (RFC 9800): if the uSID that would become active after
    // the shift is zero, the container is exhausted — behave as plain End
    // (SRH `Segments Left` walk restores the carried final destination,
    // e.g. a TI-LFA repair's original DA). Peek before shifting.
    let da = unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? };
    let block = (sid.block_bits / 8) as usize;
    let node = (sid.node_bits / 8) as usize;
    if block + node + 2 <= 16 && da[block + node] == 0 && da[block + node + 1] == 0 {
        return srv6_end(ctx, sid);
    }
    srv6_usid_shift(ctx, sid)?;
    // Same-node re-dispatch: the shift may expose one of THIS node's own
    // LIB micro-SIDs (a TI-LFA carrier packs `uN(r) + uA(r→x)`, both
    // anchored at r) — the new DA never leaves the box, so re-match it
    // against the local-SID table once. Only the adjacency form needs it;
    // anything else forwards by the FIB as usual.
    let nda = unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? };
    if let Some(next) = SRV6_LOCALSID.get(&Key::new(128, nda)) {
        if next.behavior == SRV6_BH_UALIB {
            let next = *next;
            return srv6_ua(ctx, &next);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

/// SRv6 uSID `uA` / `uALib` (NEXT-C-SID adjacency): the DA's active micro-SID
/// matched this node's adjacency uSID prefix. Shift the container (like `uN`),
/// then forward straight out the SID's cross-connect adjacency (like `End.X`)
/// rather than by the FIB. If the geometry is unsupported, pass the packet.
#[inline(always)]
fn srv6_ua(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    // End-of-carrier: shifting out this adjacency function would leave an
    // exhausted container — behave as classic End.X (SRH walk restores the
    // carried final destination, then out the adjacency). `srv6_end`
    // dispatches UA to the adjacency branch.
    let da = unsafe { *xdp_ptr::<[u8; 16]>(ctx, IP6_DST_OFF)? };
    let block = (sid.block_bits / 8) as usize;
    let node = (sid.node_bits / 8) as usize;
    if block + node + 2 <= 16 && da[block + node] == 0 && da[block + node + 1] == 0 {
        let mut end = *sid;
        end.behavior = SRV6_BH_UA; // adjacency branch in srv6_end
        return srv6_end(ctx, &end);
    }
    if !srv6_usid_shift(ctx, sid)? {
        return Ok(xdp_action::XDP_PASS);
    }
    srv6_forward_adjacency(ctx, sid.nexthop_id)
}

/// SRv6 `End.DT2U`/`End.DT2M` (EVPN over SRv6): the outer IPv6 DA matched a
/// local L2 service SID whose next-header is Ethernet (143). Strip the outer
/// Ethernet and outer IPv6 header so the inner Ethernet frame becomes the L2
/// frame, then tag the SID's bridge domain (`sid.vrf_id`) into the XDP→TC
/// metadata so the TC stage bridges it — a unicast inner MAC is forwarded
/// (`DT2U`), a broadcast/multicast one is flooded (`DT2M`), both by `l2_switch`.
/// MVP: reduced form only (no SRH).
#[inline(always)]
fn srv6_dt2u(ctx: &XdpContext, sid: &LocalSid) -> Result<u32, ()> {
    let outer_nh = unsafe { *xdp_ptr::<u8>(ctx, IP6_NEXTHDR_OFF)? };
    if outer_nh != IPPROTO_ETHERNET {
        return Ok(xdp_action::XDP_PASS); // SRH-carried L2 not handled yet
    }
    // Drop the outer eth + outer IPv6: the inner eth frame moves to the front.
    let strip = (EthHdr::LEN + IP6_HDR_LEN) as i32;
    if unsafe { bpf_xdp_adjust_head(ctx.ctx, strip) } != 0 {
        return Err(());
    }
    stat_inc(STAT_SRV6_L2_DECAP);
    // Carry the bridge domain to the TC l2_switch (mirrors the End.DT46 VRF meta).
    if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) } != 0
    {
        stat_inc(STAT_DROP);
        return Ok(xdp_action::XDP_DROP);
    }
    let meta = xdp_meta_ptr(ctx)?;
    unsafe {
        (*meta).magic = XDP_META_MAGIC_L2 ^ meta_cookie();
        (*meta).vrf_id = sid.vrf_id;
    }
    Ok(xdp_action::XDP_PASS)
}

/// `End.Replicate` (RFC 9524): the outer IPv6 DA matched a local Replication
/// SID. XDP can't `bpf_clone_redirect`, so leave the frame untouched (outer
/// header intact — the TC stage re-reads the DA to key `REPL_SEG`) and tag it
/// for the TC fan-out. Mirrors `endt_meta`'s XDP→TC hand-off.
#[inline(always)]
fn replicate_meta(ctx: &XdpContext) -> Result<u32, ()> {
    if unsafe { bpf_xdp_adjust_meta(ctx.ctx, -(core::mem::size_of::<CradleXdpMeta>() as i32)) } != 0
    {
        stat_inc(STAT_DROP);
        return Ok(xdp_action::XDP_DROP);
    }
    let meta = xdp_meta_ptr(ctx)?;
    unsafe {
        (*meta).magic = XDP_META_MAGIC_REPL ^ meta_cookie();
        (*meta).vrf_id = 0;
    }
    Ok(xdp_action::XDP_PASS)
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

/// RFC 1624 incremental one's-complement checksum update: given the current
/// header checksum `hc` and a 16-bit word changing from `old` to `new` (all in
/// host order), return the adjusted checksum. `HC' = ~(~HC + ~old + new)`.
#[inline(always)]
fn csum16_update(hc: u16, old: u16, new: u16) -> u16 {
    let mut sum: u32 = (!hc as u32) + (!old as u32 & 0xffff) + (new as u32);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

/// Uniform-model disposition (RFC 3443): write `ttl` into the IP header a pop
/// just exposed. `et` selects the family — IPv4 gets an incremental header
/// checksum fixup, IPv6 only the hop-limit byte; anything else (still MPLS)
/// no-ops. Must be called *after* `pop_head`, so offsets are relative to the
/// shifted frame.
#[inline(always)]
fn mpls_uniform_to_ip(ctx: &XdpContext, et: u16, ttl: u8) -> Result<(), ()> {
    if et == ETH_P_IP {
        // The 16-bit word at IP_TTL_OFF is [TTL, protocol] in network order.
        let old_word = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, IP_TTL_OFF)? });
        let new_word = (old_word & 0x00ff) | ((ttl as u16) << 8);
        if new_word == old_word {
            return Ok(());
        }
        let hc = u16::from_be(unsafe { *xdp_ptr::<u16>(ctx, IP_CSUM_OFF)? });
        let new_hc = csum16_update(hc, old_word, new_word);
        unsafe { *xdp_ptr::<u16>(ctx, IP_TTL_OFF)? = new_word.to_be() };
        unsafe { *xdp_ptr::<u16>(ctx, IP_CSUM_OFF)? = new_hc.to_be() };
    } else if et == ETH_P_IPV6 {
        unsafe { *xdp_ptr::<u8>(ctx, IP6_HOP_OFF)? = ttl };
    }
    Ok(())
}

/// PHP: pop one label and forward the remaining frame — still-MPLS or the
/// exposed IP — via the ILM's nexthop. Pipe-model TTL (default): nothing inner
/// is touched. Uniform: when the pop exposes IP, the popped label's TTL is
/// copied into the IP header, less one for this node's forward (this path
/// redirects directly, so it stands in for the IP FIB decrement).
#[inline(always)]
fn pop_and_forward(
    ctx: &XdpContext,
    nh: &NextHop,
    s: u8,
    ttl: u8,
    uniform: bool,
) -> Result<u32, ()> {
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
    // Uniform disposition (RFC 3443) only when the pop exposed IP (s == 1); the
    // helper no-ops for a still-labeled frame. `ttl` is >= 2 (the caller's
    // `ttl <= 1` guard), so `ttl - 1` stays >= 1.
    if uniform && s == 1 {
        mpls_uniform_to_ip(ctx, et, ttl - 1)?;
    }
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
