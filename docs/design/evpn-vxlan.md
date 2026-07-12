# cradle-rs EVPN/VXLAN support — design

> VXLAN bridging and routing in the eBPF data plane, driven by the zebra-rs
> BGP-EVPN control plane (Type-2/3/5, symmetric IRB, ingress replication).

Status: **Phase 1 (L2VNI bridging) implemented** — VXLAN encap/decap in XDP,
control-plane remote MACs, the BUM sentinel, and multi-VTEP ingress
replication, with the `cradle_evpn_vxlan`, `cradle_evpn_vxlan_bum`, and
`cradle_evpn_vxlan_multi` BDD features. Phases 2–4 (the zebra tee, symmetric
IRB, multihoming) remain design. This document describes the mechanism **as
built**; where the original proposal differed (a TC datapath, a tail-called
program, a `VNI_VTEPS` clone-fanout), the implemented EVPN-over-SRv6 twin
([evpn-srv6.md](evpn-srv6.md)) proved the better shape and this design now
follows it.

## Goal and scope

**EVPN** is a BGP control plane; **VXLAN** is the data-plane encapsulation
(MAC-in-UDP-in-IP). Together they extend an L2 domain — and, with IRB, L3 routing
— across an IP underlay. cradle-rs already switches L2 (FDB + VLAN flood) and
routes L3; EVPN/VXLAN adds (a) **VXLAN encap/decap** in the datapath, and (b) a
**control-plane-learned** forwarding database (BGP-EVPN replaces flood-and-learn
for remote MACs), including per-VNI ingress replication for BUM traffic.

The roles, by EVPN route type:

| EVPN route | Role | Data-plane action | zebra install today |
|---|---|---|---|
| **Type-2 (MAC/IP)** | L2 unicast (+ ARP/ND suppression) | remote MAC → remote VTEP (VXLAN FDB) | `mac_add` → kernel bridge+VXLAN FDB rows |
| **Type-3 (IMET)** | BUM | per-VNI ingress-replication slots | `mdb_add` → kernel zero-MAC FDB (append) |
| **Type-5 (IP prefix)** | L3 over the fabric | route the inner packet | plain **VRF IP route** (`route_ipv4/6_add`) |
| **Type-4 (ES) / AR** | multihoming, assisted replication | split-horizon, DF election | parsed only — no dataplane action |

Two things the zebra-rs exploration made clear, and this design accounts for:

- **Native L3VNI / RMAC symmetric IRB is *not* modeled in zebra-rs today.** A
  Type-5 prefix is imported as an ordinary VRF IP route, so L3-over-fabric works
  as underlay IP forwarding, not native VXLAN-routed encap. Phase 3's symmetric
  IRB is therefore a **cradle-native extension** (a capability zebra would grow
  into via a new tee call), not a mirror of an existing zebra install.
- **ARP/ND suppression** likewise: zebra relies on the bridge port's
  `neigh_suppress` and drops the Type-2 IP component, so it programs no IP→MAC
  answer. cradle can add real suppression — but only once the tee also forwards
  the Type-2 IP (a small zebra change).

## VXLAN packet format

VXLAN wraps the **entire inner Ethernet frame** as a UDP payload:

```
 Outer Eth | Outer IP (src=local VTEP, dst=remote VTEP) | UDP (dport 4789,
 sport=flow entropy) | VXLAN (flags, VNI:24) | Inner Eth | Inner payload
```

Encap prepends 50 bytes over an IPv4 underlay (14 + 20 + 8 + 8). The VNI (24-bit)
identifies the L2 segment (an L2VNI) or the routing domain (an L3VNI). The UDP
source port carries flow entropy from the inner MACs (RFC 7348 §5, the RFC 6335
dynamic range) so the underlay ECMP-hashes tunnels; the UDP checksum is 0
(legal over IPv4, §4.3 — the same choice as the GTP-U encap). The outer IPv4
header checksum comes from the shared `ipv4_hdr_csum` helper. No fragmentation
or PMTU handling: a grown frame exceeding the underlay MTU is dropped, the same
accepted limitation as the SRv6 L2 overlay.

## Map contract (`cradle-common`)

### 1. VNI ↔ bridge domain (both directions)

```rust
#[map] static VLAN_VNI: HashMap<u16 /* bd */, u32 /* vni */> = ...;   // encap
#[map] static VNI_INFO: HashMap<u32 /* vni */, VniInfo>      = ...;   // decap
#[map] static VXLAN_SRC: Array<[u8; 4]>                      = ...;   // [0] = local VTEP
```

`VLAN_VNI` maps an access port's bridge domain to its VNI for the **encap**
direction; `VNI_INFO` (`VniInfo { vlan }`, growing vrf_id/flags/rmac in
Phase 3 — maps are unpinned, so the ABI extends freely) maps a decapsulated
VNI back to its bridge domain. `VXLAN_SRC` all-zero means VXLAN is
unconfigured and the decap never claims a packet.

### 2. VXLAN FDB — remote MACs (Type-2)

`FdbEntry` did **not** grow a field: the remote VTEP IPv4 is stored
**v4-mapped** (`::ffff:a.b.c.d`, wire bytes at `remote_sid[12..16]`) in the
existing 16-byte `remote_sid`, discriminated by a new flag:

```rust
pub const FDB_F_VXLAN: u32 = 1 << 2;   // always together with FDB_F_REMOTE
```

A Type-2 route installs `FdbKey{mac, bd} → FdbEntry{FDB_F_REMOTE|FDB_F_VXLAN,
remote_sid: v4-mapped VTEP, oif: nexthop id (0 = FIB4 lookup)}`. Every
consumer keyed on `FDB_F_REMOTE` — the MAC-move displaced-local check, the
RFC 7432 §7.7 withdraw guard, aging, flush, `WatchFdb`, `dump l2` (which
renders the v4-mapped form legibly) — works unchanged. Local MACs keep
working exactly as before.

### 3. BUM — the sentinel and ingress-replication slots (Type-3)

The 2-PE form reuses the **all-ones-MAC FDB sentinel**: an
`ff:ff:ff:ff:ff:ff` entry with a VTEP makes BUM and unknown-unicast tunnel
to that single remote, exactly like the SRv6 `End.DT2M` sentinel.

Multi-VTEP fan-out reuses the **replication slots** of
[evpn-srv6.md](evpn-srv6.md) slice 5 — NOT a `VNI_VTEPS` clone-loop (the
original proposal's TC `clone_redirect`-with-rewrite cannot resize or re-encap
non-IP frames, and per-copy state has nowhere to live). The `REPL_SID` map's
value widened to a tagged target, the one cross-overlay ABI change:

```rust
pub struct ReplTarget {
    pub kind: u32,        // REPL_KIND_SRV6 = 0 (the old semantic), REPL_KIND_VXLAN = 1
    pub vni: u32,         // VXLAN only; SRv6's SID implies the bridge domain
    pub addr: [u8; 16],   // End.DT2M SID, or the VTEP v4-mapped
}
```

Each remote VTEP is a veth pair: the A end joins the bridge domain's flood
list (TC `clone_redirect` gives per-copy fan-out), the B end's XDP stage
VXLAN-encapsulates the arriving copy toward `{addr, vni}` — each copy builds
its full outer header from scratch, so there is no incremental
checksum-rewrite step. Split horizon is `flood()`'s existing `REPL_SID`
presence check: overlay-received frames flood local-only.

### 4. ARP/ND suppression (Phase 3)

```rust
#[map] static ARP_SUPPRESS: HashMap<ArpKey /* (vni, ip) */, [u8;6] /* mac */> = ...;
```

Not built yet — needs the Type-2 IP from the tee (see the zebra gap above).

## Data-plane logic (`cradle-ebpf`)

Both directions live **inline in the `cradle_xdp` stage** — not in TC, and
not in a tail-called program:

- TC's `bpf_skb_adjust_room` is `-ENOTSUPP` for non-IP skbs, and an L2
  domain carries ARP — the same constraint that put the MPLS pops and the
  SRv6 L2 encap in XDP (`bpf_xdp_adjust_head` is unrestricted).
- cradle uses no BPF tail calls anywhere; the repo deliberately chose
  monolithic programs with bpf2bpf calls
  ([tailcall-vs-monolithic.md](tailcall-vs-monolithic.md)).

### Decap (underlay → access): `try_vxlan_xdp`

The IPv4 EtherType arm of `try_xdp` is a UDP-dport dispatcher
(`try_udp4_xdp`): 2152 → GTP-U, 4789 → VXLAN. (The two decaps cannot be
*chained*, because a decap's success — `XDP_PASS` with metadata — is
indistinguishable from "not mine".) The VXLAN ladder:

1. Outer dst IP must equal `VXLAN_SRC[0]` — otherwise PASS, so **transit**
   VXLAN between other VTEPs keeps routing normally (load-bearing on a hub
   PE; the multi-VTEP BDD proves it).
2. VXLAN I-flag set; `vni = word1 >> 8`; `VNI_INFO[vni]` else PASS.
3. `bpf_xdp_adjust_head(+50)` — a plain strip; the inner frame carries its
   own Ethernet header (no MAC-slide, unlike GTP).
4. `stat_inc(STAT_VXLAN_DECAP)`; hand the bridge domain to the TC stage via
   `CradleXdpMeta{XDP_META_MAGIC_L2, bd}` — the same handoff as
   `End.DT2U`/`DT2M`, so `l2_switch(from_overlay=true)` gives split horizon
   and no-learning on the underlay port for free.

### Encap (access → core): `l2_overlay_encap` → `l2_vxlan_encap`

`l2_evpn_xdp` resolves the frame to one `(FdbEntry, bum?)` pair — known
remote unicast, or the sentinel for BUM/unknown-unicast — and encapsulates at
a **single** call site, dispatching on `FDB_F_VXLAN` between `l2_vxlan_encap`
and `l2_srv6_encap` (the VNI from `VLAN_VNI[bd]`). The VXLAN encap:

1. Underlay adjacency: the entry's explicit nexthop id, or a FIB4 **LPM**
   lookup on the VTEP (the underlay route the IGP installed). Deliberately
   the LPM trie directly, mirroring the SRv6 twin's FIB6 lookup — inlining
   the generic dir24-capable `fib4_lookup` would blow the stack budget
   (below); in dir24 mode a VXLAN FDB entry needs an explicit nexthop.
2. Grow 50 bytes at the head, write outer Ethernet (MACs from
   `NEIGH4`/`PORTS` via `xdp_resolve_l2`), IPv4 (`ipv4_hdr_csum`), UDP
   (dport 4789, entropy sport, checksum 0), and VXLAN (I-flag, `vni << 8`);
   `bpf_redirect` out the underlay. `stat_inc(STAT_VXLAN_ENCAP)`
   (`STAT_VXLAN_FLOOD` for BUM).

A replication-slot B-end runs the same `l2_vxlan_encap` with the slot's
`ReplTarget` (`oif` 0 → the FIB4 fallback).

### Verifier budget

Not a tail call — a **stack discipline**: `cradle_xdp`'s flattened frame must
stay ≤ 448 bytes (the 512-byte call-chain budget minus the 32-byte charges
for the entry stub and memset — the same arithmetic as `PolicyScratch6` on
the TC side). VXLAN initially tipped it over; what keeps it inside:

- one `l2_overlay_encap` call site in `l2_evpn_xdp` (each expansion inlines
  *both* encap bodies; there were three);
- `FdbEntry`/`NextHop`/`FibEntry` borrowed from map memory, not copied to
  stack (the copies were never atomic anyway);
- the direct FIB4 LPM lookup instead of the inlined dir24 engine.

### Packet geometry

XDP `adjust_head` for both grow and strip; re-load packet pointers after
every resize; every access through the bounds-checked `xdp_ptr`. Headroom
for the 50-byte grow rides veth XDP's `XDP_PACKET_HEADROOM` guarantee.

## Observability

```
STAT_VXLAN_ENCAP = 41   // access → core imposition (unicast)
STAT_VXLAN_DECAP = 42   // core → access disposition
STAT_VXLAN_FLOOD = 43   // BUM: sentinel tunnel or per-slot replication copy
```

Surfaced through `GetStats` / `cradle stats`, asserted by name in the BDD.
`dump l2` marks VXLAN entries with a `vxlan` flag and the v4-mapped VTEP.

## Control-plane API (gRPC)

The seam is the same `cradle.v1.Cradle` service. Rather than parallel
`AddEvpnMac`/`AddVniVtep` RPCs, the **existing EVPN messages gained a
`remote_vtep` field** (exactly one of `remote_sid`/`remote_vtep`), so the
Phase-2 zebra tee reuses the SRv6 call sites nearly verbatim — same
idempotency, same MAC-move hint, same `WatchFdb` reverse channel, same slot
lifecycle:

```proto
message FdbRemote {                       // Type-2 ↔ mac_add / mac_del
  string mac         = 1;
  uint32 bd          = 2;                 // = VNI in the zebra tee convention
  string remote_sid  = 3;                 // SRv6: End.DT2U/DT2M SID
  uint32 nexthop_id  = 4;                 // 0 = FIB lookup on the SID/VTEP
  string remote_vtep = 5;                 // VXLAN: remote VTEP IPv4
}
message ReplSlot {                        // Type-3 IMET ↔ mdb_add / mdb_del
  uint32 bd          = 1;
  string remote_sid  = 2;
  string remote_vtep = 3;                 // VNI resolved from the SetVni binding
}
message Vni  { uint32 vni = 1; uint32 vlan = 2; }   // ↔ vxlan_add + vni_filter_add
message VtepSource { string addr = 1; }              // fabric-wide local VTEP source

rpc SetVni(Vni)               returns (Empty);
rpc DelVni(VniDel)            returns (Empty);
rpc SetVtepSource(VtepSource) returns (Empty);
```

`AddReplSlot` with a `remote_vtep` requires the bd's `SetVni` binding first
(the VNI's single source of truth); a VXLAN slot is keyed in the slot
registry by its VTEP v4-mapped, so one registry and one `DelReplSlot` path
serve both overlays. The JSON bootstrap / `ctl apply` config gained `vnis`
and `vtep_source`; `FdbCfg` and `ReplSlotCfg` gained `remote_vtep` (slots
also take an explicit `vni` — static slots name ports, not a bridge domain).
The fabric is provable standalone before the zebra tee — the shipped BDD
features run exactly this way.

## Control-plane integration (zebra-rs, Phase 2)

zebra-rs runs BGP-EVPN and programs the overlay today through the **kernel
VXLAN netdev** (`external vnifilter` + `collect_metadata`) plus bridge
FDB/MDB neighbor messages. cradle **replaces** that kernel path with its own
eBPF maps, extending the `CradleFib` tee (gated by `system cradle-grpc`).
The mapping, mirroring the SRv6 tee one-for-one:

- **Type-2** (`FibHandle::mac_add` / `mac_del`) — fires the VXLAN branch when
  `tunnel_endpoint` is set and `srv6_sid` is not →
  `AddFdbRemote{remote_vtep}` / `DelFdbRemote`;
- **Type-3** (`mdb_add` / `mdb_del`, the misleadingly-named zero-MAC FDB
  list) — each peer VTEP → `Add`/`DelReplSlot{remote_vtep}`;
- **VNI / VTEP config** (`vxlan_add` + `vni_filter_add`,
  `register_vxlan_ifindex`) — VNI↔bridge binding + the local VTEP source →
  `SetVni` / `SetVtepSource`.

Two capabilities beyond what zebra drives today, each needing a small
zebra-side change to feed the tee:

- **ARP/ND suppression** — zebra drops the Type-2 IP (relying on kernel
  `neigh_suppress`); filling `ARP_SUPPRESS` needs the tee to forward MAC+IP;
- **symmetric IRB (L3VNI/RMAC)** — unmodeled in zebra (Type-5 is a plain VRF
  route); native VXLAN-routed IRB is cradle-defined and needs a new
  `SetVni`-with-RMAC + Type-5-with-VNI hook.

Route origination, RD/RT policy, DF election, and replication-mode selection
stay in zebra-rs; cradle executes the encap/decap/replication in eBPF — the
thesis, applied to the overlay.

## Symmetric IRB and VRF / L3VNI (Phase 3)

A routed packet whose FIB nexthop is a host/prefix behind a remote VTEP
resolves to a nexthop flagged `NH_F_VXLAN` carrying `{remote_vtep, l3vni,
remote_rmac}`: rewrite the inner dst MAC to the remote RMAC and src MAC to
the local RMAC, then VXLAN-encap with the L3VNI and forward as above. ARP/ND
for silent hosts is answered locally from `ARP_SUPPRESS`. Symmetric IRB
routes the inner packet in a VRF selected by the L3VNI (`VniInfo.vrf_id`),
sharing the per-VRF FIB mechanism with the MPLS and SRv6 L3VPN paths — the
three overlays build that seam once.

## Testing (BDD)

All three features run VXLAN with **no kernel vxlan device** and kernel
forwarding off — reachability proves the eBPF datapath — and end with the
mandatory `Scenario: Teardown topology`:

- **`cradle_evpn_vxlan`** — unicast: 2 VTEPs over one IPv4 hop, VNI 10100 on
  bd 100 (deliberately different numbers, proving the mapping), static CE
  ARP + static remote-MAC FDB. Asserts `vxlan_encap`@pe1, `vxlan_decap`@pe2,
  and the v4-mapped VTEP in `dump l2`.
- **`cradle_evpn_vxlan_bum`** — the sentinel: same topology, **no static
  ARP** — c1's broadcast ARP must ride the all-ones-MAC tunnel
  (`vxlan_flood`) for the ping to succeed; the reply then rides unicast.
- **`cradle_evpn_vxlan_multi`** — 3 VTEPs, pe1 the underlay hub, VTEP
  addresses `192.0.2.x` **eBPF-only** (reached via /32 routes — exercising
  the encap's FIB4 fallback), operator-created slot veths, no unicast FDB
  and no sentinel: pure flood-and-learn over per-copy replication. pe2↔pe3
  VXLAN transits pe1 as plain routed IPv4, proving the decap's local-VTEP
  check; convergence with bounded counters proves split horizon (a leak
  loops BUM between pe2 and pe3 forever).

Phase 2 adds the `cradle_evpn_vxlan_zebra` variant: a real BGP-EVPN session
teed over gRPC, mirroring `cradle_evpn_srv6_zebra`.

## Phasing

1. **Phase 1 — L2VNI datapath** *(done)*. `VLAN_VNI`/`VNI_INFO`/`VXLAN_SRC`,
   XDP encap/decap, `FDB_F_VXLAN` remote MACs, the sentinel, `ReplTarget`
   ingress replication, counters, gRPC (`SetVni`/`SetVtepSource` + extended
   `FdbRemote`/`ReplSlot`), static config, and the three BDD features.
2. **Phase 2 — BGP-EVPN L2 tee.** Wire the `CradleFib` tee for Type-2
   (`mac_add`) and Type-3 (`mdb_add`) so a real BGP-EVPN session programs
   the fabric — the integration zebra already supports.
3. **Phase 3 — symmetric IRB (cradle-native).** Per-VRF FIB, RMAC rewrite,
   `NH_F_VXLAN` nexthops, and ARP/ND suppression from Type-2 MAC+IP — plus
   the small zebra-side hooks to drive them.
4. **Phase 4 — multihoming & multicast.** EVPN Ethernet Segments (Type-4),
   split-horizon / DF election, SMET selective multicast (Type-6 /
   `mdb_install`), and assisted replication.
