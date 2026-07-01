# cradle-rs EVPN/VXLAN support — design

> VXLAN bridging and routing in the eBPF data plane, driven by the zebra-rs
> BGP-EVPN control plane (Type-2/3/5, symmetric IRB, ingress replication).

Status: **design / not yet implemented.** This proposes the map contract,
data-plane logic, control-plane API, and a phased plan. It builds on the existing
L2-switching and L3 datapath (see [architecture.md](architecture.md)) and reuses
mechanisms from the [MPLS](mpls.md) and [SRv6](srv6.md) designs (packet geometry,
the verifier tail-call, the VRF model, the zebra tee).

## Goal and scope

**EVPN** is a BGP control plane; **VXLAN** is the data-plane encapsulation
(MAC-in-UDP-in-IP). Together they extend an L2 domain — and, with IRB, L3 routing
— across an IP underlay. cradle-rs already switches L2 (FDB + VLAN flood) and
routes L3; EVPN/VXLAN adds (a) **VXLAN encap/decap** in the datapath, and (b) a
**control-plane-learned** forwarding database (BGP-EVPN replaces flood-and-learn
for remote MACs), including a per-VNI VTEP list for BUM traffic.

The roles, by EVPN route type:

| EVPN route | Role | Data-plane action | zebra install today |
|---|---|---|---|
| **Type-2 (MAC/IP)** | L2 unicast (+ ARP/ND suppression) | remote MAC → remote VTEP (VXLAN FDB) | `mac_add` → kernel bridge+VXLAN FDB rows |
| **Type-3 (IMET)** | BUM | per-VNI ingress-replication VTEP list | `mdb_add` → kernel zero-MAC FDB (append) |
| **Type-5 (IP prefix)** | L3 over the fabric | route the inner packet | plain **VRF IP route** (`route_ipv4/6_add`) |
| **Type-4 (ES) / AR** | multihoming, assisted replication | split-horizon, DF election | parsed only — no dataplane action |

Two things the exploration made clear, and this design accounts for:

- **Native L3VNI / RMAC symmetric IRB is *not* modeled in zebra-rs today.** A
  Type-5 prefix is imported as an ordinary VRF IP route, so L3-over-fabric works
  as underlay IP forwarding, not native VXLAN-routed encap. Phase 3's symmetric
  IRB is therefore a **cradle-native extension** (a capability zebra would grow
  into via a new tee call), not a mirror of an existing zebra install.
- **ARP/ND suppression** likewise: zebra relies on the bridge port's
  `neigh_suppress` and drops the Type-2 IP component, so it programs no IP→MAC
  answer. cradle can add real suppression — but only once the tee also forwards
  the Type-2 IP (a small zebra change).

## The MVP: L2VNI bridging with control-plane MACs

Phase 1 is the core EVPN use case — **L2 extension**: bridge a VLAN across VXLAN
between VTEPs, with remote MACs learned from BGP (Type-2) and BUM flooded by
ingress replication (Type-3). No IRB, no VRF, no multihoming. That is a complete,
demonstrable VXLAN fabric and exercises every hard mechanism (encap, decap,
replication) once. The BGP-EVPN L2 tee is Phase 2; symmetric IRB (L3VNI, RMAC,
ARP suppression) is Phase 3; multihoming and assisted replication are Phase 4.

## VXLAN packet format

VXLAN wraps the **entire inner Ethernet frame** as a UDP payload:

```
 Outer Eth | Outer IP (src=local VTEP, dst=remote VTEP) | UDP (dport 4789,
 sport=flow entropy) | VXLAN (flags, VNI:24) | Inner Eth | Inner payload
```

Encap prepends 50 bytes over an IPv4 underlay (14 + 20 + 8 + 8). The VNI (24-bit)
identifies the L2 segment (an L2VNI) or the routing domain (an L3VNI). UDP source
port carries flow entropy so the underlay ECMP-hashes tunnels.

## Map contract additions (`cradle-common`)

### 1. VNI ↔ bridge/VRF mapping

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VniInfo {
    pub vlan: u16,      // access bridge domain (L2VNI); 0 for pure L3VNI
    pub _pad: u16,
    pub vrf_id: u32,    // VRF (L3VNI); 0 for L2VNI
    pub flags: u32,     // VNI_F_L2 | VNI_F_L3
    pub rmac: [u8; 6],  // local router MAC (L3VNI / symmetric IRB)
    pub _pad2: [u8; 2],
}

#[map] static VNI_INFO: HashMap<u32 /* vni */, VniInfo>  = HashMap::with_max_entries(4096, 0);
#[map] static VLAN_VNI: HashMap<u16 /* vlan */, u32 /* vni */> = HashMap::with_max_entries(4096, 0);
```

`VLAN_VNI` maps an access port's bridge domain to its VNI for the **encap**
direction; `VNI_INFO` maps a decapsulated VNI back to its bridge/VRF.

### 2. VXLAN FDB — remote MACs (Type-2)

The existing `FdbEntry` gains a remote-VTEP target and a flag, so one FDB serves
both local switching and EVPN:

```rust
pub struct FdbEntry {
    pub oif: u32,
    pub flags: u32,          // + FDB_F_REMOTE
    pub remote_vtep: u32,    // new: remote VTEP IPv4 (when FDB_F_REMOTE)
}
pub const FDB_F_REMOTE: u32 = 1 << 1;
```

A Type-2 route installs `FdbKey{mac, vlan} → FdbEntry{FDB_F_REMOTE, remote_vtep}`;
the switch path, on a remote hit, VXLAN-encaps toward `remote_vtep` instead of
`bpf_redirect`. Local MACs keep working exactly as today.

### 3. BUM ingress-replication list (Type-3)

Mirrors the existing L2 flood maps, but the members are **remote VTEPs**:

```rust
#[map] static VNI_VTEPS:      HashMap<VniVtepKey /* (vni, slot) */, u32 /* vtep */> = ...;
#[map] static VNI_VTEP_COUNT: HashMap<u32 /* vni */, u32>                           = ...;
```

This per-VNI bounded VTEP list is exactly the *shape* of zebra-rs's
`offload/tc-evpn-replicate` map (`REPL_SEG[vni] = { root, leaves[MAX_LEAVES=32] }`,
fed by an idempotent `repl-add <vni> … <leaf-ip>…` line protocol from a
control-plane supervisor). Note, though, that that offload is an **SR-P2MP**
(`End.Replicate` / `End.DT2M`) forwarder, used only when `bum-tunnel-type` is
`sr-*-p2mp`; zebra's *plain-VXLAN* BUM path is instead kernel FDB zero-MAC entries
appended per peer VTEP (`mdb_add`). cradle adopts the offload's clean per-VNI
leaf-list **structure** while functionally replacing the kernel-FDB VXLAN BUM path
with eBPF. `MAX_LEAVES = 32` is a sensible starting fan-out bound.

### 4. ARP/ND suppression (Type-2 MAC+IP) and local VTEP

```rust
#[map] static ARP_SUPPRESS: HashMap<ArpKey /* (vni, ip) */, [u8;6] /* mac */> = ...;
#[map] static VXLAN_LOCAL:   Array<VtepConfig>  // [0] = { vtep_src_ip }
```

### New maps summary

| Map | Key | Value | From |
|---|---|---|---|
| `VNI_INFO` | `u32` vni | `VniInfo` | VNI config |
| `VLAN_VNI` | `u16` vlan | `u32` vni | VNI config |
| `FDB` *(extended)* | `(mac, vlan)` | `FdbEntry{+remote_vtep}` | Type-2 |
| `VNI_VTEPS` / `_COUNT` | `(vni, slot)` / `vni` | `u32` vtep | Type-3 |
| `ARP_SUPPRESS` | `(vni, ip)` | `[u8;6]` | Type-2 MAC+IP |
| `VXLAN_LOCAL` | `0` | `VtepConfig` | config |

## Data-plane logic (`cradle-ebpf`)

VXLAN encap/decap and replication are heavy — this runs in a tail-called
`cradle_vxlan` program (see Verifier). Two entry triggers:

### Decap (underlay → access)

A packet on an L3 (underlay) port whose outer dst IP is the local VTEP and whose
UDP dport is `4789`:

1. Parse the VXLAN header → `vni`.
2. Strip the outer encapsulation (outer Eth + IP + UDP + VXLAN), exposing the
   **inner Ethernet frame** (`adjust_room`; VXLAN decap in TC is a known pattern).
3. Look up `VNI_INFO[vni]`:
   - **L2VNI** — bridge the inner frame in `vlan`'s domain: FDB lookup on the
     inner dst MAC → local access `oif` → `bpf_redirect`; BUM → flood to local
     access ports only (**split-horizon**: never re-encap back to the core).
   - **L3VNI** *(Phase 3)* — the inner dst MAC is the local `rmac`; route the
     inner IP packet in `vrf_id`.

`stat_inc(STAT_VXLAN_DECAP)`.

### Encap (access → core)

A frame from a local access port in a bridge domain mapped to a VNI (`VLAN_VNI`):

1. FDB lookup `(inner_dst_mac, vlan)`:
   - **local `oif`** — bridge locally (the existing L2 path);
   - **`FDB_F_REMOTE`** — VXLAN-encap toward `remote_vtep`;
   - **BUM / unknown / multicast** — **ingress replication**: for each VTEP in
     `VNI_VTEPS[vni]`, send an encapped copy; also flood to local access ports.
2. **VXLAN encap** — grow room by 50 bytes (`adjust_room`, `BPF_ADJ_ROOM_MAC`
   with the `ENCAP_L3_IPV4 | ENCAP_L4_UDP | ENCAP_L2_ETH` flags), then write the
   outer IPv4 (src = `VXLAN_LOCAL.vtep_src_ip`, dst = `remote_vtep`), UDP
   (dport 4789, sport = inner-flow hash for entropy), and VXLAN (VNI) headers.
3. **Underlay delivery** — the encapped frame is now an ordinary IPv4 packet, so
   re-enter `l3_forward_v4`: it LPM-looks-up the VTEP, resolves the underlay
   nexthop, and `bpf_redirect_neigh`s. No new underlay machinery — VXLAN reuses
   the IP forwarding tail (the same trick SRv6 uses after `H.Encaps`).

`stat_inc(STAT_VXLAN_ENCAP)` (and `STAT_VXLAN_FLOOD` on replication).

### BUM ingress replication

Bounded like the existing L2 flood (`MAX` members / one adjust per copy). Encap
toward the first VTEP in place, then `clone_redirect` a copy per additional VTEP
with the outer dst IP + checksum rewritten — mirroring zebra-rs's
`tc-evpn-replicate` fan-out. Split-horizon drops any BUM frame that arrived from
the core (it must not be reflected back).

### Symmetric IRB (Phase 3, cradle-native)

This capability has no zebra driver today (zebra installs Type-5 as a plain VRF
route), so it is a cradle-native extension gated behind the new tee hook. A routed
packet whose FIB nexthop is a host/prefix behind a remote VTEP resolves to a
nexthop flagged `NH_F_VXLAN` carrying `{remote_vtep, l3vni, remote_rmac}`:
rewrite the inner dst MAC to the remote RMAC and src MAC to the local RMAC, then
VXLAN-encap with the L3VNI and forward as above. ARP/ND for silent hosts is
answered locally from `ARP_SUPPRESS` (Type-2 MAC+IP), so the datapath never
floods an ARP across the fabric.

### Packet geometry

Encap uses `bpf_skb_adjust_room` with the kernel's `ENCAP_*` flags (build an
outer IPv4/UDP and preserve the inner Ethernet as `ENCAP_L2_ETH`), then
`bpf_skb_store_bytes` for the header fields — the standard TC VXLAN-encap recipe.
Decap is the inverse pop. The usual skb-resize rules apply: adjust before write,
re-load pointers after, keep writes inside re-validated bounds.

### Verifier budget

Header build (encap), header parse + inner discovery (decap), and the replication
fan-out clearly exceed the single-classifier budget, so VXLAN lives in a
**tail-called `cradle_vxlan`** program, entered on the two triggers (UDP:4789 to
the local VTEP; an access frame whose VLAN maps to a VNI). This keeps the L2/L3
fast paths lean.

## Observability

```
STAT_VXLAN_ENCAP   // access → core imposition
STAT_VXLAN_DECAP   // core → access disposition
STAT_VXLAN_FLOOD   // BUM ingress replication
```

Surfaced through `GetStats` / `cradle ctl stats`, and used by the BDD suite to
assert which VXLAN action handled a packet.

## Control-plane API (gRPC)

The seam is the same `cradle.v1.Cradle` service. EVPN adds RPCs that mirror
zebra-rs's real FibHandle calls (`mac_add`, `mdb_add`, `vxlan_add` +
`vni_filter_add`):

```proto
message Vni {                 // ↔ vxlan_add + vni_filter_add
  uint32 vni        = 1;
  uint32 vlan       = 2;   // access bridge domain (L2VNI)
  string local_vtep = 3;   // local VTEP source IP
  uint32 vrf_id     = 4;   // L3VNI (cradle-native IRB; see below)
  uint32 flags      = 5;   // VNI_F_L2 | VNI_F_L3
  string rmac       = 6;   // local router MAC (L3VNI, cradle-native)
}
message EvpnMac {             // Type-2  ↔ mac_add(vni, mac, tunnel_endpoint, flags, esi)
  uint32 vni         = 1;
  string mac         = 2;
  string remote_vtep = 3;   // tunnel endpoint VTEP (empty ⇒ withdraw)
  uint32 flags       = 4;   // sticky, ...
  bytes  esi         = 5;   // 10-byte Ethernet Segment ID (multihoming)
  string ip          = 6;   // Type-2 IP for ARP/ND suppression (see the gap note)
}
message VniVtep {             // Type-3 IMET member  ↔ mdb_add(vni, group=vtep)
  uint32 vni  = 1;
  string vtep = 2;          // append / remove one peer VTEP from the VNI's BUM list
}
message VtepSource { string addr = 1; }  // fabric-wide local VTEP source

rpc SetVni(Vni)               returns (Empty);
rpc AddEvpnMac(EvpnMac)       returns (Empty);   // ↔ mac_add / mac_del
rpc DelEvpnMac(EvpnMac)       returns (Empty);
rpc AddVniVtep(VniVtep)       returns (Empty);    // ↔ mdb_add / mdb_del
rpc DelVniVtep(VniVtep)       returns (Empty);
rpc SetVtepSource(VtepSource) returns (Empty);
```

`cradle`'s `Control`/`Dataplane` gain `vni_set`, `evpn_mac_add/del`,
`vni_vtep_add/del`, and `vtep_source_set`. The JSON bootstrap / `ctl apply`
config gains a `vnis` array (with static remote MACs and VTEP lists) and a
`vtep_source` field, so the fabric is provable standalone before the zebra tee.

> The `Vni`/`EvpnMac`/`VniVtep` shapes mirror zebra's `vxlan_add`+`vni_filter_add`,
> `mac_add`, and `mdb_add`. The **L3VNI / RMAC** fields (`vrf_id`, `rmac`) and the
> Type-2 `ip` have no zebra counterpart yet — symmetric IRB and ARP suppression
> are cradle-native, so those fields are defined fresh rather than mirrored.
> (Reconciled against the zebra-rs source.)

## Control-plane integration (zebra-rs)

zebra-rs runs BGP-EVPN and programs the overlay today through the **kernel VXLAN
netdev** (`external vnifilter` + `collect_metadata`) plus bridge FDB/MDB neighbor
messages — not eBPF maps. Its one eBPF offload, `offload/tc-evpn-replicate`, is
SR-P2MP-specific (`End.Replicate` / `End.DT2M`), fed by a `ReplicationHelper`
supervisor over an idempotent per-VNI line protocol. cradle **replaces** the
kernel-FDB VXLAN path with its own eBPF maps, extending the `CradleFib` tee (gated
by `system cradle-grpc`) so learned EVPN state flows into the cradle data plane.

The tee calls sit beside the existing netlink sends (or, more cleanly, at the RIB
message layer in `rib/inst.rs`, which owns the `mac_table` / `vtep_table` shadow
state):

- **Type-2** (`FibHandle::mac_add` / `mac_del`) — a remote MAC + its VTEP →
  `AddEvpnMac` / `DelEvpnMac`;
- **Type-3** (`mdb_add` / `mdb_del`, the misleadingly-named zero-MAC FDB list) —
  each peer VTEP → `AddVniVtep` / `DelVniVtep`;
- **VNI / VTEP config** (`vxlan_add` + `vni_filter_add`, `register_vxlan_ifindex`)
  — VNI↔bridge binding + the local VTEP source → `SetVni` / `SetVtepSource`.

Two capabilities this design adds that zebra does not drive yet, each needing a
small zebra-side change to feed the tee:

- **ARP/ND suppression** — zebra drops the Type-2 IP (relying on kernel
  `neigh_suppress`); filling `ARP_SUPPRESS` needs the tee to forward the MAC+IP;
- **symmetric IRB (L3VNI/RMAC)** — unmodeled in zebra (Type-5 is a plain VRF
  route); native VXLAN-routed IRB is cradle-defined and needs a new
  `SetVni`-with-RMAC + Type-5-with-VNI hook.

Route origination, RD/RT policy, DF election, and replication-mode selection stay
in zebra-rs; cradle executes the encap/decap/replication in eBPF — the thesis,
applied to the overlay.

## VRF / L3VNI (Phase 3)

Symmetric IRB routes the inner packet in a VRF selected by the L3VNI, so it needs
the same per-VRF FIB tables as the [MPLS](mpls.md) and [SRv6](srv6.md) L3VPN
paths — `VniInfo.vrf_id` selects the table. The three overlays therefore share one
VRF-FIB mechanism, built once. (As noted above, zebra-rs does not model L3VNI/RMAC
today, so this phase also entails a small zebra-side tee addition, not just cradle
work.)

## Testing (BDD)

A `cradle_evpn` feature: two VTEPs over an IP underlay, each with a local access
host in the same L2VNI —

```
 h1 ── vtep1 [cradle] ══(VXLAN/IPv4 underlay)══ vtep2 [cradle] ── h2
        VNI 100                                   VNI 100
```

Kernel VXLAN (`ip link add type vxlan`) stays **absent** on the VTEPs, so a ping
between `h1` and `h2` proves the *eBPF* data plane did the encap/decap — the same
"kernel forwarding off" trick the IP features use. Assert `vxlan_encap` /
`vxlan_decap` nonzero, and an ARP across the fabric drives `vxlan_flood` (ingress
replication). Drive it two ways: a static JSON config (VNIs, remote MACs, VTEP
list) to prove the datapath, then a zebra-rs BGP-EVPN session teed over gRPC to
prove the integration. Each scenario ends with the mandatory
`Scenario: Teardown topology`.

## Phasing

1. **Phase 1 — L2VNI datapath.** `VNI_INFO`/`VLAN_VNI`, VXLAN encap/decap, the
   extended `FDB` (remote MACs), `VNI_VTEPS` ingress replication, the
   `cradle_vxlan` tail-call, counters, gRPC (`SetVni`/`AddEvpnMac`/`AddVniVtep`/
   `SetVtepSource`), static config + `cradle_evpn` BDD (static).
2. **Phase 2 — BGP-EVPN L2 tee.** Wire the `CradleFib` tee for Type-2 (`mac_add`)
   and Type-3 (`mdb_add`) so a real BGP-EVPN session programs the fabric — the
   integration zebra already supports.
3. **Phase 3 — symmetric IRB (cradle-native).** Per-VRF FIB, RMAC rewrite,
   `NH_F_VXLAN` nexthops, and ARP/ND suppression from Type-2 MAC+IP — plus the
   small zebra-side hooks to drive them (L3VNI/RMAC and the Type-2 IP are not
   modeled in zebra today).
4. **Phase 4 — multihoming & multicast.** EVPN Ethernet Segments (Type-4),
   split-horizon / DF election, SMET selective multicast (Type-6 / `mdb_install`),
   and assisted replication.
