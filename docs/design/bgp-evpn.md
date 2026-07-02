# cradle-rs BGP EVPN for VXLAN — design

> The control-plane half of the overlay: how BGP EVPN routes in zebra-rs become
> VXLAN forwarding state in cradle's eBPF maps — in both directions, because
> with no kernel bridge, MAC learning itself moves into the data plane.

Status: **design / not yet implemented.** Companion to
[`evpn-vxlan.md`](evpn-vxlan.md), which designs the *data plane* (VXLAN
encap/decap, the map contract, the install-direction gRPC). This document
designs the *control plane*: the route → forwarding-state chain through
zebra-rs's BGP, the learn-direction feedback cradle must provide, and the
zebra-side gaps that gate each phase. Grounded in a full exploration of the
zebra-rs source; every claim below carries a file reference.

## Goal and scope

EVPN is BGP doing what flood-and-learn used to do: MAC reachability (Type-2),
BUM distribution trees (Type-3), and inter-subnet prefixes (Type-5) as BGP
routes. [`evpn-vxlan.md`](evpn-vxlan.md) already defines what cradle's datapath
does with that state (`FDB_F_REMOTE` entries, `VNI_VTEPS` replication lists,
per-VRF routes). What it left as "Phase 2 — BGP-EVPN L2 tee" this document
expands into a real design, because the tee turns out to be **two seams, not
one**:

- **Install direction** (zebra → cradle): received EVPN best paths become map
  writes. This mirrors plumbing zebra already has.
- **Learn direction** (cradle → zebra): Type-2 *origination* is fed by local
  MAC learning — which zebra today reads from the **kernel bridge** via
  netlink. cradle replaces the kernel bridge, so cradle must also replace the
  bridge's role as the learning event source.

The second seam is the novel content here. The design's punchline: cradle
impersonates the kernel bridge **on both sides of zebra's existing
interfaces**, so zebra's EVPN machinery — origination, best path, mobility,
withdraw — runs unmodified.

## What zebra-rs BGP already implements

The exploration found an EVPN stack well beyond RFC 7432 — RFC 9251 (SMET /
IGMP proxy), RFC 9572 (BUM segmentation), RFC 9574 (assisted replication),
RFC 9136 (Type-5). The status that matters for cradle:

| Piece | Status | Where |
|---|---|---|
| AFI 25 / SAFI 70, MP capability (default), Add-Path | implemented | `bgp-packet/src/afi.rs`, `bgp/cap.rs:39` |
| NLRI codec, route types 1–11, encode+decode | implemented | `bgp-packet/src/attrs/nlri_evpn.rs` |
| RT (`AS:VNI`) + VXLAN encap EC (tunnel type 8) | implemented | `route.rs:15580`, `route.rs:15598` |
| PMSI tunnel attr (IR / AR / SR-P2MP), VNI in Label | implemented | `bgp-packet/src/attrs/pmsi_tunnel.rs` |
| Type-2 origination from local FDB | implemented | `route.rs:14105` `evpn_originate_macip` |
| Type-3 IMET origination + flood reconcile | implemented | `route.rs:14366`, `evpn_flood.reconcile` |
| Type-2/3 install → kernel FDB/MDB | implemented | `rib/inst.rs:3301`, `fib/netlink/handle.rs:2696` |
| Type-5 origination + import (via VRF/VPN machinery) | implemented | `route.rs:14263`, `bgp/vrf/inst.rs:308` |
| Auto RD (`router-id:vni16`) / auto RT (`AS:VNI`) | implemented | `route.rs:15270`, `route.rs:15580` |
| MAC mobility seq — **receive** (stale suppression) | implemented | `route.rs:6758`, `rib/inst.rs:3311` |
| MAC mobility seq — **originate** (EC builder, seq bump) | **absent** | no builder exists |
| Type-2 **IP component** (parse + emit) | **discarded** | `nlri_evpn.rs:811` reads-and-drops |
| Router's MAC EC (RFC 9135) / L3VNI / RMAC | **absent** | no type anywhere |
| ES routes (Type-1/4), DF election | control-plane only | computed for `show`, not enforced |
| Per-VNI explicit RD/RT config | **absent** | YANG notes it as follow-up |

Two consequences worth stating up front. First, the BGP side needs **no new
protocol work** for the L2VNI MVP — origination, PMSI, best path, and install
messages all exist. Second, every gap sits exactly where
[`evpn-vxlan.md`](evpn-vxlan.md) predicted cradle would lead zebra: ARP
suppression (needs the Type-2 IP), symmetric IRB (needs RMAC/L3VNI), and now
MAC mobility origination (needs the EC builder plus a move-event source —
which cradle happens to produce, see below).

## The route → forwarding-state chain

End to end, with the real names. Left column runs on the PE where a host is
local; right column on every remote PE importing the RT.

```
 access frame                                    BGP UPDATE (MP_REACH, RT match)
   │ cradle eBPF FDB learn                          │ best path: select_best_path_evpn
   │   (l2_switch step 2)                           │ route_evpn_export_selected (route.rs:6799)
   ▼                                                ▼
 WatchFdb stream ──▶ RibRx::FdbAdd            rib::Message::MacAdd{vni,mac,vtep,seq,esi}
   │                   (bgp/inst.rs:721             │ Rib::mac_add (rib/inst.rs:3301)
   │                    local_fdb shadow)           │   seq-stale check, mac_table
   ▼                                                ▼
 evpn_originate_macip (route.rs:14105)        FibHandle::mac_add ──[CradleFib tee]──▶
   RD = router-id:vni16   RT = AS:VNI               AddEvpnMac ──▶ FDB[(mac,bd)] =
   encap EC = VXLAN(8)    nexthop = local VTEP        {FDB_F_REMOTE, remote_vtep}
   │                                                (kernel dual-FDB rows: skipped)
   ▼
 BGP UPDATE to peers ───────────────────────────────▶
```

Type-3 runs the same pattern: `local_vxlans` (VNI → local VTEP) triggers
`evpn_originate_imet` with a PMSI ingress-replication attribute carrying the
VNI; on receipt, `evpn_flood.reconcile` emits `MdbAdd`/`MdbDel` per peer VTEP,
which the tee forwards as `AddVniVtep`/`DelVniVtep` into `VNI_VTEPS`. Type-5
reuses the VPN import machinery wholesale (`dispatch_import_v4/v6` keyed by
import RTs) and lands as an ordinary VRF route — the per-VRF FIB seam shared
with MPLS and SRv6.

### Identity derivation (what configures itself)

With `advertise-all-vni` (the FRR-style knob, `zebra-bgp-evpn.yang`), nothing
per-VNI is configured:

- **RD** = type-1, `router-id(4):vni(2)` (`rd_from_router_id_vni`,
  `route.rs:15270`). Consequence: **local origination requires VNI ≤ 65535**
  (`route.rs:14124` warns and drops above that). Fabrics using large VNIs need
  the per-VNI RD config zebra has marked as follow-up — noted in Phasing, not
  solved here.
- **RT** = `AS(2):VNI(4)` (`evpn_route_target`). The receive side extracts the
  VNI from the RT for Type-2/3 (`extract_vni_from_attr`) — the NLRI Label1
  carries it too, but the RT is authoritative for import.
- **Encapsulation** = VXLAN via the encap EC (tunnel type 8); cradle ignores
  anything else on import (MPLS-encap EVPN is out of scope).
- **Local VTEP** = the nexthop `BgpNexthop::Evpn(vtep_local)`, sourced from
  `local_vxlans`.

## The learn-direction seam: `WatchFdb`

zebra's `local_fdb` shadow (`bgp/inst.rs:721`) is populated by
`RibRx::FdbAdd/FdbDel` — today produced by the netlink monitor watching
**kernel bridge** FDB events. In a cradle deployment there is no kernel bridge
and never will be; learning happens in `l2_switch` step 2
([`l2-switching.md`](l2-switching.md)) and aging happens in cradle's userspace
ager. So cradle must publish learning events, and the cleanest join point is
zebra's existing message: make the cradle client a second producer of
`RibRx::FdbAdd/FdbDel`, leaving everything downstream — `local_fdb`,
`evpn_originate_macip`, withdraw, replay on config change — untouched.

New server-streaming RPC on the cradle side:

```proto
message FdbEvent {
  enum Kind {
    LEARNED = 0;   // new dynamic MAC on an access port
    AGED    = 1;   // ager expired it (or port down flushed it)
    MOVED   = 2;   // station move: same MAC, new port
  }
  Kind kind   = 1;
  uint32 bd   = 2;   // bridge domain (l2-switching.md)
  string mac  = 3;
  string port = 4;   // access port name
  uint32 vni  = 5;   // VLAN_VNI binding, 0 if the BD has no VNI
}
rpc WatchFdb(Empty) returns (stream FdbEvent);
```

Design points:

- **Only dynamic local entries stream.** Entries flagged
  `FDB_F_REMOTE`/`FDB_F_STATIC`/`FDB_F_LOCAL` are control-plane-installed and
  must not echo back — this is the same discipline that zebra applies on its
  own path (origination is gated on *non-external-learned*, and the kernel
  rows it installs carry `NTF_EXT_LEARNED` precisely so the monitor can filter
  them). cradle's FDB flags give the equivalent filter for free.
- **Event source, not map polling.** The datapath can't call gRPC; it already
  produces the needed signals cheaply — the learning discipline distinguishes
  *new insert* (`STAT_L2_LEARN`) from *move* (`STAT_L2_MOVE`), and the
  userspace ager owns expiry. Learn/move events surface through a perf/ring
  buffer from `l2_switch` (a `RingBuf` map, the one addition to the
  [`l2-switching.md`](l2-switching.md) contract); aged events originate in the
  ager directly. The stream coalesces and is replayable: a (re)connecting
  subscriber first gets a full dump of current dynamic entries, then deltas —
  so a zebra restart reconverges without a fabric-wide flush.
- **`AGED` drives the withdraw.** Ager deletes the map entry → `AGED` event →
  `FdbDel` → `evpn_withdraw_macip` (`route.rs:14217`). EVPN's promise that
  remote state follows *control-plane* liveness rather than per-PE flood
  timers only works if aging is reported, not just performed.
- **`MOVED` is mobility's trigger** — which exposes a zebra gap, next section.

The VNI inventory itself (`local_vxlans`) keeps its existing source: zebra
creates the VXLAN netdev (`FibHandle::vxlan_add`, `external vnifilter`) and
its own monitor reports it back. In a cradle deployment that netdev carries no
traffic — it survives as the **configuration anchor** (VNI + local VTEP IP)
so `evpn_originate_imet` fires unchanged, while the tee's `SetVni` /
`SetVtepSource` program the maps that actually forward. A netdev-free VNI
config in zebra is a possible later cleanup, not a dependency.

## MAC mobility

Receive-side is done: the seq is read from the MAC Mobility EC
(`extract_mac_mobility_seq`), compared in `Rib::mac_add`, and stale updates
are suppressed. Originate-side does not exist — no EC builder, no seq bump —
so today a host moving between PEs converges only by luck of adj-RIB ordering.

The fix is split across the seam exactly once:

- **cradle** reports `MOVED` (it already detects the move in the learning
  discipline; a remote→local transition — frame from a MAC currently flagged
  `FDB_F_REMOTE` arriving on an access port — also reports `MOVED`, the
  cross-PE mobility case).
- **zebra** grows the MAC Mobility EC builder and the RFC 7432 §7.7 sequence
  rule: on originating a MAC that currently has a remote path with seq *N*,
  advertise seq *N+1*; sticky MACs (`FDB_F_STICKY` ↔ `NTF_STICKY`) advertise
  with the sticky bit and are never preempted.

Small, well-bounded zebra work — but it gates the mobility BDD scenario, so it
is Phase C, not MVP.

## ARP/ND suppression feed

[`evpn-vxlan.md`](evpn-vxlan.md) defines `ARP_SUPPRESS[(vni, ip)] → mac` and
notes zebra drops the Type-2 IP. The exploration pinned it down: the NLRI
parser reads and discards the IP (`nlri_evpn.rs:811-815`), `EvpnPrefix`
carries `ip: None`, and origination emits MAC-only Type-2. Enabling
suppression is therefore three small zebra changes and one tee field:

1. parse the IP into `EvpnMac` (and key `EvpnPrefix` with it — MAC+IP and
   MAC-only are distinct RIB entries per RFC 7432);
2. emit it on origination — the source is the host's ARP/ND entry, which the
   netlink neighbor monitor already watches for other purposes;
3. carry it through `MacAdd` → `mac_add`;
4. the tee forwards it in the existing `EvpnMac.ip` field →
   `AddEvpnMac` fills `ARP_SUPPRESS`.

Until then the datapath floods ARP across the fabric via ingress replication —
correct, just not suppressed.

## Type-5 and the L3 story

Type-5 needs no new control-plane design: origination rides the VRF export
path beside VPNv4/v6 (`bgp/inst.rs:4816`), import dispatches on RTs into the
same VRF machinery, and the result is a plain VRF route — which reaches cradle
through the ordinary route tee once per-VRF FIBs exist. This is the
interface-less L3VPN model, and it is *sufficient* for inter-subnet routing
across the fabric.

Symmetric IRB (L3VNI + RMAC) remains the cradle-native extension from
[`evpn-vxlan.md`](evpn-vxlan.md) Phase 3. The control-plane cost is now
precise: zebra has **no Router's MAC EC codec** (RFC 9135) and no L3VNI/RMAC
model at all, so cradle-native IRB needs (a) the EC codec in `bgp-packet`,
(b) an L3VNI binding on the VRF config, (c) `MacAdd`-analogous plumbing for
the RMAC, and (d) the `SetVni`-with-RMAC tee. That is the largest zebra-side
work item in the whole EVPN program and stays gated behind the shared per-VRF
FIB.

## Multihoming

Type-1/4 are originated for configured Ethernet Segments and DF election is
computed (`bgp/ethernet_segment.rs`) — but consumed only by `show`; nothing
enforces DF in forwarding, and `mac_add` stores the ESI without programming
ESI-based paths. cradle's enforcement surface is already designed
(`PORT_F_NO_FLOOD` for non-DF ports, split-horizon in the VXLAN path), so when
zebra wires DF results into install messages, cradle consumes them as port
flag updates. Watching brief; Phase E.

## Configuration walkthrough

The operator surface, all existing zebra YANG (`zebra-bgp-evpn.yang`):

```
router bgp 65001
  afi-safi evpn
    advertise-all-vni true
    bum-tunnel-type ingress-replication
  neighbor 10.255.0.2 { afi-safi { name evpn; enabled true } }
system cradle-grpc                        # the tee (existing knob)
vrf blue evpn advertise-ipv4 true         # Type-5 export (existing)
```

plus the VXLAN netdev as VNI anchor (`vni 100 ↔ bridge domain`, local VTEP
address). Nothing cradle-specific appears in BGP configuration — the thesis
again: zebra decides, cradle forwards.

## Testing (BDD)

`cradle_bgp_evpn.feature` — the integration proof on top of
`cradle_evpn.feature`'s static datapath proof:

```
 h1 ── vtep1 [cradle + zebra-rs] ══ iBGP/EVPN over IPv4 underlay ══ vtep2 [cradle + zebra-rs] ── h2
         VNI 100, advertise-all-vni                                   VNI 100, advertise-all-vni
```

- No kernel bridge; the VXLAN netdev exists but kernel forwarding is off — a
  working ping proves eBPF forwarding fed by BGP state.
- Assert the chain, not just reachability: `show bgp evpn` on vtep2 carries
  vtep1's Type-2 and Type-3; `GetFdb` on vtep2 shows h1's MAC with
  `FDB_F_REMOTE` and vtep1's VTEP; `vxlan_encap`/`vxlan_decap` counters move.
- **Withdraw scenario**: silence h1, shrink cradle's `ageing_time`, and assert
  the `AGED → FdbDel → withdraw` chain — h1's MAC disappears from vtep2's BGP
  table and FDB. This is the learn-direction seam's end-to-end test.
- Mobility scenario (h1's MAC moves to a third PE, seq bumps) lands with
  Phase C.
- Ends with the mandatory `Scenario: Teardown topology` (stop daemons, delete
  namespaces, assert the environment is clean).

## Phasing

Phases here refine `evpn-vxlan.md` Phase 2+ on the control-plane axis; its
Phase 1 (static L2VNI datapath) is the prerequisite for all of them.

- **Phase A — install tee.** `CradleFib` forwards `mac_add`/`mac_del` →
  `AddEvpnMac`/`DelEvpnMac`, `mdb_add`/`mdb_del` → `AddVniVtep`/`DelVniVtep`,
  `vxlan_add`+`vni_filter_add` → `SetVni`/`SetVtepSource`, skipping the kernel
  FDB writes when the tee is active. Received EVPN routes now program eBPF.
  One-way fabric: remote hosts reachable once *they* advertise.
- **Phase B — learn tee.** `WatchFdb` (RingBuf learn/move events + ager
  expiry, dump-then-deltas), zebra subscribes and feeds
  `RibRx::FdbAdd/FdbDel`. Full bidirectional L2VNI fabric;
  `cradle_bgp_evpn.feature` including the withdraw scenario.
- **Phase C — correctness gaps.** MAC Mobility EC builder + §7.7 seq rule in
  zebra driven by `MOVED`; Type-2 IP parse/emit/tee → `ARP_SUPPRESS`;
  mobility BDD. Optionally per-VNI RD/RT config in zebra (lifts the
  VNI ≤ 65535 origination limit).
- **Phase D — L3.** Type-5 through the per-VRF FIB (shared with MPLS/SRv6);
  then cradle-native symmetric IRB: RFC 9135 RMAC EC codec, L3VNI config,
  `SetVni`-with-RMAC — per `evpn-vxlan.md` Phase 3.
- **Phase E — multihoming.** DF enforcement as cradle port-flag updates,
  ESI-based split-horizon, once zebra wires election results into installs.
