# cradle-rs L2 switching — design

> A full VLAN-aware eBPF bridge: 802.1Q classification, bridge domains,
> FDB lifecycle, and IRB — grown out of the MVP switch already in the datapath.

Status: **MVP implemented, full design not yet.** MAC learning, known-unicast
forward, and BUM flooding for untagged single-domain ports are live
(`crates/cradle-ebpf/src/main.rs:264` `l2_switch`). This document designs the
rest: 802.1Q tagging, bridge domains decoupled from VLAN IDs, FDB aging /
static entries, and the L2↔L3 boundary (IRB). It builds on
[`architecture.md`](architecture.md) and borrows overall eBPF design from
[Vinbero](https://github.com/takehaya/Vinbero) (see next section).

## What we take from Vinbero

Vinbero is an XDP SRv6 stack whose L2VPN side solved the same problems cradle's
L2 stage faces. Its design docs (`docs/design/ja/`) yield four ideas worth
adopting and one deliberate divergence:

1. **Bridge domain ≠ VLAN ID.** Vinbero scopes its MAC table by a *bridge
   domain* (`fdb_map[(bd_id, mac)]`), not by the VLAN tag. The VLAN is just
   framing on a port; the BD is the forwarding scope. Two customers can reuse
   VLAN 100 on different ports without polluting each other's MAC table, and
   VLAN translation across a trunk falls out for free. cradle's `FdbKey.vlan`
   becomes `FdbKey.bd`.
2. **Learning discipline: local never overwrites remote/static.** Vinbero's
   FDB rule — data-plane learning must not clobber entries installed by the
   control plane (remote peers, statics) — is exactly what cradle needs once
   zebra-rs (and later EVPN, [`evpn-vxlan.md`](evpn-vxlan.md)) installs FDB
   rows. The datapath checks flags before writing.
3. **Read-before-write FDB updates.** Learning does a lookup first and writes
   only on change, avoiding a hash-map insert per packet on the hot path.
4. **Userspace derives, the datapath looks up.** Vinbero's control plane turns
   user intent (ports, VLANs, peers) into pre-computed maps the XDP program
   consumes without runtime coordination. cradle applies the same split: the
   user configures *(port, vid, bd)* rows once; the control plane derives the
   ingress-classification, egress-tagging, and flood-list maps from them.

The divergence: Vinbero keeps a **kernel bridge** on the decap side for BUM
flooding and slow-path learning (an FDB watcher syncs `RTM_NEWNEIGH` back into
the map). cradle's whole point is *no kernel bridge* — the eBPF program floods
by itself (`bpf_clone_redirect` today, XDP `BPF_F_BROADCAST` later) and all
learning happens in the datapath. That keeps the L2 BDD honest: reachability
proves the eBPF switch, nothing else.

## Current state

| Piece | Today | File |
|---|---|---|
| Port model | `PortConfig{mac, vlan, flags}`, `PORT_F_L2` = access port in `vlan` | `cradle-common/src/lib.rs:127` |
| FDB | `HashMap<FdbKey{mac,vlan}, FdbEntry{oif,flags}>`, 8192 | `cradle-ebpf/src/main.rs:65` |
| Flood list | `L2_MEMBERS[(vlan,slot)] → oif` + `L2_COUNT[vlan]`, bound `MAX_L2_MEMBERS = 64` | `main.rs:67` |
| Datapath | learn src → BUM? flood : FDB hit? redirect (hairpin drop) : flood | `main.rs:264` |
| gRPC | `SetPort`, `SetL2Domain` | `proto/cradle.proto` |
| BDD | `cradle_l2.feature` — 3 hosts, one untagged domain | |

Gaps: 802.1Q tags are ignored (a tagged frame is switched by PVID as if
untagged); one port = one VLAN (no trunks); FDB entries never age and the
datapath would happily overwrite a control-plane entry; `FDB_F_LOCAL` is
defined but never consulted (no IRB); no way to inspect the FDB.

## Where the VLAN tag actually lives at TC

A subtlety that shapes the whole design: at TC ingress the outer 802.1Q tag is
usually **not in the packet data**. The kernel strips it into skb metadata
(`skb->vlan_present` / `vlan_proto` / `vlan_tci`), so a byte-wise parse for
EtherType `0x8100` never matches on the common (veth, offloading-NIC) path.
Classification must therefore read the skb fields first and fall back to an
in-band parse (`0x8100`/`0x88a8` at offset 12) only for the non-accelerated
case. Symmetrically, egress tagging uses `bpf_skb_vlan_push` /
`bpf_skb_vlan_pop`, which operate on the same metadata and serialize the tag
on transmit. Both helpers invalidate cached packet pointers — offsets are
re-loaded after every call, same rule as `adjust_room` in
[`mpls.md`](mpls.md).

## Map contract changes (`cradle-common`)

Four tables, all derived by the control plane from one user-facing config.

### 1. `FDB` v2 — keyed by bridge domain, lifecycle-aware

```rust
#[repr(C)]
pub struct FdbKey {
    pub mac: [u8; 6],
    pub bd: u16,               // bridge domain, not the wire VID
}

#[repr(C)]
pub struct FdbEntry {
    pub oif: u32,
    pub flags: u32,            // FDB_F_*
    pub remote_vtep: u32,      // reserved for EVPN/VXLAN (evpn-vxlan.md); 0 = none
    pub _pad: u32,
    pub last_seen: u64,        // bpf_ktime_get_ns() of last src sighting (dynamic)
}

pub const FDB_F_LOCAL:  u32 = 1 << 0;  // ours: punt to L3 / host (IRB)
pub const FDB_F_STATIC: u32 = 1 << 1;  // control-plane installed; never learned over
pub const FDB_F_REMOTE: u32 = 1 << 2;  // reachable via remote VTEP (EVPN, later)
pub const FDB_F_STICKY: u32 = 1 << 3;  // dynamic, but station moves are refused
```

`remote_vtep` lands now so the EVPN design extends this entry without an ABI
break — the same "carry the field early" trick `MplsEntry.vrf_id` used.

### 2. `PORT_VLAN` — ingress classification: *(port, vid) → bd*

```rust
#[repr(C)]
pub struct PortVlanKey { pub ifindex: u32, pub vid: u16, pub _pad: u16 }

#[repr(C)]
pub struct PortVlanEntry { pub bd: u16, pub flags: u16 }   // PV_F_*

pub const PV_F_TAGGED: u16 = 1 << 0;   // egress from this port in this VLAN is tagged
```

A tagged frame classifies by its VID; an untagged frame classifies by the
port's PVID (`PortConfig.vlan`, unchanged). Either way the *(ifindex, vid)*
row must exist — a miss is a **VLAN-filtering drop**, exactly the Linux
`bridge vlan` semantic. The row's `bd` is the forwarding scope from here on.

### 3. `PORT_BD` — egress tagging: *(port, bd) → (vid, tag action)*

```rust
#[repr(C)]
pub struct PortBdKey { pub ifindex: u32, pub bd: u16, pub _pad: u16 }
// value: PortVlanEntry — vid to emit and PV_F_TAGGED, reused with vid in `bd`'s slot
```

The reverse row of `PORT_VLAN`, needed because a BD is decoupled from the VID:
a frame that entered on VID 100 (→ BD 5) may leave a trunk that carries BD 5
as VID 200. Known-unicast egress looks up *(oif, bd)* and pushes/pops/rewrites
the tag accordingly — VLAN translation is not a feature, it is the absence of
an assumption. Both `PORT_VLAN` and `PORT_BD` are projections of the same
user-facing rows; the control plane keeps them consistent, the datapath never
writes them.

### 4. `BD_PORTS` — flood list with per-member tag action

```rust
#[repr(C)]
pub struct BdMemberKey { pub bd: u16, pub slot: u16 }      // dense slot 0..count

#[repr(C)]
pub struct BdMember { pub oif: u32, pub vid: u16, pub flags: u16 }  // PV_F_TAGGED
```

Replaces `L2_MEMBERS`/`L2_COUNT` (`BD_COUNT[bd] → u32` keeps the count). Each
member carries its own egress `(vid, tagged)` so flooding handles mixed
access/trunk domains. The control plane **sorts the slots by tag action**
(untagged members first, then tagged members grouped by VID) so the flood loop
changes the frame's tag state at group boundaries only — a derived-state trick
that keeps per-member work near zero.

## Data-plane logic (`cradle-ebpf`)

`l2_switch` becomes:

```
1. classify   vid  = skb metadata tag (fallback: in-band parse) else PVID
              bd   = PORT_VLAN[(iif, vid)]           miss → drop (STAT_L2_VLAN_DROP)
              port blocked (PORT_F_BLOCK)?           → drop
2. learn      e = FDB[(src, bd)]
              none            → insert {oif: iif, last_seen: now}   (STAT_L2_LEARN)
              STATIC|REMOTE|LOCAL|STICKY flags       → leave it alone
              e.oif != iif    → station move: update oif            (STAT_L2_MOVE)
              else            → refresh last_seen (rate-limited, ~1/s)
              (skipped entirely under PORT_F_NO_LEARN)
3. forward    dst multicast/broadcast                → flood
              e = FDB[(dst, bd)]
              none                                   → flood
              e.flags & FDB_F_LOCAL                  → punt / IRB (Phase 3)
              e.oif == iif                           → drop (hairpin)
              else → retag via PORT_BD[(e.oif, bd)]  → bpf_redirect(e.oif)
```

Learning is read-before-write (Vinbero rule 3): the common case — known MAC,
same port, fresh timestamp — touches nothing. The timestamp refresh writes
through `get_ptr_mut` (a field store, not an insert) and only when
`now - last_seen > 1s`, so the hot path costs one hash lookup and the FDB
cacheline doesn't bounce between CPUs on every frame.

### Flooding

The loop keeps its `MAX_L2_MEMBERS = 64` verifier bound, but members now carry
tag actions. Because `bpf_clone_redirect` snapshots the skb *at call time*,
the sorted slot order lets the loop mutate the frame between groups:

```
pop the tag (if present)
for each untagged member (oif != iif):  clone_redirect(oif)
for each tagged group (vid):            vlan_push(vid); clone_redirect each; vlan_pop
return TC_ACT_SHOT          // original consumed; clones did the work
```

`PORT_F_NO_FLOOD` excludes a port from BUM (useful for EVPN split-horizon
later); the ingress port is always excluded. Frames destined to the reserved
`01-80-C2-00-00-0x` block (STP, LACP, LLDP) are **not** flooded — punt to the
host (`TC_ACT_PIPE`), matching bridge behavior and leaving room for a future
control protocol.

### Port state

No STP implementation in cradle — that is a control-plane protocol and out of
scope (zebra-rs or an external agent can drive it later). What the datapath
provides is the enforcement surface, three `PortConfig` flag bits:

```rust
pub const PORT_F_BLOCK:    u32 = 1 << 2;  // drop everything (STP blocking)
pub const PORT_F_NO_LEARN: u32 = 1 << 3;  // forward but don't learn
pub const PORT_F_NO_FLOOD: u32 = 1 << 4;  // never a BUM target
```

Until a loop-prevention agent exists, a physical loop is a broadcast storm —
same as a Linux bridge with STP off. Documented, not defended (storm-control
rate limiting is Phase 4).

## FDB aging

The kernel bridge ages dynamic entries (default 300 s); cradle must too, or a
departed host shadows its MAC forever. Two candidate mechanisms:

- **`LruHashMap`** — rejected: eviction is by memory pressure, not time; a
  quiet-but-present host can be evicted while a long-gone one survives, and
  statics would need a separate map.
- **Userspace ager** — chosen: the datapath stamps `last_seen`; a tokio task
  in `cradle` scans the FDB every 30 s and deletes dynamic entries (no
  `STATIC|REMOTE|LOCAL|STICKY` flag) older than `ageing_time` (default 300 s,
  configurable). A scan of even a full 8k-entry map is microseconds of
  userspace work per 30 s.

This is also where Vinbero's slow-path FDB watcher maps onto cradle: Vinbero
reconciles the kernel bridge's learning into BPF; cradle has no kernel bridge,
so the ager is the *only* userspace touch on dynamic entries — one-directional
and simple.

## Observability

New counters in the `STAT_*` scheme (surfaced by `GetStats` / `cradle ctl
stats`, asserted by BDD):

```
STAT_L2_LEARN       // new MAC inserted
STAT_L2_MOVE        // station move (oif changed)
STAT_L2_VLAN_DROP   // VLAN-filtering drop (no (port, vid) row)
```

Plus the FDB itself becomes inspectable — `GetFdb` below is cradle's
`bridge fdb show`, and the BDD uses it to assert learning/aging directly
instead of inferring from pings.

## Control-plane API (gRPC)

The user-facing model is **rows of (port, vid, bd, tagged, pvid)** — the same
shape as `bridge vlan add`. Everything else is derived.

```proto
message PortVlan {
  string port  = 1;
  uint32 vid   = 2;
  uint32 bd    = 3;   // 0 => bd = vid (the common, un-decoupled case)
  bool tagged  = 4;   // egress tagged on this port
  bool pvid    = 5;   // untagged ingress classifies to this vid
}
rpc SetPortVlan(PortVlan) returns (Empty);
rpc DelPortVlan(PortVlan) returns (Empty);

message Fdb {
  uint32 bd    = 1;
  string mac   = 2;
  string port  = 3;
  uint32 flags = 4;   // FDB_F_STATIC | FDB_F_LOCAL | ...
}
rpc AddFdb(Fdb) returns (Empty);      // static / local entries
rpc DelFdb(Fdb) returns (Empty);
rpc GetFdb(FdbRequest) returns (FdbReply);   // dump, with age + flags
```

On each `SetPortVlan`/`DelPortVlan` the server recomputes the affected
`PORT_VLAN`, `PORT_BD`, and (sorted) `BD_PORTS` slots — the Vinbero
derive-in-userspace pattern. `SetL2Domain` survives as sugar: it expands to
one untagged-PVID `PortVlan` row per member with `bd = vlan`, which is exactly
today's semantics, so existing configs and the current BDD keep working
unchanged. The JSON bootstrap config gains a `vlans` array per port and
optional `fdb` statics, keeping the datapath provable standalone.

## Control-plane integration (zebra-rs)

zebra-rs's L2 FIB surface is `FibHandle::mac_add` / `mac_del` — AF_BRIDGE FDB
rows (today driven by EVPN Type-2, see [`evpn-vxlan.md`](evpn-vxlan.md)). The
`CradleFib` tee forwards them as `AddFdb`/`DelFdb` with `FDB_F_STATIC` (or
`FDB_F_REMOTE` + `remote_vtep` once VXLAN lands). The learning discipline in
step 2 is what makes this safe: a teed control-plane entry is authoritative
and data-plane learning routes around it, never over it. Nothing else is
needed from zebra for plain switching — L2 learning is a data-plane job.

## IRB — the L2↔L3 boundary (Phase 3)

A frame whose destination MAC hits an `FDB_F_LOCAL` entry is *ours to route*:
today's code has the flag but drops through to flood. IRB wires it up:

```rust
#[repr(C)]
pub struct BdInfo { pub vrf_id: u32, pub svi_mac: [u8; 6], pub _pad: u16 }
// BD_INFO: HashMap<u16 /* bd */, BdInfo>
```

- **L2 → L3**: dst MAC = SVI MAC (`FDB_F_LOCAL`) → strip the frame's VLAN
  context, enter `l3_forward` (in the BD's VRF once per-VRF FIBs exist).
- **L3 → L2**: a route whose nexthop resolves onto an SVI needs one extra
  lookup — neighbor IP → MAC (`NEIGH4/6`), then `FDB[(mac, bd)]` → member
  port + tag action. This is the routed-into-bridge path every overlay needs
  at egress.

This is deliberately the same per-VRF seam as MPLS `POP_L3`, SRv6 `End.DT46`,
and the EVPN L3VNI — the "build once" FIB mechanism shared by all four
designs. IRB waits for it rather than inventing a parallel one.

## Testing (BDD)

`cradle_l2.feature` stays as-is (it exercises the `SetL2Domain` sugar). New:

**`cradle_vlan.feature`** — two VLANs across a trunk between two cradle
switches; isolation is the assertion:

```
 h1(10.0.10.1, vid 10) ─ swA ─┐             ┌─ swB ─ h3(10.0.10.3, vid 10)
                              trunk(10,20)
 h2(10.0.20.2, vid 20) ─ swA ─┘             └─ swB ─ h4(10.0.20.4, vid 20)
```

- h1 ↔ h3 and h2 ↔ h4 eventually succeed (tagged trunk, untagged access,
  learning across two switches);
- h1 → h4 **fails** (different BD — the negative proves VLAN filtering);
- `l2_vlan_drop` is nonzero on the trunk after the failed ping;
- an FDB dump (`GetFdb`) shows h1's MAC on the right port with a nonzero age;
- with `ageing_time` set to a few seconds, the entry disappears after quiet
  time (aging asserted directly, not inferred).

Neither switch namespace has a kernel bridge or `8021q` module configured —
reachability through tags proves the eBPF switch did the (un)tagging. The
feature ends with the mandatory `Scenario: Teardown topology` (stop cradle in
each namespace, delete namespaces, assert clean environment).

## Phasing

1. **Phase 1 — VLAN-aware switching.** Tag classification (metadata +
   in-band fallback), `PORT_VLAN`/`PORT_BD`/`BD_PORTS`, egress push/pop,
   grouped flood, `STAT_L2_VLAN_DROP`, `SetPortVlan`, JSON `vlans`,
   `cradle_vlan` BDD. `SetL2Domain` reimplemented as sugar.
2. **Phase 2 — FDB lifecycle.** `FdbEntry` v2 (`last_seen`, flags), learning
   discipline (read-before-write, no-overwrite, station move), userspace
   ager, `AddFdb`/`DelFdb`/`GetFdb`, `STAT_L2_LEARN`/`STAT_L2_MOVE`, aging
   BDD, zebra `mac_add` tee.
3. **Phase 3 — IRB.** `FDB_F_LOCAL` honored, `BD_INFO`, SVI routing both
   directions — gated on the shared per-VRF FIB (with MPLS/SRv6/EVPN).
4. **Phase 4 — scale & safety.** XDP fast path with devmap
   `BPF_F_BROADCAST`/`BPF_F_EXCLUDE_INGRESS` flooding (kernel ≥ 5.14), storm
   control, pinned-map FDB persistence across restarts (Vinbero's
   `pin_maps`), larger FDB sizing.
