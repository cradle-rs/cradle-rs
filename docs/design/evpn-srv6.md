# cradle-rs EVPN over SRv6 — design

> Ethernet (L2VPN) over an SRv6 fabric in the eBPF data plane: a CE frame is
> carried inside an outer IPv6 header (next-header 143, *Ethernet*) to the
> remote PE's `End.DT2U`/`End.DT2M` service SID, which decapsulates and
> bridges it into the local bridge domain. The SRv6 analog of MPLS EVPN /
> VXLAN, and the L2 counterpart of the `End.DT46` L3VPN already shipped.

Status: **Slices 1–9 implemented** (Slice 9 = RFC 9524 `End.Replicate`
SR-P2MP replication, below): `End.DT2U` unicast,
`End.DT2M` BUM, **the BGP EVPN control-plane tee** — zebra-rs
(`router bgp afi-safi evpn encapsulation srv6`, RFC 9252) advertises a
per-VNI `End.DT2U` SID on Type-2 routes and an `End.DT2M` SID on Type-3
IMETs, and the `FibHandle` tee installs remote MACs, the BUM sentinel, and
the local L2 service SIDs into cradle — and **the cradle→zebra MAC-learn
channel** (`WatchFdb`), which streams datapath-learned CE MACs up so zebra
originates Type-2 routes for them — **multi-PE BUM ingress replication**
(per-copy `End.DT2M` encap via replication-slot veth pairs in the flood
list, with EVPN split horizon) — and **the Type-3 → slot tee**: every
received IMET becomes a cradle-managed replication slot (`AddReplSlot`;
cradle creates the veth pair, flood membership, and XDP attach itself), so
any number of PEs works BGP-driven — plus **FDB aging**: idle local MACs
expire (`FdbEntry.last_seen` + a user-space sweep, `fdb_age_secs`, default
300) and their Type-2s are withdrawn via `WatchFdb` age events — and **MAC
mobility** (RFC 7432 §7.7): a moved station's Type-2 carries the MAC
Mobility sequence (max remote + 1) so every PE follows the move.
**BGP EVPN over SRv6 programs the L2 data
plane end to end, fully dynamically** (the L2 analog of the L3VPN tee, plus
the reverse channel L3 never needed). This was the last Phase-4 SRv6 item.
It builds on the SRv6 encap/decap geometry (Phases 1–4) and the L2
switching MVP ([l2-switching.md](l2-switching.md)); the FDB, flood, and
per-BD member maps already exist.

## Packet format

MAC-in-SRv6 (RFC 8986 §6.3/§6.4). A CE Ethernet frame is encapsulated in an
outer IPv6 header whose **next-header is 143 (`IPPROTO_ETHERNET`)**; the SRv6
destination is the egress PE's L2 service SID:

```
[ outer eth ][ outer IPv6  DA=End.DT2* SID, nh=143 ][ inner eth ][ inner payload ]
```

Single service SID ⇒ no SRH (reduced form), exactly like the single-SID
`End.DT46` L3VPN. Multi-SID SR-TE steering of L2 is out of scope here.

## Why the encap lives in XDP (not TC)

`bpf_skb_adjust_room` is `-ENOTSUPP` for non-IP skbs — the same constraint
that forced MPLS pops into XDP. A bridged frame can be **ARP** (BUM) or any
non-IP EtherType, so the L2 encap cannot use TC `adjust_room`. It runs in the
`cradle_xdp` stage with `bpf_xdp_adjust_head` (unrestricted), which also gives
a **predictable byte layout**: grow the head by `14 + 40` bytes, write the
outer Ethernet + outer IPv6, and the original frame follows untouched as the
inner payload. Decap is the mirror (`adjust_head` shrink), like the existing
`End.DT*` decap.

## Data-plane logic

### Ingress PE — encap (`cradle_xdp`, L2 port)

For a frame on an `PORT_F_L2` port, look up the destination MAC in the FDB for
the port's bridge domain (`FdbKey{mac, vlan}`):

- **remote unicast** (`FDB_F_REMOTE`, entry carries a 128-bit `remote_sid`) —
  MAC-in-SRv6 encap toward that `End.DT2U` SID and `bpf_redirect` out the
  underlay: `adjust_head(-(14+40))`, write outer eth (dst = the underlay
  nexthop MAC, resolved from the SID's FIB6 route / a configured adjacency),
  outer IPv6 (SA = `SRV6_ENCAP_SRC`, DA = `remote_sid`, next-header = 143),
  then redirect. `stat_inc(STAT_SRV6_L2_ENCAP)`.
- **BUM** (broadcast/multicast dst) — tunneled to the bridge domain's
  `End.DT2M` SID: the **all-ones-MAC FDB entry** (`ff:ff:ff:ff:ff:ff`) is the
  per-BD BUM sentinel, so the same `l2_srv6_encap` runs with the `End.DT2M` SID
  as DA. `stat_inc(STAT_SRV6_L2_BUM)`. In a 2-PE / single-local-CE domain that
  one remote copy is the whole flood set; local flood and multi-remote
  ingress replication are a later slice (see below).
- **local / unknown-unicast** — `XDP_PASS` to the TC `l2_switch` (local
  forward or flood), unchanged.

### Egress PE — `End.DT2U`/`End.DT2M` decap + bridge (`cradle_xdp`, then TC)

The outer IPv6 DA matches a local `End.DT2U` (unicast) or `End.DT2M` (BUM)
SID — the decap is identical, and the inner frame's dst MAC (unicast → forward,
broadcast/multicast → flood) selects the `l2_switch` action:

1. Strip the outer IPv6 header (`adjust_head(+40)` after sliding the outer eth
   off) — the inner Ethernet frame is now the L2 frame.
2. Attach the SID's **bridge domain** to the XDP→TC metadata
   (`CradleXdpMeta`, an L2 mode + `bd`), analogous to the `End.DT46` VRF meta.
3. `XDP_PASS`. The TC stage, seeing the L2 meta on an L3 (underlay) port,
   dispatches to `l2_switch(bd)` instead of `l3_forward` — the inner dst MAC
   resolves to the local CE port and is delivered. `stat_inc(STAT_SRV6_L2_DECAP)`.

## Map / ABI additions

- `FdbEntry` gains `remote_sid: [u8;16]`; `FDB_F_REMOTE` marks an overlay
  entry (its `remote_sid` is the target `End.DT2U` SID; `oif` unused).
- `CradleXdpMeta` gains an L2 mode: when set, TC bridges in `bd` rather than
  routing in `vrf_id` (the field is reused as the bridge domain).
- Behaviors `SRV6_BH_END_DT2U` / `SRV6_BH_END_DT2M`; the `SRV6_LOCALSID` entry
  carries the SID's bridge domain (reuse `vrf_id` as `bd`).
- Counters `STAT_SRV6_L2_ENCAP` / `STAT_SRV6_L2_DECAP` / `STAT_SRV6_L2_BUM`.
- Static config: L2 ports in a BD (existing), `localsids` with `end.dt2u` /
  `end.dt2m` (+ `bd`), FDB entries with a `remote_sid` (including the
  all-ones-MAC BUM sentinel), and `srv6_source`.

## Testing (BDD)

`c1 ── pe1[cradle] ──(IPv6 underlay)── pe2[cradle] ── c2`, c1/c2 in the same
bridge domain, kernel forwarding/seg6 off on the PEs.

- `cradle_evpn_srv6` — unicast: static ARP on the CEs + static FDB (remote MAC
  → remote `End.DT2U` SID) keep it BUM-free. A ping proves the L2 frame was
  encapped at pe1 and `End.DT2U`-decapped + bridged at pe2 (`srv6_l2_encap`
  @pe1, `srv6_l2_decap` @pe2).
- `cradle_evpn_srv6_bum` — BUM: **no** static ARP, so c1's ARP is broadcast and
  must ride `End.DT2M` (the all-ones-MAC FDB sentinel → fd00:2::200); the reply
  and ping then ride `End.DT2U`. A successful ping proves the BUM path carried
  the ARP (`srv6_l2_bum` @pe1, `srv6_l2_decap` @pe2).
- `cradle_evpn_srv6_zebra` — the control-plane tee + learn channel:
  cradle+zebra on both PEs, iBGP L2VPN-EVPN (`encapsulation srv6`) over an
  IS-IS SRv6 underlay, **fully dynamic** — no static ARP, no static cradle
  FDB, and no static kernel FDB. CE MACs are learned by the XDP stage,
  streamed to zebra over `WatchFdb`, advertised as Type-2 (with the DT2U
  SID), and installed on the remote PE via the tee; the BUM sentinel, local
  L2 SIDs, and locator routes arrive via the tee too. Asserts the BGP
  session, c1↔c2 reach, and `srv6_l2_bum`/`srv6_l2_encap` @pe1 +
  `srv6_l2_decap` @pe2 (`srv6_l2_encap` nonzero proves a learned MAC made
  the full loop: XDP learn → WatchFdb → Type-2 → remote tee → DT2U encap).
- `cradle_evpn_srv6_multi` — 3-PE BUM replication, static slots: one BD
  across three PEs (hub underlay), no unicast FDB — flood-and-learn over
  per-copy `End.DT2M` replication; bounded BUM counters prove split horizon.
- `cradle_evpn_srv6_zebra_multi` — the whole stack, BGP-driven, 3 PEs:
  iBGP EVPN full mesh over an IS-IS SRv6 hub; Type-3s become cradle-managed
  replication slots, learned MACs become Type-2s/DT2U entries; fully
  dynamic (no static ARP/FDB/slots anywhere).
- `cradle_srv6_replicate` — RFC 9524 `End.Replicate` (Slice 9): a root, a
  bud, and two leaves. The root encapsulates BUM once toward the bud's
  `End.Replicate` SID; the bud fans out to leaf1, leaf2, and its own local CE
  (the Bud role). `cr↔c1` (a remote branch) and `cr↔cb` (the Bud local
  branch) reach; `srv6_replicate` fires on the bud and every branch's
  `srv6_l2_decap` increments.

Mandatory teardown on each.

## Phasing

1. **Slice 1 — `End.DT2U` unicast** *(done)*. MAC-in-SRv6 encap (XDP),
   `End.DT2U` decap + bridge, static FDB, `cradle_evpn_srv6` BDD.
2. **Slice 2 — `End.DT2M` BUM** *(done, 2-PE)*. BUM frames tunnel to the BD's
   `End.DT2M` SID via the all-ones-MAC FDB sentinel; egress `End.DT2M` decap
   reuses the `End.DT2U` decap (the broadcast inner floods via `l2_switch`).
   `cradle_evpn_srv6_bum` BDD (ARP over DT2M, no static ARP). The 2-PE
   single-remote form; per-copy replication is Slice 5.
3. **Slice 3 — the BGP EVPN control-plane tee** *(done)*. zebra-rs grew
   `End.DT2U` over SRv6 (RFC 9252 §6.1/§6.2): a `router bgp afi-safi evpn
   encapsulation srv6` knob, per-VNI `End.DT2U` allocation next to the
   existing `End.DT2M` allocator, the DT2U SRv6 L2 Service TLV on originated
   Type-2 routes, and extraction of the peer's DT2U/DT2M SIDs on receive.
   The tee (all in `FibHandle`):
   - **Type-2 → `AddFdbRemote`** — `MacAdd` carries `srv6_sid`; with a SID
     the entry is cradle-only (no kernel VXLAN FDB row, no VXLAN device
     required) with `nexthop_id: 0` — cradle resolves the underlay adjacency
     by a **FIB6 lookup on the SID** in the datapath (the IGP locator route,
     itself teed), so the control plane never pre-resolves nexthops for L2.
   - **Type-3 → the all-ones BUM sentinel** — a remote `End.DT2M` SID on an
     IMET is sent as `MacAdd { mac: ff:ff:ff:ff:ff:ff, srv6_sid }`, feeding
     the same pathway.
   - **Local L2 SIDs → `AddLocalSid`** — the per-VNI DT2U/DT2M SIDs register
     in the RIB SID registry (`SidBehavior::EndDT2U/EndDT2M`, `table_id` =
     VNI = bridge domain) and ride the existing Phase-3 local-SID tee;
     `route_sid_install` skips netlink for them (no kernel seg6local action).
   `cradle_evpn_srv6_zebra` BDD: iBGP EVPN over IS-IS SRv6, kernel
   bridge+vxlan as zebra's VNI declaration, no static ARP, no static
   cradle FDB.
4. **Slice 4 — the cradle→zebra MAC-learn channel** *(done)*. The reverse
   direction, making the L2VPN fully dynamic:
   - **XDP learning** — `l2_evpn_xdp` learns the CE source MAC (the TC
     `l2_switch` learn never sees frames the XDP stage tunnels), and
     **unknown unicast** now also rides the BUM sentinel (the "U" in BUM),
     so a first bidirectional exchange completes before BGP converges.
   - **`WatchFdb`** — a server-streaming gRPC on cradle: a 1s poll of the
     FDB map diffs locally-learned `(mac, bd)` entries (never remote/
     sentinel ones) and streams them; a fresh subscription replays the
     current set. Learns only — cradle has no FDB aging yet.
   - **zebra watcher** — spawned with the tee (`system cradle-grpc`),
     reconnects with backoff; each event synthesizes the same `FdbAdd` a
     kernel bridge learn produces (VNI = bridge domain, `vxlan_local`
     resolved from the VNI's vxlan device), so BGP originates the Type-2
     with the DT2U SID exactly as for a kernel-learned MAC.
   The `cradle_evpn_srv6_zebra` BDD runs fully dynamic: no static kernel
   FDB either — CE MACs are datapath-learned, streamed up, advertised,
   and installed back down on the remote PE.
5. **Slice 5 — multi-PE BUM ingress replication** *(done, static config)*.
   Per-copy encap with existing primitives: each remote PE gets a
   **replication slot** — a veth pair whose A end joins the bridge
   domain's flood list. The TC flood `clone_redirect`s the bare BUM frame
   into each slot (cloning needs no resize, so non-IP frames are fine);
   the copy arrives as *ingress* on the B end, where the XDP stage — one
   packet in hand — MAC-in-SRv6 encapsulates it toward that slot's
   `End.DT2M` SID (`REPL_SID[ifindex]`, FIB6 fallback for the underlay
   adjacency) and redirects it out. Local flood happens in the same loop.
   **Split horizon**: overlay-received frames (`from_overlay`, the decap
   path) flood local-only — `flood()` skips members present in `REPL_SID`
   — so BUM never re-enters the overlay. A multi-PE BD simply programs
   slots instead of the all-ones sentinel; `l2_evpn_xdp` needed no change
   (BUM/unknown-unicast falls through to the TC flood). Static
   `repl_slots` config; `cradle_evpn_srv6_multi` BDD (3 PEs, hub underlay,
   no unicast FDB — every pair reaches via flood-and-learn, and bounded
   BUM counters prove the horizon holds).
6. **Slice 6 — the Type-3 → slot tee** *(done)*. The zebra tee programs
   replication slots instead of the single-remote sentinel: each received
   IMET with a DT2M SID sends `Message::CradleReplAdd { vni, sid }` →
   `FibHandle::cradle_repl_add` → `AddReplSlot` (withdraw mirrors with
   `DelReplSlot`). cradle owns the whole slot lifecycle: it creates the
   `crs<N>a`/`crs<N>b` veth pair itself, joins the A end to the BD's flood
   list (`l2_member_add`, dynamic append/compact), attaches the XDP stage
   to the B end, and keys `REPL_SID` by both ends; idempotent per
   `(bd, sid)`. The all-ones sentinel remains for static 2-PE configs
   only. `cradle_evpn_srv6_zebra_multi` BDD: 3 PEs, iBGP EVPN full mesh
   over an IS-IS SRv6 hub, fully dynamic — Type-3s become slots, learned
   MACs become Type-2s, every CE pair reaches every other.
7. **Slice 7 — FDB aging** *(done)*. `FdbEntry.last_seen` (`bpf_ktime`,
   refreshed by every learn — both the TC and XDP learn sites insert per
   frame, so the refresh is free); a user-space sweep expires local
   entries idle past `fdb_age_secs` (default 300, 0 = off) and bumps
   `fdb_aged`. `WatchFdb` gained an `event` field: subscribers diff both
   directions, so a disappeared entry emits `aged` — zebra re-emits it as
   an `FdbDel`, withdrawing the Type-2 (`evpn_withdraw_macip`), and the
   remote PE's overlay entry is removed by the existing `MacDel` tee.
   Fresh traffic re-learns and the L2VPN reconverges by itself.
   `cradle_evpn_srv6_age` BDD (5s age, IPv6-quieted CE links: learn →
   idle → `fdb_aged` on both PEs → re-ping reconverges).
8. **Slice 8 — MAC mobility (RFC 7432 §7.7)** *(done)*. The move machinery
   mostly falls out of the earlier slices: at the NEW PE the datapath learn
   overwrites the remote FDB entry → `WatchFdb` reports it → the Type-2 is
   originated with the **MAC Mobility extended community** (seq =
   `max(remote seqs) + 1`, tracked per `(vni, mac)` on `LocalRib`,
   monotonic across re-advertisements; first-time local MACs stay at 0
   with no EC); at the OLD PE, the new remote install flips its local
   entry → the `WatchFdb` disappearance withdraws the stale Type-2. The
   one datapath addition: `fdb_remote_del` is **local-guarded** — the old
   owner's withdraw must not clobber the new PE's fresh local learn.
   `rib::mac_add`'s existing seq staleness gate drops out-of-order
   advertisements. `cradle_evpn_srv6_mob` BDD: a station (same MAC + IP)
   migrates PE1 → PE2 → PE1 across a two-CE-port pe2; pings follow the
   station at every step.

9. **Slice 9 — `End.Replicate` SR-P2MP replication (RFC 9524)** *(done)*. The
   SR-P2MP tree the head-end slots never built: instead of the root
   ingress-replicating one copy per remote leaf, the root sends **one** copy
   into the tree and intermediate **bud** nodes fan it out. A Replication
   segment is a local `End.Replicate` SID whose state (`REPL_SEG`, keyed by the
   SID) is a list of downstream branches. On a copy arriving at the SID the
   node — per RFC 9524 §5.2 — checks/decrements the Hop Limit once, then for
   each branch sets the outer IPv6 DA to that branch's **downstream
   Replication-SID** (a remote leaf's `End.DT2M` SID, or the next tier's
   `End.Replicate` SID) and forwards a copy over the underlay; a **Bud**
   additionally delivers one copy into its own bridge domain. Composes with the
   existing decap: the copies keep the original MAC-in-SRv6 payload untouched
   (only DA + Hop Limit change), so a leaf's `End.DT2M` decap handles them
   unchanged, and buds chain.

   **Why it straddles XDP and TC.** Replication needs `bpf_clone_redirect`, a
   TC-only helper (XDP has no clone). But the frame is already IPv6, so no
   resize is needed — only a 16-byte DA rewrite per copy. So the XDP stage
   matches the `End.Replicate` SID (`SRV6_LOCALSID`) and hands the intact frame
   to the TC stage via the `XDP_META_MAGIC_REPL` metadata tag (the same
   XDP→TC hand-off `End.DT2M` uses); `srv6_replicate` in the TC stage re-reads
   the DA, walks `REPL_SEG`, and for each branch `store`s the new DA, resolves
   the underlay adjacency (an explicit per-branch nexthop, or a FIB6 lookup on
   the branch SID — as `l2_srv6_encap` does), rewrites the outer Ethernet, and
   `bpf_clone_redirect`s a copy. All packet access is via skb `store`/`load` so
   nothing is held across a clone (which invalidates packet pointers); the
   branch list lives in map memory, so its borrow survives the clones. A **Bud
   local** branch instead clone_redirects the copy — with its DA set to this
   node's own `End.DT2M` SID — to a cradle-owned **leaf veth** whose peer runs
   the XDP `End.DT2M` decap, reusing `srv6_dt2u` for local delivery with no new
   TC decap path.

   **Map / ABI.** Behavior `SRV6_BH_END_REPLICATE`; `REPL_SEG:
   HashMap<[u8;16], ReplSeg>` (branch list + role + Hop-Limit Threshold);
   counter `STAT_SRV6_REPLICATE`. gRPC `SetReplSeg` / `DelReplSeg` (cradle owns
   the Bud leaf-veth lifecycle, `crl<N>a`/`crl<N>b`), static `repl_segs` config
   (register the SID as a `localsids` entry with `behavior: end.replicate`).
   `cradle_srv6_replicate` BDD: a root feeds one copy toward a bud's
   `End.Replicate` SID; the bud fans out to two remote leaves **and** delivers
   locally to its own CE (`srv6_replicate` on the bud, `srv6_l2_decap` on each
   leaf and the bud, `cr↔c1` and `cr↔cb` reach).

## Out of scope (still design)

Refinements to aging (per-BD age knobs, event-driven expiry instead of the
1s scan), MAC mobility hardening (RFC 7432 §15.1 duplicate-MAC damping for
flapping stations; the sticky/static bit), symmetric IRB (L3 gateway on the
SRv6 L2 domain), 802.1Q-tagged bridge domains, and `End.M`
egress-protection. For `End.Replicate`: per-branch **segment lists** (an SRH
push per copy, for explicit-path branches — today each branch is a single
downstream SID), non-reduced (SRH-present) replication, and the **BGP tee**
that programs the tree from the EVPN SR-P2MP PMSI (RFC 9524's tree is
controller-instantiated; the datapath primitive and gRPC land first).
