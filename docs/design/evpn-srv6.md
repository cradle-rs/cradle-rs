# cradle-rs EVPN over SRv6 — design

> Ethernet (L2VPN) over an SRv6 fabric in the eBPF data plane: a CE frame is
> carried inside an outer IPv6 header (next-header 143, *Ethernet*) to the
> remote PE's `End.DT2U`/`End.DT2M` service SID, which decapsulates and
> bridges it into the local bridge domain. The SRv6 analog of MPLS EVPN /
> VXLAN, and the L2 counterpart of the `End.DT46` L3VPN already shipped.

Status: **Slice 1 (End.DT2U unicast) — in progress.** This is the last
Phase-4 SRv6 item. It builds on the SRv6 encap/decap geometry (Phases 1–4)
and the L2 switching MVP ([l2-switching.md](l2-switching.md)); the FDB, flood,
and per-BD member maps already exist.

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
- **local / unknown** — `XDP_PASS` to the TC `l2_switch` (local forward or
  flood), unchanged.

### Egress PE — `End.DT2U` decap + bridge (`cradle_xdp`, then TC)

The outer IPv6 DA matches a local `End.DT2U` SID:

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
- Counters `STAT_SRV6_L2_ENCAP` / `STAT_SRV6_L2_DECAP`.
- Static config: L2 ports in a BD (existing), `localsids` with `end.dt2u`
  (+ `bd`), FDB entries with a `remote_sid`, and `srv6_source`.

## Testing (BDD)

`cradle_evpn_srv6`: `c1 ── pe1[cradle] ──(IPv6 underlay)── pe2[cradle] ── c2`,
c1/c2 in the same bridge domain, kernel forwarding/seg6 off on the PEs. Static
ARP on the CEs and static FDB on the PEs (remote MAC → remote `End.DT2U` SID)
keep it deterministic and BUM-free. A ping c1↔c2 proves the L2 frame was
encapped at pe1, carried over SRv6, and `End.DT2U`-decapped + bridged at pe2.
Assert `srv6_l2_encap` @pe1 and `srv6_l2_decap` @pe2. Mandatory teardown.

## Phasing

1. **Slice 1 — `End.DT2U` unicast** *(this change)*. MAC-in-SRv6 encap (XDP),
   `End.DT2U` decap + bridge, static FDB, `cradle_evpn_srv6` BDD.
2. **Slice 2 — `End.DT2M` BUM**. Ingress replication of BUM (ARP/flood) frames
   to the per-BD list of remote `End.DT2M` SIDs, plus local flood; egress
   `End.DT2M` decap + local flood. The hard part is per-copy encap during
   replication (`clone_redirect` can't encap; TC can't encap non-IP) — the
   likely shape is an XDP flood that encaps one copy per remote SID and
   `clone_redirect`s locals, or a recirculation. Enables real ARP + learning.
3. **Slice 3 — data-plane learning + the zebra tee**. Learn remote MAC →
   remote SID from decapped frames (EVPN Type-2 in the control plane); tee
   BGP EVPN routes (Type-2 → remote FDB, Type-3 → per-BD DT2M list) so a real
   EVPN control plane drives it. `End.M` egress-protection mirror.

## Out of scope (this slice)

BUM/`End.DT2M`, MAC learning over the overlay, multi-PE ingress replication,
symmetric IRB (L3 gateway on the SRv6 L2 domain), 802.1Q-tagged bridge
domains, and the EVPN control-plane tee — all listed above as later slices.
