# cradle-rs EVPN over MPLS — design

> Ethernet (L2VPN) over an MPLS fabric in the eBPF data plane: a CE frame is
> carried under an EVI service label — beneath whatever transport LSP reaches
> the egress PE — which that PE pops and bridges into the local bridge domain.
> RFC 7432's original encapsulation, and the one the Linux kernel has **no**
> data path for at all: unlike VXLAN (kernel vxlan device) or SRv6 (kernel
> seg6local), there is no kernel action that pops an MPLS label and hands the
> exposed Ethernet frame to a bridge. cradle is what makes it forward.

Status: **Slices 1–3 implemented.** Slice 1: unicast `l2_mpls_encap` /
`MPLS_OP_POP_L2`, the gRPC and static-JSON surfaces, and the
`cradle_evpn_mpls` BDD (two PEs, CE-to-CE ping over an MPLS underlay with
kernel MPLS off). Slice 2: BUM — the per-BD all-ones-MAC sentinel and
multi-PE ingress replication (`REPL_KIND_MPLS` slots), proven by
`cradle_evpn_mpls_bum` and `cradle_evpn_mpls_multi`. Slice 3: the zebra-rs
BGP EVPN control-plane tee — `router bgp afi-safi evpn encapsulation mpls`
with a declared `evi`, whose Type-2/Type-3 routes drive the FDB entries,
replication slots and decap ILM end to end (`cradle_evpn_mpls_zebra`). It
builds on the MPLS
phases ([mpls.md](mpls.md)) and reuses the L2 switching, FDB, flood and
bridge-domain machinery the SRv6 and VXLAN overlays already established
([evpn-srv6.md](evpn-srv6.md), [evpn-vxlan.md](evpn-vxlan.md)) — this is a
third *encapsulation*, not a third L2 stack.

## Packet format

An inner Ethernet frame under a label stack, EtherType `0x8847`:

```
[ outer eth 0x8847 ][ transport LSP labels… S=0 ][ EVI service label S=1 ][ inner eth ][ payload ]
```

The transport labels come from the underlay nexthop (an SR-MPLS prefix-SID, an
LDP label, or nothing at all when the PEs are adjacent); the bottom-of-stack
label is the *egress PE's* downstream-assigned EVI label, which identifies the
bridge domain on that PE. Every imposed LSE is seeded TTL 255: an Ethernet
payload has no inner TTL to copy, so the pipe model is the only one that
applies.

**No control word.** RFC 7432 leaves the Ethernet control word optional and it
must be agreed by both ends, so it is a later negotiated knob. The hazard it
addresses is real but narrow: a P router doing deep ECMP hashing can mistake a
customer frame whose first nibble is 4 or 6 for an IP packet and hash the flow
on garbage.

## Why the encap lives in XDP (not TC)

The same constraint that forced MPLS pops and MAC-in-SRv6 encap into XDP:
`bpf_skb_adjust_room` returns `-ENOTSUPP` for any skb whose protocol is not
IPv4/IPv6, and a bridged frame can be ARP or any other EtherType. So the grow
runs in the `cradle_xdp` stage with `bpf_xdp_adjust_head`, which has no
protocol restriction and gives a predictable byte layout.

## Data-plane logic

### Ingress PE — `l2_mpls_encap` (`cradle_xdp`, L2 port)

A frame on a `PORT_F_L2` port whose destination MAC hits an `FDB_F_MPLS |
FDB_F_REMOTE` entry:

1. Resolve the underlay adjacency — the entry's explicit `nexthop_id`, or a
   `FIB4` lookup on the remote PE address (`FdbEntry::remote_sid`, v4-mapped).
   That route's nexthop carries the transport LSP stack, so the control plane
   never has to pre-resolve one: it advertises *the PE*, and the IGP's own
   labelled route supplies the tunnel. IPv6 underlays punt (see *Limits*).
2. `xdp_resolve_l2` for the outer MACs from `NEIGH4/6` + `PORTS` — MPLS egress
   can never use `bpf_redirect_neigh` (there is no MPLS `nh_family`; see
   [mpls.md](mpls.md) §"Why not `bpf_redirect_neigh` for MPLS").
3. `adjust_head(-(14 + 4·(n+1)))`, write the outer Ethernet (`0x8847`), the `n`
   transport labels (S=0) and the service label (S=1).
4. `bpf_redirect` out the adjacency. `stat_inc(STAT_MPLS_L2_ENCAP)` — or
   `STAT_MPLS_L2_BUM` for a flooded copy.

### Egress PE — `MPLS_OP_POP_L2` (`cradle_xdp`, then TC)

An ILM whose `op` is `MPLS_OP_POP_L2` says "this label is an EVI service
label". `try_mpls_xdp` dispatches it **before** resolving the nexthop — a
service label is purely local, never forwarded on, so its ILM carries no
adjacency and the `NEXTHOPS` lookup would miss. `pop_decap_l2` then:

1. `adjust_head(+(14 + 4))` — drop the outer Ethernet and the one LSE, so the
   inner Ethernet frame is at the front. `stat_inc(STAT_MPLS_L2_DECAP)`.
2. Attach the ILM's bridge domain as `XDP_META_MAGIC_L2` metadata — the exact
   hand-off `srv6_dt2u` uses.
3. `XDP_PASS`. The TC stage's `tc_meta_l2` sees the tag and dispatches
   `l2_switch(bd, from_overlay = true)`, so unicast forwarding, flooding **and
   EVPN split horizon** all come for free.

A `POP_L2` label that is not bottom-of-stack is malformed — what sits under it
is not an Ethernet frame — and is dropped rather than misparsed.

Transport labels above the service label need no special handling: they are
ordinary ILMs. In the two-PE BDD the egress PE's transport ILM is the familiar
oif-less "swap with no out-labels" (the UHP shape), so the transport pop and
the service-label decap chain in one XDP pass.

## Map / ABI additions (`cradle-common`)

| Addition | Meaning |
|---|---|
| `FDB_F_MPLS` | set with `FDB_F_REMOTE`; `remote_sid` holds the PE address, `oif` the underlay nexthop id |
| `FdbEntry.label` | the remote PE's EVI service label |
| `MPLS_OP_POP_L2` | ILM op; `MplsEntry.vrf_id` is reused as the **bridge domain** |
| `REPL_KIND_MPLS` | `ReplTarget.addr` = remote PE, `.vni` = its BUM label — no struct change |
| `STAT_MPLS_L2_{ENCAP,DECAP,BUM}` | the counters the BDD asserts on |

### The BPF stack budget — a constraint this slice ran into

`cradle_xdp` is one flattened frame, and the 512-byte BPF stack limit is a live
constraint, not a theoretical one. This slice hit it twice:

- **At compile time**, when `l2_overlay_encap` dispatched to a *third* encap
  body and the replication-slot path dispatched to all three again. Fixed by
  making `l2_overlay_encap` the single encap call site every caller funnels
  through — the slot path restates its target in those terms instead of
  branching on the slot kind itself.
- **At load time** (the verifier, which the compiler does not model), when
  `FdbEntry` grew 8 bytes and four throwaway `FdbEntry` stack temporaries grew
  with it: `combined stack size of 2 calls is 544. Too large`. Fixed by giving
  the encap functions the target's fields — `(addr, nh_id, aux)` — instead of a
  synthesized `&FdbEntry`, so the call sites that had no real FDB entry stopped
  building one.

The lesson worth carrying: **a clean `cargo build` proves nothing about the
verifier.** Load the program (run the BDD) before believing a datapath change
fits.

## Control-plane API (gRPC)

- `FdbRemote` gains `remote_pe` + `remote_label` (a non-empty `remote_pe`
  selects the MPLS flavor; exactly one of `remote_sid` / `remote_vtep` /
  `remote_pe`).
- `ReplSlot` gains the same pair, for RFC 7432 ingress replication.
- `Ilm.action` accepts `3` (`POP_L2`), with `vrf_table_id` carrying the bridge
  domain. **No new field** — the same reuse `LocalSid.vrf_id` already applies
  to `End.DT2U`/`End.DT2M`.

The static JSON bootstrap mirrors all three (`fdb` entries with `remote_pe` +
`label`, `ilm` entries with `"action": "pop-l2"` and a `bd`, `repl_slots` with
`remote_pe` + `label`), so the data plane is provable standalone — before any
control plane exists — exactly as MPLS and EVPN-over-SRv6 were.

## Testing (BDD)

`c1 ── pe1[cradle] ──10.0.1.0/24── pe2[cradle] ── c2`, both CEs in bridge
domain 100, kernel IPv4 forwarding off and kernel MPLS untouched
(`net.mpls.platform_labels` stays 0) on the PEs — so a successful ping proves
the *eBPF* stage imposed and disposed of the labels.

- `cradle_evpn_mpls` — unicast: static ARP on the CEs + static FDB rows (remote
  MAC → PE + service label) keep it BUM-free. The FDB rows name only the PE, so
  the transport label is picked up from the PE's `/32` route — the shape an
  SR-MPLS underlay produces. Asserts `mpls_l2_encap` / `mpls_l2_decap` on both
  PEs (the ping is bidirectional).
- `cradle_evpn_mpls_bum` — no static ARP, so the first frame is a broadcast ARP
  that must take the all-ones-MAC sentinel. A *distinct* BUM label per PE
  (1200/2200 beside the unicast 1100/2100) is what makes `mpls_l2_bum` prove
  the sentinel row — not the unicast row — carried it.
- `cradle_evpn_mpls_multi` — three PEs on a hub underlay, static replication
  slots, no unicast FDB: every pair reaches every other by flood-and-learn, and
  bounded BUM counters prove the horizon holds. pe2↔pe3 is two hops, so those
  copies carry a transport label pe1 pops and forwards — `mpls_pop` on pe1
  proves the transit hop, and exercises the rule that the service label
  underneath belongs to the egress PE and is never looked up locally.

- `cradle_evpn_mpls_zebra` — the whole stack, BGP-driven, three transit
  nodes: `c1 ── pe1 ── p ── pe2 ── c2`, IS-IS SR-MPLS for the transport LSP
  and iBGP L2VPN-EVPN for the service. Fully dynamic — no static ARP, FDB,
  slots or labels anywhere. The P router carries no EVPN state at all: it
  only swaps (and, being penultimate for both loopbacks, pops) the transport
  label, which is what makes this the layering test — BGP advertises a *PE*,
  IS-IS supplies the label to reach it, and the data plane composes the two.

Mandatory teardown scenario on each.

Two integration traps this feature walked into, both worth knowing:

- **The PEs' own iBGP session** is router-originated TCP entering an
  XDP-forwarded core. It leaves the stack with deferred (partial) checksums
  that an XDP redirect never resolves, so the far end drops the segments
  while ICMP and transit traffic flow fine — the session simply never
  establishes. The BDD disables TX checksum offload on the core-facing
  veths. Same trap [`mpls.md`](mpls.md) records for L3VPN.
- **An ILM installed before the tee connects was never re-teed.** zebra's
  post-connect resync walked IP routes but not the ILM table, and a service
  label is programmed once, at config load — exactly when the tee is still
  connecting. The symptom is maximally confusing: both control planes look
  correct, `show mpls ilm` lists the decap, and the egress PE silently drops
  frames whose top label it has no entry for. Fixed in zebra-rs (#2129).

One harness bug had to be fixed to run these: every per-feature resource is
named `<feature-tag>_<logical>`, and the startup sweep / clean-environment
check matched namespaces and pid files by that bare prefix — so
`cradle_evpn_mpls` would delete `cradle_evpn_mpls_bum`'s *live* namespaces when
the two ran concurrently, and report them as its own leak. Both scans now skip
names owned by a feature whose tag extends this one's
(`World::sibling_prefixes`). Bridges and host veths were never affected: they
carry `short_id()`, a hash of the whole tag.

## Limits / next slices

- **IPv4 underlay only.** An IPv6-underlay PE would need a second 16-byte-key
  trie lookup inlined into `cradle_xdp`, which the stack budget above does not
  have room for today; MPLS cores are IPv4 in practice, and such an entry punts
  to the host stack rather than misforwarding.
- **Multihoming** — Type-1/Type-4 and the ESI label's split-horizon check,
  which needs a second label inspection below the service label.
- Out of scope for now: multihoming (Type-1/Type-4 and the ESI label's
  split-horizon check, which needs a *second* label inspection below the
  service label), the control word, EVPN-VPWS over MPLS, and symmetric IRB.
