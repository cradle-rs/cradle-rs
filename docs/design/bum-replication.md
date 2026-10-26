# BUM replication: why a veth slot per remote PE — design note

> EVPN ingress replication needs N copies of one frame, each with a *different*
> outer header, and in a real fabric those N copies leave through the *same*
> uplink. This note records why cradle manufactures a netdevice per remote PE
> to get that, why the obvious XDP alternative (devmap broadcast with per-entry
> egress programs) cannot express it, and the one composition the datapath
> cannot serve — now refused rather than trusted.

Status: **the mechanism is implemented and BDD-proven**; the devmap comparison
is analysis, and the guard it motivated is in
(`cradle_evpn_bum_guard`). Builds on [`architecture.md`](architecture.md) and
[`tailcall-vs-monolithic.md`](tailcall-vs-monolithic.md); the per-overlay
detail lives in [`evpn-srv6.md`](evpn-srv6.md), [`evpn-vxlan.md`](evpn-vxlan.md)
and [`evpn-mpls.md`](evpn-mpls.md).

## The problem

BUM — broadcast, unknown unicast, multicast — in an EVPN bridge domain must
reach every remote PE. With ingress replication the headend makes one copy per
PE, and each copy carries that PE's own encapsulation: its `End.DT2M` SID, its
VTEP, or its EVI label under the transport LSP. The *inner* frame is identical
in every copy; everything outside it differs.

Two properties make this awkward in eBPF:

1. **The copies need different headers, not just different output ports.** A
   plain clone-and-forward is not enough.
2. **The copies usually leave through the same device.** PEs in a fabric sit
   behind one uplink (or an ECMP set); "one copy per egress interface" is not
   the shape of the problem.

## What cradle does

`flood()` (TC) clones the bare frame to each member of the bridge domain's
flood list with `bpf_clone_redirect`. A remote PE is represented in that list
by a **replication slot**: a cradle-owned veth pair whose A end is the flood
member and whose B end carries a `REPL_SID` row naming that PE's target
(`ReplTarget { kind, addr, vni, esi_label }`). A cloned copy lands on the A
end, crosses to the B end, and the XDP stage there encapsulates it toward that
slot's PE and forwards it over the underlay.

```
             ┌─ local AC ports ───────────────────────────▶ (bridge locally)
 BUM ──▶ flood() ─┬─ slot A₁ ══ veth ══ B₁ ─[XDP encap → PE1]──▶ uplink
  (TC)            ├─ slot A₂ ══ veth ══ B₂ ─[XDP encap → PE2]──▶ uplink
                  └─ slot A₃ ══ veth ══ B₃ ─[XDP encap → PE3]──▶ uplink
```

The veth hop looks like overhead to be optimised away. It is not: **the slot's
ifindex *is* the per-copy identity.** `bpf_clone_redirect` chooses a
netdevice, so giving each PE its own netdevice is what turns "one frame, N
different outer headers" into something the hook can express at all. The B end
then has a private ingress context in which the copy is a whole packet again,
with full XDP framing powers — which matters because MPLS/SRv6/VXLAN L2 encap
is frame *resizing*, and TC cannot resize a non-IP frame
([`architecture.md`](architecture.md)).

`flood()` also makes per-copy *decisions*, not just per-copy rewrites: `SLOT_ES`
affinity (which slot carries a segment's BUM, and with which ESI or leaf
label), the `ES_DF` non-DF filter, E-Tree leaf/root withholding, and the
`es_bits` local-bias split horizon. Those are filters over the member list, so
they live naturally where the member list is.

### The single-remote fast path

A domain with exactly one remote PE does not need any of this. The all-ones-MAC
FDB entry — the **BUM sentinel** — names that one target, and `l2_evpn_xdp`
matches it in XDP and encapsulates there, never reaching TC. One map row
instead of a veth pair, and one hook instead of three.

## The XDP alternative, and why it does not apply

[takehaya's note of 2026-10-26][takeio] argues — correctly — that XDP can
replicate and rewrite each copy independently, disputing the eBPF'26 *XDP_CLONE*
paper's claim that it cannot. The mechanism is `bpf_redirect_map()` with
`BPF_F_BROADCAST` over a `DEVMAP_HASH` whose entries each carry a program with
the `xdp_devmap` expected attach type. Verified against the kernel source
(`kernel/bpf/devmap.c`, v6.12 through current `master`):

* `dev_map_bpf_prog_run()` loops per frame, converting each clone to its own
  `xdp_buff`, running the program, and writing it back with
  `xdp_update_frame_from_buff()`. Per-copy rewriting is real.
* `XDP_PASS` there means *keep this copy for transmission*, not *to the stack*;
  `XDP_DROP` discards that copy alone. Anything else is warned about and
  dropped.
* `dev_map_enqueue_multi()` iterates per *entry* for `DEVMAP_HASH`, so several
  keys may name the same ifindex and each gets a copy.

That last point is what makes it look applicable to N-PEs-behind-one-uplink.
It is not, because of how the copies are batched:

```c
static void bq_enqueue(struct net_device *dev, struct xdp_frame *xdpf,
                       struct net_device *dev_rx, struct bpf_prog *xdp_prog)
{
        struct xdp_dev_bulk_queue *bq = this_cpu_ptr(dev->xdp_bulkq);
        ...
        if (!bq->dev_rx) {
                bq->dev_rx = dev_rx;
                bq->xdp_prog = xdp_prog;   /* latched by the FIRST frame */
                ...
        }
        bq->q[bq->count++] = xdpf;
}
```

The bulk queue is **per-device, per-CPU**, and `bq->xdp_prog` is latched by the
first frame enqueued to it. `bq_xmit_all()` then runs *that one program* over
every frame in the queue. Two entries naming the same ifindex with different
programs therefore send both copies through whichever was enqueued first —
order-dependent, and silent.

A single shared program cannot separate them either. The only per-copy context
an `xdp_devmap` program gets is `ctx->egress_ifindex`, identical across those
copies, and `data_meta` is written before replication so every clone carries
the same bytes (`xdpf_clone()` copies the frame wholesale).

**So: at most one distinct rewrite per egress netdevice per flush.** No
per-copy identifier closes that gap without a kernel change. The technique fits
takehaya's case — peers reachable out *distinct* interfaces — and does not fit
EVPN ingress replication, where the fan-out is to PEs sharing an uplink. Our
veth slot supplies exactly the distinct netdevice the bulk queue keys on.

Two further details worth recording, because they would bite anyone porting the
idea here:

* **MTU is checked before the egress program runs, on the pre-rewrite length**
  — in `is_valid_dst()` and again in `__xdp_enqueue()`, both
  `xdp_ok_fwd_dev(dev, xdp_get_frame_len(xdpf))`. After the program grows the
  frame, `ndo_xdp_xmit` is called with no re-check: the kernel will not stop an
  egress program from handing an oversized frame to the driver.
* **`BPF_F_EXCLUDE_INGRESS` excludes the ingress device's upper devices too**
  (`get_upper_ifindexes()`), which is the right behaviour for a bond or bridge
  member but is more than the flag's name suggests.

[takeio]: https://takeio.hatenablog.com/entry/2026/10/26/220402

### What would change the analysis

A per-entry cookie visible to the `xdp_devmap` program — or per-entry program
dispatch that survives bulk queueing — would make devmap broadcast expressible
for this shape, and would be worth revisiting then: it would collapse the veth
hop, and [takeio]'s benchmark suggests the XDP/TC boundary alone is worth
1.6–1.8× on small frames. We have no BUM figure of our own; `bench/` covers
FIB lookup and bulk forwarding, not flooding. Measuring the slot hop is the
prerequisite for taking any of this seriously.

## The sentinel and slots do not compose

The two mechanisms above are alternatives, never layers. The sentinel path
terminates in XDP with a redirect, so if a bridge domain carries **both** the
all-ones sentinel and replication slots:

* BUM matches the sentinel in XDP and is encapsulated toward its single target;
* the TC flood never runs, so **every slot is skipped** — and so is the local
  flood;
* `STAT_SRV6_L2_BUM` (or the VXLAN/MPLS equivalent) increments normally.

Half the flood set disappears with no error and no counter that distinguishes
the broken case from the healthy one. `proto/cradle.proto` has always stated
the contract on `ReplSlot` ("a bridge domain using slots must not also program
the all-ones-MAC sentinel"); it is now enforced at the two write sites rather
than trusted to producers:

| Site | Catches | How the bridge domain is known |
|---|---|---|
| `Dataplane::fdb_overlay_add` | a sentinel added to a domain that floods through slots | an argument |
| `Dataplane::repl_target_add` | a statically-configured slot added to a domain carrying the sentinel | `bd_of_member()` — the slot's A end is already a flood member |
| `Control::add_repl_slot_auto_keyed` | the same for a cradle-owned (Type-3 tee) slot | an argument; the A end joins the domain only *after* the target is programmed, so `repl_target_add` cannot see it yet |

`bd_has_repl_slot()` walks the flood list and tests each member for a
`REPL_SID` row — the same membership test `flood()`'s `local_only` exclusion
makes, so the guard sees a slot exactly when the datapath would.

The refusal is an error, not a warning, precisely because the failure it
prevents is invisible: there is no counter a reader could have used to notice
it. Producers are unaffected in practice — the EVPN Type-3 tee uses slots
exclusively (zebra-rs's `fib/cradle.rs` has no all-ones MAC anywhere; every
`add_fdb_remote` formats a Type-2 route's MAC), and the static configs use one
mechanism or the other.

`cradle_evpn_bum_guard` pins all of it: both mechanisms alone are accepted (the
positive control), the sentinel is refused where slots exist, a bootstrap
config carrying both is refused outright, and the refused attempt leaves the
flood path untouched. Mutation-checked — with both guards neutered, three of
those steps fail.

### The same failure shape, next door

`cradle ctl apply` used to walk only the sections it had been taught, printing
`applied` and silently discarding `repl_slots`, `repl_segs`, `xconnects`,
`dx2v`, `vtep_source6`, `fib4_mode` and `fdb_age_secs` — an operator told it
worked, with nothing to say otherwise. Closed in the same change:
`repl_segs`, `xconnects` and `vtep_source6` have RPCs behind them and are now
sent; the other four cannot be replayed and are refused up front, before any
RPC, so a doomed apply does not land half of itself.

`repl_slots` is one of the four, and for a reason worth recording here: the
static section names operator-created veth ports and carries no bridge domain,
while the gRPC `AddReplSlot` takes a bridge domain and creates its own pair.
They are not the same operation, so a slot still arrives either from
`serve --config` or from the Type-3 tee — which is why
`cradle_evpn_bum_guard` drives the slot direction through the bootstrap path.
`cradle_ctl_apply_guard` pins the rest.
