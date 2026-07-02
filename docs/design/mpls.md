# cradle-rs MPLS support — design

> Label-switched forwarding in the eBPF data plane, driven by the zebra-rs
> MPLS control plane (static label bindings, SR-MPLS, labeled BGP, L3VPN).

Status: **Phases 1–2 implemented.** Phase 1: transit swap in the TC
classifier, pops in a native-XDP stage, `MPLS_FIB` + `NEIGH6`,
`AddIlm`/`DelIlm`/`SetNeighbor6`, `labels` on nexthops, static JSON config.
Phase 2: **ingress imposition** (TC push — the skb is still IP, so
`adjust_room` grow is allowed), **SR stacks** (multi-label push; XDP
grow-swap completing with an in-XDP L2 rewrite + redirect; a bounded pop
loop resolving chained pops in one pass), **PHP by S bit** (a swap with an
empty out stack — zebra's PHP shape — pops to IP or to the next label per
packet), and the **zebra-rs `CradleFib` MPLS tee** (labeled nexthops, ILM
add/replace/del, and resolved-neighbor feed). Proven by the `cradle_mpls`
(all-static, full operation matrix) and `cradle_mpls_zebra` (zebra-driven
LSP) BDD features. Phases 3–4 below remain design.

## Goal and scope

cradle-rs already forwards IPv4/IPv6 by LPM lookup, resolving the L2 next hop
through the kernel with `bpf_redirect_neigh`. MPLS adds a parallel forwarding
plane: the datapath must classify MPLS frames (EtherType `0x8847`), look up the
top label in a label FIB, and **push / swap / pop** label stack entries before
forwarding. The control plane (zebra-rs) computes the label operations and
programs them through the same gRPC seam that already carries IP routes.

The three router roles an MPLS network needs:

| Role | Ingress | Operation | Egress |
|---|---|---|---|
| **Ingress LER** (imposition) | IP | push one or more labels | MPLS |
| **Transit LSR** (P router) | MPLS | swap top label (± push, for SR) | MPLS |
| **Egress LER** (disposition) | MPLS | pop (PHP / explicit-null), then IP forward | IP |

This covers plain LSPs, SR-MPLS label stacks, labeled-unicast BGP, and — with the
VRF work in Phase 3 — L3VPN egress (pop the VPN label, look up in a VRF).

## Why not `bpf_redirect_neigh` for MPLS

The IP path leans on `bpf_redirect_neigh`: it hands the packet to the kernel's
neighbor layer, which writes the destination MAC and the source MAC and sets the
EtherType from the `nh_family` we pass (`AF_INET`/`AF_INET6`). That is perfect
for IP egress and means cradle owns no ARP/ND state.

It does **not** work when the frame leaves as MPLS. `bpf_redirect_neigh` builds an
*IP* L2 header (EtherType `0x0800`/`0x86dd`); there is no MPLS `nh_family`. So the
MPLS egress path must do the L2 rewrite itself:

- **destination MAC** — resolved from a neighbor map keyed by `(oif, nexthop-IP)`,
  populated by the control plane (zebra-rs already learns these; the tee feeds
  them, extending today's `SetNeighbor4`);
- **source MAC** — the egress port's MAC, already in `PORTS` (`PortConfig.mac`);
- **EtherType** — `0x8847`;

then a plain `bpf_redirect(oif, 0)`.

The one MPLS case that *can* reuse `bpf_redirect_neigh` is the egress-LER
disposition where the result is a bare IP packet to an IP next hop (PHP-to-IP,
or L3VPN pop-to-CE): after the pop the frame is IP again, so we forward it like
any routed packet. Only frames that stay labeled (swap, ingress push, pop that
leaves ≥1 label) need the explicit rewrite. This split keeps the neighbor-map
requirement narrow.

## Packet format recap

An MPLS label stack entry is 4 bytes, big-endian on the wire:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Label                  | TC  |S|       TTL     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Label = 20 bits, TC (EXP) = 3, S (bottom-of-stack) = 1, TTL = 8. Reserved
labels: 0 = IPv4 explicit-null, 2 = IPv6 explicit-null, 3 = implicit-null (means
"pop", never appears on the wire). The label FIB is keyed by the incoming 20-bit
label value.

## Map contract additions (`cradle-common`)

Two changes: a label FIB, and an out-label stack on the existing nexthop.

### 1. `MPLS_FIB` — the incoming-label map (ILM)

```rust
// Keyed by the incoming top label (20-bit value in the low bits of a u32).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MplsEntry {
    /// Index into NEXTHOPS. The nexthop's out-label stack (below) is imposed
    /// after the incoming label is removed (swap) or, for POP_L3, dropped.
    pub nexthop_id: u32,
    /// VRF/table id for POP_L3 disposition (0 = global).
    pub vrf_id: u32,
    /// MPLS_OP_*.
    pub op: u8,
    pub _pad: [u8; 3],
}

pub const MPLS_OP_SWAP:   u8 = 0; // pop incoming, impose nexthop.labels, stay MPLS
pub const MPLS_OP_POP_L3: u8 = 1; // pop to IP, forward (PHP-to-IP / L3VPN egress)
pub const MPLS_OP_POP:    u8 = 2; // pop one label, forward the remaining stack
```

`MplsEntry` is deliberately small — the out-label stack lives on the nexthop, so
one labeled nexthop is shared by every ILM entry and every IP route that imposes
the same stack.

### 2. Out-label stack on `NextHop`

```rust
pub struct NextHop {
    pub gateway_v4: u32,
    pub gateway_v6: [u8; 16],
    pub oif: u32,
    pub flags: u32,          // + NH_F_MPLS
    // --- new ---
    pub labels: [u32; MAX_LABELS],  // out-label stack, index 0 = top/outermost
    pub num_labels: u8,             // 0 = no imposition (plain IP forward / PHP)
    pub _pad: [u8; 3],
}
pub const NH_F_MPLS: u32 = 1 << 2;
pub const MAX_LABELS: usize = 3;    // covers SR-MPLS depths seen in practice
```

Unifying "labels to push" and "label to swap to" on the nexthop keeps the model
small:

- **Ingress LER**: an IP `FibEntry` → a nexthop with `num_labels > 0` ⇒ push
  `labels[0..num_labels]` onto the IP packet, egress MPLS.
- **Transit swap**: `MPLS_FIB[label]` → `MplsEntry{op: SWAP, nexthop_id}`; the
  nexthop's `labels` are the swap value (`labels[0]`) plus any additional SR
  labels — pop the incoming label, impose the stack.
- **PHP / pop**: `op: POP_L3` (result is IP → `bpf_redirect_neigh`) or `op: POP`
  with `num_labels == 0` (still labeled underneath → forward remaining stack).

`MAX_LABELS = 3` bounds both the parse loop and the push loop for the verifier;
deeper SR stacks are a Phase 4 concern (see below). This mirrors zebra-rs's
`NexthopUni.mpls_label` (an unbounded, explicit-only `Vec<u32>` — implicit-null /
PHP labels are already dropped there); cradle caps the depth at `MAX_LABELS` and
the tee rejects anything deeper.

### New maps summary

| Map | Key | Value | Populated by |
|---|---|---|---|
| `MPLS_FIB` | `u32` incoming label | `MplsEntry` | control plane (LFIB) |
| `NEIGH4` *(exists)* | `(oif, ipv4)` | `NeighEntry{mac}` | control plane, extended use |
| `NEIGH6` *(new)* | `(oif, ipv6)` | `NeighEntry{mac}` | control plane |

`NEIGH4` already exists but is currently unused by the datapath (IP forwarding
uses `bpf_redirect_neigh`). MPLS egress makes it load-bearing; `NEIGH6` mirrors
it for IPv6 LSP next hops.

## Data-plane logic (`cradle-ebpf`)

### Classification

`l3_forward` already branches on EtherType. Add the MPLS case, taken in the L3
port path *before* IP handling:

```rust
match u16::from_be(ethertype) {
    ETH_P_MPLS_UC => mpls_forward(ctx),   // 0x8847
    ETH_P_IP      => l3_forward_v4(ctx),
    ETH_P_IPV6    => l3_forward_v6(ctx),
    _             => Ok(TC_ACT_PIPE as i32),
}
```

### `mpls_forward` (TC) — swap

1. Load the top label entry at `EthHdr::LEN`. Extract `label`, `s` (BOS), `ttl`.
2. **TTL**: if `ttl <= 1`, `TC_ACT_PIPE` to the stack (let the host generate the
   ICMP/label TTL-exceeded). Otherwise decrement for the imposed/swapped entry.
3. Look up `MPLS_FIB[label]`; miss ⇒ `TC_ACT_PIPE` (punt) or `TC_ACT_SHOT`.
4. Resolve `nexthop_id → NextHop`.
5. **SWAP** — rewrite the top entry's label to `nh.labels[0]` in place (carry
   TC and BOS, decrement TTL). Egress MPLS via `mpls_l2_xmit` (explicit
   rewrite, below). Phase 1 bounds this to a single-label swap; a stack-growing
   swap (extra SR labels via `adjust_room` grow) is Phase 2.

### `cradle_mpls` (XDP) — pops, PHP, and SR grow-swaps

Frame-resizing MPLS ops do **not** run at TC, for a reason discovered in
implementation: `bpf_skb_adjust_room` returns `-ENOTSUPP` for any skb whose
`skb->protocol` is not IPv4/IPv6 — a TC program cannot resize an MPLS frame
at all. They run in an XDP program attached to L3 ports, where
`bpf_xdp_adjust_head` is unrestricted:

- **Pop loop** (bounded by `MAX_LABELS + 1`): while the ILM says pop —
  explicit **POP** (`s == 0`, keep `0x8847`) or **POP_L3** (`s == 1`,
  EtherType from the exposed version nibble), or the zebra-shaped **PHP: a
  SWAP with an empty out stack**, dispatched on the packet's S bit — shift
  the Ethernet addresses over the LSE and `adjust_head(+4)`. Chained pops
  (PHP + stacked labels, later the VPN label) resolve in one pass; the
  frame then `XDP_PASS`es into the stack as plain IP (TC routes it) or as
  MPLS whose next label TC swaps in place. Pipe-model TTL throughout.
- **Grow-swap** (SWAP with `num_labels > 1` — SR stacks): `adjust_head`
  with a negative delta grows the frame, the full out stack is written
  (TTL − 1, BOS on the innermost iff the incoming label carried it), and
  the frame **completes in XDP** — L2 rewrite from `NEIGH4/6` + `PORTS`
  and `bpf_redirect(oif)` — because passing a swapped frame up would make
  TC re-look-up the *outgoing* label.

After an `adjust_head` the veth native-XDP receive path re-runs
`eth_type_trans`, so `skb->protocol` matches the popped frame and the TC
stages compose naturally. One more implementation-discovered constraint:
the program attaches in **native (driver) mode** — generic XDP is skipped
entirely for TC-redirected skbs (`netif_receive_generic_xdp` bails on
`skb_is_redirected`, set by the previous hop's `bpf_redirect` since ~6.3),
which is exactly how a mid-LSP frame arrives on a veth chain. veth supports
native XDP; on drivers that don't, cradle falls back to generic mode with a
logged caveat.

The hook-placement rule: **operations that change an MPLS-protocol frame's
length live in XDP; everything else lives in TC** — single-label swaps
rewrite in place, and push grows an *IP* skb, which `adjust_room` does
support.

### Ingress push (from the IP path)

In `l3_forward_v4/v6`, after resolving the nexthop, if `nh.flags & NH_F_MPLS`:
grow the room by `4*nh.num_labels` (`BPF_ADJ_ROOM_MAC`), write the label entries
(setting BOS on the innermost, copying the IP TTL into the outer label TTL), set
EtherType `0x8847`, and hand off to `mpls_l2_xmit`. No IP TTL decrement games —
the label TTL carries the hop count on the LSP.

### `mpls_l2_xmit` — the explicit MPLS L2 rewrite

```
dst_mac = NEIGH{4,6}[(oif, nexthop-gateway-IP)].mac   // control-plane fed
src_mac = PORTS[oif].mac
ethertype = 0x8847
store dst_mac @0, src_mac @6, ethertype @12
return bpf_redirect(oif, 0)
```

A neighbor miss ⇒ `TC_ACT_PIPE` (punt to the host stack, which resolves the
neighbor and, via the control-plane tee, backfills `NEIGH{4,6}`) so the LSP
"warms up" the same way IP connected routes do.

### Packet geometry

Push and pop change the frame length between the MAC header and the payload.
The available resizing tools differ by hook, and this drives the TC/XDP split
above:

- **TC `adjust_room(len_diff, BPF_ADJ_ROOM_MAC, 0)`** inserts/removes bytes
  right after the Ethernet header — but **only on IPv4/IPv6 skbs**
  (`-ENOTSUPP` otherwise). Usable for the Phase 2 ingress push (the skb is
  still IP when labels are imposed); unusable for pops (the skb is MPLS).
- **XDP `bpf_xdp_adjust_head(delta)`** moves the packet start with no
  protocol restriction — the pop mechanism.

Standard resizing rules apply at both hooks: resize before writing the new
bytes, re-derive all packet pointers afterward, keep every access inside
re-validated bounds.

### Verifier budget

The current `cradle_tc` is one classifier with every stage inlined. MPLS adds a
bounded parse and a bounded push loop (`MAX_LABELS`), which is affordable for the
swap/PHP/single-push MVP. If deep SR stacks or the VRF lookup push complexity
past the limit, move MPLS into a **tail-call** program (the architecture doc
already lists tail-call staging as a borrowed technique): the classifier
tail-calls `cradle_mpls` on EtherType `0x8847`. This keeps the IP fast path lean
and isolates MPLS complexity. The MVP stays inline; the tail call is the escape
hatch.

## Observability

Add counters, mirroring the existing `STAT_*` scheme:

```
STAT_MPLS_PUSH   // IP → labels imposed (ingress LER)
STAT_MPLS_SWAP   // label swapped (transit LSR)
STAT_MPLS_POP    // label popped (PHP / egress LER)
```

Surfaced through the existing `GetStats` RPC and `cradle ctl stats`, and used by
the BDD suite to assert *which* MPLS operation handled a packet.

## Control-plane API (gRPC)

The seam is the same `cradle.v1.Cradle` service. zebra-rs's MPLS surface is
narrow and worth matching exactly: there are **no** `route_mpls_*` / `lsp_*`
calls. It is the **ILM triplet** — `FibHandle::ilm_add` / `ilm_replace` /
`ilm_del`, keyed by the 20-bit incoming label — plus an **out-label stack carried
on the nexthop object** (`nexthop_add`, where `Group::Uni.labels` is non-empty).
cradle mirrors that with two additions:

1. **Out-label stack on `Nexthop`.** Extend the existing message so a nexthop can
   carry an imposition/swap stack — exactly as zebra rides the stack on
   `nexthop_add`:

   ```proto
   message Nexthop {
     // ... existing fields ...
     repeated uint32 labels = 6;   // out-label stack, [0] = outermost
   }
   ```

   This alone enables ingress-LER push (a labeled nexthop referenced by an IP
   route via its `nexthop_id`) and supplies the swap stack for transit entries.

2. **The label FIB (ILM).** New RPCs mirroring `ilm_add` / `ilm_del`:

   ```proto
   message Ilm {
     uint32 in_label     = 1;   // 20-bit incoming label (the LFIB key)
     uint32 nexthop_id   = 2;   // resolved nexthop; its labels are the swap stack
     uint32 action       = 3;   // MPLS_OP_SWAP | POP | POP_L3
     uint32 vrf_table_id = 4;   // for POP_L3 into a VRF (0 = global)
   }
   message IlmDel { uint32 in_label = 1; }

   rpc AddIlm(Ilm)    returns (Empty);
   rpc DelIlm(IlmDel) returns (Empty);
   ```

   zebra expresses the incoming-label action as an `IlmType`: `Swap` / `Node`
   (prefix-SID) / `Adjacency` (adj-SID) map to `MPLS_OP_SWAP`; implicit-null / PHP
   (an empty out-label stack) maps to `POP`; `DecapVrf` / `ContextLabel` (L3VPN
   egress) map to `POP_L3` with `vrf_table_id`. The tee resolves zebra's inline
   `(via, oif)` to a cradle `nexthop_id` the same way the IP tee already does.

3. **Neighbor for IPv6** (MPLS egress needs it): add `SetNeighbor6`, mirroring
   `SetNeighbor4`.

`cradle`'s `Control`/`Dataplane` gain `ilm_add/del`, a `labels` parameter on
`nexthop_set`, and `neigh6_set`. The JSON bootstrap/`ctl apply` config gains
optional `labels` on nexthops and an `ilm` array so the data plane is provable
standalone, before the zebra tee.

## Control-plane integration (zebra-rs)

zebra-rs already tees IP FIB operations to cradle over gRPC through its
`CradleFib` backend (`zebra-rs/src/fib/cradle.rs`), gated by the `system
cradle-grpc` YANG leaf / `CRADLE_GRPC` (see
[the manual's integration chapter](../../book/src/ch-02-00-zebra-integration.md)).
Today that tee forwards **only** IPv4/IPv6 unicast routes and their nexthops and
carries no labels — so MPLS genuinely extends both `proto/cradle.proto` and the
tee. The hooks to add:

- **labeled routes** (SR-MPLS, labeled-unicast BGP, static label binding) — the
  nexthop zebra hands the FIB already carries `mpls_label`; `nexthop_add` is teed
  as a `Nexthop { labels }`, and the IP route references it by `nexthop_id`
  (ingress LER push);
- **ILM entries** — tee `FibHandle::ilm_add` / `ilm_replace` / `ilm_del` to
  `AddIlm` / `DelIlm` (transit swap, PHP, L3VPN VPN-label decap);
- **neighbors** — extend the forwarded neighbor updates to `SetNeighbor6`.

The static-config surface already exists in zebra: `config-static.yang`'s
`mpls { label { nexthop { outgoing-label } } }` bindings emit `IlmAdd` / `IlmDel`,
and a per-nexthop `label` leaf-list on an IP static route pushes an out-label
stack. Nothing MPLS-specific lives in cradle's policy: zebra-rs decides the label
operations; cradle executes them in eBPF. This is the whole thesis — a real
routing stack driving the eBPF data plane — applied to labels.

## VRF / L3VPN (Phase 3)

L3VPN egress needs a per-VRF IP lookup after popping the VPN label. Today cradle
has a single global `FIB4`/`FIB6`. Two options, in increasing order of work:

1. **Per-CE / per-prefix label** (no VRF lookup): zebra allocates the VPN label
   per CE nexthop, so `MPLS_FIB[vpn_label]` = `POP_L3` to a specific nexthop —
   pop and `bpf_redirect_neigh` to the CE. Works within the MVP map contract; the
   common case for many deployments.
2. **Per-VRF label** (true VRF FIB): make `FIB4`/`FIB6` keyed by `(table_id,
   prefix)` (an outer hash of LPM tries, or a `table_id` prefix in the key).
   `MplsEntry.vrf_id` selects the table; `POP_L3` pops then looks up in that VRF.
   This is a larger change and is scoped to Phase 3.

The map contract above already carries `vrf_id` on `MplsEntry` so Phase 1/2 don't
need an ABI break to reach Phase 3.

## Testing (BDD)

A `cradle_mpls` feature mirroring `cradle_zebra`: a three-namespace LSP —

```
 cl ── ingress-LER [cradle] ── transit-LSR [cradle] ── egress-LER [cradle] ── srv
        push 16                   swap 16→17               pop (PHP)
```

Kernel MPLS forwarding (`net.mpls.platform_labels`) stays **0** on the
forwarders, so a ping/HTTP that crosses the LSP proves the *eBPF* data plane
switched the labels — the same "kernel forwarding off" trick the IP features use.
Assert `mpls_push`/`mpls_swap`/`mpls_pop` counters are nonzero at the respective
hops. Drive it two ways: first a static JSON config (nexthop `labels` + an `ilm`
array) to prove the datapath, then a zebra-rs static label binding
(`config-static.yang` `mpls/label`) teed over gRPC to prove the integration. Each scenario ends with the mandatory
`Scenario: Teardown topology`.

## Phasing

1. **Phase 1 — transit + disposition** *(done)*. `MPLS_FIB`, `NEIGH6`,
   swap / PHP-to-IP / pop, `mpls_l2_xmit`, counters, gRPC `AddIlm` +
   `SetNeighbor6`, static config, `cradle_mpls` BDD (static). The P-router
   and egress-LER roles.
2. **Phase 2 — imposition + SR + zebra tee** *(done)*. Labeled nexthops
   (`NH_F_MPLS`, push), ingress LER, SR stacks (grow-swap, chained pops,
   S-bit PHP), and the zebra-rs `CradleFib` MPLS tee — labeled nexthops,
   `ilm_add/replace/del`, and the resolved-neighbor feed `mpls_l2_xmit`
   depends on (`cradle_mpls_zebra` BDD).
3. **Phase 3 — L3VPN.** Per-VRF FIB tables and `POP_L3` VRF lookup; the
   per-CE-label shortcut lands earlier, in Phase 1, as a special case.
4. **Phase 4 — depth & offload.** Tail-call the MPLS program if the verifier
   budget demands it; raise `MAX_LABELS`; entropy/EL label handling.
```
