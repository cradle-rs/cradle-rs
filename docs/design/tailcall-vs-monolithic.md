# eBPF program structure: tail-call staging (Cilium) vs monolithic inlining (cradle) — design note

> Where do you spend the eBPF verifier's budget, and where do you spend
> per-packet cycles? Cilium splits its datapath into many small programs
> chained by `bpf_tail_call`; cradle compiles one fully-inlined program per
> hook; Vinbero (SRv6, same domain as cradle) sits between the two with
> behavior-level dispatch and plugin slots. This note records the
> comparison and cradle's position: stay monolithic until the verifier wall
> is in sight, but pick the future seam (SRv6 behavior dispatch) now.

Status: **analysis only — nothing to implement today.** Written while
evaluating the integration of zebra-rs's `offload/` programs
(`xdp-bfd-echo`, `tc-evpn-replicate`) into cradle, which would grow the
monolith and adds pressure on the verifier budget. (Outcome: `xdp-bfd-echo`
was imported as a `crates/` member; `tc-evpn-replicate` was retired rather than
absorbed — this engine already replicated EVPN BUM toward each leaf's End.DT2M
SID, so the standalone program was redundant.) Builds on the datapath
described in [`architecture.md`](architecture.md); the SRv6 surface it
names as the natural split point is [`srv6.md`](srv6.md) /
[`evpn-srv6.md`](evpn-srv6.md).

## Background: the two structures

**Cilium** structures its datapath around tail calls. Each endpoint's
datapath (`bpf_lxc.c`) compiles to a set of programs indexed by
`CILIUM_CALL_*` constants (~40+ slots: per-AF forwarding continuations,
NAT stages, encryption, SRv6 encap, …) in a per-endpoint `cilium_calls_*`
prog array; the entry classifier does the minimum and `tail_call_static()`s
into the next stage. Per-endpoint policy programs live in a global prog
array (`cilium_call_policy`) indexed by endpoint ID — recompiling one
endpoint's policy swaps one array entry, with no detach/reattach. An
unpopulated slot drops the packet with `DROP_MISSED_TAIL_CALL`.

**cradle** compiles three programs (`cradle_xdp`, `cradle_tc`,
`cradle_egress`) into one object, fully inlined — no `ProgramArray`, no
`bpf_tail_call` anywhere. All frame-resizing work lives in XDP, forwarding
in TC, with the XDP→TC hand-off carried in xdp metadata guarded by the
per-instance `META_COOKIE` XOR.

## Monolithic — pros

1. **Per-packet performance.** No tail-call dispatch cost, and — more
   importantly — the compiler sees the whole pipeline: constant
   propagation, dead-branch elimination, state kept in registers. A tail
   call is a one-way jump into a separate program: registers reset, and
   every stage must redo its `data`/`data_end` bounds checks from scratch.
   A monolith hoists checks once.

2. **Free state passing.** Stack variables flow through the whole path.
   Cilium serializes inter-stage state through `skb->cb` (20 bytes) and
   per-CPU scratch maps — extra map ops per packet and a standing design
   constraint (what fits in 20 bytes?).

3. **No runtime dispatch failure mode.** If the monolith loads, every path
   provably exists. Cilium's equivalent failure is
   `DROP_MISSED_TAIL_CALL`: an unpopulated prog-array slot silently drops
   traffic at runtime — a whole class of operational bugs (load ordering,
   upgrade races) that a monolith cannot have.

4. **Atomic, skew-free updates.** One program per hook, replaced
   atomically via bpf_link. Cilium's prog arrays update entry-by-entry, so
   during an upgrade a packet can traverse a mix of old and new stages;
   managing that skew carries real engineering weight.

5. **Loader and mental-model simplicity.** One object, one load, no
   orchestration of dozens of programs and array-population order.
   Cilium's loader/ELF-templating machinery is a substantial codebase in
   itself. For a small team this is a large, underrated win.

## Monolithic — cons

1. **One shared verifier budget.** The 1M-instruction ceiling and (more
   binding) the analyzed-state budget cover the whole pipeline. The
   failure mode is *nonlocal*: adding feature X can push an unrelated path
   over the limit, and the verifier error points somewhere useless. cradle
   already pays tax here — the constant-latch loop tricks and reading
   `Srv6Encap` through the map pointer (512-byte stack) are symptoms.

2. **One shared 512-byte stack** for the entire path. Each tail call gets
   a fresh stack. (Caveat: mixing bpf-to-bpf calls with tail calls on one
   path caps the stack at 256 bytes, so Cilium doesn't get this for free
   everywhere either.)

3. **`#[inline(always)]` multiplies instructions.** Every call site
   duplicates the body, so instruction count grows faster than source
   does; verification time grows superlinearly with it.

4. **No selective loading.** Features not in use still occupy verifier
   budget unless compiled out. Cilium leaves the slot empty.

5. **No partial update.** Any change to any feature reloads the whole
   program on every port. Cilium can recompile and swap one endpoint's
   policy program without touching the rest of the datapath — that
   per-endpoint atomic swap is arguably the single strongest reason tail
   calls are load-bearing for them.

## Tail-call staging — the mirror image, plus its own costs

Pros: per-stage verifier budget reset, fresh stack per stage,
modular/conditional loading, atomic per-unit replacement, and
**per-endpoint compile-time specialization** — Cilium compiles
endpoint-specific constants into each endpoint's programs instead of doing
generic map lookups.

Costs beyond those already implied: the 33-chained-call kernel limit
shapes pipeline depth; control flow is one-way (no returning from a tail
call), forcing a strict pipeline structure; end-to-end reasoning and
debugging span many programs; and `tail_call_static` mitigates but does
not eliminate dispatch cost.

## Prior art: Vinbero — the hybrid middle point

[Vinbero](https://github.com/takehaya/Vinbero) (takehaya) is the closest
prior art in cradle's own domain: an SRv6 stack with a C/libbpf XDP
dataplane (plus a TC piece for L2VPN), in-process GoBGP v4 (VPNv4/v6,
EVPN-SRv6, MUP, SR Policy), doing EVPN L2VPN on eBPF. It sits exactly
between Cilium and cradle structurally — and its tail-call seam is the one
this note recommends cradle reserve.

**How it uses tail calls:**

- **Inline skeleton, tail-called behaviors.** One XDP entry
  (`xdp_vinbero_main`) does parse → a single "VRF ingress front door" →
  LPM SID/headend lookups *inline*; only on a match does it tail-call into
  a behavior program via four prog arrays: `sid_endpoint_progs` (indexed
  by `srv6_local_action`) and `headend_v4/v6/l2_progs` (indexed by
  `srv6_headend_behavior`). Dispatch is **per SRv6 behavior**, not per
  pipeline stage as in Cilium.
- **State crosses via a per-CPU scratch map, not `cb`.** A single-element
  per-CPU "tailcall ctx" carries `l3_offset`, `dispatch_type`,
  `inner_proto`, target slot, `vrf_id` (set once at entry), plus a union
  holding a **copy of the matched map entry** (12-byte SID entry or
  200-byte headend entry) — the tail-called program never redoes the LPM
  lookup. The call is taken only if the ctx write succeeded
  (`if (tailcall_ctx_write_headend(...) == 0) bpf_tail_call(...)`). No
  magic/version guard on the ctx ABI.
- **Reserved plugin slots.** Slots 16–31 of the headend arrays are
  reserved for third-party BPF programs, registered at runtime via
  `vinbero plugin`, with an SDK doing JSON→BTF marshaling for per-SID
  config; the L2 array reuses the same numbering so plugin slots align
  across L3/L2. A `tailcall_epilogue` program picks per-slot stats maps by
  dispatch type.

**What it teaches cradle:**

1. **It validates the recommended seam.** Behavior-indexed prog arrays are
   the direct analogue of dispatching on cradle's `SRV6_LOCALSID` behavior
   code — an existence proof, in the same domain and on XDP, that
   behavior-level dispatch works and that additions like End.Replicate
   land as "just another slot." Notably, Vinbero adopted tail calls at a
   *smaller* feature scope than cradle's SRv6 surface alone — the verifier
   wall may be closer than it looks.
2. **The scratch-ctx design is worth stealing.** Copying the matched entry
   into per-CPU scratch (rather than re-looking-up in the target, or
   squeezing into 20-byte `cb` / small xdp-meta) is clean and roomy — XDP
   has no `cb`, so per-CPU scratch is the natural carrier if cradle
   splits. Per-CPU scratch within one hook invocation also doesn't leak
   across veth hops the way xdp-meta does, so it needs no `META_COOKIE`
   equivalent; the residual risks are a stale ctx (Vinbero guards with
   write-then-call) and ABI skew with out-of-tree plugins (unversioned
   there; cradle should version it).
3. **A plugin ABI is the one capability a monolith can never have.**
   Stably-numbered reserved slots + a config-marshaling SDK is the pattern
   if cradle ever wants third-party/experimental SIDs without forking the
   datapath. Trust caveat: the verifier proves a plugin *safe*, not
   *correct* — it shares the maps and can drop or misroute traffic.
4. **Opposite control-plane pole.** Vinbero fuses BGP into the dataplane
   daemon (no IPC seam, one lifecycle, BGP-only); cradle/zebra-rs keeps a
   full multi-protocol suite in a separate process behind the gRPC tee.
   Vinbero's choice is consistent with its narrower scope — it has no
   zebra and doesn't need one.

## Which pressures actually apply to cradle

Two observations cut against simply copying Cilium:

- **Cilium's strongest argument doesn't apply.** The per-endpoint policy
  swap exists because Cilium is a multi-tenant per-endpoint policy engine.
  cradle is a router dataplane with global tables (FIB, ILM, localsid,
  FDB) updated per-element via `bpf(2)` — map writes already give atomic
  incremental updates (see
  [`forwarding-table-updates.md`](forwarding-table-updates.md)). cradle
  would adopt tail calls only for the *verifier budget*, not for the
  update model. (If cradle grows per-endpoint policy —
  [`policy-multitenant.md`](policy-multitenant.md) — the plan gets the
  atomic swap from map-in-map inner-map replacement, still without
  per-endpoint programs.)

- **cradle already has a two-stage pipeline for free.** The XDP→TC split
  with the `META_COOKIE` metadata hand-off is functionally a tail call
  across hook layers — separate verifier budgets, separate stacks, state
  via metadata. This is why the monolith has stretched as far as it has.

There is a middle ground before full tail-call adoption:
`#[inline(never)]` bpf-to-bpf functions cut instruction duplication
(though verifier state is still walked per call site), and C-style
*global functions* are verified independently — but aya/Rust ergonomics
for global functions are unproven; treat that as a research item.

## Position

Stay monolithic until the verifier wall is actually in sight — cradle is
currently collecting the monolith's per-packet and operational benefits at
zero cost. But pick the seam now: the natural prog-array boundary is the
**SRv6 behavior dispatch** — `SRV6_LOCALSID` behavior code → tail call per
behavior is a direct analogue of `CILIUM_CALL_*`, and it is exactly where
absorbing zebra-rs's `offload/` functions (End.Replicate, BFD echo timers)
would add pressure. When cradle does split, Vinbero's shape
(behavior-indexed arrays + a per-CPU ctx carrying the matched entry) is a
better template than Cilium's full stage-pipeline — cradle shares
Vinbero's domain (router, global tables), not Cilium's (per-endpoint
multi-tenant policy). Design new features so their cross-stage state
travels via xdp metadata / per-CPU scratch / `skb->cb` rather than the
stack; that keeps the future migration mechanical instead of
architectural.
