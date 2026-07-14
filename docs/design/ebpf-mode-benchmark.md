# Single-hook eBPF mode (`--ebpf-mode`) — design + veth benchmark

A performance-investigation knob for root-causing the datapath cost measured in
[`xdp-tc-fast-path.md`](../../xdp-tc-fast-path.md) (cradle ~63 % of kernel on a
physical NIC). It restricts the datapath to **plain IPv4 L3 forwarding through a
single eBPF hook**, so the XDP-hook and TC-hook costs can be measured in
isolation instead of paying both in the normal `cradle_xdp → cradle_tc →
cradle_egress` pipeline.

## Config surface

```
system { ebpf { enabled true; mode {tc-only | xdp-only}; } }
```

zebra-rs passes the mode to the managed engine as `cradle serve --ebpf-mode
<mode>` (a change restarts the child); `show ebpf` reports it. Non-L3 features
(NAT, policy, overlay, L2) are unsupported while a mode is set — **benchmark
only, not for production**.

## What each mode does

- **tc-only** — attaches *only* `cradle_tc`. `try_main` reads `DPC_L3_ONLY` and
  skips the L7 / NAT / conntrack / egress-policy stages, forwarding straight
  through the existing `l3_forward` (kept as one call site — a second inlined
  copy of `#[inline(always)] l3_forward` overflows the 512 B verifier stack).
- **xdp-only** — attaches *only* a **dedicated** program `cradle_xdp_l3`
  (separate from the near-budget `cradle_xdp` monolith, so it has its own 512 B
  stack). `xdp_l3_forward_v4` forwards plain IPv4 entirely in XDP: a direct
  DIR-24-8 read (calling the generic `fib4_lookup` would inline the whole engine
  and blow the stack), nexthop + neighbor resolution (`xdp_resolve_l2`), TTL
  decrement with an RFC 1624 incremental checksum, Ethernet rewrite, and
  `bpf_redirect` (`bpf_redirect_neigh` is a TC-only helper the XDP verifier
  rejects). Non-plain cases (encap nexthop, local/blackhole/ECMP, neighbor
  miss, TTL≤1, non-IPv4) fall to `XDP_PASS` / the stack.

Both modes default the IPv4 FIB engine to **DIR-24-8** (scoped to the mode — the
global default stays LPM, so ordinary deployments avoid the ~64 MiB TBL24). A
`STAT_XDP_L3_FWD` counter confirms the XDP fast path is taken.

## Benchmark (veth + namespaces)

Topology `src — r[cradle] — dst`, three network namespaces, veth links, all
NIC offloads off. pktgen floods 60 B IPv4/UDP from `src` at `10.0.2.1`; the
router `r` forwards; throughput is the loss-free forwarding rate (veth tx→rx is
synchronous, so generation and forwarding share a core — the *comparison* under
an identical setup is the signal, not the absolute Mpps). The sinks run a
pass-through cradle so a native XDP redirect is delivered over veth (the
receiving veth peer must have XDP enabled — a veth quirk, not present on a
physical NIC). Config: `scratchpad/{topo.sh,perf.sh,router.json}`.

Kernel 6.8, single flow, 3 runs:

| Mode      | pps (3 runs)              | mean pps | vs kernel |
|-----------|---------------------------|----------|-----------|
| kernel    | 1.405 M / 1.380 M / 1.395 M | ~1.39 M | baseline  |
| tc-only   | 1.539 M / 1.518 M / 1.542 M | ~1.53 M | **+10 %** |
| xdp-only  | 1.614 M / 1.661 M / 1.611 M | ~1.63 M | **+17 %** |

Loss was ~zero in every run (≈20 M/20 M forwarded).

## Findings

- **xdp-only beats tc-only by ~6–7 %** — the XDP hook is leaner than the TC hook
  for plain L3 (no `sk_buff`, earliest point in the RX path), so collapsing the
  two-hook pipeline to a single XDP hook is the fastest option. This is direct
  evidence for the fast-path doc's premise that the XDP tax / double hook is a
  real cost.
- **On veth both single-hook cradle modes *exceed* the kernel**, the opposite of
  the physical-NIC result (63 %). veth is pure software: the kernel's forwarding
  path (full FIB + netfilter hooks) has no hardware offload to lean on, so the
  minimal eBPF single-hook path wins. The physical-NIC gap therefore comes from
  NIC-offload/GRO advantages the kernel enjoys there **plus** the two-hook
  overhead — the latter is what this knob isolates and what a physical-NIC rerun
  of these modes should quantify next.

## Follow-ups

- Rerun these modes on the physical-NIC topology to quantify the two-hook
  overhead there (where the kernel has the offload advantage).
- If xdp-only wins meaningfully on hardware too, the production path is the
  automatic per-port XDP fast path sketched in the fast-path doc (Phase 2/3),
  not this global benchmark knob.
