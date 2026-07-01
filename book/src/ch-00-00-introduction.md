# Introduction

Welcome to an introductory book about *cradle-rs*. cradle-rs is an **eBPF-based
L2–L7 data plane, written from scratch in Rust**, whose forwarding is driven by a
real multi-protocol routing stack —
[zebra-rs](https://github.com/zebra-rs/zebra-rs). The entire stack is Rust: the
data plane is built with [aya](https://aya-rs.dev), so there is no clang or
libbpf anywhere in the toolchain.

## The gap cradle-rs fills

Two existing systems bracket the problem, and neither closes it:

- **Cilium** proves you can run the whole **L3–L7 data plane in eBPF**: pinned
  BPF maps as the shared-state contract, tail-call staging under the verifier
  limit, socket load balancing, conntrack/NAT, and L7 via a proxy redirect — over
  a flat L3 fabric (its L2 story is ARP-based service announcement, not eBPF
  switching). But its **routing-protocol integration is the weak seam** — the BGP
  control plane is *advertisement-only* and, by Cilium's own docs and open
  proposals, **does not install learned routes into the data plane**. Native
  routing falls back to the kernel FIB plus out-of-band route distribution.

- **zebra-rs** is the inverse: a mature, multi-protocol Rust routing control
  plane (BGP / OSPF / IS-IS / EVPN / SRv6 / MPLS) with a single clean data-plane
  chokepoint — `FibHandle` — and an existing precedent of feeding aya eBPF
  programs from the control plane through BPF maps.

**cradle-rs is the part neither has built:** a Cilium-class eBPF **L2–L7** data
plane — adding true L2 switching below Cilium's L3 floor — whose forwarding is
*actually driven by* a real routing stack. **Learned**
routes — not just advertised ones — program the eBPF FIB. Nobody has done this
end to end in pure Rust.

## Pure Rust, no clang

The data plane is compiled with aya for the `bpfel-unknown-none` target. A
nightly toolchain with `rust-src` and `bpf-linker` is all that is required —
there is no C compiler, no libbpf, and no BTF-generation step outside what the
Rust toolchain already provides. The kernel side and the user-space side share
one crate, `cradle-common`, whose `#[repr(C)]` types *are* the map ABI, so the
two halves can never disagree on byte layout.

## Map-driven, compile-once

Following the pattern Cilium established, cradle-rs compiles the eBPF object
**once** and configures everything through maps at run time. Adding a service, a
route, or an L7 backend writes a map entry; it never recompiles or reloads the
data plane. The user-space control plane (`cradle`) owns those maps and exposes
a small gRPC API to program them — the same API the zebra-rs `FibHandle` backend
drives.

## What the data plane does

A single TC classifier, attached to each port's `clsact` ingress hook, runs the
packet through staged forwarding logic:

```
 L2 switch / FDB  →  L3 LPM forward + neighbor rewrite  →  L4 LB / NAT / conntrack  →  L7 TPROXY redirect
```

- **L2** — a forwarding database with VLAN-scoped flooding for bridge ports.
- **L3** — longest-prefix-match forwarding for IPv4 and IPv6, with ECMP, using
  `bpf_redirect_neigh` so the kernel resolves the next-hop MAC.
- **L4** — service load balancing (VIP → backends) with connection tracking and
  DNAT/SNAT, for both IPv4 and IPv6.
- **L7** — TCP flows to an HTTP VIP are steered with `bpf_sk_assign` to a
  user-space transparent proxy that routes by request path.

The chapters that follow explain how to build cradle-rs, how to configure each
layer, how to drive it from zebra-rs, and how to observe and test it.
