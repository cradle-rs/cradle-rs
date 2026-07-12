# cradle-rs architecture

> eBPF-based L2–L7 networking with routing-protocol integration, in Rust.

## The idea

Two existing systems bracket the problem:

- **Cilium** proves you can run the entire **L3–L7 data plane in eBPF** — pinned
  BPF maps as the shared-state contract, identity-based policy, tail-call
  staging, socket-LB, conntrack/NAT, and L7 via a proxy redirect, over a flat L3
  fabric (its L2 story is ARP-based service announcement, not eBPF switching).
  But its
  **routing-protocol integration is the weak seam**: the BGP control plane is
  *advertisement-only* and, by Cilium's own docs and open CFPs (#34841, #31091),
  **does not install learned routes into the data plane**. Native routing falls
  back to the kernel FIB plus out-of-band route distribution.

- **zebra-rs** is the inverse: a mature, multi-protocol Rust routing control
  plane (BGP/OSPF/IS-IS/EVPN/SRv6/MPLS) with a single clean data-plane
  chokepoint — `FibHandle`, selected at compile time by `cfg(target_os)` — and
  an existing precedent of feeding **aya** eBPF programs from the control plane
  via BPF maps (the imported `crates/xdp-bfd-echo`; the sibling
  `tc-evpn-replicate` BUM-replication offload was retired once this engine
  subsumed it).

**cradle-rs is the part neither has built:** a fully-Rust, Cilium-class eBPF
**L2–L7** data plane — adding true L2 switching below Cilium's L3 floor — whose
forwarding is *actually driven by* a real routing stack —
**learned** routes (not just advertised ones) program the eBPF FIB. The whole
stack stays in Rust (aya), which nobody has done end to end.

## Shape

```
 zebra-rs control plane   (BGP / OSPF / IS-IS / EVPN / SRv6 → RIB best-path + nexthop groups)
            │   FibHandle boundary   (route_*_add/del, nexthop_sync, neigh, L2/EVPN)
            ▼
 cradle  (user-space, aya)  ── reconciles ──▶   pinned BPF maps
   · loads/attaches programs                    (FIB-LPM, NEXTHOPS, NEIGH,
   · owns the map contract                       FDB, PORTS, SERVICES,
   · route-injection API                         BACKENDS, CT, ...)
            ▼                                            ▲
 cradle-ebpf  (kernel, XDP + TC/tcx, tail-call staged)  ┘  reads maps
   L2 switch/FDB → L3 LPM forward + neigh → L4 LB/NAT/CT → (L7 TPROXY redirect, later)
```

Deliberately borrowed: from Cilium — a central LPM "what/where is this IP" map,
tail-call staging under the verifier limit, compile-once + map-driven config (no
per-endpoint recompile), TPROXY for L7. From zebra-rs — the RIB/nexthop-group
model and the map-feeding offload-supervisor pattern.

## Workspace layout

| Crate | Target | Role |
|---|---|---|
| `cradle-common` | host + bpf | The **data-plane contract**: `#[repr(C)]` POD types used as map keys/values by both sides. `aya::Pod` impls behind the `user` feature. |
| `cradle-ebpf`   | `bpfel-unknown-none` | The eBPF programs (XDP + TC). Built by `cradle`'s build script via `aya-build`; excluded from `default-members`. |
| `cradle`        | host | User-space control plane: loads/attaches programs, programs maps, exposes the route-injection API. |

Build glue: `cradle/build.rs` uses `aya-build` to compile `cradle-ebpf` for
`bpfel-unknown-none` (nightly + `-Z build-std=core`, no clang/libbpf needed) and
embeds the object with `aya::include_bytes_aligned!`.

## Map contract (`cradle-common`)

- **L3** — `FibEntry` (LPM v4/v6 → `nexthop_id`), `NextHop`, `Neigh4Key`/`NeighEntry`.
- **L2** — `FdbKey`/`FdbEntry`, `PortConfig`.
- **L4** — `ServiceKey`/`ServiceInfo`, `BackendKey`/`Backend`, `CtKey`/`CtEntry`.

These define the kernel↔user-space ABI; everything else reconciles into them.

## Control-plane integration (zebra-rs)

The integration target is the `FibHandle` boundary. Two viable couplings:

1. **In-process backend** — add an eBPF `FibHandle` variant inside zebra-rs that
   writes cradle maps directly. Tightest, single process.
2. **Sidecar** — `cradle` runs as its own daemon; zebra-rs programs it over a
   side channel (gRPC / shared pinned maps), mirroring the existing `offload/`
   supervisor pattern. Looser coupling, keeps the data plane independently
   buildable and testable.

Phase 1–3 build `cradle` standalone with a local route-injection API (CLI /
unix socket) so the data plane is provable before the zebra-rs wiring lands; the
chosen coupling is layered on in Phase 4.

## Roadmap

- **Phase 0 — foundation (this commit).** Workspace, map contract, aya build
  pipeline, TC `clsact` classifier skeleton that passes traffic. Proves
  build + load on this host (aarch64, kernel 6.8, BTF, aya 0.14).
- **Phase 1 — L3 spine.** `FIB`/`NEXTHOPS`/`NEIGH` maps; TC/XDP forward with
  neighbor rewrite + `bpf_redirect`; route-injection API. The core thesis:
  routes drive eBPF forwarding.
- **Phase 2 — L2.** FDB + MAC learning, VLAN, flood/broadcast; per-port mode.
- **Phase 3 — L4.** Service LB (random → Maglev), conntrack, DNAT/SNAT.
- **Phase 4 — control-plane integration.** zebra-rs `FibHandle` → cradle maps;
  learned-route install (the gap Cilium leaves open).
- **Phase 5 — L7 + ops.** TPROXY redirect to a Rust/Envoy proxy; observability
  (perf events, metrics); BDD netns features (per project convention).

## Build & test

```sh
cargo build                 # builds cradle-common + cradle (+ cradle-ebpf via build.rs)
sudo ./target/debug/cradle --iface <dev>   # attach the datapath (needs CAP_BPF/NET_ADMIN)
```

Tests follow the zebra-rs convention: BDD features over network namespaces, each
ending in an explicit `Scenario: Teardown topology`.
