# Architecture

cradle-rs is a small workspace of three crates plus an integration-test crate.
The split is deliberate: one crate holds the kernel↔user-space contract, one is
the eBPF data plane, and one is the user-space control plane that owns the maps.

## Workspace layout

| Crate | Target | Role |
|---|---|---|
| `cradle-common` | host + bpf | The **data-plane contract**: `#[repr(C)]` POD types used as map keys/values by *both* sides. `aya::Pod` impls are gated behind the `user` feature so the `no_std` eBPF build never links aya. |
| `cradle-ebpf` | `bpfel-unknown-none` | The eBPF programs (TC classifier). Built by `cradle`'s build script via `aya-build`; excluded from `default-members`. |
| `cradle` | host | User-space control plane: loads and attaches the programs, programs the maps, and serves the gRPC control API. |
| `cradle-bdd` | host | Behaviour-driven integration tests over Linux network namespaces. |

Build glue lives in `cradle/build.rs`: `aya-build` compiles `cradle-ebpf` for
`bpfel-unknown-none` (nightly + `-Z build-std=core`, no clang/libbpf), and the
resulting object is embedded into the `cradle` binary with
`aya::include_bytes_aligned!`. One binary ships the data plane inside it.

## The data-plane contract

`cradle-common` is the single source of truth for the byte layout of every map.
Its types follow strict rules — `#[repr(C)]`, `Copy`, explicit padding, network
byte order for addresses — because the kernel compares hash-map keys byte-wise.
The major families:

- **L3** — `FibEntry` (an LPM value → `nexthop_id` + flags), `NextHop`,
  `Neigh4Key` / `NeighEntry`, and nexthop-group keys for ECMP.
- **L2** — `FdbKey` / `FdbEntry`, `PortConfig` (per-ifindex port mode), and
  `L2MemberKey` for flood membership.
- **L4** — `ServiceKey` / `ServiceInfo`, `BackendKey` / `Backend`, and
  `CtKey` / `CtEntry` for conntrack, each mirrored for IPv6.
- **Observability** — the `STAT_*` indices into the per-CPU counter array.
- **L7** — `L7_PROXY_PORT`, the port the transparent proxy listens on.

Route flags (`FIB_F_*`) mark a FIB entry as local (punt to the host stack),
connected (resolve the neighbor by the packet's destination), blackhole, or ECMP
(the nexthop id is a *group* id).

## The datapath

A single `SchedClassifier` program, `cradle_tc`, is attached to each configured
port's `clsact` **ingress** hook. It runs the frame through the layers in order:

```
 ┌─────────┐   ┌──────────────────────┐   ┌───────────────────────┐   ┌──────────────────┐
 │ L2 FDB  │ → │ L3 LPM forward + NH  │ → │ L4 service LB / CT/NAT │ → │ L7 TPROXY redirect│
 │ + flood │   │ (v4/v6, ECMP)        │   │ (v4/v6, DNAT/SNAT)     │   │ (bpf_sk_assign)  │
 └─────────┘   └──────────────────────┘   └───────────────────────┘   └──────────────────┘
```

Forwarding uses `bpf_redirect_neigh`, which hands the packet to the kernel's
neighbor layer for L2 resolution — so cradle does not have to own an ARP/ND state
machine for connected next-hops. A host (`/32` or `/128`) `FIB_F_LOCAL` route is
installed for each of the router's own addresses so packets addressed *to* the
router are punted to the host stack instead of being (mis)forwarded.

## The control plane

`cradle` (user space) is the reconciler. It:

1. loads and attaches the embedded eBPF object,
2. owns the maps and exposes typed operations over them
   (`set_port`, `add_route4`, `set_nexthop`, `add_service`, `add_l7_service`, …),
3. auto-derives connected and local routes for routed ports from the kernel's
   interface addresses, and
4. serves those operations over a gRPC API.

The gRPC surface is the seam the zebra-rs `FibHandle` backend drives. The method
names mirror `route_*_add/del`, nexthop and neighbor updates, and L2/L4 setup —
so learned routes from BGP, OSPF, IS-IS, or static configuration land directly
in the eBPF FIB. See [Driving cradle from zebra-rs](ch-02-00-zebra-integration.md).

## Shape end to end

```
 zebra-rs control plane  (BGP / OSPF / IS-IS / EVPN / SRv6 → RIB best-path + nexthop groups)
            │   FibHandle boundary  (route add/del, nexthop, neighbor, L2)
            ▼   gRPC (unix or tcp)
 cradle  (user space, aya)  ── reconciles ──▶  BPF maps  (FIB-LPM, NEXTHOPS, NEIGH,
   · loads / attaches programs                  FDB, PORTS, SERVICES, BACKENDS, CT, …)
            ▼                                          ▲
 cradle-ebpf  (kernel, TC clsact ingress)  ───────────┘  reads maps
   L2 switch → L3 forward → L4 LB/NAT → L7 TPROXY
```
