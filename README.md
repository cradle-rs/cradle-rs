# cradle-rs

eBPF-based networking for L2–L7 with routing-protocol integration — in Rust.

A Cilium-class eBPF **L2–L7** data plane — adding true L2 switching below
Cilium's L3 floor — whose forwarding is driven by a real multi-protocol routing
stack ([zebra-rs](https://github.com/zebra-rs/zebra-rs)).
Where Cilium's BGP control plane only *advertises* routes, cradle-rs installs
**learned** routes directly into the eBPF data plane. The whole stack is Rust:
the data plane uses [aya](https://aya-rs.dev) (no clang/libbpf required).

See [`docs/design/architecture.md`](docs/design/architecture.md) for the full
design and roadmap.

## Layout

| Crate | Target | Role |
|---|---|---|
| `cradle-common` | host + bpf | Data-plane contract: `#[repr(C)]` map key/value types. |
| `cradle-ebpf`   | `bpfel-unknown-none` | eBPF programs (XDP + TC). |
| `cradle`        | host | User-space control plane: loads/attaches programs, programs maps. |

## Build & run

Prerequisites: a **nightly** Rust toolchain with `rust-src`, and `bpf-linker`
(`cargo install bpf-linker`). No clang/libbpf needed.

```sh
cargo build
sudo ./target/debug/cradle --iface <dev>   # attach the datapath (CAP_BPF/NET_ADMIN)
```

## Status

Phase 0 (foundation): workspace, map contract, aya build pipeline, and a TC
`clsact` datapath skeleton — validated build → load → attach on Linux 6.8.
L3/L2/L4 stages and zebra-rs integration are in progress. MPLS transit
(label swap / pop / PHP-to-IP via a static ILM) is implemented
([design](docs/design/mpls.md)).
