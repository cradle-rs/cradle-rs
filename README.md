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

The full L2–L7 data plane is implemented and BDD-tested on Linux 6.8:
L2 switching (learn / forward / flood, FDB aging), dual-stack L3 with ECMP
and a DIR-24-8 large-FIB engine (1M routes, ~51 ns lookups), L4 load
balancing with conntrack, an L7 transparent proxy (TPROXY), MPLS
(swap / pop / PHP / push, L3VPN — [design](docs/design/mpls.md)), SRv6
including uSID and EVPN (below — [design](docs/design/srv6.md),
[EVPN](docs/design/evpn-srv6.md)), and observability counters. Everything is
drivable over gRPC, and [zebra-rs](https://github.com/zebra-rs/zebra-rs)
drives it as a real control plane: IS-IS SR/SRv6, BGP L3VPN (MPLS and SRv6),
and BGP EVPN program the eBPF FIBs through the `FibHandle` tee, with a
reverse `WatchFdb` channel reporting data-plane MAC learning back up.

## MPLS support status

✅ = implemented (BDD-proven), ⬜ = not yet.
([design](docs/design/mpls.md))

### Label operations

| Operation | Status | Notes |
|---|---|---|
| Swap | ✅ | single-label at TC; multi-label SR swaps complete in XDP |
| Pop | ✅ | XDP stage (`bpf_skb_adjust_room` can't shrink MPLS at TC); chained pops in one pass |
| PHP (pop-and-forward) | ✅ | zebra-shaped implicit-null handling |
| Push (imposition) | ✅ | up to 3-label stacks (TC, IP payloads) |
| Pop-to-VRF (VPN label) | ✅ | decap + per-VRF lookup; VRF carried XDP→TC as metadata |
| ECMP over labeled paths | ✅ | flow-hashed nexthop groups |
| Entropy / TTL-propagate knobs | ⬜ | TTL decrements; no ELI/EL |

### Control plane

| Producer | Status | Notes |
|---|---|---|
| Static ILM (gRPC/JSON) | ✅ | `AddIlm`/`DelIlm` + labels on nexthops |
| IS-IS SR (SR-MPLS) | ✅ | prefix SIDs / SRGB → ILM + out-labels teed |
| BGP L3VPN (VPNv4/v6 over MPLS) | ✅ | per-VRF VPN label, `cradle_l3vpn_zebra` |
| LDP | ⬜ | no producer in zebra-rs |
| SR-MPLS TI-LFA | ⬜ | (SRv6 TI-LFA is supported) |

## SRv6 support status

Function taxonomy after
[Vinbero's roadmap](https://github.com/takehaya/Vinbero/blob/main/docs/loadmap.md),
extended with the uSID (NEXT-C-SID) actions and flavors. ✅ = implemented
(BDD-proven), 🔶 = partial, ⬜ = not yet.

### Headend behaviors

| Function | Status | Notes |
|---|---|---|
| H.Encaps | ✅ | multi-SID SRH imposition (TC stage) |
| H.Encaps.Red | ✅ | the default; single-SID = no SRH |
| H.Encaps.L2 / L2.Red | ✅ | MAC-in-SRv6 (next-header 143) for EVPN, XDP stage |
| H.Insert | ✅ | TI-LFA repair imposition (v6; original DA as final segment) |
| H.M.GTP4.D / GTP6.D | ⬜ | mobile user plane out of scope |

### Endpoint behaviors

| Function | Status | Notes |
|---|---|---|
| End | ✅ | SRH `Segments Left` walk (XDP) |
| End.X | ✅ | adjacency cross-connect (XDP redirect) |
| End.T | ⬜ | |
| End.DX2 / DX2V | ⬜ | |
| End.DT2U | ✅ | EVPN unicast: decap + bridge by dst MAC |
| End.DT2M | ✅ | EVPN BUM: decap + flood (split horizon) |
| End.DX4 / DX6 | ⬜ | |
| End.DT4 | ✅ | decap + per-VRF v4 lookup |
| End.DT6 | ✅ | decap + per-VRF v6 lookup |
| End.DT46 | ✅ | dual-family; the BGP L3VPN service SID |
| End.B6.Insert / B6.Encaps | ⬜ | behavior code reserved in the ABI |
| End.BM | ⬜ | |
| End.M (mirror) | ✅ | egress protection: repair-decap + mirror-context lookup + service decap |
| End.Replicate | ⬜ | BUM replication uses per-remote slots instead |
| End.S / End.AN / AS / AD / AM | ⬜ | service programming out of scope |

### uSID (NEXT-C-SID, RFC 9800) actions

| Action | Status | Notes |
|---|---|---|
| uN | ✅ | shift-and-forward at the locator (block+node) prefix |
| uA | ✅ | adjacency micro-SID (/128, classic End.X form) |
| uA (LIB) | ✅ | block:function prefix — shift + adjacency mid-carrier |
| uDT4 / uDT6 / uDT46 | ✅ | End.DT* matched at the carrier's last micro-SID |
| uDX* / uB6 | ⬜ | |

### Flavors

| Flavor | Status | Notes |
|---|---|---|
| NEXT-C-SID | ✅ | 16-bit micro-SIDs; blocks 16/32/48 |
| REPLACE-C-SID | ✅ | End/End.X, 32/16-bit C-SIDs — container walk + DA index argument, eBPF only (no kernel support) |
| PSP | ✅ | pop at the penultimate segment; End/End.X/uN/uA + the REPLACE composite condition |
| USP | ✅ | pop before local delivery; End/uN/End(REP) (SID must be a local address) |
| USD | ✅ | decap + main-table forward; End/uN/End(REP) |

### Control plane (zebra-rs tee)

| Producer | Status | Notes |
|---|---|---|
| Static gRPC/JSON config | ✅ | every function above |
| IS-IS SRv6 (locators, uN/uA) | ✅ | locator routes + local SIDs teed |
| BGP L3VPN over SRv6 (VPNv4/v6) | ✅ | per-VRF End.DT46, `encapsulation srv6` |
| BGP EVPN over SRv6 (RFC 9252) | ✅ | Type-2→End.DT2U, Type-3→End.DT2M (+ BUM slots), MAC mobility seq, `WatchFdb` learn/age channel |
| BGP SR Policy / color steering | ⬜ | needs End.B6 |
| TI-LFA uSID repair carriers | ✅ | protected-nexthop tee + link-down failover; `cradle_tilfa_srv6` |
| Mirror SID egress protection (End.M) | ✅ | mirror-route tee + PLR post-encap re-lookup; `cradle_endm` |
| Locator flavors (PSP/USP/USD) | ✅ | `flavor` leaf-list → flavored IANA codepoints (IS-IS + OSPFv3) + kernel flavor ops + tee; `cradle_tilfa_psp` |
