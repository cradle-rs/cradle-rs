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
| `cradle`        | host | User-space control plane: loads/attaches programs, programs maps, serves the gRPC API. |
| `cradle-cni`    | host | Kubernetes CNI plugin (spec 1.1): attaches pods to the data plane. |
| `cradle-k8s`    | host | Kubernetes controller: Services → eBPF L4 LB, CNI conflist render. |
| `bdd`           | host | Cucumber BDD suite over network namespaces. |

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
including both RFC 9800 compressions (uSID/NEXT-C-SID and REPLACE-C-SID),
the RFC 8986 flavors, and EVPN (below — [design](docs/design/srv6.md),
[EVPN](docs/design/evpn-srv6.md)), and observability counters. Everything is
drivable over gRPC, and [zebra-rs](https://github.com/zebra-rs/zebra-rs)
drives it as a real control plane: IS-IS SR/SRv6, BGP L3VPN (MPLS and SRv6),
and BGP EVPN program the eBPF FIBs through the `FibHandle` tee, with a
reverse `WatchFdb` channel reporting data-plane MAC learning back up.
cradle also runs as a **Kubernetes CNI** (plugin + node controller +
DaemonSet packaging, proven in kind — see below), with Cilium API
compatibility as the next arc.

## Kubernetes CNI support status

cradle runs as a Kubernetes CNI provider: `cradle-cni` (a CNI spec 1.1
plugin) plumbs each pod's veth and ptp default route (169.254.1.1 with a
permanent neighbor entry) and hands the host end to the daemon, which
allocates the pod address from node-local IPAM and programs the pod /32
into the eBPF FIB; `cradle-k8s` maps Services onto the eBPF L4 load
balancer and renders the kubelet CNI conflist from the Node's podCIDR.
`deploy/` carries the DaemonSet and `kind-e2e.sh` (a kind cluster with the
default CNI disabled, smoke-tested end to end). Because zebra-rs is the
node's routing stack, pod reachability rides real BGP — including the
direction Cilium doesn't support: **routes learned from BGP program the
pod datapath** (Cilium's BGP control plane is advertise-only,
cilium/cilium#34841). Plan and roadmap: `docs/design/cni-cilium.md`.
✅ = implemented (BDD/e2e-proven), 🔶 = partial by design, ⬜ = not yet.

| Function | Status | Notes |
|---|---|---|
| CNI 1.1 ADD / DEL | ✅ | veth + ptp gateway, pod /32 into the eBPF FIB via `AllocIp`/`CreateEndpoint`; idempotent DEL; `cradle_cni` |
| CNI CHECK / STATUS / VERSION | ✅ | persisted endpoint store + daemon health; `cradle_cni_restart` |
| CNI GC | ✅ | sweeps attachments absent from `cni.dev/valid-attachments`; `cradle_cni_restart` |
| Node-local IPAM | ✅ | daemon-owned allocator persisted under `--state-dir`; idempotent per attachment; survives restarts |
| Daemon-restart reconcile | ✅ | fresh maps re-programmed from the endpoint store; completes deletes for pods torn down while the daemon was dead |
| Cross-node pod routing over BGP | ✅ | eBGP-exchanged pod CIDRs tee into each node's eBPF FIB — kernel forwarding off end to end; `cradle_cni_bgp` |
| ClusterIP Services (eBPF L4 LB) | ✅ | `cradle-k8s` Service/EndpointSlice sync (`AddService` replaces, `DelService` removes, periodic resync); `cradle_cni_svc` |
| DaemonSet packaging + kind e2e | ✅ | conflist rendered from Node podCIDR; nginx ClusterIP proven served by the eBPF DNAT (`l4_dnat > 0`) |
| Host-network-backed services | 🔶 | intentionally left to kube-proxy: unprogrammed VIPs miss the eBPF FIB and fall through to the kernel (hybrid model) |
| Dual-stack pods (IPv6 IPAM) | ⬜ | the datapath is fully dual-stack; the allocator/plumbing is v4-only today |
| NodePort / hostPort / egress SNAT | ⬜ | ClusterIP only; no masquerade |
| Full kube-proxy replacement | ⬜ | needs an egress reverse-NAT hook for node-local backends |

## Cilium compatibility status

Story 2 of `docs/design/cni-cilium.md`: expose Cilium-compatible surfaces so
the Cilium ecosystem (the stock `cilium-cni` plugin, `kubectl get
ciliumendpoints`, chaining deployments) works against a cradle node — while
gaining the routing stack underneath. ✅ = implemented (proven against the
stock binary), ⬜ = planned, in roadmap order.

| Surface | Status | Notes |
|---|---|---|
| cilium-agent REST API subset (`cilium.sock`) | ✅ | `serve --cilium-sock`: `/healthz`, `/config`, `/ipam`, `/endpoint` — the UNMODIFIED cilium-cni v1.19.5 binary attaches pods to the cradle datapath; `cradle_cilium` |
| `CiliumEndpoint` / `CiliumNode` CRDs | ✅ | `cradle-k8s --publish-crds` mirrors the daemon's endpoint store into CEPs (`kubectl get cep` shows cradle pods) + a CiliumNode with the podCIDR; vendored CRDs in `deploy/crds/`; kind e2e |
| Generic-veth CNI chaining | ✅ | the stock Cilium agent chained on cradle-plumbed veths (`chained` netconf mode leaves the veth TC hook to Cilium; the pod /32 stays in the eBPF FIB for fabric-ingress forwarding); a CiliumNetworkPolicy blocks/restores pod traffic in `deploy/kind-cilium-e2e.sh` |
| NetworkPolicy / identity enforcement | ✅ | native `IDENTITY`/`POLICY`/`PCT` maps + ingress verdict in `cradle_tc` (stateful, default-allow); `cradle-k8s --enforce-policy` translates k8s NetworkPolicies; `cradle_policy` BDD + kind e2e ([design](docs/design/policy.md)) |
| Hubble API | ⬜ | out of scope for this arc |

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

## SRv6 support status

Function taxonomy after
[Vinbero's roadmap](https://github.com/takehaya/Vinbero/blob/main/docs/loadmap.md),
extended with the RFC 9800 compression flavors (uSID/NEXT-C-SID actions and
REPLACE-C-SID) and the RFC 8986 flavors. ✅ = implemented (BDD-proven),
🔶 = partial, ⬜ = not yet.

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
| End.T | ✅ | End walk + table-scoped egress lookup (VRF metadata to the TC stage) |
| End.DX2 / DX2V | ✅ | EVPN VPWS E-Line: AC xconnect encap (any EtherType) + decap-and-emit raw; DX2V demuxes the inner 802.1Q VID; XDP decap, TC-stage redirect |
| End.DT2U | ✅ | EVPN unicast: decap + bridge by dst MAC |
| End.DT2M | ✅ | EVPN BUM: decap + flood (split horizon) |
| End.DX4 / DX6 | ✅ | decap + cross-connect to the CE adjacency (per-CE VPN); XDP decap, TC-stage redirect |
| End.DT4 | ✅ | decap + per-VRF v4 lookup |
| End.DT6 | ✅ | decap + per-VRF v6 lookup |
| End.DT46 | ✅ | dual-family; the BGP L3VPN service SID |
| End.B6.Encaps / .Red | ✅ | Binding SID: End walk + policy push in XDP (Reduced form on the wire) |
| End.B6.Insert | ⬜ | deprecated insert form |
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
| uT | ✅ | table-bound uN — End.T semantics at end-of-carrier |
| uDX4 / uDX6 | ✅ | End.DX* matched at the carrier's last micro-SID |
| uB6 | ⬜ | |

### Flavors

| Flavor | Status | Notes |
|---|---|---|
| NEXT-C-SID | ✅ | 16-bit micro-SIDs; blocks 16/32/48 |
| REPLACE-C-SID | ✅ | End/End.X, 32/16-bit C-SIDs — container walk + DA index argument, eBPF only (no kernel support) |
| PSP | ✅ | pop at the penultimate segment; End/End.X/uN/uA + the REPLACE composite condition |
| USP | ✅ | pop before local delivery; End/uN/End(REP) (SID must be a local address) |
| USD | ✅ | decap + main-table forward; End/uN/End(REP) |

## Control plane

Producers that program the eBPF data plane: cradle's own gRPC/JSON API for
static entries, and zebra-rs protocol machinery through the `FibHandle` tee
for everything else. ✅ = implemented (BDD-proven), ⬜ = not yet.

| Producer | Data plane | Status | Notes |
|---|---|---|---|
| Static ILM (gRPC/JSON) | MPLS | ✅ | `AddIlm`/`DelIlm` + labels on nexthops |
| IS-IS SR (SR-MPLS) | MPLS | ✅ | prefix SIDs / SRGB → ILM + out-labels teed |
| BGP L3VPN (VPNv4/v6 over MPLS) | MPLS | ✅ | per-VRF VPN label, `cradle_l3vpn_zebra` |
| LDP | MPLS | ⬜ | no producer in zebra-rs |
| SR-MPLS TI-LFA | MPLS | ✅ | protected-nexthop tee (repair label stack as backup) + link-down failover; `cradle_tilfa_mpls` |
| Static SRv6 config (gRPC/JSON) | SRv6 | ✅ | every SRv6 function above |
| IS-IS SRv6 (locators, uN/uA) | SRv6 | ✅ | locator routes + local SIDs teed |
| BGP L3VPN over SRv6 (VPNv4/v6) | SRv6 | ✅ | per-VRF End.DT46, `encapsulation srv6` |
| BGP EVPN over SRv6 (RFC 9252) | SRv6 | ✅ | Type-2→End.DT2U, Type-3→End.DT2M (+ BUM slots), MAC mobility seq, `WatchFdb` learn/age channel |
| BGP EVPN VPWS (RFC 8214) | SRv6 | ✅ | per-EVI Type-1 ⇄ End.DX2, `vpws` service config, one-RPC AC bind (xconnect + local decap); `cradle_vpws_zebra` |
| BGP SR Policy Binding SID (SAFI 73) | SRv6 | ✅ | controller-originated candidate path → headend BSID + policy list via tee; `cradle_b6_zebra` |
| BGP color steering to a BSID | SRv6 | ⬜ | steering imposes raw segment lists today |
| SRv6 TI-LFA | SRv6 | ✅ | uSID repair carriers: protected-nexthop tee + link-down failover; `cradle_tilfa_srv6` |
| Mirror SID egress protection (End.M) | SRv6 | ✅ | mirror-route tee + PLR post-encap re-lookup; `cradle_endm` |
| Locator flavors (PSP/USP/USD) | SRv6 | ✅ | `flavor` leaf-list → flavored IANA codepoints (IS-IS + OSPFv3) + kernel flavor ops + tee; `cradle_tilfa_psp` |
| REPLACE-C-SID locators | SRv6 | ✅ | `behavior: replace` → End(REP)/End.X(REP) at /(LB+LN+Fun), REP codepoints + Arg-length advertisement; eBPF-only (no kernel op); `cradle_replace_zebra` |
| VRF-bound locators (End.T / uT) | SRv6 | ✅ | locator `vrf` leaf → RIB table resolution → End.T/uT codepoints + kernel End.T + tee; `cradle_endt_zebra` |
| Static seg6local SIDs (config-static `action`) | SRv6 | ✅ | route-embedded actions now tee as local SIDs; DX adjacency via `nh6`/`nh4`; `cradle_dx_zebra` |
