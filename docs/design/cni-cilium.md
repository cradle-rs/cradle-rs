# Kubernetes CNI support with Cilium compatibility

Status: PLAN (no implementation yet)
Branch: `cni-cilium-compatibility`

This document plans two stories:

- **Story 1 — CNI API support**: cradle becomes a first-class Kubernetes CNI
  provider. A new `cradle-cni` plugin binary (CNI spec 1.1: ADD / DEL / CHECK /
  STATUS / GC / VERSION) wires pod network namespaces into the existing cradle
  eBPF datapath, with node-local IPAM, and zebra-rs BGP distributing pod
  reachability between nodes.
- **Story 2 — Cilium API support**: cradle exposes Cilium-compatible API
  surfaces so the Cilium ecosystem works against it — first the cilium-agent
  REST API subset that the stock `cilium-cni` binary calls (drop-in agent
  replacement), then the Cilium CRDs (`CiliumEndpoint`, `CiliumNode`), with
  CNI chaining and network policy as follow-ons.

The strategic frame is the project thesis (README, `architecture.md`):
Cilium's BGP control plane is advertise-only — it cannot install learned
routes into its datapath (cilium/cilium#34841, #23464). cradle + zebra-rs
already do exactly that (BGP → RIB → FibHandle tee → eBPF FIB, proven by
`cradle_bgp.feature`). CNI support turns that from a router demo into a
Kubernetes networking product; Cilium compatibility lets it slot into the
ecosystem Cilium created.

---

## 1. What we already have (leverage inventory)

### cradle-rs

| Asset | Where | Use for CNI |
|---|---|---|
| gRPC `Cradle` control API over UDS | `proto/cradle.proto`, `control.rs` | The plugin/agent seam already exists: `SetPort`, `AddRoute4/6`, `SetNeighbor4/6`, `SetNexthop`, `AddService(6)`, `GetStats` |
| Dual-stack L3 FIB + ECMP + VRF | `FIB4/FIB6`, `FIB4_VRF/FIB6_VRF`, DIR-24-8 | Pod /32 (/128) routes; per-tenant pod VRFs later |
| L4 LB + conntrack (VIP→backends DNAT/SNAT, v4+v6) | `SERVICES*/BACKENDS*/CT*`, `l4_nat_*` | ClusterIP services ≈ kube-proxy replacement, already in the datapath |
| L7 TPROXY HTTP proxy | `l7.rs`, `L7_SERVICES` | Later: L7 policy / ingress experiments |
| `bpf_redirect_neigh` forwarding | eBPF `l3_forward` | Kernel resolves pod veth neighbors — no ARP code needed in cradle |
| Port auto-derivation of connected/local routes | `kernel.rs::derive_port` | Node-side plumbing on `SetPort` |
| veth/netns/`ip`-shellout toolkit | `kernel.rs`, `bdd/src/netns.rs` | The exact primitives CNI ADD/DEL needs, already battle-tested |
| BDD harness with per-feature netns scoping | `bdd/tests/cucumber.rs` | Simulate kubelet: a step that execs the plugin with CNI env + stdin JSON |
| MPLS / SRv6 / EVPN overlays | datapath + zebra tee | Differentiators: pod networks as L3VPN/SRv6 slices (post-MVP) |

### zebra-rs

| Asset | Where | Use for CNI |
|---|---|---|
| FibHandle → cradle tee (routes, ECMP, ILM, SIDs, neighbors) | `fib/cradle.rs`, `system cradle-grpc` leaf | Learned BGP routes land in the pod datapath automatically — the core differentiator |
| Programmatic config northbound (`Apply` gRPC on `unix:zebra-rs/vty`) | `config/serve.rs`, `vtyctl apply` | Inject `router bgp … network <podCIDR>` / static routes from a controller without templating config files |
| BGP unnumbered (RA-triggered interface neighbors) | `bgp/interface_neighbor.rs` | Zero-config node↔ToR peering, the Cilium/Calico deployment pattern |
| BGP dynamic neighbors (listen-range) | `bgp/dynamic_neighbors.rs` | Many nodes peering to a RR without per-node config |
| Live netlink link/addr watch → RIB | `fib/netlink/handle.rs::process_msg` | CNI-created veths are observed with no new code |

### What does not exist anywhere (greenfield)

- CNI protocol handling (JSON-over-stdin, env vars, result/error formats).
- Netns entry / veth-into-container / pod-side address+route config.
- IPAM (no allocator, no pool state).
- Endpoint model + persistent endpoint store (needed for CHECK/GC/restart).
- Kubernetes client (watching Nodes/Services/EndpointSlices/CRDs).
- Network policy / identity in the datapath (no ACL maps at all).
- Cilium REST API / CRDs.

---

## 2. Story 1 — CNI API support

> As a Kubernetes cluster operator, I can select cradle as the cluster CNI so
> that pods get IPs and connectivity from the cradle eBPF datapath, and pod
> reachability is exchanged between nodes with real BGP via zebra-rs —
> including routes *learned from* the fabric, which Cilium cannot install.

### 2.1 Per-pod datapath design

Veth model, mirroring Cilium/Calico so Story 2 chaining stays possible:

```
pod netns                          root netns
+----------------+                +---------------------------------+
| eth0 10.244.1.7/32              | crdl<hash> (host side, no IP)   |
|  default via 169.254.1.1        |   TC clsact + XDP = cradle port |
|  neigh 169.254.1.1 = host MAC ──┼─> cradle FIB: 10.244.1.7/32     |
+----------------+                |   -> nexthop oif=crdl<hash>     |
                                  |   kernel: 10.244.1.7/32 dev crdl<hash>
                                  +---------------------------------+
```

Per ADD:
1. Create veth pair; move peer into `CNI_NETNS`, rename to `CNI_IFNAME`.
2. Pod side: assign allocated IP as /32 (v6 /128), `default via 169.254.1.1
   dev eth0 scope link` + permanent neigh entry for 169.254.1.1 pointing at
   the host-side veth MAC (ptp gateway trick; no shared L2, no ARP flood).
3. Host side: `SetPort{name, l3: true, vrf_id}` — attaches `cradle_tc` +
   `cradle_xdp`, so all pod egress enters the cradle datapath.
4. Routes: cradle `AddRoute4 {pod_ip/32 → nexthop{oif: host_veth}}` AND a
   kernel route `pod_ip/32 dev <host_veth>` (needed by `bpf_redirect_neigh`
   fib lookup + ARP; this is Cilium's endpoint-routes mode). The pod answers
   ARP for its own /32 on the veth link, so neighbor resolution is untouched
   kernel behavior.
5. Persist an endpoint record (see 2.4).

Per DEL: reverse; idempotent (CNI requires DEL to succeed on repeat/partial
state).

Traffic paths that fall out for free:
- pod→pod same node: host veth TC → FIB /32 → redirect to other veth.
- pod→pod cross node: FIB (BGP-learned podCIDR route via zebra tee) →
  fabric. Native routing, no tunnels — the flagship differentiator.
- pod→ClusterIP: `l4_nat` DNAT on the pod's port before `l3_forward`
  (existing datapath, needs only a Service controller to program it).
- pod→node / node→pod: local routes + `FIB_F_LOCAL` punt (existing).

### 2.2 Component split (mirrors cilium-cni ↔ cilium-agent)

- **`cradle-cni`** (new workspace crate, small static binary in
  `/opt/cni/bin`): speaks CNI 1.1 on stdin/env; does the netns-side plumbing
  (it runs in kubelet's privileged context and receives `CNI_NETNS`); calls
  the cradle daemon over the existing UDS gRPC for IPAM + endpoint
  programming. Protocol layer hand-rolled with serde (the spec is small and
  the existing Rust CNI crates — `rscni`, `cni-plugin` — are
  minimal-maintenance; keep them as reference, not dependencies).
- **`cradle serve`** (existing daemon = the "agent"): new RPCs
  `AllocIp`/`ReleaseIp` (IPAM) and `CreateEndpoint`/`DeleteEndpoint`/
  `ListEndpoints` (wraps SetPort + routes + neighbor + kernel route +
  endpoint store, one transactional call per pod so partial failure is
  cleaned up server-side). `Control` stays the single impl behind gRPC, per
  the established pattern.

Interface plumbing keeps the repo's `ip`-shellout convention initially
(`kernel.rs`, `bdd/src/netns.rs` already do veth create/move/addr); a later
hardening task swaps to rtnetlink syscalls so the plugin doesn't depend on
`iproute2` on the host.

### 2.3 IPAM

Host-scope model (per-node PodCIDR), like Cilium's `ipam: kubernetes` mode:
- Pool = `podCIDR` from the CNI network config (the DaemonSet writes it from
  `Node.spec.podCIDR`), or static in the netconf for BDD.
- Allocator lives in the daemon (bitmap over the pool), persisted to
  `/run/cradle/ipam.json` so daemon restarts don't double-allocate; first IP
  reserved as the (virtual) gateway, dual-stack from day one.
- GC reconciles the pool against live endpoints.
Cluster-pool mode (CiliumNode-driven) is Story 2.

### 2.4 Endpoint store, CHECK / STATUS / GC

- `/run/cradle/endpoints/<containerid>-<ifname>.json`: container ID, netns
  path, ifname, veth names, IPs, vrf, created-at. Written by
  `CreateEndpoint`, removed by `DeleteEndpoint`.
- **CHECK**: verify endpoint record exists, host veth present + attached,
  FIB entry present (via `GetFibSummary`/lookup RPC), pod IP matches
  prevResult.
- **STATUS**: exit 0 iff daemon UDS answers `GetStats` and the IPAM pool is
  configured and not exhausted (spec error codes 50/51 otherwise).
- **GC**: input `cni.dev/valid-attachments` → `ListEndpoints` diff → delete
  stale endpoints + release IPs. Also run the same reconcile on daemon start.

### 2.5 zebra-rs integration (no zebra code changes for MVP)

- Node advertises its PodCIDR: `vtyctl apply -c "router bgp ... network
  <podCIDR>"` (or a static route + `redistribute static`) over the `Apply`
  gRPC — done once at agent bootstrap, not per pod.
- Remote pod routes arrive by BGP and are installed into the cradle FIB by
  the existing `system cradle-grpc` tee — this path is already proven by
  `cradle_bgp.feature`.
- Node peering: BGP unnumbered (`interface-neighbor <fabric-if> remote-as
  external`) or dynamic-neighbors listen-range on the ToR/RR — both already
  in zebra-rs.
- Known seam to respect (from prior BDD work): zebra tees only protocol
  routes; cradle self-derives connected routes at `SetPort` — per-pod /32s
  are programmed directly by `CreateEndpoint`, so nothing new is needed, but
  CE-side addressing order still matters in tests.

### 2.6 Kubernetes packaging (second half of the story)

- `cradle-k8s` controller (kube-rs), initially tiny: read `Node.spec.podCIDR`
  → render CNI netconf; watch `Service`/`EndpointSlice` → `AddService`
  (ClusterIP kube-proxy replacement using the existing L4 LB maps).
- DaemonSet: init container installs `cradle-cni` into `/opt/cni/bin` +
  writes `/etc/cni/net.d/05-cradle.conflist`; main container runs
  `cradle serve` + zebra-rs (or zebra-rs as a second container), hostNetwork,
  privileged, bpffs mount.
- e2e on `kind` (worker nodes are just containers; cradle's aarch64/aya stack
  runs fine on the dev box kernel 6.8).

### 2.7 Milestones & acceptance (BDD-first, like every other feature)

- **M1 — plugin + endpoint plumbing.** `cradle-cni` ADD/DEL/VERSION against a
  netns "pod"; new gRPC endpoint RPCs; BDD feature `cradle_cni.feature`:
  harness plays kubelet (exec plugin with env + stdin netconf), asserts pod
  ping node, pod↔pod same node, teardown clean. Kernel forwarding off so only
  eBPF can forward (house style).
- **M2 — multi-node + BGP.** Two "nodes" (netns) each running cradle+zebra,
  eBGP unnumbered between them, PodCIDR per node via `vtyctl apply`; BDD:
  cross-node pod↔pod ping through BGP-learned routes; `cradle_cni_bgp.feature`.
  This scenario — *pods reachable over routes the node learned via BGP* — is
  the demo Cilium cannot do; it goes in the README.
- **M3 — lifecycle correctness.** CHECK/STATUS/GC + endpoint store +
  daemon-restart reconcile; repeat-DEL idempotence; BDD scenarios for GC of a
  leaked attachment and restart survival.
- **M4 — services + packaging.** `cradle-k8s` Service watcher → `AddService`;
  DaemonSet manifests; kind e2e (smoke: 2-node kind, nginx pod, ClusterIP
  curl). This can overlap with Story 2.

---

## 3. Story 2 — Cilium API support

> As a platform team invested in the Cilium ecosystem (cilium-cni deployment
> model, CiliumEndpoint/CiliumNode tooling, kubectl-based observability), I
> can point that ecosystem at cradle and it keeps working — while gaining a
> real routing stack underneath.

"Cilium API" has three concrete planes; we take them in order of leverage:

### 3.1 Phase A — cilium-agent REST API subset (stock `cilium-cni` drop-in)

The stock `cilium-cni` binary talks to the agent over
`unix:///var/run/cilium/cilium.sock` using a REST API that Cilium guarantees
stable for all of 1.x. On ADD it: creates the veth pair itself, moves+renames
the peer, then calls `POST /ipam` (allocate) and `PUT /endpoint/{id}`
(EndpointChangeRequest carries the host ifname/ifindex, MACs, IPs, labels) —
i.e. *the plugin does the plumbing and hands the agent a ready host veth*.
That maps almost 1:1 onto what `CreateEndpoint` does in Story 1 minus the
veth creation.

Plan: serve a minimal, version-pinned subset (target Cilium 1.19.x models
from `api/v1/openapi.yaml`) on `cilium.sock` from `cradle serve` (axum/hyper
over UDS; hand-written serde models for just these endpoints):

| Endpoint | cradle behavior |
|---|---|
| `GET /healthz` | daemon + datapath status (reuse `GetStats` plumbing) |
| `GET /config` | static DaemonConfig: ipam mode, datapath mode `veth`, enable-endpoint-routes=true |
| `POST /ipam`, `DELETE /ipam/{ip}` | Story 1 allocator |
| `PUT /endpoint/{id}` | `CreateEndpoint` minus veth creation (host veth already exists; do SetPort + routes + store) |
| `DELETE /endpoint/{id}` | `DeleteEndpoint` |
| `GET /endpoint` / `GET /endpoint/{id}` | endpoint store |

Acceptance: BDD feature where the **unmodified `cilium-cni` binary** (pinned
version, fetched in CI/test setup) performs ADD/DEL against cradle-agent and
pods get connectivity through the cradle datapath. Explicitly out of scope in
this phase: identity allocation, policy, Hubble — `/endpoint` responses
report `policy-enforcement: disabled`.

Risk note: EndpointChangeRequest is a wide model; we accept-and-ignore fields
we don't implement, and gate the whole listener behind
`--cilium-compat-sock <path>` so it's opt-in.

### 3.2 Phase B — CRD compatibility (`CiliumNode`, `CiliumEndpoint`)

- `cradle-k8s` writes a `CiliumEndpoint` per pod (name/namespace = pod,
  networking status, identity stubbed) and maintains `CiliumNode` for its
  node. This makes standard fleet tooling (`kubectl get cep`, operators,
  dashboards) see cradle-managed pods.
- Optionally run the **stock cilium-operator** for cluster-pool IPAM: it
  allocates per-node PodCIDRs into `CiliumNode.spec.ipam.podCIDRs`; the
  cradle agent watches its CiliumNode and feeds the Story 1 allocator. That
  buys Cilium's default IPAM mode without writing an operator.
- Acceptance: kind cluster; `kubectl get ciliumendpoints` lists cradle pods;
  cluster-pool mode allocates/routes correctly across 2 nodes.

### 3.3 Phase C — policy and/or coexistence (choose per deployment)

Two complementary endgames; both stay on the roadmap, C1 ships first:

- **C1 — CNI chaining coexistence (fast, high leverage).** Because Story 1
  uses the standard veth model, real Cilium can chain on top via its
  documented **generic-veth chaining** mode (`cni.exclusive=false`,
  cni-chaining-mode=generic-veth): cradle-cni does IPAM+veth+routing (and
  keeps the BGP-learned-route FIB), Cilium attaches its policy/observability
  eBPF to the same veths. Acceptance: kind + Cilium chained; a
  CiliumNetworkPolicy blocks pod→pod while cradle still forwards allowed
  traffic. Caveat to verify early: program co-residency on TC ingress
  (cradle uses clsact ingress; Cilium also attaches there — ordering and
  TC_ACT semantics need a spike, and is the main technical risk of C1).
- **C2 — native policy in the cradle datapath (the long pole).** New
  datapath work, patterned on the existing map conventions: `IDENTITY` map
  (IP→numeric identity, fed from CiliumEndpoint/CiliumIdentity or plain
  label-set hashing), per-endpoint `POLICY` map ((identity, proto, dport) →
  verdict) enforced in `cradle_tc` before forwarding, `POLICY_STATS` +
  drop stat. Scope first cut to k8s `NetworkPolicy` semantics (L3/L4,
  namespace/pod selectors, CIDR blocks) translated by `cradle-k8s`;
  `CiliumNetworkPolicy` L7/FQDN much later (L7 could ride the existing
  TPROXY). Default-allow until the first policy selects an endpoint
  (Cilium semantics).

### 3.4 Milestones

- **M5** = Phase A (REST shim + stock cilium-cni BDD).
- **M6** = Phase B (CEP/CiliumNode writers; optional cilium-operator
  cluster-pool spike).
- **M7** = C1 chaining validation on kind (+ the TC co-residency spike as
  its first task).
- **M8** = C2 identity/policy maps + NetworkPolicy translation (own design
  doc when reached).

---

## 4. Sequencing, ownership, non-goals

- Order: M1 → M2 → M3 → (M4 ∥ M5) → M6 → M7 → M8. Story 2 Phase A reuses
  Story 1's allocator + endpoint RPCs, so Story 1 M1–M3 is the foundation;
  M4 and M5 are parallelizable.
- Repos: everything above lives in cradle-rs; zebra-rs needs **no changes**
  for MVP (config injected via existing `Apply` northbound). If a zebra-side
  convenience emerges (e.g. a `kubernetes` YANG stanza that renders
  network/redistribute statements), it follows the established cross-repo
  workflow: zebra-rs PR first, its CI gates apply.
- Per CLAUDE.md: every new BDD feature ends with `Scenario: Teardown
  topology`; feature-prefix-scoped namespace cleanup only.
- Non-goals for this arc: Hubble API, kvstore/clustermesh, egress NAT /
  masquerade (pod egress to Internet assumes routed fabric or a follow-up
  SNAT feature), Windows, IPVLAN datapath mode.

## 5. References

- CNI spec 1.1 (ADD/DEL/CHECK/STATUS/GC/VERSION, GC valid-attachments,
  STATUS error codes 50/51): https://www.cni.dev/docs/spec/
- Cilium component overview (cilium-cni ↔ agent via cilium.sock):
  https://docs.cilium.io/en/stable/overview/component-overview/
- Cilium agent REST API (stable for 1.x): https://docs.cilium.io/en/stable/api/
  and https://github.com/cilium/cilium/blob/main/api/v1/openapi.yaml
- cilium-cni ADD code walk (veth by plugin; POST /ipam; PUT /endpoint/{id}):
  https://arthurchiao.art/blog/cilium-code-cni-create-network/
- Cilium IPAM modes: https://docs.cilium.io/en/stable/network/concepts/ipam/
- CiliumEndpoint CRD: https://docs.cilium.io/en/latest/network/kubernetes/ciliumendpoint/
- Generic veth chaining: https://docs.cilium.io/en/stable/installation/cni-chaining-generic-veth/
- BGP route-learning gap (advertise-only): https://github.com/cilium/cilium/issues/34841
  and https://github.com/cilium/cilium/issues/23464
- Rust CNI protocol references: https://github.com/terassyi/rscni ,
  https://github.com/passcod/cni-plugins
