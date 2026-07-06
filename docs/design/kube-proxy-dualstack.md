# Dual-stack pods & full kube-proxy replacement (Story 3)

Status: PLAN. Closes the four ⬜/🔶 rows in the README's Kubernetes CNI
table: dual-stack pods (IPv6 IPAM), NodePort/hostPort/egress-SNAT,
host-network-backed services, and full kube-proxy replacement.

## What we already have (leverage)

The L4 datapath is **already dual-stack and stateful**, which is most of
the hard part:

- `l4_nat_v4` / `l4_nat_v6` run on every `PORT_F_L3` ingress before routing
  (`cradle-ebpf/src/main.rs`), with `SERVICES`/`SERVICES6` frontends,
  `BACKENDS`/`BACKENDS6`, and `CT`/`CT6` LRU conntrack. DNAT on the forward
  packet installs a reverse `CT_F_SNAT`/`CT_F_DNAT` entry, applied when the
  reply re-enters any cradle L3 port. ClusterIP works for pod backends today
  (M4 e2e).
- `PORT_F_ENDPOINT` already marks pod veths and the `PCT` policy conntrack
  already tracks pod-egress 5-tuples — the exact hook a masquerade stage
  needs.
- `AddService`/`DelService` reconcile surface + `cradle-k8s` Service watcher.

Two genuinely new pieces unlock everything below, so they come first:

1. **Node-uplink attach.** cradle only attaches `cradle_tc` to pod veths
   today. Attaching it to the node's uplink (`SetPort` on the fabric device)
   makes off-node/return traffic visible — the reverse-NAT re-entry point for
   masquerade, NodePort, and host-network services.
2. **Egress masquerade.** SNAT pod→outside-the-cluster to the node IP, with
   the reverse folded into the existing CT machinery.

## K1 — Dual-stack pods (IPv6 IPAM)

The datapath forwards v6 already; only the IPAM/plumbing layer is v4-only.

- **IPAM** (`cradle/src/cni.rs`): add a parallel `Ipv6Addr` allocator + a
  `pool6` in the netconf; `alloc_ip` returns an optional v6 too. Persist a
  second allocations map.
- **Endpoint record + proto**: `CniEndpoint.ip6`, `Endpoint.ip6:
  Option<Ipv6Addr>`. `cni_create_endpoint` programs the pod `/128` into
  `FIB6` via a v6 connected nexthop (`nexthop_set_v6`) + the kernel twin
  route (`ip -6 route replace <ip6>/128 dev <veth>`).
- **`cradle-cni`**: allocate v6, assign the v6 addr, install the v6 ptp
  default route (`fe80::1` link-local gateway + permanent v6 neigh to the
  host veth MAC), and return both IPs in the CNI result.
- **cilium shim** (`cradle/src/cilium.rs`): `/config` advertises v6
  addressing; `/ipam` returns `ipv6`; `PUT /endpoint` takes `addressing.ipv6`.
- **`cradle-k8s`**: render both v4/v6 `podCIDRs` into the conflist; a v6
  ClusterIP maps onto the existing v6 service path.
- **Policy** (follow-on within K1 or deferred): `IDENTITY6`/`POLICY6` maps +
  a v6 branch in `l3_forward_v6`, mirroring the v4 engine.
- **Tests**: `cradle_cni_v6.feature` (v6 pod↔pod / pod↔node with kernel
  forwarding off) + a dual-stack ClusterIP; kind e2e stays v4 (kind
  dual-stack is a separate config toggle).

## K2 — Egress masquerade (the shared primitive)

- **Maps/config**: `NON_MASQ` (LPM of CIDRs never masqueraded: the pod CIDR,
  the service CIDR, and operator-supplied ranges) and a `NODE_ADDR` config
  (this node's v4/v6 uplink address). A small BPF source-port allocator for
  the SNAT (hash the tuple, linear-probe a `MASQ_PORTS` bitmap on collision).
- **Datapath**: a `masq()` stage on `PORT_F_ENDPOINT` ingress, after `PCT`
  tracking and before routing: if the destination is **not** in `NON_MASQ`,
  rewrite the source to `(NODE_ADDR, alloc_port)` and install a CT reverse
  entry `(dst, node, dport, alloc_port) → CT_F_DNAT rev=(pod, sport)`. The
  reply enters the **uplink** cradle port ingress, `l4_nat` hits that CT
  entry, and un-NATs to the pod — no new reverse code, just the K1 uplink
  attach. `STAT_MASQ`.
- **Control plane**: `SetNodeAddr` + `AddNonMasq(cidr)` gRPC; `cradle-k8s`
  seeds the pod/service CIDRs and a `nonMasqueradeCIDRs` config (Cilium's
  `ipv4NativeRoutingCIDR` analogue — masquerade is *off* when the fabric
  already routes pod CIDRs, e.g. the M2 BGP setup).
- **Tests**: `cradle_masq.feature` — a pod pings/curls an "internet" netns
  reachable only via the node; assert the reply returns and the external
  host sees the node IP as source (tcpdump or a returned `X-Forwarded`-style
  echo), and that in-cluster traffic is **not** masqueraded.

## K3 — NodePort & hostPort

Both are node-IP frontends built on K2's uplink + masquerade.

- **NodePort**: `cradle-k8s` watches Services of type `NodePort`/
  `LoadBalancer` and programs a node-IP frontend. Datapath adds a
  `NODEPORT` match in `l4_nat` keyed `(proto, nodeport)` when the dst is a
  local node address (checked against `NODE_ADDR` / a `FIB_F_LOCAL` hit),
  DNAT to a backend. `externalTrafficPolicy: Cluster` (default) reuses K2 to
  SNAT the client so the reply returns through this node; `Local` (source-IP
  preserving, node-local backends only) is a follow-on needing the uplink
  **egress** hook.
- **hostPort**: advertise `"capabilities": {"portMappings": true}` in the
  conflist; kubelet then passes `runtimeConfig.portMappings`. `cradle-cni`
  reads them and calls a new `AddHostPort` (node:hostPort → this pod:
  containerPort — a one-backend service on `NODE_ADDR`), torn down on DEL.
  No Pod-watch needed.
- **Tests**: `cradle_nodeport.feature` — curl `<nodeIP>:<nodeport>` from an
  external netns reaches a backend pod; a hostPort pod is reachable on the
  node IP; both with kernel forwarding off.

## K4 — Host-network-backed services

The reason these are skipped today: a host-network backend replies from the
node's own stack, which never crosses a pod veth, so the veth-ingress
reverse-SNAT can't fire. With K2's uplink attach + masquerade the return
path exists.

- **`cradle-k8s/src/sync.rs`**: stop dropping empty-Pod-backend services;
  accept `target_ref.kind != "Pod"` endpoints whose address is a node IP.
- **Datapath**: program them as normal `SERVICES` DNAT but force **client
  SNAT to the node IP** (so the host-network backend replies to the node,
  where the uplink-ingress CT reverse un-NATs). This is the same
  client-SNAT K3-Cluster uses.
- **Milestone target**: serve `default/kubernetes` (API server, host-network
  at the control-plane node) — the prerequisite for running with kube-proxy
  off.
- **Tests**: a `hostNetwork: true` nginx served via its ClusterIP through
  cradle in the kind e2e.

## K5 — Full kube-proxy replacement (capstone)

Everything above, plus the gaps that let kube-proxy be turned **off**:

- **Session affinity** (`service.spec.sessionAffinity: ClientIP`): an
  `AFFINITY` map `(svc_id, client_ip) → (slot, expiry)` consulted before the
  random pick in `l4_nat`; `cradle-k8s` sets it from the Service.
- **LB quality** (follow-on): wire the existing `LB_ALGO_MAGLEV` stub for
  consistent backend selection across nodes. **Blocked on the monolith
  stack wall** (see [`tailcall-vs-monolithic.md`](tailcall-vs-monolithic.md)):
  a working userspace table generator + datapath lookup were prototyped,
  but the backend-selection change adds ~16 bytes to `cradle_tc`'s already
  at-budget main frame — inlining grows main past the 448-byte verifier
  budget, and out-lining forces the fat `l4_nat_v4/v6` NAT branches (which
  must stay inlined to *overlap* their mutually-exclusive stack) into a
  too-deep call chain. Maglev is the LB feature that hits the wall the
  policy engine first hit; it wants the tail-call restructuring, not
  another stack shave.
- **Health-check node port** for `externalTrafficPolicy: Local`.
- **Deploy**: `deploy/kind-config.yaml` gains `kubeProxyMode: none`; the
  DaemonSet already carries the datapath. A dedicated
  `deploy/kind-noproxy-e2e.sh`: cluster comes up (API service served by
  cradle per K4), then ClusterIP + NodePort + CoreDNS all resolve/serve with
  **no kube-proxy in the cluster**.
- **README**: flip the four rows to ✅ and drop the "hybrid / kube-proxy
  serves it" caveats.

## Sequencing & rationale

```
K1 (IPv6 IPAM) ─ independent; do first, unblocks dual-stack everywhere
K2 (masquerade + uplink attach) ─ the shared primitive
       ├── K3 (NodePort/hostPort)
       └── K4 (host-network services)  ──► K5 (kube-proxy off) capstone
```

K1 is independent and can land in parallel. K2 is the linchpin — it adds the
node-uplink attach and the SNAT/return machinery that K3, K4, and K5 all
build on, and it's the one that reuses the existing CT/`l4_nat` reverse path
rather than writing new datapath. Each Kx is one PR with a BDD feature (or
kind-e2e phase) proving it with kernel forwarding off, per house style.

Non-goals for this arc: L7/FQDN policy, egress gateway, BPF NAT
port-exhaustion tuning at scale, Windows. Maglev and IPv6 policy are noted
as quality follow-ons.
