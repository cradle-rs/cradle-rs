# Network Policy

cradle enforces network policy **natively in the eBPF datapath** — no iptables,
no sidecar. `cradle-k8s --enforce-policy` translates Kubernetes
`NetworkPolicy`, `CiliumNetworkPolicy`, and `CiliumClusterwideNetworkPolicy`
objects into a handful of BPF maps, and the datapath decides every packet from
those maps. It is dual-stack, ingress **and** egress, supports deny rules and
L7 HTTP filtering, and — because identity is scoped by VRF — enforces per-tenant
policy over overlapping pod CIDRs, which a flat identity space cannot.

The design is in `docs/design/policy.md`; the plan and phase history in
`docs/design/policy-multitenant.md`.

## Identities

Policy matches on **identity**, not IP — the compressed answer to "who is
talking". A pod's identity is derived from its namespace + label set, so pods
with identical labels share one identity and rules stay stable as pods churn.

- With `--enforce-policy`, `cradle-k8s` **allocates** collision-free numeric
  identities (from 256 up) and records each as a cluster-scoped
  `CiliumIdentity` CRD — visible to `kubectl get ciliumidentities`, restart-safe,
  and GC'd when no endpoint references them (`--gc-identities`).
- When the CRD is absent (non-Kubernetes use, the BDD gRPC path), identity falls
  back to a stable **FNV-1a hash** of the same label set.
- Two values are reserved, following Cilium: `1` = **host** (the node itself,
  e.g. kubelet health probes), `2` = **world** (any peer with no identity). `0`
  is the wildcard in rules, never assigned.

The datapath resolves a peer's identity from `(vrf, ip)` — exact binding first
(`IDENTITY` / `IDENTITY6`), then a longest-prefix CIDR binding
(`CIDR_ID` / `CIDR_ID6`, used for `ipBlock` peers), then world.

## Enforcement points

Policy is checked once per direction, both on the pod's host-side veth:

| Direction | Where | Notes |
|---|---|---|
| **Ingress** | at *delivery* — the veth's TC **egress** hook (`cradle_egress`) | sees every packet entering the pod: routed fabric-ingress, same-node pod-to-pod, and node-originated traffic (kubelet probes) that never traverses `cradle_tc`. Post-NAT, so verdicts apply to the real destination. |
| **Egress** | at the *source* — the veth's TC **ingress** hook (`cradle_tc`) | post-NAT (service DNAT resolved), pre-FIB (the verdict must not depend on a route existing). |

An endpoint is **default-allow** until a policy selects it for that direction —
matching Kubernetes semantics.

Policy is **stateful**, both directions, via a policy conntrack (`PCT` / `PCT6`,
separate from the NAT conntrack): a pod-initiated flow's replies bypass the
pod's ingress rules, and an admitted inbound flow's replies bypass its egress
rules. The controller also adds an implicit *allow-from-host* rule so kubelet
probes and their replies always pass.

## Rules and the verdict

Each rule is a `(endpoint, peer-identity, proto, port, direction)` key in the
`POLICY` map with an **allow** or **deny** value; any of identity/proto/port may
be `0` (wildcard). The datapath walks six wildcard patterns, most-specific
first:

```
(identity, proto, port)   exact
(identity, proto, 0)      any port
(identity, 0,     0)      "these pods"
(0,        proto, port)   "this port from/to anyone"
(0,        proto, 0)
(0,        0,     0)      allow-all (empty from/to)
```

A **deny at any specificity wins over any allow** (Cilium deny semantics), so
the walk visits all six and returns denied on the first deny hit — allow
requires at least one allow hit and no deny hit. It is still six lookups, not
twelve.

Peers are expressed as pods (label selectors), `ipBlock` CIDRs (with `except`
prefixes, which bind back to world so an excepted source is excluded), and named
ports (resolved to numbers against the target/peer pods — an unresolvable named
port yields no rule, failing closed).

## Enforcement modes

`cradle-k8s --policy-enforcement <mode>`:

| Mode | Behaviour |
|---|---|
| `default` | Kubernetes semantics — enforce only endpoints a policy selects. |
| `always` | default-deny every endpoint (host-allow only until a policy selects it). |
| `never` | translate policies but do not apply them. |

## Cilium policy CRDs

The `CiliumNetworkPolicy` (namespaced) and `CiliumClusterwideNetworkPolicy`
(cluster-scoped, matches endpoints and peers across **all** namespaces) L3/L4
subset is supported:

- `endpointSelector`, `fromEndpoints` / `toEndpoints` (matchLabels), `toPorts`.
- `ingressDeny` / `egressDeny` → deny rules (see above).
- `fromEntities` / `toEntities`: `all` → wildcard peer, `host` → 1, `world` → 2,
  `cluster` → the host plus every allocated identity.
- `toPorts[].rules.http` → the L7 allow-lists below.

## L7 HTTP policy

An endpoint's ingress L7 rules attach per port. The control plane steers those
ports through the same [transparent proxy](ch-01-06-l7-proxy.md) the L7 load
balancer uses — no new datapath code — and the proxy enforces the allow-list:

- Each rule is `{method, path}`; `path` is a **regex** full-matched against the
  request path (Cilium semantics; an invalid regex falls back to exact match).
- A request matching no rule gets an empty **403** and the connection closes; a
  match is spliced transparently to the pod.
- Every handled request is reported to **Hubble** as an L7 (HTTP) flow —
  `hubble observe --type l7` shows the method, path, and verdict.

## Multi-tenancy

Identity keys on **`(vrf, ip)`**, not `ip` alone. Bind a tenant's pod ports to a
VRF, and the ingress check scopes by the endpoint port's VRF while the egress
check scopes by the source port's — so two tenants can reuse the **same pod
CIDRs** and the same client address resolves to a *different* identity per
tenant, giving opposite verdicts under identical rules. VRF `0` is the global
table, so single-tenant clusters and the Kubernetes controller are unaffected.
This is the differentiator over Cilium's flat identity space, proven by the
`cradle_policy_vrf` BDD.

## Atomic replacement, audit, revisions

- **Atomic replacement**: `SetEndpointPolicy` performs an A/B **generation
  flip** — the new rule set lands under the inactive generation, one `EP_POLICY`
  word update switches the endpoint, and the stale generation is swept. Packets
  never observe a half-replaced table. (The map-in-map inner-swap design is
  deferred until aya-ebpf can declare BTF maps.)
- **Audit mode**: a per-endpoint bit reports denied verdicts (the `policy_audit`
  counter + an `AUDITED` Hubble flow) while forwarding the packet.
- **Revisions**: each replacement bumps the endpoint's policy revision,
  published into `CiliumEndpoint` `status.policy.revision`, alongside its
  `status.identity`.

## Operations

| Command | What it does |
|---|---|
| `cradle ctl policy-trace --from <ip> --to <ip> [--port] [--proto] [--vrf]` | Resolves a hypothetical flow against the live maps exactly the way the datapath does, printing each step — endpoint, `EP_POLICY` flags, L7 steering, identity resolution, every probe hit — and the verdict (`ALLOW`/`DENY`/`AUDIT`/`L7`/`DEFAULT-ALLOW`). |
| `cradle ctl policy-summary` | Live entry counts across the policy maps (identities, CIDR bindings, endpoints, rules, conntrack) — the map-pressure gauges. |
| `cradle policy-bench --endpoints N --rules M` | Times full-fleet policy replacement (root; loads the eBPF object without attaching). |

## Status

Every row is proven by a BDD feature (`bdd/tests/features/cradle_*`) or a kind
end-to-end script.

| Function | Status | Proof |
|---|---|---|
| Ingress + egress, stateful (both directions) | ✅ | `cradle_policy` |
| Deny rules (deny-over-allow) | ✅ | `cradle_policy` |
| `ipBlock` CIDR peers (with `except`) | ✅ | `cradle_policy` |
| IPv6 policy | ✅ | `cradle_policy_v6` |
| VRF-scoped identity (overlapping CIDRs) | ✅ | `cradle_policy_vrf` |
| Ingress L7 HTTP allow-lists (method + path regex) | ✅ | `cradle_policy` |
| Atomic replacement + audit mode | ✅ | `cradle_policy` |
| CiliumIdentity allocator + GC | ✅ | `deploy/kind-e2e.sh` |
| CiliumNetworkPolicy / ClusterwideNetworkPolicy | ✅ | unit + `deploy/kind-cilium-e2e.sh` |
| `policy-trace` / `policy-summary` / `policy-bench` | ✅ | `cradle_policy` |
| kind e2e (ingress + egress) | ✅ | `deploy/kind-e2e.sh` |

Follow-ons: namespace→VRF tenant mapping wired through the CNI, a host endpoint,
egress L7, and slices of `cilium connectivity test`.
