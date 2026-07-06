# Network policy in the cradle datapath (story 2 / M8)

Status: **Phases 1–2 plus phase-3 deny rules and enforcement modes of
[`policy-multitenant.md`](policy-multitenant.md) implemented** — atomic per-endpoint policy replacement (A/B generation
flip), audit mode, per-endpoint policy revisions (CiliumEndpoint
`status.policy.revision`), Hubble policy verdicts carrying the peer
identity, plus the full phase-1 surface: Kubernetes `NetworkPolicy` ingress **and egress**, IPv4 and
IPv6, `ipBlock` CIDR peers (with `except`), and named ports, in native
(non-chained) CNI mode. Ingress L7 (HTTP) policy is
implemented (phase 5): per-port allow-lists steered through the
transparent proxy. `matchExpressions` selectors, egress L7, and Hubble
L7 flow records are follow-ups.

## Model

**Identities** compress "who is talking" the way Cilium does, but with no
allocator state: an identity is the FNV-1a/32 hash of a pod's sorted label
set plus its namespace (pods with identical labels share one identity, and
a restarted controller re-derives the same numbers). Reserved values follow
Cilium's numbering: `1` = host (node addresses), `2` = world (any source
with no identity). `0` is the wildcard in policy keys, never assigned.
`ipBlock` peers get a derived CIDR identity (`cidr_identity()`), bound via
the `CIDR_ID`/`CIDR_ID6` LPM maps and consulted on exact-identity miss; an
`except` prefix is a more-specific binding back to world. The collision-free
allocator is the phase-3 CiliumIdentity work; unreferenced identities
are garbage-collected (`cradle-k8s --gc-identities`: mark-and-sweep
against the cluster-wide CiliumEndpoint `status.identity` set, with a
grace period so a fresh identity survives until its CEP is published).

**Enforcement points** — one per direction, both on the pod's host-veth:

- **Ingress: at delivery**, in `cradle_egress` (the veth's TC *egress* hook,
  `ingress_policy`). Every packet entering the pod traverses it — routed
  fabric ingress, same-node pod-to-pod, and node-originated traffic such as
  kubelet probes (which never traverse `cradle_tc`). Runs post-NAT, so
  verdicts apply to the real destination, not a service VIP.
- **Egress: at the source**, in `cradle_tc` (the veth's TC *ingress* hook,
  the `from_ep` path of `l3_forward_v4/v6`) — post-NAT (service DNAT has
  resolved the real peer), pre-FIB (the verdict must not depend on route
  presence).

**Default-allow** until a policy selects the endpoint for that direction
(`EP_POLICY` miss, or the direction's `EP_F_*` bit clear), matching
Kubernetes semantics. When enforcing, verdicts come from `POLICY` with
bounded wildcard fallback, most-specific first — six probes per direction:

```
(ep, dir, identity, proto, port)   exact
(ep, dir, identity, proto, 0)      any port
(ep, dir, identity, 0,     0)      any proto/port  ("these pods")
(ep, dir, 0,        proto, port)   any peer        ("this port from/to anyone")
(ep, dir, 0,        proto, 0)
(ep, dir, 0,        0,     0)      allow-all rule  (empty from/to)
```

The peer whose identity is matched is the *remote* end: the source for
ingress rules, the destination for egress rules. Rules carry a verdict
value (`POLICY_ALLOW`/`POLICY_DENY`): the datapath walks all six probes
and a **deny at any specificity wins over any allow** (Cilium deny-rule
semantics) — allow requires at least one allow hit and no deny hit.
`cradle-k8s --policy-enforcement default|always|never` selects the
enforcement mode (`always` = default-deny endpoints nothing selects, host
allow only; `never` = translate but don't apply).

**Statefulness**: Kubernetes policy is stateful in both directions, tracked
in `PCT`/`PCT6` (an LRU conntrack for policy, separate from the NAT `CT`):

- Packets *from* a local endpoint insert their pre-NAT 5-tuple
  (`PCT_POD_INITIATED`, at the veth TC ingress before `l4_nat`) — replies
  bypass the pod's ingress rules.
- Admitted packets *to* an egress-enforced endpoint insert their post-NAT
  5-tuple (`PCT_INBOUND`, at delivery) — the pod's replies bypass its
  egress rules.

**Host bypass**: kubelet probes must always reach pods and their replies
must always leave. The controller adds an `(identity=1)` allow rule to every
enforced endpoint in *both* directions rather than hardcoding it in the
datapath (the egress one matters: a node-originated probe records a
`PCT_INBOUND` entry at delivery, but the explicit rule keeps replies safe
even when `PCT` has aged the flow out).

**Stack budget note**: the policy code keeps its lookup keys in the
`POL6_SCRATCH` per-CPU map rather than on the stack, and ingress enforcement
lives in `cradle_egress` — `cradle_tc`'s flattened frame sits at the
verifier's call-chain budget (512 bytes including 32 each for the entry stub
and the compiler's `memset`), and this feature is what first hit that wall.
See [`tailcall-vs-monolithic.md`](tailcall-vs-monolithic.md).

## Maps

| Map | Type | Key → Value |
|---|---|---|
| `IDENTITY` | Hash | `(vrf, IPv4)` → identity (u32; vrf 0 = global) |
| `IDENTITY6` | Hash | `(vrf, IPv6)` → identity (u32) |
| `CIDR_ID` | LpmTrie | `(vrf, CIDR)` (v4) → identity, on `IDENTITY` miss |
| `CIDR_ID6` | LpmTrie | `(vrf, CIDR)` (v6) → identity, on `IDENTITY6` miss |
| `EP_POLICY` | Hash | endpoint host-veth ifindex → `EP_F_INGRESS \| EP_F_EGRESS \| EP_F_AUDIT \| EP_F_GEN` |
| `POLICY` | Hash | `PolicyKey{ep, identity, proto, port, dir\|gen}` → allow (u8) |
| `PCT` / `PCT6` | LruHash | 5-tuple → `PCT_POD_INITIATED` / `PCT_INBOUND` |
| `POL6_SCRATCH` | PerCpuArray | policy lookup keys (off-stack scratch) |

`STAT_POLICY_DROP` counts enforcement drops, `STAT_POLICY_AUDIT` audit-mode
verdicts (denied but forwarded); v4 verdicts emit Hubble `DROPPED`/`AUDITED`
flows carrying the direction and the peer identity the rules matched
against.

**Atomic replacement (phase 2)**: `SetEndpointPolicy` performs an A/B
generation flip — the new rule set lands in `POLICY` under the inactive
generation (`PolicyKey.dir` bit 1), one `EP_POLICY` word update switches the
endpoint (`EP_F_GEN`), and the stale generation is swept afterwards. Packets
never observe a half-replaced table. The map-in-map inner-swap design is
deferred until aya-ebpf can declare BTF maps (the aya 0.14 loader supports
`HashOfMaps`, but legacy `bpf_map_def` declarations cannot carry the inner
map spec). Each replacement bumps the endpoint's policy revision, published
via `ListEndpoints` into the CiliumEndpoint CRD, alongside
`status.identity` (the endpoint's security identity id + label list,
resolved read-only against the CiliumIdentity CRDs with the FNV
fallback).

**Ingress L7 policy (phase 5)**: `EndpointPolicy.l7` attaches per-port
HTTP allow-lists (`L7Rule{method, path_prefix}`, empty = any). The
control plane steers each `(pod-ip, port)` through the transparent proxy
by inserting it into `L7_SERVICES` — the same `bpf_sk_assign` path the
L7 load balancer uses, no new datapath code — and installs the
allow-list in the proxy's route table. The proxy answers non-matching
requests with an empty 403 and splices matches to the original
destination; its onward connection is node-originated, so the L4 ingress
verdict at delivery sees the host identity. CiliumNetworkPolicy
`toPorts.rules.http` translates to the same surface (`path` is a
regex full-matched against the request path, Cilium semantics — an
invalid regex falls back to exact match). Egress L7 and Hubble L7
records are follow-ups.

## Control plane

- gRPC: `SetIdentity{ip, identity}` / `DelIdentity{ip}` (v4 or v6),
  `SetCidrIdentity{cidr, identity, del}`, and `SetEndpointPolicy` with
  per-direction enforcement (`enforce` gates ingress `rules`,
  `enforce_egress` gates `egress_rules`) and replace semantics per endpoint.
  Neither direction enforcing returns the endpoint to default-allow.
- `cradle-k8s` (`netpol.rs`) watches Pods, Namespaces, and NetworkPolicies:
  every pod IP (dual-stack `podIPs`) is published into `IDENTITY`/
  `IDENTITY6`; `policyTypes` selects the enforced directions (K8s
  defaulting: unset ⇒ Ingress always, Egress iff egress rules exist);
  `ingress.from`/`egress.to` peers resolve to identity allow tuples;
  `ipBlock` CIDRs (and their `except`s) are pushed as CIDR bindings and
  diffed across reconciles; named ports resolve against the enforced pod's
  containers (ingress) or the peer pods' (egress) — unresolvable named
  ports yield no rule (fail closed).

## Operations

- **`cradle ctl policy-trace --from <ip> --to <ip> [--port N] [--proto
  tcp|udp|any] [--vrf N]`** — resolves a hypothetical flow against the
  live maps exactly the way the datapath does and prints each step:
  endpoint lookup, `EP_POLICY` flags (directions/audit/generation), L7
  steering, identity resolution (exact → CIDR LPM → world), and every
  `POLICY` probe hit, ending in a verdict (`ALLOW`/`DENY`/`AUDIT`/`L7`/
  `DEFAULT-ALLOW`). PCT statefulness is not simulated — replies of live
  flows may pass where the trace says deny.
- **`cradle ctl policy-summary`** — live entry counts across the policy
  maps (identities v4/v6, CIDR bindings, enforced endpoints, rules
  including both generations, PCT entries): the map-pressure gauges.
- **`cradle policy-bench --endpoints N --rules M --repeat K`** (root) —
  times full-fleet policy replacement (the generation flip). Measured on
  the dev box: 64 endpoints × 64 rules/direction ≈ **2.2 ms/replace
  (~450 replaces/s, ~57k rules/s)**. The cost is dominated by the sweep's
  full `POLICY` key scan (O(fleet rules) per replace), so whole-fleet
  reconcile is quadratic in rules — fine at hundreds of endpoints; a
  per-endpoint key index is the noted optimization if profiles demand it.

## Testing

- BDD `cradle_policy.feature` (no Kubernetes): identities + policies pushed
  over gRPC against cradle-cni pods — ingress allow/deny/un-enforce,
  stateful replies in both directions, egress allow-by-identity with
  world denied, and ipBlock CIDR with an `except` override.
- BDD `cradle_policy_v6.feature`: v6 ingress on a plain L3 topology —
  deny, allow via a CIDR binding, allow via an exact v6 identity.
- BDD policy-trace scenario: verdict + resolution lines asserted against
  the live maps over the `cradle_policy` topology.
- kind e2e: two `NetworkPolicy` phases in `deploy/kind-e2e.sh` — ingress
  deny-then-restore against a web pod, and egress default-deny-then-allow
  on the client pod — both enforced by cradle (no Cilium installed).
