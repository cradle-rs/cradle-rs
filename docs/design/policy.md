# Network policy in the cradle datapath (story 2 / M8)

Status: **Phase 1 of [`policy-multitenant.md`](policy-multitenant.md)
implemented** — Kubernetes `NetworkPolicy` ingress **and egress**, IPv4 and
IPv6, `ipBlock` CIDR peers (with `except`), and named ports, in native
(non-chained) CNI mode. L7 rules, `matchExpressions` selectors, and
`CiliumNetworkPolicy` extensions are follow-ups (phases 3+).

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
allocator is the phase-3 CiliumIdentity work.

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
ingress rules, the destination for egress rules.

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
| `IDENTITY` | Hash | pod/node IPv4 → identity (u32) |
| `IDENTITY6` | Hash | pod/node IPv6 → identity (u32) |
| `CIDR_ID` | LpmTrie | peer CIDR (v4) → identity, on `IDENTITY` miss |
| `CIDR_ID6` | LpmTrie | peer CIDR (v6) → identity, on `IDENTITY6` miss |
| `EP_POLICY` | Hash | endpoint host-veth ifindex → `EP_F_INGRESS \| EP_F_EGRESS` |
| `POLICY` | Hash | `PolicyKey{ep, identity, proto, port, dir}` → allow (u8) |
| `PCT` / `PCT6` | LruHash | 5-tuple → `PCT_POD_INITIATED` / `PCT_INBOUND` |
| `POL6_SCRATCH` | PerCpuArray | policy lookup keys (off-stack scratch) |

`STAT_POLICY_DROP` counts enforcement drops (both directions); v4 drops
also emit Hubble `DROPPED` flows with the direction.

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

## Testing

- BDD `cradle_policy.feature` (no Kubernetes): identities + policies pushed
  over gRPC against cradle-cni pods — ingress allow/deny/un-enforce,
  stateful replies in both directions, egress allow-by-identity with
  world denied, and ipBlock CIDR with an `except` override.
- BDD `cradle_policy_v6.feature`: v6 ingress on a plain L3 topology —
  deny, allow via a CIDR binding, allow via an exact v6 identity.
- kind e2e: a `NetworkPolicy` phase in `deploy/kind-e2e.sh` — deny-then-allow
  against the nginx ClusterIP, enforced by cradle (no Cilium installed).
