# Network policy in the cradle datapath (story 2 / M8)

Status: first cut — Kubernetes `NetworkPolicy` **ingress** semantics, IPv4,
native (non-chained) CNI mode. Egress policies, `ipBlock` CIDR peers, IPv6,
L7 rules, and `CiliumNetworkPolicy` extensions are follow-ups.

## Model

**Identities** compress "who is talking" the way Cilium does, but with no
allocator state: an identity is the FNV-1a/32 hash of a pod's sorted label
set plus its namespace (pods with identical labels share one identity, and
a restarted controller re-derives the same numbers). Reserved values follow
Cilium's numbering: `1` = host (node addresses), `2` = world (any source
with no identity entry). `0` is the wildcard in policy keys, never assigned.

**Enforcement point**: ingress-to-endpoint, checked where the destination
resolves — the pod /32 FIB entry gains `FIB_F_ENDPOINT`, and `l3_forward_v4`
runs the policy check after the LPM hit and before the redirect. One check
covers both paths: same-node traffic enforces at the source pod's veth TC
hook, cross-node traffic at the fabric ingress of the destination node —
which is exactly where Kubernetes ingress policy belongs (the receiver).

**Default-allow** until a policy selects the endpoint (`EP_POLICY` miss or
`enforce=0`), matching Kubernetes semantics. When enforcing, verdicts come
from `POLICY` with bounded wildcard fallback, most-specific first:

```
(ep, identity, proto, port)   exact
(ep, identity, proto, 0)      any port
(ep, identity, 0,     0)      any proto/port  ("allow from these pods")
(ep, 0,        proto, port)   any source      ("allow this port from anyone")
(ep, 0,        proto, 0)
(ep, 0,        0,     0)      allow-all rule  (empty `from` in the policy)
```

**Statefulness**: Kubernetes policy is stateful — replies to a pod-initiated
connection must pass regardless of ingress rules. Packets *from* a local
endpoint (ingress port flagged `PORT_F_ENDPOINT`) insert their 5-tuple into
`PCT` (an LRU conntrack for policy, separate from the NAT `CT`); the
enforcement path allows a packet whose reverse tuple hits `PCT` before
consulting `POLICY`.

**Host bypass**: kubelet probes must always reach pods. The controller adds
an `(identity=1)` allow rule to every enforced endpoint rather than
hardcoding it in the datapath.

## Maps

| Map | Type | Key → Value |
|---|---|---|
| `IDENTITY` | Hash | pod/node IPv4 → identity (u32) |
| `EP_POLICY` | Hash | endpoint host-veth ifindex → enforce (u8) |
| `POLICY` | Hash | `PolicyKey{ep, identity, proto, port}` → allow (u8) |
| `PCT` | LruHash | `CtKey` 5-tuple → 1 (pod-initiated flow) |

`STAT_POLICY_DROP` counts enforcement drops.

## Control plane

- gRPC: `SetIdentity{ip, identity}` / `DelIdentity{ip}`, and
  `SetEndpointPolicy{host_if, enforce, rules[]}` with replace semantics
  (stale rules for the endpoint are cleared, mirroring `AddService`).
  `DelEndpointPolicy{host_if}` returns the endpoint to default-allow.
- `cradle-k8s` (`netpol.rs`) watches Pods, Namespaces, and NetworkPolicies:
  every pod's IP is published into `IDENTITY` with its label-set identity;
  for each policy target on this node, peer selectors resolve to the set of
  matching label-set identities and each `ingress` rule becomes
  `(identity, proto, port)` allow entries. Empty `from` ⇒ the `(0, …)`
  wildcard rules. `ipBlock` peers are skipped in this cut (logged).

## Testing

- BDD `cradle_policy.feature` (no Kubernetes): identities + policies pushed
  over gRPC against cradle-cni pods; asserts allow/deny/reply-statefulness
  and the drop counter.
- kind e2e: a `NetworkPolicy` phase in `deploy/kind-e2e.sh` — deny-then-allow
  against the nginx ClusterIP, enforced by cradle (no Cilium installed).
