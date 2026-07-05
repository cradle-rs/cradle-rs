# cradle-rs as a multi-tenant per-endpoint policy engine — plan

> Grow the policy first-cut ([`policy.md`](policy.md)) into a Cilium-class
> per-endpoint engine — but layered on what Cilium can't be: real tenancy
> (VRFs, overlapping pod CIDRs, SRv6/EVPN slices) underneath, with
> Cilium's CRD/API surface on top so its ecosystem carries over.

Status: **PLAN (no implementation yet).** Builds on the implemented
ingress-only IPv4 NetworkPolicy engine ([`policy.md`](policy.md)), the
Cilium-compat groundwork ([`cni-cilium.md`](cni-cilium.md) story 2), and
the program-structure analysis
([`tailcall-vs-monolithic.md`](tailcall-vs-monolithic.md)).

## Positioning

Cilium is a per-endpoint policy engine that grew routing features; cradle
is a router that grew a policy first-cut. The end state worth aiming for
is not a Cilium clone but identity-based per-endpoint policy on top of
real tenancy — per-tenant VRFs, overlapping PodCIDRs, per-tenant
SRv6/EVPN slices via the zebra-rs tee — consuming Cilium's CRDs and APIs
so its tooling (Hubble already works against cradle) keeps working.

## Load-bearing architecture decisions

Decide these first; every phase hangs off them.

1. **Per-endpoint policy state = map-in-map, not per-endpoint programs.**
   Replace the global `POLICY` hash with `HashOfMaps`: outer key =
   endpoint, inner map = that endpoint's policy table. Regeneration
   becomes compute → build fresh inner map → swap one outer entry,
   atomically. This delivers Cilium's per-endpoint atomic swap *without*
   per-endpoint program compilation — the data-driven alternative
   anticipated in
   [`tailcall-vs-monolithic.md`](tailcall-vs-monolithic.md). The monolith
   stays; the reserved SRv6-behavior tail-call seam remains the escape
   hatch if the policy function's growth (deny + egress + L7 redirect)
   pressures the verifier. **Risk to spike in week one:** map-in-map
   ergonomics in aya 0.14 — both `aya-ebpf` inner-map lookup and
   userspace inner-map fd swap.

2. **Identity becomes allocated, not hashed.** The FNV label-hash
   identity is elegant but has silent-collision risk (a collision merges
   two label sets — unacceptable once deny rules exist) and no
   cluster-wide agreement story. Move to a real allocator backed by
   `CiliumIdentity` CRDs (restart-safe, Cilium-tooling compatible); keep
   hash mode as the non-Kubernetes/BDD fallback. `IDENTITY` (IP →
   identity) is already the ipcache equivalent and works cross-node
   because SRv6/EVPN preserves inner source addresses — no
   identity-in-tunnel needed. Audit the masquerade paths: SNAT before the
   remote policy check destroys identity (the same trap Cilium handles
   explicitly).

3. **Tenant = VRF.** Namespace (or a Tenant CRD mapping a namespace set)
   → VRF id. Identity lookups become `(vrf, ip) → identity`; policy
   tables are per endpoint, which is already per tenant; overlapping pod
   CIDRs across tenants work because the FIB is VRF-aware
   (`FIB4_VRF`/`FIB6_VRF`). Cross-node tenant context rides the existing
   per-VRF SRv6 SIDs / EVPN routes. This is the differentiator — Cilium's
   identity space is flat.

4. **L7 policy reuses the TPROXY proxy.** Policy-driven redirect of
   selected flows to the existing Rust L7 proxy (`l7.rs`,
   `bpf_sk_assign` machinery already proven), which enforces HTTP rules
   and emits Hubble L7 flow records. No Envoy dependency.

## Phases

### Phase 1 — NetworkPolicy parity

Finish Kubernetes `NetworkPolicy` semantics on the current structure:

- **Egress direction**: enforce at the pod's veth TC hook; direction bit
  in the policy key; extend `PCT` statefulness to egress-initiated flows.
- **`ipBlock`/CIDR peers**: LPM map allocating local CIDR identities on
  `IDENTITY` miss, Cilium-style.
- **IPv6** and **named ports**.
- Tests: extend `cradle_policy.feature`; kind e2e egress phase.

### Phase 2 — Per-endpoint restructure + observability

The phase where "per-endpoint engine" becomes structurally true:

- Map-in-map policy tables (decision 1) and endpoint regeneration in
  `cradle-k8s`: label change → recompute → inner-map swap, with a
  generation counter exposed via `GetStats` / CiliumEndpoint status.
- **Audit mode**: verdict computed and reported, packet not dropped.
- Hubble policy-verdict flows carrying the matched rule, not just
  `STAT_POLICY_DROP`.

### Phase 3 — Identity allocator + Cilium policy CRDs

- `CiliumIdentity` allocation and GC; `CiliumEndpoint` status (identity,
  policy realized/enforcing) — the CRD plumbing from
  [`cni-cilium.md`](cni-cilium.md) story 2.
- `CiliumNetworkPolicy` L3/L4 subset: **deny rules** with deny-over-allow
  precedence (the six unrolled lookups become a deny pass + an allow
  pass — watch instruction growth), entities
  (`host`/`world`/`cluster`/`all`), enforcement modes
  (default/always/never).
- Acceptance: relevant slices of `cilium connectivity test` pass.

### Phase 4 — Multi-tenancy

- Tenant→VRF mapping and `(vrf, ip)` identity scoping (decision 3).
- Overlapping PodCIDR test topology; per-tenant EVPN/SRv6 slice wiring
  through the existing zebra-rs tee.
- `CiliumClusterwideNetworkPolicy`; host endpoint (the node itself as an
  enforced endpoint — reserved identity 1 already exists).

### Phase 5 — L7 policy

- Per-endpoint L7 rule sets (HTTP method/path first), policy-driven
  TPROXY redirect, proxy-side enforcement + Hubble L7 records,
  visibility annotations. Cilium's L7 CRD syntax as the config surface.

### Phase 6 — Scale + operations

- `cradle ctl policy trace` (à la `cilium policy trace`): resolve a
  (src, dst, port) tuple against the live maps.
- Identity/endpoint churn benchmarks — the regeneration path is the hot
  spot at scale; policy-map pressure metrics; operator docs.

## Sequencing rationale and risks

Phases 1–2 are pure cradle work with no new external dependencies and
deliver the per-endpoint core; 3 unlocks the ecosystem claim; 4 is the
differentiator and touches zebra-rs config surface (per-tenant VRF/SID
provisioning); 5–6 are independent tails.

Risks, in order:

1. **aya map-in-map support** (spike first — it gates Phase 2).
2. **Verifier growth** of the policy function once deny + egress + L7
   land; mitigation documented in
   [`tailcall-vs-monolithic.md`](tailcall-vs-monolithic.md) (the
   behavior-dispatch seam).
3. **Identity churn performance** in the CRD allocator.
4. **Masquerade/identity interaction** (decision 2).

Deliberate omission: **FQDN/DNS policy** — it requires a DNS proxy and
adds a large moving part; deferred until there is demand.
