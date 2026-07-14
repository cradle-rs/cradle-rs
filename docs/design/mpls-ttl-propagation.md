# cradle-rs MPLS TTL propagation (pipe / uniform) — design

> A configurable RFC 3443 TTL-processing model for the MPLS data plane —
> `uniform` (LSP hops visible end to end) vs `pipe` (LSP core hidden) —
> driven by a zebra-rs YANG leaf and teed to the eBPF push/pop paths.

Status: **Implemented end to end (BDD-proven), datapath + static config +
zebra-rs producer.** The eBPF gates, the two flags, the static gRPC/JSON
config path, and the zebra-rs `mpls ttl propagate {pipe|uniform}` YANG leaf
are all in tree; the datapath is exercised by the `cradle_mpls_ttl` BDD (pipe
imposition seeds label TTL 255; uniform disposition writes the popped label
TTL back into the inner IP with an IPv4 checksum fixup). Pipe is the default,
so nothing changes for existing configs until the knob is set. **Still to
do:** a per-VRF override, and the IOS-style forwarded/local split
(`propagate-local`) — the datapath has no local-origin distinction yet, so
that leaf was deliberately not modeled. The "baseline behavior" section is
retained as the pre-work starting point. Tracked as the `TTL propagation
(pipe/uniform)` 🔶 row in the MPLS support table ([`mpls.md`](mpls.md)).

### What shipped

- `cradle-common`: `NH_F_MPLS_PIPE` (imposition), `MplsEntry.flags` +
  `MPLS_E_TTL_UNIFORM` (disposition), `MPLS_PIPE_TTL` (255).
- `cradle-ebpf`: `mpls_push` seeds 255 under pipe; `pop_decap_local` /
  `pop_and_forward` copy the popped label TTL into the exposed IPv4/IPv6 header
  under uniform (`mpls_uniform_to_ip` + `csum16_update`, RFC 1624). PHP writes
  `ttl-1` since it redirects directly; the pop-to-local path writes `ttl` and
  lets the TC FIB apply the onward-hop decrement.
- `cradle` control: `mpls_pipe_ttl` on `Nexthop`, `ttl_uniform` on `Ilm`
  (proto + JSON config), threaded through `nexthop_set*` / `ilm_add`.
- **zebra-rs producer** (`mpls-ttl-propagate`, merged): the global
  `mpls ttl propagate {pipe|uniform}` YANG leaf → a `TtlModel` on the RIB →
  `CradleFib` sets `Nexthop.mpls_pipe_ttl` at labeled-nexthop imposition and
  `Ilm.ttl_uniform` at pop-to-IP disposition. Default `pipe`; see the schema
  section for the (revised) shape that actually shipped.

## Goal and scope

RFC 3443 defines two ways the TTL of a label-switched path relates to the
TTL of the payload it carries:

- **Uniform** — the LSP is transparent. Imposition copies the inner IP TTL
  into the outer label TTL; every LSR decrements the label TTL; disposition
  copies the (decremented) label TTL back into the inner IP header. A
  `traceroute` across the LSP shows every P router, and the end-to-end hop
  count is accurate.
- **Pipe** — the LSP is one opaque hop. Imposition seeds the label TTL
  independently of the inner (canonically `255`); disposition **discards**
  the label TTL and leaves the inner IP TTL as the ingress left it. The P
  routers are invisible to a customer `traceroute`; the core topology is
  hidden.

Scope of this note: the **TTL** knob only. The companion class (TC/EXP)
model and ICMP-tunneling are noted under [Companions](#companion-features)
but are out of scope for the first slice.

## Baseline behavior (the pre-work starting point)

Before this work cradle was pipe on disposition and uniform-*style* on
imposition — i.e. it seeded the label TTL from the inner but never wrote it
back. This is now the behavior when neither flag is set (pipe disposition +
uniform-style imposition seed), preserved for backward compatibility:

- **Imposition (ingress LER).** `l3_forward_*` pushes a labeled nexthop via
  `mpls_push(ctx, &nh, ttl)` where `ttl` is the inner IP TTL
  (`crates/cradle-ebpf/src/main.rs:1852`, `mpls_push` at
  `main.rs:2116`); the label stack entry is packed with
  `mpls_lse(label, tc, s, ttl)` (`crates/cradle-common/src/lib.rs:577`).
  The inner IP TTL is left untouched — no decrement, no games.
- **Transit (P router).** The TC/XDP label path decrements the top label's
  TTL per hop and `<= 1` punts to the host stack for the ICMP time-exceeded
  ([`mpls.md`](mpls.md) — the swap/pop stages).
- **Disposition (egress / PHP / pop-to-VRF).** `pop_and_forward`
  (`main.rs:4254`), `pop_decap_local` (`main.rs:3164`) and `pop_head`
  (`main.rs:4279`) strip the label and forward the inner frame with its IP
  TTL as-is. The label TTL is discarded — the pipe half.

So the *defining* end is disposition, and it is pipe. A real knob has to
gate **both** ends, because uniform needs imposition to seed (already does)
**and** disposition to write the label TTL back into the inner header.

## Schema (as shipped in zebra-rs)

The model lives in zebra-rs (YANG-driven CLI) and reaches cradle over the
`FibHandle` tee, exactly like locator `flavor` / `behavior` / `vrf`. The
shipped leaf is a single global enum (top-level `container mpls`):

```yang
container mpls {
  container ttl {
    // RFC 3443 label-stack TTL processing model.
    leaf propagate {
      type enumeration {
        enum pipe;     // outer label TTL independent (seed 255); inner preserved; core hidden
        enum uniform;  // copy TTL both directions; LSP hops visible
      }
      default "pipe";
    }
  }
}
```

Generated CLI:

```
set mpls ttl propagate {pipe | uniform}
```

`propagate-local` (the IOS forwarded/local split, `mpls ip propagate-ttl
[forwarded | local]`) was **not** shipped: the cradle datapath has no
local-origin distinction at imposition, so the leaf would be a silent no-op.
It is left as a follow-up gated on a datapath change.

### Per-VRF override (follow-up, not yet shipped)

The model is enforced at **disposition**, and for L3VPN the egress PE knows
the VRF from the VPN label at pop-to-VRF. That makes a per-VRF override
clean and matches real deployments (internet-in-global = `uniform`, each VPN
= `pipe`):

```yang
// under the existing vrf/table config
leaf mpls-ttl-propagate {
  type enumeration { enum inherit; enum uniform; enum pipe; }
  default inherit;   // take the global mpls/ttl/propagate value
}
```

Transit swaps carry no VRF, so they always take the global value.

## Default and rationale

Shipped global default: **`pipe`**. During design this was weighed against a
`uniform` default (the RFC 3443 / vendor least-surprise value), but `pipe`
won for the implementation:

1. **No behavior change on upgrade.** cradle's per-entry datapath default is
   already pipe, and zebra-rs's prior MPLS behavior is pipe-equivalent (the
   label TTL was discarded at disposition). A `uniform` default would
   silently alter every existing L3VPN / IS-IS-SR deployment's delivered TTL
   and traceroute on upgrade — the wrong default for a routing daemon.
2. **The flagship case wants it.** L3VPN (cradle's main MPLS use) wants the
   core hidden; pipe is the appropriate default there.
3. **Uniform is one keystroke away** (`set mpls ttl propagate uniform`) for
   the global-table transit case that wants hop visibility.

The cost is a documented divergence from the "vendor least-surprise"
argument, accepted in exchange for a no-op upgrade. The `README` MPLS row and
the zebra-rs CHANGELOG both record `pipe` as the default.

## Datapath / tee design

Because the two enforcement points differ, carry **two flags** rather than a
hot-path global-map read. zebra-rs resolves the global leaf into a `TtlModel`
on the RIB and stamps the flags when it builds the tee (a per-VRF override
would refine this later):

- **Imposition → per-nexthop flag.** Add `NH_F_MPLS_PIPE` alongside
  `NH_F_MPLS` (next free bit `1 << 6` in `crates/cradle-common/src/lib.rs`;
  current flags stop at `NH_F_VXLAN = 1 << 5`) and a bool on the `Nexthop`
  proto message (`proto/cradle.proto:37`). In `mpls_push`, seed the outer
  label TTL with `255` when the flag is set instead of the inner IP TTL.
- **Disposition → per-ILM flag.** A bit on the `Ilm` pop entry
  (`proto/cradle.proto:343`). When uniform, the pop path
  (`pop_decap_local` / `pop_and_forward`) copies the top label's TTL into
  the inner IP header and recomputes the IP checksum (RFC 1624 incremental,
  the same pattern already used for the TTL-decrement at
  `main.rs:1864`). This checksum write is the only non-trivial datapath
  addition.

Keeping the state per-entry (not a global settings map) means the eBPF hot
path reads it from the FIB/ILM entry it already loaded, and a future per-VRF
override falls out for free (the producer just stamps different per-entry
values without any datapath change).

## Companion features (out of scope, noted)

- **ICMP tunneling** (RFC 3032 §3.4; Junos `icmp-tunneling`). Under pipe,
  a TTL-exceeded raised by a P router has no route back to the source
  (customer space is hidden). ICMP tunneling forwards the ICMP to the LSP
  egress and back so `traceroute` still returns errors. Without it, pipe
  both hides the core *and* swallows the errors. Worth a sibling leaf.
- **TC/EXP propagation (short-pipe).** RFC 3443 pairs TTL with a class
  model; cradle isn't doing uniform TC either. Natural as `mpls tc
  propagate` once the TTL leaf lands, with a `short-pipe` variant where the
  egress PE forwards on the inner class rather than the tunnel class.

## Testing (as shipped)

The `cradle_mpls_ttl` BDD runs two single-label LSPs over the `cradle_mpls`
topology (`cl → ler1 → lsr2 → per3 → srv`), a client packet starting at TTL
64. It observes the concrete TTLs with `tcpdump` rather than relying on
traceroute (cradle has no kernel-MPLS ICMP path):

- **uniform LSP** (dst `10.0.3.1`): the server sees the request at **TTL 62**
  — the lsr2 transit hop is counted (label TTL written back at per3, then one
  IP-forward decrement).
- **pipe LSP** (dst `10.0.5.1`, `mpls_pipe`): the server sees **TTL 63** — the
  LSP is hidden, only per3's IP-forward decrement applies.
- **pipe imposition on the wire**: on the ler1→lsr2 link the label carries
  **TTL 255** (the pipe seed).
- Ends with an explicit teardown asserting a clean environment.

The zebra-rs producer side is verified by build / clippy / `ttl_model_tests`
and a live daemon loading the new YANG; a zebra-driven end-to-end BDD (which
would need the flag surfaced in cradle's nexthop/ILM dump) is a follow-up.

## Open questions — resolved

1. **Global default `pipe` vs `uniform`** → shipped `pipe` (no-op upgrade;
   see [Rationale](#default-and-rationale)).
2. **Per-VRF override in the first slice?** → no; global-only shipped, the
   override is a follow-up.
3. **`propagate-local` (forwarded/local split)?** → not shipped; the datapath
   has no local-origin distinction, so the leaf would be a no-op.

Still open: **ICMP-tunneling** (RFC 3032 §3.4) — under pipe a P-router
TTL-exceeded has no route back to hidden customer space, so operator
`traceroute` diagnostics are degraded until this lands; and **TC/EXP
propagation** (see [Companions](#companion-features-out-of-scope-noted)).
