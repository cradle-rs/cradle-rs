# cradle-rs MPLS TTL propagation (pipe / uniform) — design

> A configurable RFC 3443 TTL-processing model for the MPLS data plane —
> `uniform` (LSP hops visible end to end) vs `pipe` (LSP core hidden) —
> driven by a zebra-rs YANG leaf and teed to the eBPF push/pop paths.

Status: **Design / proposed — not implemented.** The datapath hardwires the
pipe model today (see below). This note captures the schema, defaults, and
tee shape so an implementation can follow the existing SRv6-flavor /
locator-behavior pattern (a control-plane leaf → codepoint/flag → tee →
eBPF gate). Tracked as the `TTL propagation (pipe/uniform)` ⬜ row in the
MPLS support table ([`mpls.md`](mpls.md)).

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

## Current behavior (hardwired pipe)

cradle is pipe on disposition and uniform-*style* on imposition — i.e. it
seeds the label TTL from the inner but never writes it back:

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

## Proposed schema (zebra-rs YANG)

The model lives in zebra-rs (YANG-driven CLI) and reaches cradle over the
`FibHandle` tee, exactly like locator `flavor` / `behavior` /
`vrf`. Mirror IOS semantics — operators already know
`mpls ip propagate-ttl [forwarded | local]`.

```yang
container mpls {
  container ttl {
    // RFC 3443 label-stack TTL processing model.
    leaf propagate {
      type enumeration {
        enum uniform;  // copy TTL both directions; LSP hops visible
        enum pipe;     // outer label TTL independent (seed 255); inner preserved; core hidden
      }
      default uniform;
    }
    // Even under pipe, still propagate for packets THIS router originates,
    // so the local PE's own traceroute traverses the LSP. IOS "local" knob.
    leaf propagate-local {
      type boolean;
      default true;
    }
  }
}
```

Generated CLI:

```
mpls ttl propagate {uniform | pipe}
mpls ttl propagate-local
```

### Per-VRF override

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

Recommended global default: **`uniform`**, despite it changing cradle's
current observable behavior. Reasons:

1. It is the RFC 3443 / vendor least-surprise default; someone who sets the
   knob expects other-vendor semantics.
2. It makes plain global-table MPLS transit `traceroute` correct — today
   cradle hides core hops even for non-VPN traffic, which is non-standard.
3. The flagship L3VPN case that *wants* hiding is better served by the
   per-VRF `pipe` override than by inverting the global default.

If backward-compat outweighs the above, `pipe` default is defensible — but
then the divergence from every other stack must be documented. This is the
one decision to confirm before implementing.

## Datapath / tee design

Because the two enforcement points differ, carry **two flags** rather than a
hot-path global-map read. zebra-rs resolves the leaf (+ VRF override) and
stamps them when it builds the tee:

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
path reads it from the FIB/ILM entry it already loaded, and the per-VRF
override falls out for free.

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

## Testing sketch

A `cradle_mpls_ttl` BDD over the existing `cradle_mpls` topology:

- **uniform**: push at the ingress LER, verify the egress inner IP TTL is
  `ingress_ttl − hop_count` (label TTL written back); a `traceroute` across
  the LSP lists the P hops.
- **pipe**: same path, verify the egress inner IP TTL is `ingress_ttl − 1`
  (LSP counts as one hop) and the P hops are absent from `traceroute`.
- **per-VRF override**: an L3VPN topology (`cradle_l3vpn`) with global
  `uniform` but the VRF set `pipe` — customer `traceroute` hides the core
  while global-table transit on the same node shows it.
- Teardown per the standard topology-cleanup convention.

## Open questions

1. Global default `uniform` vs `pipe` (see [Rationale](#default-and-rationale)).
2. Is per-VRF override needed in slice 1, or is the global leaf enough to
   start? (Global-only is the smaller change and matches the single
   hardwired setting cradle has now.)
3. ICMP-tunneling: ship with pipe, or accept swallowed errors until a
   follow-up? Pipe without it degrades operator `traceroute` diagnostics.
