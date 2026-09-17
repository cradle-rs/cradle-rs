# STAMP offload: zebra-rs userspace vs the cradle datapath — design note

> zebra-rs measures link delay/loss with STAMP (RFC 8762/8972) and feeds the
> results into IS-IS/OSPF TE sub-TLVs, where Flex-Algo and CSPF consume them.
> Should any of that measurement move into `cradle_xdp`, the way the BFD Echo
> reflector and watchdog did? This note records the pros, the cons, and where
> the line sits.

Status: **analysis only — nothing to implement today.** Position: *do not
offload for the ms-class WAN TE case that Pattern A actually targets; rung 1
(`SO_TIMESTAMPING`, already shipped) is sufficient there.* Offload is justified
by µs-class fabrics, load immunity, and line-rate reflection for external
controllers — not by the Phase-1 baseline. Builds on
[`bfd-echo-absorption.md`](bfd-echo-absorption.md) (the precedent and the
infrastructure this would reuse) and [`architecture.md`](architecture.md); the
verifier-budget argument is the one in
[`tailcall-vs-monolithic.md`](tailcall-vs-monolithic.md). The zebra-side design
lives in zebra-rs `docs/design/stamp-isis-ospf.md` and
`docs/design/bfd-sbfd-stamp-xdp-offload-notes.md`.

## Where things stand today

**cradle-rs has no STAMP support at all.** Verified 2026-09-17:

- No udp/862 anywhere. `crates/cradle-ebpf/src/main.rs:457` defines only
  `BFD_ECHO_PORT` (3785) and `BFD_CTRL_PORT` (3784); the dport `match` in
  `try_udp4_xdp` (`main.rs:3203`) and `try_bfd6` (`main.rs:3301`) covers
  GTP 2152 / VXLAN 4789 / 3785 / 3784 and falls through `_ => XDP_PASS`.
- No RFC 8762/8972 parsing, no session state, no PM maps, and no STAMP RPCs in
  `proto/cradle.proto` — BFD has `ArmBfdEcho`/`ArmBfdDetect`/`WatchBfd`, and
  there is no performance-measurement analogue.
- The only literal occurrence of "STAMP" in the tree is a doc comment on a
  generic BDD step (`bdd/tests/cucumber.rs:3465`), describing the zebra-side
  feature rather than any cradle behavior.

**Nothing in cradle blocks the userspace implementation.** udp/862 falls through
`XDP_PASS` to the stack, so zebra's reflector and sender sockets work unchanged
on a cradle port.

**zebra-rs side** (~5.1 kLOC): `zebra-rs/src/stamp/*` plus the `stamp-packet`
crate. Two properties matter for this analysis:

- **Unauthenticated mode only** (`crates/stamp-packet/src/lib.rs:16` — the HMAC
  TLV is explicitly out of scope).
- **The reflector emits exactly one TLV type**, `ExtraPadding`, for symmetric
  sizing (`zebra-rs/src/stamp/reflector.rs:40`). The Return Path TLV is
  implemented in the packet crate but not on the reflect path.

Accuracy work already landed: Phase 1.5 rung 1 (`SO_TIMESTAMPING`, zebra PR
#1431, 2026-06-13) puts kernel software stamps on T4/T2 with `t4_kernel` /
`t2_kernel` counters. Rung 2 (TX errqueue) was abandoned the next day — software
TX stamps need the driver's `skb_tx_timestamp()`, absent on `lo`/`veth`, so it
is real-NIC-only and untestable in the lab.

## Three separable stages

"Offload STAMP" is not one decision. Most arguments below apply to exactly one
row:

| Stage | What moves | Verdict |
|---|---|---|
| **A** | Session-Reflector into `cradle_xdp` — base-44 in-place rewrite + `XDP_TX` | Worth it, but only on a concrete trigger (below) |
| **B** | Sender-RX fastpath — per-session aggregate in a map, userspace reads once per export period | Defer; no scale problem exists |
| **C** | Hardware timestamps on capable NICs (PHC) | Real NICs only; untestable in the veth BDD lab |

## Pros

**1. Load immunity — the only argument worth building a case on.** Without
offload, advertised delay and jitter spike exactly when the router is busy: BGP
churn, SPF storms, LSDB floods. Those are the same events that cause reroutes,
so the measurement error is *correlated with* the thing it feeds. Damping cannot
separate "real network jitter" from "my own scheduling jitter" — both are
variance. This is self-inflicted TE flap, and it is the identical rationale the
project already accepted for BFD detect-offload.

**2. It rescues the statistics the A-bit keys on.** The four userspace
stamp-to-wire residues drop from tens of µs idle / ms-class tails to roughly µs
(generic XDP) or sub-µs (native + HW). Note *which* metrics that helps: max
delay and delay variation, hence the anomaly threshold. A false A-bit raises TE
cost and drains the link from SPF/CSPF — real operational damage from a
scheduling artifact.

*Honest caveat:* Flex-Algo's headline metric is **min** unidirectional delay
(RFC 9350), and min-of-N is the statistic most naturally immune to scheduling
tails — taking the minimum already filters them. The fidelity win lands on
max/variation/A-bit, not on the metric the Flex-Algo case is usually argued
from.

**3. The implemented feature set is fully XDP-expressible — no loss.** Because
zebra is unauthenticated-mode only and the reflect path emits only
`ExtraPadding`, base-44 reflect plus a padding memset is the entire job. The
usual "auth and TLVs can't go in XDP" objection does not bite against today's
code. Authenticated mode, if it ever lands, simply stays in userspace.

**4. Marginal cost is genuinely low.** Every piece of infrastructure exists and
is production-validated by the BFD absorption: `crates/cradle-ebpf/src/bfd.rs`
is a working template for in-place rewrite + `XDP_TX`; `PortRequest::Acquire` /
`Release` is already the per-ifindex refcounting attach supervisor; `Arm` /
`Disarm` / `Watch` is an established RPC triple. This is a new dispatcher arm
and a map, not new architecture.

**5. Reflector hardening.** An in-kernel allow-list drops unsolicited probes
before the stack sees them. zebra counts `reflector_stats.unauthorized` today
(`zebra-rs/src/stamp/inst.rs:84`), which means it burns a wakeup and a parse on
every hostile probe. Offloaded, the reflector stops being a way to load the
daemon.

**6. Clean degradation.** `cradle_xdp` `XDP_PASS`es everything it does not own,
so engine death or an empty map falls through to the userspace 862 socket and
reflection continues.

## Cons

**1. The coupling inverts a dependency — the real cost.** Today STAMP measures
any interface that has a UDP socket. Offloaded, the reflector only runs where
`cradle_xdp` is attached, so **measuring a link means making it a cradle port**:
enabling delay measurement changes that interface's forwarding path. zebra's
auto-attach (`PortRequest::Acquire`, zebra-rs `f56e02bc`) fixes the *ergonomics*
— no explicit `interface <if> ebpf enabled` needed — but not the blast radius. A
measurement feature acquiring a dependency on the eBPF datapath is not
proportionate risk.

**2. You pay verifier budget out of the forwarding path.** `cradle_xdp` is a
near-budget monolith: the flattened frame must stay within the verifier's
512-byte call-chain stack (`main.rs:353`), and `cradle_xdp_l3` was split into
its own program precisely so it would not compete for it (`main.rs:3081`). A
STAMP branch adds parse + rewrite + lookups to the dispatcher every packet
traverses. Expect scratch-map gymnastics or another program split. Spending the
datapath's scarcest resource on a measurement feature is a bad trade to make
casually.

**3. The scale argument is fiction for Pattern A.** `DEFAULT_INTERVAL_MS = 1000`
(`zebra-rs/src/stamp/session.rs:72`), and the adjacent comment records Cisco
SR-PM probing at 3 s. Hundreds of adjacencies is hundreds of pps — noise against
a datapath benchmarked near 1.3 Mpps. Scale only revives for SR-Policy PM at
10–100 Hz across many candidate paths, or if we become an external controller's
reflector target at rate. **Stage B must not be justified on scale**; there is
no scale problem to solve.

**4. Stage A can regress the clock axis while improving the residue axis.**
In-XDP stamping without PHC is `bpf_ktime_get_ns` — monotonic, not NTP-epoch.
STAMP wants NTP-format timestamps, so we would carry a conversion offset that
itself drifts, and widen the Error Estimate to cover it. Meanwhile rung 1 gives
kernel stamps *with* correct clock semantics. The honest comparison is not
"userspace vs XDP" but "kernel-stamped userspace vs XDP monotonic", and XDP only
clearly wins once stage C and a real PHC are in play.

**5. Split-brain observability.** `show stamp statistics` becomes half BPF map,
half userspace, with a readout path to keep them consistent. Every counter gets
two sources of truth.

**6. Testability regression.** Native `XDP_TX` on a veth only reaches the peer's
XDP RX path, so STAMP BDDs would need `CRADLE_XDP_MODE=skb` — and generic mode
skips the XDP pop/decap for TC-redirected skbs. We would be validating STAMP
under a datapath mode the SRv6/EVPN features deliberately avoid, i.e. testing a
configuration that is not production. The `isis_bfd*` features already sit in
this trap (see [`bfd-echo-absorption.md`](bfd-echo-absorption.md)).

**7. Cross-repo release coupling.** A feature that is self-contained in one
daemon becomes a two-repo, proto-versioned change for every protocol increment.

**8. It does not touch what decides whether delay routing is stable.** Damping,
anomaly/A-bit hysteresis, ASLA encoding, re-advertise thresholds — all
userspace, all unaffected. Offload improves input quality, not the control logic
that turns samples into LSPs. If the thresholds are wrong, better timestamps
just make the wrong decision more precisely.

## Verdict

Do not start on the strength of the Flex-Algo delay story alone. Start when one
of these is true:

1. **µs-class fabric** (DC/metro) where real path-delay differences are below
   the userspace noise floor — there, the advertised numbers currently measure
   tokio scheduling rather than the network.
2. **Demonstrated contamination under control-plane load** — A-bit or
   delay-variation excursions that correlate with BGP/SPF activity rather than
   with the link.
3. **Reflector-target duty** for an external controller at a rate where per-probe
   userspace wakeups actually cost something.

For ms-class WAN TE — what Pattern A in the IS-IS/OSPF integration doc is
actually about — rung 1 has already bought the cheap accuracy, and this should
be left alone.

## If we do it: the shape

Stage A only, reflector only:

- A `stamp` module beside `crates/cradle-ebpf/src/bfd.rs`, an `862 =>` arm in
  `try_udp4_xdp` and `try_bfd6`, and an allow-list map keyed like
  `OUR_LOCAL_IPS`. The reflect is an in-place rewrite returning `XDP_TX`, which
  chains cleanly exactly as the Echo reflect does (terminal, not
  PASS-with-metadata).
- `ArmStampReflect` / `DisarmStampReflect` plus a stats-readout stream in
  `proto/cradle.proto`, modelled on the BFD five.
- Attach via the existing `PortRequest::Acquire` / `Release` refcount — no new
  supervisor.

**Keep the role split: reflector in cradle, sender in zebra.** The sender is
where T1, authentication, TLVs and the Return Path TLV would live, and none of
those belong in XDP. Note that BFD went further — cradle took the AF_PACKET Echo
originator in Slice 2b — but that precedent should *not* be copied here, because
STAMP's TX side carries exactly the parts with the clearest reasons to stay in
userspace.

## Correction to the zebra-side offload notes

`bfd-sbfd-stamp-xdp-offload-notes.md` §9b.4 is stale in its premise. It says to
extend `offload/xdp-bfd-echo/` with a STAMP branch, with a "prerequisite
refactor" promoting `EchoReflectors` into a shared per-ifindex offload
supervisor. Both halves are obsolete:

- The standalone helper is gone. cradle absorbed the Echo reflector and watchdog
  into `cradle_xdp`; `offload/` and `crates/xdp-bfd-echo{,-ebpf}` no longer exist
  in either tree, and `zebra-rs/src/bfd/reflector.rs` is now a gRPC driver.
- The shared-supervisor refactor already exists in another shape:
  `PortRequest::Acquire` / `Release` refcounts ifindexes into cradle's attach
  set. A STAMP client joins by sending the same requests.

The §9b.5 staging ladder and the §9b.6 pro case remain valid; only the
integration mechanics changed.

## References

- RFC 8762 / RFC 8972 — STAMP and its optional extensions
- RFC 8570 / RFC 7471 — IS-IS / OSPF TE metric extensions (what the results feed)
- RFC 9350 — IGP Flexible Algorithm (min unidirectional link delay)
- RFC 9503 / draft-ietf-spring-stamp-srpm — STAMP in SR networks (path PM)
- zebra-rs `docs/design/stamp-isis-ospf.md` — how the results reach the IGP
- zebra-rs `docs/design/bfd-sbfd-stamp-xdp-offload-notes.md` §9–9b — the
  original offload feasibility study
- zebra-rs `docs/design/stamp-phase1.5-so-timestamping-plan.md` — the rung
  ladder and what rung 1 shipped
