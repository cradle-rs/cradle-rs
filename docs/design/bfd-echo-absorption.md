# Absorbing the XDP BFD Echo reflector + watchdog into cradle_xdp

Phase 2 of the eBPF offload consolidation (zebra-rs
`docs/design/ebpf-offload-consolidation.md`). Phase 0a imported `xdp-bfd-echo`
as a cradle-rs crate; Phase 1 retired `tc-evpn-replicate`. This phase folds the
BFD Echo datapath **into `cradle_xdp`** and drives it over gRPC, retiring the
standalone helper (user decision 2026-07-12: full absorption).

## What moves where

Source: `crates/xdp-bfd-echo-ebpf/src/main.rs` (the XDP program) +
`crates/xdp-bfd-echo/src/{main,sender}.rs` (loader + AF_PACKET originator).

- **eBPF (Slice 1)** — into `crates/cradle-ebpf/src/main.rs` (`cradle_xdp`):
  - `DetectState` (32B, `bpf_timer` at offset 0) + `ECHO_TIMERS`/`CONTROL_TIMERS`
    `#[btf_map]` (cradle's first BTF maps + first `bpf_timer`).
  - `OUR_LOCAL_IPS` / `OUR_LOCAL_IPS_V6` (`#[map]`).
  - The reflect + watchdog logic: `swap_macs`/`swap_ip6` (memcpy-avoidance
    volatile byte swaps), `decrement_ttl`/`decrement_hop_limit`, `record_return`,
    `observe_control`, `kick_timer`, the `detect_timeout` callback + the
    map-pointer trick.
  - Dispatch: a `3785 => try_bfd_echo_xdp` / `3784 => try_bfd_ctrl_xdp` arm in
    `try_udp4_xdp`'s dport `match` (alongside GTP 2152 / VXLAN 4789), and an IPv6
    equivalent in the `ETH_P_IPV6` path (`try_srv6_xdp`).
  - Reflect returns `XDP_TX`/`XDP_DROP` (terminal, chainable — unlike the UDP
    decaps which are PASS-with-metadata), so it slots in cleanly.
- **Control plane (Slice 2)** — into `crates/cradle` + `proto/cradle.proto`:
  - `ArmBfdEcho`/`DisarmBfdEcho` + `ArmBfdDetect`/`DisarmBfdDetect` RPCs (keyed by
    discriminator; mirror `AddFdbRemote`/`DelFdbRemote`) — seed/remove the timer
    maps + `OUR_LOCAL_IPS`.
  - `WatchBfd(stream BfdEvent)` — modeled on `WatchFdb`: a poll loop over the
    `down` flags emitting `echo-down`/`detect-down` per discriminator.
  - The AF_PACKET Echo originator (`sender.rs`) → cradle's control loop.
- **zebra-rs (Slice 3)** — `bfd/reflector.rs` child-spawn → gRPC arm/disarm via a
  cradle BFD client; a `WatchBfd` consumer task feeding `Message::EchoDown`/
  `DetectDown`/(engine-down = `HelperGone`); readiness gate via engine
  reachability instead of "child alive".
- **BDD + cleanup (Slice 4)** — migrate BFD echo/detect-offload BDDs to
  cradle-engine mode; then delete `crates/xdp-bfd-echo{,-ebpf}` + revert their
  Phase-0a wiring.

## Key facts / constraints (from the investigation)

- aya 0.14 / aya-ebpf 0.2 (cradle's pins) already support `#[btf_map]` +
  embedded `bpf_timer` — proven by the standalone crate. Kernel ≥ 5.15 for
  `bpf_timer`.
- **Coupling (accepted):** the absorbed reflector only runs where `cradle_xdp` is
  attached, so BFD echo now requires the interface to be a cradle port
  (`system ebpf enabled` + `interface <if> ebpf enabled`, which zebra turns into
  a `SetPort`). `cradle_xdp` `XDP_PASS`es everything it doesn't own, so a
  BFD-only port is a normal l3-passthrough `SetPort`.
- **veth `XDP_TX` caveat (`CRADLE_XDP_MODE`):** native `XDP_TX` on a veth only
  delivers to the *peer's* XDP RX path. Reflecting a peer's Echo off a veth
  whose peer has no XDP — e.g. a bridge-enslaved veth in the BDD LAN topology —
  is silently dropped in native mode. `CRADLE_XDP_MODE=skb` forces generic
  attach (re-inject through the stack, reflect regardless of peer), the mode the
  retired `xdp-bfd-echo` helper used on veths. Real NICs do native `XDP_TX`
  fine, so it is off by default; the BDD sets it for the `isis_bfd*` features
  only (generic mode skips the XDP pop/decap for TC-redirected skbs, so the
  SRv6/EVPN datapaths keep native).
- **Stack budget:** the 448-byte wall is `cradle_tc`'s; `cradle_xdp` is lighter
  and shares the 512-byte ceiling. The reflect path is stack-cheap by
  construction (in-place volatile byte swaps, `DetectState` lives in the map,
  touched only via `get_ptr_mut`). Main risk is verifier-state/instruction
  pressure on the shared program — keep the BFD logic in its own functions.
- **Verifier-sensitive tricks to preserve verbatim:** the per-byte volatile
  swaps (an array copy lowers to a pointer-diff memcpy the verifier rejects); the
  BTF map with `bpf_timer` at offset 0; the `core::ptr::from_ref(&MAP).cast_mut()`
  map-pointer for `bpf_timer_init`; single-bounds-check-then-constant-offset
  reads; **no aya-log** in this path.
- ABI invariants (must match the userspace mirror): `DetectState` 32B/8-aligned;
  `ECHO_MAGIC = 0x7a62_6664`; payload `{magic,discr,seq,tx_ts}` big-endian at
  UDP+8; ports 3785/3784; GTSM TTL/HL 255; IPv4 reflect → TTL 254; IPv6 reflect →
  HL 254 + src/dst swap.

## Status

- 2026-07-12: investigation done, full absorption chosen, this doc written.
- 2026-07-12: **Slice 1 DONE** (branch `bfd-echo-absorb`, commit `24aa5bd`):
  `crates/cradle-ebpf/src/bfd.rs` (`mod bfd`) + dispatch wiring in `cradle_xdp`.
  cradle's first `bpf_timer`/`#[btf_map]`. **Verifier-validated**: `cargo build
  -p cradle` links via bpf-linker, and `cradle serve` loads all three programs —
  `cradle_xdp` with the BFD branch + BTF maps + bpf_timer passes the kernel
  verifier. Nothing drives the new maps yet (Slice 2).
- 2026-07-12: **Slice 2 DONE** (branch `bfd-control-plane`, commit `6ace23c`):
  the userspace control plane for the detection offload — proto
  Arm/Disarm{Echo,Detect} + `WatchBfd(stream BfdEvent)`; `DetectStateUser` mirror
  + the four BFD maps in `Dataplane`; `bfd_echo_arm`/`bfd_detect_arm`/`bfd_poll_down`;
  the five service handlers + `watch_bfd` (modeled on `watch_fdb`). Build/clippy/
  fmt clean; `cradle serve` resolves all four map names.
  **Scope note:** the AF_PACKET Echo *originator* (sender.rs's transmit path) was
  split into a follow-on **Slice 2b** — Slice 2 wires everything the XDP reads,
  so the *responder* (Slice 1 reflect) + the *control-packet watchdog* work
  end-to-end; the *Echo originator* role awaits 2b (`arm_bfd_echo` seeds the maps
  but nothing transmits yet, and `watch_bfd` emits only on `down==1`, which stays
  0 for echo until the transmitter runs — so no spurious events).
- 2026-07-12: **Slice 2b DONE** (branch `bfd-echo-originator`, commit `0548dd3`):
  `crates/cradle/src/bfd_echo.rs` `BfdEchoEngine` — the AF_PACKET Echo transmit
  path ported from sender.rs as a background task, driven over an `EchoCmd`
  channel from `bfd_echo_arm`/`disarm`; `BfdEcho` gains `oif`; bootstrap timeout
  writes `down=1` into `ECHO_TIMERS` (race-free) so `watch_bfd` reports it
  uniformly. **The cradle-side BFD datapath is now complete** (responder +
  control watchdog + Echo originator). build/clippy/fmt clean.
- Next: Slice 3 (zebra `bfd/reflector.rs` child-spawn → gRPC arm/disarm +
  WatchBfd consumer; readiness gate via engine reachability), Slice 4 (BDD
  engine-mode + retire the standalone `xdp-bfd-echo{,-ebpf}` crates).
