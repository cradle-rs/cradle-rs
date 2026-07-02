# cradle-rs large FIB (DIR-24-8) — design

> A million learned routes in the eBPF data plane: replace the IPv4 LPM trie
> with a DPDK-style DIR-24-8 direct-index FIB — O(1)–O(2) flat array lookups,
> no per-packet lock, full-DFZ capacity — behind the unchanged `FibHandle` seam.

Status: **design / not yet implemented.** This proposes the map layout, the
packed entry format, the data-plane lookup, the userspace expansion engine,
and a phased plan. It builds on the L3 path in
[`architecture.md`](architecture.md) and is a prerequisite none of the overlay
designs ([`mpls.md`](mpls.md), [`srv6.md`](srv6.md),
[`evpn-vxlan.md`](evpn-vxlan.md)) depend on — but the shared per-VRF FIB they
all converge on should be built knowing this is where the global table is
going.

(日本語訳: [`large-fib.ja.md`](large-fib.ja.md))

## Goal and scope

cradle's differentiator is that **learned** routes program the eBPF FIB — and
"learned" at its most demanding means a full IPv4 DFZ feed, ~1M prefixes
today. The current FIB cannot carry that usefully:

```rust
// crates/cradle-ebpf/src/main.rs:50
static FIB4: LpmTrie<[u8; 4], FibEntry> = LpmTrie::with_max_entries(4096, 0);
```

Raising `max_entries` is not the fix. `BPF_MAP_TYPE_LPM_TRIE` *holds* a
million entries fine (it is forced `BPF_F_NO_PREALLOC`; ~2M trie nodes ≈
150–250 MB) — it just stops being a router at that size, for two reasons that
are properties of the map type, not of eBPF:

1. **Per-packet lookup cost.** The kernel LPM trie is a path-compressed
   binary trie: a longest-match descent of up to **32 node visits** for IPv4
   (128 for IPv6), each a pointer chase and a likely cache miss. Against a
   full table at line rate, that walk *is* the pps ceiling.
2. **Update serialization.** One spinlock guards the whole trie. A BGP
   convergence storm over 1M routes serializes every insert/withdraw — a
   control-plane (convergence-time) cost, but at DFZ churn a real one.

The fix is the structure hardware-adjacent software routers use: **DIR-24-8**
(DPDK `rte_lpm`; VPP's `ip4-mtrie` is the 16-8-8 cousin). It trades memory
for determinism — and in eBPF it is expressible with nothing but `Array` maps
and index arithmetic.

For calibration: this is deliberately past what Cilium carries. Cilium's L3
map (`cilium_ipcache`) defaults to 512k entries and is an identity/CIDR cache
for policy and tunnel selection, not a next-hop FIB. A full-DFZ eBPF FIB is
cradle's thesis made concrete.

## DIR-24-8 in one page

Two flat arrays:

- **`TBL24`** — indexed by the top 24 bits of the destination address:
  2²⁴ = 16,777,216 slots. One 4-byte entry each ⇒ **64 MiB, preallocated**.
  A slot either resolves the packet directly (all routes covering that /24
  are ≤ /24) or points to a tbl8 group.
- **`TBL8`** — a pool of 256-entry groups. A /24 that contains any longer
  prefix (/25–/32) gets one group; the final 8 address bits index into it.

Lookup is one array access for ≥ 99% of DFZ-shaped traffic (prefixes ≤ /24)
and exactly two in the worst case. No loops, no pointer chasing beyond the
array deref, no lock — `Array` map reads are plain RCU-protected loads. The
cost moves to **update time**: a route shorter than /24 is *expanded* — a /16
writes 256 `TBL24` slots — which is the right trade for a read-dominant DFZ.

Why 24-8 and not VPP's 16-8-8: 16-8-8 shrinks the root to 256 KiB and makes a
/16 a single write, but the common lookup becomes up to 3 dependent loads and
the common *update* (a /24, the modal DFZ prefix) still touches a leaf. At
64 MiB the 24-8 root is cheap on the class of machine that wants a DFZ; we
buy the flattest possible read path. 16-8-8 remains the fallback if the
memory footprint ever matters (and is the likely v6 shape — see below).

## Map contract (`cradle-common`)

### Packed entry

`FibEntry{nexthop_id: u32, flags: u32}` is 8 bytes; the direct-index tables
pack the same information into a **4-byte word** so `TBL24` stays at 64 MiB:

```rust
/// Packed DIR-24-8 slot. Layout (bit 31 .. bit 0):
///   [31]     FIBW_VALID
///   [30]     FIBW_TBL8    — low bits are a TBL8 group index, not a nexthop
///   [29:26]  flags        — FIB_F_BLACKHOLE | LOCAL | CONNECTED | ECMP (4 bits)
///   [25:0]   nexthop_id (or group index when FIBW_TBL8): 64M ids
pub type FibWord = u32;

pub const FIBW_VALID: u32 = 1 << 31;
pub const FIBW_TBL8:  u32 = 1 << 30;
pub const FIBW_FLAGS_SHIFT: u32 = 26;
pub const FIBW_ID_MASK: u32 = (1 << 26) - 1;
```

The existing `FIB_F_*` bits fit the 4-bit field with room to spare (they are
`1<<0..1<<3` today); `nexthop_id` keeps 26 bits, far beyond any nexthop/group
population. The unpacked `FibEntry` stays as-is for the LPM path and the gRPC
surface — packing is internal to the DIR tables.

### The maps

```rust
#[map] static TBL24: Array<FibWord> = Array::with_max_entries(1 << 24, 0);
#[map] static TBL8:  Array<FibWord> = Array::with_max_entries(TBL8_GROUPS * 256, 0);
```

- `TBL8_GROUPS` default **4096** (4 MiB): one group per /24 that contains a
  longer-than-/24 prefix. The v4 DFZ propagates almost nothing longer than
  /24, so groups are consumed by *local* state — host routes, VIP locals,
  connected /31–/32s. 4096 is generous; it is a load-time knob (below).
- Both are plain (shared, preallocated) `Array` maps: read-mostly, lock-free
  readers, per-element atomic 4-byte updates.

### Load-time sizing, not compile-time forks

aya's `EbpfLoader::set_max_entries` resizes maps before creation. `cradle
--fib4-mode {lpm,dir24}` (also in the JSON config) selects the engine:

- `lpm` (default for small deployments): `TBL24`/`TBL8` are created with 1
  entry each — the 64 MiB cost simply doesn't exist; `FIB4` keeps working as
  today (its `max_entries` becomes a knob too).
- `dir24`: full-size arrays; `FIB4` shrinks to 1 entry.

One compiled object, one datapath. The datapath picks the engine per packet
from a config flag (an `Array<u32>` config word it already reads is cheap; a
miss on the 1-entry array falls through to the other engine anyway, making
the flag a fast-path hint rather than a correctness requirement).

## Data-plane lookup (`cradle-ebpf`)

Replaces the `FIB4.get(Key::new(32, dst))` in `l3_forward_v4`
(`main.rs:703`); everything downstream — `FIB_F_*` handling, ECMP member
selection, TTL, `bpf_redirect_neigh` — is unchanged:

```rust
let idx24 = (u32::from_be_bytes(dst) >> 8) as u32;
let mut w = *TBL24.get(idx24).ok_or(())?;
if w & FIBW_TBL8 != 0 {
    let group = w & FIBW_ID_MASK;
    w = *TBL8.get(group * 256 + dst[3] as u32).ok_or(())?;
}
if w & FIBW_VALID == 0 {
    return Ok(TC_ACT_PIPE as i32);            // no route → host stack
}
let flags = (w >> FIBW_FLAGS_SHIFT) & 0xf;
let nexthop_id = w & FIBW_ID_MASK;
// → existing blackhole/local/ECMP/nexthop path
```

Two bounded array derefs, zero verifier drama. This is *less* program
complexity than the LPM call it replaces.

### The default route stays out of the table

Expanding `0.0.0.0/0` would mean writing all 16.7M `TBL24` slots on every
default-route change. Instead the invalid-word fallthrough checks a
1-entry `DEFAULT4: Array<FibWord>` before punting. This also gives very
short prefixes a cheap escape hatch if an operator's table is
pathological — but ordinary /8s (a handful exist in a DFZ) just expand:
65,536 batched writes is milliseconds.

## The userspace side: shadow trie + expansion engine

Today `Dataplane::route4_add` writes the LPM map directly and **no userspace
route shadow exists** (`crates/cradle/src/dataplane.rs`). DIR-24-8 makes a
shadow mandatory: expansion must know, for every affected slot, which prefix
is the *most specific cover* — information only the full route set provides.

New in the `cradle` crate:

- **Shadow trie** — a userspace radix trie of `(prefix → FibEntry)`,
  authoritative for what *should* be programmed. (This is also the natural
  host for the depth information DPDK burns into its table entries; keeping
  depth in the shadow keeps the kernel word to 4 bytes.)
- **Expansion engine** — turns one route add/del into slot writes:
  - `len ≤ 24`: for each of the `2^(24-len)` covered `TBL24` slots, write the
    packed word **only if** this prefix is more specific than the slot's
    current cover (shadow lookup). Deletion rewrites the range to the
    next-best cover, or invalid.
  - `len > 24`: ensure the covering /24 has a `TBL8` group (allocate from a
    free list, **fully populate it** from the shadow — the ≤ /24 cover fills
    the background slots, longer prefixes overlay theirs — *then* flip the
    `TBL24` slot to point at it). Delete may collapse a group back to a
    direct entry; the group returns to the free list **lazily** (a grace
    period), so an in-flight packet that read the old `TBL24` word never
    indexes into a group being rewritten for a different /24.
  - All range writes go through `BPF_MAP_UPDATE_BATCH` (kernel ≥ 5.6, aya
    batch ops): a full 1M-route initial load expands to ~1.5–2M slot writes
    and bulk-loads in low single-digit seconds; a /16 flap is one 256-slot
    batch call.

Ordering gives readers a consistent view without any locking: a group is
complete before `TBL24` points at it, and `TBL24` points away before a group
is recycled. Individual 4-byte updates are atomic; during a multi-slot
expansion the table transiently mixes old and new covers — the same
eventual-consistency window every hardware FIB has during churn, and the
LPM trie's per-prefix atomicity does not actually promise anything stronger
end-to-end (a route change is already multiple RPCs).

Update-cost profile, for intuition:

| Change | Slot writes |
|---|---|
| /25–/32 add | ≤ 256 (group fill) + 1 flip; 1 if group exists |
| /24 add (DFZ modal case) | 1 |
| /20 add | 16 |
| /16 add | 256 |
| /8 add | 65,536 (batched) |
| default route | 1 (`DEFAULT4`) |
| full 1M-route feed | ~1.5–2M, batched |

And crucially: **nexthop churn costs zero slot writes.** cradle routes
already indirect through `nexthop_id` (`NEXTHOPS`, `NHGROUP`) — a peer flap
that moves 800k routes to a new nexthop rewrites *one nexthop entry or group
member*, never the big arrays. The indirection that made ECMP clean is what
makes DIR-24-8 maintainable.

## Snapshot semantics — considered, deferred

Per-slot updates mean a multi-slot expansion transiently mixes old and new
covers — the standard eventual-consistency window. The eBPF idiom for
sdplane-style *whole-table snapshots* (zero microloops) exists: an
`ARRAY_OF_MAPS` outer map holding the FIB, where flipping the outer entry is
a RIB-pointer swap. It imports the matching trade — O(N) rebuild per swap and
double memory while both generations live — which is the wrong trade at DFZ
churn rates, so this design stays with O(Δ) in-place updates. (See
[`forwarding-table-updates.md`](forwarding-table-updates.md) for the full
sdplane / VPP / cradle comparison; DIR-24-8's fill-then-flip group ordering
is VPP mtrie's complete-then-publish discipline, and full preallocation is
what deletes mtrie's pool-expansion barrier from cradle's model.)

## What does NOT change

- **`proto/cradle.proto`** — `AddRoute4`/`DelRoute4`/`SetNexthop*` are
  untouched. The engine swap is invisible at the seam.
- **The zebra-rs tee** — `CradleFib` keeps sending the same messages; a DFZ
  feed is just *more* of them. (The tee should batch-friendly-buffer during
  initial convergence, but that is transport tuning, not API.)
- **`FIB6`** — stays an LPM trie. The v6 DFZ is ~200–250k prefixes and 128-bit
  keys cannot be direct-indexed; a 200k-entry trie is affordable. When v6
  scale demands it, the answer is a multibit-stride trie over `Array` maps
  (16-8-8-…-shaped) or a hash fast-path on /48+/64 with LPM fallback —
  Phase 4, sketched only.
- **The overlay designs** — MPLS `POP_L3`, SRv6 `End.DT46`, EVPN Type-5 all
  do "an IP lookup in a table". Per-VRF tables default to LPM tries (VRFs
  are small); a VRF that carries a full feed can get its own DIR instance
  via `ARRAY_OF_MAPS` later. The per-VRF seam should pass a *table handle*,
  not assume a map type — that is the one design constraint this document
  exports to the others.

## Observability

```
STAT_FIB4_TBL24_HIT   // resolved in one lookup
STAT_FIB4_TBL8_HIT    // two-lookup resolution
STAT_FIB4_DEFAULT     // fell through to DEFAULT4
```

plus `cradle ctl fib summary`: engine mode, route count, `TBL8` groups
used/free, last bulk-load duration. The BDD asserts these instead of
inferring behavior from pings alone.

## Testing

Correctness first — the expansion engine is pure logic and gets the heavy
testing where it is cheap:

- **Property tests (userspace, no eBPF):** generate random route sets and
  add/del sequences; after every step, for a sample of addresses, the
  DIR-24-8 tables (simulated as arrays) must resolve identically to a
  reference LPM over the shadow trie. This is the whole correctness argument
  for the expansion engine, run in `cargo test -p cradle`.
- **BDD `cradle_bigfib.feature`:** a forwarder namespace loads a synthetic
  route set (a generator emits ~1M prefixes with DFZ-like length
  distribution via `ctl apply`), then: a ping through a /24 succeeds, a ping
  through a /28-inside-a-/24 takes the tbl8 path (`fib4_tbl8_hit` moves), a
  covered-then-withdrawn prefix falls back to its covering route, and the
  default route works. Ends with the mandatory `Scenario: Teardown topology`.
- **Perf harness (not BDD):** `BPF_PROG_TEST_RUN` on the TC program with the
  table populated at 1k / 100k / 1M routes, LPM vs DIR — the numbers that
  justify the design, kept out of CI gating.

## Phasing

1. **Phase 1 — engine.** Shadow trie + expansion engine + property tests;
   `TBL24`/`TBL8`/`DEFAULT4` maps and packed-word datapath; `--fib4-mode`
   with load-time sizing; counters. LPM remains the default mode.
2. **Phase 2 — scale.** Batch updates, group free-list with lazy recycle,
   bulk initial-load path, the 1M-route BDD + perf harness numbers.
3. **Phase 3 — churn under a real feed.** zebra-rs BGP with a full-table
   injector through the tee; convergence-time measurement; tee batching if
   the RPC path is the bottleneck; `dir24` becomes the documented
   DFZ-deployment default.
4. **Phase 4 — v6 and VRFs.** Multibit-stride v6 design if/when needed;
   per-VRF DIR instances via map-in-map for full-feed VRFs, riding the
   shared per-VRF FIB seam.
