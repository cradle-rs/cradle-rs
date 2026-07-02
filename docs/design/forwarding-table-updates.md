# Forwarding-table update mechanics — sdplane / VPP / cradle eBPF

> How three software data planes update their forwarding tables while packets
> keep flowing — and where cradle's kernel-eBPF model sits on that spectrum.

Status: **comparative analysis**, not a proposal. Companion to
[`large-fib.md`](large-fib.md) (which designs cradle's DIR-24-8 IPv4 FIB) and
[`architecture.md`](architecture.md). Source for the sdplane and VPP columns:

> Y. Ohara, T. Tanabe, T. Umeda, K. Sebayashi, M. Maruyama,
> *"sdplane: An SRv6-enabled DPDK Software Router Reference Implementation"*,
> IEICE Technical Report, 2026 — including its source-level analysis of VPP's
> `ip4_mtrie` and `bihash` (FD.io VPP, `src/vnet/fib/`, `src/vppinfra/`).

## The three prior models, condensed

**sdplane — RIB pointer swap under userspace RCU.** Run-to-completion workers
(one per lcore) read a shared RIB pointer through QSBR RCU
(`rcu_dereference`, liburcu-qsbr). An update never touches the live table:
`rib-manager` builds a **complete new RIB**, atomically swaps the pointer,
waits for the grace period, frees the old one. Workers are never stopped,
spun, or barriered — and never observe an intermediate state (no microloops:
readers see whole-table snapshots). The cost lands on the control plane:
every update is an **O(N-total)** rebuild plus a grace period, and memory
transiently holds two RIBs. The paper notes this is a choice of the current
`rib-manager`, not inherent to RCU — differential updates could keep the
worker non-interference property. The FIB itself is a deliberately naive
2-bit-stride trie (≤16 levels for v4, ≤64 for v6); RCU decouples reader
safety from the structure, so a faster structure (radix, poptrie, hash) can
be swapped in without designing any concurrency.

**VPP IPv4 — `ip4_mtrie` (16-8-8), concurrency baked into the structure.**
Leaves are 32-bit words (terminal = load-balance index, else next-ply pool
index); lookup is ≤3 dependent array derefs; each slot holds the most
specific covering route so LPM holds per-slot. Updates: leaf rewrites are
atomic release-stores; new subtrees are **built completely, then published**
with one atomic store to the parent leaf; deletes atomically restore the
covering route and return plys to a freelist. The one hole: plys live in a
global pool (`ip4_ply_pool`), and **pool expansion may realloc/move the whole
node array** — a walking reader would be stranded — so VPP stops *all*
workers with `vlib_worker_thread_barrier_sync` for that case. It is bounded
(only during growth beyond the historical high-water mark; freed plys are
reused; the pool never shrinks or moves otherwise), but under a growing full
feed it fires intermittently and shows up as Rx-ring loss/latency.

**VPP IPv6 — `bihash`, per-bucket optimistic concurrency.** LPM is not a tree
walk: the real prefix lengths present in the table are probed longest-first,
one masked-key hash each (3 chained CRC32C per probe). Updates lock a single
bucket bit, mutate or split that bucket in fresh memory, and atomically swap
the 64-bit bucket descriptor; readers are lock-free with a seqlock-style
generation re-check (a colliding reader spins briefly or retries once).
**Never barriers** — but lookup cost is O(P) in the number of real prefix
lengths (an IPv6 DFZ has ~40), and a no-match destination probes all of them.

## The chart

"cradle today" = `FIB4`/`FIB6` LPM tries + hash maps as implemented;
"cradle DIR-24-8" = the planned IPv4 engine of [`large-fib.md`](large-fib.md).

| Aspect | sdplane (RIB+RCU) | VPP v4 (mtrie) | VPP v6 (bihash) | cradle today (eBPF LPM/hash) | cradle DIR-24-8 (planned) |
|---|---|---|---|---|---|
| Reader context | userspace lcore workers, polling | userspace graph workers, polling | same | kernel TC/XDP hooks, NAPI softirq, per-packet run-to-completion | same |
| Structure (v4) | 2-bit-stride trie (≤16 levels) | 16-8-8 mtrie (≤3 array derefs) | — | kernel `LPM_TRIE` (≤32 node visits) | `TBL24`+`TBL8` arrays (1–2 derefs) |
| Structure (v6) | same trie (≤64 levels) | — | hash probe per real prefix length, O(P) | kernel `LPM_TRIE` (≤128 visits) | stays LPM (v6 table is small) |
| Reader protection | userspace RCU (QSBR) | atomic leaf loads | lock-free + seqlock re-check; short spin on colliding bucket | **kernel RCU**, implicit under every BPF program run | plain array loads |
| Single-route update | build new RIB → pointer swap | atomic leaf store; subtrees complete-then-publish | per-bucket lock + atomic descriptor swap | one `bpf(2)` element op; LPM node RCU-replaced under a **global writer spinlock** | 1 slot write (/24); word-atomic slot range for shorter prefixes |
| Update cost per route | **O(N)** + grace period (implementation choice) | O(affected slots) | O(1) bucket op | O(1) element; writers serialize on the trie lock | O(2^(24−len)) batched writes; nexthop churn = **1 write** (id indirection) |
| Short-prefix handling | trie — no expansion | expanded into covering slots | none — one probe per length | trie — no expansion | expanded; default route held out in `DEFAULT4` |
| Capacity growth | new RIB every update anyway | ply-pool realloc ⇒ **all-worker barrier** | per-bucket split only | LPM is NO_PREALLOC: per-node alloc, pointer-linked, never relocates | fully preallocated at load; no growth path (resize = reload) |
| All-workers stop? | never | **only on pool expansion** | never | never | never |
| Memory reclamation | free old RIB after grace period | freelist; pool never shrinks | freelist | kernel RCU-deferred free (LPM); prealloc hash recycles via freelist immediately (documented reuse caveat) | in-place words; `TBL8` groups lazily recycled |
| Consistency granularity | **whole-table snapshot** — no intermediate states, no microloops | per-leaf atomic; multi-route changes show intermediates | per-bucket | per-element atomic; route↔nexthop cross-map is eventual, with write ordering | per-word atomic; groups fill-then-flip; range expansion transiently mixes covers |
| Full-feed churn (BGP storm) | control plane degrades: O(N)/update, grace/update, 2× memory | good (O(Δ)); intermittent barriers while growing to high-water | good (O(Δ)) | syscall per route (batchable); the trie writer lock is the serialization point | batch syscalls; ~1M-route load in low seconds; no lock, no barrier |
| Concurrency control lives… | in a **separate mechanism** (RCU), structure-independent | **inside the structure** (publish discipline + barrier) | inside the structure (bucket lock + seqlock) | **delegated to the kernel** — each map type ships verified semantics; datapath *and* control plane stay concurrency-oblivious | same, plus a userspace ordering discipline (fill-then-flip) |
| Algorithm swap freedom | highest — any C structure behind the pointer | costly — re-implement concurrency, DPO/graph integration | costly | limited to the kernel map menu — or **compositions over it**; program swap is atomic at the hook | DIR-24-8 *is* such a composition (arrays + index math) |
| Entry field extensibility | plain C structs, free under snapshot semantics | packed words, static asserts; additions ripple | fixed 24B/8B key/value | `#[repr(C)]` shared crate: compile-time agreement; live layout change = new maps + atomic program replace | packed u32 word is deliberate (torn-read avoidance) |
| Control-plane linkage | Linux netlink/TAP, RIB in-process | binary API / linux-cp | same | zebra-rs RIB → gRPC tee → `bpf(2)` per element (O(Δ) diffs, never rebuilds) | same + userspace shadow trie driving expansion |

## Where cradle sits on the spectrum

The paper's central observation is that sdplane and VPP differ in *where
concurrency control lives*: **inside the forwarding structure** (VPP — publish
disciplines, bucket locks, and the barrier as the escape hatch) versus
**separated into an independent mechanism** (sdplane — RCU makes reader safety
a property of the *pointer*, not the structure, buying algorithm-swap
freedom).

cradle is a genuine third position: **concurrency control delegated to the
kernel.** Every eBPF map type ships with verified reader/writer semantics
(BPF programs always run under RCU; element updates are atomic at element
granularity), so neither the datapath nor the control plane implements any
concurrency at all. The price is the inverse of sdplane's freedom: the
structure menu is fixed by the kernel — until you *compose* map types, which
is exactly what DIR-24-8 does (index arithmetic over `Array` maps, with the
one concurrency rule cradle must supply — fill-then-flip ordering — enforced
by the userspace expansion engine, not by the datapath).

Three resonances between the paper's findings and cradle's designs:

1. **DIR-24-8's fill-then-flip is mtrie's complete-then-publish.**
   [`large-fib.md`](large-fib.md) independently arrived at VPP's subtree
   discipline — populate a `TBL8` group fully, then atomically flip the
   `TBL24` word to point at it; flip away before recycling. Same invariant
   ("readers see the old cover or the finished new node, never a
   half-built one"), expressed at the map-ABI level.
2. **Full preallocation deletes mtrie's one stop-the-world case.** VPP
   barriers because its node pool *relocates* on growth. eBPF `Array` maps
   never relocate, and the kernel LPM trie is pointer-linked per node — the
   all-worker-stop case structurally cannot exist in cradle. The trade is
   capacity fixed at load time (`--fib4-mode` sizing), i.e. cradle buys
   VPP's lookup shape without its growth barrier by refusing to grow.
3. **sdplane's whole-table snapshot is the one property nobody else has.**
   Zero microloops, by construction. cradle's consistency is per-element /
   per-word with ordering discipline — the same eventual-consistency window
   as VPP and every hardware FIB. If snapshot semantics are ever wanted, the
   eBPF idiom exists: **map-in-map** (`ARRAY_OF_MAPS` outer map holding the
   FIB), where flipping the outer entry is precisely sdplane's RIB pointer
   swap — and it would import precisely sdplane's trade: O(N) rebuild per
   swap, double memory while both generations live. Noted as an option in
   [`large-fib.md`](large-fib.md); not proposed, because route churn at DFZ
   scale wants O(Δ).

Two honest asymmetries to keep in mind when reading the chart:

- **Reader placement.** sdplane and VPP burn dedicated polling cores for
  deterministic latency; cradle's readers run in kernel softirq on whatever
  CPU NAPI lands on — no reserved cores, no busy-poll tax, but also none of
  the latency isolation. That difference is orthogonal to update mechanics
  but colors every "never stops the workers" cell: cradle has no workers *to*
  stop.
- **The writer bottleneck moved, not vanished.** sdplane pays O(N) rebuilds;
  VPP pays occasional barriers; cradle today pays a per-trie writer spinlock
  (the kernel serializes `LPM_TRIE` updates), which is the convergence-time
  ceiling [`large-fib.md`](large-fib.md) exists to remove — DIR-24-8's writer
  path is lock-free word stores, leaving batch-syscall throughput as the only
  writer-side limit.
