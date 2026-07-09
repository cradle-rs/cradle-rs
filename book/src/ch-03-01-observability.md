# Observability and Counters

The datapath maintains a set of **per-CPU packet counters**, one at each
forwarding decision point, so you can see what the eBPF program actually did with
traffic. They are read over the gRPC `GetStats` RPC and printed by `cradle
stats`.

```sh
$ cradle stats
l2_forward     0
l2_flood       0
l3v4_forward   128
l3v6_forward   0
l3_local       4
l4_dnat        0
l4_snat        0
drop           0
l7_redirect    10
policy_drop    2
policy_audit   0
masq           0
```

## The counters

| Counter | Incremented when… |
|---|---|
| `l2_forward` | A frame is switched to a known unicast FDB entry. |
| `l2_flood` | A BUM/unknown-unicast frame is flooded to a VLAN domain. |
| `l3v4_forward` | An IPv4 packet is forwarded via the FIB. |
| `l3v6_forward` | An IPv6 packet is forwarded via the FIB. |
| `l3_local` | A packet addressed to the router itself is punted to the host stack. |
| `l4_dnat` | A service packet is DNAT'd toward its chosen backend. |
| `l4_snat` | A return packet is SNAT'd back to the VIP. |
| `drop` | A packet is dropped by the datapath. |
| `l7_redirect` | A TCP flow is assigned to the L7 proxy via `bpf_sk_assign`. |
| `policy_drop` | A packet is dropped by [network policy](ch-05-03-network-policy.md) (ingress or egress). |
| `policy_audit` | A policy verdict that would drop, but the endpoint is in audit mode (forwarded). |
| `masq` | A pod-egress flow to outside the cluster is SNAT'd to the node IP. |

## How they are stored and read

The counters live in a `PerCpuArray` indexed by the `STAT_*` constants in
`cradle-common`, so each CPU bumps its own slot with no cross-CPU contention on
the hot path. User space reads every CPU's copy and **sums** them, so the value
you see is the aggregate across cores. The names are attached in the `cradle`
crate (`STAT_NAMES`), in the same index order as the shared constants — the two
must stay in sync, which is why they live one lookup apart.

These counters are the primary way the BDD suite confirms *which layer* handled
traffic — for example the `cradle_stats` feature asserts `l3v4_forward` is
nonzero after an L3 ping, and `cradle_l7` asserts `l7_redirect` is nonzero after
a proxied request. See [BDD Integration Tests](ch-04-00-bdd-tests.md).

## Dumping the forwarding tables

Counters tell you *how many* packets each layer handled; `cradle dump` shows the
table **entries** behind those decisions. It streams one forwarding table back
over the `Dump` RPC and prints it in aligned columns:

```sh
$ cradle dump ipv4
prefix                vrf   nh_id flags      nexthop
10.9.9.0/24             0       1 -          via 10.0.2.1 dev if7
0.0.0.0/0               0       2 -          via 10.0.1.1 dev if6
```

The positional argument selects the table — `l2` (bridge FDB), `ipv4` / `ipv6`
(the FIB, with `--vrf <id>` for a non-global table), `mpls` (the ILM), or `srv6`
(local SIDs plus transit encaps). By default each `nexthop_id` is resolved
against the `NEXTHOPS` map into `via <gateway> dev if<oif> [labels …]`;
`--no-resolve` prints the raw id. See
[Command Line Options](ch-00-03-command-line-options.md) for the full option
list, and the `cradle_dump` BDD feature for an end-to-end example.

### MPLS: why an ILM entry reads `swap` or `pop`

The `op` column of `dump mpls` reports the **effective** operation, matching
`zebra sh mpls ilm`. This needs a word of explanation, because cradle stores
fewer opcodes than zebra prints.

zebra-rs encodes penultimate- and ultimate-hop pops — SR adjacency SIDs, and
prefix SIDs doing PHP — not as a distinct "pop" opcode but as a **swap whose
nexthop carries an empty out-label stack** (`num_labels == 0`). The datapath
pops based on that empty stack (and the incoming S bit), not on the opcode: a
`SWAP` with no out-label and a real `POP` take the same `pop_and_forward` path.
A genuine transit swap is the same `SWAP` opcode but with a real out-label.

So the raw stored opcode alone can't distinguish a PHP pop from a transit swap.
`dump mpls` therefore resolves each entry's nexthop and reports the effective op:

- `SWAP` with an **empty** out-label stack → `pop`
- `SWAP` carrying a real out-label → `swap`
- explicit `POP` / `POP_L3` → `pop` / `pop_l3`

The result lines up with `zebra sh mpls ilm`: an SR adjacency SID or PHP prefix
SID shows `pop`, while a transit LSP that keeps a label shows `swap`. Add
`--no-resolve` to see the underlying encoding — the `pop` entries have a nexthop
with no labels, the `swap` entries carry the out-label in the resolved output.
