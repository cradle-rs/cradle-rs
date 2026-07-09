# Observability and Counters

The datapath maintains a set of **per-CPU packet counters**, one at each
forwarding decision point, so you can see what the eBPF program actually did with
traffic. They are read over the gRPC `GetStats` RPC and printed by `cradle ctl
stats`.

```sh
$ cradle ctl stats
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
