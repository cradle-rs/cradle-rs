# ECMP / Multipath

Equal-cost multipath spreads traffic for one prefix across several next-hops. In
cradle a **nexthop group** is an ordered set of member next-hop ids; a route
whose FIB entry carries the `FIB_F_ECMP` flag treats its `nexthop_id` as a
*group* id rather than a single next-hop. The datapath hashes each flow to a
member, so a flow always follows one path while the aggregate is balanced.

## Where ECMP comes from

ECMP is a property of the FIB entry and the nexthop-group maps, programmed
through the gRPC control API (`SetNexthopGroup` plus a route with the ECMP flag).
In practice this is driven by a routing control plane that computed multiple
equal-cost paths — for example zebra-rs resolving several BGP or IS-IS next-hops
for a prefix and installing them as a group. See
[Driving cradle from zebra-rs](ch-02-00-zebra-integration.md).

## Data-plane behaviour

- A nexthop group is stored as members keyed by `(group_id, slot)` with a dense
  slot index `0..count`; the member count lives in a companion per-group map.
- A route pointing at the group has `FIB_F_ECMP` set and `nexthop_id = group_id`.
- On lookup, the datapath hashes the flow (its 5-tuple) to choose a member slot,
  resolves that member next-hop, and forwards as usual with
  `bpf_redirect_neigh`.

Because the selection is a hash of the flow, all packets of a connection pin to
the same member — no per-packet reordering — while different flows fan out across
the group. ECMP is supported for both IPv4 and IPv6, and is exercised by the
`cradle_ecmp` and `cradle_ecmpv6` BDD features.
