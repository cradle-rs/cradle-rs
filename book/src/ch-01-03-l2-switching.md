# L2 Switching

Ports configured **without** `l3` are L2 bridge members. The datapath switches
frames between them using a forwarding database (FDB) and floods
broadcast/unknown-unicast/multicast (BUM) frames within a VLAN domain.

## Flood domains from ports

You do not configure L2 domains directly. cradle builds them by grouping all
non-L3 ports by their `vlan`: every port sharing a `vlan` is a member of that
domain and receives flooded frames for it.

```json
{
  "ports": [
    {"name": "sw1", "vlan": 0},
    {"name": "sw2", "vlan": 0},
    {"name": "sw3", "vlan": 0}
  ]
}
```

Here `sw1`, `sw2`, and `sw3` form one flood domain in VLAN 0. A frame arriving on
`sw1` whose destination MAC is unknown (or is broadcast/multicast) is flooded out
`sw2` and `sw3`; once the destination replies, its MAC is learned and subsequent
frames are unicast to the single correct port.

## How forwarding works

- **Known unicast** — a hit in the FDB (`FdbKey` = destination MAC + VLAN) gives
  the output port; the frame is redirected there.
- **Local** — a destination MAC that is one of the router's own is flagged
  `FDB_F_LOCAL` and punted up to L3 / the host stack.
- **BUM / unknown** — flooded to every other member port of the VLAN domain, the
  members being enumerated from the per-VLAN membership map.

The `l2_forward` and `l2_flood` counters record these two paths and are visible
through `cradle ctl stats` — see
[Observability and Counters](ch-03-01-observability.md).

## Mixing L2 and L3

A single cradle instance can carry both routed and bridged ports at once: mark
the routed ones `"l3": true` and leave the bridge members with a shared `vlan`.
Frames on bridge ports are switched within their domain; frames destined to the
router's own MAC are punted to L3, where the routing FIB takes over.
