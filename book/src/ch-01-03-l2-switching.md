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
through `cradle stats` — see
[Observability and Counters](ch-03-01-observability.md).

## EVPN multihoming: the non-DF filter

When a CE is attached to two PEs over one Ethernet Segment (EVPN
multihoming, RFC 7432), both PEs receive every BUM frame from the overlay
but only the elected **Designated Forwarder** may deliver it to the CE —
otherwise the CE sees one copy per PE. cradle enforces that in the flood
loop. Declare the segment's local ports and, per bridge domain, whether this
PE won the election:

```json
{
  "ethernet_segments": [
    { "esi": "00:00:00:00:00:00:00:00:00:01",
      "ports": ["pe3c"],
      "roles": [ { "bd": 100, "df": false } ] }
  ]
}
```

A `"df": false` role withholds broadcast, multicast and unknown-unicast
copies from the segment's ports in that domain (counted as
`l2_drop_nondf`); known unicast still flows, as all-active multihoming
requires. Over gRPC the same two facts are `SetEthernetSegment` and
`SetEsRole`, which is how a control plane replays a DF re-election. Ports
outside any segment are unaffected.

The second half of multihoming is the **split horizon** (local bias): a
BUM frame the CE sends into one PE is flooded to the other PE too, which
must not send it back onto the same segment. Name the segment's other PEs
by their VTEP / overlay source address:

```json
    { "esi": "00:00:00:00:00:00:00:00:00:01",
      "ports": ["pe3c"],
      "roles": [ { "bd": 100, "df": true } ],
      "peers": ["192.0.2.2"] }
```

An overlay frame whose source is one of `peers` is then never flooded to
`ports`, even on the DF (counted as `l2_drop_sph`). Over gRPC this is
`SetEsPeers` (replace semantics; an empty list clears it). It applies to
VXLAN and SRv6 overlays — MPLS frames carry no source address.

The remote side of multihoming is **aliasing**: a MAC learned behind a
segment may be sent to any PE on it. Give the segment a nexthop group per
bridge domain and point the MAC at the segment instead of at one VTEP:

```json
{
  "ethernet_segments": [
    { "esi": "00:00:00:00:00:00:00:00:00:01",
      "nhg": [ { "bd": 100,
                 "members": [ { "remote_vtep": "192.0.2.2" },
                              { "remote_vtep": "192.0.2.3" } ] } ] }
  ],
  "fdb": [
    { "mac": "02:00:00:00:ce:02", "bd": 100,
      "esi": "00:00:00:00:00:00:00:00:00:01" }
  ]
}
```

Each flow to that MAC hashes onto one member (`l2_es_nhg`); replacing the
member list — `SetEsNhg` over gRPC — moves every MAC behind the segment at
once, which is how a PE leaving the segment (a mass withdraw) takes effect.
Members may equally be SRv6 `remote_sid`s or MPLS `remote_pe` + `label`.
A PE that is itself on the segment reaches such a MAC over its own port:
`{ "mac": …, "bd": 100, "port": "pe3c" }` installs a static local entry
(`AddFdbLocal`), which is never aged or reported as a learn.

## Mixing L2 and L3

A single cradle instance can carry both routed and bridged ports at once: mark
the routed ones `"l3": true` and leave the bridge members with a shared `vlan`.
Frames on bridge ports are switched within their domain; frames destined to the
router's own MAC are punted to L3, where the routing FIB takes over.
