# Ports

A **port** is an interface the datapath is attached to. Listing a port both
attaches the `cradle_tc` classifier to that interface's `clsact` ingress hook
and records the port's mode in the `PORTS` map. Nothing forwards on an interface
that is not configured as a port.

```json
{
  "ports": [
    {"name": "fwd1", "l3": true},
    {"name": "fwd2", "l3": true}
  ]
}
```

## Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | string | — | Interface name; resolved to an ifindex at apply time. |
| `l3` | bool | `false` | `true` = routed (L3) port; `false` = L2 bridge member. |
| `vlan` | number | `0` | Access/PVID VLAN for an L2 port (ignored when `l3`). |

The port's MAC is read from the interface itself and used as the source MAC when
the L3 stage forwards a frame *out* of that port. (Over gRPC an explicit MAC may
be supplied; the JSON config always reads it from the kernel.)

## Routed (L3) ports

A port with `"l3": true` participates in L3 forwarding. When it is attached,
cradle reads the interface's addresses from the kernel and **auto-derives** its
routes — for every address `A/p`:

- a host route for `A` (`/32` for IPv4, `/128` for IPv6) flagged `FIB_F_LOCAL`,
  so packets addressed to the router itself are punted to the host stack rather
  than forwarded; and
- a **connected** route for the subnet `A/p`, via a connected next-hop on the
  port, so directly attached hosts are reachable without any manual route.

Because of this, a routed port needs **no** `nexthops`, `routes`, or `neighbors`
entries for its own attached subnets. You only configure `routes` for prefixes
reachable *beyond* the connected subnets — or let a control plane install them
(see [Driving cradle from zebra-rs](ch-02-00-zebra-integration.md)).

Link-local IPv6 (`fe80::/10`) and loopback addresses are skipped when deriving
routes; they do not participate in global forwarding here.

## L2 (bridge) ports

A port with `l3` unset (or `false`) is an L2 bridge member in the VLAN given by
`vlan`. cradle groups all non-L3 ports by their `vlan` into L2 **domains** — the
set of ports a broadcast, unknown-unicast, or multicast frame is flooded to.
See [L2 Switching](ch-01-03-l2-switching.md).

```json
{
  "ports": [
    {"name": "sw1", "vlan": 0},
    {"name": "sw2", "vlan": 0},
    {"name": "sw3", "vlan": 0}
  ]
}
```

The three ports above form one flood domain in VLAN 0.

## LAG (bond) ports

A kernel bond can be a port like any other — name it, and cradle attaches to
the bond. This is how a multihomed Ethernet Segment is wired: the CE bundles
its links to two PEs with LACP, and each PE's leg of that LAG is a one-member
802.3ad bond carrying the **same** `ad_actor_system` (and `ad_user_port_key`)
on both PEs, so the CE sees one partner:

```sh
ip link add bond0 type bond mode 802.3ad ad_actor_system 02:00:00:00:aa:01 ad_user_port_key 7
ip link set eth1 master bond0
```

```json
{ "ports": [ {"name": "bond0", "vlan": 100} ] }
```

Under the hood cradle aliases the bond's members to it for the XDP stage
(which runs on the members) and hands link-local control frames —
`01:80:c2:00:00:0x`, so LACPDUs, STP, LLDP — to the host rather than the
bridge domain, which is what keeps the aggregation up. Membership is
tracked live: enslave or release a link (or replace a member with a new
device) after the port is attached and cradle re-aliases it on its own —
no `SetPort` needed. Supported bond modes are those the kernel supports XDP
on: balance-xor, 802.3ad and active-backup.
