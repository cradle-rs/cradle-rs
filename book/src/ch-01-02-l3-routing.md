# L3 Routing

L3 forwarding is a longest-prefix-match lookup in the FIB (an LPM trie), which
yields a **next-hop id**; the next-hop names an output interface and, for
off-link destinations, a gateway. The datapath rewrites the frame and hands it to
`bpf_redirect_neigh`, which lets the kernel resolve the destination MAC.

For directly attached subnets you configure nothing — routed ports auto-derive
their connected and local routes (see [Ports](ch-01-01-ports.md)). This chapter
covers **static** routes to remote prefixes, which are three related objects:
`nexthops`, `routes`, and (optionally) `neighbors`.

## Next-hops

A next-hop is a reusable forwarding target — a gateway reachable out of an
interface. Routes reference it by `id`.

```json
{
  "nexthops": [
    {"id": 1, "oif": "fwd2", "gateway": "10.0.2.254"}
  ]
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `id` | number | — | Identifier a route points at. |
| `oif` | string | — | Output interface name. |
| `gateway` | string | none | Gateway IP; omit for an on-link / connected next-hop. |

Omitting `gateway` makes the next-hop **on-link**: the destination address is
resolved directly as the neighbor, which is how the auto-derived connected routes
work.

## Routes

A route binds a destination prefix to a next-hop id.

```json
{
  "routes": [
    {"prefix": "10.9.9.0/24", "nexthop": 1}
  ]
}
```

| Field | Type | Meaning |
|---|---|---|
| `prefix` | string | Destination as `a.b.c.d/len`. |
| `nexthop` | number | A next-hop `id` defined in `nexthops`. |

The JSON `routes` field installs **IPv4** static routes. IPv6 forwarding is fully
supported in the data plane, but IPv6 routes are programmed through the gRPC API
(and thus by the zebra-rs tee), not through this JSON field — see
[Driving cradle from zebra-rs](ch-02-00-zebra-integration.md).

## Neighbors

`neighbors` installs a **static** IPv4 neighbor: the MAC to use for a given IP on
a given output interface.

```json
{
  "neighbors": [
    {"oif": "fwd2", "ip": "10.0.2.1", "mac": "02:00:00:00:00:01"}
  ]
}
```

You rarely need this. Because the datapath forwards with `bpf_redirect_neigh`,
the kernel's own neighbor table resolves connected next-hops, so a static entry
is only for cases where you want to pin resolution rather than rely on the kernel.

## Putting it together

A forwarder with two routed ports and a static route to a remote `/24` reachable
via a gateway on `fwd2`:

```json
{
  "ports":    [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ],
  "nexthops": [ {"id":1, "oif":"fwd2", "gateway":"10.0.2.254"} ],
  "routes":   [ {"prefix":"10.9.9.0/24", "nexthop":1} ]
}
```

With kernel IP forwarding *disabled* on the box, traffic that still crosses it
was forwarded by the eBPF data plane — which is exactly how the BDD L3 test
proves the datapath is doing the work.
