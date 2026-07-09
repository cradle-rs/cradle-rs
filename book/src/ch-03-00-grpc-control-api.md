# The gRPC Control API

Everything the data plane can do is exposed as a gRPC service, `cradle.v1.Cradle`
(defined in `proto/cradle.proto`). This is the single seam driven by three
callers: the in-process bootstrap (`serve --config`), the `cradle ctl` client,
and the zebra-rs `FibHandle` tee. The method surface deliberately mirrors a
routing FIB's operations.

## Endpoint addressing

An endpoint is written in one of four forms, understood identically by server
(`serve --grpc`) and client (`ctl --grpc`, and the zebra-rs
`system cradle grpc-endpoint` leaf). Both sides default to `unix:cradle/grpc`:

- `unix:NAME` — a Linux **abstract** socket (no leading `/`), scoped to the
  network namespace. The default `unix:cradle/grpc` is this form; it needs no
  filesystem path and is unique per netns.
- `unix:/path/to.sock` — a filesystem unix-domain socket (a stale socket file is
  cleared on bind).
- `tcp:HOST:PORT` — a TCP endpoint.
- a bare `HOST:PORT` — treated as TCP.

## Methods

| RPC | Layer | Purpose |
|---|---|---|
| `SetPort` | L2/L3 | Attach the datapath to an interface and set its mode. |
| `SetL2Domain` | L2 | Define a VLAN flood domain's member ports. |
| `SetNexthop` | L3 | Create/update a next-hop (IPv4 or IPv6). |
| `SetNexthopGroup` | L3 | Define an ECMP nexthop group's members. |
| `AddRoute4` / `DelRoute4` | L3 | Install/remove an IPv4 FIB route. |
| `AddRoute6` / `DelRoute6` | L3 | Install/remove an IPv6 FIB route. |
| `SetNeighbor4` | L3 | Install a static IPv4 neighbor (MAC). |
| `AddService` | L4 | Add a VIP:port load-balancing service (v4/v6). |
| `AddL7Service` | L7 | Add an HTTP VIP with path-prefix routes. |
| `GetStats` | ops | Read the datapath packet counters. |
| `Dump` | ops | Stream a forwarding table's entries (L2/IPv4/IPv6/MPLS/SRv6). |

Routes carry a `flags` field (`FIB_F_*`) — for example `FIB_F_ECMP` to mark the
`nexthop_id` as a group id. Nexthops carry a `v6` flag and can be addressed by
`oif_index` directly (which is how zebra-rs, already working in ifindex space,
drives them) or by interface name.

## `cradle ctl`

`ctl` is a thin client over this API. `ctl apply FILE` loads the JSON config and
issues the corresponding RPCs in order — ports, L2 domains, nexthops, neighbors,
routes, services, and L7 services — so it produces exactly the same data-plane
state as an in-process bootstrap of the same file. `ctl stats` calls `GetStats`
and prints the result.

```sh
cradle ctl apply services.json
cradle ctl stats
```

The read side of the API is also exposed by the top-level `cradle dump`
command, which calls the server-streaming `Dump` RPC to print a forwarding
table's entries — see [Command Line Options](ch-00-03-command-line-options.md)
and [Observability and Counters](ch-03-01-observability.md).

The JSON schema `ctl apply` consumes is the one documented in
[Configuration Model](ch-01-00-configuration.md). Fields not expressible in that
schema (IPv6 routes, ECMP groups) are reached by driving the RPCs directly — in
practice, from the zebra-rs tee described in
[Driving cradle from zebra-rs](ch-02-00-zebra-integration.md).
