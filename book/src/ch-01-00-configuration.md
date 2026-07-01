# Configuration Model

cradle-rs is configured with a single **JSON** document. The same document is
used two ways:

- as a **bootstrap** applied in-process at startup (`cradle serve --config`), and
- as the payload of **`cradle ctl apply`**, replayed over the gRPC control API.

Both paths run the identical set of control-plane operations, so a config that
works as a bootstrap works verbatim over `ctl apply`, and vice versa.

Configuration is **additive and declarative at the level of individual objects**:
applying a config installs the ports, routes, services, and L7 services it names.
It maps directly onto the control-plane operations rather than onto a YANG tree —
cradle is the *data plane*; the routing policy and best-path selection live in
the control plane (zebra-rs) above it.

## Top-level shape

```json
{
  "ports":        [ ... ],
  "nexthops":     [ ... ],
  "routes":       [ ... ],
  "neighbors":    [ ... ],
  "services":     [ ... ],
  "l7_services":  [ ... ]
}
```

Every field is optional and defaults to empty. A minimal L3 forwarder is just a
list of routed ports:

```json
{ "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ] }
```

| Field | Layer | What it configures | Chapter |
|---|---|---|---|
| `ports` | L2/L3 | Interfaces to attach the datapath to, and their mode. | [Ports](ch-01-01-ports.md) |
| `nexthops` | L3 | Next-hop objects (gateway + output interface) referenced by routes. | [L3 Routing](ch-01-02-l3-routing.md) |
| `routes` | L3 | IPv4 static routes into the eBPF FIB. | [L3 Routing](ch-01-02-l3-routing.md) |
| `neighbors` | L3 | Static IPv4 neighbor (MAC) entries. | [L3 Routing](ch-01-02-l3-routing.md) |
| `services` | L4 | VIP:port → backend load-balancing services (v4/v6). | [L4 Load Balancing](ch-01-04-l4-load-balancing.md) |
| `l7_services` | L7 | HTTP VIPs steered to the transparent proxy, routed by path. | [L7 HTTP Proxy](ch-01-06-l7-proxy.md) |

## What is derived automatically

You configure less than you might expect, because a **routed (L3) port
auto-derives its connected and local routes** from the kernel's interface
addresses when it is attached. For each address `A/p` on the port, cradle
installs a host `FIB_F_LOCAL` route for `A` (so traffic to the router itself is
punted to the host stack) and a connected route for the subnet `A/p`. You
therefore do not hand-configure connected routes or neighbors for directly
attached subnets — only *remote* prefixes need a `routes` entry (or a control
plane feeding them in). See [Ports](ch-01-01-ports.md).

## Where the format is defined

The schema is the `Config` struct in `crates/cradle/src/config.rs`; the gRPC
replay is in `crates/cradle/src/ctl.rs`. The remaining chapters in this section
document each field with a worked example drawn from the BDD test configs under
`bdd/tests/configs/`.
