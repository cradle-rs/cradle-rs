# L7 HTTP Proxy

An **L7 service** steers TCP flows destined to an HTTP VIP into a user-space
transparent proxy, which terminates the connection, reads the request, and routes
to a backend **by HTTP path**. This is how cradle makes forwarding depend on L7
content without putting an HTTP parser in the kernel.

```json
{
  "l7_services": [
    {
      "vip": "10.0.9.9",
      "port": 80,
      "routes": [
        {"prefix": "/a", "backend": "10.0.2.1:8080"},
        {"prefix": "/b", "backend": "10.0.3.1:8080"},
        {"prefix": "/",  "backend": "10.0.2.1:8080"}
      ]
    }
  ]
}
```

## Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `vip` | string | — | HTTP virtual IP (IPv4). |
| `port` | number | — | Service port. |
| `routes` | array | — | Ordered path-prefix rules. |
| `routes[].prefix` | string | `"/"` | HTTP path prefix to match. |
| `routes[].backend` | string | — | Target as `ip:port`. |

A request is routed to the backend of the **longest matching path prefix**; if
none match, the first route acts as the fallback (so a `"/"` route catches
everything). In the example, `GET /a…` → `10.0.2.1:8080`, `GET /b…` →
`10.0.3.1:8080`, and anything else → `10.0.2.1:8080`.

## How the steering works

The mechanism is `bpf_sk_assign`-based TPROXY:

1. The datapath marks the L7 VIP:port as an L7 service. A matching TCP flow is
   looked up against the local proxy socket and **assigned** to it with
   `bpf_sk_assign` in the TC ingress hook, incrementing the `l7_redirect`
   counter.
2. The proxy binds `IP_TRANSPARENT` on `0.0.0.0:18000`, so an accepted
   connection's *local* address is the **original VIP:port** the client
   targeted. The proxy reads that with `local_addr()`, picks the backend by path,
   connects, forwards the request head, and splices the two connections.

### The `local` route — installed for you

There is a subtlety in `bpf_sk_assign` TPROXY: assigning the socket sets
`skb->sk`, but the kernel still runs a routing lookup afterward. Without a
matching route the non-local VIP is classified for **forwarding** and dropped.
The fix is a `local <vip>/32 dev lo` route, which makes the lookup return
`RTN_LOCAL` and deliver the packet to the assigned socket.

cradle installs this route **itself** when an L7 service is configured
(equivalent to `ip route replace local <vip>/32 dev lo`, run in cradle's network
namespace). You do not add it by hand. It is best-effort: if the route cannot be
installed, cradle logs a warning rather than failing service configuration, since
L7 simply will not deliver until the route exists.

Note that TPROXY delivery also requires the usual host prerequisites in the
forwarding namespace: reverse-path filtering must not drop the redirected packet,
and (in the test topology) kernel IP forwarding is deliberately off to prove the
datapath, not the kernel, moved the traffic. Those are host/topology policy and
are left to the operator; only the service-specific VIP route is cradle's to
install.

## Scope

The L7 proxy currently handles IPv4 HTTP and routes on the request path (with the
`Host` header parsed and logged). Backend health checking, richer load-balancing,
header rewriting, and IPv6 are natural follow-ups. The end-to-end path is
exercised by the `cradle_l7` BDD feature.
