# L4 Load Balancing

A **service** is a virtual IP and port (`VIP:port/proto`) that the datapath load
-balances across a set of backends, with connection tracking so every packet of a
flow lands on the same backend and the return path is reversed correctly.

```json
{
  "services": [
    {
      "vip": "10.0.9.9",
      "port": 8080,
      "proto": "tcp",
      "backends": [
        {"ip": "10.0.2.1", "port": 8080},
        {"ip": "10.0.3.1", "port": 8080}
      ]
    }
  ]
}
```

## Fields

| Field | Type | Default | Meaning |
|---|---|---|---|
| `vip` | string | — | Virtual IP. IPv4 or IPv6 — the family selects the datapath. |
| `port` | number | — | Service port. |
| `proto` | string | `"tcp"` | `tcp` or `udp`. |
| `backends` | array | — | Real endpoints; each has `ip` and `port`. |

Services are assigned a `svc_id` automatically from their order in the list
(first service = 1, second = 2, …); it namespaces that service's backend slots in
the `BACKENDS` map. You do not set it in JSON.

## How a flow is handled

On the first packet of a new flow to `VIP:port`, the datapath picks a backend and
records the choice in the connection-tracking table (`CtKey` → `CtEntry`):

- the forward direction is rewritten toward the chosen backend (**DNAT**), and
- the reverse direction is rewritten back to the VIP (**SNAT**),

so both halves of the connection are consistent for its lifetime. The
`l4_dnat` and `l4_snat` counters track the two directions.

Backend selection starts from a random algorithm, with Maglev-style consistent
hashing as the target for minimal disruption when the backend set changes.

## IPv4 and IPv6

The service model is symmetric across address families: a `vip` that parses as
IPv6 programs the IPv6 service, backend, and conntrack maps (`ServiceKey6`,
`Backend6`, `CtKey6`, `CtEntry6`), which mirror the IPv4 types with 16-byte
addresses. Backends must be the same family as the VIP.

```json
{
  "services": [
    {
      "vip": "2001:db8:9::9",
      "port": 8080,
      "proto": "tcp",
      "backends": [ {"ip": "2001:db8:2::1", "port": 8080} ]
    }
  ]
}
```

## L4 vs L7

An `services` entry load-balances at L4 — it never looks inside the payload, and
DNAT/SNAT keeps the client's connection end-to-end with a backend. When routing
has to depend on the **HTTP request** (path, host), use an L7 service instead,
which terminates the connection in a proxy. See
[L7 HTTP Proxy](ch-01-06-l7-proxy.md).
