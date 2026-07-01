# Driving cradle from zebra-rs

The reason cradle-rs exists is to have a **real routing stack** program the eBPF
data plane — learned routes, not just advertised ones. That stack is
[zebra-rs](https://github.com/zebra-rs/zebra-rs), and the coupling is at
zebra-rs's single data-plane chokepoint: **`FibHandle`**.

## The tee

zebra-rs selects a `FibHandle` backend at compile time. For cradle integration
its backend **tees** every FIB operation — route add/del, nexthop sync, neighbor
updates — to cradle over the gRPC control API, in addition to (or instead of)
the kernel FIB. So when BGP, OSPF, IS-IS, or a static route wins best-path in the
zebra-rs RIB, the resulting route is installed straight into the eBPF FIB.

```
 zebra-rs RIB  ──best-path──▶  FibHandle  ──gRPC──▶  cradle  ──▶  eBPF FIB
```

Because the seam is `FibHandle`, cradle inherits the full breadth of the control
plane for free: multipath becomes ECMP nexthop groups in cradle, connected routes
and neighbors flow through the same API, and there is nothing protocol-specific in
cradle itself.

## Turning it on: the `cradle-grpc` leaf

The tee is enabled by a single YANG config leaf in zebra-rs,
`system cradle-grpc`, whose value is the gRPC endpoint of a running cradle:

```yaml
system:
  cradle-grpc: "unix:/run/cradle.sock"
```

With that leaf set, zebra-rs connects to cradle at the given endpoint (same
`unix:` / `tcp:` address forms as everywhere else) and begins teeing FIB
operations to it. Unset the leaf and zebra-rs behaves as it always did — the tee
is entirely opt-in, gated by configuration rather than a build flag.

## End-to-end example

The `cradle_zebra` BDD feature wires the two together. cradle owns the data plane
in the forwarding namespace; zebra-rs runs there too with the tee enabled and a
static route configured:

```yaml
system:
  cradle-grpc: "unix:/tmp/cradle_zebra_ctl.sock"
router:
  static:
    ipv4:
      route:
      - prefix: 10.9.9.0/24
        nexthop:
        - address: 10.0.2.1
```

The sequence the test asserts:

1. Start cradle with just its ports (`ports.json`) and serve gRPC. At this point
   there is **no** route to `10.9.9.1`, so a ping across the forwarder **fails**
   (kernel forwarding is disabled — only the eBPF FIB can carry it).
2. Start zebra-rs with the config above. Its static route wins best-path, the
   `FibHandle` tee installs `10.9.9.0/24 → 10.0.2.1` into cradle's eBPF FIB, and
   the ping now **succeeds**.

The ping crossing the forwarder is the proof: nothing but the eBPF data plane —
programmed by a learned route from zebra-rs — could have carried it. The
`cradle_zebrav6` feature demonstrates the same for IPv6, which is why IPv6 routes
arrive through this path rather than the JSON `routes` field.
