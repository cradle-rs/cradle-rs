# Network-Namespace Demo Scripts

Alongside the BDD suite, `scripts/` holds a set of standalone **network-namespace
demo scripts** — one per layer. Each builds a small topology with `ip netns`,
starts `cradle`, drives a single scenario, and tears everything down on exit.
They predate the BDD features and are kept as quick, dependency-free, readable
demonstrations you can run directly and watch.

```sh
sudo scripts/netns-l3-test.sh
```

Each script is self-contained: it sweeps stale state on entry, sets a `trap … EXIT`
cleanup that kills the daemon and deletes the namespaces, and uses
`CRADLE=${CRADLE:-target/debug/cradle}` so you can point it at a different binary.

## The scripts

| Script | Demonstrates |
|---|---|
| `netns-l2-test.sh` | L2 switching / flooding. |
| `netns-l3-test.sh` | IPv4 L3 forwarding through the eBPF FIB. |
| `netns-l3v6-test.sh` | IPv6 L3 forwarding. |
| `netns-l4-test.sh` | IPv4 service load balancing. |
| `netns-l4v6-test.sh` | IPv6 service load balancing. |
| `netns-ecmp-test.sh` | IPv4 ECMP. |
| `netns-ecmpv6-test.sh` | IPv6 ECMP. |
| `netns-grpc-test.sh` | Programming the data plane over gRPC. |
| `netns-bgp-test.sh` | zebra-rs BGP driving the eBPF FIB. |
| `netns-zebra-test.sh` | zebra-rs static route teed into the eBPF FIB (IPv4). |
| `netns-zebrav6-test.sh` | The same for IPv6. |

## Scripts vs BDD

The two overlap by design — every script has a matching BDD feature. Reach for
the **scripts** when you want to *watch* a single scenario play out step by step,
tweak the topology by hand, or reproduce something outside the test harness. Use
the **BDD suite** ([BDD Integration Tests](ch-04-00-bdd-tests.md)) for
regression coverage: it scopes resources per feature, asserts rigorously
(including datapath counters), and enforces the explicit-teardown convention. CI
runs the BDD suite; the scripts are for interactive exploration.

The common pattern all of them rely on — disabling kernel IP forwarding on the
forwarder so that any traffic which still crosses it *must* have been moved by
the eBPF data plane — is the same trick the BDD features use, and the clearest
one-line proof that cradle, not the kernel, is doing the forwarding.
