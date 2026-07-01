# BDD Integration Tests

cradle-rs ships a behaviour-driven integration suite in the `cradle-bdd` crate
(`bdd/`). Each scenario builds a **real** topology of Linux network namespaces,
starts a real `cradle` data plane (and, where relevant, a real `zebra-rs`),
drives it through the actual config paths, and asserts on live behaviour — `ping`
reachability, HTTP responses, and datapath counters. Nothing is mocked: the tests
exercise the eBPF programs on the running kernel.

The suite is written with [cucumber-rs]. Scenarios live in [Gherkin] `.feature`
files under `bdd/tests/features/`; the step definitions that back them are in
`bdd/tests/cucumber.rs`. The harness is adapted from the zebra-rs BDD framework.

[cucumber-rs]: https://github.com/cucumber-rs/cucumber
[Gherkin]: https://cucumber.io/docs/gherkin/reference

## The features

| Feature | What it proves |
|---|---|
| `cradle_l2` | L2 switching and VLAN flooding between bridge ports. |
| `cradle_l3` | IPv4 L3 forwarding through the eBPF FIB (kernel forwarding off). |
| `cradle_l4` | IPv4 service load balancing with conntrack/NAT. |
| `cradle_l4v6` | IPv6 service load balancing. |
| `cradle_ecmp` | IPv4 ECMP across a nexthop group. |
| `cradle_ecmpv6` | IPv6 ECMP. |
| `cradle_l7` | L7 HTTP proxy via `bpf_sk_assign` TPROXY, routed by path. |
| `cradle_stats` | The datapath packet counters over gRPC. |
| `cradle_grpc` | Programming the data plane over the gRPC control API. |
| `cradle_bgp` | zebra-rs BGP routes programming the eBPF FIB. |
| `cradle_zebra` | A zebra-rs static route teed into the eBPF FIB (IPv4). |
| `cradle_zebrav6` | The same for IPv6. |

Each feature is tagged with its own name (for example `@cradle_l7`). The harness
uses that tag to scope every namespace and pid-file name it creates, so features
can run without colliding on host-global resource names.

## Anatomy of a scenario

A scenario follows the same shape, and — per project convention — every feature
that creates namespaces ends with an explicit teardown:

1. `Given a clean test environment` — sweep any stale namespaces and pid files
   left by a crashed prior run of *this* feature.
2. **Build** the topology — create namespaces, link them with veths, address
   them, start `cradle` (and `zebra-rs` where used), apply config.
3. **Assert** — `ping`, HTTP `GET`, counter values.
4. **Teardown** — a `Scenario: Teardown topology` that stops the daemons,
   deletes every namespace, and asserts `Then the test environment should be
   clean`. This runs explicitly rather than relying on the next run's cleanup, so
   processes and namespaces never leak between features.

## Running the suite

The step helpers shell out to `sudo ip netns …`, so the tests need
**passwordless `sudo`** (or to be run as root). You do *not* prefix `cargo test`
with `sudo` — the harness elevates the individual `ip` and daemon invocations.

```sh
# Every feature.
cargo test -p cradle-bdd

# One feature, by its tag.
cargo test -p cradle-bdd --test cucumber -- --tags @cradle_l7
```

Passing the tag filter to the `cucumber` test specifically (`--test cucumber`)
matters: a bare `-- --tags …` would be handed to libtest, which rejects it. The
`--tags` expression supports `not`, `and`, and `or` for selecting or excluding
scenarios. Features are tagged `@serial` because they manipulate host-global
namespaces, so they run one at a time.

The `cradle` binary the harness runs is `target/debug/cradle` (overridable with
the `CRADLE` environment variable), and `zebra-rs` is located similarly for the
integration features — so rebuild `cargo build -p cradle` before running if you
have changed the data plane.

## Inspecting a run

Per-daemon logs are written under `bdd/logs/` on every run, so a failing
scenario's cradle/zebra output is available even though the topology is torn down.
Set **`BDD_KEEP=1`** to turn the teardown steps into no-ops and leave the
namespaces and daemons up for hands-on inspection:

```sh
BDD_KEEP=1 cargo test -p cradle-bdd --test cucumber -- --tags @cradle_l7
sudo ip netns list
sudo ip netns exec cradle_l7_fwd ip route
```

The next run of the same feature begins with `Given a clean test environment`,
which sweeps the kept topology before rebuilding, so a kept run never leaks into
a later one.
