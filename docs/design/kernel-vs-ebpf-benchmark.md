# Kernel forwarding vs eBPF forwarding — benchmark plan

> How to compare Linux kernel IP forwarding against the cradle-rs eBPF datapath
> using the same topology, routes, and traffic patterns.

## Goals

1. **End-to-end throughput and latency** — the primary kernel-vs-eBPF comparison.
2. **Optional micro lookup cost** — `cradle fib-bench` for per-packet FIB engine
   numbers (eBPF only; not a kernel comparison).
3. **Optional large-FIB scale** — 1M-route table using the same synthetic
   prefix generator as `cradle ctl gen-routes`.

## Prerequisites

- **Linux host** with kernel 6.8+ (cradle's tested baseline).
- **Nightly Rust** with `rust-src`, plus `bpf-linker`.
- Built binaries: `cargo build -p cradle`.
- Measurement tools: `iperf3`, `netperf` (install via distro packages).
- Root or passwordless `sudo` (netns, sysctl, cradle attach).

## Network topology

Three network namespaces connected by veth pairs. The forwarder namespace
(`fwd`) is the only node under test; `h1` is the client and `h2` is the
server.

### Diagram

```
┌─────────────────────────┐         ┌──────────────────────────────────────┐         ┌─────────────────────────┐
│  netns: h1              │         │  netns: fwd (forwarder)              │         │  netns: h2              │
│                         │         │                                      │         │                         │
│  eth0                   │         │  fwd1              fwd2              │         │  eth0                   │
│  10.0.1.1/24            │◄─veth──►│  10.0.1.254/24     10.0.2.254/24    │◄─veth──►│  10.0.2.1/24            │
│                         │         │                                      │         │                         │
│  default via 10.0.1.254 │         │  [cradle eBPF datapath on both ports]│         │  default via 10.0.2.254 │
└─────────────────────────┘         └──────────────────────────────────────┘         └─────────────────────────┘
```

### Address table

| Namespace | Interface | IP address | Role |
|---|---|---|---|
| **h1** | `eth0` | `10.0.1.1/24` | Client / traffic source |
| **h1** | (route) | `default → 10.0.1.254` | Sends all traffic to forwarder |
| **fwd** | `fwd1` | `10.0.1.254/24` | Left leg (toward h1) |
| **fwd** | `fwd2` | `10.0.2.254/24` | Right leg (toward h2) |
| **h2** | `eth0` | `10.0.2.1/24` | Server / traffic sink |

### Traffic path (h1 → h2)

```
h1 (10.0.1.1)
  │  dst=10.0.2.1 → default via 10.0.1.254
  ▼
fwd1 (10.0.1.254)  ──►  [forwarding decision]  ──►  fwd2 (10.0.2.254)
                                                          │
                                                          ▼
                                                    h2 (10.0.2.1)
```

This topology matches the BDD features `cradle_l3` and `cradle_grpc`.

## What cradle already provides

| Tool | What it measures | Kernel comparison? |
|---|---|---|
| `cradle fib-bench` | eBPF TC lookup latency (LPM vs DIR-24-8) via `BPF_PROG_TEST_RUN` | No — eBPF only, no attach, no real packets |
| `cradle policy-bench` | Policy generation-flip churn | No |
| BDD features (`cradle_l3`, `cradle_grpc`, `cradle_bigfib`) | Correctness with kernel forwarding off | Proves eBPF works, not throughput |

The README's "~51 ns lookups" come from `fib-bench`, not from kernel-vs-eBPF
end-to-end tests.

## Phase 0 — Build topology

```sh
cargo build -p cradle

# Namespaces + veth (run as root)
ip netns add h1 && ip netns add fwd && ip netns add h2

ip link add h1-eth0 type veth peer name fwd-fwd1
ip link set h1-eth0 netns h1 name eth0
ip link set fwd-fwd1 netns fwd name fwd1

ip link add h2-eth0 type veth peer name fwd-fwd2
ip link set h2-eth0 netns h2 name eth0
ip link set fwd-fwd2 netns fwd name fwd2

ip netns exec h1  ip addr add 10.0.1.1/24  dev eth0 && ip link set eth0 up
ip netns exec h2  ip addr add 10.0.2.1/24  dev eth0 && ip link set eth0 up
ip netns exec fwd ip addr add 10.0.1.254/24 dev fwd1 && ip link set fwd1 up
ip netns exec fwd ip addr add 10.0.2.254/24 dev fwd2 && ip link set fwd2 up
ip netns exec h1  ip route add default via 10.0.1.254
ip netns exec h2  ip route add default via 10.0.2.254
```

Verify: ping from h1 to h2 should **fail** before any forwarder is configured.

## Phase 1 — Mode A: eBPF forwarding

Kernel forwarding is **off** so only the cradle datapath can forward traffic.
This is the same isolation pattern used throughout the BDD suite.

```sh
ip netns exec fwd sysctl -w net.ipv4.ip_forward=0

cat > /tmp/fwd-ebpf.json <<'EOF'
{ "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ] }
EOF

ip netns exec fwd ./target/debug/cradle serve --config /tmp/fwd-ebpf.json &
sleep 2

# Sanity check
ip netns exec h1 ping -c 3 10.0.2.1
ip netns exec fwd ./target/debug/cradle stats   # expect l3v4_forward > 0
```

cradle auto-derives connected/local routes from interface addresses
(`derive_port`); no manual route config is needed for the baseline case.

## Phase 2 — Mode B: kernel forwarding

Stop cradle, enable kernel forwarding, install equivalent kernel routes.

```sh
ip netns exec fwd killall cradle 2>/dev/null || true

ip netns exec fwd sysctl -w net.ipv4.ip_forward=1
ip netns exec fwd sysctl -w net.ipv4.conf.all.rp_filter=0
ip netns exec fwd sysctl -w net.ipv4.conf.default.rp_filter=0

ip netns exec fwd ip route add 10.0.2.0/24 dev fwd2
ip netns exec fwd ip route add 10.0.1.0/24 dev fwd1

# Sanity check
ip netns exec h1 ping -c 3 10.0.2.1
```

**Critical:** do not leave cradle attached during kernel runs — TC/XDP hooks
would still intercept traffic and invalidate the baseline.

Confirm no eBPF programs remain on the forwarder interfaces:

```sh
ip netns exec fwd tc qdisc show dev fwd1
ip netns exec fwd tc qdisc show dev fwd2
```

## Phase 3 — End-to-end measurement

Run the same traffic in both modes. Repeat each test 5+ times; report median.

### Throughput (iperf3)

```sh
# Server (h2)
ip netns exec h2 iperf3 -s

# Client (h1) — run in each mode
ip netns exec h1 iperf3 -c 10.0.2.1 -t 30 -P 4          # TCP, 4 parallel flows
ip netns exec h1 iperf3 -c 10.0.2.1 -u -b 10G -l 1400   # UDP, 1400-byte packets
ip netns exec h1 iperf3 -c 10.0.2.1 -t 30 -l 64          # TCP, 64-byte packets
```

### Latency (netperf)

```sh
ip netns exec h2 netserver -D
ip netns exec h1 netperf -H 10.0.2.1 -t TCP_RR -l 30
ip netns exec h1 netperf -H 10.0.2.1 -t UDP_RR -l 30
```

### Fairness checklist

- Same topology, MTU, packet sizes, flow count (`-P`), and test duration.
- **Offloads:** with veth defaults, kernel forwarding carries TSO/GRO
  super-frames (~64 KB skbs) while an XDP datapath forces per-MTU frames, so
  bulk-TCP results compare packet *aggregation*, not forwarding. For a
  per-packet comparison disable TSO/GSO/GRO on every veth in both modes
  (`bench/kernel-vs-ebpf.sh --no-offloads`); report both variants.
- CPU governor set to `performance`.
- Pin workloads if needed (`taskset`) so iperf and the forwarder don't share
  the same core.
- Warm up for ~10 s before recording; discard the first run.
- veth overhead affects both modes equally — that is expected.

### Path validation

| Mode | Check |
|---|---|
| eBPF | `cradle stats` → `l3v4_forward` increments; `ip_forward=0` proves kernel did not forward |
| Kernel | No TC/XDP on `fwd1`/`fwd2`; `ip_forward=1`; routes present in `ip route` |

## Phase 4 — Large-FIB benchmark (optional)

Follow the `cradle_bigfib` topology: same three-host layout with extra probe
addresses on h2 and a million-route table on the forwarder.

### Extra probe addresses (h2)

| Address | Lookup path exercised |
|---|---|
| `10.0.8.8/32` | TBL24 direct hit |
| `10.0.9.17/32` | TBL8 two-lookup path |
| `99.99.99.99/32` | Default route |

### eBPF side

```sh
ip netns exec fwd sysctl -w net.ipv4.ip_forward=0

cat > /tmp/fwd-bigfib.json <<'EOF'
{
  "fib4_mode": "dir24",
  "ports": [
    { "name": "fwd1", "l3": true },
    { "name": "fwd2", "l3": true }
  ],
  "nexthops": [
    { "id": 1, "oif": "fwd2", "gateway": "10.0.2.1" }
  ],
  "routes": [
    { "prefix": "10.0.8.0/24", "nexthop": 1 },
    { "prefix": "10.0.9.0/24", "nexthop": 1 },
    { "prefix": "10.0.9.16/28", "nexthop": 1 },
    { "prefix": "0.0.0.0/0", "nexthop": 1 }
  ]
}
EOF

ip netns exec h2 ip addr add 10.0.8.8/32 dev eth0
ip netns exec h2 ip addr add 10.0.9.17/32 dev eth0
ip netns exec h2 ip addr add 99.99.99.99/32 dev eth0

ip netns exec fwd ./target/debug/cradle serve --config /tmp/fwd-bigfib.json --fib4-mode dir24 &
sleep 2

ip netns exec fwd ./target/debug/cradle ctl gen-routes \
  --count 1000000 --seed 1 --nexthop-id 1
```

### Kernel side

Install the **same** prefix set. `util::gen_dfz_prefixes(count, seed)` is
deterministic — generate routes from the same seed and load with `ip -batch`:

```sh
# For each (addr, len) in gen_dfz_prefixes(1_000_000, 1):
#   ip route add <addr>/<len> via 10.0.2.1 dev fwd2
```

`cradle ctl gen-routes-kernel` emits exactly this: the `gen-routes` table
(same `--count`/`--seed`) as `ip -batch` lines on stdout, with no running
daemon required:

```sh
./target/debug/cradle ctl gen-routes-kernel \
  --count 1000000 --seed 1 --via 10.0.2.1 --dev fwd2 > /tmp/routes.batch
ip netns exec fwd ip -batch /tmp/routes.batch
```

Run iperf3 to each probe destination in both modes and compare.

## Phase 5 — Micro lookup benchmark (eBPF internals)

Per-packet FIB lookup cost — separate from the end-to-end kernel comparison.

```sh
sudo ./target/debug/cradle fib-bench --routes 1000000 --seed 1 --repeat 100000
sudo ./target/debug/cradle fib-bench --mode lpm   --routes 100000  --repeat 100000
sudo ./target/debug/cradle fib-bench --mode dir24 --routes 1000000 --repeat 100000
```

Uses `BPF_PROG_TEST_RUN` on `cradle_tc` without real interfaces. See
[`large-fib.md`](large-fib.md) for design context.

## Benchmark matrix

| Scenario | Routes | Packet size | Flows | Tool | Metric |
|---|---|---|---|---|---|
| Baseline L3 | ~4 (connected) | 1400 B | 1, 4, 16 | iperf3 | Gbps |
| Small packet | ~4 | 64 B | 1, 4 | iperf3 | Gbps / PPS |
| Latency | ~4 | — | 1 | netperf | TCP_RR µs |
| Large FIB | 1M (seed=1) | 1400 B | 4 | iperf3 | Gbps per probe |
| ECMP | nexthop group | 1400 B | 16 | iperf3 | Gbps (see `cradle_ecmp`) |

## Common pitfalls

1. **Leaving eBPF attached during kernel runs** — invalidates the baseline.
2. **`rp_filter=1` on veth** — asymmetric routing drops in kernel mode.
3. **Comparing `fib-bench` ns to iperf Gbps** — different measurement layers.
4. **Route table mismatch** — kernel and eBPF FIBs must carry equivalent entries.
5. **Install time vs steady-state** — `fib-bench` and `gen-routes` print load
   time separately; throughput tests should run only after convergence.

## Workflow summary

```
Build topology (h1 ─ fwd ─ h2)
        │
        ├── Mode A: ip_forward=0 + cradle serve  ──► iperf3 / netperf
        │
        └── Mode B: stop cradle + ip_forward=1 + ip route  ──► iperf3 / netperf
                    │
                    └── Compare throughput + latency
```

## Automation

`bench/kernel-vs-ebpf.sh` automates all of the above: topology setup
(`crb_`-prefixed namespaces so BDD runs are never touched), mode switching
with path validation in each mode, the traffic matrix, and median-of-N
result collection into `bench/results/`.

```sh
sudo bench/kernel-vs-ebpf.sh                        # baseline, both modes
sudo bench/kernel-vs-ebpf.sh --no-offloads          # per-MTU apples-to-apples
sudo bench/kernel-vs-ebpf.sh --bigfib --no-offloads # 1M-route probe suite
sudo bench/kernel-vs-ebpf.sh --quick                # short smoke run
```

Measured results live in
[`kernel-vs-ebpf-results.md`](kernel-vs-ebpf-results.md).
