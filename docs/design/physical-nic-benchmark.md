# Physical-NIC forwarding benchmark — two-box scenario

> Follow-up to [`kernel-vs-ebpf-benchmark.md`](kernel-vs-ebpf-benchmark.md):
> the same kernel-vs-eBPF comparison on real NICs. The veth results
> ([`kernel-vs-ebpf-results.md`](kernel-vs-ebpf-results.md)) are bounded by a
> single veth NAPI core (~1.3 Mpps); this scenario removes that ceiling with
> multi-queue RSS and measures where per-packet forwarding cost actually
> shows: small-packet pps.

## Goals

1. **Kernel vs eBPF at line rate** — same two modes, same traffic matrix as
   the veth plan, but across physical links with multi-queue RSS.
2. **Small-packet pps ceiling** — 64 B forwarding rate per mode (pktgen).
   MTU-sized TCP will likely sit at line rate on both modes for ≤ 25 G links;
   pps is the differentiator.
3. **Queue/core scaling** — throughput vs `ethtool -L` channel count, and
   pps-per-busy-core from `mpstat`.
4. **Latency under load** — RR latency with background bulk traffic (the
   veth run only measured unloaded RR).
5. **Optional large-FIB** — 1M routes via `gen-routes` / `gen-routes-kernel`,
   unchanged from the veth plan.

## Testbed

Two machines, two point-to-point links. `tgen` generates and sinks traffic;
`fwd` is the only device under test.

```
┌───────────────────────────────┐            ┌───────────────────────────────┐
│  box: tgen (source + sink)    │            │  box: fwd (DUT)               │
│                               │            │                               │
│  netns h1                     │   link 1   │                               │
│    $T1  10.0.1.1/24           │◄──────────►│  $F1  10.0.1.254/24           │
│    default via 10.0.1.254     │            │                               │
│                               │            │   [kernel forwarding  OR      │
│  netns h2                     │   link 2   │    cradle eBPF datapath]      │
│    $T2  10.0.2.1/24           │◄──────────►│  $F2  10.0.2.254/24           │
│    default via 10.0.2.254     │            │                               │
└───────────────────────────────┘            └───────────────────────────────┘
```

The two tgen ports live in **separate namespaces** so h1→h2 traffic must
cross both wires and the forwarder — otherwise the kernel would deliver it
locally. The DUT runs in the root namespace: cradle attaches to the physical
NICs directly.

Direct cabling (DAC/fiber) preferred. If a switch is unavoidable, disable
pause frames end to end and note the switch model in results.

### Parameters

Set once per testbed; every command below uses these.

```sh
# tgen
T1=enp1s0f0   T2=enp1s0f1
# fwd
F1=enp1s0f0   F2=enp1s0f1
```

Record in results: NIC model + driver (`ethtool -i`), link speed, firmware,
cable type, kernel versions on both boxes, CPU model, NIC NUMA node
(`cat /sys/class/net/$F1/device/numa_node`).

### Address table

| Box | Interface | Netns | IP | Role |
|---|---|---|---|---|
| tgen | `$T1` | `h1` | `10.0.1.1/24`, default → `10.0.1.254` | client |
| tgen | `$T2` | `h2` | `10.0.2.1/24`, default → `10.0.2.254` | server |
| tgen | `$T2` | `h2` | `10.0.8.8/32`, `10.0.9.17/32`, `99.99.99.99/32` | large-FIB probes |
| fwd | `$F1` | root | `10.0.1.254/24` | DUT left leg |
| fwd | `$F2` | root | `10.0.2.254/24` | DUT right leg |

Same addressing as the veth plan, so configs, probes, and the
`gen-routes`/`gen-routes-kernel` seed carry over unmodified.

## Prerequisites

- **Native XDP support** in the DUT NIC driver (mlx5, ice, i40e, ixgbe,
  bnxt_en, …). A generic-XDP fallback invalidates the eBPF numbers — Phase 1
  asserts the attach mode.
- cradle built on fwd (`cargo build -p cradle`); iperf3 + netperf on both
  boxes; `pktgen` kernel module on tgen for the pps tests.
- Both boxes: CPU governor `performance`, `irqbalance` stopped, C-states
  capped if latency numbers matter (`cpupower idle-set -D 10` or
  `intel_idle.max_cstate=`).
- DUT NIC IRQs pinned one-per-core on the NIC's NUMA node
  (`set_irq_affinity.sh` or manual `/proc/irq/*/smp_affinity_list`).
- Flow control off on all four ports: `ethtool -A $IF rx off tx off`.
- Identical MTU everywhere (default 1500 unless testing jumbo).

## Phase 0 — tgen setup

```sh
# tgen, as root
ip netns add h1; ip netns add h2
ip link set "$T1" netns h1
ip link set "$T2" netns h2
ip -n h1 addr add 10.0.1.1/24 dev "$T1";  ip -n h1 link set "$T1" up; ip -n h1 link set lo up
ip -n h2 addr add 10.0.2.1/24 dev "$T2";  ip -n h2 link set "$T2" up; ip -n h2 link set lo up
ip -n h1 route add default via 10.0.1.254
ip -n h2 route add default via 10.0.2.254
ip -n h2 addr add 10.0.8.8/32    dev "$T2"
ip -n h2 addr add 10.0.9.17/32   dev "$T2"
ip -n h2 addr add 99.99.99.99/32 dev "$T2"

ip netns exec h2 iperf3 -s -i 0 &
ip netns exec h2 netserver -D &
```

Verify links are up at the expected speed (`ethtool $T1 | grep Speed`) and
that ping h1→10.0.2.1 **fails** before the DUT is configured.

## Phase 1 — Mode A: eBPF forwarding

```sh
# fwd, as root
ip addr add 10.0.1.254/24 dev "$F1"; ip link set "$F1" up
ip addr add 10.0.2.254/24 dev "$F2"; ip link set "$F2" up
sysctl -w net.ipv4.ip_forward=0

cat > /tmp/fwd-ebpf.json <<EOF
{ "ports": [ {"name":"$F1","l3":true}, {"name":"$F2","l3":true} ] }
EOF
RUST_LOG=info ./target/debug/cradle serve --config /tmp/fwd-ebpf.json &
```

Validation (all three, every run):

```sh
ip netns exec h1 ping -c3 10.0.2.1                    # from tgen
./target/debug/cradle stats | grep l3v4_forward       # > 0
ip -d link show "$F1" | grep -o ' xdp[a-z]* '         # must be ' xdp ', NOT ' xdpgeneric '
```

If the driver fell back to generic XDP, stop: fix the driver/firmware before
recording anything.

## Phase 2 — Mode B: kernel forwarding

```sh
# fwd
kill %1   # stop cradle, then confirm detach:
tc filter show dev "$F1" ingress; tc filter show dev "$F2" ingress   # empty
ip -d link show "$F1" | grep xdp                                     # nothing

sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
sysctl -w "net.ipv4.conf.$F1.rp_filter=0" "net.ipv4.conf.$F2.rp_filter=0"
```

Connected routes already cover both subnets.

## Phase 3 — traffic matrix

Run in both modes; medians of 5 × 10 s (30 s for the headline rows).
Discard a ~10 s warm-up per mode.

### 3a. iperf3 / netperf suite (comparability with the veth results)

Same commands as the veth plan, from tgen:

```sh
ip netns exec h1 iperf3 -c 10.0.2.1 -t 30 -P {1,4,16}
ip netns exec h1 iperf3 -c 10.0.2.1 -u -b 0 -l 1400 -t 30      # -b 0 = unthrottled
ip netns exec h1 netperf -H 10.0.2.1 -t TCP_RR -l 30 -j -- -o THROUGHPUT,MEAN_LATENCY,P90_LATENCY,P99_LATENCY
ip netns exec h1 netperf -H 10.0.2.1 -t UDP_RR -l 30 -j -- -o THROUGHPUT,MEAN_LATENCY,P90_LATENCY,P99_LATENCY
```

Offload variants, as established on veth: run once with NIC defaults and
once with `ethtool -K $IF tso off gso off gro off` on all four ports. On
hardware the default variant is the realistic one (TSO/GRO are real silicon
here, and both modes keep them on RX); report both.

### 3b. Small-packet pps (pktgen, the headline test)

iperf3 cannot source > a few Mpps; use kernel pktgen on tgen h1, 64 B UDP,
dst 10.0.2.1, dst MAC = `$F1`'s MAC, with enough flow entropy
(`IPDST_RND`/`UDPDST_RND` over a /16) to spread the DUT's RSS queues.

Measure at the **sink**: rx pps on `$T2` (delta of
`/sys/class/net/$T2/statistics/rx_packets` over the run, cross-checked with
`ethtool -S`). Offered − received = drop rate; report both pps and loss%.

Sweep offered rate to find the max rate with < 0.1 % loss (coarse binary
search is enough; full RFC 2544 is not the goal).

### 3c. Queue scaling

```sh
ethtool -L "$F1" combined N; ethtool -L "$F2" combined N   # N = 1, 2, 4, max
```

Repeat 3b (and `iperf3 -P 16`) per N, both modes. This is the direct answer
to the veth single-NAPI ceiling: eBPF throughput should now scale with N.
Re-pin IRQs after every `-L` change.

### 3d. Latency under load

`netperf TCP_RR` while `iperf3 -c 10.0.2.1 -P 8` runs in the background —
p99 under load is where a slow path or queue misconfiguration shows.

### 3e. Per-core efficiency

`mpstat -P ALL 1` on fwd during 3b steady state. Report Mpps / busy-core so
modes are comparable even when one saturates the link.

## Phase 4 — large FIB (optional)

Identical to the veth plan Phase 4: `fib4_mode: dir24` + nexthop
`{oif: $F2, gateway: 10.0.2.1}` on the eBPF side, `ctl gen-routes --count
1000000 --seed 1 --nexthop-id 1`; kernel side `ctl gen-routes-kernel --count
1000000 --seed 1 --via 10.0.2.1 --dev $F2 | ip -batch -`. Run 3b against the
three probe addresses.

## Benchmark matrix

| Scenario | Pkt size | Flows | DUT queues | Tool | Metric |
|---|---|---|---|---|---|
| Bulk TCP | MTU | 1, 4, 16 | max | iperf3 | Gbps |
| Bulk UDP | 1400 B | 1 | max | iperf3 | Gbps, loss % |
| **Small packet** | 64 B | RSS-spread | max | pktgen | Mpps @ <0.1 % loss |
| Queue scaling | 64 B, MTU | 16 | 1, 2, 4, max | pktgen, iperf3 | Mpps/Gbps vs N |
| Latency | — | 1 | max | netperf | RR µs, p99 |
| Loaded latency | — | 1 + 8 bg | max | netperf + iperf3 | p99 µs |
| Large FIB | MTU | 4 | max | iperf3 | Gbps per probe |
| Per-core | 64 B | RSS-spread | max | pktgen + mpstat | Mpps / busy core |

## Fairness checklist

- Same cables, same ports, same `ethtool -L`/ring/IRQ-affinity settings in
  both modes — the only variable is the forwarder.
- **Prove tgen is not the bottleneck**: during every UDP/pktgen test the
  offered rate must hit its target and tgen must show CPU headroom
  (`mpstat`). If tgen saturates first, the DUT comparison is meaningless.
- Snapshot `ethtool -S` on all four ports before/after each run; rx_missed /
  rx_dropped / pause counters attribute any loss to the right hop.
- Re-check the XDP attach mode (`xdp` vs `xdpgeneric`) after every cradle
  restart.
- Record everything the Parameters section lists; NIC firmware and driver
  version move these numbers as much as code does.

## Pitfalls

1. **Generic-XDP fallback** — silently ~10× slower; assert `' xdp '` in
   `ip -d link` every eBPF run.
2. **Pause frames** — a switch or link partner asserting flow control turns
   a drop test into a throttle test; `ethtool -A ... off` and check pause
   counters.
3. **IRQ affinity drift** — `irqbalance` re-spreading mid-run ruins queue
   scaling curves; stop it and re-pin after every `ethtool -L`.
4. **NUMA mismatch** — NIC on node 1, forwarding on node 0 costs double-digit
   percent; pin to the NIC's node.
5. **Single-flow pktgen** — one flow hashes to one RSS queue and reproduces
   the veth single-core ceiling by accident; randomize headers.
6. **tgen netns leak** — moving a physical NIC into a deleted netns returns
   it to root, dropping its config; re-run Phase 0 after any netns teardown.

## Automation

`bench/kernel-vs-ebpf.sh` covers the single-host veth case. A two-box runner
needs SSH orchestration (mode switching on fwd, measurement on tgen, result
collection to one place) and belongs in `bench/physical/` once the testbed
interfaces are fixed; the phases above are written so each block is directly
scriptable with `$T1/$T2/$F1/$F2` as the only inputs.
