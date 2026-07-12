# Kernel forwarding vs eBPF forwarding — measured results

> Results from executing [`kernel-vs-ebpf-benchmark.md`](kernel-vs-ebpf-benchmark.md)
> via `bench/kernel-vs-ebpf.sh`. Medians of 5 × 10 s runs per test.

## Environment

| | |
|---|---|
| Kernel | 6.8.0-134-generic (aarch64), 12 CPUs, 31 GiB RAM |
| cradle | 0.9.1, debug build (eBPF objects built `opt-level = 3`) |
| Tools | iperf 3.16, netperf 2.7.0 |
| Topology | `h1 ─veth─ fwd ─veth─ h2`, only `fwd` under test |
| Path validation | eBPF: `l3v4_forward` > 0 and `ip_forward=0`; kernel: no TC/XDP on `fwd1`/`fwd2` and `ip_forward=1` — checked every run |

CPU governor not settable (VM, no cpufreq); no core pinning. Both modes ran
interleaved on the same host within ~30 minutes.

## Headline

- **Latency is a wash.** TCP_RR/UDP_RR ≈ 29–30 µs mean in both modes; eBPF
  p99 within 2–5 % of kernel. On veth, RR latency is dominated by scheduler
  wakeups, not the forwarding decision.
- **Bulk TCP favors the kernel on veth, and the gap is mostly aggregation +
  parallelism, not lookup cost.** With offloads at veth defaults the kernel
  forwards ~64 KB TSO/GRO super-frames (130–410 "Gbps"); attaching XDP forces
  per-MTU frames. With TSO/GSO/GRO disabled everywhere (apples-to-apples),
  single-flow kernel = 24.3 Gbps vs eBPF = 15.3 Gbps (0.63×). Multi-flow,
  kernel forwarding parallelizes across the sender CPUs (198 Gbps at 16
  flows) while the veth XDP datapath serializes on one NAPI core (~15 Gbps
  regardless of flow count).
- **UDP at a fixed offered rate is equivalent — but eBPF drops 100× less.**
  ~9 Gbps goodput in both modes; kernel loses 8.1 % of packets, eBPF 0.08 %.
- **1M routes cost nothing at steady state in either mode.** Per-probe
  throughput is flat across TBL24-hit / TBL8 two-lookup / default-route
  destinations for eBPF (15.20 / 15.15 / 15.13 Gbps) and for the kernel
  fib_trie (77.6 / 77.2 / 74.3 Gbps at P4).

## Baseline suite — offloads disabled (per-MTU, apples-to-apples)

`sudo bench/kernel-vs-ebpf.sh --no-offloads`

| test | metric | kernel | eBPF | eBPF/kernel |
|---|---|---|---|---|
| TCP 1 flow | Gbps | 24.34 | 15.30 | 0.63 |
| TCP 4 flows | Gbps | 78.44 | 15.48 | 0.20 |
| TCP 16 flows | Gbps | 198.51 | 13.00 | 0.07 |
| TCP 64 B writes, 1 flow | Gbps | 1.07 | 1.09 | 1.02 |
| TCP 64 B writes, 4 flows | Gbps | 3.67 | 3.60 | 0.98 |
| UDP 1400 B @ 10G offered | goodput Gbps | 9.18 | 8.71 | 0.95 |
| UDP 1400 B @ 10G offered | lost % | 8.10 | 0.08 | — |
| TCP_RR | trans/s | 34 064 | 33 400 | 0.98 |
| TCP_RR | mean µs | 29.30 | 29.89 | 1.02 |
| TCP_RR | p99 µs | 41 | 43 | 1.05 |
| UDP_RR | trans/s | 34 724 | 34 008 | 0.98 |
| UDP_RR | mean µs | 28.75 | 29.35 | 1.02 |
| UDP_RR | p99 µs | 40 | 41 | 1.02 |

## Baseline suite — veth default offloads

`sudo bench/kernel-vs-ebpf.sh`

Kernel numbers here measure TSO/GRO super-frame forwarding (~64 KB skbs per
hop), not per-packet forwarding; shown for completeness.

| test | metric | kernel | eBPF | eBPF/kernel |
|---|---|---|---|---|
| TCP 1 flow | Gbps | 129.87 | 15.42 | 0.12 |
| TCP 4 flows | Gbps | 386.78 | 14.80 | 0.04 |
| TCP 16 flows | Gbps | 410.54 | 12.52 | 0.03 |
| TCP 64 B writes, 1 flow | Gbps | 1.13 | 1.05 | 0.93 |
| UDP 1400 B @ 10G offered | goodput Gbps | 9.17 | 8.41 | 0.92 |
| UDP 1400 B @ 10G offered | lost % | 8.19 | 0.10 | — |
| TCP_RR | mean µs | 29.26 | 30.14 | 1.03 |
| UDP_RR | mean µs | 28.81 | 29.24 | 1.01 |

eBPF-mode numbers are the same in both variants (XDP already forces per-MTU
frames), which is itself the measurement of the offload asymmetry.

## Large-FIB suite — 1M routes (seed=1), offloads disabled

`sudo bench/kernel-vs-ebpf.sh --bigfib --no-offloads`

eBPF side: DIR-24-8 (`fib4_mode: dir24`), `routes4 = 1 000 008` confirmed via
`ctl fib`; TBL24/TBL8/default hit counters all incremented tens of millions.
Kernel side: identical prefix set via `ctl gen-routes-kernel | ip -batch`.

| probe (lookup path) | kernel Gbps | eBPF Gbps | eBPF/kernel |
|---|---|---|---|
| 10.0.8.8 (TBL24 direct) | 77.62 | 15.20 | 0.20 |
| 10.0.9.17 (TBL8 two-lookup) | 77.20 | 15.15 | 0.20 |
| 99.99.99.99 (default route) | 74.26 | 15.13 | 0.20 |

Throughput matches each mode's small-FIB (4-route) numbers at the same flow
count: neither the kernel fib_trie nor DIR-24-8 shows measurable degradation
from 1M routes at these packet rates.

### Route install (1M routes, control-plane)

| mode | path | time | rate |
|---|---|---|---|
| eBPF | `ctl gen-routes` (gRPC `AddRoute4Batch`, chunk 8192) | 9.22 s | 108 k routes/s |
| kernel | `ctl gen-routes-kernel` + `ip -batch` | 3.78 s | 265 k routes/s |

## Micro lookup cost (Phase 5, `fib-bench`, not a kernel comparison)

`sudo cradle fib-bench --routes 1000000 --seed 1 --repeat 100000`
(`BPF_PROG_TEST_RUN` on `cradle_tc`, includes full program overhead per packet)

| engine | direct hit | TBL8 path | default route | 1M-route load |
|---|---|---|---|---|
| LPM | 146 ns | 95 ns | 65 ns | 0.92 s |
| DIR-24-8 | 63 ns | 66 ns | 61 ns | 6.24 s |

## Interpretation

1. **The eBPF datapath's ceiling on veth is single-core packet processing.**
   ~15 Gbps ≈ 1.3 Mpps at MTU size, invariant with flow count, with rising
   TCP retransmits under multi-flow load (drops at the redirect queue). The
   kernel path instead forwards in the softirq context of each sender CPU, so
   it scales with flows. On multi-queue physical NICs the XDP path would
   spread across RSS queues; the veth single-queue result should not be
   extrapolated to hardware.
2. **Per-packet forwarding cost is close** (single flow 0.63× with identical
   frame sizes), consistent with fib-bench's 61–66 ns lookups being a small
   fraction of the per-packet budget at 1.3 Mpps (~770 ns).
3. **Latency and small-packet workloads see no penalty** from the eBPF path.
4. **FIB scale is a solved problem in both planes** at these rates; DIR-24-8's
   flat 61–66 ns vs LPM's 146 ns direct-hit cost shows why dir24 is the
   large-table default.

## Not yet covered

- ECMP scenario from the benchmark matrix (`cradle_ecmp` topology).
- Physical-NIC (multi-queue RSS) runs — the veth results understate XDP
  parallelism.
- Raw per-run data lives in `bench/results/` (gitignored); summaries and
  validation snapshots (`stats-ebpf.txt`, `fib-ebpf.txt`, `sysinfo.txt`) are
  regenerated by each run.
