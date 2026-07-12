#!/usr/bin/env bash
# Kernel forwarding vs eBPF forwarding — end-to-end benchmark.
# Implements docs/design/kernel-vs-ebpf-benchmark.md.
#
#   h1 (10.0.1.1) ──veth── fwd1 [ fwd: cradle eBPF OR kernel ] fwd2 ──veth── h2 (10.0.2.1)
#
# Mode A (ebpf):   ip_forward=0 on fwd; cradle serve is the only forwarder.
# Mode B (kernel): cradle stopped (verified detached); ip_forward=1 + kernel routes.
# Same topology and traffic in both modes; each test repeated --reps times,
# reported as the median.
#
# Run as root:
#   sudo bench/kernel-vs-ebpf.sh                 # baseline suite, both modes
#   sudo bench/kernel-vs-ebpf.sh --bigfib        # 1M-route suite, both modes
#   sudo bench/kernel-vs-ebpf.sh --quick         # short smoke run
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"

# crb_-prefixed namespaces; cleanup only ever touches these three, so BDD
# runs (feature-tag prefixes) and other sessions are never swept.
H1=crb_h1; H2=crb_h2; FWD=crb_fwd

DURATION=10
REPS=5
MODES="ebpf kernel"
BIGFIB=0
ROUTES=1000000
SEED=1
KEEP=0
NO_OFFLOADS=0
OUTDIR=""

usage() {
    sed -n '2,14p' "$0"
    cat <<EOF

Options:
  --duration N   seconds per traffic test (default $DURATION)
  --reps N       repetitions per test, median reported (default $REPS)
  --mode M       ebpf | kernel | both (default both)
  --bigfib       run the 1M-route probe suite instead of the baseline suite
  --routes N     bigfib route count (default $ROUTES)
  --seed N       bigfib route-generator seed (default $SEED)
  --outdir DIR   results directory (default bench/results/<timestamp>)
  --no-offloads  disable TSO/GSO/GRO on every veth, forcing MTU-sized packets
                 in both modes. Without this, kernel mode forwards TSO/GRO
                 super-frames (~64 KB skbs) while XDP forces per-MTU frames,
                 so bulk-TCP numbers compare packet *aggregation*, not
                 forwarding. Use this for a per-packet apples-to-apples run.
  --keep         leave namespaces up on exit (for inspection)
  --quick        shorthand for --duration 5 --reps 2
EOF
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --duration) DURATION=$2; shift 2 ;;
        --reps)     REPS=$2; shift 2 ;;
        --mode)     case "$2" in
                        both) MODES="ebpf kernel" ;;
                        ebpf|kernel) MODES=$2 ;;
                        *) echo "bad --mode $2" >&2; usage 1 ;;
                    esac; shift 2 ;;
        --bigfib)   BIGFIB=1; shift ;;
        --routes)   ROUTES=$2; shift 2 ;;
        --seed)     SEED=$2; shift 2 ;;
        --outdir)   OUTDIR=$2; shift 2 ;;
        --no-offloads) NO_OFFLOADS=1; shift ;;
        --keep)     KEEP=1; shift ;;
        --quick)    DURATION=5; REPS=2; shift ;;
        -h|--help)  usage ;;
        *) echo "unknown option $1" >&2; usage 1 ;;
    esac
done

[ "$(id -u)" = 0 ] || { echo "run as root (sudo $0)" >&2; exit 1; }
for tool in iperf3 netperf netserver jq ethtool; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
[ -x "$CRADLE" ] || { echo "cradle binary not found at $CRADLE (cargo build -p cradle)" >&2; exit 1; }

OUTDIR="${OUTDIR:-$ROOT/bench/results/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUTDIR"
RAW="$OUTDIR/raw.csv"
echo "mode,test,metric,rep,value" > "$RAW"

CFG="$OUTDIR/fwd.json"
PIDFILE="$OUTDIR/cradle.pid"
IPERF_PID=""
NETSERVER_PID=""

cleanup() {
    stop_cradle || true
    [ -n "$IPERF_PID" ] && kill "$IPERF_PID" 2>/dev/null || true
    [ -n "$NETSERVER_PID" ] && kill "$NETSERVER_PID" 2>/dev/null || true
    if [ "$KEEP" = 0 ]; then
        ip netns del "$H1"  2>/dev/null || true
        ip netns del "$H2"  2>/dev/null || true
        ip netns del "$FWD" 2>/dev/null || true
    fi
}
trap cleanup EXIT

log() { echo "== $*"; }

# ---------------------------------------------------------------- topology

setup_topology() {
    # Sweep only our own stale namespaces from a previous aborted run.
    ip netns del "$H1" 2>/dev/null || true
    ip netns del "$H2" 2>/dev/null || true
    ip netns del "$FWD" 2>/dev/null || true

    ip netns add "$H1"; ip netns add "$H2"; ip netns add "$FWD"
    ip link add h1eth netns "$H1" type veth peer name fwd1 netns "$FWD"
    ip link add h2eth netns "$H2" type veth peer name fwd2 netns "$FWD"

    ip -n "$H1"  addr add 10.0.1.1/24   dev h1eth
    ip -n "$H2"  addr add 10.0.2.1/24   dev h2eth
    ip -n "$FWD" addr add 10.0.1.254/24 dev fwd1
    ip -n "$FWD" addr add 10.0.2.254/24 dev fwd2

    for ns_dev in "$H1:h1eth" "$H2:h2eth" "$FWD:fwd1" "$FWD:fwd2"; do
        ip -n "${ns_dev%%:*}" link set "${ns_dev##*:}" up
        ip -n "${ns_dev%%:*}" link set lo up
    done

    ip -n "$H1" route add default via 10.0.1.254
    ip -n "$H2" route add default via 10.0.2.254

    if [ "$NO_OFFLOADS" = 1 ]; then
        ip netns exec "$H1"  ethtool -K h1eth tso off gso off gro off >/dev/null
        ip netns exec "$H2"  ethtool -K h2eth tso off gso off gro off >/dev/null
        ip netns exec "$FWD" ethtool -K fwd1  tso off gso off gro off >/dev/null
        ip netns exec "$FWD" ethtool -K fwd2  tso off gso off gro off >/dev/null
    fi

    # Large-FIB probe addresses (harmless in the baseline suite: nothing
    # routes to them until the bigfib routes exist on fwd).
    ip -n "$H2" addr add 10.0.8.8/32     dev h2eth
    ip -n "$H2" addr add 10.0.9.17/32    dev h2eth
    ip -n "$H2" addr add 99.99.99.99/32  dev h2eth

    ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0

    # No forwarder configured yet: cross-subnet traffic must NOT flow.
    if ip netns exec "$H1" ping -c1 -W1 10.0.2.1 >/dev/null 2>&1; then
        echo "FAIL: ping crossed fwd with no forwarder configured" >&2
        exit 1
    fi

    ip netns exec "$H2" iperf3 -s -i 0 > "$OUTDIR/iperf3-server.log" 2>&1 &
    IPERF_PID=$!
    ip netns exec "$H2" netserver -D > "$OUTDIR/netserver.log" 2>&1 &
    NETSERVER_PID=$!
    sleep 1
}

wait_ping() {
    local dst=$1 i
    for i in $(seq 1 30); do
        ip netns exec "$H1" ping -c1 -W1 "$dst" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    return 1
}

# ------------------------------------------------------------- mode: eBPF

start_cradle() {
    ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0
    ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve \
        --config "$CFG" --pid-file "$PIDFILE" --log-format plain \
        > "$OUTDIR/cradle.log" 2>&1 &
    if ! wait_ping 10.0.2.1; then
        echo "FAIL: no connectivity through the eBPF datapath; cradle log:" >&2
        cat "$OUTDIR/cradle.log" >&2
        exit 1
    fi
}

stop_cradle() {
    local pid dev
    [ -f "$PIDFILE" ] || return 0
    pid=$(cat "$PIDFILE")
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.2
    done
    rm -f "$PIDFILE"
    # The kernel baseline is invalid if any cradle hook is still attached.
    for dev in fwd1 fwd2; do
        ip netns list 2>/dev/null | grep -qw "$FWD" || continue
        if ip netns exec "$FWD" tc filter show dev "$dev" ingress 2>/dev/null | grep -q .; then
            echo "WARN: TC ingress filter left on $dev; removing clsact" >&2
            ip netns exec "$FWD" tc qdisc del dev "$dev" clsact 2>/dev/null || true
        fi
        if ip -n "$FWD" -d link show "$dev" 2>/dev/null | grep -q xdp; then
            echo "WARN: XDP program left on $dev; detaching" >&2
            ip -n "$FWD" link set dev "$dev" xdp off 2>/dev/null || true
        fi
    done
}

setup_ebpf() {
    if [ "$BIGFIB" = 1 ]; then
        cat > "$CFG" <<'EOF'
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
    else
        cat > "$CFG" <<'EOF'
{ "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ] }
EOF
    fi
    start_cradle
    if [ "$BIGFIB" = 1 ]; then
        log "installing $ROUTES routes into the eBPF FIB (gen-routes)"
        ip netns exec "$FWD" "$CRADLE" ctl gen-routes \
            --count "$ROUTES" --seed "$SEED" --nexthop-id 1 \
            | tee "$OUTDIR/route-install-ebpf.txt"
        ip netns exec "$FWD" "$CRADLE" ctl fib | tee "$OUTDIR/fib-ebpf.txt"
    fi
}

validate_ebpf() {
    ip netns exec "$FWD" "$CRADLE" stats > "$OUTDIR/stats-ebpf.txt"
    local fwd_pkts
    fwd_pkts=$(awk '$1=="l3v4_forward"{print $2}' "$OUTDIR/stats-ebpf.txt")
    if [ -z "$fwd_pkts" ] || [ "$fwd_pkts" -eq 0 ]; then
        echo "FAIL: l3v4_forward is 0 — traffic did not cross the eBPF datapath" >&2
        exit 1
    fi
    [ "$(ip netns exec "$FWD" sysctl -n net.ipv4.ip_forward)" = 0 ] \
        || { echo "FAIL: ip_forward != 0 during eBPF mode" >&2; exit 1; }
    log "eBPF path validated: l3v4_forward=$fwd_pkts, ip_forward=0"
}

# ----------------------------------------------------------- mode: kernel

assert_no_ebpf() {
    local dev
    for dev in fwd1 fwd2; do
        if ip netns exec "$FWD" tc filter show dev "$dev" ingress 2>/dev/null | grep -q . \
           || ip -n "$FWD" -d link show "$dev" | grep -q xdp; then
            echo "FAIL: eBPF still attached to $dev — kernel baseline invalid" >&2
            exit 1
        fi
    done
}

setup_kernel() {
    stop_cradle
    assert_no_ebpf
    ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=1
    ip netns exec "$FWD" sysctl -wq net.ipv4.conf.all.rp_filter=0
    ip netns exec "$FWD" sysctl -wq net.ipv4.conf.default.rp_filter=0
    ip netns exec "$FWD" sysctl -wq net.ipv4.conf.fwd1.rp_filter=0
    ip netns exec "$FWD" sysctl -wq net.ipv4.conf.fwd2.rp_filter=0
    ip -n "$FWD" route replace 10.0.1.0/24 dev fwd1
    ip -n "$FWD" route replace 10.0.2.0/24 dev fwd2

    if [ "$BIGFIB" = 1 ]; then
        ip -n "$FWD" route replace 10.0.8.0/24  via 10.0.2.1 dev fwd2
        ip -n "$FWD" route replace 10.0.9.0/24  via 10.0.2.1 dev fwd2
        ip -n "$FWD" route replace 10.0.9.16/28 via 10.0.2.1 dev fwd2
        ip -n "$FWD" route replace default      via 10.0.2.1 dev fwd2
        log "installing $ROUTES routes into the kernel FIB (ip -batch)"
        local batch t0 t1
        batch="$OUTDIR/kernel-routes.batch"
        "$CRADLE" ctl gen-routes-kernel \
            --count "$ROUTES" --seed "$SEED" --via 10.0.2.1 --dev fwd2 > "$batch"
        t0=$(date +%s.%N)
        ip -n "$FWD" -batch "$batch"
        t1=$(date +%s.%N)
        awk -v a="$t0" -v b="$t1" -v n="$ROUTES" 'BEGIN {
            d=b-a; printf "installed %d routes in %.2fs (%.0f routes/s)\n", n, d, n/d
        }' | tee "$OUTDIR/route-install-kernel.txt"
        rm -f "$batch"
    fi

    if ! wait_ping 10.0.2.1; then
        echo "FAIL: no connectivity through kernel forwarding" >&2
        exit 1
    fi
}

validate_kernel() {
    assert_no_ebpf
    [ "$(ip netns exec "$FWD" sysctl -n net.ipv4.ip_forward)" = 1 ] \
        || { echo "FAIL: ip_forward != 1 during kernel mode" >&2; exit 1; }
    log "kernel path validated: no TC/XDP on fwd1/fwd2, ip_forward=1"
}

# ------------------------------------------------------------ measurement

emit() { echo "$1,$2,$3,$4,$5" >> "$RAW"; }   # mode test metric rep value

run_iperf_tcp() {   # mode test rep dst parallel len
    local mode=$1 test=$2 rep=$3 dst=$4 par=$5 len=$6 json
    json=$(timeout $((DURATION + 20)) ip netns exec "$H1" \
        iperf3 -J -i 0 -c "$dst" -t "$DURATION" -P "$par" ${len:+-l "$len"}) \
        || { echo "FAIL: iperf3 $test ($mode) did not complete" >&2; exit 1; }
    if [ "$(jq -r '.error // empty' <<<"$json")" != "" ]; then
        echo "FAIL: iperf3 $test ($mode): $(jq -r .error <<<"$json")" >&2; exit 1
    fi
    emit "$mode" "$test" gbps "$rep" \
        "$(jq -r '.end.sum_received.bits_per_second / 1e9' <<<"$json")"
    emit "$mode" "$test" retransmits "$rep" \
        "$(jq -r '.end.sum_sent.retransmits // 0' <<<"$json")"
}

run_iperf_udp() {   # mode test rep dst rate len
    local mode=$1 test=$2 rep=$3 dst=$4 rate=$5 len=$6 json
    json=$(timeout $((DURATION + 20)) ip netns exec "$H1" \
        iperf3 -J -i 0 -c "$dst" -u -b "$rate" -l "$len" -t "$DURATION") \
        || { echo "FAIL: iperf3 $test ($mode) did not complete" >&2; exit 1; }
    if [ "$(jq -r '.error // empty' <<<"$json")" != "" ]; then
        echo "FAIL: iperf3 $test ($mode): $(jq -r .error <<<"$json")" >&2; exit 1
    fi
    emit "$mode" "$test" goodput_gbps "$rep" \
        "$(jq -r '.end.sum.bits_per_second * (100 - .end.sum.lost_percent) / 100 / 1e9' <<<"$json")"
    emit "$mode" "$test" lost_pct "$rep" \
        "$(jq -r '.end.sum.lost_percent' <<<"$json")"
}

run_netperf_rr() {  # mode test rep type
    local mode=$1 test=$2 rep=$3 type=$4 line
    line=$(timeout $((DURATION + 20)) ip netns exec "$H1" \
        netperf -H 10.0.2.1 -t "$type" -l "$DURATION" -P 0 -j -- \
        -o THROUGHPUT,MEAN_LATENCY,P90_LATENCY,P99_LATENCY 2>/dev/null | tail -n1) \
        || { echo "FAIL: netperf $test ($mode) did not complete" >&2; exit 1; }
    IFS=, read -r tps mean p90 p99 <<<"$line"
    emit "$mode" "$test" trans_per_s "$rep" "$tps"
    emit "$mode" "$test" mean_us "$rep" "$mean"
    emit "$mode" "$test" p90_us "$rep" "$p90"
    emit "$mode" "$test" p99_us "$rep" "$p99"
}

run_suite() {       # mode
    local mode=$1 rep
    log "$mode: warm-up"
    timeout 30 ip netns exec "$H1" iperf3 -i 0 -c 10.0.2.1 -t 5 >/dev/null

    for rep in $(seq 1 "$REPS"); do
        log "$mode: rep $rep/$REPS"
        if [ "$BIGFIB" = 1 ]; then
            # Per-probe throughput: TBL24 hit, TBL8 two-lookup, default route.
            run_iperf_tcp "$mode" probe_tbl24   "$rep" 10.0.8.8    4 ""
            run_iperf_tcp "$mode" probe_tbl8    "$rep" 10.0.9.17   4 ""
            run_iperf_tcp "$mode" probe_default "$rep" 99.99.99.99 4 ""
        else
            run_iperf_tcp "$mode" tcp_p1    "$rep" 10.0.2.1  1 ""
            run_iperf_tcp "$mode" tcp_p4    "$rep" 10.0.2.1  4 ""
            run_iperf_tcp "$mode" tcp_p16   "$rep" 10.0.2.1 16 ""
            run_iperf_tcp "$mode" tcp64_p1  "$rep" 10.0.2.1  1 64
            run_iperf_tcp "$mode" tcp64_p4  "$rep" 10.0.2.1  4 64
            run_iperf_udp "$mode" udp1400   "$rep" 10.0.2.1 10G 1400
            run_netperf_rr "$mode" tcp_rr   "$rep" TCP_RR
            run_netperf_rr "$mode" udp_rr   "$rep" UDP_RR
        fi
    done
}

# ---------------------------------------------------------------- summary

median() {          # newline-separated values on stdin
    sort -g | awk '{ v[NR] = $1 } END {
        if (NR == 0) { print "-"; exit }
        if (NR % 2)  printf "%.3f\n", v[(NR + 1) / 2]
        else         printf "%.3f\n", (v[NR / 2] + v[NR / 2 + 1]) / 2
    }'
}

summarize() {
    local summary="$OUTDIR/summary.md" key test metric k e ratio
    {
        echo "# Kernel vs eBPF forwarding — $( [ "$BIGFIB" = 1 ] && echo "large-FIB ($ROUTES routes, seed=$SEED)" || echo baseline ) results"
        echo
        echo "Medians of $REPS × ${DURATION}s runs. Host: $(uname -r), $(nproc) CPUs. Offloads: $( [ "$NO_OFFLOADS" = 1 ] && echo "TSO/GSO/GRO off (per-MTU packets)" || echo "veth defaults (kernel mode carries TSO/GRO super-frames)" ). $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo
        echo "| test | metric | kernel | ebpf | ebpf/kernel |"
        echo "|---|---|---|---|---|"
        # Distinct test/metric pairs in first-seen order.
        tail -n +2 "$RAW" | awk -F, '!seen[$2","$3]++ { print $2 "," $3 }' | \
        while IFS=, read -r test metric; do
            k=$(awk -F, -v t="$test" -v m="$metric" '$1=="kernel" && $2==t && $3==m {print $5}' "$RAW" | median)
            e=$(awk -F, -v t="$test" -v m="$metric" '$1=="ebpf"   && $2==t && $3==m {print $5}' "$RAW" | median)
            ratio="-"
            if [ "$k" != "-" ] && [ "$e" != "-" ]; then
                ratio=$(awk -v k="$k" -v e="$e" 'BEGIN { if (k > 0) printf "%.2f", e / k; else print "-" }')
            fi
            echo "| $test | $metric | $k | $e | $ratio |"
        done
    } | tee "$summary"
    echo
    echo "raw data: $RAW"
}

# --------------------------------------------------------------------- run

{
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "kernel: $(uname -r) ($(uname -m))"
    echo "cpus: $(nproc)"
    echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
    echo "cradle: $("$CRADLE" --version 2>/dev/null || echo "$CRADLE")"
    echo "git: $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo n/a)"
    echo "iperf3: $(iperf3 --version | head -1)"
    echo "duration: ${DURATION}s  reps: $REPS  bigfib: $BIGFIB  no_offloads: $NO_OFFLOADS"
} > "$OUTDIR/sysinfo.txt"

log "topology up (h1 ─ fwd ─ h2), results in $OUTDIR"
setup_topology

for mode in $MODES; do
    case "$mode" in
        ebpf)
            log "Mode A: eBPF forwarding (ip_forward=0, cradle serve)"
            setup_ebpf
            run_suite ebpf
            validate_ebpf
            stop_cradle
            ;;
        kernel)
            log "Mode B: kernel forwarding (cradle stopped, ip_forward=1)"
            setup_kernel
            run_suite kernel
            validate_kernel
            ;;
    esac
done

summarize
