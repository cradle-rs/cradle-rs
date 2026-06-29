#!/usr/bin/env bash
# Phase-1 L3 forwarding proof.
#
#   h1 (10.0.1.1) ──veth── fwd1 [ cradle eBPF ] fwd2 ──veth── h2 (10.0.2.1)
#
# Kernel IP forwarding is DISABLED on the forwarder, so if the ping crosses it
# was forwarded by the eBPF data plane, not the kernel.
#
# Run as root:  sudo scripts/netns-l3-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
H1=cr_h1; H2=cr_h2; FWD=cr_fwd
CFG="$(mktemp)"
LOG="$(mktemp)"
CRADLE_PID=""

cleanup() {
    [ -n "$CRADLE_PID" ] && kill "$CRADLE_PID" 2>/dev/null || true
    ip netns del "$H1"  2>/dev/null || true
    ip netns del "$H2"  2>/dev/null || true
    ip netns del "$FWD" 2>/dev/null || true
    rm -f "$CFG" "$LOG"
}
trap cleanup EXIT
cleanup   # sweep any stale state from a previous run

# --- topology ---
ip netns add "$H1"; ip netns add "$H2"; ip netns add "$FWD"
ip link add h1eth netns "$H1" type veth peer name fwd1 netns "$FWD"
ip link add h2eth netns "$H2" type veth peer name fwd2 netns "$FWD"

ip -n "$H1"  addr add 10.0.1.1/24   dev h1eth
ip -n "$H2"  addr add 10.0.2.1/24   dev h2eth
ip -n "$FWD" addr add 10.0.1.254/24 dev fwd1
ip -n "$FWD" addr add 10.0.2.254/24 dev fwd2

for ns_dev in "$H1:h1eth" "$H2:h2eth" "$FWD:fwd1" "$FWD:fwd2"; do
    ns="${ns_dev%%:*}"; dev="${ns_dev##*:}"
    ip -n "$ns" link set "$dev" up
    ip -n "$ns" link set lo up
done

ip -n "$H1" route add default via 10.0.1.254
ip -n "$H2" route add default via 10.0.2.254

# Only the eBPF data plane may forward.
ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0

H1MAC="$(ip -n "$H1" -br link show h1eth | awk '{print $3}')"
H2MAC="$(ip -n "$H2" -br link show h2eth | awk '{print $3}')"

cat > "$CFG" <<EOF
{
  "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ]
}
EOF

echo "== baseline (no cradle, ip_forward=0): expect FAIL =="
if ip netns exec "$H1" ping -c1 -W1 10.0.2.1 >/dev/null 2>&1; then
    echo "UNEXPECTED: baseline ping succeeded — kernel forwarding not actually disabled"
    exit 1
fi
echo "OK: cross-subnet ping fails without the eBPF datapath"

echo "== starting cradle in $FWD =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CFG" >"$LOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
if ! kill -0 "$CRADLE_PID" 2>/dev/null; then
    echo "FAIL: cradle exited early; log:"; cat "$LOG"; exit 1
fi

echo "== with cradle eBPF datapath: expect SUCCESS =="
if ip netns exec "$H1" ping -c2 -W2 10.0.2.1; then
    echo "PASS: h1 -> h2 forwarded by the eBPF data plane"
    RC=0
else
    echo "FAIL: ping did not cross the eBPF datapath; cradle log:"; cat "$LOG"
    RC=1
fi
exit $RC
