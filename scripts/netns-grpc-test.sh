#!/usr/bin/env bash
# Phase-4a gRPC control-API proof.
#
# Same L3 topology as netns-l3-test.sh, but cradle starts with NO config and
# the entire data plane (ports+attach, nexthops, routes, neighbors) is pushed
# over the gRPC control API by `cradle ctl apply`. If the ping then crosses, the
# control API drove the eBPF data plane end to end.
#
# Run as root:  sudo scripts/netns-grpc-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
GRPC="127.0.0.1:50151"
H1=gr_h1; H2=gr_h2; FWD=gr_fwd
CFG="$(mktemp)"; LOG="$(mktemp)"; CRADLE_PID=""

cleanup() {
    [ -n "$CRADLE_PID" ] && kill "$CRADLE_PID" 2>/dev/null || true
    for n in "$H1" "$H2" "$FWD"; do ip netns del "$n" 2>/dev/null || true; done
    rm -f "$CFG" "$LOG"
}
trap cleanup EXIT
cleanup

ip netns add "$H1"; ip netns add "$H2"; ip netns add "$FWD"
ip link add h1eth netns "$H1" type veth peer name fwd1 netns "$FWD"
ip link add h2eth netns "$H2" type veth peer name fwd2 netns "$FWD"
ip -n "$H1"  addr add 10.0.1.1/24   dev h1eth
ip -n "$H2"  addr add 10.0.2.1/24   dev h2eth
ip -n "$FWD" addr add 10.0.1.254/24 dev fwd1
ip -n "$FWD" addr add 10.0.2.254/24 dev fwd2
for nd in "$H1:h1eth" "$H2:h2eth" "$FWD:fwd1" "$FWD:fwd2"; do
    ip -n "${nd%%:*}" link set "${nd##*:}" up; ip -n "${nd%%:*}" link set lo up
done
ip -n "$H1" route add default via 10.0.1.254
ip -n "$H2" route add default via 10.0.2.254
ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0

H1MAC="$(ip -n "$H1" -br link show h1eth | awk '{print $3}')"
H2MAC="$(ip -n "$H2" -br link show h2eth | awk '{print $3}')"
cat > "$CFG" <<EOF
{
  "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ]
}
EOF

echo "== start cradle with NO config, only the gRPC API =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --grpc "$GRPC" >"$LOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
if ! kill -0 "$CRADLE_PID" 2>/dev/null; then echo "FAIL: cradle exited early:"; cat "$LOG"; exit 1; fi

echo "== before any gRPC config: expect ping FAIL =="
if ip netns exec "$H1" ping -c1 -W1 10.0.2.1 >/dev/null 2>&1; then
    echo "UNEXPECTED: ping worked before config was pushed"; exit 1
fi
echo "OK: nothing forwards until the control plane programs it"

echo "== push the data plane over gRPC =="
ip netns exec "$FWD" "$CRADLE" ctl --grpc "$GRPC" apply "$CFG"

echo "== after gRPC config: expect ping SUCCESS =="
if ip netns exec "$H1" ping -c2 -W2 10.0.2.1; then
    echo "PASS: gRPC control API programmed the eBPF data plane"
    RC=0
else
    echo "FAIL: ping did not cross; cradle log:"; cat "$LOG"; RC=1
fi
exit $RC
