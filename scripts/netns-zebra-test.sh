#!/usr/bin/env bash
# Phase-4b proof: a zebra-rs RIB route programs the cradle eBPF FIB.
#
#   cl(10.0.1.1) ─ fwd1 ─[ cradle eBPF datapath ]─ fwd2 ─ srv(10.0.2.1, +10.9.9.1/32 on lo)
#                          ▲ programmed via gRPC by zebra-rs (CRADLE_GRPC)
#
# cradle is bootstrapped with the ports/neighbors and the two *connected*
# routes only. The route to 10.9.9.0/24 is installed by zebra-rs from a static
# route in its config; its FibHandle tees the install to cradle's gRPC API. With
# kernel forwarding disabled, the only way cl can reach 10.9.9.1 is if the
# zebra-rs route landed in the eBPF FIB.
#
# Run as root:  sudo scripts/netns-zebra-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
ZEBRA="${ZEBRA:-/home/kunihiro/zebra-rs/target/debug/zebra-rs}"
YANG="${YANG:-/home/kunihiro/zebra-rs/zebra-rs/yang}"
GRPC="127.0.0.1:50151"
CL=zb_cl; FWD=zb_fwd; SRV=zb_srv
CCFG="$(mktemp)"; ZCFG="$(mktemp --suffix=.yaml)"; CLOG="$(mktemp)"; ZLOG="$(mktemp)"
CRADLE_PID=""; ZEBRA_PID=""

cleanup() {
    [ -n "$CRADLE_PID" ] && kill "$CRADLE_PID" 2>/dev/null || true
    [ -n "$ZEBRA_PID" ] && kill "$ZEBRA_PID" 2>/dev/null || true
    for n in "$CL" "$FWD" "$SRV"; do ip netns del "$n" 2>/dev/null || true; done
    rm -f "$CCFG" "$ZCFG" "$CLOG" "$ZLOG"
}
trap cleanup EXIT
cleanup

[ -x "$ZEBRA" ] || { echo "zebra-rs binary not found at $ZEBRA"; exit 1; }

for n in "$CL" "$FWD" "$SRV"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add cleth  netns "$CL"  type veth peer name fwd1 netns "$FWD"
ip link add srveth netns "$SRV" type veth peer name fwd2 netns "$FWD"
ip -n "$CL"  addr add 10.0.1.1/24   dev cleth;  ip -n "$CL"  link set cleth up
ip -n "$SRV" addr add 10.0.2.1/24   dev srveth; ip -n "$SRV" link set srveth up
ip -n "$FWD" addr add 10.0.1.254/24 dev fwd1;   ip -n "$FWD" link set fwd1 up
ip -n "$FWD" addr add 10.0.2.254/24 dev fwd2;   ip -n "$FWD" link set fwd2 up
ip -n "$CL"  route add default via 10.0.1.254
ip -n "$SRV" route add default via 10.0.2.254
ip -n "$SRV" addr add 10.9.9.1/32 dev lo          # destination behind the static route
ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0

CLMAC=$(ip -n "$CL"  -br link show cleth  | awk '{print $3}')
SRVMAC=$(ip -n "$SRV" -br link show srveth | awk '{print $3}')

# cradle bootstrap: ports + neighbors + the two connected routes only.
cat > "$CCFG" <<EOF
{
  "ports":     [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ],
  "nexthops":  [ {"id":100,"oif":"fwd1"}, {"id":101,"oif":"fwd2"} ],
  "routes":    [ {"prefix":"10.0.1.0/24","nexthop":100}, {"prefix":"10.0.2.0/24","nexthop":101} ]
}
EOF

# zebra-rs config: a single static route to 10.9.9.0/24 via the server.
cat > "$ZCFG" <<'EOF'
router:
  static:
    ipv4:
      route:
      - prefix: 10.9.9.0/24
        nexthop:
        - address: 10.0.2.1
EOF

echo "== start cradle (bootstrap: ports, neighbors, connected routes only) =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CCFG" --grpc "$GRPC" >"$CLOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
kill -0 "$CRADLE_PID" 2>/dev/null || { echo "FAIL: cradle exited:"; cat "$CLOG"; exit 1; }

echo "== baseline: 10.9.9.1 not reachable yet (no route in eBPF FIB) =="
if ip netns exec "$CL" ping -c1 -W1 10.9.9.1 >/dev/null 2>&1; then
    echo "UNEXPECTED: reachable before zebra-rs installed the route"; exit 1
fi
echo "OK"

echo "== start zebra-rs with CRADLE_GRPC (tees RIB routes to cradle) =="
ip netns exec "$FWD" env RUST_LOG=info CRADLE_GRPC="$GRPC" \
    "$ZEBRA" --yang-path "$YANG" --config-file "$ZCFG" \
    --log-output=file --log-file="$ZLOG" >"$ZLOG" 2>&1 &
ZEBRA_PID=$!
sleep 4
kill -0 "$ZEBRA_PID" 2>/dev/null || { echo "FAIL: zebra-rs exited:"; tail -30 "$ZLOG"; exit 1; }

echo "== cradle FIB4 after zebra-rs install (expect 10.9.9.0/24 = 0a 09 09 00) =="
ip netns exec "$FWD" bpftool map dump name FIB4 2>/dev/null | sed -n '1,12p'

echo "== reachability test: cl -> 10.9.9.1 (only via the zebra-rs route in eBPF) =="
if ip netns exec "$CL" ping -c2 -W2 10.9.9.1; then
    echo "PASS: zebra-rs RIB route programmed the cradle eBPF FIB"
    RC=0
else
    echo "FAIL: not reachable."
    echo "--- cradle NEXTHOPS ---"; ip netns exec "$FWD" bpftool map dump name NEXTHOPS 2>/dev/null | head
    echo "--- zebra-rs log tail ---"; tail -30 "$ZLOG"
    RC=1
fi
exit $RC
