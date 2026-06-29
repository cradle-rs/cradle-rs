#!/usr/bin/env bash
# IPv6 integration proof: a zebra-rs RIB route programs the cradle eBPF FIB6.
#
#   cl(2001:db8:1::1) ─ fwd1 ─[ cradle eBPF ]─ fwd2 ─ srv(2001:db8:2::1, +2001:db8:9::1/128)
#                              ▲ programmed over gRPC by zebra-rs (CRADLE_GRPC)
#
# cradle is bootstrapped with only the L3 ports (v6 connected/local auto-derive).
# zebra-rs installs a static route 2001:db8:9::/64 via the server; its FibHandle
# tees the v6 install to cradle. With kernel v6 forwarding off, cl reaches
# 2001:db8:9::1 only via the eBPF FIB6.
#
# Run as root:  sudo scripts/netns-zebrav6-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
ZEBRA="${ZEBRA:-/home/kunihiro/zebra-rs/target/debug/zebra-rs}"
YANG="${YANG:-/home/kunihiro/zebra-rs/zebra-rs/yang}"
GRPC="127.0.0.1:50151"
CL=z6_cl; FWD=z6_fwd; SRV=z6_srv
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
[ -x "$ZEBRA" ] || { echo "zebra-rs not found at $ZEBRA"; exit 1; }

for n in "$CL" "$FWD" "$SRV"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add cleth  netns "$CL"  type veth peer name fwd1 netns "$FWD"
ip link add srveth netns "$SRV" type veth peer name fwd2 netns "$FWD"
for nd in "$CL:cleth" "$SRV:srveth" "$FWD:fwd1" "$FWD:fwd2"; do
    ns="${nd%%:*}"; dev="${nd##*:}"
    ip netns exec "$ns" sysctl -wq "net.ipv6.conf.${dev}.accept_dad=0"
    ip -n "$ns" link set "$dev" up
done
ip -n "$CL"  addr add 2001:db8:1::1/64    dev cleth  nodad
ip -n "$SRV" addr add 2001:db8:2::1/64    dev srveth nodad
ip -n "$FWD" addr add 2001:db8:1::ffff/64 dev fwd1   nodad
ip -n "$FWD" addr add 2001:db8:2::ffff/64 dev fwd2   nodad
ip -n "$CL"  route add default via 2001:db8:1::ffff
ip -n "$SRV" route add default via 2001:db8:2::ffff
ip -n "$SRV" addr add 2001:db8:9::1/128 dev lo nodad   # destination behind the static route
ip netns exec "$FWD" sysctl -wq net.ipv6.conf.all.forwarding=0

echo '{ "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ] }' > "$CCFG"
cat > "$ZCFG" <<'EOF'
router:
  static:
    ipv6:
      route:
      - prefix: 2001:db8:9::/64
        nexthop:
        - address: 2001:db8:2::1
EOF

echo "== start cradle (ports only; v6 connected/local auto-derived) =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CCFG" --grpc "$GRPC" >"$CLOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
kill -0 "$CRADLE_PID" 2>/dev/null || { echo "FAIL: cradle exited:"; cat "$CLOG"; exit 1; }

echo "== baseline: 2001:db8:9::1 unreachable (no route yet) =="
ip netns exec "$CL" ping -6 -c1 -W1 2001:db8:9::1 >/dev/null 2>&1 && { echo "UNEXPECTED reachable"; exit 1; }
echo "OK"

echo "== start zebra-rs with CRADLE_GRPC (tees v6 RIB routes) =="
ip netns exec "$FWD" env RUST_LOG=info CRADLE_GRPC="$GRPC" \
    "$ZEBRA" --yang-path "$YANG" --config-file "$ZCFG" \
    --log-output=file --log-file="$ZLOG" >"$ZLOG" 2>&1 &
ZEBRA_PID=$!
sleep 4
kill -0 "$ZEBRA_PID" 2>/dev/null || { echo "FAIL: zebra exited:"; tail -25 "$ZLOG"; exit 1; }

echo "== cradle FIB6 (expect 2001:db8:9::/64) =="
ip netns exec "$FWD" bpftool map dump name FIB6 2>/dev/null | grep -A1 '40 00 00 00 20 01 0d b8  00 09' || \
  ip netns exec "$FWD" bpftool map dump name FIB6 2>/dev/null | sed -n '1,16p'

echo "== reachability: cl -> 2001:db8:9::1 (only via the zebra-rs route in eBPF) =="
if ip netns exec "$CL" ping -6 -c2 -W2 2001:db8:9::1; then
    echo "PASS: zebra-rs IPv6 RIB route programmed the cradle eBPF FIB6"
    RC=0
else
    echo "FAIL; zebra log:"; tail -25 "$ZLOG"; RC=1
fi
exit $RC
