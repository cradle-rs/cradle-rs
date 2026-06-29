#!/usr/bin/env bash
# IPv6 ECMP proof: a zebra-rs v6 multipath route load-balances across two paths.
#
#                          ┌ fwd2 ─ reth2(2001:db8:2::2) ┐
#   cl(2001:db8:1::/64) ─ fwd1 ─[ cradle eBPF ]          ├─ R (hosts 2001:db8:9::1)
#                          └ fwd3 ─ reth3(2001:db8:3::2) ┘
#
# zebra-rs installs static 2001:db8:9::/64 with two nexthops; the FibHandle tees
# an ECMP group to cradle. The v6 data plane hashes flows onto a member, so
# different source addresses egress different ports.
#
# Run as root:  sudo scripts/netns-ecmpv6-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
ZEBRA="${ZEBRA:-/home/kunihiro/zebra-rs/target/debug/zebra-rs}"
YANG="${YANG:-/home/kunihiro/zebra-rs/zebra-rs/yang}"
GRPC="127.0.0.1:50151"
CL=e6_cl; FWD=e6_fwd; R=e6_r
CCFG="$(mktemp)"; ZCFG="$(mktemp --suffix=.yaml)"; CLOG="$(mktemp)"; ZLOG="$(mktemp)"
CRADLE_PID=""; ZEBRA_PID=""

cleanup() {
    [ -n "$CRADLE_PID" ] && kill "$CRADLE_PID" 2>/dev/null || true
    [ -n "$ZEBRA_PID" ] && kill "$ZEBRA_PID" 2>/dev/null || true
    for n in "$CL" "$FWD" "$R"; do ip netns del "$n" 2>/dev/null || true; done
    rm -f "$CCFG" "$ZCFG" "$CLOG" "$ZLOG"
}
trap cleanup EXIT
cleanup
[ -x "$ZEBRA" ] || { echo "zebra-rs not found at $ZEBRA"; exit 1; }

for n in "$CL" "$FWD" "$R"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add cleth netns "$CL" type veth peer name fwd1 netns "$FWD"
ip link add reth2 netns "$R"  type veth peer name fwd2 netns "$FWD"
ip link add reth3 netns "$R"  type veth peer name fwd3 netns "$FWD"
for nd in "$CL:cleth" "$FWD:fwd1" "$FWD:fwd2" "$FWD:fwd3" "$R:reth2" "$R:reth3"; do
    ns="${nd%%:*}"; dev="${nd##*:}"
    ip netns exec "$ns" sysctl -wq "net.ipv6.conf.${dev}.accept_dad=0"
    ip -n "$ns" link set "$dev" up
done
ip -n "$CL"  addr add 2001:db8:1::1/64    dev cleth nodad
ip -n "$FWD" addr add 2001:db8:1::ffff/64 dev fwd1  nodad
ip -n "$FWD" addr add 2001:db8:2::ffff/64 dev fwd2  nodad
ip -n "$FWD" addr add 2001:db8:3::ffff/64 dev fwd3  nodad
ip -n "$R"   addr add 2001:db8:2::2/64    dev reth2 nodad
ip -n "$R"   addr add 2001:db8:3::2/64    dev reth3 nodad
ip -n "$R"   addr add 2001:db8:9::1/128   dev lo    nodad
ip -n "$CL"  route add default via 2001:db8:1::ffff
ip -n "$R"   route add 2001:db8:1::/64 via 2001:db8:2::ffff
ip netns exec "$FWD" sysctl -wq net.ipv6.conf.all.forwarding=0
for i in $(seq 10 19); do ip -n "$CL" addr add "2001:db8:1::$i/64" dev cleth nodad; done

echo '{ "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true}, {"name":"fwd3","l3":true} ] }' > "$CCFG"
cat > "$ZCFG" <<'EOF'
router:
  static:
    ipv6:
      route:
      - prefix: 2001:db8:9::/64
        nexthop:
        - address: 2001:db8:2::2
        - address: 2001:db8:3::2
EOF

echo "== start cradle (ports only) + zebra-rs (v6 ECMP static route) =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CCFG" --grpc "$GRPC" >"$CLOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
kill -0 "$CRADLE_PID" 2>/dev/null || { echo "FAIL: cradle exited:"; cat "$CLOG"; exit 1; }
ip netns exec "$FWD" env RUST_LOG=info CRADLE_GRPC="$GRPC" \
    "$ZEBRA" --yang-path "$YANG" --config-file "$ZCFG" --log-output=file --log-file="$ZLOG" >"$ZLOG" 2>&1 &
ZEBRA_PID=$!
for i in $(seq 1 15); do
    ip netns exec "$FWD" bpftool map dump name FIB6 2>/dev/null | grep -q '20 01 0d b8  00 09' && break; sleep 1
done

echo "== eBPF ECMP state =="
echo "-- NHGROUP groups --"; ip netns exec "$FWD" bpftool map dump name NHGROUP 2>/dev/null | grep -c '^key' | sed 's/^/  groups: /'
echo "-- NHGROUP_MEMBER --"; ip netns exec "$FWD" bpftool map dump name NHGROUP_MEMBER 2>/dev/null | grep -c '^key' | sed 's/^/  members: /'

tx() { ip -n "$FWD" -s link show "$1" | awk '/TX:/{getline; print $2}'; }
b2=$(tx fwd2); b3=$(tx fwd3)
echo "== ping6 2001:db8:9::1 from 11 source addresses =="
ok=0
for s in 1 $(seq 10 19); do
    ip netns exec "$CL" ping -6 -c1 -W2 -I "2001:db8:1::$s" 2001:db8:9::1 >/dev/null 2>&1 && ok=$((ok+1))
done
a2=$(tx fwd2); a3=$(tx fwd3); d2=$((a2-b2)); d3=$((a3-b3))
echo "  replies: $ok/11    fwd2 +$d2    fwd3 +$d3"

RC=0
[ "$ok" -ge 9 ] || { echo "FAIL: too few replies"; RC=1; }
{ [ "$d2" -gt 0 ] && [ "$d3" -gt 0 ]; } || { echo "FAIL: traffic not balanced across both ECMP members"; RC=1; }
[ "$RC" = 0 ] && echo "PASS: eBPF IPv6 ECMP load-balanced a zebra-rs v6 multipath route" || { echo "zebra log:"; tail -20 "$ZLOG"; }
exit $RC
