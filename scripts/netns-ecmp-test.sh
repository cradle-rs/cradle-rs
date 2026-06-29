#!/usr/bin/env bash
# ECMP proof: a zebra-rs multipath route load-balances across two paths in eBPF.
#
#                       ┌ fwd2 ──veth── Reth2(10.0.2.2) ┐
#   cl(10.0.1.0/24) ─ fwd1 ─[ cradle eBPF ]             ├─ R (hosts 10.9.9.1)
#                       └ fwd3 ──veth── Reth3(10.0.3.2) ┘
#
# zebra-rs installs a static route 10.9.9.0/24 with TWO nexthops (10.0.2.2 via
# fwd2, 10.0.3.2 via fwd3). Its FibHandle tees this as an ECMP nexthop group to
# cradle. The eBPF data plane hashes each flow onto a member, so different source
# addresses take different egress ports — both fwd2 and fwd3 carry traffic.
#
# Run as root:  sudo scripts/netns-ecmp-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
ZEBRA="${ZEBRA:-/home/kunihiro/zebra-rs/target/debug/zebra-rs}"
YANG="${YANG:-/home/kunihiro/zebra-rs/zebra-rs/yang}"
GRPC="127.0.0.1:50151"
CL=ec_cl; FWD=ec_fwd; R=ec_r
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
ip link add cleth netns "$CL" type veth peer name fwd1  netns "$FWD"
ip link add reth2 netns "$R"  type veth peer name fwd2  netns "$FWD"
ip link add reth3 netns "$R"  type veth peer name fwd3  netns "$FWD"
ip -n "$CL"  addr add 10.0.1.1/24   dev cleth; ip -n "$CL"  link set cleth up
ip -n "$FWD" addr add 10.0.1.254/24 dev fwd1;  ip -n "$FWD" link set fwd1 up
ip -n "$FWD" addr add 10.0.2.254/24 dev fwd2;  ip -n "$FWD" link set fwd2 up
ip -n "$FWD" addr add 10.0.3.254/24 dev fwd3;  ip -n "$FWD" link set fwd3 up
ip -n "$R"   addr add 10.0.2.2/24   dev reth2; ip -n "$R"   link set reth2 up
ip -n "$R"   addr add 10.0.3.2/24   dev reth3; ip -n "$R"   link set reth3 up
ip -n "$R"   addr add 10.9.9.1/32   dev lo
ip -n "$CL"  route add default via 10.0.1.254
ip -n "$R"   route add 10.0.1.0/24 via 10.0.2.254
ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0
# ECMP forward path and reverse path can use different R interfaces; relax rpf.
ip netns exec "$R" sysctl -wq net.ipv4.conf.all.rp_filter=0
# extra client source addresses so flows hash across both members
for i in $(seq 10 19); do ip -n "$CL" addr add "10.0.1.$i/24" dev cleth; done

echo '{ "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true}, {"name":"fwd3","l3":true} ] }' > "$CCFG"
cat > "$ZCFG" <<'EOF'
router:
  static:
    ipv4:
      route:
      - prefix: 10.9.9.0/24
        nexthop:
        - address: 10.0.2.2
        - address: 10.0.3.2
EOF

echo "== start cradle (ports only) + zebra-rs (ECMP static route) =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CCFG" --grpc "$GRPC" >"$CLOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
kill -0 "$CRADLE_PID" 2>/dev/null || { echo "FAIL: cradle exited:"; cat "$CLOG"; exit 1; }
ip netns exec "$FWD" env RUST_LOG=info CRADLE_GRPC="$GRPC" \
    "$ZEBRA" --yang-path "$YANG" --config-file "$ZCFG" --log-output=file --log-file="$ZLOG" >"$ZLOG" 2>&1 &
ZEBRA_PID=$!
for i in $(seq 1 15); do
    ip netns exec "$FWD" bpftool map dump name FIB4 2>/dev/null | grep -q '0a 09 09 00' && break; sleep 1
done

echo "== eBPF ECMP state =="
echo "-- FIB4 (10.9.9.0/24 should carry flags=08 ECMP) --"
ip netns exec "$FWD" bpftool map dump name FIB4 2>/dev/null | grep -A0 '0a 09 09 00'
echo "-- NHGROUP (group -> member count) --"; ip netns exec "$FWD" bpftool map dump name NHGROUP 2>/dev/null | grep -c '^key' | sed 's/^/  groups: /'
echo "-- NHGROUP_MEMBER count --"; ip netns exec "$FWD" bpftool map dump name NHGROUP_MEMBER 2>/dev/null | grep -c '^key' | sed 's/^/  members: /'

tx() { ip -n "$FWD" -s link show "$1" | awk '/TX:/{getline; print $2}'; }
b2=$(tx fwd2); b3=$(tx fwd3)
echo "== ping 10.9.9.1 from 11 source addresses (hash across members) =="
ok=0
for s in 1 $(seq 10 19); do
    ip netns exec "$CL" ping -c1 -W2 -I "10.0.1.$s" 10.9.9.1 >/dev/null 2>&1 && ok=$((ok+1))
done
a2=$(tx fwd2); a3=$(tx fwd3)
d2=$((a2-b2)); d3=$((a3-b3))
echo "  replies: $ok/11    fwd2 fwd-tx +$d2    fwd3 fwd-tx +$d3"

RC=0
[ "$ok" -ge 9 ] || { echo "FAIL: too few replies"; RC=1; }
{ [ "$d2" -gt 0 ] && [ "$d3" -gt 0 ]; } || { echo "FAIL: traffic not balanced across both ECMP members"; RC=1; }
[ "$RC" = 0 ] && echo "PASS: eBPF ECMP load-balanced a zebra-rs multipath route across both paths" || { echo "zebra log:"; tail -20 "$ZLOG"; }
exit $RC
