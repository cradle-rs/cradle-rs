#!/usr/bin/env bash
# IPv6 L3 forwarding proof.
#
#   h1(2001:db8:1::1) ─ fwd1 ─[ cradle eBPF ]─ fwd2 ─ h2(2001:db8:2::1)
#
# Kernel IPv6 forwarding on the forwarder is disabled; cradle auto-derives the
# connected/local v6 routes from the port addresses, the kernel resolves next
# hops via NDP (bpf_redirect_neigh, AF_INET6). If the ping crosses, the eBPF
# data plane forwarded it.
#
# Run as root:  sudo scripts/netns-l3v6-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
H1=v6_h1; H2=v6_h2; FWD=v6_fwd
CFG="$(mktemp)"; LOG="$(mktemp)"; CRADLE_PID=""

cleanup() {
    [ -n "$CRADLE_PID" ] && kill "$CRADLE_PID" 2>/dev/null || true
    for n in "$H1" "$H2" "$FWD"; do ip netns del "$n" 2>/dev/null || true; done
    rm -f "$CFG" "$LOG"
}
trap cleanup EXIT
cleanup

for n in "$H1" "$H2" "$FWD"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add h1eth netns "$H1" type veth peer name fwd1 netns "$FWD"
ip link add h2eth netns "$H2" type veth peer name fwd2 netns "$FWD"

# Disable DAD so addresses are usable immediately.
for nd in "$H1:h1eth" "$H2:h2eth" "$FWD:fwd1" "$FWD:fwd2"; do
    ns="${nd%%:*}"; dev="${nd##*:}"
    ip netns exec "$ns" sysctl -wq "net.ipv6.conf.${dev}.accept_dad=0"
    ip -n "$ns" link set "$dev" up
done
ip -n "$H1"  addr add 2001:db8:1::1/64    dev h1eth nodad
ip -n "$H2"  addr add 2001:db8:2::1/64    dev h2eth nodad
ip -n "$FWD" addr add 2001:db8:1::ffff/64 dev fwd1  nodad
ip -n "$FWD" addr add 2001:db8:2::ffff/64 dev fwd2  nodad
ip -n "$H1"  route add default via 2001:db8:1::ffff
ip -n "$H2"  route add default via 2001:db8:2::ffff
ip netns exec "$FWD" sysctl -wq net.ipv6.conf.all.forwarding=0

echo '{ "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ] }' > "$CFG"

echo "== baseline (no cradle, v6 forwarding off): expect FAIL =="
if ip netns exec "$H1" ping -6 -c1 -W1 2001:db8:2::1 >/dev/null 2>&1; then
    echo "UNEXPECTED: reachable without cradle"; exit 1
fi
echo "OK"

echo "== start cradle (ports only; v6 connected/local auto-derived) =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CFG" >"$LOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
kill -0 "$CRADLE_PID" 2>/dev/null || { echo "FAIL: cradle exited:"; cat "$LOG"; exit 1; }

echo "== cradle FIB6 (expect 2001:db8:2::/64 connected) =="
ip netns exec "$FWD" bpftool map dump name FIB6 2>/dev/null | sed -n '1,10p'

echo "== with cradle: h1 -> h2 over IPv6 =="
if ip netns exec "$H1" ping -6 -c3 -W2 2001:db8:2::1; then
    echo "PASS: eBPF IPv6 forwarding works"
    RC=0
else
    echo "FAIL; cradle log:"; cat "$LOG"; RC=1
fi
exit $RC
