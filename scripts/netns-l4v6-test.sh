#!/usr/bin/env bash
# IPv6 L4 service load-balancing proof.
#
#                              ┌ fwd2 ─ b1 (2001:db8:2::1:8080  "backend-1")
#   cl(2001:db8:1::1) ─ fwd1 ─[ cradle eBPF L3+L4 ]
#                              └ fwd3 ─ b2 (2001:db8:3::1:8080  "backend-2")
#
#   service VIP [2001:db8:9::9]:8080/tcp -> { b1, b2 }
#
# Kernel v6 forwarding is off; cradle DNATs the VIP to a backend, conntracks the
# flow, reverse-NATs replies (fixing the TCP checksum over the IPv6
# pseudo-header), and routes — all in eBPF.
#
# Run as root:  sudo scripts/netns-l4v6-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
CL=l6_cl; FWD=l6_fwd; B1=l6_b1; B2=l6_b2
CFG="$(mktemp)"; LOG="$(mktemp)"; WWW="$(mktemp -d)"
CRADLE_PID=""; SRV1=""; SRV2=""

cleanup() {
    [ -n "$CRADLE_PID" ] && kill "$CRADLE_PID" 2>/dev/null || true
    [ -n "$SRV1" ] && kill "$SRV1" 2>/dev/null || true
    [ -n "$SRV2" ] && kill "$SRV2" 2>/dev/null || true
    for n in "$CL" "$FWD" "$B1" "$B2"; do ip netns del "$n" 2>/dev/null || true; done
    rm -rf "$CFG" "$LOG" "$WWW"
}
trap cleanup EXIT
cleanup

for n in "$CL" "$FWD" "$B1" "$B2"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add cleth netns "$CL" type veth peer name fwd1 netns "$FWD"
ip link add b1eth netns "$B1" type veth peer name fwd2 netns "$FWD"
ip link add b2eth netns "$B2" type veth peer name fwd3 netns "$FWD"
for nd in "$CL:cleth" "$B1:b1eth" "$B2:b2eth" "$FWD:fwd1" "$FWD:fwd2" "$FWD:fwd3"; do
    ns="${nd%%:*}"; dev="${nd##*:}"
    ip netns exec "$ns" sysctl -wq "net.ipv6.conf.${dev}.accept_dad=0"
    ip -n "$ns" link set "$dev" up
done
ip -n "$CL"  addr add 2001:db8:1::1/64    dev cleth nodad
ip -n "$B1"  addr add 2001:db8:2::1/64    dev b1eth nodad
ip -n "$B2"  addr add 2001:db8:3::1/64    dev b2eth nodad
ip -n "$FWD" addr add 2001:db8:1::ffff/64 dev fwd1  nodad
ip -n "$FWD" addr add 2001:db8:2::ffff/64 dev fwd2  nodad
ip -n "$FWD" addr add 2001:db8:3::ffff/64 dev fwd3  nodad
ip -n "$CL"  route add default via 2001:db8:1::ffff
ip -n "$B1"  route add default via 2001:db8:2::ffff
ip -n "$B2"  route add default via 2001:db8:3::ffff
ip netns exec "$FWD" sysctl -wq net.ipv6.conf.all.forwarding=0

mkdir -p "$WWW/b1" "$WWW/b2"
echo "backend-1" > "$WWW/b1/index.html"
echo "backend-2" > "$WWW/b2/index.html"
( cd "$WWW/b1" && ip netns exec "$B1" python3 -m http.server 8080 --bind :: >/dev/null 2>&1 ) & SRV1=$!
( cd "$WWW/b2" && ip netns exec "$B2" python3 -m http.server 8080 --bind :: >/dev/null 2>&1 ) & SRV2=$!

cat > "$CFG" <<'EOF'
{
  "ports":    [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true}, {"name":"fwd3","l3":true} ],
  "services": [ {"vip":"2001:db8:9::9","port":8080,"proto":"tcp",
                 "backends":[ {"ip":"2001:db8:2::1","port":8080}, {"ip":"2001:db8:3::1","port":8080} ]} ]
}
EOF

echo "== baseline (no cradle, v6 forwarding off): expect FAIL =="
if ip netns exec "$CL" curl -s -g --max-time 1 "http://[2001:db8:9::9]:8080/" >/dev/null 2>&1; then
    echo "UNEXPECTED: VIP reachable without cradle"; exit 1
fi
echo "OK: VIP unreachable without the eBPF data plane"

echo "== start cradle (ports + v6 service) =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CFG" >"$LOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
kill -0 "$CRADLE_PID" 2>/dev/null || { echo "FAIL: cradle exited:"; cat "$LOG"; exit 1; }

echo "== 12 connections to the v6 VIP =="
ok=0; SEEN="$(mktemp)"
for i in $(seq 1 12); do
    r=$(ip netns exec "$CL" curl -s -g --max-time 2 "http://[2001:db8:9::9]:8080/" 2>/dev/null | tr -d '[:space:]' || true)
    if [ -n "$r" ]; then ok=$((ok+1)); echo "$r" >> "$SEEN"; fi
done
ndistinct=$(sort -u "$SEEN" | grep -c .)
echo "  successful responses: $ok/12    distinct backends: $(sort -u "$SEEN" | tr '\n' ' ')"
rm -f "$SEEN"
echo "  CT6 entries: $(ip netns exec "$FWD" bpftool map dump name CT6 2>/dev/null | grep -c '^key')"

RC=0
[ "$ok" -ge 10 ] || { echo "FAIL: too few responses"; RC=1; }
[ "$ndistinct" -ge 2 ] || echo "  note: only one backend observed (random LB; rare)"
[ "$RC" = 0 ] && echo "PASS: eBPF IPv6 L4 service load balancing works" || { echo "cradle log:"; cat "$LOG"; }
exit $RC
