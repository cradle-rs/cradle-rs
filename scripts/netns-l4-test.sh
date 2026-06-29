#!/usr/bin/env bash
# Phase-3 L4 service load-balancing proof.
#
#                          ┌ fwd2 ──veth── b1 (10.0.2.1:8080  "backend-1")
#   cl(10.0.1.1) ─ fwd1 ─[ cradle eBPF L3+L4 ]
#                          └ fwd3 ──veth── b2 (10.0.3.1:8080  "backend-2")
#
#   service VIP 10.0.9.9:8080/tcp -> { b1, b2 }
#
# Kernel IP forwarding is DISABLED on the forwarder, so the only thing that can
# DNAT the VIP, connection-track the flow, reverse-NAT the replies, and route
# everything is the eBPF data plane. Each backend serves a distinct page so we
# can observe load balancing across new connections.
#
# Run as root:  sudo scripts/netns-l4-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
CL=l4_cl; FWD=l4_fwd; B1=l4_b1; B2=l4_b2
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

# client <-> fwd1
ip link add cleth netns "$CL" type veth peer name fwd1 netns "$FWD"
ip -n "$CL"  addr add 10.0.1.1/24   dev cleth; ip -n "$CL"  link set cleth up
ip -n "$FWD" addr add 10.0.1.254/24 dev fwd1;  ip -n "$FWD" link set fwd1 up
ip -n "$CL"  route add default via 10.0.1.254
# b1 <-> fwd2
ip link add b1eth netns "$B1" type veth peer name fwd2 netns "$FWD"
ip -n "$B1"  addr add 10.0.2.1/24   dev b1eth; ip -n "$B1"  link set b1eth up
ip -n "$FWD" addr add 10.0.2.254/24 dev fwd2;  ip -n "$FWD" link set fwd2 up
ip -n "$B1"  route add default via 10.0.2.254
# b2 <-> fwd3
ip link add b2eth netns "$B2" type veth peer name fwd3 netns "$FWD"
ip -n "$B2"  addr add 10.0.3.1/24   dev b2eth; ip -n "$B2"  link set b2eth up
ip -n "$FWD" addr add 10.0.3.254/24 dev fwd3;  ip -n "$FWD" link set fwd3 up
ip -n "$B2"  route add default via 10.0.3.254

ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0

CLMAC=$(ip -n "$CL" -br link show cleth | awk '{print $3}')
B1MAC=$(ip -n "$B1" -br link show b1eth | awk '{print $3}')
B2MAC=$(ip -n "$B2" -br link show b2eth | awk '{print $3}')

# distinct page per backend
mkdir -p "$WWW/b1" "$WWW/b2"
echo "backend-1" > "$WWW/b1/index.html"
echo "backend-2" > "$WWW/b2/index.html"
( cd "$WWW/b1" && ip netns exec "$B1" python3 -m http.server 8080 >/dev/null 2>&1 ) & SRV1=$!
( cd "$WWW/b2" && ip netns exec "$B2" python3 -m http.server 8080 >/dev/null 2>&1 ) & SRV2=$!

cat > "$CFG" <<EOF
{
  "ports":     [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true}, {"name":"fwd3","l3":true} ],
  "services":  [ {"vip":"10.0.9.9","port":8080,"proto":"tcp",
                  "backends":[ {"ip":"10.0.2.1","port":8080}, {"ip":"10.0.3.1","port":8080} ]} ]
}
EOF

echo "== baseline (no cradle, ip_forward=0): expect FAIL =="
if ip netns exec "$CL" curl -s --max-time 1 http://10.0.9.9:8080/ >/dev/null 2>&1; then
    echo "UNEXPECTED: VIP reachable without cradle"; exit 1
fi
echo "OK: VIP unreachable without the eBPF data plane"

echo "== starting cradle in $FWD =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CFG" >"$LOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
if ! kill -0 "$CRADLE_PID" 2>/dev/null; then echo "FAIL: cradle exited early:"; cat "$LOG"; exit 1; fi

echo "== 12 connections to the VIP (new flow each time) =="
ok=0; SEEN="$(mktemp)"
for i in $(seq 1 12); do
    r=$(ip netns exec "$CL" curl -s --max-time 2 http://10.0.9.9:8080/ 2>/dev/null | tr -d '[:space:]' || true)
    if [ -n "$r" ]; then ok=$((ok+1)); echo "$r" >> "$SEEN"; fi
done
ndistinct=$(sort -u "$SEEN" | grep -c .)
echo "  successful responses: $ok/12"
echo "  distinct backends seen: $(sort -u "$SEEN" | tr '\n' ' ')"
rm -f "$SEEN"

RC=0
[ "$ok" -ge 10 ] || { echo "FAIL: too few successful responses"; RC=1; }
[ "$ndistinct" -ge 2 ] || echo "  note: only one backend observed (random LB; rare but possible)"

echo "== conntrack entries created by the data plane (CT map) =="
ip netns exec "$FWD" bpftool map dump name CT 2>/dev/null | grep -c '^key' | sed 's/^/  CT entries: /' || true

if [ "$RC" = 0 ]; then echo "PASS: eBPF L4 service load balancing works"; else echo "cradle log:"; cat "$LOG"; fi
exit $RC
