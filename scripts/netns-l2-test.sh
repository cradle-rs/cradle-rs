#!/usr/bin/env bash
# Phase-2 L2 switching proof.
#
#   h1(10.0.0.1) ─ sw1 ┐
#   h2(10.0.0.2) ─ sw2 ┼─ [ cradle eBPF switch, one L2 domain, NO kernel bridge ]
#   h3(10.0.0.3) ─ sw3 ┘
#
# The switch namespace has no bridge device, so if hosts can reach each other it
# is the eBPF data plane (MAC learning + flood + unicast forward) doing it.
#
# Run as root:  sudo scripts/netns-l2-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
SW=l2_sw; H1=l2_h1; H2=l2_h2; H3=l2_h3
CFG="$(mktemp)"; LOG="$(mktemp)"; CRADLE_PID=""

cleanup() {
    [ -n "$CRADLE_PID" ] && kill "$CRADLE_PID" 2>/dev/null || true
    for n in "$SW" "$H1" "$H2" "$H3"; do ip netns del "$n" 2>/dev/null || true; done
    rm -f "$CFG" "$LOG"
}
trap cleanup EXIT
cleanup

ip netns add "$SW"; ip netns add "$H1"; ip netns add "$H2"; ip netns add "$H3"
i=1
for h in "$H1" "$H2" "$H3"; do
    ip link add "h${i}eth" netns "$h" type veth peer name "sw${i}" netns "$SW"
    ip -n "$h"  addr add "10.0.0.${i}/24" dev "h${i}eth"
    ip -n "$h"  link set "h${i}eth" up; ip -n "$h" link set lo up
    ip -n "$SW" link set "sw${i}" up
    i=$((i+1))
done
ip -n "$SW" link set lo up

# All three switch ports in one L2 domain (vlan 0), no kernel bridge.
cat > "$CFG" <<'JSON'
{ "ports": [ {"name":"sw1","vlan":0}, {"name":"sw2","vlan":0}, {"name":"sw3","vlan":0} ] }
JSON

echo "== baseline (no cradle, no bridge): expect FAIL =="
if ip netns exec "$H1" ping -c1 -W1 10.0.0.2 >/dev/null 2>&1; then
    echo "UNEXPECTED: baseline ping succeeded — is there a bridge in $SW?"; exit 1
fi
echo "OK: hosts cannot reach each other without the eBPF switch"

echo "== starting cradle in $SW =="
ip netns exec "$SW" env RUST_LOG=info "$CRADLE" serve --config "$CFG" >"$LOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
if ! kill -0 "$CRADLE_PID" 2>/dev/null; then echo "FAIL: cradle exited early:"; cat "$LOG"; exit 1; fi

RC=0
echo "== with cradle eBPF switch =="
for target in "h1->h2 10.0.0.2" "h1->h3 10.0.0.3" "h2->h3 10.0.0.3"; do
    label="${target%% *}"; ip="${target##* }"; src="${label%%-*}"
    ns="l2_${src}"
    if ip netns exec "$ns" ping -c2 -W2 "$ip" >/dev/null 2>&1; then
        echo "  PASS: $label"
    else
        echo "  FAIL: $label"; RC=1
    fi
done

echo "== learned FDB (populated by the eBPF data plane) =="
ip netns exec "$SW" bpftool map dump name FDB 2>/dev/null | sed -n '1,12p' || true

[ "$RC" = 0 ] && echo "PASS: eBPF L2 switching works" || { echo "cradle log:"; cat "$LOG"; }
exit $RC
