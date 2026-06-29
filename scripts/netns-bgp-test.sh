#!/usr/bin/env bash
# Phase-4b BGP proof: a BGP-learned route programs the cradle eBPF FIB.
#
#   cl(10.0.1.1) ─ fwd1 ─[ fwd: cradle eBPF + zebra-rs BGP AS65001 ]─ fwd2 ─ peer(10.0.2.2)
#                              ▲ learns 10.9.9.0/24 via eBGP,            zebra-rs BGP AS65002,
#                                tees it to cradle (CRADLE_GRPC)         originates 10.9.9.0/24,
#                                                                        hosts 10.9.9.1
#
# The forwarder learns 10.9.9.0/24 from its eBGP peer; its FibHandle tees the
# install into cradle's eBPF FIB. Kernel forwarding on fwd is disabled, so cl can
# only reach 10.9.9.1 if the BGP route made it into the eBPF data plane.
#
# Run as root:  sudo scripts/netns-bgp-test.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CRADLE="${CRADLE:-$ROOT/target/debug/cradle}"
ZEBRA="${ZEBRA:-/home/kunihiro/zebra-rs/target/debug/zebra-rs}"
YANG="${YANG:-/home/kunihiro/zebra-rs/zebra-rs/yang}"
SOCK="$(mktemp -u --suffix=.sock)"; GRPC="unix:$SOCK"
CL=bg_cl; FWD=bg_fwd; PEER=bg_peer
CCFG="$(mktemp)"; ZFWD="$(mktemp --suffix=.yaml)"; ZPEER="$(mktemp --suffix=.yaml)"
CLOG="$(mktemp)"; ZFLOG="$(mktemp)"; ZPLOG="$(mktemp)"
CRADLE_PID=""; ZFWD_PID=""; ZPEER_PID=""

cleanup() {
    for p in "$CRADLE_PID" "$ZFWD_PID" "$ZPEER_PID"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    for n in "$CL" "$FWD" "$PEER"; do ip netns del "$n" 2>/dev/null || true; done
    rm -f "$CCFG" "$ZFWD" "$ZPEER" "$CLOG" "$SOCK" "$ZFLOG" "$ZPLOG"
}
trap cleanup EXIT
cleanup
[ -x "$ZEBRA" ] || { echo "zebra-rs not found at $ZEBRA"; exit 1; }

for n in "$CL" "$FWD" "$PEER"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add cleth   netns "$CL"   type veth peer name fwd1 netns "$FWD"
ip link add peereth netns "$PEER" type veth peer name fwd2 netns "$FWD"
ip -n "$CL"   addr add 10.0.1.1/24   dev cleth;   ip -n "$CL"   link set cleth up
ip -n "$PEER" addr add 10.0.2.2/24   dev peereth; ip -n "$PEER" link set peereth up
ip -n "$FWD"  addr add 10.0.1.254/24 dev fwd1;    ip -n "$FWD"  link set fwd1 up
ip -n "$FWD"  addr add 10.0.2.254/24 dev fwd2;    ip -n "$FWD"  link set fwd2 up
ip -n "$CL"   route add default via 10.0.1.254
ip -n "$PEER" route add default via 10.0.2.254
ip -n "$PEER" addr add 10.9.9.1/24 dev lo          # origin of 10.9.9.0/24, hosts 10.9.9.1
ip netns exec "$FWD" sysctl -wq net.ipv4.ip_forward=0

CLMAC=$(ip -n "$CL"   -br link show cleth   | awk '{print $3}')
PEERMAC=$(ip -n "$PEER" -br link show peereth | awk '{print $3}')

cat > "$CCFG" <<EOF
{
  "ports": [ {"name":"fwd1","l3":true}, {"name":"fwd2","l3":true} ]
}
EOF
# Bootstrap declares only the L3 ports: cradle auto-derives their connected +
# local routes from the kernel, the kernel resolves next-hop MACs
# (bpf_redirect_neigh), and zebra-rs supplies the BGP route over gRPC.

cat > "$ZFWD" <<'EOF'
router:
  bgp:
    global:
      as: 65001
      router-id: 10.0.2.254
    neighbor:
    - remote-address: 10.0.2.2
      timers:
        connect-retry-time: 5
      afi-safi:
      - name: ipv4
        enabled: true
      enabled: true
      remote-as: 65002
EOF

cat > "$ZPEER" <<'EOF'
router:
  bgp:
    global:
      as: 65002
      router-id: 10.0.2.2
    neighbor:
    - remote-address: 10.0.2.254
      transport:
        passive-mode: true
      timers:
        connect-retry-time: 5
      afi-safi:
      - name: ipv4
        enabled: true
      enabled: true
      remote-as: 65001
    afi-safi:
    - name: ipv4
      network:
      - prefix: 10.9.9.0/24
EOF

zebra() { ip netns exec "$1" env RUST_LOG=info ${3:-} "$ZEBRA" --yang-path "$YANG" --config-file "$2" --log-output=file --log-file="$4" >"$4" 2>&1 & echo $!; }

echo "== start cradle on fwd (bootstrap: ports, neighbors, connected routes) =="
ip netns exec "$FWD" env RUST_LOG=info "$CRADLE" serve --config "$CCFG" --grpc "$GRPC" >"$CLOG" 2>&1 &
CRADLE_PID=$!
sleep 1.5
kill -0 "$CRADLE_PID" 2>/dev/null || { echo "FAIL: cradle exited:"; cat "$CLOG"; exit 1; }

echo "== baseline: 10.9.9.1 unreachable (no BGP route yet) =="
ip netns exec "$CL" ping -c1 -W1 10.9.9.1 >/dev/null 2>&1 && { echo "UNEXPECTED reachable"; exit 1; }
echo "OK"

echo "== start zebra-rs on peer (AS65002, originates 10.9.9.0/24) =="
ZPEER_PID=$(zebra "$PEER" "$ZPEER" "" "$ZPLOG")
sleep 2  # let the peer's BGP listener come up before fwd connects (avoid connect-retry backoff)
echo "== start zebra-rs on fwd (AS65001, CRADLE_GRPC tee) =="
ZFWD_PID=$(zebra "$FWD" "$ZFWD" "CRADLE_GRPC=$GRPC" "$ZFLOG")

echo "== wait for eBGP to converge and the route to reach the eBPF FIB =="
ok=0
for i in $(seq 1 40); do
    if ip netns exec "$FWD" bpftool map dump name FIB4 2>/dev/null | grep -q '0a 09 09 00'; then ok=1; break; fi
    sleep 1
done
echo "  waited ${i}s; route in FIB4: $([ $ok = 1 ] && echo yes || echo no)"
echo "== cradle FIB4 =="; ip netns exec "$FWD" bpftool map dump name FIB4 2>/dev/null | sed -n '1,12p'

echo "== reachability: cl -> 10.9.9.1 (only via the BGP route in eBPF) =="
if [ "$ok" = 1 ] && ip netns exec "$CL" ping -c2 -W2 10.9.9.1; then
    echo "PASS: BGP-learned route programmed the cradle eBPF FIB"
    RC=0
else
    echo "FAIL."; echo "--- fwd zebra log ---"; tail -25 "$ZFLOG"; echo "--- peer zebra log ---"; tail -15 "$ZPLOG"
    RC=1
fi
exit $RC
