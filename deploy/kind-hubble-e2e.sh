#!/usr/bin/env bash
# End-to-end: the stock Hubble Relay + UI observing a cradle CNI cluster (H3 of
# docs/design/hubble.md).
#
# Brings up a single-node kind cluster with cradle as the CNI, enables cradle's
# Hubble Observer + Peer API (deploy/hubble-cradle-patch.yaml), deploys the
# UNMODIFIED hubble-relay + hubble-ui (deploy/hubble.yaml), generates pod +
# service traffic, and proves the stock `hubble` CLI — talking to the RELAY,
# not the node — sees cradle's datapath flows (FORWARDED pod traffic and a
# TRANSLATED service access), and that hubble-ui serves its page.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-cradle-hubble-e2e}
HUBBLE=${HUBBLE:-"$HOME/.cache/cradle-bdd/hubble"}
RELAY_IMAGE=${RELAY_IMAGE:-quay.io/cilium/hubble-relay:v1.19.5}
UI_IMAGE=${UI_IMAGE:-quay.io/cilium/hubble-ui:v0.13.2}
UI_BACKEND_IMAGE=${UI_BACKEND_IMAGE:-quay.io/cilium/hubble-ui-backend:v0.13.2}

[ -x "$HUBBLE" ] || { echo "need the stock hubble CLI at $HUBBLE (run deploy/fetch-hubble.sh)" >&2; exit 1; }

echo "==> building release binaries"
cargo build --release -p cradle -p cradle-k8s
rustup target add aarch64-unknown-linux-musl >/dev/null
RUSTFLAGS="-C target-feature=+crt-static -C linker=rust-lld" \
    cargo build --release -p cradle-cni --target aarch64-unknown-linux-musl

echo "==> building the node image"
docker build -t cradle:dev -f deploy/Dockerfile .

echo "==> creating the kind cluster (default CNI disabled)"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --config deploy/kind-config.yaml --wait 0s
kind load docker-image cradle:dev --name "$CLUSTER"
for img in "$RELAY_IMAGE" "$UI_IMAGE" "$UI_BACKEND_IMAGE"; do
    docker pull -q "$img"
    kind load docker-image "$img" --name "$CLUSTER"
done

echo "==> installing cradle (+ vendored cilium.io CRDs) with Hubble enabled"
kubectl apply -f deploy/crds/ciliumendpoints.yaml -f deploy/crds/ciliumnodes.yaml
kubectl apply -f deploy/cradle.yaml
kubectl -n cradle-system patch ds cradle --patch-file deploy/hubble-cradle-patch.yaml
kubectl -n cradle-system rollout status ds/cradle --timeout=180s
kubectl wait node --all --for=condition=Ready --timeout=180s

echo "==> deploying hubble-relay + hubble-ui"
kubectl apply -f deploy/hubble.yaml
kubectl -n cradle-system rollout status deploy/hubble-relay --timeout=180s
kubectl -n cradle-system rollout status deploy/hubble-ui --timeout=180s

echo "==> deploying the smoke workload"
kubectl create deployment web --image=nginx --replicas=2
kubectl expose deployment web --port 80
kubectl run client --image=curlimages/curl --restart=Never --command -- sleep 3600
kubectl wait deploy/web --for=condition=Available --timeout=300s
kubectl wait pod/client --for=condition=Ready --timeout=300s

echo "==> generating traffic (pod -> ClusterIP, repeated)"
VIP=$(kubectl get svc web -o jsonpath='{.spec.clusterIP}')
for i in $(seq 1 10); do
    kubectl exec client -- curl -s --max-time 3 "http://$VIP/" >/dev/null 2>&1 || true
done

PF_PID=""
cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null || true; }
trap cleanup EXIT

echo "==> port-forwarding hubble-relay and querying it with the stock hubble CLI"
kubectl -n cradle-system port-forward svc/hubble-relay 4245:80 >/dev/null 2>&1 &
PF_PID=$!
sleep 3

# Capture into a variable — never `hubble … | grep -q`: with `set -o pipefail`,
# grep -q closing the pipe on an early match kills hubble with SIGPIPE and the
# pipeline reports failure even though the match succeeded.
observe() { "$HUBBLE" observe --server localhost:4245 --last 500 -o json 2>/dev/null; }
status() { "$HUBBLE" --server localhost:4245 status 2>/dev/null; }

# The relay discovers the node through the Peer service and dials its Observer;
# that can take a reconnect interval (relay --retry-timeout is 30s), so wait
# until it reports a connected node before asserting on flows.
echo "==> waiting for the relay to connect to the node"
relay_ready=0
for i in $(seq 1 45); do
    kubectl exec client -- curl -s --max-time 3 "http://$VIP/" >/dev/null 2>&1 || true
    st=$(status)
    if [[ "$st" == *"Connected Nodes: 1/1"* || "$st" =~ Connected\ Nodes:\ [1-9] ]]; then
        echo "$st" | sed 's/^/    /'
        relay_ready=1; break
    fi
    sleep 2
done
[ "$relay_ready" = 1 ] || { echo "✗ relay never reported a connected node" >&2; exit 1; }

check_relay() {
    local want=$1 desc=$2 out
    for i in $(seq 1 30); do
        # regenerate traffic each round so the relay's buffer stays warm
        kubectl exec client -- curl -s --max-time 3 "http://$VIP/" >/dev/null 2>&1 || true
        out=$(observe)
        if [[ "$out" == *"\"$want\""* ]]; then
            echo "✓ hubble-relay surfaced a $want flow ($desc)"
            return 0
        fi
        sleep 2
    done
    echo "✗ hubble-relay never surfaced a $want flow ($desc)" >&2
    echo "--- last observe output ---" >&2
    observe | tail -5 >&2
    exit 1
}

# A pod->ClusterIP curl is a forwarded pod flow plus a service DNAT: the relay
# should aggregate both from this node's Observer.
check_relay FORWARDED "pod traffic aggregated through Relay"
check_relay TRANSLATED "service DNAT observed through Relay"

echo "==> checking hubble-ui serves its page"
kubectl -n cradle-system port-forward svc/hubble-ui 8080:80 >/dev/null 2>&1 &
UI_PID=$!
sleep 3
ui_ok=0
for i in $(seq 1 15); do
    page=$(curl -s --max-time 3 http://localhost:8080/ 2>/dev/null || true)
    if [[ "$page" == *"Hubble UI"* || "$page" == *"<!doctype html"* || "$page" == *"<html"* ]]; then
        ui_ok=1; break
    fi
    sleep 2
done
kill "$UI_PID" 2>/dev/null || true
[ "$ui_ok" = 1 ] && echo "✓ hubble-ui is serving (service map reachable at :8080)" \
    || { echo "✗ hubble-ui did not serve a page" >&2; exit 1; }

echo "==> ✓ Hubble Relay + UI e2e passed: the stock hubble stack observes cradle flows"
