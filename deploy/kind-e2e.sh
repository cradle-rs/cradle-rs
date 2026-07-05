#!/usr/bin/env bash
# End-to-end smoke test: cradle as the CNI of a kind cluster.
#
# Builds the release binaries (cradle-cni as static musl — it executes on the
# kind node's own filesystem), bakes the node image, brings up a single-node
# kind cluster with the default CNI disabled, installs the cradle DaemonSet,
# and curls an nginx ClusterIP from a client pod — the VIP exists only in the
# eBPF SERVICES map, so a served page proves the datapath DNAT end to end.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-cradle-e2e}

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

echo "==> installing cradle"
kubectl apply -f deploy/cradle.yaml
kubectl -n cradle-system rollout status ds/cradle --timeout=180s
kubectl wait node --all --for=condition=Ready --timeout=180s

echo "==> deploying the smoke workload"
kubectl create deployment web --image=nginx --replicas=2
kubectl expose deployment web --port 80
kubectl run client --image=curlimages/curl --restart=Never --command -- sleep 3600
kubectl wait deploy/web --for=condition=Available --timeout=300s
kubectl wait pod/client --for=condition=Ready --timeout=300s

VIP=$(kubectl get svc web -o jsonpath='{.spec.clusterIP}')
echo "==> curling ClusterIP $VIP from the client pod"
for i in $(seq 1 30); do
    if kubectl exec client -- curl -s --max-time 3 "http://$VIP/" | grep -q "Welcome to nginx"; then
        # kube-proxy also runs (it serves the host-network-backed services
        # cradle skips), so prove the VIP was NATed in eBPF, not iptables.
        DNAT=$(kubectl -n cradle-system exec ds/cradle -c cradle -- \
            cradle ctl --grpc unix:/run/cradle/cradle.sock stats \
            | awk '$1=="l4_dnat"{print $2}')
        if [ "${DNAT:-0}" -gt 0 ]; then
            echo "✓ ClusterIP $VIP served through the cradle eBPF datapath (l4_dnat=$DNAT)"
            exit 0
        fi
        echo "✗ VIP answered but l4_dnat=0 — served by kube-proxy, not eBPF" >&2
        exit 1
    fi
    sleep 2
done
echo "✗ ClusterIP $VIP did not answer" >&2
exit 1
