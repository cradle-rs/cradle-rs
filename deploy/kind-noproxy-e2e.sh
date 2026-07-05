#!/usr/bin/env bash
# Capstone: a kind cluster with the default CNI AND kube-proxy both disabled.
# cradle is the only thing providing pod networking and service load
# balancing. The cluster only becomes usable because cradle serves the
# `default/kubernetes` service (the API server, a host-network backend) — the
# K4/K5 capability. Proves ClusterIP, NodePort, and DNS all work with no
# kube-proxy in the cluster.
#
# Bootstrap note: cradle-k8s runs hostNetwork and would normally reach the API
# at the 10.96.0.1 VIP — which nothing serves until cradle-k8s programs it, a
# deadlock with kube-proxy off. So we point cradle-k8s directly at the node's
# API server (<nodeIP>:6443, whose cert SANs kubeadm includes) via
# KUBERNETES_SERVICE_HOST/PORT; pods keep using the VIP, served by cradle.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-cradle-noproxy}

echo "==> building release binaries"
cargo build --release -p cradle -p cradle-k8s
rustup target add aarch64-unknown-linux-musl >/dev/null
RUSTFLAGS="-C target-feature=+crt-static -C linker=rust-lld" \
    cargo build --release -p cradle-cni --target aarch64-unknown-linux-musl

echo "==> building the node image"
docker build -t cradle:dev -f deploy/Dockerfile .

echo "==> creating the kind cluster (default CNI + kube-proxy disabled)"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --config deploy/kind-noproxy-config.yaml --wait 0s
kind load docker-image cradle:dev --name "$CLUSTER"

NODE_IP=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
echo "==> node API server at $NODE_IP:6443 (cradle-k8s bootstrap target)"

echo "==> installing cradle (+ cilium.io CRDs)"
kubectl apply -f deploy/crds/ciliumendpoints.yaml -f deploy/crds/ciliumnodes.yaml
kubectl apply -f deploy/cradle.yaml
# Point cradle-k8s directly at the API server (bypass the not-yet-served VIP).
kubectl -n cradle-system set env ds/cradle -c cradle-k8s \
    "KUBERNETES_SERVICE_HOST=$NODE_IP" "KUBERNETES_SERVICE_PORT=6443"
kubectl -n cradle-system rollout status ds/cradle --timeout=180s
kubectl wait node --all --for=condition=Ready --timeout=180s

echo "==> the default/kubernetes (API server) service is served by cradle"
kubectl -n cradle-system logs ds/cradle -c cradle-k8s | grep -m1 "10.96.0.1:443" || true

echo "==> deploying the smoke workload"
kubectl create deployment web --image=nginx --replicas=2
kubectl expose deployment web --port 80
kubectl expose deployment web --name web-np --type NodePort --port 80
kubectl run client --image=curlimages/curl --restart=Never --command -- sleep 3600
kubectl wait deploy/web --for=condition=Available --timeout=300s
kubectl wait pod/client --for=condition=Ready --timeout=300s

pass() { echo "✓ $1"; }
fail() { echo "✗ $1" >&2; exit 1; }

VIP=$(kubectl get svc web -o jsonpath='{.spec.clusterIP}')
echo "==> ClusterIP $VIP (no kube-proxy)"
ok=0; for i in $(seq 1 30); do
    kubectl exec client -- curl -s --max-time 3 "http://$VIP/" | grep -q "Welcome to nginx" && { ok=1; break; }; sleep 2; done
[ "$ok" = 1 ] && pass "ClusterIP served with kube-proxy off" || fail "ClusterIP $VIP unreachable"

NP=$(kubectl get svc web-np -o jsonpath='{.spec.ports[0].nodePort}')
echo "==> NodePort $NODE_IP:$NP (no kube-proxy)"
ok=0; for i in $(seq 1 30); do
    kubectl exec client -- curl -s --max-time 3 "http://$NODE_IP:$NP/" | grep -q "Welcome to nginx" && { ok=1; break; }; sleep 2; done
[ "$ok" = 1 ] && pass "NodePort served with kube-proxy off" || fail "NodePort $NODE_IP:$NP unreachable"

echo "==> cluster DNS by service name (CoreDNS → API via cradle, no kube-proxy)"
ok=0; for i in $(seq 1 30); do
    kubectl exec client -- curl -s --max-time 3 "http://web.default.svc.cluster.local/" | grep -q "Welcome to nginx" && { ok=1; break; }; sleep 2; done
[ "$ok" = 1 ] && pass "DNS + ClusterIP by name served with kube-proxy off" || fail "DNS resolution failed"

# Confirm the datapath actually did the LB (kube-proxy is genuinely absent).
DNAT=$(kubectl -n cradle-system exec ds/cradle -c cradle -- \
    cradle ctl --grpc unix:/run/cradle/cradle.sock stats | awk '$1=="l4_dnat"{print $2}')
[ "${DNAT:-0}" -gt 0 ] && pass "eBPF l4_dnat=$DNAT (cradle served the services, not kube-proxy)" \
    || fail "l4_dnat=0 — services were not served by cradle"
echo "✓ full kube-proxy replacement: cluster works with no kube-proxy"
