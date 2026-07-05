#!/usr/bin/env bash
# End-to-end: REAL Cilium chained on top of cradle (generic-veth chaining).
#
# cradle-cni is the primary CNI (IPAM, veth, routes — `chained` mode leaves
# the veth TC hook free); the stock Cilium agent chains its policy datapath
# onto the same veths via cni-chaining-mode=generic-veth. The test proves
# coexistence the way the design doc asks: a CiliumNetworkPolicy blocks
# pod→service traffic, deleting it restores connectivity, and Cilium's
# endpoint list shows it manages the cradle-plumbed pods.
set -euo pipefail
cd "$(dirname "$0")/.."

CLUSTER=${CLUSTER:-cradle-cilium-e2e}
CILIUM_VERSION=${CILIUM_VERSION:-1.19.5}

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
docker pull -q "quay.io/cilium/cilium:v$CILIUM_VERSION"
docker pull -q "quay.io/cilium/operator-generic:v$CILIUM_VERSION"
kind load docker-image "quay.io/cilium/cilium:v$CILIUM_VERSION" --name "$CLUSTER"
kind load docker-image "quay.io/cilium/operator-generic:v$CILIUM_VERSION" --name "$CLUSTER"

echo "==> installing cradle (chained mode: no conflist render, no CRD publish)"
# Cilium owns the conflist (customConf ConfigMap below) and the CiliumEndpoint
# CRDs in this deployment; strip the two flags from the stock manifest.
sed -e '/--write-cni-conf/d' -e '/--publish-crds/d' deploy/cradle.yaml | kubectl apply -f -
kubectl apply -f deploy/cilium-chain-config.yaml
kubectl -n cradle-system rollout status ds/cradle --timeout=180s

echo "==> installing Cilium $CILIUM_VERSION (generic-veth chaining)"
helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo update cilium >/dev/null
helm install cilium cilium/cilium --version "$CILIUM_VERSION" -n kube-system \
    --set cni.chainingMode=generic-veth \
    --set cni.customConf=true \
    --set cni.configMap=cni-configuration \
    --set routingMode=native \
    --set ipv4NativeRoutingCIDR=10.244.0.0/16 \
    --set enableIPv4Masquerade=false \
    --set operator.replicas=1
kubectl -n kube-system rollout status ds/cilium --timeout=300s
kubectl wait node --all --for=condition=Ready --timeout=180s

echo "==> deploying the smoke workload"
kubectl create deployment web --image=nginx --replicas=2
kubectl expose deployment web --port 80
kubectl label deployment web app=web --overwrite
kubectl run client --image=curlimages/curl --labels app=client --restart=Never --command -- sleep 3600
kubectl wait deploy/web --for=condition=Available --timeout=300s
kubectl wait pod/client --for=condition=Ready --timeout=300s

VIP=$(kubectl get svc web -o jsonpath='{.spec.clusterIP}')
curl_ok() { kubectl exec client -- curl -s --max-time 3 "http://$VIP/" 2>/dev/null | grep -q "Welcome to nginx"; }

echo "==> baseline: client can reach ClusterIP $VIP"
ok=0
for i in $(seq 1 30); do
    if curl_ok; then ok=1; break; fi
    sleep 2
done
[ "$ok" = 1 ] || { echo "✗ baseline curl to $VIP failed" >&2; exit 1; }
echo "✓ baseline connectivity through cradle-plumbed veths"

echo "==> Cilium manages the cradle-plumbed endpoints"
kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg endpoint list \
    | grep -E "10\.244\." | head -5
COUNT=$(kubectl -n kube-system exec ds/cilium -c cilium-agent -- cilium-dbg endpoint list 2>/dev/null | grep -cE "10\.244\." || true)
[ "${COUNT:-0}" -ge 3 ] || { echo "✗ expected >=3 cilium endpoints, got $COUNT" >&2; exit 1; }
echo "✓ $COUNT cilium endpoints on cradle veths"

echo "==> applying a CiliumNetworkPolicy denying ingress to web"
kubectl apply -f - <<'EOF'
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: deny-web
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: no-such-client
EOF
blocked=0
for i in $(seq 1 30); do
    if ! curl_ok; then blocked=1; break; fi
    sleep 2
done
[ "$blocked" = 1 ] || { echo "✗ CiliumNetworkPolicy did not block client->web" >&2; exit 1; }
echo "✓ CiliumNetworkPolicy blocks client -> web"

echo "==> deleting the policy restores connectivity"
kubectl delete ciliumnetworkpolicy deny-web
restored=0
for i in $(seq 1 30); do
    if curl_ok; then restored=1; break; fi
    sleep 2
done
[ "$restored" = 1 ] || { echo "✗ connectivity did not recover after policy delete" >&2; exit 1; }
echo "✓ real Cilium policy enforced on cradle-plumbed pods (generic-veth chaining)"
