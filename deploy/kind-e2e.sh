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

echo "==> installing cradle (+ vendored cilium.io CRDs)"
kubectl apply -f deploy/crds/ciliumendpoints.yaml -f deploy/crds/ciliumnodes.yaml \
    -f deploy/crds/ciliumidentities.yaml
kubectl apply -f deploy/cradle.yaml
kubectl -n cradle-system rollout status ds/cradle --timeout=180s
kubectl wait node --all --for=condition=Ready --timeout=180s

echo "==> deploying the smoke workload"
kubectl create deployment web --image=nginx --replicas=2
kubectl expose deployment web --port 80
kubectl run client --image=curlimages/curl --restart=Never --command -- sleep 3600
kubectl wait deploy/web --for=condition=Available --timeout=300s
kubectl wait pod/client --for=condition=Ready --timeout=300s

# CiliumEndpoint/CiliumNode publication: every cradle-managed pod must show
# up as a CEP with its IP (the kubectl IPv4 printer column), and the node
# must have a CiliumNode carrying its podCIDR.
check_crds() {
    echo "==> checking CiliumEndpoint/CiliumNode publication"
    for i in $(seq 1 30); do
        CEPS=$(kubectl get ciliumendpoints -o jsonpath='{range .items[*]}{.metadata.name}={.status.networking.addressing[0].ipv4}{"\n"}{end}' 2>/dev/null | grep -c "=10\." || true)
        PODS=$(kubectl get pods --field-selector=status.phase=Running -o name | wc -l)
        if [ "${CEPS:-0}" -ge "$PODS" ] && [ "$PODS" -gt 0 ]; then
            kubectl get ciliumendpoints
            kubectl get ciliumnode "$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')" \
                -o jsonpath='{.metadata.name} podCIDRs={.spec.ipam.podCIDRs}{"\n"}'
            echo "✓ $CEPS CiliumEndpoints published for $PODS running pods"
            return 0
        fi
        sleep 2
    done
    echo "✗ CiliumEndpoints not published (got ${CEPS:-0} for $PODS pods)" >&2
    exit 1
}

# NodePort: expose web as a NodePort service and reach it at the node's
# InternalIP:<nodePort> — the frontend cradle-k8s programs on the node IP,
# DNAT'd by the eBPF datapath (no kube-proxy involvement asserted separately).
check_nodeport() {
    echo "==> checking NodePort (node IP frontend)"
    kubectl expose deployment web --name web-np --type NodePort --port 80 >/dev/null
    local node_ip np
    node_ip=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    for i in $(seq 1 30); do
        np=$(kubectl get svc web-np -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null)
        if [ -n "$np" ] && kubectl exec client -- curl -s --max-time 3 "http://$node_ip:$np/" 2>/dev/null | grep -q "Welcome to nginx"; then
            echo "✓ NodePort $node_ip:$np served through the cradle datapath"
            return 0
        fi
        sleep 2
    done
    echo "✗ NodePort $node_ip:$np did not answer" >&2
    exit 1
}

# NetworkPolicy: a default-deny-ingress on web must block the client, and
# deleting it must restore connectivity — enforced by cradle's eBPF datapath
# (no Cilium in this cluster). Uses a direct pod IP so kube-proxy DNAT can't
# mask the drop.
check_policy() {
    echo "==> checking NetworkPolicy enforcement"
    local pod_ip
    pod_ip=$(kubectl get pod -l app=web -o jsonpath='{.items[0].status.podIP}')
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: deny-web, namespace: default }
spec:
  podSelector: { matchLabels: { app: web } }
  policyTypes: [ Ingress ]
EOF
    local blocked=0
    for i in $(seq 1 30); do
        if ! kubectl exec client -- curl -s --max-time 3 "http://$pod_ip/" 2>/dev/null | grep -q nginx; then
            blocked=1; break
        fi
        sleep 2
    done
    [ "$blocked" = 1 ] || { echo "✗ NetworkPolicy did not block client->web pod $pod_ip" >&2; exit 1; }
    echo "✓ NetworkPolicy blocks client -> web ($pod_ip), enforced in cradle eBPF"
    kubectl delete networkpolicy deny-web
    local restored=0
    for i in $(seq 1 30); do
        if kubectl exec client -- curl -s --max-time 3 "http://$pod_ip/" 2>/dev/null | grep -q nginx; then
            restored=1; break
        fi
        sleep 2
    done
    [ "$restored" = 1 ] || { echo "✗ connectivity did not recover after policy delete" >&2; exit 1; }
    echo "✓ deleting the NetworkPolicy restores connectivity"
}

# Egress NetworkPolicy: default-deny-egress on the client must block its
# curl to the web pod IP; adding an allow-to-web rule must restore it —
# enforced at the client's veth hook in cradle's eBPF (policy Phase 1,
# docs/design/policy.md). Direct pod IP: DNS to kube-dns would also be
# denied under default-deny egress and mask the real signal.
check_egress_policy() {
    echo "==> checking egress NetworkPolicy enforcement"
    local pod_ip
    pod_ip=$(kubectl get pod -l app=web -o jsonpath='{.items[0].status.podIP}')
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: deny-client-egress, namespace: default }
spec:
  podSelector: { matchLabels: { run: client } }
  policyTypes: [ Egress ]
EOF
    local blocked=0
    for i in $(seq 1 30); do
        if ! kubectl exec client -- curl -s --max-time 3 "http://$pod_ip/" 2>/dev/null | grep -q nginx; then
            blocked=1; break
        fi
        sleep 2
    done
    [ "$blocked" = 1 ] || { echo "✗ egress policy did not block client->web pod $pod_ip" >&2; exit 1; }
    echo "✓ default-deny egress blocks client -> web ($pod_ip)"
    kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: deny-client-egress, namespace: default }
spec:
  podSelector: { matchLabels: { run: client } }
  policyTypes: [ Egress ]
  egress:
  - to: [ { podSelector: { matchLabels: { app: web } } } ]
EOF
    local allowed=0
    for i in $(seq 1 30); do
        if kubectl exec client -- curl -s --max-time 3 "http://$pod_ip/" 2>/dev/null | grep -q nginx; then
            allowed=1; break
        fi
        sleep 2
    done
    [ "$allowed" = 1 ] || { echo "✗ egress allow-to-web did not restore client->web" >&2; exit 1; }
    echo "✓ egress allow-to-web restores client -> web, enforced in cradle eBPF"
    kubectl delete networkpolicy deny-client-egress
}

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
            check_crds
            check_nodeport
            check_policy
            check_egress_policy
            exit 0
        fi
        echo "✗ VIP answered but l4_dnat=0 — served by kube-proxy, not eBPF" >&2
        exit 1
    fi
    sleep 2
done
echo "✗ ClusterIP $VIP did not answer" >&2
exit 1
