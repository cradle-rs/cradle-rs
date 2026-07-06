# Kubernetes

cradle-rs runs as a **Kubernetes CNI provider**: it gives pods their network
interfaces and addresses, forwards pod traffic in eBPF, load-balances Services
as a full kube-proxy replacement, and enforces NetworkPolicy natively — all
driven by the same map-programmed datapath the rest of this book describes.

Because the node's routing stack is [zebra-rs](ch-02-00-zebra-integration.md),
pod reachability also rides real routing protocols, including the direction the
Cilium ecosystem does not cover: **routes learned from BGP program the pod
datapath** (Cilium's BGP control plane is advertise-only —
[cilium/cilium#34841](https://github.com/cilium/cilium/issues/34841)).

## The pieces

Beyond the `cradle` daemon, two binaries turn a node into a Kubernetes CNI
node:

```
 kubelet ──exec──▶ cradle-cni (CNI 1.1 plugin) ──gRPC──▶ cradle ──▶ eBPF datapath
                                                            ▲
 kube-apiserver ◀──watch/publish── cradle-k8s ──gRPC───────┘
   (Services, EndpointSlices,        (Service→LB sync, conflist render,
    NetworkPolicies, Nodes)           CRD publication, policy translation)
```

- **`cradle-cni`** — a [CNI spec 1.1](https://github.com/containernetworking/cni)
  plugin the kubelet execs for each pod. It plumbs the veth pair and the pod's
  default route, then calls the daemon over gRPC to allocate the address and
  program the datapath.
- **`cradle-k8s`** — a per-node controller that watches the Kubernetes API and
  drives the daemon: it maps Services onto the eBPF L4 load balancer, renders
  the kubelet CNI configuration from the Node's `podCIDR`, publishes Cilium
  CRDs, and translates NetworkPolicies into datapath rules.
- **`cradle`** — the daemon (this book's subject): it owns the eBPF maps, the
  node-local IPAM allocator, and the persistent endpoint store, and exposes the
  gRPC control API both of the above drive.

## The chapters

- [**CNI Support**](ch-05-01-cni.md) — cradle's own CNI provider: the
  `cradle-cni` plugin, node-local IPAM, the pod-endpoint lifecycle, Services as
  a kube-proxy replacement, and dual-stack.
- [**Cilium API Compatibility**](ch-05-02-cilium.md) — the surfaces that let
  the *unmodified* Cilium ecosystem drive a cradle node: the cilium-agent REST
  API shim (so the stock `cilium-cni` plugin works), the `CiliumEndpoint` /
  `CiliumNode` / `CiliumIdentity` CRDs, generic-veth chaining, and the Hubble
  Observer/Peer API (so the stock `hubble`, `hubble-relay`, and `hubble-ui`
  observe cradle flows).
- [**Network Policy**](ch-05-03-network-policy.md) — native, in-datapath
  enforcement of Kubernetes `NetworkPolicy` and the Cilium policy CRDs:
  ingress + egress, dual-stack, deny rules, L7 HTTP, and per-tenant identity
  over overlapping pod CIDRs.

## Deploying

`deploy/cradle.yaml` is the per-node DaemonSet (an init container installs the
`cradle-cni` binary onto the node; the daemon and `cradle-k8s` run as
containers). The `deploy/kind-*.sh` scripts stand up end-to-end kind clusters —
plain CNI, kube-proxy-free, chained Cilium, and the Hubble stack — and are the
integration proof behind every status claim in the chapters that follow. The
design rationale lives in `docs/design/cni-cilium.md` and
`docs/design/kube-proxy-dualstack.md`.
