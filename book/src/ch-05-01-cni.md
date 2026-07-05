# CNI Support

cradle is a **CNI spec 1.1** provider. The `cradle-cni` plugin does the veth
plumbing the container runtime expects; the daemon owns the addressing and the
datapath. Because kernel forwarding on the node is off, a pod that can reach
anything proves the eBPF datapath carried the packet.

## The `cradle-cni` plugin

The kubelet execs `cradle-cni` with the CNI operation in the environment and
the network configuration on stdin. The plugin supports the full CNI 1.1 verb
set:

| Verb | What it does |
|---|---|
| `ADD` | Creates the veth pair, moves one end into the pod netns, installs the ptp gateway route, and calls the daemon to allocate the address and program the pod `/32` (and `/128`) into the eBPF FIB. |
| `DEL` | Releases the address and removes the datapath state. Idempotent — a repeated `DEL` for an already-gone attachment succeeds. |
| `CHECK` | Confirms the attachment is still present in the daemon's endpoint store. |
| `GC` | Sweeps datapath endpoints whose attachment is absent from the runtime's `cni.dev/valid-attachments` list. |
| `STATUS` | Reports plugin/daemon readiness. |
| `VERSION` | Advertises the supported CNI versions. |

The conflist the kubelet reads names the plugin and points it at the daemon's
gRPC socket and the pod CIDR IPAM pool:

```json
{
  "cniVersion": "1.1.0",
  "name": "cradle",
  "type": "cradle-cni",
  "grpcEndpoint": "unix:/run/cradle/cradle.sock",
  "ipam": { "type": "cradle", "subnet": "10.244.0.0/24" }
}
```

`cradle-k8s` renders this file automatically from the Node's `podCIDR`
(`--write-cni-conf`), so operators do not hand-write it in a cluster.

## Addressing and the datapath

For each pod, `cradle-cni` sets up a **point-to-point** gateway inside the pod
netns — `169.254.1.1` for IPv4 (and `fe80::1` for IPv6) — installed as a
`scope link` route plus a permanent neighbor entry, with a default route via
that gateway. The pod's own address is a `/32` (`/128`) allocated by the
daemon, programmed as a connected next-hop into the eBPF FIB so traffic to the
pod redirects onto its host veth.

Addresses come from a **node-local IPAM allocator** owned by the daemon and
persisted under `--state-dir` (default `/run/cradle`). Allocation is idempotent
per attachment — a retried `ADD` returns the same address — and survives daemon
restarts.

## Surviving a restart

The endpoint store (IPAM allocations + one record per attachment) is persisted,
so a daemon restart re-programs the fresh eBPF maps from disk and completes any
deletes for pods torn down while it was down. Pod churn is orders of magnitude
slower than the datapath, so this file-backed store is the source of truth
rather than the maps.

## Services: a kube-proxy replacement

`cradle-k8s` watches Services and EndpointSlices and programs each ClusterIP
onto the eBPF [L4 load balancer](ch-01-04-l4-load-balancing.md) (`AddService`
replaces the backend set, `DelService` removes it, with a periodic resync).
This is a **full kube-proxy replacement**, not a supplement:

- **ClusterIP** — VIP → pod backends via the `SERVICES`/`BACKENDS` maps, with
  conntrack DNAT/SNAT.
- **NodePort** — a frontend on the node IP that `cradle-k8s` programs from the
  Service's `nodePort`.
- **hostPort** — via the CNI `portMappings` capability.
- **Host-network-backed services** (e.g. `default/kubernetes`) — served by a
  DNAT to the node-local backend plus a `clsact`-**egress** reverse-NAT that
  rewrites the local-stack reply back to the VIP.
- **ClientIP session affinity** — a sticky backend per client via the
  `AFFINITY` map.
- **Egress masquerade** — pod traffic to a destination outside the cluster is
  SNAT'd to the node's uplink IP (`MASQ_CFG`), with in-cluster CIDRs left
  untouched (`NON_MASQ`).

`deploy/kind-noproxy-e2e.sh` brings up a cluster with `kubeProxyMode: none` and
the default CNI disabled, where ClusterIP, NodePort, and cluster DNS are all
served by cradle's datapath.

## Dual-stack

The allocator and datapath are symmetric across families: a pod gets an IPv6
`/128` from a node-local v6 pool behind the `fe80::1` ptp gateway, programmed
into `FIB6` alongside its v4 `/32`. Services follow the
[L4 model's](ch-01-04-l4-load-balancing.md) IPv6 path. (The NetworkPolicy
engine is currently IPv4-ingress only.)

## Cross-node pod routing over BGP

This is the capability that motivates driving the datapath from a real routing
stack. Each node runs [zebra-rs](ch-02-00-zebra-integration.md); nodes exchange
their pod CIDRs over eBGP, and the **learned** routes tee straight into each
node's eBPF FIB. Cross-node pod-to-pod traffic forwards entirely in eBPF with
kernel forwarding off end to end — no overlay, and no out-of-band route
distribution. `cradle_cni_bgp` is the BDD proof.

## NetworkPolicy

cradle enforces Kubernetes-style ingress NetworkPolicy **natively in the
datapath**. `cradle-k8s --enforce-policy` translates NetworkPolicies into the
`IDENTITY` / `POLICY` / `EP_POLICY` maps: pod IPs map to label-set identities,
and an enforced endpoint drops ingress that is neither a reply to a
pod-initiated flow (stateful, tracked in `PCT`) nor matched by an allow rule.
The verdict is taken in `cradle_tc` where the destination resolves to the pod's
veth, so same-node and fabric-ingress traffic enforce at the same point. The
design is in `docs/design/policy.md`.

## Status

Every row below is proven by a BDD feature (`bdd/tests/features/cradle_*`) or a
kind end-to-end script. See [BDD Integration Tests](ch-04-00-bdd-tests.md).

| Function | Status | Proof |
|---|---|---|
| CNI 1.1 ADD / DEL | ✅ | `cradle_cni` |
| CNI CHECK / STATUS / VERSION / GC | ✅ | `cradle_cni_restart` |
| Node-local IPAM + daemon-restart reconcile | ✅ | `cradle_cni_restart` |
| Cross-node pod routing over BGP | ✅ | `cradle_cni_bgp` |
| ClusterIP Services (eBPF L4 LB) | ✅ | `cradle_cni_svc` |
| Host-network-backed services | ✅ | `cradle_hostnet` |
| Dual-stack pods (IPv6 IPAM) | ✅ | `cradle_cni_v6` |
| NodePort / hostPort / egress masquerade | ✅ | `cradle_nodeport`, `cradle_masq` |
| Full kube-proxy replacement | ✅ | `deploy/kind-noproxy-e2e.sh` |
| Native ingress NetworkPolicy | ✅ | `cradle_policy` |
| DaemonSet packaging + kind e2e | ✅ | `deploy/kind-e2e.sh` |
