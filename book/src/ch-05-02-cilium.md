# Cilium API Compatibility

cradle can be driven by, and observed with, the **unmodified Cilium
ecosystem**. It implements the subset of Cilium's API surfaces that the stock
tools drive, so a cradle node gains the Cilium tooling while keeping the
routing stack underneath. All surfaces are pinned to **Cilium v1.19.5** and
proven against the real upstream binaries.

## The cilium-agent REST shim

The daemon serves the slice of the cilium-agent REST API that the stock
`cilium-cni` plugin calls, over a unix socket, so the **unmodified `cilium-cni`
binary** is a drop-in front end for cradle:

```
cradle serve --cilium-sock /var/run/cilium/cilium.sock --pod-cidr 10.244.0.0/24
```

| Endpoint | Purpose |
|---|---|
| `GET /healthz` | agent readiness |
| `GET /config` | advertises `datapathMode: veth` and the ptp gateway addressing |
| `POST /ipam`, `DELETE /ipam/{ip}` | allocate / release a pod address from the node pool |
| `PUT /endpoint/{id}`, `DELETE /endpoint` | attach / detach a pod endpoint (batch delete by container id) |
| `GET /endpoint/{id}/healthz` | endpoint readiness |

The stock plugin does the veth plumbing and installs the pod routes itself from
the advertised gateway; the shim maps `PUT /endpoint` onto the same endpoint
creation the [native CNI path](ch-05-01-cni.md) uses (and writes the gateway's
permanent neighbor entry into the pod netns, which v1.19.5 leaves to the
datapath). `cradle_cilium` runs the unmodified plugin against this API.

## CiliumEndpoint / CiliumNode CRDs

`cradle-k8s --publish-crds` mirrors the daemon's endpoint store into
`CiliumEndpoint` resources — so `kubectl get ciliumendpoints` shows cradle's
pods with their addresses — and publishes a `CiliumNode` carrying the node's
`podCIDR`. The CRDs are vendored under `deploy/crds/`.

## Generic-veth chaining

cradle can be the **primary CNI with the real Cilium agent chained on top**
(`cni.chainingMode=generic-veth`). In `chained` endpoint mode, cradle does the
IPAM and veth plumbing but leaves the veth's TC hook free for Cilium's datapath
to own; the pod `/32` still lives in the eBPF FIB so fabric-ingress traffic
forwards in eBPF. `deploy/kind-cilium-e2e.sh` proves the coexistence: a
CiliumNetworkPolicy blocks and restores pod traffic while Cilium's endpoint
list shows it managing the cradle-plumbed pods.

## Hubble observability

cradle emits a **flow event at each forwarding verdict** the datapath reaches
and serves the Hubble **Observer** + **Peer** gRPC API, so the stock `hubble`
CLI, `hubble-relay`, and `hubble-ui` observe a cradle node unmodified.

```
cradle serve --hubble-sock /var/run/cilium/hubble.sock --hubble-listen 0.0.0.0:4244
```

### Flow events

A `FLOWS` eBPF ring buffer carries one record per verdict; user space drains it,
enriches each into a Hubble `Flow`, and keeps the most recent in a per-node
ring:

| Verdict | Emitted at |
|---|---|
| `FORWARDED` | L3 forward success |
| `DROPPED` | the ingress-policy check |
| `TRANSLATED` | service DNAT and egress masquerade |

Each flow is **enriched** with the endpoint's namespace, pod name, security
identity, and labels (pod IP → identity from a user-space mirror of the
`IDENTITY` map), so `hubble observe` shows pod-level context.

### Filters and the CLI

`GetFlows` applies Hubble's `FlowFilter` server-side (whitelist-OR /
within-AND): verdict, traffic direction, source/destination IP (exact or CIDR),
pod (`namespace/prefix`), identity, label, and protocol, plus `since`/`until`
time windows. So the stock CLI's filters work end to end:

```
hubble observe --server unix:///var/run/cilium/hubble.sock \
    --namespace default --verdict DROPPED
```

`ServerStatus`, `GetNodes`, and `GetNamespaces` are served too;
`GetAgentEvents` / `GetDebugEvents` return empty streams (cradle has no
agent/debug event source).

### Relay and UI

The **Peer** service (`peer.Peer/Notify`) advertises the node's Observer
address, and `--hubble-listen` serves Observer + Peer over TCP, so the stock
`hubble-relay` discovers the node and aggregates its flows; `hubble-ui` then
renders the service map. `deploy/hubble.yaml` wires up `hubble-peer` +
`hubble-relay` + `hubble-ui`, and `deploy/hubble-cradle-patch.yaml` enables the
API on the DaemonSet. `deploy/kind-hubble-e2e.sh` proves the stock stack
(relay reports `Connected Nodes 1/1` and aggregates FORWARDED + TRANSLATED
flows; the UI serves its page).

The design and milestones are in `docs/design/hubble.md`.

## Status

| Surface | Status | Proof |
|---|---|---|
| cilium-agent REST shim (stock `cilium-cni`) | ✅ | `cradle_cilium` |
| `CiliumEndpoint` / `CiliumNode` CRDs | ✅ | `deploy/kind-e2e.sh` |
| Generic-veth chaining (real Cilium on top) | ✅ | `deploy/kind-cilium-e2e.sh` |
| Hubble Observer + Peer (stock `hubble` / relay / UI) | ✅ | `cradle_hubble`, `deploy/kind-hubble-e2e.sh` |

Follow-ons: multi-node Hubble peer federation, IPv6 and L7/HTTP flows. The
NetworkPolicy engine that feeds the `DROPPED` verdict is IPv4-ingress only —
see [CNI Support](ch-05-01-cni.md).
