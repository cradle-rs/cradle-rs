# Hubble observability for cradle

Status: PLAN. Closes the one remaining ⬜ in the Cilium-compatibility table:
make the stock **`hubble observe`** CLI (and, later, Hubble Relay + UI) work
against a cradle node by emitting flow events from the eBPF datapath and
serving the Hubble **Observer** gRPC API on `/var/run/cilium/hubble.sock`.

## Where cradle stands

Real Hubble is three stages: the datapath emits *monitor events* → the
cilium-agent buffers them in a user-space ring → the **Observer** gRPC
service (`GetFlows`, `ServerStatus`, `GetNodes`, `GetNamespaces`) serves them
on `hubble.sock`. cradle has the third-stage plumbing (tonic gRPC, the UDS
server pattern already used for `cilium.sock` in `cilium.rs`) and rich
per-flow context in-kernel — but **no event channel**:

- Telemetry today is only `STATS` (`PerCpuArray<u64>`, aggregate counters via
  `stat_inc`) — totals, not per-flow events. There is **no** `RingBuf` /
  `PerfEventArray` / `bpf_ringbuf_output` anywhere.
- The forwarding decision points that *are* the flow verdicts already exist:
  `l3_forward_v4/v6` (FORWARDED), `policy_denied` (DROPPED — `STAT_POLICY_DROP`
  already marks it), `l4_nat_v4` DNAT + `masq_v4` (TRANSLATED). The `CT`/`PCT`
  maps already hold the 5-tuples.
- Endpoint enrichment is available: the CNI endpoint store (`cni.rs`:
  ip→pod_name/namespace), the `IDENTITY` map (ip→identity), and cradle-k8s's
  label-set identities.

So the only genuinely new datapath work is a **flow-event ring buffer + emit
calls**; the rest is a user-space drain/enrich pipeline and the Observer
server, both on infrastructure that already exists.

## Architecture

```
 cradle_tc / cradle_egress ──emit_flow()──▶ FLOWS ringbuf ──▶ user-space drain
   (verdict at each decision point)                              │ enrich (store+IDENTITY)
                                                                 ▼
                                                     in-memory flow ring (last N)
                                                                 │
                                        Observer gRPC on hubble.sock ─▶ `hubble observe`
```

### 1. Datapath flow events (`cradle-ebpf`)

- New `FLOWS` map, `RingBuf` (aya `RingBuf`, `BPF_MAP_TYPE_RINGBUF`), sized
  e.g. 4 MiB.
- A compact fixed-size `FlowRecord` (`cradle-common`, `#[repr(C)]`):
  `time` (ktime), `saddr`/`daddr` (16 bytes each; v4 in the low 4), `sport`,
  `dport`, `proto`, `verdict`, `dir`, `ep_ifindex` (the local endpoint veth,
  for enrichment), `family`, `flags`. Fixed size keeps the verifier happy.
- One `emit_flow(ctx, verdict, dir, ep_ifindex)` helper called at the verdict
  points:
  - `l3_forward_v4/v6` success → `FORWARDED` (dir from `PORT_F_ENDPOINT`:
    pod-egress = `EGRESS`, toward-endpoint = `INGRESS`).
  - `policy_denied` → `DROPPED` (the highest-value signal for `hubble observe
    --verdict DROPPED`).
  - `l4_nat_v4` DNAT and `masq_v4` → `TRANSLATED`.
- Overhead control: sample under load (a per-CPU token bucket); on ringbuf-full,
  bump a `STAT_FLOW_LOST` counter that surfaces as Hubble `LostEvent`.

### 2. User-space flow pipeline (`cradle` daemon)

- A task drains `FLOWS` (aya async `RingBuf`) and turns each record into a
  `flow.Flow`:
  - source/destination **Endpoint**: `saddr`/`daddr` → endpoint store
    (pod_name, namespace, ip) + `IDENTITY` (identity number) + labels (an
    `IP → labels` cache that cradle-k8s already computes for policy/CEPs,
    pushed over a small gRPC or read from the CEP objects).
  - verdict / traffic_direction / L4 straight from the record; `node_name`
    from config.
- Keep the last N flows (default 16 384, Hubble's default) in an in-memory
  ring; fan out to live `follow` subscribers.

### 3. Observer gRPC server (`cradle` daemon)

- Serve `observer.Observer` on `unix:/var/run/cilium/hubble.sock` (opt-in
  `--hubble-sock <path>`; optional TCP for Relay). Vendor `observer.proto` +
  `flow.proto` (pinned Cilium **v1.19.5**, like `cradle.proto`), compiled by
  the build script.
- Implement:
  - `GetFlows` (server-streaming): honor `number`, `first`, `follow`,
    `since`/`until`, and a first-cut `FlowFilter` (verdict, source/destination
    namespace + pod, protocol). Replay from the ring, then stream live when
    `follow`.
  - `ServerStatus`: `num_flows` / `max_flows` / `seen_flows` / `uptime`.
  - `GetNodes` (this node), `GetNamespaces` (from the endpoint store).
  - `GetAgentEvents` / `GetDebugEvents`: empty streams (documented no-op).

## Milestones

- **H1 — flow events + minimal Observer. ✅ delivered.** `FLOWS` ringbuf +
  emit at L3-forward (FORWARDED) and policy-drop (DROPPED); user-space drain +
  in-memory ring; `GetFlows` (number/follow) + `ServerStatus` + `GetNodes` +
  `GetNamespaces` on `hubble.sock` (`serve --hubble-sock`, `--node-name`).
  **Acceptance (met)**: the stock `hubble` v1.19.5 CLI (extracted from the
  Cilium image by `deploy/fetch-hubble.sh`, like `cilium-cni`) against a
  cradle node shows FORWARDED pod↔pod flows and a DROPPED flow when a
  NetworkPolicy blocks traffic — proven by the `cradle_hubble` BDD feature.
  A kind-e2e phase is still to come.
- **H2 — enrichment + filters + service/masq verdicts. ✅ delivered.**
  Endpoint identity/namespace/pod/labels on both ends (identity from a
  user-space mirror of the `IDENTITY` map; namespace/pod-name labels
  synthesized); TRANSLATED emitted at service DNAT and egress masquerade;
  server-side `FlowFilter` (verdict / traffic-direction / source+destination
  ip [exact or CIDR] / pod [`ns/prefix`] / identity / label / protocol) with
  whitelist-OR / within-AND semantics; `since`/`until` time-window filtering.
  **Acceptance (met)**: `hubble observe --namespace default --verdict DROPPED`
  filters correctly (shows the policy drop, hides forwarded flows) and flows
  carry pod identities — proven by the `cradle_hubble` BDD feature, which also
  observes a TRANSLATED masqueraded flow.
- **H3 — Hubble Relay + UI.** Serve the Peer/TCP Observer endpoint so the
  stock `hubble-relay` aggregates cradle nodes; DaemonSet wiring for
  hubble-relay + hubble-ui; kind-e2e shows the UI service map. IPv6 flows and
  L7/HTTP flows (via the TPROXY emitting) are follow-ons.

## Leverage & non-goals

Reuses: tonic + the UDS server pattern (`cilium.rs`), the endpoint store +
`IDENTITY` for enrichment, and the existing verdict points (policy / L4 NAT /
L3 forward). New: the ringbuf + emit calls + the Observer server.

Non-goals for this arc: L7/HTTP flow visibility (needs the L7 proxy to emit),
agent/debug event streams (empty), drop-reason fidelity beyond policy/no-route,
and clustermesh/identity-federation flows. Pinned to Cilium v1.19.5 to match
the M5 agent shim and the M7 chaining e2e.

## References

- Hubble internals (datapath → ring → Observer):
  https://docs.cilium.io/en/stable/internals/hubble/
- Observer service (`observer.proto`, GetFlows/ServerStatus/GetNodes/
  GetNamespaces): https://github.com/cilium/cilium/blob/v1.19.5/api/v1/observer/observer.proto
- Flow message (`flow.proto`; Verdict FORWARDED/DROPPED/TRANSLATED,
  TrafficDirection): https://github.com/cilium/cilium/blob/v1.19.5/api/v1/flow/flow.proto
