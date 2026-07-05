@serial
@cradle_hubble
Feature: The stock hubble CLI observes cradle datapath flows
  cradle emits a flow event at each forwarding verdict the eBPF datapath
  reaches (FORWARDED at L3 forward, DROPPED at the ingress-policy check,
  TRANSLATED at service DNAT / egress masquerade), enriches each with the
  endpoint's namespace/pod/identity from the CNI store, drains them in user
  space into a per-node ring, and serves the Hubble Observer gRPC API on
  `--hubble-sock` with `FlowFilter` support. The UNMODIFIED `hubble` CLI
  (pinned v1.19.5, extracted from the official image by deploy/fetch-hubble.sh)
  is a drop-in front end: `hubble observe --server unix://…` streams this
  node's flows and its `--namespace` / `--verdict` filters work server-side.
  Kernel forwarding on the node is disabled, so a flow only exists if the
  cradle datapath carried, dropped, or translated the packet. Design:
  docs/design/hubble.md.

  Topology (single node, cradle-cni pods):
  ```
   host1(10.1.1.2, "world") ── n0 [node: cradle serve --hubble-sock] crdl* ── pod1(10.244.0.2), pod2(10.244.0.3)
  ```

  Scenario: hubble observe shows FORWARDED pod flows and a policy DROP
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "host1"
    And I create namespace "pod1"
    And I create namespace "pod2"
    And I connect namespace "node" interface "n0" to namespace "host1" interface "eth0"
    And I add address "10.1.1.1/24" to interface "n0" in namespace "node"
    And I add address "10.1.1.2/24" to interface "eth0" in namespace "host1"
    And I add route "10.244.0.0/24" via "10.1.1.1" in namespace "host1"
    And I disable IPv4 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl" and Hubble as "hub"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json" expecting "10.244.0.2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" expecting "10.244.0.3"
    Then ping from "pod1" to "10.244.0.3" should eventually succeed
    And hubble observe on node "node" via Hubble "hub" should show a "FORWARDED" flow from "10.244.0.2" to "10.244.0.3"
    When I apply cradle config "policy-on.json" to namespace "node" via gRPC as "ctl"
    Then ping from "host1" to "10.244.0.3" should fail
    And the cradle stat "policy_drop" in namespace "node" via gRPC as "ctl" should be nonzero
    And hubble observe on node "node" via Hubble "hub" should show a "DROPPED" flow from "10.1.1.2" to "10.244.0.3"
    # H2: server-side FlowFilter — `hubble observe --namespace default
    # --verdict DROPPED` shows the drop but hides the earlier forwarded flows.
    And hubble observe on node "node" via Hubble "hub" with filter "--namespace default --verdict DROPPED" should show a "DROPPED" flow from "10.1.1.2" to "10.244.0.3"
    And hubble observe on node "node" via Hubble "hub" with filter "--namespace default --verdict DROPPED" should show no "FORWARDED" flow
    # H2: enrichment — the enforced pod carries its security identity (200).
    And hubble observe on node "node" via Hubble "hub" should show a flow with identity "200"

  Scenario: masqueraded pod egress is a TRANSLATED flow
    Given the test topology exists
    When I apply cradle config "masq-on.json" to namespace "node" via gRPC as "ctl"
    And I serve source-echo HTTP in namespace "host1" bound to "10.1.1.2"
    # pod → "external" host1 is SNAT'd to the node IP (10.1.1.1); the echo
    # proves masquerade happened, and the datapath emits a TRANSLATED flow.
    Then HTTP GET "http://10.1.1.2:8080/" from namespace "pod1" should contain "10.1.1.1"
    And hubble observe on node "node" via Hubble "hub" should show a "TRANSLATED" flow from "10.244.0.2" to "10.1.1.2"

  # H3: the UNMODIFIED hubble-relay (pinned v1.19.5, extracted by
  # deploy/fetch-hubble-relay.sh) discovers this node through its Peer service
  # on hubble.sock, dials the advertised TCP Observer, and aggregates the
  # node's flows — so `hubble observe` against the RELAY (not the node) shows
  # them. This is the single-node core of Relay aggregation; DaemonSet wiring
  # for relay + hubble-ui lives in deploy/kind-hubble-e2e.sh.
  Scenario: the stock hubble-relay aggregates this node's flows
    Given the test topology exists
    When I start hubble-relay in namespace "node" peering Hubble "hub"
    Then hubble observe via relay in namespace "node" should show a "FORWARDED" flow from "10.244.0.2" to "10.244.0.3"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop hubble-relay in namespace "node"
    And I stop HTTP in namespace "host1"
    And I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
