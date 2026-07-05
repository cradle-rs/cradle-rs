@serial
@cradle_hubble
Feature: The stock hubble CLI observes cradle datapath flows
  cradle emits a flow event at each forwarding verdict the eBPF datapath
  reaches (FORWARDED at L3 forward, DROPPED at the ingress-policy check),
  drains them in user space into a per-node ring, and serves the Hubble
  Observer gRPC API on `--hubble-sock`. The UNMODIFIED `hubble` CLI (pinned
  v1.19.5, extracted from the official image by deploy/fetch-hubble.sh) is a
  drop-in front end: `hubble observe --server unix://…` streams this node's
  flows. Kernel forwarding on the node is disabled, so a flow only exists if
  the cradle datapath carried (or dropped) the packet. Design:
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

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
