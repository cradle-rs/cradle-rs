@serial
@cradle_cni_bgp
Feature: Cross-node pod networking over BGP-learned routes
  Two CNI nodes each run cradle + zebra-rs. eBGP between the nodes exchanges
  the per-node pod CIDRs, zebra-rs tees each learned route into its node's
  eBPF FIB (`system cradle enabled`), and pods on different nodes reach each
  other with kernel forwarding disabled on both nodes — every inter-node hop
  is forwarded by the eBPF data plane over a route learned from BGP. This is
  the seam Cilium leaves open: its BGP control plane only advertises, learned
  routes never program its datapath (cilium/cilium#34841).

  Topology:
  ```
   pod1(10.244.1.2) ─ crdl* [node1: cradle+zebra AS65001] n0 ─ 10.0.12.0/24 ─ n0 [node2: cradle+zebra AS65002] crdl* ─ pod2(10.244.2.2)
                             advertises 10.244.1.0/24                              advertises 10.244.2.0/24
  ```

  Scenario: Pods on different nodes reach each other via BGP-learned routes
    Given a clean test environment
    When I create namespace "node1"
    And I create namespace "node2"
    And I create namespace "pod1"
    And I create namespace "pod2"
    And I connect namespace "node1" interface "n0" to namespace "node2" interface "n0"
    And I add address "10.0.12.1/24" to interface "n0" in namespace "node1"
    And I add address "10.0.12.2/24" to interface "n0" in namespace "node2"
    And I disable IPv4 forwarding in namespace "node1"
    And I disable IPv4 forwarding in namespace "node2"
    And I start cradle CNI node in namespace "node1" with config "node.json" serving gRPC as "ctl1"
    And I start cradle CNI node in namespace "node2" with config "node.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "node1" with config "zebra1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "node2" with config "zebra2.yaml" teeing to cradle as "ctl2"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node1" with config "cni1.json" expecting "10.244.1.2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node2" with config "cni2.json" expecting "10.244.2.2"
    Then kernel route "10.244.2.0/24" in namespace "node1" should eventually contain "10.0.12.2"
    And kernel route "10.244.1.0/24" in namespace "node2" should eventually contain "10.0.12.1"
    And ping from "pod1" to "10.244.2.2" should eventually succeed
    And ping from "pod2" to "10.244.1.2" should succeed
    And the cradle stat "l3v4_forward" in namespace "node1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "l3v4_forward" in namespace "node2" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "node1"
    And I stop the zebra-rs tee in namespace "node2"
    And I stop cradle CNI node in namespace "node1"
    And I stop cradle CNI node in namespace "node2"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "node1"
    And I delete namespace "node2"
    Then the test environment should be clean
