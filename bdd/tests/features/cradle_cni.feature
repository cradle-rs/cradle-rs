@serial
@cradle_cni
Feature: Kubernetes CNI plugin attaches pods to the eBPF data plane
  cradle-cni (CNI spec 1.1) wires pod network namespaces into a cradle node:
  it allocates the pod address from the node's pod CIDR over the daemon's
  gRPC API, creates the veth pair and the pod's ptp default route, and the
  daemon programs the pod /32 into the eBPF FIB on the host-side veth.
  Kernel IP forwarding on the node is disabled, so every forwarded path
  proves the eBPF data plane carried the traffic.

  Topology:
  ```
   host1(10.1.1.2) ── n0 [node: cradle serve] crdl* ── pod1, pod2 (10.244.0.0/24)
  ```

  Scenario: Attach two pods and forward between pods, node, and off-node
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
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json" expecting "10.244.0.2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" expecting "10.244.0.3"
    Then ping from "pod1" to "10.1.1.1" should eventually succeed
    And ping from "pod1" to "10.244.0.3" should eventually succeed
    And ping from "pod2" to "10.244.0.2" should succeed
    And ping from "pod1" to "10.1.1.2" should eventually succeed
    And ping from "host1" to "10.244.0.2" should succeed
    And the cradle stat "l3v4_forward" in namespace "node" via gRPC as "ctl" should be nonzero

  Scenario: Delete an endpoint idempotently
    Given the test topology exists
    When I run CNI DEL for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json"
    Then ping from "host1" to "10.244.0.2" should fail
    And ping from "host1" to "10.244.0.3" should succeed
    When I run CNI DEL for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json"
    Then ping from "host1" to "10.244.0.2" should fail

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
