@serial
@cradle_cni_restart
Feature: CNI endpoint lifecycle — daemon restart and GC
  The daemon persists IPAM allocations and endpoint records under its state
  dir. A restarted daemon loads a fresh eBPF object (its predecessor's maps
  died with it), clears the predecessor's stale TC filter, and re-programs
  every stored endpoint (reconcile); allocations survive, so a pod added
  after the restart draws the next free address, not a reused one. CNI GC
  sweeps every endpoint the runtime no longer lists as valid.

  Topology (single node, as in cradle_cni):
  ```
   host1(10.1.1.2) ── n0 [node: cradle serve] crdl* ── pod1, pod2, pod3 (10.244.0.0/24)
  ```

  Scenario: Endpoints survive a daemon restart
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "host1"
    And I create namespace "pod1"
    And I create namespace "pod2"
    And I create namespace "pod3"
    And I connect namespace "node" interface "n0" to namespace "host1" interface "eth0"
    And I add address "10.1.1.1/24" to interface "n0" in namespace "node"
    And I add address "10.1.1.2/24" to interface "eth0" in namespace "host1"
    And I add route "10.244.0.0/24" via "10.1.1.1" in namespace "host1"
    And I disable IPv4 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json" expecting "10.244.0.2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" expecting "10.244.0.3"
    And I run CNI CHECK for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json"
    Then ping from "pod1" to "10.244.0.3" should eventually succeed
    When I stop cradle in namespace "node"
    And I restart cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    Then ping from "pod1" to "10.244.0.3" should eventually succeed
    And ping from "host1" to "10.244.0.2" should eventually succeed
    And the cradle stat "l3v4_forward" in namespace "node" via gRPC as "ctl" should be nonzero
    When I run CNI ADD for container "pod3" in pod namespace "pod3" on node "node" with config "cni.json" expecting "10.244.0.4"
    Then ping from "pod3" to "10.244.0.2" should eventually succeed

  Scenario: GC removes endpoints the runtime no longer lists
    Given the test topology exists
    When I run CNI GC on node "node" with config "gc.json"
    Then ping from "host1" to "10.244.0.2" should succeed
    And ping from "host1" to "10.244.0.3" should fail
    And ping from "host1" to "10.244.0.4" should fail
    And CNI CHECK for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" should fail

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "pod3"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
