@serial
@cradle_policy
Feature: Ingress network policy in the eBPF datapath
  cradle enforces Kubernetes-style ingress NetworkPolicy natively: pod IPs map
  to label-set identities, and an enforced pod endpoint drops ingress that is
  neither a reply to a pod-initiated flow (stateful, via PCT) nor matched by
  an allow rule. Policy is checked in `cradle_tc` where the destination
  resolves to the pod's veth — so same-node and fabric-ingress traffic
  enforce at the same point. Kernel forwarding is off, so the datapath is the
  only thing that could carry or drop the packets. Design: docs/design/policy.md.

  Topology (single node, cradle-cni pods):
  ```
   host1(10.1.1.2, "world") ── n0 [node: cradle serve] crdl* ── pod1(id 100), pod2(id 200)
  ```

  Scenario: Allow by identity, deny world, and un-enforce
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
    Then ping from "pod1" to "10.244.0.3" should eventually succeed
    And ping from "host1" to "10.244.0.3" should succeed
    When I apply cradle config "policy-on.json" to namespace "node" via gRPC as "ctl"
    Then ping from "pod1" to "10.244.0.3" should succeed
    And ping from "host1" to "10.244.0.3" should fail
    And the cradle stat "policy_drop" in namespace "node" via gRPC as "ctl" should be nonzero
    When I apply cradle config "policy-off.json" to namespace "node" via gRPC as "ctl"
    Then ping from "host1" to "10.244.0.3" should eventually succeed

  Scenario: Stateful replies pass an enforced endpoint with no allow rules
    Given the test topology exists
    When I serve HTTP "p2" in namespace "pod2" bound to "10.244.0.3"
    And I apply cradle config "policy-pct.json" to namespace "node" via gRPC as "ctl"
    Then ping from "host1" to "10.244.0.2" should fail
    And HTTP GET "http://10.244.0.3:8080/" from namespace "pod1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop HTTP in namespace "pod2"
    And I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
