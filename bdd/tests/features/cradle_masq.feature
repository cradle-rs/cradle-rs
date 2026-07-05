@serial
@cradle_masq
Feature: Egress masquerade (pod → outside the cluster)
  A pod's traffic to a destination outside the cluster is SNAT'd to the
  node's uplink IP, so a fabric host with no route back to the pod CIDR can
  still reply — the reply lands on the node and un-NATs back to the pod
  (folded into the existing conntrack). In-cluster traffic (a NON_MASQ CIDR)
  is left untouched. Kernel forwarding on the node is off, so both the
  outbound masquerade and the return path are the eBPF datapath's doing.
  Design: docs/design/kube-proxy-dualstack.md (K2).

  Topology:
  ```
   pod1(10.244.0.2) ─ crdl* [node: cradle serve, uplink 203.0.113.1] n0 ── inet(203.0.113.9)
   pod2(10.244.0.3)                masq_node 203.0.113.1, non_masq 10.244.0.0/24
   inet has NO route to 10.244.0.0/24 — only masquerade makes the reply return.
  ```

  Scenario: Pod egress is masqueraded; in-cluster traffic is not
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "inet"
    And I create namespace "pod1"
    And I create namespace "pod2"
    And I connect namespace "node" interface "n0" to namespace "inet" interface "eth0"
    And I add address "203.0.113.1/24" to interface "n0" in namespace "node"
    And I add address "203.0.113.9/24" to interface "eth0" in namespace "inet"
    And I disable IPv4 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json" expecting "10.244.0.2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" expecting "10.244.0.3"
    And I serve source-echo HTTP in namespace "inet" bound to "203.0.113.9"
    And I serve source-echo HTTP in namespace "pod2" bound to "10.244.0.3"
    # pod → external host: the reply only returns because the source was
    # masqueraded to the node IP (inet has no route to the pod CIDR).
    Then HTTP GET "http://203.0.113.9:8080/" from namespace "pod1" should contain "203.0.113.1"
    And the cradle stat "masq" in namespace "node" via gRPC as "ctl" should be nonzero
    # pod → pod: a NON_MASQ (in-cluster) destination is not rewritten — the
    # far pod sees the real pod source IP.
    And HTTP GET "http://10.244.0.3:8080/" from namespace "pod1" should contain "10.244.0.2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop HTTP in namespace "inet"
    And I stop HTTP in namespace "pod2"
    And I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "inet"
    And I delete namespace "node"
    Then the test environment should be clean
