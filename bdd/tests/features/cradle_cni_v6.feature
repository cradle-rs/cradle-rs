@serial
@cradle_cni_v6
Feature: Dual-stack pods (IPv4 + IPv6 IPAM) via cradle-cni
  cradle-cni allocates both a v4 and a v6 pod address (node-local IPAM),
  plumbs the veth with a ptp gateway per family (169.254.1.1 / fe80::1 +
  permanent neighbor entries), and the daemon programs the pod /32 into
  FIB4 and the pod /128 into FIB6. Kernel forwarding (v4 and v6) is off on
  the node, so both families forwarding proves the eBPF datapath carried
  them. Design: docs/design/kube-proxy-dualstack.md (K1).

  Topology:
  ```
   host1(10.1.1.2 / fd00:1::2) ── n0 [node: cradle serve] crdl* ── pod1, pod2
                                       v4 10.244.0.0/24, v6 fd00:244::/64
  ```

  Scenario: Attach dual-stack pods and forward both families
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "host1"
    And I create namespace "pod1"
    And I create namespace "pod2"
    And I connect namespace "node" interface "n0" to namespace "host1" interface "eth0"
    And I add address "10.1.1.1/24" to interface "n0" in namespace "node"
    And I add address "10.1.1.2/24" to interface "eth0" in namespace "host1"
    And I add address "fd00:1::1/64" to interface "n0" in namespace "node"
    And I add address "fd00:1::2/64" to interface "eth0" in namespace "host1"
    And I add route "10.244.0.0/24" via "10.1.1.1" in namespace "host1"
    And I add route "fd00:244::/64" via "fd00:1::1" in namespace "host1"
    And I disable IPv4 forwarding in namespace "node"
    And I disable IPv6 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json" expecting "fd00:244::2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" expecting "fd00:244::3"
    Then ping from "pod1" to "10.244.0.3" should eventually succeed
    And ping from "pod1" to "fd00:244::3" should eventually succeed
    And ping from "pod2" to "fd00:244::2" should succeed
    And ping from "pod1" to "fd00:1::1" should eventually succeed
    And ping from "host1" to "fd00:244::2" should succeed
    And the cradle stat "l3v6_forward" in namespace "node" via gRPC as "ctl" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
