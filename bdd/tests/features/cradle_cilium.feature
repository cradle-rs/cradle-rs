@serial
@cradle_cilium
Feature: The stock cilium-cni plugin drives the cradle data plane
  cradle serves the cilium-agent REST API subset (`--cilium-sock`), so the
  UNMODIFIED cilium-cni binary (pinned v1.19.5, extracted from the official
  image by deploy/fetch-cilium-cni.sh) is a drop-in front end: it allocates
  the pod address over `POST /ipam`, plumbs the veth pair and pod routes
  itself from the advertised ptp gateway, and hands the host interface to
  cradle via `PUT /endpoint`, which programs the pod /32 into the eBPF FIB.
  Kernel forwarding on the node is disabled, so pod connectivity proves the
  cradle datapath carried the traffic — Cilium's own CNI, cradle's eBPF.

  Topology:
  ```
   host1(10.1.1.2) ── n0 [node: cradle serve --cilium-sock] lxc* ── pod1, pod2 (10.244.0.0/24)
  ```

  Scenario: Attach two pods with the unmodified cilium-cni
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
    And I start cradle Cilium node in namespace "node" with config "node.json" pod CIDR "10.244.0.0/24" serving gRPC as "ctl" and Cilium API as "capi"
    And I run stock cilium-cni ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cilium.json" via Cilium API "capi" expecting "10.244.0.2"
    And I run stock cilium-cni ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cilium.json" via Cilium API "capi" expecting "10.244.0.3"
    Then ping from "pod1" to "10.1.1.1" should eventually succeed
    And ping from "pod1" to "10.244.0.3" should eventually succeed
    And ping from "pod2" to "10.244.0.2" should succeed
    And ping from "pod1" to "10.1.1.2" should eventually succeed
    And ping from "host1" to "10.244.0.2" should succeed
    And the cradle stat "l3v4_forward" in namespace "node" via gRPC as "ctl" should be nonzero

  Scenario: Delete an endpoint with the unmodified cilium-cni
    Given the test topology exists
    When I run stock cilium-cni DEL for container "pod1" in pod namespace "pod1" on node "node" with config "cilium.json" via Cilium API "capi"
    Then ping from "host1" to "10.244.0.2" should fail
    And ping from "host1" to "10.244.0.3" should succeed
    When I run stock cilium-cni DEL for container "pod1" in pod namespace "pod1" on node "node" with config "cilium.json" via Cilium API "capi"
    Then ping from "host1" to "10.244.0.2" should fail

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
