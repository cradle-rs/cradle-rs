@serial
@cradle_evpn_vxlan_bum
Feature: EVPN/VXLAN BUM floods L2 across the eBPF data plane
  As an operator running an L2VPN over a VXLAN fabric on cradle
  I want broadcast/unknown frames (ARP) carried to the remote VTEP
  So that CEs resolve each other over the overlay with no static ARP, and the
  BUM flood + VXLAN decap happen entirely in eBPF.

  Topology (kernel v4+v6 forwarding off on pe1/pe2; no kernel vxlan device):
  ```
   c1 ── pe1[cradle] ──10.100.0.0/24── pe2[cradle] ── c2
    bd 100         VTEP 10.100.0.1 / 10.100.0.2         bd 100
   10.0.0.1                VNI 10100                   10.0.0.2
  ```
  Unlike the unicast test there is NO static ARP: c1's ARP for c2 is
  broadcast, so pe1 tunnels it toward the bridge domain's BUM VTEP — the
  all-ones-MAC FDB entry with a remote_vtep is the per-BD BUM sentinel
  (the flood counter, not the unicast one, counts it). pe2 matches its
  local VTEP address, strips the outer headers, and floods the inner
  (broadcast) frame into bd 100 out to c2. c2's unicast reply then rides
  the unicast FDB entries, and once the CEs have learned each other the
  ping flows unicast both ways. A successful ping therefore proves the
  BUM path carried the ARP.

  Scenario: Resolve and bridge two CEs over EVPN/VXLAN BUM
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:02" in namespace "c2"
    And I execute "ip link set dev pe1u address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "vxlan_flood" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
