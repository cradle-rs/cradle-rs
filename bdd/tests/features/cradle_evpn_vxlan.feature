@serial
@cradle_evpn_vxlan
Feature: EVPN/VXLAN bridges L2 across the eBPF data plane
  As an operator running an L2VPN over a VXLAN fabric on cradle
  I want a CE Ethernet frame carried inside VXLAN to the remote VTEP
  So that two CEs in one bridge domain reach each other over the IPv4 underlay,
  with the encap and decap done entirely in eBPF — no kernel vxlan device.

  Topology (kernel v4+v6 forwarding off on pe1/pe2; the VXLAN fabric is a
  single IPv4 underlay hop; the VTEP addresses live only in the eBPF maps):
  ```
   c1 ── pe1[cradle] ──10.100.0.0/24── pe2[cradle] ── c2
    bd 100         VTEP 10.100.0.1 / 10.100.0.2         bd 100
   10.0.0.1                VNI 10100                   10.0.0.2
  ```
  c1 and c2 share bridge domain 100 (one L2 subnet), bound to L2VNI 10100
  (deliberately different from the VLAN id, proving the VNI↔bd mapping). A
  frame from c1 to c2 arrives on pe1's L2 port; its destination MAC resolves
  to a remote FDB entry (c2 is behind VTEP 10.100.0.2), so pe1 VXLAN-
  encapsulates it (outer IPv4 + UDP 4789 + VNI 10100) and forwards it over
  the underlay. pe2 matches its local VTEP address, strips the outer headers,
  and bridges the inner Ethernet frame into bd 100 out to c2. Static ARP on
  the CEs and a static overlay FDB on the PEs keep the path deterministic and
  BUM-free (the flood tunnel is a later slice).

  Scenario: Bridge two CEs across an eBPF EVPN/VXLAN domain
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
    And I execute "ip neigh replace 10.0.0.2 lladdr 02:00:00:00:c2:02 dev eth0 nud permanent" in namespace "c1"
    And I execute "ip neigh replace 10.0.0.1 lladdr 02:00:00:00:c1:01 dev eth0 nud permanent" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "::ffff:10.100.0.2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
