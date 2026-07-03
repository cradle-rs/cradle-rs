@serial
@cradle_evpn_srv6
Feature: EVPN over SRv6 (End.DT2U) bridges L2 across the eBPF data plane
  As an operator running an L2VPN over an SRv6 fabric on cradle
  I want a CE Ethernet frame carried inside SRv6 to the remote PE's L2 SID
  So that two CEs in one bridge domain reach each other over the IPv6 underlay,
  with the encap and End.DT2U decap done entirely in eBPF.

  Topology (kernel v4+v6 forwarding and seg6 off on pe1/pe2; the SRv6 fabric
  is a single IPv6 underlay hop):
  ```
   c1 ── pe1[cradle] ──2001:db8::/64── pe2[cradle] ── c2
    bd 100         End.DT2U fd00:1::100 / fd00:2::100        bd 100
   10.0.0.1                                                 10.0.0.2
  ```
  c1 and c2 share bridge domain 100 (one L2 subnet). A frame from c1 to c2
  arrives on pe1's L2 port; its destination MAC resolves to a remote FDB entry
  (c2 is behind pe2's End.DT2U SID), so pe1 MAC-in-SRv6 encapsulates it
  (outer IPv6, next-header 143, DA = fd00:2::100) and forwards it over the
  underlay. pe2 matches its End.DT2U SID, strips the outer header, and bridges
  the inner Ethernet frame into bd 100 out to c2. Static ARP on the CEs and a
  static overlay FDB on the PEs keep the path deterministic and BUM-free
  (End.DT2M / flood is a later slice).

  Scenario: Bridge two CEs across an eBPF EVPN-over-SRv6 domain (End.DT2U)
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
    And the cradle stat "srv6_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
