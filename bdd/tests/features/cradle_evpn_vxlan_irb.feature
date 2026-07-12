@serial
@cradle_evpn_vxlan_irb
Feature: EVPN/VXLAN symmetric IRB routes between subnets across the fabric
  As an operator running EVPN/VXLAN with inter-subnet routing on cradle
  I want a routed packet between two different tenant subnets carried over an
  L3VNI, in a per-VRF FIB, with router-MAC rewrite
  So that two hosts in different subnets reach each other entirely in eBPF —
  routed (not bridged) at each PE. RFC 9135 symmetric IRB.

  The datapath reuses the per-VRF FIB and the End.DT46-style VRF handoff: at
  the ingress PE the routed packet resolves to an NH_F_VXLAN nexthop, gets a
  fresh inner Ethernet header (dst = the remote PE's router MAC), and is
  VXLAN-wrapped with the L3VNI; at the egress PE the L3VNI decap hands the
  inner IP to l3_forward, which routes it in the tenant VRF to the local
  subnet. This is a cradle-native datapath test driven by static config —
  the BGP-EVPN Type-5/RMAC tee is a later slice.

  Topology (kernel forwarding off; VTEPs are identifiers only, the underlay
  adjacency is an explicit nexthop):
  ```
   c1(10.1.1.100/24) ── pe1[cradle] ──10.0.12.0/24── pe2[cradle] ── c2(10.2.2.100/24)
     subnet A          VRF 10, L3VNI 5000, VTEP 192.0.2.1|192.0.2.2         subnet B
  ```

  Scenario: Route between two tenant subnets over an eBPF L3VNI
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I execute "ip link set dev pe1u address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I add address "10.1.1.100/24" to interface "eth0" in namespace "c1"
    And I add address "10.2.2.100/24" to interface "eth0" in namespace "c2"
    And I add address "10.1.1.1/24" to interface "pe1c" in namespace "pe1"
    And I add address "10.2.2.1/24" to interface "pe2c" in namespace "pe2"
    And I add address "10.0.12.1/24" to interface "pe1u" in namespace "pe1"
    And I add address "10.0.12.2/24" to interface "pe2u" in namespace "pe2"
    And I add route "default" via "10.1.1.1" in namespace "c1"
    And I add route "default" via "10.2.2.1" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.2.2.100" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.2.2.100" should eventually succeed
    And ping from "c2" to "10.1.1.100" should eventually succeed
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe2" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
