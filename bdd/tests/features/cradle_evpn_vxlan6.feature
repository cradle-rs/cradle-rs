@serial
@cradle_evpn_vxlan6
Feature: EVPN/VXLAN bridges L2 over an IPv6 underlay
  As an operator running an L2VPN over a VXLAN fabric on cradle
  I want a CE Ethernet frame carried inside VXLAN to a remote IPv6 VTEP
  So that two CEs in one bridge domain reach each other over the IPv6
  underlay, with the encap and decap done entirely in eBPF — the v6 twin
  of cradle_evpn_vxlan (outer Ethernet + IPv6 + UDP 4789, zero UDP
  checksum per RFC 6935/6936).

  Topology (kernel v4+v6 forwarding off on pe1/pe2; the VXLAN fabric is a
  single IPv6 underlay hop; the VTEP addresses live only in the eBPF maps):
  ```
   c1 ── pe1[cradle] ──2001:db8::/64── pe2[cradle] ── c2
    bd 100        VTEP 2001:db8::1 / ::2               bd 100
   10.0.0.1               VNI 10100                   10.0.0.2
  ```
  The two PEs deliberately differ in how they are configured, covering
  both halves of the v6 surface in one run: pe1 sets the v6 VTEP through
  the family-agnostic `vtep_source` knob and pins the remote's underlay
  adjacency with an explicit FDB nexthop; pe2 uses the dual-stack
  `vtep_source6` field and leaves the FDB nexthop 0, so its encap
  resolves the VTEP through a FIB6 /128 route — the path a control-plane
  tee exercises. A frame from c1 hits pe1's L2 port, matches the remote
  FDB entry (c2 is behind VTEP 2001:db8::2, carried native — not
  v4-mapped — in the 16-byte address slot), gains the 70-byte outer
  Ethernet+IPv6+UDP+VXLAN encapsulation and rides the underlay; pe2
  matches its local v6 VTEP, strips the outer headers and bridges the
  inner frame to c2. Static ARP on the CEs and a static overlay FDB keep
  the path deterministic and BUM-free.

  Scenario: Bridge two CEs across an eBPF EVPN/VXLAN IPv6-underlay domain
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
    And the cradle stat "vxlan_encap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "2001:db8::2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
