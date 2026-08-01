@serial
@cradle_vpws_vxlan6_zebra
Feature: BGP EVPN VPWS over IPv6-underlay VXLAN programs the eBPF E-Line
  The full EVPN VPWS provider edge (RFC 8214) over a VXLAN fabric whose
  VTEPs are IPv6 — the v6 twin of cradle_vpws_vxlan_zebra. A VPWS service
  has no VXLAN device to take a VTEP from, and the router-id fallback can
  only express an IPv4 one, so each PE names its v6 loopback with the
  `vtep-source` leaf: the Type-1 then carries the service VNI in its
  label field, the VXLAN Encapsulation EC, and the v6 VTEP as next hop.
  Importing the peer's Type-1 drives one cradle AddXconnect binding the
  E-Line both ways — the AC's ingress XCONNECT toward the remote v6 VTEP
  (native in the 16-byte slot) with the VNI the REMOTE advertised, the
  local E-Line VNI decap on the v6 side (VXLAN_SRC6 from SetVtepSource),
  and the encap's FIB6 /128 resolution — everything over the tee, zero
  static state in cradle.

  Topology (kernel v4+v6 forwarding off on the PEs):
  ```
   c1 ── pe1[cradle+zebra] ──2001:db8:12::/64── pe2[cradle+zebra] ── c2
   10.0.0.1  VTEP 2001:db8:ff::1 (lo) | ::2 (lo)            10.0.0.2
      vpws eline1: evi 100, pe1 svc-id 101 (vni 5001) ⇄ pe2 svc-id 102
  ```

  Scenario: Cross-connect two CEs through a BGP-signalled v6 VXLAN E-Line
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8:ff::2" should be "Established"
    # The E-Line is transparent: ARP + ICMP ride the cross-connect, both
    # directions, with zero static state anywhere.
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_dx2" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_dx2" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # Pure VXLAN: nothing fell back to (or leaked into) the SRv6 E-Line
    # path on either PE.
    And the cradle stat "srv6_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "srv6_dx2" in namespace "pe1" via gRPC as "ctl1" should be zero

  Scenario: A VLAN-scoped E-Line multiplexes the same ACs by 802.1Q VID
    Given the test topology exists
    # eline2 (evi 200, VID 30, VNI defaulting to the EVI on both ends)
    # shares pe1c/pe2c with the untagged eline1: VID-30 frames ride the
    # VLAN-scoped service, demuxed at the egress from the DX2V table
    # behind the 70-byte v6 outer encapsulation; untagged traffic still
    # rides eline1.
    #
    # VLAN offloads must be OFF on the CE side of the AC: with them on,
    # the CE transmits the 802.1Q tag as skb *metadata* (never in the
    # packet bytes), and XDP — which sees only bytes — cannot demux the
    # VID. The standard operational requirement for any XDP VLAN path.
    When I execute "ethtool -K eth0 txvlan off rxvlan off" in namespace "c1"
    And I execute "ethtool -K eth0 txvlan off rxvlan off" in namespace "c2"
    And I execute "ip link add link eth0 name eth0.30 type vlan id 30" in namespace "c1"
    And I execute "ip addr add 10.0.30.1/24 dev eth0.30" in namespace "c1"
    And I execute "ip link set dev eth0.30 up" in namespace "c1"
    And I execute "ip link add link eth0 name eth0.30 type vlan id 30" in namespace "c2"
    And I execute "ip addr add 10.0.30.2/24 dev eth0.30" in namespace "c2"
    And I execute "ip link set dev eth0.30 up" in namespace "c2"
    Then ping from "c1" to "10.0.30.2" should eventually succeed
    And ping from "c2" to "10.0.30.1" should eventually succeed
    # The untagged E-Line still works alongside its VLAN-scoped twin.
    And ping from "c1" to "10.0.0.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
