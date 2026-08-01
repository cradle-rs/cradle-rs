@serial
@cradle_vpws_mpls6_zebra
Feature: BGP EVPN VPWS over MPLS between IPv6 PEs programs the eBPF E-Line
  The EVPN VPWS provider edge (RFC 8214) under `encapsulation mpls` with
  IPv6 PEs — the v6 twin of cradle_vpws_mpls_zebra. Each `vpws` service
  advertises a per-service label on its Type-1 (no Encapsulation EC —
  RFC 8365 §5.1.3's default) with the `vtep-source` v6 loopback as next
  hop; importing the peer's Type-1 drives one cradle AddXconnect that
  imposes the remote's service label toward its v6 PE — resolved by a
  FIB6 /128 in the datapath — and binds the local label's pop-to-AC
  disposition for the return direction. Direct PE-PE link: the service
  label rides alone.

  Same transparency contract as every E-Line twin: ARP resolves through
  the service, nothing on the CE path is pinned, kernel v4+v6 forwarding
  off on the PEs, and per-direction labels are downstream-assigned.

  Topology:
  ```
   c1 ── pe1[zebra+cradle] ──2001:db8:12::/64── pe2[zebra+cradle] ── c2
   10.0.0.1        lo 2001:db8:255::1 | ::2               10.0.0.2
      vpws eline1: evi 100, svc-id 101 ⇄ 102 (whole-port)
      vpws eline2: evi 200, svc-id 201 ⇄ 202 (VID 30, same AC)
  ```

  Scenario: Cross-connect two CEs through a BGP-signalled MPLS E-Line on v6 PEs
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
    Then BGP session in "pe1" to "2001:db8:255::2" should be "Established"
    # The E-Line is transparent: ARP + ICMP ride the cross-connect, both
    # directions, with zero static state anywhere.
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_dx2" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_dx2" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # Pure MPLS E-Line: nothing bridged, nothing leaked into the other
    # encapsulations' E-Line paths.
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be zero
    And the cradle stat "srv6_dx2" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "vxlan_dx2" in namespace "pe1" via gRPC as "ctl1" should be zero

  Scenario: A VLAN-scoped E-Line multiplexes the same ACs by 802.1Q VID
    Given the test topology exists
    # eline2 (evi 200, VID 30) shares pe1c/pe2c with the untagged eline1:
    # VID-30 frames ride the VLAN-scoped service, demuxed at the egress
    # from the DX2V table; untagged traffic still rides eline1.
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
