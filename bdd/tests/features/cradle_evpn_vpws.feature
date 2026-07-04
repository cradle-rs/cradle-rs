@serial
@cradle_evpn_vpws
Feature: EVPN VPWS (End.DX2 / End.DX2V) — E-Line over SRv6 in eBPF
  As an operator selling point-to-point Ethernet (RFC 8214 E-Line)
  I want End.DX2 and End.DX2V executed in eBPF
  So that an attachment circuit cross-connects to its remote peer as a
  transparent wire: every frame — any EtherType, ARP included — is
  MAC-in-SRv6 encapsulated toward the remote service SID, and the
  egress emits the inner frame raw on the AC. No FDB, no learning, no
  flooding, no MAC rewrite.

  The transparency IS the assertion: c1 and c2 share subnets and
  resolve each other's MACs by ARP *through the service* — nothing is
  pinned on the CE path (only the two underlay neighbors are). Kernel
  v4+v6 forwarding off on the PEs, seg6 never enabled.

  Topology (double AC pair — untagged E-Line via DX2, VLAN-tagged
  E-Line via DX2V):
  ```
   c1 eth0 ── pe1c                     pe2c ── eth0 c2     10.0.0.0/24
   c1 eth1.30 ─ pe1v   pe1u ══ pe2u   pe2v ─ eth1.30 c2   10.0.30.0/24
                    2001:db8::/64 underlay
  ```
  pe1: xconnect pe1c→fd00:2::d2, pe1v→fd00:2::dd2; SIDs fd00:1::d2
  (End.DX2 → pe1c) and fd00:1::dd2 (End.DX2V table 7, vid 30 → pe1v).
  pe2 is the mirror.

  Scenario: Untagged and VLAN-tagged E-Lines carry traffic transparently
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "c1" interface "eth1" to namespace "pe1" interface "pe1v"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I connect namespace "pe2" interface "pe2v" to namespace "c2" interface "eth1"
    And I execute "ip link set dev pe1u address 02:00:00:00:0a:01" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:0b:01" in namespace "pe2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    And I execute "ip link set dev eth1 up" in namespace "c1"
    And I execute "ip link set dev eth1 up" in namespace "c2"
    And I execute "ip link add link eth1 name eth1.30 type vlan id 30" in namespace "c1"
    And I execute "ip link add link eth1 name eth1.30 type vlan id 30" in namespace "c2"
    And I execute "ip addr add 10.0.30.1/24 dev eth1.30" in namespace "c1"
    And I execute "ip addr add 10.0.30.2/24 dev eth1.30" in namespace "c2"
    And I execute "ip link set dev eth1.30 up" in namespace "c1"
    And I execute "ip link set dev eth1.30 up" in namespace "c2"
    # veth TX VLAN acceleration puts the 802.1Q tag in skb->vlan_tci, not
    # in the frame — XDP never sees it and the encap would carry the
    # inner frame untagged. Force in-band tagging on the ACs.
    And I execute "ethtool -K eth1 txvlan off" in namespace "c1"
    And I execute "ethtool -K eth1 txvlan off" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    # Untagged E-Line (End.DX2): ARP + ICMP ride the cross-connect.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "srv6_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_dx2" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # Tagged E-Line (End.DX2V): the 802.1Q VID picks the AC at the
    # egress; the tag survives end to end.
    Then ping from "c1" to "10.0.30.2" should eventually succeed
    And the cradle stat "srv6_dx2" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
