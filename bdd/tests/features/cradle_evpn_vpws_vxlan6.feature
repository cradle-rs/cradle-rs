@serial
@cradle_evpn_vpws_vxlan6
Feature: EVPN VPWS over VXLAN with an IPv6 underlay — E-Line in eBPF
  As an operator selling point-to-point Ethernet (RFC 8214 E-Line)
  I want the VPWS cross-connect executed over VXLAN whose VTEPs are IPv6
  So that the E-Line rides an IPv6-only fabric: every frame is
  VXLAN-encapsulated in an outer IPv6 + UDP toward the remote's v6 VTEP
  (native in the 16-byte target slot, not v4-mapped), and the egress
  matches its own E-Line VNI on the v6 decap and emits the inner frame
  raw on the AC — the v6-underlay twin of cradle_evpn_vpws_vxlan.

  Same transparency contract as the v4 feature: c1 and c2 resolve each
  other by ARP *through the service*, nothing on the CE path is pinned,
  kernel v4+v6 forwarding off on the PEs, VNIs asymmetric on purpose.
  The xconnect targets carry no explicit adjacency, so every encap
  resolves its VTEP through a FIB6 /128 — the tagged pair additionally
  proves the v6 decap's inner-802.1Q DX2V demux (the VID is read past
  the 70-byte outer encapsulation).

  Topology (double AC pair — untagged E-Line, VLAN-tagged E-Line):
  ```
   c1 eth0 ── pe1c                     pe2c ── eth0 c2     10.0.0.0/24
   c1 eth1.30 ─ pe1v   pe1u ══ pe2u   pe2v ─ eth1.30 c2   10.0.30.0/24
                    2001:db8::/64 underlay (eBPF-only)
  ```
  pe1 (VTEP 2001:db8::1): pe1c → vtep 2001:db8::2 vni 5002, decap vni
  5001; pe1v → vtep 2001:db8::2 vni 5032 (vid 30), decap vni 5031 over
  DX2V table 7. pe2 (VTEP 2001:db8::2) is the mirror.

  Scenario: Untagged and VLAN-tagged E-Lines carry traffic over v6 VXLAN
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
    # Untagged E-Line: ARP + ICMP ride the cross-connect as v6 VXLAN.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_dx2" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # Tagged E-Line: the inner 802.1Q VID picks the AC at the egress
    # (DX2V demux behind the 70-byte v6 outer); the tag survives.
    Then ping from "c1" to "10.0.30.2" should eventually succeed
    And the cradle stat "vxlan_dx2" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    # The E-Line never touched the bridging paths: no flood, no bridged
    # VXLAN decap (vxlan_dx2 is the only decap counter that moved).
    And the cradle stat "vxlan_flood" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be zero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
