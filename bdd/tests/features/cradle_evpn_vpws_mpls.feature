@serial
@cradle_evpn_vpws_mpls
Feature: EVPN VPWS over MPLS — E-Line in eBPF (RFC 8214 / RFC 7432)
  As an operator selling point-to-point Ethernet (RFC 8214 E-Line)
  I want the VPWS cross-connect executed over MPLS in eBPF
  So that an attachment circuit cross-connects to its remote peer as a
  transparent wire over a plain label-switched underlay: every frame —
  any EtherType, ARP included — is imposed with the service label the
  remote advertised under the transport LSP toward its PE, and the
  egress pops its own service label and emits the inner frame raw on
  the AC. No FDB, no learning, no flooding, no MAC rewrite, no bridge.

  The transparency IS the assertion: c1 and c2 share subnets and
  resolve each other's MACs by ARP *through the service* — nothing is
  pinned on the CE path (only the two underlay neighbors are). Kernel
  v4+v6 forwarding off on the PEs. Service labels are asymmetric on
  purpose — each direction carries the label its EGRESS end assigned
  (the downstream-assigned Type-1 label-field semantic).

  Topology (double AC pair — untagged E-Line, VLAN-tagged E-Line whose
  inner 802.1Q VID picks the AC at the egress via the DX2V table):
  ```
   c1 eth0 ── pe1c                     pe2c ── eth0 c2     10.0.0.0/24
   c1 eth1.30 ─ pe1v   pe1u ══ pe2u   pe2v ─ eth1.30 c2   10.0.30.0/24
                    10.0.1.0/24 underlay (eBPF-only MPLS)
  ```
  pe1 (PE 10.255.0.1): transport label 16 toward pe2's PE loopback;
  pe1c → pe 10.255.0.2 label 2101, decap label 1101; pe1v → pe
  10.255.0.2 label 2130 (vid 30), decap label 1130 over DX2V table 7.
  pe2 (PE 10.255.0.2, transport label 26 back) is the mirror.

  Scenario: Untagged and VLAN-tagged E-Lines carry traffic over MPLS
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
    # Untagged E-Line: ARP + ICMP ride the cross-connect as MPLS.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_dx2" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # Tagged E-Line: the inner 802.1Q VID picks the AC at the egress
    # (DX2V table demux); the tag survives end to end.
    Then ping from "c1" to "10.0.30.2" should eventually succeed
    And the cradle stat "mpls_dx2" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    # The E-Line never touched the bridging or flooding paths, and never
    # fell back to another overlay.
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be zero
    And the cradle stat "mpls_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be zero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
