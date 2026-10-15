@serial
@cradle_evpn_etree_vxlan_zebra
Feature: EVPN E-Tree over VXLAN driven by zebra-rs — leaf-only PEs from BGP
  As an operator running an EVPN E-Tree over a VXLAN fabric with zebra-rs
  I want each PE's leaf-only colour carried on its IMET and turned into
  cradle's leaf-only marks by the other PEs
  So that a leaf's BUM never reaches a leaf on another PE where the PEs'
  roles make that decidable, with no static marks anywhere.

  `cradle_evpn_etree_vxlan` proves the datapath with static configuration.
  Here zebra-rs drives it (E-Tree plan phase 4b, the V1+ scheme):
  - a PE whose ACs in a VNI are all leaves colours that VNI's IMET with the
    E-Tree EC's Leaf flag. zebra-rs knows a VNI's ACs from the kernel
    bridge: the bridge ports that are not the VXLAN device;
  - a PE with a leaf AC of its own tells cradle which remote VTEPs are
    leaf-only, per bridge domain (`SetEtreeRemote`);
  - between two mixed PEs (leaf and root ACs both) a leaf's BUM still
    reaches the other's leaves, and `show bgp evpn etree` warns about it.

  Topology: pe1 is leaf-only (one leaf host), pe2 is mixed (a leaf and a
  root host). iBGP EVPN over loopback VTEPs, VNI 100 = bd 100. The access
  ports are in br100 with vxlan100. tc counters on l1 and l2 count what
  each receives from the other leaf.
  ```
   l1 (leaf) ─ pe1l ─ pe1 ──10.0.12.0/24── pe2 ┬ pe2l ─ l2 (leaf)
                     192.0.2.1          192.0.2.2 └ pe2r ─ r2 (root)
   hosts 10.0.0.0/24
  ```

  Scenario: Setup — pe1's IMET is leaf-only and pe2 marks it
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "pe1"
    And I create namespace "pe2"
    # No IPv6 anywhere: MLD, router solicitations and the bridges' own
    # announcements are BUM too.
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2l" to namespace "l2" interface "eth0"
    And I connect namespace "pe2" interface "pe2r" to namespace "r2" interface "eth0"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l2"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:01" in namespace "l1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:02" in namespace "r2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l1"
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l2"
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1" with feature "etree"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2" with feature "etree"
    And I wait 3 seconds
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set pe1l master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set pe2l master br100" in namespace "pe2"
    And I execute "ip link set pe2r master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "192.0.2.2" should be "Established"
    And show command "show bgp evpn etree" in namespace "pe1" should eventually contain "Leaf-only EVIs:  100"
    And show command "show bgp evpn etree" in namespace "pe2" should eventually contain "EVI 100        192.0.2.1"
    And show command "show bgp evpn etree" in namespace "pe2" should contain "Leaf-only EVIs:  none"
    # Each leaf reaches the root; this also teaches both PEs every MAC.
    And ping from "l1" to "10.0.0.22" should eventually succeed
    And ping from "l2" to "10.0.0.22" should eventually succeed
    And show command "show bgp evpn etree" in namespace "pe2" should not contain "Warning"

  Scenario: A leaf-only PE's broadcast is kept off the remote leaf at the egress PE
    Given the test topology exists
    When I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    # l1's ARP for r2 crosses to pe2, which floods it to r2 but not to l2.
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"

  Scenario: A leaf's broadcast is not sent to a leaf-only PE at all
    Given the test topology exists
    When I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e2:01 action pass" in namespace "l1"
    And I execute "ip neigh flush dev eth0" in namespace "l2"
    And I record the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2"
    # l2's ARP for l1 reaches r2 locally and nothing else: pe1 has no root.
    Then ping from "l2" to "10.0.0.11" should fail
    And the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2" should still equal its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l1" should contain "Sent 0 bytes 0 pkt"

  Scenario: A root's broadcast still reaches the leaf-only PE
    Given the test topology exists
    When I record the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev eth0" in namespace "r2"
    Then ping from "r2" to "10.0.0.11" should eventually succeed
    And the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value

  Scenario: A root AC on pe1 makes it mixed, and leaf BUM crosses both ways
    Given the test topology exists
    # A port in br100 that zebra-rs does not name as a leaf is a root AC.
    # pe1 is then mixed: its IMET loses the Leaf flag and pe2 clears its
    # mark. Both PEs have leaf MACs, so pe2 warns.
    When I execute "ip link add pe1x type veth peer name pe1y" in namespace "pe1"
    And I execute "ip link set pe1x master br100" in namespace "pe1"
    And I execute "ip link set pe1x up" in namespace "pe1"
    And I execute "ip link set pe1y up" in namespace "pe1"
    Then show command "show bgp evpn etree" in namespace "pe1" should eventually contain "Leaf-only EVIs:  none"
    And show command "show bgp evpn etree" in namespace "pe2" should eventually contain "leaf BUM not isolated between mixed PEs: local, 192.0.2.1"
    When I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should eventually not contain "Sent 0 bytes 0 pkt"
    When I execute "tc filter del dev eth0 ingress pref 1" in namespace "l1"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e2:01 action pass" in namespace "l1"
    And I execute "ip neigh flush dev eth0" in namespace "l2"
    # l1's ARP reply is leaf-to-leaf known unicast, dropped at pe1; only
    # l2's broadcast reaching l1 is the point.
    Then ping from "l2" to "10.0.0.11" should fail
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l1" should eventually not contain "Sent 0 bytes 0 pkt"

  Scenario: The root AC leaving makes pe1 leaf-only again
    Given the test topology exists
    When I execute "ip link set pe1x nomaster" in namespace "pe1"
    Then show command "show bgp evpn etree" in namespace "pe1" should eventually contain "Leaf-only EVIs:  100"
    And show command "show bgp evpn etree" in namespace "pe2" should eventually contain "EVI 100        192.0.2.1"
    And show command "show bgp evpn etree" in namespace "pe2" should not contain "Warning"
    When I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "l1"
    And I delete namespace "l2"
    And I delete namespace "r2"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
