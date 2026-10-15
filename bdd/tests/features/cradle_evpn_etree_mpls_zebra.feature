@serial
@cradle_evpn_etree_mpls_zebra
Feature: EVPN E-Tree over MPLS driven by zebra-rs — leaf labels from BGP
  As an operator running an EVPN E-Tree over an MPLS core with zebra-rs
  I want each PE's leaf label advertised and imported through BGP
  So that a leaf's broadcast reaches the roots on the other PE but never its
  leaves, with no static labels or slots anywhere.

  `cradle_evpn_etree_mpls` proves the datapath with static configuration.
  Here zebra-rs drives it (E-Tree plan phase 3b). With a leaf AC under
  `encapsulation mpls`, zebra-rs:
  - draws a leaf label from its service labels and tees it to cradle for
    decap (`SetEtreeLeafLabel`);
  - advertises it in a per-ES Ethernet A-D route with ESI 0, carrying the
    E-Tree EC and the leaf AC's EVI RT (RFC 8317 §4.2.1);
  - turns the other PE's leaf label and BUM label into a leaf slot toward
    it (`AddReplSlot.etree_leaf_label`).

  Topology: `cradle_evpn_mpls_zebra` (IS-IS SR-MPLS across a P router, iBGP
  over loopbacks) with a leaf and a root host on each PE. The access ports
  are in br100, which is how zebra-rs knows their EVI.
  ```
   l1 (leaf) ─ pe1l ┐                                     ┌ pe2l ─ l2 (leaf)
   r1 (root) ─ pe1r ┴ pe1 ── p ── pe2 ┴ pe2r ─ r2 (root)
                   lo 1.1.1.1   lo 3.3.3.3   lo 2.2.2.2
   hosts 10.0.0.0/24, bd 100 / EVI 100
  ```

  Scenario: Each PE advertises a leaf label and builds a leaf slot from the other's
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "r1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "pe1"
    And I create namespace "p"
    And I create namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l"
    And I connect namespace "r1" interface "eth0" to namespace "pe1" interface "pe1r"
    And I connect namespace "pe1" interface "p" to namespace "p" interface "pe1"
    And I connect namespace "p" interface "pe2" to namespace "pe2" interface "p"
    And I connect namespace "pe2" interface "pe2l" to namespace "l2" interface "eth0"
    And I connect namespace "pe2" interface "pe2r" to namespace "r2" interface "eth0"
    # No IPv6 on the hosts: their MLD and router solicitations are BUM too.
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l2"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:01" in namespace "l1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:02" in namespace "r1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:02" in namespace "r2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.12/24" to interface "eth0" in namespace "r1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set pe1l master br100" in namespace "pe1"
    And I execute "ip link set pe1r master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set pe2l master br100" in namespace "pe2"
    And I execute "ip link set pe2r master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "p"
    And I disable IPv4 forwarding in namespace "pe2"
    # Router-originated TCP into an XDP-forwarded core needs software
    # checksums (see cradle_evpn_mpls_zebra and docs/design/mpls.md).
    And I execute "ethtool -K p tx off" in namespace "pe1"
    And I execute "ethtool -K p tx off" in namespace "pe2"
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "ports-p.json" serving gRPC as "ctlp"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1" with feature "etree"
    And I start zebra-rs in namespace "p" with config "p.yaml" teeing to cradle as "ctlp"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2" with feature "etree"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2.2.2.2" should be "Established"
    # Each PE's leaf-label route reached the other.
    And show command "show bgp evpn" in namespace "pe1" should eventually contain "etree:leaf-label:"
    And show command "show bgp evpn etree" in namespace "pe1" should eventually contain "2.2.2.2"
    And show command "show bgp evpn etree" in namespace "pe2" should eventually contain "1.1.1.1"
    And show command "show bgp evpn etree" in namespace "pe1" should not contain "Leaf label:      none"
    # Roots reach each other, and each leaf the root on the other PE: the
    # leaves' ARP broadcasts cross through the leaf slots.
    And ping from "r1" to "10.0.0.22" should eventually succeed
    And ping from "l1" to "10.0.0.22" should eventually succeed
    And ping from "l2" to "10.0.0.12" should eventually succeed
    And the cradle stat "mpls_l2_leaf_push" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_leaf_pop" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_leaf_push" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_leaf_pop" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: A leaf's broadcast reaches the remote root but not the remote leaf; a root's reaches both
    Given the test topology exists
    When I execute "tc qdisc add dev eth0 clsact" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 2 flower src_mac 02:00:00:00:e1:02 action pass" in namespace "l2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"
    When I execute "ip neigh flush dev eth0" in namespace "r1"
    Then ping from "r1" to "10.0.0.21" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 2" in namespace "l2" should eventually not contain "Sent 0 bytes 0 pkt"

  Scenario: A leaf's known unicast to the remote leaf is dropped at its own PE
    Given the test topology exists
    # l2's MAC is advertised as a leaf (zebra-rs colours the Type-2), so pe1
    # drops l1's unicast to it before encapsulation.
    When I execute "ip neigh replace 10.0.0.21 lladdr 02:00:00:00:e2:01 dev eth0 nud permanent" in namespace "l1"
    And I record the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1"
    Then the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "etree-leaf"
    And ping from "l1" to "10.0.0.21" should fail
    And the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "p"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "p"
    And I stop cradle in namespace "pe2"
    And I delete namespace "l1"
    And I delete namespace "r1"
    And I delete namespace "l2"
    And I delete namespace "r2"
    And I delete namespace "pe1"
    And I delete namespace "p"
    And I delete namespace "pe2"
    Then the test environment should be clean
