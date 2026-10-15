@serial
@cradle_evpn_etree_mpls
Feature: EVPN E-Tree over MPLS — a leaf's BUM is kept from remote leaves by the leaf label
  As an operator running an EVPN E-Tree over an MPLS fabric
  I want a broadcast, multicast or unknown-unicast frame from a leaf AC to
  reach the roots on other PEs but never their leaves
  So that leaves stay apart across the core for BUM as well as unicast.

  RFC 8317 §4.2: BUM cannot be filtered at the ingress PE, because one copy
  serves roots and leaves alike. So each PE advertises a **leaf label**,
  and the ingress PE pushes the egress PE's leaf label under the EVI label
  on every copy from a leaf AC. The egress PE pops it (`LEAF_LABEL`,
  `mpls_l2_leaf_pop`) and keeps the copy off its leaf ports
  (`l2_drop_etree_bum`), whether it floods the copy or switches it to a
  MAC it knows. On the ingress side the label rides a replication slot of
  its own (`SLOT_ES` `etree`, `mpls_l2_leaf_push`). The PE's other slots
  then serve roots only, and the leaf label replaces the ESI label rather
  than stacking with it (§4.2.3).

  Topology: two PEs back to back, static MPLS. Each has a leaf and a root
  host. l1's port is also on Ethernet Segment ES-1, so without E-Tree its
  BUM goes through the ESI-label slot. pe2's side of ES-1 is a dark port,
  pe2x. Labels: EVI 1200 (pe1) / 2200 (pe2), ESI 1900 / 2900, leaf
  1800 / 2800. Each PE has a plain slot and a leaf slot toward the other,
  and pe1 also has the ESI slot.
  ```
   l1 (leaf, ES-1) ─ pe1l ┐                                ┌ pe2l ─ l2 (leaf)
   r1 (root)       ─ pe1r ┴ pe1 ──10.0.12.0/24── pe2 ┼ pe2r ─ r2 (root)
                         10.255.0.1          10.255.0.2  └ pe2x (ES-1, dark)
   hosts 10.0.0.0/24 in bd 100
  ```
  tc counters on l2's eth0 count what l2 receives from l1 (pref 1) and from
  r1 (pref 2).

  Scenario: Without leaf roles a leaf's broadcast reaches the remote leaf through the ESI-label slot
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "r1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "pe1"
    And I create namespace "pe2"
    # No IPv6 anywhere: MLD, DAD and router solicitations are BUM too, and
    # would land in the counters.
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l"
    And I connect namespace "r1" interface "eth0" to namespace "pe1" interface "pe1r"
    And I connect namespace "l2" interface "eth0" to namespace "pe2" interface "pe2l"
    And I connect namespace "r2" interface "eth0" to namespace "pe2" interface "pe2r"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l2"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r2"
    And I execute "ip link set dev pe1u address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:01" in namespace "l1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:02" in namespace "r1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:02" in namespace "r2"
    # Replication slots (one veth pair each) and pe2's dark ES-1 port.
    And I execute "ip link add r12a type veth peer name r12b" in namespace "pe1"
    And I execute "ip link add r12ea type veth peer name r12eb" in namespace "pe1"
    And I execute "ip link add r12la type veth peer name r12lb" in namespace "pe1"
    And I execute "ip link set r12a up" in namespace "pe1"
    And I execute "ip link set r12b up" in namespace "pe1"
    And I execute "ip link set r12ea up" in namespace "pe1"
    And I execute "ip link set r12eb up" in namespace "pe1"
    And I execute "ip link set r12la up" in namespace "pe1"
    And I execute "ip link set r12lb up" in namespace "pe1"
    And I execute "ip link add r21a type veth peer name r21b" in namespace "pe2"
    And I execute "ip link add r21la type veth peer name r21lb" in namespace "pe2"
    And I execute "ip link add pe2x type veth peer name pe2xp" in namespace "pe2"
    And I execute "ip link set r21a up" in namespace "pe2"
    And I execute "ip link set r21b up" in namespace "pe2"
    And I execute "ip link set r21la up" in namespace "pe2"
    And I execute "ip link set r21lb up" in namespace "pe2"
    And I execute "ip link set pe2x up" in namespace "pe2"
    And I execute "ip link set pe2xp up" in namespace "pe2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.12/24" to interface "eth0" in namespace "r1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    And I add address "10.0.12.1/24" to interface "pe1u" in namespace "pe1"
    And I add address "10.0.12.2/24" to interface "pe2u" in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 2 flower src_mac 02:00:00:00:e1:02 action pass" in namespace "l2"
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    # l1's ARP for r2 enters ES-1, so it leaves through the ESI-label slot.
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "mpls_l2_esi_push" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_esi_pop" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_leaf_push" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should be zero
    # Without roles the broadcast reaches l2, and leaf reaches leaf.
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should eventually not contain "Sent 0 bytes 0 pkt"
    And ping from "l1" to "10.0.0.21" should eventually succeed

  Scenario: With leaf roles a leaf's broadcast reaches the remote root but not the remote leaf
    Given the test topology exists
    When I apply cradle config "pe1-etree.json" to namespace "pe1" via gRPC as "ctl1"
    And I apply cradle config "pe2-etree.json" to namespace "pe2" via gRPC as "ctl2"
    And I record the cradle stat "mpls_l2_esi_push" in namespace "pe1" via gRPC as "ctl1"
    And I record the cradle stat "mpls_l2_leaf_push" in namespace "pe1" via gRPC as "ctl1"
    And I record the cradle stat "mpls_l2_leaf_pop" in namespace "pe2" via gRPC as "ctl2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    # A fresh ARP broadcast from the leaf: it leaves through the leaf slot,
    # with pe2's leaf label instead of its ESI label.
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "mpls_l2_leaf_push" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value
    And the cradle stat "mpls_l2_esi_push" in namespace "pe1" via gRPC as "ctl1" should still equal its recorded value
    And the cradle stat "mpls_l2_leaf_pop" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"

  Scenario: A root's broadcast still reaches the remote leaf
    Given the test topology exists
    When I execute "tc filter del dev eth0 ingress pref 2" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 2 flower src_mac 02:00:00:00:e1:02 action pass" in namespace "l2"
    And I execute "ip neigh flush dev eth0" in namespace "r1"
    Then ping from "r1" to "10.0.0.21" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 2" in namespace "l2" should eventually not contain "Sent 0 bytes 0 pkt"

  Scenario: A leaf's unknown unicast that meets a known leaf MAC at the egress PE is dropped there
    Given the test topology exists
    # pe1 has no FDB entry for l2's MAC, so l1's unicast to it is flooded as
    # unknown unicast, with the leaf label. pe2 knows l2's MAC (learned
    # above) and would switch the copy straight to l2; the egress filter
    # applies to that path too.
    When I execute "ip neigh replace 10.0.0.21 lladdr 02:00:00:00:e2:01 dev eth0 nud permanent" in namespace "l1"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    Then ping from "l1" to "10.0.0.21" should fail
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "l1"
    And I delete namespace "r1"
    And I delete namespace "l2"
    And I delete namespace "r2"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
