@serial
@cradle_evpn_etree_srv6
Feature: EVPN E-Tree over SRv6 — a leaf's BUM is kept from remote leaves by the leaf argument
  As an operator running an EVPN E-Tree over an SRv6 fabric
  I want a broadcast, multicast or unknown-unicast frame from a leaf AC to
  reach the roots on other PEs but never their leaves
  So that leaves stay apart across the core for BUM over SRv6 too.

  RFC 8317 over SRv6 (rfc8317bis §5.4, RFC 9819): each PE advertises a
  **leaf argument**, an Arg.FE2 of its End.DT2M SID (RFC 8986 §4.12), and
  the ingress PE places the egress PE's leaf argument after the function
  (offset LBL+LNL+FL) on every copy from a leaf AC. The egress PE installs
  its End.DT2M SID at that offset's prefix length, reads the argument at
  decap (`srv6_l2_leaf_decap`), and keeps the copy off its leaf ports
  (`l2_drop_etree_bum`). An argument it never allocated is dropped
  (`srv6_drop_arg`). On the ingress side the leaf argument rides a
  replication slot of its own (`repl_slots[].etree_leaf_sid`), and the
  PE's plain slot then serves roots only.

  Topology: two PEs back to back over an IPv6 underlay, static SRv6. Each
  has a leaf and a root host. SID structure LBL 32 / LNL 16 / FL 16 /
  AL 16: End.DT2M `fd00:N:0:200::` installed at /64, leaf argument 1, so a
  leaf copy goes to `fd00:N:0:200:1::`. Each PE has a plain slot and a leaf
  slot toward the other.
  ```
   l1 (leaf) ─ pe1l ┐                                         ┌ pe2l ─ l2 (leaf)
   r1 (root) ─ pe1r ┴ pe1 ──2001:db8:12::/64── pe2 ┴ pe2r ─ r2 (root)
                    locator fd00:1::/48   fd00:2::/48
   hosts 10.0.0.0/24 in bd 100
  ```
  tc counters on l2's eth0 count what l2 receives from l1 (pref 1) and from
  r1 (pref 2). IPv6 is off everywhere but the underlay ports: the PEs' own
  MLD and neighbour discovery out of a slot veth would be flooded too, and
  land in the counters.

  Scenario: Without leaf roles a leaf's broadcast reaches the remote leaf
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "r1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1" in namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l"
    And I connect namespace "r1" interface "eth0" to namespace "pe1" interface "pe1r"
    And I connect namespace "l2" interface "eth0" to namespace "pe2" interface "pe2l"
    And I connect namespace "r2" interface "eth0" to namespace "pe2" interface "pe2r"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I execute "sysctl -q -w net.ipv6.conf.pe1u.disable_ipv6=0" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.pe2u.disable_ipv6=0" in namespace "pe2"
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
    # Replication slots: a plain and a leaf slot toward the other PE.
    And I execute "ip link add r12a type veth peer name r12b" in namespace "pe1"
    And I execute "ip link add r12la type veth peer name r12lb" in namespace "pe1"
    And I execute "ip link set r12a up" in namespace "pe1"
    And I execute "ip link set r12b up" in namespace "pe1"
    And I execute "ip link set r12la up" in namespace "pe1"
    And I execute "ip link set r12lb up" in namespace "pe1"
    And I execute "ip link add r21a type veth peer name r21b" in namespace "pe2"
    And I execute "ip link add r21la type veth peer name r21lb" in namespace "pe2"
    And I execute "ip link set r21a up" in namespace "pe2"
    And I execute "ip link set r21b up" in namespace "pe2"
    And I execute "ip link set r21la up" in namespace "pe2"
    And I execute "ip link set r21lb up" in namespace "pe2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.12/24" to interface "eth0" in namespace "r1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    And I add address "2001:db8:12::1/64" to interface "pe1u" in namespace "pe1"
    And I add address "2001:db8:12::2/64" to interface "pe2u" in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 2 flower src_mac 02:00:00:00:e1:02 action pass" in namespace "l2"
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_l2_leaf_decap" in namespace "pe2" via gRPC as "ctl2" should be zero
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should be zero
    # Without roles the broadcast reaches l2, and leaf reaches leaf.
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should eventually not contain "Sent 0 bytes 0 pkt"
    And ping from "l1" to "10.0.0.21" should eventually succeed

  Scenario: With leaf roles a leaf's broadcast reaches the remote root but not the remote leaf
    Given the test topology exists
    When I apply cradle config "pe1-etree.json" to namespace "pe1" via gRPC as "ctl1"
    And I apply cradle config "pe2-etree.json" to namespace "pe2" via gRPC as "ctl2"
    And I record the cradle stat "srv6_l2_leaf_decap" in namespace "pe2" via gRPC as "ctl2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    # A fresh ARP broadcast from the leaf: it leaves through the leaf slot,
    # to pe2's End.DT2M SID with pe2's leaf argument.
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "srv6_l2_leaf_decap" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
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
    # unknown unicast, through the leaf slot. pe2 knows l2's MAC (learned
    # above) and would switch the copy straight to l2; the egress filter
    # applies to that path too.
    When I execute "ip neigh replace 10.0.0.21 lladdr 02:00:00:00:e2:01 dev eth0 nud permanent" in namespace "l1"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    Then ping from "l1" to "10.0.0.21" should fail
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"

  Scenario: An argument the egress PE never allocated is dropped
    Given the test topology exists
    # pe2 now advertises leaf argument 2, but pe1 still places 1: pe2 drops
    # the copy rather than flood it unfiltered.
    When I apply cradle config "pe2-arg2.json" to namespace "pe2" via gRPC as "ctl2"
    And I record the cradle stat "srv6_drop_arg" in namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    Then ping from "l1" to "10.0.0.22" should fail
    And the cradle stat "srv6_drop_arg" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    When I apply cradle config "pe2-etree.json" to namespace "pe2" via gRPC as "ctl2"
    Then ping from "l1" to "10.0.0.22" should eventually succeed

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
