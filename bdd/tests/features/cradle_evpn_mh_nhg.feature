@serial
@cradle_evpn_mh_nhg
Feature: EVPN multihoming aliasing — the Ethernet Segment nexthop group in eBPF
  As an operator whose remote CEs are dual-homed to two PEs
  I want a MAC learned behind an Ethernet Segment to be reachable through
  every PE on the segment, and a single group update to move it
  So that traffic load-balances across the segment and fails over at once.

  RFC 7432 §8.4 (aliasing): a MAC advertised by one PE on a segment may be
  sent to any PE attached to that segment; §8.2 (mass withdraw): when a PE
  leaves the segment, every MAC behind it must move without a per-MAC
  update. cradle models both with a `(segment, bridge domain)` nexthop
  group: an FDB entry flagged `FDB_F_ESNHG` names the segment instead of a
  remote, the XDP encap picks a group member per flow, and replacing the
  member list re-points every such entry at once.

  Topology: the cradle_evpn_vxlan_multi hub-and-spoke; the CE is a Linux
  bridge with a leg to pe2 (DF) and a leg to pe3 (non-DF) on ES-1 — a real
  dual-homed station. pe1 has no segment ports; it holds the CE's MAC
  behind ES-1 with a group of {pe2, pe3}:
  ```
        c1 ── pe1[cradle] ──10.12.0.0/24── pe2[cradle] ──pe2c── eth0 ┐
   bd 100        │  VTEP 192.0.2.1          VTEP .2  DF              ce br0
                 └────10.13.0.0/24── pe3[cradle] ──pe3c── eth1 ┘  10.0.0.2
                            VNI 10100        VTEP .3  non-DF     (ES-1)
  ```
  Each CE leg counts the ICMP it receives from c1 (a tc flower counter, pass
  action). The group is then narrowed to one member and the other; the
  counters show the MAC following the group.

  Scenario: A MAC behind a segment follows its nexthop group
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe3"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "ce"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "ce" interface "eth0" to namespace "pe2" interface "pe2c"
    And I connect namespace "ce" interface "eth1" to namespace "pe3" interface "pe3c"
    And I connect namespace "pe1" interface "pe1u2" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe1" interface "pe1u3" to namespace "pe3" interface "pe3u"
    And I execute "ip link set dev pe1u2 address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe1u3 address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev pe3u address 02:00:00:00:03:0a" in namespace "pe3"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    # Replication slots: one veth pair per remote VTEP, per PE.
    And I execute "ip link add r12a type veth peer name r12b" in namespace "pe1"
    And I execute "ip link add r13a type veth peer name r13b" in namespace "pe1"
    And I execute "ip link set r12a up" in namespace "pe1"
    And I execute "ip link set r12b up" in namespace "pe1"
    And I execute "ip link set r13a up" in namespace "pe1"
    And I execute "ip link set r13b up" in namespace "pe1"
    And I execute "ip link add r21a type veth peer name r21b" in namespace "pe2"
    And I execute "ip link add r23a type veth peer name r23b" in namespace "pe2"
    And I execute "ip link set r21a up" in namespace "pe2"
    And I execute "ip link set r21b up" in namespace "pe2"
    And I execute "ip link set r23a up" in namespace "pe2"
    And I execute "ip link set r23b up" in namespace "pe2"
    And I execute "ip link add r31a type veth peer name r31b" in namespace "pe3"
    And I execute "ip link add r32a type veth peer name r32b" in namespace "pe3"
    And I execute "ip link set r31a up" in namespace "pe3"
    And I execute "ip link set r31b up" in namespace "pe3"
    And I execute "ip link set r32a up" in namespace "pe3"
    And I execute "ip link set r32b up" in namespace "pe3"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    # The dual-homed CE: a static LAG over both legs — one MAC, one address,
    # and (unlike a bridge) never forwarding between its own links. The CE
    # transmits each flow on one leg, so only that PE learns its MAC;
    # the other PE holds it as a static local entry on its segment port —
    # what a Type-2 for one's own segment installs (RFC 7432 §8.4), here
    # from config.
    And I execute "ip link add bond0 type bond mode balance-xor xmit_hash_policy layer2" in namespace "ce"
    And I execute "ip link set bond0 address 02:00:00:00:ce:02" in namespace "ce"
    And I execute "ip link set eth0 down" in namespace "ce"
    And I execute "ip link set eth1 down" in namespace "ce"
    And I execute "ip link set eth0 master bond0" in namespace "ce"
    And I execute "ip link set eth1 master bond0" in namespace "ce"
    And I execute "ip link set eth0 up" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "ip link set bond0 up" in namespace "ce"
    And I add address "10.0.0.2/24" to interface "bond0" in namespace "ce"
    # Per-leg counters of ICMP from c1 (pass action: the bond still sees
    # the frame).
    And I execute "tc qdisc add dev eth0 clsact" in namespace "ce"
    And I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I add address "10.12.0.1/24" to interface "pe1u2" in namespace "pe1"
    And I add address "10.13.0.1/24" to interface "pe1u3" in namespace "pe1"
    And I add address "10.12.0.2/24" to interface "pe2u" in namespace "pe2"
    And I add address "10.13.0.2/24" to interface "pe3u" in namespace "pe3"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe3"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe3"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe3" with config "pe3.json" serving gRPC as "ctl3"
    # Aliasing: c1 → CE resolves through the {pe2, pe3} group; whichever
    # member the flow hashes to delivers on its leg.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    # Narrow the group to pe3 alone — one update, the MAC moves: fresh
    # counters see c1's ICMP only on the pe3 leg.
    When I apply cradle config "pe1-nhg-pe3.json" to namespace "pe1" via gRPC as "ctl1"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "ce"
    And I execute "tc filter del dev eth1 ingress pref 1" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # ...and back to pe2 alone (a mass withdraw of pe3): only the pe2 leg.
    When I apply cradle config "pe1-nhg-pe2.json" to namespace "pe1" via gRPC as "ctl1"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "ce"
    And I execute "tc filter del dev eth1 ingress pref 1" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I stop cradle in namespace "pe3"
    And I delete namespace "c1"
    And I delete namespace "ce"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "pe3"
    Then the test environment should be clean
