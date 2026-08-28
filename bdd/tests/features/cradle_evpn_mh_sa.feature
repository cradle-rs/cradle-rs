@serial
@cradle_evpn_mh_sa
Feature: EVPN multihoming single-active — the standby segment port blocks
  As an operator dual-homing a CE in single-active mode
  I want the non-DF PE's segment port to pass nothing in either direction
  So that only the Designated Forwarder carries the CE's traffic.

  RFC 7432 §14.1.1: under single-active redundancy only the DF forwards
  to and from the segment; a non-DF's port is a standby. That is stronger
  than the all-active non-DF filter, which withholds BUM only — known
  unicast toward the CE and anything the CE sends into the standby port
  must be dropped as well. cradle's `SetEsRole{single_active}` renders a
  non-DF row with `ES_DF_F_BLOCK`; `l2_switch` drops on the port's ingress
  and before a unicast redirect to it, the XDP stage drops before learning
  or tunneling from it (`l2_drop_sa`). Remote PEs send to the DF alone —
  no aliasing group under single-active.

  Topology: the aliasing hub-and-spoke; the CE is an active-backup bond
  (primary eth0 → pe2, the DF) that also receives on its standby leg:
  ```
        c1 ── pe1[cradle] ──10.12.0.0/24── pe2[cradle] ──pe2c── eth0 ┐
   bd 100        │  VTEP 192.0.2.1          VTEP .2  DF (active)     ce bond0
                 └────10.13.0.0/24── pe3[cradle] ──pe3c── eth1 ┘  10.0.0.2
                            VNI 10100        VTEP .3  standby   (ES-1, single-active)
  ```
  pe1 holds the CE's MAC toward pe2 (the DF). Re-pointing it at pe3 over
  gRPC is how the standby is exercised: pe3 must drop known unicast toward
  the CE, and, with the CE's active leg flipped to eth1, whatever the CE
  sends in. Switching pe3 to all-active (the negative control) lets the
  same traffic through.

  Scenario: The standby PE drops toward and from the CE; the DF carries it
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
    # The CE: an active-backup LAG, active on the DF's leg, receiving on both.
    And I execute "ip link add bond0 type bond mode active-backup all_slaves_active 1" in namespace "ce"
    And I execute "ip link set bond0 address 02:00:00:00:ce:02" in namespace "ce"
    And I execute "ip link set eth0 down" in namespace "ce"
    And I execute "ip link set eth1 down" in namespace "ce"
    And I execute "ip link set eth0 master bond0" in namespace "ce"
    And I execute "ip link set eth1 master bond0" in namespace "ce"
    And I execute "ip link set bond0 type bond primary eth0" in namespace "ce"
    And I execute "ip link set eth0 up" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "ip link set bond0 up" in namespace "ce"
    And I add address "10.0.0.2/24" to interface "bond0" in namespace "ce"
    # The standby leg counts the ICMP from c1 it receives (pass action).
    And I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
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
    # The DF carries everything: c1 → CE via pe2, replies out the active leg.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_drop_sa" in namespace "pe2" via gRPC as "ctl2" should be zero
    # Inward block: flip the CE's active leg to the standby PE — its frames
    # now enter pe3 and are dropped before anything is learned from them.
    When I execute "ip link set bond0 type bond primary eth1" in namespace "ce"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should fail
    And the cradle stat "l2_drop_sa" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    When I execute "ip link set bond0 type bond primary eth0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    # Outward block: point pe1's entry for the CE at pe3 — known unicast
    # toward the standby port is dropped, nothing reaches the CE's eth1.
    When I apply cradle config "pe1-via-pe3.json" to namespace "pe1" via gRPC as "ctl1"
    Then ping from "c1" to "10.0.0.2" should fail
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: the same port, the same traffic, all-active instead
    # — a non-DF still forwards known unicast, and the CE answers.
    When I apply cradle config "pe3-aa.json" to namespace "pe3" via gRPC as "ctl3"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"

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
