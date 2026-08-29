@serial
@cradle_evpn_mh_lag
Feature: EVPN multihoming over a LACP LAG — the Ethernet Segment as a bond
  As an operator dual-homing a CE with a real 802.3ad LAG across two PEs
  I want each PE's leg of that LAG (a kernel bond) to be the cradle port the
  Ethernet Segment binds to
  So that MC-LAG multihoming works with the CE seeing one aggregated link.

  An Ethernet Segment IS a LAG (RFC 7432 §5): the CE bundles its links to
  both PEs with LACP, so both PEs must present the same LACP system — the
  kernel bonding driver's `ad_actor_system` on each PE's single-member bond.
  cradle then attaches to the bond as its port. What makes that work: a
  native XDP program on a bond runs on the members and sees THEIR ifindex,
  so cradle aliases every member to the bond (`PORT_MASTER`, resolved from
  the bond's member list at SetPort) — without it the XDP stage does not
  recognise the port and every frame from the CE falls through to the TC
  flood. Link-local control frames (`01:80:c2:00:00:0x`: LACP, STP, LLDP)
  are handed to the host rather than learned or flooded; here the bonding
  driver consumes LACPDUs on the member before either hook could tunnel
  them, so the aggregation is proven, the punt is not.

  Topology: cradle_evpn_mh_nhg with LACP bonds on all three CE-facing ends:
  ```
        c1 ── pe1[cradle] ──10.12.0.0/24── pe2[cradle] bond0{pe2c} ── eth0 ┐
   bd 100        │  VTEP 192.0.2.1          VTEP .2  DF                 ce bond0
                 └────10.13.0.0/24── pe3[cradle] bond0{pe3c} ── eth1 ┘  802.3ad
                            VNI 10100        VTEP .3  non-DF    (ES-1, one LACP system)
  ```
  pe1 holds the CE's MAC behind ES-1 with a {pe2, pe3} group; each PE holds
  it as a static local entry on its bond. The proofs are those of the
  aliasing feature, on top of LACP having aggregated both links.

  Scenario: LACP aggregates both PE legs and traffic follows the segment group
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
    # The PE legs of the MC-LAG: one-member 802.3ad bonds presenting the
    # SAME LACP actor system (and port key) on both PEs — to the CE they are
    # one partner. Fast LACP so the aggregation forms in seconds.
    And I execute "ip link add bond0 type bond mode 802.3ad lacp_rate fast ad_actor_system 02:00:00:00:aa:01 ad_user_port_key 7" in namespace "pe2"
    And I execute "ip link set pe2c down" in namespace "pe2"
    And I execute "ip link set pe2c master bond0" in namespace "pe2"
    And I execute "ip link set pe2c up" in namespace "pe2"
    And I execute "ip link set bond0 up" in namespace "pe2"
    And I execute "ip link add bond0 type bond mode 802.3ad lacp_rate fast ad_actor_system 02:00:00:00:aa:01 ad_user_port_key 7" in namespace "pe3"
    And I execute "ip link set pe3c down" in namespace "pe3"
    And I execute "ip link set pe3c master bond0" in namespace "pe3"
    And I execute "ip link set pe3c up" in namespace "pe3"
    And I execute "ip link set bond0 up" in namespace "pe3"
    # The CE: one 802.3ad LAG over both legs, one MAC, one address.
    And I execute "ip link add bond0 type bond mode 802.3ad lacp_rate fast xmit_hash_policy layer2" in namespace "ce"
    And I execute "ip link set bond0 address 02:00:00:00:ce:02" in namespace "ce"
    And I execute "ip link set eth0 down" in namespace "ce"
    And I execute "ip link set eth1 down" in namespace "ce"
    And I execute "ip link set eth0 master bond0" in namespace "ce"
    And I execute "ip link set eth1 master bond0" in namespace "ce"
    And I execute "ip link set eth0 up" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "ip link set bond0 up" in namespace "ce"
    And I add address "10.0.0.2/24" to interface "bond0" in namespace "ce"
    # Per-leg counters of ICMP from c1 (pass action).
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
    # LACP converges THROUGH cradle: the PEs' LACPDUs cross the ports cradle
    # owns, and the CE's arrive on bond members the XDP stage runs on. Each
    # PE bond aggregates its one link; the CE aggregates both.
    Then command "cat /sys/class/net/bond0/bonding/ad_num_ports" in namespace "pe2" should eventually contain "1"
    And command "cat /sys/class/net/bond0/bonding/ad_num_ports" in namespace "pe3" should eventually contain "1"
    And command "cat /sys/class/net/bond0/bonding/ad_num_ports" in namespace "ce" should eventually contain "2"
    # Aliasing over the LAG: c1 → CE resolves through the {pe2, pe3} group,
    # is delivered on the winning PE's bond, and the CE replies over its LAG.
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    # The CE's replies enter the PE on a bond MEMBER. Only because cradle
    # aliases the member to its bond does the XDP stage recognise the port
    # and unicast-encapsulate them toward c1 (`vxlan_encap`); un-aliased,
    # they fall through to the TC stage and get flooded instead. The CE's
    # layer-2 transmit hash (last MAC octets 0x01 ^ 0x02 = 3, odd) pins its
    # transmit leg to its second member, eth1 → pe3.
    And the cradle stat "vxlan_encap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    # Narrow the group to pe3, then to pe2: the MAC follows, leg by leg.
    When I apply cradle config "pe1-nhg-pe3.json" to namespace "pe1" via gRPC as "ctl1"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "ce"
    And I execute "tc filter del dev eth1 ingress pref 1" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    When I apply cradle config "pe1-nhg-pe2.json" to namespace "pe1" via gRPC as "ctl1"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "ce"
    And I execute "tc filter del dev eth1 ingress pref 1" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol ip flower ip_proto icmp src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"

  Scenario: A rebuilt bond member is re-aliased without a SetPort
    # Tear the pe3 leg down and build it again: deleting the veth drops it
    # from both bonds, and the rebuilt link gets a NEW ifindex on each end.
    # Nothing re-applies pe3's port — cradle's link monitor sees the new
    # member join bond0 and aliases it (PORT_MASTER) by itself.
    When I record the cradle stat "vxlan_encap" in namespace "pe3" via gRPC as "ctl3"
    And I execute "ip link del pe3c" in namespace "pe3"
    And I connect namespace "ce" interface "eth1" to namespace "pe3" interface "pe3c"
    And I execute "ip link set pe3c down" in namespace "pe3"
    And I execute "ip link set pe3c master bond0" in namespace "pe3"
    And I execute "ip link set pe3c up" in namespace "pe3"
    And I execute "ip link set eth1 down" in namespace "ce"
    And I execute "ip link set eth1 master bond0" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    # Pin the CE's replies to the rebuilt leg (eth0 out of its aggregator)
    # and c1's frames to pe3 (the group narrowed to it).
    And I execute "ip link set eth0 down" in namespace "ce"
    And I apply cradle config "pe1-nhg-pe3.json" to namespace "pe1" via gRPC as "ctl1"
    Then command "cat /sys/class/net/bond0/bonding/ad_num_ports" in namespace "pe3" should eventually contain "1"
    And command "cat /sys/class/net/bond0/bonding/ad_num_ports" in namespace "ce" should eventually contain "1"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    # The CE's replies now enter pe3 on the new member. Only because the
    # monitor re-aliased it does the XDP stage recognise the port and
    # unicast-encapsulate them toward c1 again; with the stale alias of the
    # deleted ifindex they would fall through to the TC stage and flood.
    And the cradle stat "vxlan_encap" in namespace "pe3" via gRPC as "ctl3" should exceed its recorded value

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
