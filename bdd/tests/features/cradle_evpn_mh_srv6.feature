@serial
@cradle_evpn_mh_srv6
Feature: EVPN multihoming over SRv6 — DF filter, split horizon and aliasing in eBPF
  As an operator dual-homing a CE to two EVPN PEs on an SRv6 fabric
  I want the multihoming dataplane — non-DF filter, split horizon, aliasing —
  to work for MAC-in-SRv6 exactly as it does for VXLAN
  So that an Ethernet Segment needs no VXLAN underneath it.

  The SRv6 twin of cradle_evpn_mh_df / _sph / _nhg in one feature. The
  three mechanisms are encapsulation-agnostic in cradle — the DF gate is a
  `(port, bd)` row checked at egress, the aliasing group's members each
  carry their own overlay kind, and the split horizon keys the segment
  bitmap (`VTEP_ES`) on the outer source — but the SRv6 side had never been
  exercised: the End.DT2M / End.DT2U decap (`srv6_dt2u`) reads the outer
  IPv6 source into `es_bits`, and the ES peers are the PEs' SRv6 *outer
  source addresses* (`srv6_source`), not their SIDs.

  Topology: the cradle_evpn_srv6_multi hub-and-spoke with c2 and c3
  collapsed into ONE CE dual-homed to pe2 (DF) and pe3 (non-DF) on ES-1:
  ```
        c1 ── pe1[cradle] ──2001:db8:12::/64── pe2[cradle] ──pe2c── eth0 ┐
   bd 100        │  src fd00:1::1               src fd00:2::1  DF          ce
                 └────2001:db8:13::/64── pe3[cradle] ──pe3c── eth1 ┘   bond0
                   DT2U ::100 / DT2M ::200 per PE   src fd00:3::1 non-DF  ES-1
  ```
  ce is a real multihomed station: one LAG (active-backup, transmitting on
  the pe3 leg, receiving on both) with one MAC and one address. Per-leg tc
  counters tell which PE delivered what: ARP from c1 on the pe3 leg is a
  BUM copy the non-DF let through; the CE's own MAC arriving on the pe2 leg
  is an echo the split horizon failed to stop. pe1 knows the CE's MAC only
  through the segment (`fdb[].esi`), so its unicast rides the {pe2, pe3}
  End.DT2U aliasing group.

  Scenario: DF filter, split horizon and aliasing hold over SRv6
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "ce" interface "eth0" to namespace "pe2" interface "pe2c"
    And I connect namespace "ce" interface "eth1" to namespace "pe3" interface "pe3c"
    And I connect namespace "pe1" interface "pe1u2" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe1" interface "pe1u3" to namespace "pe3" interface "pe3u"
    # No IPv6 on the CE-facing ports: a PE's own MLD / DAD / router
    # solicitations would land on the CE (the underlay is IPv6, so the
    # PEs keep it elsewhere).
    And I execute "sysctl -q -w net.ipv6.conf.pe1c.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.pe2c.disable_ipv6=1" in namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.pe3c.disable_ipv6=1" in namespace "pe3"
    And I execute "ip link set dev pe1u2 address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe1u3 address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev pe3u address 02:00:00:00:03:0a" in namespace "pe3"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    # Replication slots: one veth pair per remote PE, per PE.
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
    # The dual-homed CE: an active-backup LAG over both legs — one MAC, one
    # address, transmitting on the pe3 leg (primary eth1) and accepting
    # frames on either (all_slaves_active: aliasing may deliver on eth0).
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "ce"
    And I execute "ip link add bond0 type bond mode active-backup all_slaves_active 1" in namespace "ce"
    And I execute "ip link set bond0 address 02:00:00:00:ce:02" in namespace "ce"
    And I execute "ip link set eth0 down" in namespace "ce"
    And I execute "ip link set eth1 down" in namespace "ce"
    And I execute "ip link set eth0 master bond0" in namespace "ce"
    And I execute "ip link set eth1 master bond0" in namespace "ce"
    And I execute "ip link set bond0 type bond primary eth1" in namespace "ce"
    And I execute "ip link set eth0 up" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "ip link set bond0 up" in namespace "ce"
    And I add address "10.0.0.2/24" to interface "bond0" in namespace "ce"
    # Kernel addresses on the hub links so pe1's transit forwarding can
    # resolve neighbours; the fd00:N:: SRv6 sources and SIDs stay eBPF-only.
    And I add address "2001:db8:12::1/64" to interface "pe1u2" in namespace "pe1"
    And I add address "2001:db8:13::1/64" to interface "pe1u3" in namespace "pe1"
    And I add address "2001:db8:12::2/64" to interface "pe2u" in namespace "pe2"
    And I add address "2001:db8:13::2/64" to interface "pe3u" in namespace "pe3"
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
    # Split horizon (RFC 8365 §8.3.1 local bias, over SRv6): the CE
    # transmits on its pe3 leg — a non-DF still accepts the CE's traffic
    # and floods it (End.DT2M) to pe1 and pe2. pe2 is the DF, so only the
    # split horizon stops that copy coming back to the CE on eth0: pe2's
    # ES-1 peer list names pe3's SRv6 outer source, fd00:3::1, and cradle
    # drops what arrives from it. A flower counter on eth0 keyed on the
    # CE's own source MAC catches any echo (deliveries to the CE carry c1's).
    When I execute "tc qdisc add dev eth0 clsact" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:ce:02 action drop" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "l2_drop_sph" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: clear pe2's peer list and the same traffic echoes
    # back onto eth0. (Forget c1's MAC so the next ping starts with an ARP
    # broadcast again — a cached neighbour would make it known unicast,
    # which pe3 tunnels straight to pe1 without ever flooding it to pe2.)
    When I apply cradle config "pe2-nosph.json" to namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    # Non-DF filter (RFC 7432 §8.5): count the BUM copies pe3 delivers on
    # the CE's second leg with an ARP-only counter — known unicast may
    # legitimately land here too, because pe1 aliases the CE's MAC across
    # both segment PEs.
    When I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol arp flower src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    # Reachability: c1's ARP rides the DF (pe2) to eth0; its ICMP is known
    # unicast at pe1, sent through the {pe2, pe3} End.DT2U aliasing group.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    # The non-DF (pe3) received the same overlay copies and withheld every
    # one of them from pe3c...
    And the cradle stat "srv6_l2_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe2" via gRPC as "ctl2" should be zero
    # ...so the CE's second leg saw no broadcast: no duplicate BUM.
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: make pe3 the DF too (as if the election flipped and
    # both PEs claimed it) and c1's next ARP shows up on eth1 as well.
    When I apply cradle config "pe3-df.json" to namespace "pe3" via gRPC as "ctl3"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
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
