@serial
@cradle_evpn_mh_df
Feature: EVPN multihoming non-DF filter in eBPF
  As an operator dual-homing a CE to two EVPN PEs (one Ethernet Segment)
  I want only the segment's Designated Forwarder to deliver BUM to the CE
  So that the CE sees one copy of each broadcast, not one per PE.

  RFC 7432 §8.5: every PE attached to an Ethernet Segment receives the
  overlay's BUM copies, but only the elected DF may forward them onto the
  segment. cradle enforces that in the flood loop: a `(port, bridge domain)`
  row in `ES_DF` marks a non-DF port, and `flood()` withholds the copy
  (`l2_drop_nondf`) instead of `clone_redirect`ing it. Known unicast is
  untouched (all-active). The roles come from the control plane —
  `SetEthernetSegment` / `SetEsRole` — here from static config.

  Topology: the cradle_evpn_vxlan_multi hub-and-spoke, with c2 and c3
  collapsed into ONE CE dual-homed to pe2 (DF) and pe3 (non-DF):
  ```
        c1 ── pe1[cradle] ──10.12.0.0/24── pe2[cradle] ──pe2c── eth0 ┐
   bd 100        │  VTEP 192.0.2.1          VTEP .2  DF                ce
                 └────10.13.0.0/24── pe3[cradle] ──pe3c── eth1 ┘
                            VNI 10100        VTEP .3  non-DF     (ES-1)
  ```
  ce owns 10.0.0.2 on eth0; eth1 carries no address and drops everything
  it receives under a counting tc rule, so its packet count IS the number
  of BUM copies the non-DF PE let through. No unicast FDB anywhere, so every
  frame between c1 and ce is BUM (ARP, then unknown-unicast ICMP) and both
  PEs get a copy of all of it.

  Scenario: Only the Designated Forwarder delivers BUM to the multihomed CE
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    # No IPv6 on the PEs: a PE's own MLD / DAD / router solicitations on its
    # CE-facing port would land on the CE and pollute the copy counter below.
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe3"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "ce" interface "eth0" to namespace "pe2" interface "pe2c"
    And I connect namespace "ce" interface "eth1" to namespace "pe3" interface "pe3c"
    And I connect namespace "pe1" interface "pe1u2" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe1" interface "pe1u3" to namespace "pe3" interface "pe3u"
    And I execute "ip link set dev pe1u2 address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe1u3 address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev pe3u address 02:00:00:00:03:0a" in namespace "pe3"
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
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "ce"
    # The CE's second leg: no address, no IPv6 chatter, and a counting drop
    # on ingress — whatever pe3 delivers is counted, never answered.
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress matchall action drop" in namespace "ce"
    # Kernel addresses on the hub links so pe1's transit forwarding can ARP
    # (bpf_redirect_neigh); the VTEP 192.0.2.x addresses stay eBPF-only.
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
    # Reachability rides the DF (pe2): ARP and the unknown-unicast ICMP both
    # reach ce on eth0.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The non-DF (pe3) received the same overlay copies and withheld every
    # one of them from pe3c...
    And the cradle stat "vxlan_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe2" via gRPC as "ctl2" should be zero
    # ...so the CE's second leg saw nothing: no duplicate BUM.
    And command "tc -s filter show dev eth1 ingress" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: make pe3 the DF too (as if the election flipped and
    # both PEs claimed it) and the duplicates appear on eth1 — proving the
    # counter above was measuring the filter, not a dead link.
    When I apply cradle config "pe3-df.json" to namespace "pe3" via gRPC as "ctl3"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth1 ingress" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"

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
