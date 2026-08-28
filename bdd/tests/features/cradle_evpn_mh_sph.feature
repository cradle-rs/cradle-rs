@serial
@cradle_evpn_mh_sph
Feature: EVPN multihoming split-horizon (local bias) filter in eBPF
  As an operator dual-homing a CE to two EVPN PEs (one Ethernet Segment)
  I want a BUM frame the CE sends into one PE never to come back to the CE
  through the other PE
  So that the multihomed segment does not loop or duplicate its own frames.

  RFC 8365 §8.3.1 (local bias): the PE that receives a BUM frame from the
  CE floods it to every remote VTEP — including the segment's peer PE, which
  must also flood it to its other ports but never back onto the shared
  segment. The peer knows the frame came from a segment member because the
  overlay source address is one of the ES's VTEPs. cradle resolves the outer
  source at decap into a bitmap of the segments that VTEP shares with us
  (`VTEP_ES` → `CradleXdpMeta::es_bits`) and the flood loop withholds the
  copy from any port on one of those segments (`PORT_ES`, `l2_drop_sph`).
  The DF filter is deliberately NOT what stops it here: pe3 is the DF.

  Topology: the cradle_evpn_vxlan_multi hub-and-spoke with a CE dual-homed
  to pe2 (non-DF) and pe3 (DF) on ES-1:
  ```
        c1 ── pe1[cradle] ──10.12.0.0/24── pe2[cradle] ──pe2c── eth0 ┐
   bd 100        │  VTEP 192.0.2.1          VTEP .2  non-DF            ce
                 └────10.13.0.0/24── pe3[cradle] ──pe3c── eth1 ┘
                            VNI 10100        VTEP .3  DF        (ES-1)
  ```
  ce owns 10.0.0.2 on eth0 and talks to c1 through pe2. Every frame ce
  sends is flooded by pe2 to pe1 and pe3; pe3 — the DF, so allowed to
  deliver BUM — must recognise pe2 as its ES peer and drop. eth1 counts
  frames whose source MAC is ce's own (a tc flower rule): exactly the
  echoes the filter exists to stop. pe1 has a static FDB entry for ce so
  c1's replies ride known unicast to pe2, which as non-DF would otherwise
  withhold them.

  Scenario: A CE's own BUM never returns to it through the peer PE
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
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
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:ce:02" in namespace "ce"
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
    # The CE's second leg: no address, no IPv6, and two counting drops on
    # ingress — pref 1 matches the CE's OWN source MAC (an echo of a frame
    # it sent via eth0 — the split-horizon failure), pref 2 the rest.
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 flower src_mac 02:00:00:00:ce:02 action drop" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 2 matchall action drop" in namespace "ce"
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
    Then ping from "ce" to "10.0.0.1" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe3" with config "pe3.json" serving gRPC as "ctl3"
    # ce reaches c1 via pe2: its ARP floods to pe1 (answered) and to pe3.
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And the cradle stat "vxlan_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    # pe3 is the DF — no non-DF drops — yet it withheld every copy that
    # came from its segment peer pe2...
    And the cradle stat "l2_drop_nondf" in namespace "pe3" via gRPC as "ctl3" should be zero
    And the cradle stat "l2_drop_sph" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    # ...so none of ce's own frames came back on eth1.
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: forget pe3's peers (replace with an empty list) —
    # the DF now floods pe2's copies onto the segment and ce's own frames
    # echo back on eth1.
    When I apply cradle config "pe3-nosph.json" to namespace "pe3" via gRPC as "ctl3"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
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
