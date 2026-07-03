@serial
@cradle_evpn_srv6_zebra_multi
Feature: BGP EVPN over SRv6 drives multi-PE BUM replication in eBPF
  Three PEs in one bridge domain, everything BGP-driven: each PE's Type-3
  IMET carries its End.DT2M SID (encapsulation srv6), and the FibHandle tee
  turns every received Type-3 into a cradle replication slot — a per-remote
  veth pair in the flood list whose far end per-copy MAC-in-SRv6
  encapsulates BUM toward that PE. Unicast rides tee-installed End.DT2U
  entries from Type-2 routes originated off the WatchFdb MAC-learn stream.
  Fully dynamic: no static ARP, no static FDB (cradle or kernel), no static
  replication config — cradle creates the slot veths itself.

  Topology (kernel v4+v6 forwarding off on the PEs; pe1 is the IS-IS hub,
  so pe2↔pe3 traffic transits pe1 as plain IPv6):
  ```
        c1 ── pe1[cradle+zebra] ──2001:db8:0:12::/64── pe2[cradle+zebra] ── c2
   bd 100         │  LOC1 fcbb:bbbb:1::/48              LOC2 fcbb:bbbb:2::/48
                  └────2001:db8:0:13::/64── pe3[cradle+zebra] ── c3
                                             LOC3 fcbb:bbbb:3::/48
  ```
  iBGP EVPN full mesh over the loopbacks; per-PE kernel bridge+vxlan100 is
  zebra's VNI declaration only. Every c*↔c* pair reaching each other proves
  the Type-3 → slot tee, per-copy replication, decap+flood, split horizon,
  and the learned-MAC Type-2 loop — across three PEs.

  Scenario: Bridge three CEs across a BGP-EVPN-over-SRv6 eBPF data plane
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "c2"
    And I create namespace "c3"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "c2" interface "eth0" to namespace "pe2" interface "pe2c"
    And I connect namespace "c3" interface "eth0" to namespace "pe3" interface "pe3c"
    And I connect namespace "pe1" interface "pe1u2" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe1" interface "pe1u3" to namespace "pe3" interface "pe3u"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:02" in namespace "c2"
    And I execute "ip link set dev eth0 address 02:00:00:00:c3:03" in namespace "c3"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    And I add address "10.0.0.3/24" to interface "eth0" in namespace "c3"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe3"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe3"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe3" with config "ports-pe3.json" serving gRPC as "ctl3"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "pe3" with config "pe3.yaml" teeing to cradle as "ctl3"
    And I wait 3 seconds
    # zebra's VNI declaration: a bridge per PE with the zebra-created vxlan100.
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I execute "ip link add br100 type bridge" in namespace "pe3"
    And I execute "ip link set vxlan100 master br100" in namespace "pe3"
    And I execute "ip link set br100 up" in namespace "pe3"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8::2" should be "Established"
    And BGP session in "pe1" to "2001:db8::3" should be "Established"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c1" to "10.0.0.3" should eventually succeed
    And ping from "c2" to "10.0.0.3" should eventually succeed
    And ping from "c3" to "10.0.0.1" should eventually succeed
    And the cradle stat "srv6_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "srv6_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop the zebra-rs tee in namespace "pe3"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I stop cradle in namespace "pe3"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "c3"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "pe3"
    Then the test environment should be clean
