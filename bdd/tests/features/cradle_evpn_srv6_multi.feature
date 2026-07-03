@serial
@cradle_evpn_srv6_multi
Feature: EVPN-over-SRv6 multi-PE BUM ingress replication in eBPF
  As an operator running an EVPN L2VPN across more than two PEs
  I want a BUM frame replicated once per remote PE, each copy MAC-in-SRv6
  encapsulated toward that PE's End.DT2M SID, plus the local flood
  So that one bridge domain spans three PEs with correct split horizon.

  Per-copy encap is the piece clone_redirect can't do (it clones bytes, and
  TC can't resize non-IP frames): each remote PE gets a "replication slot" —
  a veth pair whose A end joins the bridge domain's flood list. The TC flood
  clones the bare BUM frame into each slot; the copy arrives as ingress on
  the B end, where the XDP stage encapsulates it toward that slot's End.DT2M
  SID and forwards it out the underlay (FIB6 lookup on the SID). Overlay-
  received frames flood local-only (split horizon: never back into a slot).

  Topology (kernel v4+v6 forwarding off on all PEs; pe1 is the underlay hub,
  so pe2↔pe3 BUM transits pe1 as plain IPv6):
  ```
        c1 ── pe1[cradle] ──2001:db8:12::/64── pe2[cradle] ── c2
   bd 100        │  DT2M fd00:1::200            DT2M fd00:2::200
                 └────2001:db8:13::/64── pe3[cradle] ── c3
                                          DT2M fd00:3::200
  ```
  No unicast FDB anywhere: replies ride the unknown-unicast flood (the "U"
  in BUM), so every c*↔c* pair reaching each other proves replication,
  decap+flood, and split horizon (a horizon leak would loop BUM between
  pe2 and pe3 forever).

  Scenario: Flood one bridge domain across three PEs (per-copy End.DT2M)
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
    And I execute "ip link set dev pe1u2 address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe1u3 address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev pe3u address 02:00:00:00:03:0a" in namespace "pe3"
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
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    And I add address "10.0.0.3/24" to interface "eth0" in namespace "c3"
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
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c1" to "10.0.0.3" should eventually succeed
    And ping from "c2" to "10.0.0.3" should eventually succeed
    And ping from "c3" to "10.0.0.1" should eventually succeed
    And the cradle stat "srv6_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_l2_bum" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I stop cradle in namespace "pe3"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "c3"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "pe3"
    Then the test environment should be clean
