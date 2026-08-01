@serial
@cradle_gtp6
Feature: GTP-U tunnel over an IPv6 underlay (GTP6.E encap + H.M.GTP6.D decap)
  As an operator building a mobile user plane on an IPv6 N3 transport
  I want subscriber traffic carried in a GTP-U tunnel over an IPv6 outer
  So that a UPF-style node encaps/decaps v6-outer GTP-U entirely in eBPF.

  The v6-outer twin of @cradle_gtp: pe1 routes c1->c2 traffic to a GTP
  nexthop whose gtp_dst is IPv6 — it imposes outer IPv6 + UDP(2152) +
  GTP-U(TEID 256) toward pe2 (GTP6.E; UDP checksum 0, RFC 6935/6936
  zero-checksum tunnel mode). pe2's v6 PDR (2001:db8:12::2, TEID 256)
  strips the outer headers and forwards the inner v4 packet to c2
  (H.M.GTP6.D). The reverse direction mirrors it (TEID 512, pe1's PDR
  2001:db8:12::1). Inner traffic stays IPv4 — the outer family is the
  thing under test.

  Topology (kernel v4+v6 forwarding off on pe1/pe2; every GTP action runs
  in eBPF):
  ```
   c1 ── pe1[cradle] ──2001:db8:12::/64── pe2[cradle] ── c2
    10.0.1.1/24                                       10.0.2.1/24
  ```

  Scenario: Forward customer traffic over an eBPF v6-outer GTP-U tunnel
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1a"
    And I connect namespace "pe1" interface "pe1b" to namespace "pe2" interface "pe2a"
    And I connect namespace "pe2" interface "pe2b" to namespace "c2" interface "eth0"
    And I execute "ip link set dev pe1b address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2a address 02:00:00:00:02:0a" in namespace "pe2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.254/24" to interface "pe1a" in namespace "pe1"
    And I add address "2001:db8:12::1/64" to interface "pe1b" in namespace "pe1"
    And I add address "2001:db8:12::2/64" to interface "pe2a" in namespace "pe2"
    And I add address "10.0.2.254/24" to interface "pe2b" in namespace "pe2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.2.1" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed
    And the cradle stat "gtp_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_encap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
