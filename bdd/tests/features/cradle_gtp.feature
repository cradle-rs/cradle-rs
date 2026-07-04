@serial
@cradle_gtp
Feature: GTP-U tunnel in the eBPF data plane (GTP4.E encap + H.M.GTP4.D decap)
  As an operator building a mobile user plane on cradle
  I want subscriber traffic carried in a GTP-U tunnel over an IPv4 underlay
  So that a UPF-style node encaps/decaps GTP-U entirely in eBPF.

  Topology (kernel v4 forwarding off on pe1/pe2; every GTP action runs in
  eBPF):
  ```
   c1 ── pe1[cradle] ──10.0.12.0/24── pe2[cradle] ── c2
    10.0.1.1/24                                    10.0.2.1/24
  ```
  pe1 routes c1->c2 traffic to a GTP nexthop: it imposes outer IPv4 + UDP
  (2152) + GTP-U(TEID 256) toward pe2 (GTP4.E). pe2's PDR (10.0.12.2, TEID
  256) strips the outer headers and forwards the inner packet to c2
  (H.M.GTP4.D). The reverse direction mirrors it (TEID 512, pe1's PDR
  10.0.12.1). No SRv6, no VRF — a plain IPv4 GTP-U tunnel in the datapath.

  Scenario: Forward customer traffic over an eBPF GTP-U tunnel
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
    And I add address "10.0.12.1/24" to interface "pe1b" in namespace "pe1"
    And I add address "10.0.12.2/24" to interface "pe2a" in namespace "pe2"
    And I add address "10.0.2.254/24" to interface "pe2b" in namespace "pe2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
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
