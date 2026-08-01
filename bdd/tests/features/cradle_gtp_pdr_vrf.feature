@serial
@cradle_gtp_pdr_vrf
Feature: VRF-scoped GTP-U PDR match (the interwork-segment match context)
  As an operator running GTP-U termination inside VRFs
  I want a decap PDR keyed by the ingress port's VRF as well as (dst, TEID)
  So that a tunnel only terminates in the VRF it was installed for and the
  same (endpoint, TEID) space may be reused per VRF (MUP slices).

  The PDR key is (match_vrf, outer dst, TEID): a G-PDU decaps only when its
  tunnel was installed for the VRF of the port it arrived on (0 = global).
  The decapped inner packet then routes in the PDR's own inner table (decap
  metadata, independent of the match context).

  Scenario: The same (endpoint, TEID) coexists per match VRF with distinct inner tables
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I create namespace "c3"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1a"
    And I connect namespace "pe1" interface "pe1b" to namespace "pe2" interface "pe2a"
    And I connect namespace "pe1" interface "pe1c" to namespace "pe2" interface "pe2c"
    And I connect namespace "pe2" interface "pe2b" to namespace "c2" interface "eth0"
    And I connect namespace "pe2" interface "pe2d" to namespace "c3" interface "eth0"
    And I execute "ip link set dev pe1b address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe1c address 02:00:00:00:01:0c" in namespace "pe1"
    And I execute "ip link set dev pe2a address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev pe2c address 02:00:00:00:02:0c" in namespace "pe2"
    And I execute "ip link set dev eth0 address 02:00:00:00:02:c2" in namespace "c2"
    And I execute "ip link set dev eth0 address 02:00:00:00:03:c3" in namespace "c3"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.254/24" to interface "pe1a" in namespace "pe1"
    And I add address "10.0.12.1/24" to interface "pe1b" in namespace "pe1"
    And I add address "10.0.13.1/24" to interface "pe1c" in namespace "pe1"
    And I add address "10.0.12.2/24" to interface "pe2a" in namespace "pe2"
    And I add address "10.0.13.2/24" to interface "pe2c" in namespace "pe2"
    And I add address "10.0.2.254/24" to interface "pe2b" in namespace "pe2"
    And I add address "10.0.3.254/24" to interface "pe2d" in namespace "pe2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add address "10.0.3.1/24" to interface "eth0" in namespace "c3"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I add route "default" via "10.0.3.254" in namespace "c3"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.2.1" should fail
    And ping from "c1" to "10.0.3.1" should fail
    When I start cradle in namespace "pe1" with config "coex-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "coex-pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c1" to "10.0.3.1" should eventually succeed
    And the cradle stat "gtp_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_encap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown coexistence topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    And I delete namespace "c3"
    Then the test environment should be clean

  Scenario: A global-context PDR does not match on a VRF-bound port
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
    And I execute "ip link set dev eth0 address 02:00:00:00:02:c2" in namespace "c2"
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
    When I start cradle in namespace "pe1" with config "one-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "one-pe2-global.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.2.1" should fail
    When I stop cradle in namespace "pe2"
    And I start cradle in namespace "pe2" with config "one-pe2-scoped.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed
    And the cradle stat "gtp_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown match-context topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
