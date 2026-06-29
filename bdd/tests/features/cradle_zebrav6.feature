@serial
@cradle_zebrav6
Feature: zebra-rs static route programs the eBPF FIB (IPv6)
  IPv6 sibling of cradle_zebra: a zebra-rs static v6 route is teed into cradle's
  FIB6 and forwards traffic.

  Scenario: A zebra-rs IPv6 static route forwards via the eBPF data plane
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "srv"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "srv" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "2001:db8:1::1/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:2::1/64" to interface "eth0" in namespace "srv"
    And I add address "2001:db8:1::ffff/64" to interface "fwd1" in namespace "fwd"
    And I add address "2001:db8:2::ffff/64" to interface "fwd2" in namespace "fwd"
    And I add address "2001:db8:9::1/128" to interface "lo" in namespace "srv"
    And I add route "default" via "2001:db8:1::ffff" in namespace "cl"
    And I add route "default" via "2001:db8:2::ffff" in namespace "srv"
    And I disable IPv6 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" with config "ports.json" serving gRPC as "ctl"
    Then ping from "cl" to "2001:db8:9::1" should fail
    When I start zebra-rs in namespace "fwd" with config "static.yaml" teeing to cradle as "ctl"
    Then ping from "cl" to "2001:db8:9::1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "fwd"
    And I stop cradle in namespace "fwd"
    And I delete namespace "cl"
    And I delete namespace "srv"
    And I delete namespace "fwd"
    Then the test environment should be clean
