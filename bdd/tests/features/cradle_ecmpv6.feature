@serial
@cradle_ecmpv6
Feature: ECMP multipath in the eBPF data plane (IPv6)
  IPv6 sibling of cradle_ecmp: a v6 multipath route load-balances flows across
  both egress paths.

  Scenario: A v6 multipath route load-balances flows across both eBPF paths
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "r"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "r" interface "reth2" to namespace "fwd" interface "fwd2"
    And I connect namespace "r" interface "reth3" to namespace "fwd" interface "fwd3"
    And I add address "2001:db8:1::1/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:1::11/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:1::12/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:1::13/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:1::14/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:1::15/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:1::ffff/64" to interface "fwd1" in namespace "fwd"
    And I add address "2001:db8:2::ffff/64" to interface "fwd2" in namespace "fwd"
    And I add address "2001:db8:3::ffff/64" to interface "fwd3" in namespace "fwd"
    And I add address "2001:db8:2::2/64" to interface "reth2" in namespace "r"
    And I add address "2001:db8:3::2/64" to interface "reth3" in namespace "r"
    And I add address "2001:db8:9::1/128" to interface "lo" in namespace "r"
    And I add route "default" via "2001:db8:1::ffff" in namespace "cl"
    And I add route "2001:db8:1::/64" via "2001:db8:2::ffff" in namespace "r"
    And I disable IPv6 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" with config "ports.json" serving gRPC as "ctl"
    And I start zebra-rs in namespace "fwd" with config "static.yaml" teeing to cradle as "ctl"
    Then ping from "cl" to "2001:db8:9::1" should eventually succeed
    And namespace "cl" balances pings to "2001:db8:9::1" from sources "2001:db8:1::1,2001:db8:1::11,2001:db8:1::12,2001:db8:1::13,2001:db8:1::14,2001:db8:1::15" across interfaces "fwd2,fwd3" in namespace "fwd"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "fwd"
    And I stop cradle in namespace "fwd"
    And I delete namespace "cl"
    And I delete namespace "r"
    And I delete namespace "fwd"
    Then the test environment should be clean
