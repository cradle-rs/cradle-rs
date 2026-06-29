@serial
@cradle_l4v6
Feature: eBPF L4 service load balancing (IPv6)
  IPv6 sibling of cradle_l4: a v6 VIP is DNAT'd to one of two v6 backends,
  conntracked, and replies reverse-NAT'd (TCP checksum fixed over the IPv6
  pseudo-header).

  Scenario: Load-balance HTTP across two IPv6 backends via a v6 VIP
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "b1"
    And I create namespace "b2"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "b1" interface "eth0" to namespace "fwd" interface "fwd2"
    And I connect namespace "b2" interface "eth0" to namespace "fwd" interface "fwd3"
    And I add address "2001:db8:1::1/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:2::1/64" to interface "eth0" in namespace "b1"
    And I add address "2001:db8:3::1/64" to interface "eth0" in namespace "b2"
    And I add address "2001:db8:1::ffff/64" to interface "fwd1" in namespace "fwd"
    And I add address "2001:db8:2::ffff/64" to interface "fwd2" in namespace "fwd"
    And I add address "2001:db8:3::ffff/64" to interface "fwd3" in namespace "fwd"
    And I add route "default" via "2001:db8:1::ffff" in namespace "cl"
    And I add route "default" via "2001:db8:2::ffff" in namespace "b1"
    And I add route "default" via "2001:db8:3::ffff" in namespace "b2"
    And I disable IPv6 forwarding in namespace "fwd"
    And I serve HTTP "backend-1" in namespace "b1" bound to "::"
    And I serve HTTP "backend-2" in namespace "b2" bound to "::"
    And I start cradle in namespace "fwd" with config "fwd.json"
    Then HTTP GET "http://[2001:db8:9::9]:8080/" from namespace "cl" should eventually succeed
    And HTTP GET "http://[2001:db8:9::9]:8080/" from namespace "cl" returns at least 2 distinct responses over 12 requests

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I stop HTTP in namespace "b1"
    And I stop HTTP in namespace "b2"
    And I delete namespace "cl"
    And I delete namespace "b1"
    And I delete namespace "b2"
    And I delete namespace "fwd"
    Then the test environment should be clean
