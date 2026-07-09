@serial
@cradle_dump
Feature: dump forwarding-table contents
  cradle programs its eBPF forwarding tables (L2 FDB, IPv4/IPv6 FIB, MPLS ILM,
  SRv6 local SIDs) from the control plane; `cradle dump <table>` reads each
  one back over the gRPC control API.

  Scenario: dump each forwarding table
    Given a clean test environment
    When I create namespace "h1"
    And I create namespace "fwd"
    And I create namespace "h2"
    And I connect namespace "h1" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "h2" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I start cradle in namespace "fwd" with config "dump.json" serving gRPC as "ctl"
    Then the cradle dump "ipv4" in namespace "fwd" via gRPC as "ctl" should contain "10.9.9.0/24"
    And the cradle dump "ipv6" in namespace "fwd" via gRPC as "ctl" should contain "2001:db8:9::/64"
    And the cradle dump "mpls" in namespace "fwd" via gRPC as "ctl" should contain "swap"
    And the cradle dump "srv6" in namespace "fwd" via gRPC as "ctl" should contain "fc00:0:1::"
    And the cradle dump "l2" in namespace "fwd" via gRPC as "ctl" should contain "02:00:00:00:00:0b"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "fwd"
    Then the test environment should be clean
