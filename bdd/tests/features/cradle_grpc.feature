@serial
@cradle_grpc
Feature: gRPC control API drives the eBPF data plane
  cradle starts with no config, exposing only its gRPC control API on a unix
  socket. The data plane is then programmed entirely over gRPC by `cradle ctl`.

  Scenario: Program L3 forwarding over the gRPC control API
    Given a clean test environment
    When I create namespace "h1"
    And I create namespace "fwd"
    And I create namespace "h2"
    And I connect namespace "h1" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "h2" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "h1"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "h2"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add route "default" via "10.0.1.254" in namespace "h1"
    And I add route "default" via "10.0.2.254" in namespace "h2"
    And I disable IPv4 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" serving gRPC as "ctl"
    Then ping from "h1" to "10.0.2.1" should fail
    When I apply cradle config "ports.json" to namespace "fwd" via gRPC as "ctl"
    Then ping from "h1" to "10.0.2.1" should eventually succeed
    And the cradle dump "nexthop" in namespace "fwd" via gRPC as "ctl" should contain "nh_id"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "fwd"
    Then the test environment should be clean
