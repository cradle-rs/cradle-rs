@serial
@cradle_l3
Feature: eBPF L3 IPv4 forwarding
  As an operator running the cradle data plane
  I want IPv4 routed in eBPF
  So that hosts in different subnets reach each other without kernel forwarding.

  Topology:
  ```
   h1(10.0.1.1) ── fwd1 [ cradle eBPF ] fwd2 ── h2(10.0.2.1)
  ```
  Kernel IP forwarding on the forwarder is disabled, so reachability proves the
  eBPF data plane forwarded the traffic. cradle is given only the two L3 ports;
  it auto-derives the connected/local routes and the kernel resolves next hops.

  Scenario: Forward IPv4 between subnets through the eBPF data plane
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
    Then ping from "h1" to "10.0.2.1" should fail
    When I start cradle in namespace "fwd" with config "fwd.json"
    Then ping from "h1" to "10.0.2.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "fwd"
    Then the test environment should be clean
