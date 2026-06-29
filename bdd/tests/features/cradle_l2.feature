@serial
@cradle_l2
Feature: eBPF L2 switching
  As an operator running the cradle data plane
  I want frames switched at L2 in eBPF
  So that hosts on one bridge domain reach each other with no kernel bridge.

  Topology (one L2 domain, no kernel bridge in the switch namespace):
  ```
   h1(10.0.0.1) ─ sw1 ┐
   h2(10.0.0.2) ─ sw2 ┼ [ cradle eBPF switch ]
   h3(10.0.0.3) ─ sw3 ┘
  ```
  Reachability proves the eBPF switch (MAC learning + FDB forward + flood) moved
  the frames; the switch namespace has no bridge of its own.

  Scenario: Switch frames between hosts on one L2 domain
    Given a clean test environment
    When I create namespace "h1"
    And I create namespace "h2"
    And I create namespace "h3"
    And I create namespace "sw"
    And I connect namespace "h1" interface "eth0" to namespace "sw" interface "sw1"
    And I connect namespace "h2" interface "eth0" to namespace "sw" interface "sw2"
    And I connect namespace "h3" interface "eth0" to namespace "sw" interface "sw3"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "h1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "h2"
    And I add address "10.0.0.3/24" to interface "eth0" in namespace "h3"
    Then ping from "h1" to "10.0.0.2" should fail
    When I start cradle in namespace "sw" with config "sw.json"
    Then ping from "h1" to "10.0.0.2" should eventually succeed
    And ping from "h1" to "10.0.0.3" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "sw"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "h3"
    And I delete namespace "sw"
    Then the test environment should be clean
