@serial
@cradle_bigfib
Feature: DIR-24-8 FIB at full-table scale
  As an operator carrying a DFZ-sized routing table
  I want a million learned routes installed in the eBPF FIB
  So that forwarding stays correct and fast with the table fully loaded.

  Topology (cradle_l3 shape; the forwarder runs dir24 and is bulk-loaded
  with a synthetic DFZ-shaped table on top of a few explicit routes):
  ```
   h1(10.0.1.1) ── fwd1 [ cradle eBPF, dir24 + 1M routes ] fwd2 ── h2(10.0.2.1,
                                                             10.0.9.9, 10.0.9.17, 99.99.99.99)
  ```
  The explicit fixture routes exercise every lookup path with the million
  routes installed: 10.0.8.0/24 (direct TBL24 — its block holds no longer
  route), 10.0.9.16/28 inside 10.0.9.0/24 (the /28 group-backs that whole
  block, so 10.0.9.x resolves via TBL8), and 0.0.0.0/0 (DEFAULT4 — hit via
  99.99.99.99, which no table route covers; the generator stays below
  90.0.0.0). Withdrawing the /28 proves delete/collapse under load: traffic
  falls back to the /24 cover.

  Scenario: Forward correctly with a million-route FIB
    Given a clean test environment
    When I create namespace "h1"
    And I create namespace "fwd"
    And I create namespace "h2"
    And I connect namespace "h1" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "h2" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "h1"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "h2"
    And I add address "10.0.8.8/32" to interface "eth0" in namespace "h2"
    And I add address "10.0.9.17/32" to interface "eth0" in namespace "h2"
    And I add address "99.99.99.99/32" to interface "eth0" in namespace "h2"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add route "default" via "10.0.1.254" in namespace "h1"
    And I add route "default" via "10.0.2.254" in namespace "h2"
    And I disable IPv4 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" with config "fwd.json" serving gRPC as "ctl"
    And I generate 1000000 routes with seed 1 nexthop 1 via gRPC as "ctl" in namespace "fwd"
    Then the cradle fib route count via gRPC as "ctl" in namespace "fwd" should be at least 1000000
    And ping from "h1" to "10.0.8.8" should eventually succeed
    And ping from "h1" to "10.0.9.17" should eventually succeed
    And ping from "h1" to "99.99.99.99" should eventually succeed
    And the cradle stat "fib4_tbl24_hit" in namespace "fwd" via gRPC as "ctl" should be nonzero
    And the cradle stat "fib4_tbl8_hit" in namespace "fwd" via gRPC as "ctl" should be nonzero
    And the cradle stat "fib4_default" in namespace "fwd" via gRPC as "ctl" should be nonzero
    When I delete cradle route "10.0.9.16/28" via gRPC as "ctl" in namespace "fwd"
    Then ping from "h1" to "10.0.9.17" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "fwd"
    Then the test environment should be clean
