@serial
@cradle_dir24
Feature: eBPF L3 forwarding with the DIR-24-8 FIB engine
  As an operator carrying a large routing table
  I want IPv4 routed through the DIR-24-8 direct-index FIB
  So that lookups are 1-2 flat array loads instead of an LPM trie walk.

  Topology (same as cradle_l3, but the forwarder runs with
  "fib4_mode": "dir24" — TBL24/TBL8 sized at load, the LPM trie unused):
  ```
   h1(10.0.1.1) ── fwd1 [ cradle eBPF, dir24 ] fwd2 ── h2(10.0.2.1, 10.0.9.9)
  ```
  Kernel IP forwarding on the forwarder is disabled, so reachability proves
  the eBPF data plane forwarded via the direct-index tables. Both engine
  paths are exercised and asserted separately: the connected /24 blocks
  contain the auto-derived local /32s, so traffic to 10.0.2.1 resolves
  through a TBL8 group (fib4_tbl8_hit); the static 10.0.9.0/24 lives in a
  block with no /32s, so traffic to 10.0.9.9 resolves directly in TBL24
  (fib4_tbl24_hit).

  Scenario: Forward IPv4 through the DIR-24-8 tables
    Given a clean test environment
    When I create namespace "h1"
    And I create namespace "fwd"
    And I create namespace "h2"
    And I connect namespace "h1" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "h2" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "h1"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "h2"
    And I add address "10.0.9.9/32" to interface "eth0" in namespace "h2"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add route "default" via "10.0.1.254" in namespace "h1"
    And I add route "default" via "10.0.2.254" in namespace "h2"
    And I disable IPv4 forwarding in namespace "fwd"
    Then ping from "h1" to "10.0.2.1" should fail
    When I start cradle in namespace "fwd" with config "fwd.json" serving gRPC as "ctl"
    Then ping from "h1" to "10.0.2.1" should eventually succeed
    And ping from "h1" to "10.0.9.9" should eventually succeed
    And the cradle stat "fib4_tbl8_hit" in namespace "fwd" via gRPC as "ctl" should be nonzero
    And the cradle stat "fib4_tbl24_hit" in namespace "fwd" via gRPC as "ctl" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "fwd"
    Then the test environment should be clean
