@serial
@cradle_del_port
Feature: DelPort / FlushFdb — dynamic port removal over gRPC
  DelPort is the inverse of SetPort: it detaches the datapath programs from a
  port, removes its PORTS entry and derived state, and flushes the MACs
  learned on it. FlushFdb clears locally-learned FDB entries on demand.
  Both exist so a control plane (zebra-rs) can manage port membership
  dynamically instead of fixing it at daemon start.

  Topology (one L2 domain, programmed entirely over gRPC):
  ```
   h1(10.0.0.1) ─ sw1 ┐
                      ┼ [ cradle eBPF switch ]
   h2(10.0.0.2) ─ sw2 ┘
  ```
  IPv6 is disabled in the hosts so nothing spontaneously re-learns MACs
  (RS/NS/MLD) after a flush — learned-FDB assertions stay deterministic.

  Scenario: L2 switching between two hosts programmed over gRPC
    Given a clean test environment
    When I create namespace "h1"
    And I create namespace "h2"
    And I create namespace "sw"
    And I connect namespace "h1" interface "eth0" to namespace "sw" interface "sw1"
    And I connect namespace "h2" interface "eth0" to namespace "sw" interface "sw2"
    And I execute "sysctl -w net.ipv6.conf.all.disable_ipv6=1" in namespace "h1"
    And I execute "sysctl -w net.ipv6.conf.all.disable_ipv6=1" in namespace "h2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "h1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "h2"
    And I start cradle in namespace "sw" serving gRPC as "ctl"
    Then ping from "h1" to "10.0.0.2" should fail
    When I apply cradle config "sw.json" to namespace "sw" via gRPC as "ctl"
    Then ping from "h1" to "10.0.0.2" should eventually succeed
    And the cradle dump "l2" in namespace "sw" via gRPC as "ctl" should contain "learned"

  Scenario: FlushFdb clears locally-learned MACs
    Given the test topology exists
    When I flush the cradle fdb in namespace "sw" via gRPC as "ctl"
    Then the cradle dump "l2" in namespace "sw" via gRPC as "ctl" should eventually not contain "learned"

  Scenario: DelPort detaches a port and SetPort re-attaches it
    Given the test topology exists
    When I delete cradle port "sw2" in namespace "sw" via gRPC as "ctl"
    Then ping from "h1" to "10.0.0.2" should fail
    When I apply cradle config "sw.json" to namespace "sw" via gRPC as "ctl"
    Then ping from "h1" to "10.0.0.2" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "sw"
    And I delete namespace "h1"
    And I delete namespace "h2"
    And I delete namespace "sw"
    Then the test environment should be clean
