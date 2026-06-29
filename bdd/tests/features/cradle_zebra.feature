@serial
@cradle_zebra
Feature: zebra-rs static route programs the eBPF FIB (IPv4)
  cradle runs the eBPF data plane; zebra-rs runs the control plane with its
  FibHandle teeing route installs to cradle over gRPC. A static route therefore
  lands in the eBPF FIB and forwards traffic.

  Topology:
  ```
   cl(10.0.1.1) ─ fwd1 [ cradle + zebra-rs ] fwd2 ─ srv(10.0.2.1, +10.9.9.1/32)
  ```

  Scenario: A zebra-rs static route forwards via the eBPF data plane
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "srv"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "srv" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "srv"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add address "10.9.9.1/32" to interface "lo" in namespace "srv"
    And I add route "default" via "10.0.1.254" in namespace "cl"
    And I add route "default" via "10.0.2.254" in namespace "srv"
    And I disable IPv4 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" with config "ports.json" serving gRPC as "ctl"
    Then ping from "cl" to "10.9.9.1" should fail
    When I start zebra-rs in namespace "fwd" with config "static.yaml" teeing to cradle as "ctl"
    Then ping from "cl" to "10.9.9.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "fwd"
    And I stop cradle in namespace "fwd"
    And I delete namespace "cl"
    And I delete namespace "srv"
    And I delete namespace "fwd"
    Then the test environment should be clean
