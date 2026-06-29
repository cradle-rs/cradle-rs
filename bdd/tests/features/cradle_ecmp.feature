@serial
@cradle_ecmp
Feature: ECMP multipath in the eBPF data plane (IPv4)
  zebra-rs installs a multipath route; cradle hashes each flow onto a member, so
  distinct source addresses spread across both egress paths.

  Topology:
  ```
   cl ─ fwd1 [ cradle + zebra-rs ] fwd2 ─ R(10.0.2.2) ┐
                                   fwd3 ─ R(10.0.3.2) ┘  hosts 10.9.9.1
   route 10.9.9.0/24 via 10.0.2.2 and 10.0.3.2
  ```

  Scenario: A multipath route load-balances flows across both eBPF paths
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "r"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "r" interface "reth2" to namespace "fwd" interface "fwd2"
    And I connect namespace "r" interface "reth3" to namespace "fwd" interface "fwd3"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.1.11/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.1.12/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.1.13/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.1.14/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.1.15/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add address "10.0.3.254/24" to interface "fwd3" in namespace "fwd"
    And I add address "10.0.2.2/24" to interface "reth2" in namespace "r"
    And I add address "10.0.3.2/24" to interface "reth3" in namespace "r"
    And I add address "10.9.9.1/32" to interface "lo" in namespace "r"
    And I add route "default" via "10.0.1.254" in namespace "cl"
    And I add route "10.0.1.0/24" via "10.0.2.254" in namespace "r"
    And I disable IPv4 forwarding in namespace "fwd"
    And I disable reverse path filtering in namespace "r"
    And I start cradle in namespace "fwd" with config "ports.json" serving gRPC as "ctl"
    And I start zebra-rs in namespace "fwd" with config "static.yaml" teeing to cradle as "ctl"
    Then ping from "cl" to "10.9.9.1" should eventually succeed
    And namespace "cl" balances pings to "10.9.9.1" from sources "10.0.1.1,10.0.1.11,10.0.1.12,10.0.1.13,10.0.1.14,10.0.1.15" across interfaces "fwd2,fwd3" in namespace "fwd"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "fwd"
    And I stop cradle in namespace "fwd"
    And I delete namespace "cl"
    And I delete namespace "r"
    And I delete namespace "fwd"
    Then the test environment should be clean
