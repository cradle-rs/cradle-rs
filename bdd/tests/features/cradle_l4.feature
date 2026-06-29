@serial
@cradle_l4
Feature: eBPF L4 service load balancing (IPv4)
  A VIP is DNAT'd in eBPF to one of several backends, the flow is
  connection-tracked, and replies are reverse-NAT'd back to the VIP.

  Topology:
  ```
   cl(10.0.1.1) ─ fwd1 [ cradle eBPF L3+L4 ] fwd2 ─ b1(10.0.2.1:8080)
                                              fwd3 ─ b2(10.0.3.1:8080)
   VIP 10.0.9.9:8080 -> { b1, b2 }
  ```

  Scenario: Load-balance HTTP across two backends via a VIP
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "b1"
    And I create namespace "b2"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "b1" interface "eth0" to namespace "fwd" interface "fwd2"
    And I connect namespace "b2" interface "eth0" to namespace "fwd" interface "fwd3"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "b1"
    And I add address "10.0.3.1/24" to interface "eth0" in namespace "b2"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add address "10.0.3.254/24" to interface "fwd3" in namespace "fwd"
    And I add route "default" via "10.0.1.254" in namespace "cl"
    And I add route "default" via "10.0.2.254" in namespace "b1"
    And I add route "default" via "10.0.3.254" in namespace "b2"
    And I disable IPv4 forwarding in namespace "fwd"
    And I serve HTTP "backend-1" in namespace "b1" bound to "0.0.0.0"
    And I serve HTTP "backend-2" in namespace "b2" bound to "0.0.0.0"
    And I start cradle in namespace "fwd" with config "fwd.json"
    Then HTTP GET "http://10.0.9.9:8080/" from namespace "cl" should eventually succeed
    And HTTP GET "http://10.0.9.9:8080/" from namespace "cl" returns at least 2 distinct responses over 12 requests

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
