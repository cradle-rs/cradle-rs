@serial
@cradle_l7
Feature: L7 HTTP proxy via eBPF TPROXY (bpf_sk_assign)
  TCP flows to an L7-marked VIP are steered by the eBPF datapath to a user-space
  transparent proxy (bpf_sk_assign), which terminates the connection, routes by
  HTTP path, and forwards to the matching backend.

  Topology:
  ```
   cl(10.0.1.1) ─ fwd1 [ cradle eBPF TPROXY + L7 proxy ] fwd2 ─ a(10.0.2.1:8080)
                                                          fwd3 ─ b(10.0.3.1:8080)
   VIP 10.0.9.9:80  /a -> a   /b -> b   / -> a
  ```

  Scenario: Path-routed HTTP through the eBPF-steered transparent proxy
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "a"
    And I create namespace "b"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "a" interface "eth0" to namespace "fwd" interface "fwd2"
    And I connect namespace "b" interface "eth0" to namespace "fwd" interface "fwd3"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "a"
    And I add address "10.0.3.1/24" to interface "eth0" in namespace "b"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add address "10.0.3.254/24" to interface "fwd3" in namespace "fwd"
    And I add route "default" via "10.0.1.254" in namespace "cl"
    And I add route "default" via "10.0.2.254" in namespace "a"
    And I add route "default" via "10.0.3.254" in namespace "b"
    And I disable IPv4 forwarding in namespace "fwd"
    And I disable reverse path filtering in namespace "fwd"
    And I add local route "10.0.9.9/32" in namespace "fwd"
    And I serve HTTP "backend-a" in namespace "a" bound to "0.0.0.0"
    And I serve HTTP "backend-b" in namespace "b" bound to "0.0.0.0"
    And I start cradle in namespace "fwd" with config "l7.json" serving gRPC as "ctl"
    Then HTTP GET "http://10.0.9.9/a" from namespace "cl" should contain "backend-a"
    And HTTP GET "http://10.0.9.9/b" from namespace "cl" should contain "backend-b"
    And the cradle stat "l7_redirect" in namespace "fwd" via gRPC as "ctl" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I stop HTTP in namespace "a"
    And I stop HTTP in namespace "b"
    And I delete namespace "cl"
    And I delete namespace "a"
    And I delete namespace "b"
    And I delete namespace "fwd"
    Then the test environment should be clean
