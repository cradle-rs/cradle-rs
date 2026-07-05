@serial
@cradle_policy_v6
Feature: IPv6 network policy in the eBPF datapath
  v6 sibling of cradle_policy, on a plain L3 topology (no CNI): ingress
  enforcement keyed by the delivery port (`host_if`), with v6 peers resolved
  through `IDENTITY6` (exact) and `CIDR_ID6` (LPM, ipBlock) against the same
  address-family-agnostic `POLICY` rules. Kernel forwarding is off, so the
  datapath is the only thing that could carry or drop the packets.

  Topology:
  ```
   cl(2001:db8:1::1) ── fwd1 [fwd: cradle serve] fwd2 ── sv(2001:db8:2::1)
  ```

  Scenario: v6 ingress deny, allow by CIDR binding, allow by exact identity
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "sv"
    And I create namespace "fwd"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "sv" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "2001:db8:1::1/64" to interface "eth0" in namespace "cl"
    And I add address "2001:db8:2::1/64" to interface "eth0" in namespace "sv"
    And I add address "2001:db8:1::ffff/64" to interface "fwd1" in namespace "fwd"
    And I add address "2001:db8:2::ffff/64" to interface "fwd2" in namespace "fwd"
    And I add route "default" via "2001:db8:1::ffff" in namespace "cl"
    And I add route "default" via "2001:db8:2::ffff" in namespace "sv"
    And I disable IPv6 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" with config "fwd.json" serving gRPC as "ctl"
    Then ping from "cl" to "2001:db8:2::1" should eventually succeed
    # Enforce with no allow rules: everything toward sv drops.
    When I apply cradle config "pol-deny.json" to namespace "fwd" via gRPC as "ctl"
    Then ping from "cl" to "2001:db8:2::1" should fail
    And the cradle stat "policy_drop" in namespace "fwd" via gRPC as "ctl" should be nonzero
    # cl has no exact identity — the /64 CIDR binding resolves it.
    When I apply cradle config "pol-cidr.json" to namespace "fwd" via gRPC as "ctl"
    Then ping from "cl" to "2001:db8:2::1" should eventually succeed
    # Exact v6 identity binding wins where present.
    When I apply cradle config "pol-allow.json" to namespace "fwd" via gRPC as "ctl"
    Then ping from "cl" to "2001:db8:2::1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I delete namespace "cl"
    And I delete namespace "sv"
    And I delete namespace "fwd"
    Then the test environment should be clean
