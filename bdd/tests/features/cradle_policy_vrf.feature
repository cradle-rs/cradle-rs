@serial
@cradle_policy_vrf
Feature: VRF-scoped policy identities (multi-tenant, overlapping addresses)
  Phase 4 of docs/design/policy-multitenant.md: identity is `(vrf, ip)`.
  Two tenants use the SAME addresses on either side of one cradle node
  (ports bound to VRF 1 and VRF 2); the same client IP resolves to a
  different identity per tenant, so identical policy rules give different
  verdicts. Kernel forwarding is off — the datapath does all forwarding,
  per-VRF via FIB4_VRF.

  Topology (overlapping CIDRs, one namespace per tenant side):
  ```
   t1cl(10.9.0.2) ── t1c [fwd] t1s ── t1sv(10.9.1.2)   VRF 1
   t2cl(10.9.0.2) ── t2c [fwd] t2s ── t2sv(10.9.1.2)   VRF 2
  ```

  Scenario: Same IP, different tenant identity, different verdict
    Given a clean test environment
    When I create namespace "t1cl"
    And I create namespace "t1sv"
    And I create namespace "t2cl"
    And I create namespace "t2sv"
    And I create namespace "fwd"
    And I connect namespace "t1cl" interface "eth0" to namespace "fwd" interface "t1c"
    And I connect namespace "t1sv" interface "eth0" to namespace "fwd" interface "t1s"
    And I connect namespace "t2cl" interface "eth0" to namespace "fwd" interface "t2c"
    And I connect namespace "t2sv" interface "eth0" to namespace "fwd" interface "t2s"
    And I add address "10.9.0.2/24" to interface "eth0" in namespace "t1cl"
    And I add address "10.9.1.2/24" to interface "eth0" in namespace "t1sv"
    And I add address "10.9.0.2/24" to interface "eth0" in namespace "t2cl"
    And I add address "10.9.1.2/24" to interface "eth0" in namespace "t2sv"
    And I add address "10.9.0.1/24" to interface "t1c" in namespace "fwd"
    And I add address "10.9.1.1/24" to interface "t1s" in namespace "fwd"
    And I add address "10.9.0.1/24" to interface "t2c" in namespace "fwd"
    And I add address "10.9.1.1/24" to interface "t2s" in namespace "fwd"
    And I add route "default" via "10.9.0.1" in namespace "t1cl"
    And I add route "default" via "10.9.1.1" in namespace "t1sv"
    And I add route "default" via "10.9.0.1" in namespace "t2cl"
    And I add route "default" via "10.9.1.1" in namespace "t2sv"
    And I disable IPv4 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" with config "fwd.json" serving gRPC as "ctl"
    # Overlapping CIDRs forward independently per VRF.
    Then ping from "t1cl" to "10.9.1.2" should eventually succeed
    And ping from "t2cl" to "10.9.1.2" should eventually succeed
    # Both servers enforce "allow identity 100"; 10.9.0.2 is identity 100
    # in VRF 1 but identity 200 in VRF 2 — same address, opposite verdicts.
    When I apply cradle config "pol.json" to namespace "fwd" via gRPC as "ctl"
    Then ping from "t1cl" to "10.9.1.2" should eventually succeed
    And ping from "t2cl" to "10.9.1.2" should fail
    And the cradle stat "policy_drop" in namespace "fwd" via gRPC as "ctl" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "fwd"
    And I delete namespace "t1cl"
    And I delete namespace "t1sv"
    And I delete namespace "t2cl"
    And I delete namespace "t2sv"
    And I delete namespace "fwd"
    Then the test environment should be clean
