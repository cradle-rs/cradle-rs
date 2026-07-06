@serial
@cradle_policy
Feature: Network policy in the eBPF datapath
  cradle enforces Kubernetes-style NetworkPolicy natively: pod IPs map to
  label-set identities, and an enforced pod endpoint drops traffic — ingress
  or egress — that is neither a reply to a flow recorded in the opposite
  direction (stateful, via PCT) nor matched by an allow rule. Ingress is
  checked in `cradle_tc` where the destination resolves to the pod's veth;
  egress at the pod's veth ingress hook, post-NAT. Peers without an exact
  identity fall back to the CIDR LPM (ipBlock; an `except` prefix is a
  more-specific entry back to world). Kernel forwarding is off, so the
  datapath is the only thing that could carry or drop the packets.
  Design: docs/design/policy.md.

  Topology (single node, cradle-cni pods):
  ```
   host1(10.1.1.2, "world") ── n0 [node: cradle serve] crdl* ── pod1(id 100), pod2(id 200)
  ```

  Scenario: Allow by identity, deny world, and un-enforce
    Given a clean test environment
    When I create namespace "node"
    And I create namespace "host1"
    And I create namespace "pod1"
    And I create namespace "pod2"
    And I connect namespace "node" interface "n0" to namespace "host1" interface "eth0"
    And I add address "10.1.1.1/24" to interface "n0" in namespace "node"
    And I add address "10.1.1.2/24" to interface "eth0" in namespace "host1"
    And I add route "10.244.0.0/24" via "10.1.1.1" in namespace "host1"
    And I disable IPv4 forwarding in namespace "node"
    And I start cradle CNI node in namespace "node" with config "node.json" serving gRPC as "ctl"
    And I run CNI ADD for container "pod1" in pod namespace "pod1" on node "node" with config "cni.json" expecting "10.244.0.2"
    And I run CNI ADD for container "pod2" in pod namespace "pod2" on node "node" with config "cni.json" expecting "10.244.0.3"
    Then ping from "pod1" to "10.244.0.3" should eventually succeed
    And ping from "host1" to "10.244.0.3" should succeed
    When I apply cradle config "policy-on.json" to namespace "node" via gRPC as "ctl"
    Then ping from "pod1" to "10.244.0.3" should succeed
    And ping from "host1" to "10.244.0.3" should fail
    And the cradle stat "policy_drop" in namespace "node" via gRPC as "ctl" should be nonzero
    When I apply cradle config "policy-off.json" to namespace "node" via gRPC as "ctl"
    Then ping from "host1" to "10.244.0.3" should eventually succeed

  Scenario: Stateful replies pass an enforced endpoint with no allow rules
    Given the test topology exists
    When I serve HTTP "p2" in namespace "pod2" bound to "10.244.0.3"
    And I apply cradle config "policy-pct.json" to namespace "node" via gRPC as "ctl"
    Then ping from "host1" to "10.244.0.2" should fail
    And HTTP GET "http://10.244.0.3:8080/" from namespace "pod1" should eventually succeed

  Scenario: Egress allow by identity, deny world, inbound replies pass
    Given the test topology exists
    When I serve HTTP "p1" in namespace "pod1" bound to "10.244.0.2"
    And I apply cradle config "policy-egress.json" to namespace "node" via gRPC as "ctl"
    # pod1 egress: pod2's identity allowed, world (host1) is not.
    Then ping from "pod1" to "10.244.0.3" should succeed
    And ping from "pod1" to "10.1.1.2" should fail
    # Egress statefulness: host1-initiated flow admitted inbound (pod1 has no
    # ingress enforcement) — pod1's replies bypass its egress rules.
    And HTTP GET "http://10.244.0.2:8080/" from namespace "host1" should eventually succeed

  Scenario: ipBlock CIDR identity with except-prefix override
    Given the test topology exists
    When I apply cradle config "policy-cidr.json" to namespace "node" via gRPC as "ctl"
    # host1 (10.1.1.2) matches the 10.1.1.0/24 binding → identity 300, allowed.
    Then ping from "host1" to "10.244.0.3" should eventually succeed
    When I apply cradle config "policy-cidr-except.json" to namespace "node" via gRPC as "ctl"
    # The /32 except entry is more specific → host1 is world again, denied.
    Then ping from "host1" to "10.244.0.3" should fail

  Scenario: Audit mode reports but forwards; replace flips generations
    Given the test topology exists
    # pod2 enforced with no allow rules BUT audit: denied verdicts are
    # counted (policy_audit) while the traffic still flows.
    When I apply cradle config "policy-audit.json" to namespace "node" via gRPC as "ctl"
    Then ping from "host1" to "10.244.0.3" should eventually succeed
    And the cradle stat "policy_audit" in namespace "node" via gRPC as "ctl" should be nonzero
    # Back to enforcing (an A/B generation flip per apply): verdicts hold
    # across repeated replaces.
    When I apply cradle config "policy-on.json" to namespace "node" via gRPC as "ctl"
    Then ping from "pod1" to "10.244.0.3" should succeed
    And ping from "host1" to "10.244.0.3" should fail
    When I apply cradle config "policy-on.json" to namespace "node" via gRPC as "ctl"
    Then ping from "pod1" to "10.244.0.3" should succeed
    And ping from "host1" to "10.244.0.3" should fail

  Scenario: Deny rule wins over a wildcard allow
    Given the test topology exists
    # pod2 allows any peer (identity 0) but denies pod1's identity — the
    # deny wins at any specificity (Cilium deny semantics).
    When I apply cradle config "policy-deny.json" to namespace "node" via gRPC as "ctl"
    Then ping from "host1" to "10.244.0.3" should eventually succeed
    And ping from "pod1" to "10.244.0.3" should fail

  Scenario: L7 policy filters HTTP by method and path via the proxy
    Given the test topology exists
    # pod2's port 8080 is steered through the transparent proxy, which
    # allows only GET /allowed* and answers anything else with an empty 403.
    When I apply cradle config "policy-l7.json" to namespace "node" via gRPC as "ctl"
    Then HTTP GET "http://10.244.0.3:8080/allowed" from namespace "pod1" should eventually succeed
    And HTTP GET "http://10.244.0.3:8080/secret" from namespace "pod1" should fail
    And the cradle stat "l7_redirect" in namespace "node" via gRPC as "ctl" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop HTTP in namespace "pod1"
    And I stop HTTP in namespace "pod2"
    And I stop cradle CNI node in namespace "node"
    And I delete namespace "pod1"
    And I delete namespace "pod2"
    And I delete namespace "host1"
    And I delete namespace "node"
    Then the test environment should be clean
