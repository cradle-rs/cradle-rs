@serial
@cradle_tee_connected
Feature: Connected routes tee to cradle and neighbors resolve dynamically
  As an operator running zebra-driven cradle nodes
  I want directly-connected prefixes in the eBPF FIB and neighbors
  resolved without any pinning
  So that a router whose config is nothing but interface addresses
  forwards between its LANs — the baseline every real deployment
  assumes.

  Historically the tee only carried protocol routes (`is_protocol`),
  so a zebra-driven node could not deliver to its own connected
  subnets without hand-pinned neighbors and synthetic static routes —
  every zebra-driven BDD in this suite worked around it. This feature
  is the un-contorted baseline: r's zebra config contains ONLY
  interface addresses; no static routes, no pinned neighbors, no
  pinned MACs anywhere. Connected routes reach cradle through the tee
  as interface-only members, and the eBPF forward's
  `bpf_redirect_neigh` fallback resolves c1/c2 via kernel ND/ARP on
  its own. Kernel v4+v6 forwarding is OFF on r — without the teed
  routes every packet dies, which is the assertion teeth.

  Topology:
  ```
   c1 ── r[zebra+cradle] ── c2
   fc00:1::/64          fc00:2::/64
   10.0.1.0/24          10.0.2.0/24
  ```

  Scenario: Interface-only config forwards both families
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "r"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "r" interface "ra"
    And I connect namespace "r" interface "rb" to namespace "c2" interface "eth0"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "0.0.0.0/0" via "10.0.1.254" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I add route "0.0.0.0/0" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "r"
    And I disable IPv6 forwarding in namespace "r"
    When I start cradle in namespace "r" with config "ports-r.json" serving gRPC as "ctl1"
    And I start zebra-rs in namespace "r" with config "r.yaml" teeing to cradle as "ctl1"
    # v6: the connected fc00:2::/64 must have teed, and c2's neighbor
    # resolves via redirect_neigh-driven ND — nothing is pinned.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    # v4: same through the connected 10.0.2.0/24 and kernel ARP.
    Then ping from "c1" to "10.0.2.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "r"
    And I stop cradle in namespace "r"
    And I delete namespace "c1"
    And I delete namespace "r"
    And I delete namespace "c2"
    Then the test environment should be clean
