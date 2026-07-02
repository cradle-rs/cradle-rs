@serial
@cradle_mpls_isis
Feature: IS-IS SR-MPLS labels drive the eBPF label switch
  zebra-rs runs IS-IS with segment-routing MPLS; prefix-SIDs distribute
  labels dynamically. The FibHandle tee forwards the resulting labeled
  routes (imposition), ILM entries (transit/PHP), and resolved neighbors to
  cradle — so an IGP-signaled LSP forwards entirely in eBPF, with zero
  MPLS-specific test plumbing: this feature proves the tee generalizes from
  static bindings to a real label-distribution protocol unchanged.

  Topology (kernel IP forwarding off on all routers; IS-IS hellos are LLC
  frames, which the TC classifier passes to the host stack untouched):
  ```
   cl ─10.0.0/24─ r1[zebra+cradle] ─192.168.1/30─ r2[zebra+cradle] ─192.168.2/30─ r3[zebra+cradle]
                                                                                    lo 3.3.3.3/32, SID index 3
  ```
  SRGB default 16000 ⇒ r3's prefix-SID resolves to label 16003. r1 imposes
  16003 (its route to 3.3.3.3 rides a transit neighbor); r2 is the
  penultimate hop — IS-IS expresses PHP as an ILM with an empty out-label
  stack, which the data plane pops by the packet's S bit; r3 delivers
  locally. One warm-up ping seeds r1's ARP so the teed neighbor feeds the
  MPLS egress rewrite.

  Scenario: An IS-IS prefix-SID LSP forwards via the eBPF data plane
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "r3"
    And I connect namespace "cl" interface "eth0" to namespace "r1" interface "r1a"
    And I connect namespace "r1" interface "r1b" to namespace "r2" interface "r2a"
    And I connect namespace "r2" interface "r2b" to namespace "r3" interface "r3a"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.0.254/24" to interface "r1a" in namespace "r1"
    And I add address "192.168.1.1/30" to interface "r1b" in namespace "r1"
    And I add address "192.168.1.2/30" to interface "r2a" in namespace "r2"
    And I add address "192.168.2.1/30" to interface "r2b" in namespace "r2"
    And I add address "192.168.2.2/30" to interface "r3a" in namespace "r3"
    And I add address "1.1.1.1/32" to interface "lo" in namespace "r1"
    And I add address "2.2.2.2/32" to interface "lo" in namespace "r2"
    And I add address "3.3.3.3/32" to interface "lo" in namespace "r3"
    And I add route "default" via "10.0.0.254" in namespace "cl"
    And I disable IPv4 forwarding in namespace "r1"
    And I disable IPv4 forwarding in namespace "r2"
    And I disable IPv4 forwarding in namespace "r3"
    And I start cradle in namespace "r1" with config "ports-r1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "r2" with config "ports-r2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "r3" with config "ports-r3.json" serving gRPC as "ctl3"
    Then ping from "cl" to "3.3.3.3" should fail
    When I start zebra-rs in namespace "r1" with config "r1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "r2" with config "r2.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "r3" with config "r3.yaml" teeing to cradle as "ctl3"
    And I wait 10 seconds
    And I execute "ping -c 1 -W 2 192.168.1.2" in namespace "r1"
    Then mpls ilm in namespace "r2" should contain label 16003
    And ping from "cl" to "3.3.3.3" should eventually succeed
    And the cradle stat "mpls_push" in namespace "r1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_pop" in namespace "r2" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "r1"
    And I stop the zebra-rs tee in namespace "r2"
    And I stop the zebra-rs tee in namespace "r3"
    And I stop cradle in namespace "r1"
    And I stop cradle in namespace "r2"
    And I stop cradle in namespace "r3"
    And I delete namespace "cl"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "r3"
    Then the test environment should be clean
