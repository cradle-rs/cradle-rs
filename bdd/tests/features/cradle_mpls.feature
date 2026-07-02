@serial
@cradle_mpls
Feature: eBPF MPLS label switching (push, swap, SR stacks, pop)
  As an operator running the cradle data plane
  I want complete LSPs — imposition, transit, disposition — in eBPF
  So that MPLS forwards without kernel MPLS support anywhere on the path.

  Topology (kernel MPLS nowhere — imposition is now cradle's, so even the
  client pushes nothing):
  ```
   cl ─10.0.0/24─ ler1[push] ─10.0.1/24─ lsr2[swap] ─10.0.2/24─ per3[pop] ─10.0.3/24─ srv
  ```
  Two LSPs prove the whole operation matrix:
  - 10.0.3.0/24: push [16] (TC grow on an IP frame) → swap 16→[17] (TC
    in-place) → explicit pop-l3 (XDP shrink) — the single-label path.
  - 10.0.4.0/24: push [26,28] (multi-label) → swap 26→[27,29] (XDP
    grow-swap + redirect; wire stack becomes 27,29,28) → per3 owns all three
    remaining labels: its "swap with no out-labels" ILMs carry an *oif-less*
    nexthop, so the pops chain locally in one XDP pass (the UHP/egress
    shape; a pop ILM with a real nexthop would instead pop-and-forward).
  Counters prove which hop did which operation; the reverse path is plain
  eBPF IPv4 forwarding.

  Scenario: Label-switch single-label and SR-stacked LSPs
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "ler1"
    And I create namespace "lsr2"
    And I create namespace "per3"
    And I create namespace "srv"
    And I connect namespace "cl" interface "eth0" to namespace "ler1" interface "ler1a"
    And I connect namespace "ler1" interface "ler1b" to namespace "lsr2" interface "lsr2a"
    And I connect namespace "lsr2" interface "lsr2b" to namespace "per3" interface "per3a"
    And I connect namespace "per3" interface "per3b" to namespace "srv" interface "eth0"
    And I execute "ip link set dev lsr2a address 02:00:00:00:02:0a" in namespace "lsr2"
    And I execute "ip link set dev per3a address 02:00:00:00:03:0a" in namespace "per3"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.0.254/24" to interface "ler1a" in namespace "ler1"
    And I add address "10.0.1.1/24" to interface "ler1b" in namespace "ler1"
    And I add address "10.0.1.2/24" to interface "lsr2a" in namespace "lsr2"
    And I add address "10.0.2.1/24" to interface "lsr2b" in namespace "lsr2"
    And I add address "10.0.2.2/24" to interface "per3a" in namespace "per3"
    And I add address "10.0.3.254/24" to interface "per3b" in namespace "per3"
    And I add address "10.0.3.1/24" to interface "eth0" in namespace "srv"
    And I add address "10.0.4.1/32" to interface "eth0" in namespace "srv"
    And I add route "default" via "10.0.0.254" in namespace "cl"
    And I add route "default" via "10.0.3.254" in namespace "srv"
    And I disable IPv4 forwarding in namespace "ler1"
    And I disable IPv4 forwarding in namespace "lsr2"
    And I disable IPv4 forwarding in namespace "per3"
    Then ping from "cl" to "10.0.3.1" should fail
    When I start cradle in namespace "ler1" with config "ler1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "lsr2" with config "lsr2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "per3" with config "per3.json" serving gRPC as "ctl3"
    Then ping from "cl" to "10.0.3.1" should eventually succeed
    And ping from "cl" to "10.0.4.1" should eventually succeed
    And the cradle stat "mpls_push" in namespace "ler1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_swap" in namespace "lsr2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_pop" in namespace "per3" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "ler1"
    And I stop cradle in namespace "lsr2"
    And I stop cradle in namespace "per3"
    And I delete namespace "cl"
    And I delete namespace "ler1"
    And I delete namespace "lsr2"
    And I delete namespace "per3"
    And I delete namespace "srv"
    Then the test environment should be clean
