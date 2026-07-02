@serial
@cradle_mpls
Feature: eBPF MPLS label switching (transit swap + PHP)
  As an operator running the cradle data plane
  I want MPLS frames label-switched in eBPF
  So that LSPs are forwarded without kernel MPLS support on the routers.

  Topology (kernel MPLS forwarding stays off on both LSRs — the client's
  kernel does the imposition; swap and pop are provably eBPF):
  ```
   cl(10.0.0.1) ── lsr1 [cradle] ── lsr2 [cradle] ── srv(10.0.2.1)
   encap mpls 16     swap 16→17      pop-l3 (PHP)
  ```
  The forward path is labeled (client pushes 16, lsr1 swaps to 17, lsr2 pops
  and routes the exposed IP packet); the return path is plain eBPF IPv4
  forwarding. Reachability plus the mpls_swap/mpls_pop counters prove which
  LSR performed which label operation.

  Scenario: Label-switch a flow across a static LSP
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "lsr1"
    And I create namespace "lsr2"
    And I create namespace "srv"
    And I connect namespace "cl" interface "eth0" to namespace "lsr1" interface "lsr1a"
    And I connect namespace "lsr1" interface "lsr1b" to namespace "lsr2" interface "lsr2a"
    And I connect namespace "lsr2" interface "lsr2b" to namespace "srv" interface "eth0"
    And I execute "ip link set dev lsr2a address 02:00:00:00:02:0a" in namespace "lsr2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.0.254/24" to interface "lsr1a" in namespace "lsr1"
    And I add address "10.0.1.1/24" to interface "lsr1b" in namespace "lsr1"
    And I add address "10.0.1.2/24" to interface "lsr2a" in namespace "lsr2"
    And I add address "10.0.2.254/24" to interface "lsr2b" in namespace "lsr2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "srv"
    And I execute "modprobe mpls_iptunnel" in namespace "cl"
    And I execute "ip route add 10.0.2.0/24 encap mpls 16 via 10.0.0.254" in namespace "cl"
    And I add route "default" via "10.0.2.254" in namespace "srv"
    And I disable IPv4 forwarding in namespace "lsr1"
    And I disable IPv4 forwarding in namespace "lsr2"
    Then ping from "cl" to "10.0.2.1" should fail
    When I start cradle in namespace "lsr1" with config "lsr1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "lsr2" with config "lsr2.json" serving gRPC as "ctl2"
    Then ping from "cl" to "10.0.2.1" should eventually succeed
    And the cradle stat "mpls_swap" in namespace "lsr1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_pop" in namespace "lsr2" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "lsr1"
    And I stop cradle in namespace "lsr2"
    And I delete namespace "cl"
    And I delete namespace "lsr1"
    And I delete namespace "lsr2"
    And I delete namespace "srv"
    Then the test environment should be clean
