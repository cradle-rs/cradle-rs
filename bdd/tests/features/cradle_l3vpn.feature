@serial
@cradle_l3vpn
Feature: MPLS L3VPN in the eBPF data plane (per-VRF FIB)
  As an operator running PE routers on cradle
  I want VPN traffic isolated in per-VRF FIB tables end to end
  So that customer routes never touch the global table and vice versa.

  Topology (kernel forwarding off on pe1/p/pe2; all label ops in eBPF):
  ```
   c1(10.0.1.1) ── pe1[cradle] ──192.168.1/30── p[cradle] ──192.168.2/30── pe2[cradle] ── c2(10.0.2.1)
        vrf 10 ↑                    PHP LSR                       ↑ vrf 20
  ```
  The full L3VPN datapath matrix in one ping each way:
  - ingress PE: the customer port is VRF-bound, so the lookup runs in the
    per-VRF FIB (fib4_vrf_hit) and hits a route with a [transport, vpn]
    label stack — a two-label push;
  - P: the transport label's ILM is a "swap with no out-labels" whose
    nexthop is real — the penultimate hop pops and *forwards the remaining
    still-MPLS stack via that nexthop*, never examining the VPN label
    (label spaces are per-node);
  - egress PE: the VPN label's ILM is pop-l3 into the customer VRF — the
    XDP stage decaps and hands the VRF context to the TC FIB stage as
    packet metadata, which routes it in the per-VRF table to the CE.
  Connected VRF routes come from the port derivation; reverse direction is
  the mirror image (labels 117/101).

  Scenario: Route between customer sites over an eBPF L3VPN
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "p"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1a"
    And I connect namespace "pe1" interface "pe1b" to namespace "p" interface "pa"
    And I connect namespace "p" interface "pb" to namespace "pe2" interface "pe2a"
    And I connect namespace "pe2" interface "pe2b" to namespace "c2" interface "eth0"
    And I execute "ip link set dev pa address 02:00:00:00:0a:01" in namespace "p"
    And I execute "ip link set dev pb address 02:00:00:00:0a:02" in namespace "p"
    And I execute "ip link set dev pe1b address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2a address 02:00:00:00:02:0a" in namespace "pe2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.254/24" to interface "pe1a" in namespace "pe1"
    And I add address "192.168.1.1/30" to interface "pe1b" in namespace "pe1"
    And I add address "192.168.1.2/30" to interface "pa" in namespace "p"
    And I add address "192.168.2.1/30" to interface "pb" in namespace "p"
    And I add address "192.168.2.2/30" to interface "pe2a" in namespace "pe2"
    And I add address "10.0.2.254/24" to interface "pe2b" in namespace "pe2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "p"
    And I disable IPv4 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.2.1" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "p.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl3"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed
    And the cradle stat "mpls_push" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_pop" in namespace "p" via gRPC as "ctl2" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe2" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "p"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "p"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
