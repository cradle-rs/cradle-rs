@serial
@cradle_srv6
Feature: SRv6 L3VPN in the eBPF data plane (H.Encaps + End.DT46)
  As an operator running SRv6 PE routers on cradle
  I want VPN traffic carried over an IPv6 underlay with per-VRF isolation
  So that customer v4 and v6 both ride a single SRv6 transport in eBPF.

  Topology (kernel v4+v6 forwarding and seg6 off on pe1/p/pe2; every SRv6
  action runs in eBPF):
  ```
   c1 ── pe1[cradle] ──2001:db8:1::/64── p[cradle] ──2001:db8:2::/64── pe2[cradle] ── c2
    vrf 10: 10.0.1/24 + fc00:1::/64                              vrf 20: 10.0.2/24 + fc00:2::/64
  ```
  pe1 binds SID fd00:2::100 to reach pe2's vrf-20 sites and imposes an outer
  IPv6 header (DA = that SID) on the c1 CE traffic — H.Encaps.Red, no SRH.
  p is a plain IPv6 underlay forwarder toward the fd00::/16 locators. pe2's
  local SID fd00:2::100 is End.DT46: it strips the outer IPv6 and looks the
  inner packet up in VRF 20 — v4 or v6, both carried by the one SID. The
  reverse direction mirrors it (SID fd00:1::100, vrf 10). Because the CE
  ports are VRF-bound, the decap's inner lookup lands in the right table.

  Scenario: Route customer v4 and v6 over an eBPF SRv6 L3VPN
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
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.254/24" to interface "pe1a" in namespace "pe1"
    And I add address "fc00:1::ff/64" to interface "pe1a" in namespace "pe1"
    And I add address "2001:db8:1::1/64" to interface "pe1b" in namespace "pe1"
    And I add address "2001:db8:1::2/64" to interface "pa" in namespace "p"
    And I add address "2001:db8:2::1/64" to interface "pb" in namespace "p"
    And I add address "2001:db8:2::2/64" to interface "pe2a" in namespace "pe2"
    And I add address "10.0.2.254/24" to interface "pe2b" in namespace "pe2"
    And I add address "fc00:2::ff/64" to interface "pe2b" in namespace "pe2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "p"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "p"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.2.1" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "p.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl3"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c1" to "fc00:2::1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed
    And the cradle stat "srv6_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_decap" in namespace "pe2" via gRPC as "ctl3" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe2" via gRPC as "ctl3" should be nonzero
    And the cradle stat "fib6_vrf_hit" in namespace "pe2" via gRPC as "ctl3" should be nonzero

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
