@serial
@cradle_srv6_te
Feature: SRv6 SR-TE transit in the eBPF data plane (SRH walk: End / End.X)
  As an operator running SRv6 SR-TE policies on cradle
  I want packets steered through explicit waypoint SIDs
  So that a multi-SID segment list is imposed, walked, and decapped in eBPF.

  Topology (kernel v4+v6 forwarding and seg6 off on pe1/p/pe2):
  ```
   c1 ── pe1[cradle] ──2001:db8:1::/64── p[cradle] ──2001:db8:2::/64── pe2[cradle] ── c2
    vrf 10                 End + End.X waypoint                  vrf 20 (End.DT46)
  ```
  pe1 imposes a two-SID list [p-waypoint-SID, pe2-DT46-SID] on the c1 traffic
  — H.Encaps.Red writes an actual SRH (Segments Left = 1, DA = the waypoint
  SID). p owns two waypoint SIDs, exercising both transit behaviors in one
  topology: the v4 flow's SID is End (decrement SL, rewrite DA to pe2's SID,
  forward by the FIB), the v6 flow's SID is End.X (same SRH walk, but forward
  straight out the adjacency toward pe2). pe2's End.DT46 then arrives with an
  exhausted SRH (SL = 0), which it skips before decapping into VRF 20. The
  reverse direction stays single-SID (Phase 1 form) for a trivial return path.

  Scenario: Steer customer v4 and v6 through an SRv6 waypoint (End / End.X)
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
    And the cradle stat "srv6_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_end" in namespace "p" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_decap" in namespace "pe2" via gRPC as "ctl3" should be nonzero

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
