@serial
@cradle_srv6_ualib
Feature: SRv6 uSID adjacency (uALib) transit in the eBPF data plane
  As an operator running explicit-path SRv6 uSID (e.g. TI-LFA repair carriers)
  I want an adjacency micro-SID to steer a packet out a specific link
  So that cradle shifts the uSID container and forwards out the cross-connect
  adjacency (uALib) — not by the FIB, which uN would use.

  Topology (kernel v4+v6 forwarding and seg6 off on pe1/p/pe2):
  ```
   c1 ── pe1[cradle] ──2001:db8:1::/64── p[cradle] ──2001:db8:2::/64── pe2[cradle] ── c2
    vrf 10       uALib e002→pe2, e001→pe1 (adjacency, no FIB)      vrf 20 (End.DT46)
  ```
  The uSID block is fcbb:bbbb::/32; micro-SIDs are 16 bits. pe1 H.Encaps.Red the
  c1 traffic with the carrier fcbb:bbbb:e002:20:: — p's adjacency uSID toward pe2
  (e002) followed by pe2's End.DT46 micro-SID (0020). p matches its uALib prefix
  (fcbb:bbbb:e002::/48), shifts the container (DA becomes fcbb:bbbb:20::) and
  forwards straight out the p→pe2 adjacency — the reverse carrier
  fcbb:bbbb:e001:21:: does the mirror via p's e001 adjacency toward pe1.

  Crucially p carries NO IPv6 routes: the shifted DA is reachable only through
  the uALib adjacency cross-connect. If the shift-and-forward went by the FIB
  (as uN does) the packet would be dropped — so a successful ping proves the
  adjacency behavior specifically.

  Scenario: Steer customer v4 and v6 through an SRv6 uSID adjacency (uALib)
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
    And the cradle stat "srv6_usid" in namespace "p" via gRPC as "ctl2" should be nonzero
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
