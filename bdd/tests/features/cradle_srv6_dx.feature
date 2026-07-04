@serial
@cradle_srv6_dx
Feature: SRv6 End.DX4 / End.DX6 cross-connect decap in the eBPF data plane
  As an operator running per-CE L3VPN egress (RFC 8986 §4.4 / §4.5)
  I want End.DX4 and End.DX6 executed in eBPF
  So that the egress PE decapsulates and hands the inner packet straight
  to the CE adjacency — no tenant-table (or any) FIB lookup, the
  SRv6 equivalent of the per-CE VPN label.

  The assertion teeth are intrinsic: d has NO forward routes at all
  (v4 or v6) toward c2 — only the DX SIDs' cross-connect adjacency.
  If the decap fell back to a FIB lookup the packets would die. Kernel
  v4+v6 forwarding off and seg6 never enabled on s/d. The uDX6 form
  is the same SID matched at block+node+function — the carrier's last
  micro-SID, like uDT46.

  Topology:
  ```
   c1 ── s[cradle] ─2001:db8:1::/64─ d[cradle] ── c2
   fc00:1::/64                                    fc00:2::/64
   10.0.1.0/24                                    10.0.2.0/24
  ```
  d: End.DX6 fd00:d::64 → v6 adjacency to c2; End.DX4 fd00:d::4 → v4
  adjacency to c2; uDX6 fcbb:bbbb:d:d66::/64 (block 32 / node 16 /
  fun 16) → the same v6 adjacency.

  Three flows from c1:
    * fc00:2::1  via [End.DX6] — v6-in-v6, cross-connected.
    * 10.0.2.1   via [End.DX4] — v4-in-v6, cross-connected.
    * fc00:9::1  via [uDX6]    — matched at the micro-SID tail.

  Scenario: DX SIDs cross-connect decapped packets to the CE adjacency
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "d"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "d" interface "ds"
    And I connect namespace "d" interface "dc" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev ds address 02:00:00:00:0a:01" in namespace "d"
    And I execute "ip link set dev dc address 02:00:00:00:c2:ff" in namespace "d"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "10.0.1.254/24" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "2001:db8:1::2/64" to interface "ds" in namespace "d"
    And I add address "fc00:2::ff/64" to interface "dc" in namespace "d"
    And I add address "10.0.2.254/24" to interface "dc" in namespace "d"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I make namespace "c2" interface "lo" up
    And I add address "fc00:9::1/128" to interface "lo" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "0.0.0.0/0" via "10.0.1.254" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I add route "0.0.0.0/0" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "d" with config "d.json" serving gRPC as "ctl2"
    # End.DX6: v6-in-v6, decap + straight to the adjacency.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_dx" in namespace "d" via gRPC as "ctl2" should be nonzero
    # End.DX4: v4-in-v6 — the dual-family per-CE egress.
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    # uDX6: the same behavior matched at the carrier's last micro-SID.
    Then ping from "c1" to "fc00:9::1" should eventually succeed
    And the cradle stat "srv6_encap" in namespace "s" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "s"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "d"
    And I delete namespace "c2"
    Then the test environment should be clean
