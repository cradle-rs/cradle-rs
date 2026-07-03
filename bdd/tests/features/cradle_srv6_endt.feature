@serial
@cradle_srv6_endt
Feature: SRv6 End.T table-scoped forwarding in the eBPF data plane
  As an operator running multi-table SRv6 cores (RFC 8986 §4.3)
  I want End.T executed in eBPF
  So that the End walk's egress lookup happens in the SID's own IPv6
  table instead of main — S15.1's "set the packet's associated FIB
  table to T", carried from XDP to the TC forward stage as VRF
  metadata, exactly like the DT decap path.

  The assertion teeth: t's MAIN table has no route toward d at all —
  both flows only reach c2 if the lookup really ran in table 100.
  Kernel v4+v6 forwarding off and seg6 never enabled on s/t/d; the
  flavor composites are pinned by their stats.

  Topology:
  ```
   c1 ── s[cradle] ─2001:db8:1::/64─ t[cradle] ─2001:db8:2::/64─ d[cradle] ── c2
   fc00:1::/64                (End.T, table 100)                  fc00:2::/64
  ```
  t: End.T+PSP fd00:5::7 and End.T+USD fd00:5::8, both table 100.
  Table 100 holds the only routes toward d's DT46 and c2's loopback.

  Two flows from c1:
    * fc00:2::1 — s H.Encaps [End.T+PSP, d-DT46]: t's walk exhausts
      the SRH (pop) and the rewritten DA is looked up in table 100.
    * fc00:9::1 — s pushes the single-SID reduced form straight to
      End.T+USD: t decapsulates the bare IPv6-in-IPv6 and forwards
      the inner packet in table 100 (§4.16.3 on End.T).

  Scenario: End.T forwards in its own table, composing with PSP and USD
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "t"
    And I create namespace "d"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "t" interface "ts"
    And I connect namespace "t" interface "td" to namespace "d" interface "dt"
    And I connect namespace "d" interface "dc" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev ts address 02:00:00:00:0a:01" in namespace "t"
    And I execute "ip link set dev td address 02:00:00:00:0b:01" in namespace "t"
    And I execute "ip link set dev dt address 02:00:00:00:0b:02" in namespace "d"
    And I execute "ip link set dev dc address 02:00:00:00:c2:ff" in namespace "d"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "2001:db8:1::2/64" to interface "ts" in namespace "t"
    And I add address "2001:db8:2::1/64" to interface "td" in namespace "t"
    And I add address "2001:db8:2::2/64" to interface "dt" in namespace "d"
    And I add address "fc00:2::ff/64" to interface "dc" in namespace "d"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I make namespace "c2" interface "lo" up
    And I add address "fc00:9::1/128" to interface "lo" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "t"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "t"
    And I disable IPv6 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "t" with config "t.json" serving gRPC as "ctl2"
    And I start cradle in namespace "d" with config "d.json" serving gRPC as "ctl3"
    # End.T + PSP: the popped, rewritten packet only routes in table 100.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_endt" in namespace "t" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_psp" in namespace "t" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_decap" in namespace "d" via gRPC as "ctl3" should be nonzero
    # End.T + USD on a bare (no-SRH) arrival: decap, then table 100.
    Then ping from "c1" to "fc00:9::1" should eventually succeed
    And the cradle stat "srv6_usd" in namespace "t" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "s"
    And I stop cradle in namespace "t"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "t"
    And I delete namespace "d"
    And I delete namespace "c2"
    Then the test environment should be clean
