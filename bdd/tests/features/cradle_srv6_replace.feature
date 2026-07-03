@serial
@cradle_srv6_replace
Feature: SRv6 REPLACE-C-SID compression in the eBPF data plane
  As an operator running 32-bit compressed segment lists (RFC 9800 §4.2)
  I want End / End.X with REPLACE-C-SID executed in eBPF
  So that transit nodes rewrite only the C-SID bits of the destination
  address from packed containers in the SRH — one 128-bit list entry
  carries four 32-bit C-SIDs — instead of burning a full entry per hop.

  Geometry: block fdbb:bbbb:bbbb::/48 (LBL 48), C-SID = node(16)+fun(16)
  = 32 bits, so K = 4 positions per container and a 2-bit index rides in
  the DA's last bits. SIDs install at /80 (block + C-SID), leaving the
  argument wild. Kernel v4+v6 forwarding is off and seg6 never enabled
  on s/p/q/d — the pings only work if the eBPF REPLACE processing
  produced the right destinations, and each flavor op is pinned by its
  stat.

  Topology:
  ```
   c1 ── s[cradle] ─2001:db8:1::/64─ p[cradle] ─2001:db8:2::/64─ q[cradle] ─2001:db8:3::/64─ d[cradle] ── c2
   fc00:1::/64                                                                                fc00:2::/64
  ```
  p: End+REPLACE fdbb:bbbb:bbbb:1:: (node 1).
  q: End+REPLACE fdbb:bbbb:bbbb:2:: and End.X+REPLACE
     fdbb:bbbb:bbbb:2:e100:: (adjacency → d), both flavor PSP.
  d: End.DT46 fdbb:bbbb:bbbb:3:d46::, End+REPLACE+USP
     fdbb:bbbb:bbbb:3:: (SID+index also on d's lo), End+REPLACE+USD
     fdbb:bbbb:bbbb:3:dd::.

  Four flows from c1 (s H.Encaps.Red, containers as literal segs):
    * PSP:    [p, ::3:d46:2:0] — p advances into the container (index
      0→3), q consumes position 2 = d's DT46 C-SID; the next position
      is zero padding, so q pops the SRH (§4.2.8 composite condition);
      d decaps with the index residue still in the DA (argument
      ignored by DT*).
    * End.X:  [p, ::2:e100, d46-full] — at q's End.X the next position
      is zero mid-container (R06): the full 128-bit next entry becomes
      the DA wholesale, PSP pops, and the packet leaves via the
      cross-connect adjacency straight to d.
    * USP:    ping fdbb:bbbb:bbbb:3::3 (d's End SID with the walked
      index) — d hits the ultimate-segment condition (zero padding
      after the active position), pops the exhausted SRH, and the
      kernel answers the then-ordinary echo.
    * USD:    [p, ::3:dd] to c2's fc00:8::1 — at d the outer IPv6+SRH
      is decapsulated in one pass and the inner packet forwards in the
      main table.

  Scenario: REPLACE-C-SID containers steer four flows across p, q and d
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "p"
    And I create namespace "q"
    And I create namespace "d"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "p" interface "ps"
    And I connect namespace "p" interface "pq" to namespace "q" interface "qp"
    And I connect namespace "q" interface "qd" to namespace "d" interface "dq"
    And I connect namespace "d" interface "dc" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev ps address 02:00:00:00:0a:01" in namespace "p"
    And I execute "ip link set dev pq address 02:00:00:00:0b:01" in namespace "p"
    And I execute "ip link set dev qp address 02:00:00:00:0b:02" in namespace "q"
    And I execute "ip link set dev qd address 02:00:00:00:0c:01" in namespace "q"
    And I execute "ip link set dev dq address 02:00:00:00:0c:02" in namespace "d"
    And I execute "ip link set dev dc address 02:00:00:00:c2:ff" in namespace "d"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "2001:db8:1::2/64" to interface "ps" in namespace "p"
    And I add address "2001:db8:2::1/64" to interface "pq" in namespace "p"
    And I add address "2001:db8:2::2/64" to interface "qp" in namespace "q"
    And I add address "2001:db8:3::1/64" to interface "qd" in namespace "q"
    And I add address "2001:db8:3::2/64" to interface "dq" in namespace "d"
    And I add address "fc00:2::ff/64" to interface "dc" in namespace "d"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    # The USP target is d's End SID *with the index residue the walk
    # leaves in the argument bits* (…:3::3) — after the eBPF pop the
    # kernel answers the echo itself; its reply needs a route back.
    And I add address "fdbb:bbbb:bbbb:3::3/128" to interface "lo" in namespace "d"
    And I add route "fc00:1::/64" via "2001:db8:3::1" in namespace "d"
    # c2's loopbacks are the End.X and USD flows' inner destinations.
    And I make namespace "c2" interface "lo" up
    And I add address "fc00:9::1/128" to interface "lo" in namespace "c2"
    And I add address "fc00:8::1/128" to interface "lo" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "p"
    And I disable IPv4 forwarding in namespace "q"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "p"
    And I disable IPv6 forwarding in namespace "q"
    And I disable IPv6 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "p.json" serving gRPC as "ctl2"
    And I start cradle in namespace "q" with config "q.json" serving gRPC as "ctl3"
    And I start cradle in namespace "d" with config "d.json" serving gRPC as "ctl4"
    # Container walk: p advances into the packed container (index 0→3),
    # q consumes position 2 and pops (zero padding next). A wrong C-SID
    # rewrite anywhere yields an unroutable DA and the ping fails.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_replace" in namespace "p" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_replace" in namespace "q" via gRPC as "ctl3" should be nonzero
    And the cradle stat "srv6_psp" in namespace "q" via gRPC as "ctl3" should be nonzero
    # R06 + End.X: mid-container zero position loads the next full entry
    # as the DA and the packet exits q's cross-connect adjacency.
    Then ping from "c1" to "fc00:9::1" should eventually succeed
    # USP: without the pop, local delivery of an SL=0 SRH needs
    # seg6_enabled, which stays off — the ping only works popped.
    Then ping from "c1" to "fdbb:bbbb:bbbb:3::3" should eventually succeed
    And the cradle stat "srv6_usp" in namespace "d" via gRPC as "ctl4" should be nonzero
    # USD: d's kernel never sees the SRv6 encapsulation — the inner
    # packet forwards in the main table after the one-pass decap.
    Then ping from "c1" to "fc00:8::1" should eventually succeed
    And the cradle stat "srv6_usd" in namespace "d" via gRPC as "ctl4" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "s"
    And I stop cradle in namespace "p"
    And I stop cradle in namespace "q"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "p"
    And I delete namespace "q"
    And I delete namespace "d"
    And I delete namespace "c2"
    Then the test environment should be clean
