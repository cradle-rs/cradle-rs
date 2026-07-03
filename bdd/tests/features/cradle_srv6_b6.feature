@serial
@cradle_srv6_b6
Feature: SRv6 End.B6.Encaps Binding SID in the eBPF data plane
  As an operator running SR Policies behind Binding SIDs (RFC 8986 §4.13)
  I want End.B6.Encaps executed in eBPF
  So that a packet steered onto a BSID first advances its own segment
  list (the End walk) and is then encapsulated onto the bound policy's
  segment list — the upstream domain sees one opaque SID where the
  policy detour happens.

  The pushed encapsulation is the Reduced form (§4.14): a single-SID
  policy pushes an outer IPv6 only (no SRH), a multi-SID policy rides
  its first SID in the outer DA. Kernel v4+v6 forwarding is off and
  seg6 never enabled on s/b/t/e/d — the pings only work if the eBPF
  binding, transit walk and USD decap all ran; each is pinned by its
  stat.

  Topology:
  ```
   c1 ── s[cradle] ── b[cradle] ── t[cradle] ── e[cradle] ── d[cradle] ── c2
   fc00:1::/64   db8:1::/64  db8:2::/64  db8:3::/64  db8:4::/64   fc00:2::/64
  ```
  b (binding node): BSID fd00:b::61 → policy [e-USD] (single SID);
  BSID fd00:b::62 → policy [t-End, e-USD] (SRH pushed).
  t: End fd00:5::e — walks the *pushed* SRH. e: End+USD fd00:e::e1 —
  decapsulates the policy encap, exposing the steered packet. d:
  End.DT46 fd00:d::46 — the service egress for the inner list.

  Two flows from c1 (s H.Encaps.Red [BSID, d-DT46]):
    * fc00:2::1 via BSID1 — at b the End walk sets the inner DA to
      d's DT46, then the outer-only push sends it to e; USD exposes
      the steered packet mid-path and it continues natively to d.
    * fc00:9::1 via BSID2 — same, but the pushed policy carries an
      SRH: t's End walk serves the *outer* list before e's USD.

  Scenario: Binding SIDs encapsulate onto single- and multi-SID policies
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "b"
    And I create namespace "t"
    And I create namespace "e"
    And I create namespace "d"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "b" interface "bs"
    And I connect namespace "b" interface "bt" to namespace "t" interface "tb"
    And I connect namespace "t" interface "te" to namespace "e" interface "et"
    And I connect namespace "e" interface "ed" to namespace "d" interface "de"
    And I connect namespace "d" interface "dc" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev bs address 02:00:00:00:0a:01" in namespace "b"
    And I execute "ip link set dev bt address 02:00:00:00:0b:01" in namespace "b"
    And I execute "ip link set dev tb address 02:00:00:00:0b:02" in namespace "t"
    And I execute "ip link set dev te address 02:00:00:00:0c:01" in namespace "t"
    And I execute "ip link set dev et address 02:00:00:00:0c:02" in namespace "e"
    And I execute "ip link set dev ed address 02:00:00:00:0d:01" in namespace "e"
    And I execute "ip link set dev de address 02:00:00:00:0d:02" in namespace "d"
    And I execute "ip link set dev dc address 02:00:00:00:c2:ff" in namespace "d"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "2001:db8:1::2/64" to interface "bs" in namespace "b"
    And I add address "2001:db8:2::1/64" to interface "bt" in namespace "b"
    And I add address "2001:db8:2::2/64" to interface "tb" in namespace "t"
    And I add address "2001:db8:3::1/64" to interface "te" in namespace "t"
    And I add address "2001:db8:3::2/64" to interface "et" in namespace "e"
    And I add address "2001:db8:4::1/64" to interface "ed" in namespace "e"
    And I add address "2001:db8:4::2/64" to interface "de" in namespace "d"
    And I add address "fc00:2::ff/64" to interface "dc" in namespace "d"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I make namespace "c2" interface "lo" up
    And I add address "fc00:9::1/128" to interface "lo" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "b"
    And I disable IPv4 forwarding in namespace "t"
    And I disable IPv4 forwarding in namespace "e"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "b"
    And I disable IPv6 forwarding in namespace "t"
    And I disable IPv6 forwarding in namespace "e"
    And I disable IPv6 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "b" with config "b.json" serving gRPC as "ctl2"
    And I start cradle in namespace "t" with config "t.json" serving gRPC as "ctl3"
    And I start cradle in namespace "e" with config "e.json" serving gRPC as "ctl4"
    And I start cradle in namespace "d" with config "d.json" serving gRPC as "ctl5"
    # Single-SID policy: outer IPv6 only (no SRH). The binding at b is
    # pinned by its stat; the USD decap at e proves the pushed outer
    # carried the policy (e's kernel would drop an unbound packet).
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_b6" in namespace "b" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_usd" in namespace "e" via gRPC as "ctl4" should be nonzero
    And the cradle stat "srv6_decap" in namespace "d" via gRPC as "ctl5" should be nonzero
    # Multi-SID policy: the pushed Reduced SRH routes through t's End
    # walk before e's USD — srv6_end at t only counts if the SRH the
    # binding node built is well-formed.
    Then ping from "c1" to "fc00:9::1" should eventually succeed
    And the cradle stat "srv6_end" in namespace "t" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "s"
    And I stop cradle in namespace "b"
    And I stop cradle in namespace "t"
    And I stop cradle in namespace "e"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "b"
    And I delete namespace "t"
    And I delete namespace "e"
    And I delete namespace "d"
    And I delete namespace "c2"
    Then the test environment should be clean
