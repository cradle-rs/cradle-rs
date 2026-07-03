@serial
@cradle_replace_zebra
Feature: zebra-advertised REPLACE-C-SID SIDs drive the eBPF container walk
  As an operator running RFC 9800 REPLACE-C-SID compression
  I want zebra's locator config to become live eBPF endpoint state
  So that the whole chain holds: yang `behavior: replace` → IS-IS
  End-SID advertisement (REP codepoints + LB48/LN16/Fun16/Arg48
  structure) → FIB tee → cradle's C-SID rewrite and USD decap.

  s is a static cradle ingress — zebra has no source-side compression,
  so the packed container is expressed literally in its encap nexthop.
  r1 and r2 are zebra+cradle routers whose REPLACE locators share the
  block fdbb:bbbb:bbbb::/48; their End SIDs install into cradle via
  the tee at /80 (block + C-SID, argument wild). r2's locator carries
  `flavor: [usd]`, so its SID advertises as `End (REP, USD)` (IANA
  128) and the ultimate segment decapsulates in eBPF. Kernel v4+v6
  forwarding is off on s/r1/r2 and seg6 is never enabled — the ping
  only works if the eBPF REPLACE walk and USD decap both ran.

  Topology:
  ```
   c1 ── s[cradle] ─2001:db8:1::/64─ r1[zebra+cradle] ─2001:db8:2::/64─ r2[zebra+cradle] ── c2
   fc00:1::/64        LOC1 fdbb:bbbb:bbbb:1::/64 (replace)   LOC2 fdbb:bbbb:bbbb:2::/64 (replace, usd)   fc00:2::/64
  ```
  Flow c1→c2: s H.Encaps [r1-End, container(::2:0)]; r1 advances into
  the container (index 0→3, C-SID 0x00020000 → DA fdbb:bbbb:bbbb:2::3)
  and forwards on r2's IS-IS locator route; r2 hits the ultimate-
  segment condition (zero padding after position 3) and USD-decaps the
  inner packet onto its LAN. Returns ride plain IPv6 over static
  routes teed from zebra.

  Scenario: A REPLACE container programmed by zebra steers c1 to c2
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "r1"
    And I create namespace "r2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "r1" interface "r1-s"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I connect namespace "r2" interface "lan0" to namespace "c2" interface "eth0"
    # Only s's static neighbor entries need pinned MACs; everything on
    # the zebra side resolves through ND and the neighbor tee.
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev r1-s address 02:00:00:00:0a:01" in namespace "r1"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "r1"
    And I disable IPv4 forwarding in namespace "r2"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "r1"
    And I disable IPv6 forwarding in namespace "r2"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "r1" with config "ports-r1.json" serving gRPC as "ctl2"
    And I start cradle in namespace "r2" with config "ports-r2.json" serving gRPC as "ctl3"
    And I start zebra-rs in namespace "r1" with config "r1.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "r2" with config "r2.yaml" teeing to cradle as "ctl3"
    # Advertisement first: r2's flavored REPLACE codepoint must reach
    # r1's database before the data-plane assertions mean anything.
    Then show command "show isis database detail" in namespace "r1" should eventually contain "End (REP, USD)"
    # The container walk at r1 (tee-programmed EndRep at /80) rewrites
    # the C-SID; a wrong rewrite yields an unroutable DA and no ping.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_replace" in namespace "r1" via gRPC as "ctl2" should be nonzero
    # USD at the ultimate segment: r2's kernel (forwarding off, no
    # seg6) never sees the encapsulation.
    And the cradle stat "srv6_usd" in namespace "r2" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "r1"
    And I stop the zebra-rs tee in namespace "r2"
    And I stop cradle in namespace "s"
    And I stop cradle in namespace "r1"
    And I stop cradle in namespace "r2"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "r1"
    And I delete namespace "r2"
    And I delete namespace "c2"
    Then the test environment should be clean
