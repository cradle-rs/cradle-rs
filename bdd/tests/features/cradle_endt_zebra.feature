@serial
@cradle_endt_zebra
Feature: A zebra VRF-bound locator programs eBPF End.T through the tee
  As an operator scoping SRv6 node SIDs to VRF tables (RFC 8986 §4.3)
  I want the locator `vrf` leaf to become live eBPF End.T state
  So that the whole chain holds: yang `vrf` on the locator → RIB table
  resolution → IS-IS End.T SID install → FIB tee (behavior + table id)
  → eBPF USD decap + table-scoped forward.

  t's locator fd00:5::/64 is bound to vrf-t with `flavor: [usd]`. Its
  End.T SID installs into cradle with the VRF's table id; the
  c2-facing LAN lives IN vrf-t, so its connected route (teed from the
  VRF-attached interface) exists only in that table — t's main table
  has no route to c2 at all. The return path rides a second s↔t link
  whose t side is also in vrf-t, so nothing ever crosses tables.
  Kernel forwarding off on s/t, seg6 never enabled.

  Topology:
  ```
   c1 ── s[cradle] ══ t[zebra+cradle] ── c2
   fc00:1::/64   sp/ts (main): 2001:db8:1::/64
                 sr/tr (vrf-t): 2001:db8:3::/64
                 td (vrf-t): fc00:2::/64
  ```
  Flow: c1 → fc00:9::1 (c2's loopback, reached by a static VRF route
  teed into table 1). s pushes the single-SID reduced encap toward
  fd00:5:: (End.T+USD): t decapsulates the bare IPv6-in-IPv6 and
  forwards the inner packet in vrf-t's table — main would drop it.

  Scenario: The VRF-bound locator's End.T SID decapsulates into its table
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "t"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "t" interface "ts"
    And I connect namespace "s" interface "sr" to namespace "t" interface "tr"
    And I connect namespace "t" interface "td" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev ts address 02:00:00:00:0a:01" in namespace "t"
    And I execute "ip link set dev sr address 02:00:00:00:0a:02" in namespace "s"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "2001:db8:3::1/64" to interface "sr" in namespace "s"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I make namespace "c2" interface "lo" up
    And I add address "fc00:9::1/128" to interface "lo" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "t"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "t"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "t" with config "ports-t.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "t" with config "t.yaml" teeing to cradle as "ctl2"
    # The SID must exist as End.T (table resolved from vrf-t) before the
    # data-plane assertions mean anything.
    Then show command "show segment-routing srv6 sid" in namespace "t" should eventually contain "End.T"
    # USD decap + table-scoped forward: the static VRF route to c2's
    # loopback tees into table 1 only — t's main table has no path, so
    # the ping only works if the lookup ran in vrf-t.
    Then ping from "c1" to "fc00:9::1" should eventually succeed
    And the cradle stat "srv6_usd" in namespace "t" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_endt" in namespace "t" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "t"
    And I stop cradle in namespace "s"
    And I stop cradle in namespace "t"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "t"
    And I delete namespace "c2"
    Then the test environment should be clean
