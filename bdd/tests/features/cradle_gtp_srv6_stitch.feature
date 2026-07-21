@serial
@cradle_gtp_srv6_stitch
Feature: GTP-U / SRv6 stitch guards in the eBPF data plane
  As an operator running a mobile user plane next to SRv6 transport
  I want a packet decapsulated from one tunnel never re-imposed into the other
  So that a mis-routed inner destination cannot chain GTP-U and SRv6 tunnels.

  Topology (kernel v4+v6 forwarding off on pe1/pe2; both stitches are built
  deliberately and must be DROPPED by pe2, not forwarded):
  ```
   c1 ── pe1[cradle] ══ 10.0.12.0/24 + 2001:db8:12::/64 ══ pe2[cradle]
    10.0.1.1/24
  ```
  Flow A (GTP→SRv6): pe1 GTP-encaps c1's 10.0.2.0/24 traffic toward pe2
  (TEID 256, v4 outer). pe2's PDR decaps it into the global table, where
  10.0.2.0/24 resolves to an SRv6 nexthop — the H.Encaps re-imposition must
  be dropped (gtp_decap counts, srv6_encap stays zero on pe2).
  Flow B (SRv6→GTP): pe1 H.Encaps c1's 10.0.3.0/24 traffic toward pe2's
  End.DT4 SID fd00:2::100 (global table, vrf 0 — the marker must be attached
  even table-less). pe2 decaps; 10.0.3.0/24 resolves to a GTP nexthop — the
  GTP4.E re-imposition must be dropped (srv6_decap counts, gtp_encap stays
  zero on pe2).
  Flow C (GTP6→SRv6): as flow A over an IPv6 outer — pe1 GTP6.E-encaps
  10.0.4.0/24 toward pe2 (TEID 1024); pe2's v6 PDR (H.M.GTP6.D) decaps into
  the global table where 10.0.4.0/24 resolves to the SRv6 nexthop.
  Flow D (SRv6→GTP6): as flow B — pe2 decaps at the same End.DT4 SID, but
  10.0.5.0/24 resolves to a GTP6.E nexthop.

  gtp_encap/gtp_decap and srv6_encap/srv6_decap are shared between the v4
  and v6 variants, so the v6 flows attribute by threshold: a background ping
  is capped at 100 probes and a fail-probe loop at 30, so each v4 flow
  contributes at most ~130 to a counter — the same counter reaching 150
  after the v6 flow proves the v6 tunnel itself carried traffic.

  Scenario: Drop both directions of the GTP-U / SRv6 stitch
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1a"
    And I connect namespace "pe1" interface "pe1b" to namespace "pe2" interface "pe2a"
    And I execute "ip link set dev pe1b address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2a address 02:00:00:00:02:0a" in namespace "pe2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.254/24" to interface "pe1a" in namespace "pe1"
    And I add address "10.0.12.1/24" to interface "pe1b" in namespace "pe1"
    And I add address "2001:db8:12::1/64" to interface "pe1b" in namespace "pe1"
    And I add address "10.0.12.2/24" to interface "pe2a" in namespace "pe2"
    And I add address "2001:db8:12::2/64" to interface "pe2a" in namespace "pe2"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    # Flow A: GTP-decapped traffic must not be SRv6-encapped.
    Then ping from "c1" to "10.0.2.1" should fail
    When I start a background ping from "c1" to "10.0.2.1"
    Then the cradle stat "gtp_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "drop" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_encap" in namespace "pe2" via gRPC as "ctl2" should stay zero
    # Flow B: SRv6-decapped traffic must not be GTP-encapped.
    Then ping from "c1" to "10.0.3.1" should fail
    When I start a background ping from "c1" to "10.0.3.1"
    Then the cradle stat "srv6_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_encap" in namespace "pe2" via gRPC as "ctl2" should stay zero
    # Flow C: GTP6-decapped (v6 outer) traffic must not be SRv6-encapped.
    # gtp_encap/gtp_decap crossing 150 proves the v6 tunnel carried it (flow A
    # is capped at ~130).
    Then ping from "c1" to "10.0.4.1" should fail
    When I start a background ping from "c1" to "10.0.4.1"
    Then the cradle stat "gtp_encap" in namespace "pe1" via gRPC as "ctl1" should reach 150
    And the cradle stat "gtp_decap" in namespace "pe2" via gRPC as "ctl2" should reach 150
    And the cradle stat "srv6_encap" in namespace "pe2" via gRPC as "ctl2" should stay zero
    # Flow D: SRv6-decapped traffic must not be GTP6-encapped (v6 outer).
    Then ping from "c1" to "10.0.5.1" should fail
    When I start a background ping from "c1" to "10.0.5.1"
    Then the cradle stat "srv6_encap" in namespace "pe1" via gRPC as "ctl1" should reach 150
    And the cradle stat "srv6_decap" in namespace "pe2" via gRPC as "ctl2" should reach 150
    And the cradle stat "gtp_encap" in namespace "pe2" via gRPC as "ctl2" should stay zero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
