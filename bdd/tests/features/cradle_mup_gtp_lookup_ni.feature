@serial
@cradle_mup_gtp_lookup_ni
Feature: BGP MUP dataplane gtp with lookup-network-instance (the GTP-gateway shape)
  The stage-6 knob of zebra-rs
  docs/design/bgp-mup-gtp-segment-resolution-plan.md: ONE service VRF
  (`mobile`) binds both `route st1` and `route st2` — the single-N6 shape —
  while its `segment interwork` names a separate kernel VRF `N3` as the
  GTP-side routing context via `lookup-network-instance`. The named VRF
  needs NO `router bgp vrf` block of its own:

    - Uplink: the ST2's decap PDR is scoped to N3's table (the named
      context — where G-PDUs actually arrive), and its inner table is the
      service VRF's own (the fallback; no Direct-segment id needed when
      st1 and st2 share one VRF).
    - Downlink: the ST1's gNB endpoint falls inside the interwork prefix,
      so the outer (gw, oif) is NHT-resolved in N3's table — the table
      holding the gNB's connected route.

  This is the GTP-gateway variant of @cradle_mup_gtp_n3_vrf: same
  N3-in-a-kernel-VRF datapath, but the service VRF is not split in two.

  Topology (kernel v4 forwarding off on z1/gnb; GTP runs in eBPF):
  ```
   ue 10.0.2.2 ── gnb [cradle static mirror] ──N3 10.0.12.0/24── z1 [zebra-rs + cradle]
                                                (z1n3 in kernel VRF N3, table 1)
                                (VRF mobile, table 2) z1n6 ──10.0.60.1── dn6 10.0.60.2  dn
  ```

  NOTE: needs `pfcp-inject` on the BDD host PATH, a zebra-rs with
  `segment interwork lookup-network-instance` via $ZEBRA / $ZEBRA_YANG,
  and this cradle (VRF-scoped GTP_PDR + decap-metadata precedence).
  Root netns.

  Scenario: Build the topology and originate both STs from the one service VRF
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "gnb"
    And I create namespace "ue"
    And I create namespace "dn"
    And I connect namespace "z1" interface "z1n3" to namespace "gnb" interface "gn3"
    And I connect namespace "gnb" interface "gue" to namespace "ue" interface "eth0"
    And I connect namespace "z1" interface "z1n6" to namespace "dn" interface "dn6"
    And I execute "ip link set dev z1n3 address 02:00:00:00:00:01" in namespace "z1"
    And I execute "ip link set dev eth0 address 02:00:00:00:00:04" in namespace "ue"
    And I add address "10.0.12.2/24" to interface "gn3" in namespace "gnb"
    And I add address "10.0.2.1/24" to interface "gue" in namespace "gnb"
    And I add address "10.0.2.2/24" to interface "eth0" in namespace "ue"
    And I add address "10.0.60.2/24" to interface "dn6" in namespace "dn"
    And I add route "default" via "10.0.2.1" in namespace "ue"
    And I add route "10.0.2.0/24" via "10.0.60.1" in namespace "dn"
    And I disable IPv4 forwarding in namespace "z1"
    And I disable IPv4 forwarding in namespace "gnb"
    And I start cradle in namespace "z1" with config "z1-ports.json" serving gRPC as "ctl1"
    And I start cradle in namespace "gnb" with config "gnb.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "z1" with config "z1.yaml" teeing to cradle as "ctl1"
    And I wait 10 seconds
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.0.2.2 --endpoint 10.0.12.2 --teid 0x100 --n3-endpoint 10.0.12.1 --n3-teid 0x500 --network-instance internet" in namespace "z1"
    And I wait 5 seconds
    Then show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "[ST1]"
    And show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "[ST2]"
    And show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "teid=1280"
    And show command "show bgp mup" in namespace "z1" should contain "mobile: rd=65000:1 encap/ST1 ni=internet decap/ST2 ni=internet dataplane=gtp"

  Scenario: Round trip — UE pings the data network through the named N3 context
    Given the test topology exists
    # Seed z1's neighbors: the gNB inside the NAMED VRF N3 (feeds the GTP
    # encap adjacency via the tee), and the DN-side neighbor.
    When I execute "ping -c 1 -W 1 -I N3 10.0.12.2" in namespace "z1"
    And I execute "ping -c 1 -W 1 10.0.60.1" in namespace "dn"
    # ue -> gnb (GTP4.E, TEID 0x500) -> z1n3 (a table-1 port): the PDR was
    # installed for the NAMED context, matches, and decaps into the service
    # VRF's table -> dn6; reply: dn -> dn6 (table 2) -> UE /32 -> GTP4.E
    # toward the gNB resolved in N3's table -> gnb decap -> ue.
    Then ping from "ue" to "10.0.60.2" should eventually succeed
    And the cradle stat "gtp_encap" in namespace "z1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_decap" in namespace "z1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_encap" in namespace "gnb" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_decap" in namespace "gnb" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "z1"
    And I stop cradle in namespace "z1"
    And I stop cradle in namespace "gnb"
    And I delete namespace "z1"
    And I delete namespace "gnb"
    And I delete namespace "ue"
    And I delete namespace "dn"
    Then the test environment should be clean
