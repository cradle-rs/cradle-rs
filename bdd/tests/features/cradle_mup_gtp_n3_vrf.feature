@serial
@cradle_mup_gtp_n3_vrf
Feature: BGP MUP dataplane gtp with the N3 port inside a kernel VRF
  The faithful interwork/direct split (zebra-rs
  docs/design/bgp-mup-gtp-segment-resolution-plan.md, stage 5): VRF N3 is
  the interwork segment (the GTP/N3 routing context — `segment interwork
  prefix 10.0.12.0/24` + `route st2 { mup-ext-comm 1:6 }`), VRF N6 the
  direct segment (`segment direct { mup-ext-comm 1:6 }` + `route st1`).
  Nothing about the forwarding is implicit any more:

    - Uplink: the ST2's decap PDR is installed with match context = N3's
      table (the holding VRF is an interwork segment), so the G-PDU only
      terminates on N3-bound ports; its inner table is N6's — resolved by
      the ST2's MUP Extended Community against the direct segment's
      Direct-segment id, not the binding VRF. The decapped packet then
      routes in table 2 although it arrived on a table-1 port (the
      decap-metadata precedence).
    - Downlink: the ST1's UE route lives in N6's table; its gNB endpoint
      (10.0.12.2) falls inside the interwork prefix, so the outer
      (gw, oif) is NHT-resolved in N3's table — the table that actually
      holds the gNB's connected route.

  This topology was impossible before: the PDR match was unscoped, the
  ingress port's VRF overrode the decap target, and the endpoint NHT was
  pinned to the global table.

  Topology (kernel v4 forwarding off on z1/gnb; GTP runs in eBPF):
  ```
   ue 10.0.2.2 ── gnb [cradle static mirror] ──N3 10.0.12.0/24── z1 [zebra-rs + cradle]
                                                     (z1n3 in kernel VRF N3, table 1)
                                          (VRF N6, table 2) z1n6 ──10.0.60.1── dn6 10.0.60.2  dn
  ```

  NOTE: needs `pfcp-inject` on the BDD host PATH, a zebra-rs with the
  segment-catalog resolution (stages 3-4) via $ZEBRA / $ZEBRA_YANG, and
  this cradle (VRF-scoped GTP_PDR + decap-metadata precedence). Root netns.

  Scenario: Build the topology and originate the STs from their own segments
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
    # cradle attaches z1's ports BEFORE zebra-rs assigns their addresses and
    # VRFs — the address monitor re-derives each VRF's connected route.
    And I start cradle in namespace "z1" with config "z1-ports.json" serving gRPC as "ctl1"
    And I start cradle in namespace "gnb" with config "gnb.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "z1" with config "z1.yaml" teeing to cradle as "ctl1"
    And I wait 10 seconds
    # ONE free5GC-shaped session, NI "internet": the st1 binding on N6 and
    # the st2 binding on N3 each pick it up — the ST1 originates under N6's
    # RD, the ST2 (with the Direct-segment id 1:6) under N3's.
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.0.2.2 --endpoint 10.0.12.2 --teid 0x100 --n3-endpoint 10.0.12.1 --n3-teid 0x500 --network-instance internet" in namespace "z1"
    And I wait 5 seconds
    Then show command "show bgp vrf N6 mup" in namespace "z1" should eventually contain "[ST1]"
    And show command "show bgp vrf N3 mup" in namespace "z1" should eventually contain "[ST2]"
    # The ST2 carries the CP-allocated tunnel and the Direct-segment id
    # that resolves its decap target to the N6 segment.
    And show command "show bgp vrf N3 mup" in namespace "z1" should eventually contain "teid=1280"
    And show command "show bgp vrf N3 mup" in namespace "z1" should eventually contain "mup:1:6"
    # Each VRF's binding renders under its own RD.
    And show command "show bgp mup" in namespace "z1" should contain "N3: rd=65000:3"
    And show command "show bgp mup" in namespace "z1" should contain "decap/ST2 ni=internet"
    And show command "show bgp mup" in namespace "z1" should contain "N6: rd=65000:6"
    And show command "show bgp mup" in namespace "z1" should contain "encap/ST1 ni=internet"

  Scenario: Round trip — UE pings the data network across the two segments
    Given the test topology exists
    # Seed z1's neighbors: the gNB inside VRF N3 (feeds the GTP encap
    # adjacency via the tee), and the DN-side neighbor for decapped egress.
    When I execute "ping -c 1 -W 1 -I N3 10.0.12.2" in namespace "z1"
    And I execute "ping -c 1 -W 1 10.0.60.1" in namespace "dn"
    # ue -> gnb (GTP4.E, TEID 0x500) -> z1n3 (a table-1 port): the PDR
    # matches in N3's context and decaps into N6's table -> dn6; reply:
    # dn -> dn6 (table 2) -> UE /32 -> GTP4.E toward the gNB resolved in
    # N3's table -> gnb decap -> ue.
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
