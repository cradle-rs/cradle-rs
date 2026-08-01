@serial
@cradle_mup_gtp6_zebra
Feature: BGP MUP dataplane gtp over an IPv6 N3 transport (GTP6)
  The v6-outer twin of @cradle_mup_gtp_single_n6: the N3 link is IPv6, so
  the PFCP session's tunnel endpoints are v6 addresses and the ST routes
  drive v6-outer GTP-U (GTP6.E encap / H.M.GTP6.D decap) through the
  cradle eBPF datapath. One VRF `mobile` binds both `route` directions;
  the UE and the data network stay IPv4 — the mixed-AFI case (v4 UE
  behind a v6 tunnel) the MUP codec was built for.

  Topology (kernel v4+v6 forwarding off on z1/gnb; GTP runs in eBPF):
  ```
   ue 10.0.2.2 ── gnb [cradle static mirror] ──N3 2001:db8:12::/64── z1 [zebra-rs + cradle]
                                                                      │ dataplane gtp
                                                  (VRF mobile) z1n6 ──┤10.0.60.1 ── dn6 10.0.60.2  dn
  ```

  NOTE: needs `pfcp-inject` on the BDD host PATH (its endpoint flags take
  any IP family), a zebra-rs with the family-wide GTP seam, and this
  cradle (GTP_PDR6 / GTP6_ENCAP). Root netns.

  Scenario: Build the topology and originate both STs over the v6 N3
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
    And I add address "2001:db8:12::2/64" to interface "gn3" in namespace "gnb"
    And I add address "10.0.2.1/24" to interface "gue" in namespace "gnb"
    And I add address "10.0.2.2/24" to interface "eth0" in namespace "ue"
    And I add address "10.0.60.2/24" to interface "dn6" in namespace "dn"
    And I add route "default" via "10.0.2.1" in namespace "ue"
    And I add route "10.0.2.0/24" via "10.0.60.1" in namespace "dn"
    And I disable IPv4 forwarding in namespace "z1"
    And I disable IPv4 forwarding in namespace "gnb"
    And I disable IPv6 forwarding in namespace "z1"
    And I disable IPv6 forwarding in namespace "gnb"
    And I start cradle in namespace "z1" with config "z1-ports.json" serving gRPC as "ctl1"
    And I start cradle in namespace "gnb" with config "gnb.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "z1" with config "z1.yaml" teeing to cradle as "ctl1"
    And I wait 10 seconds
    # ONE free5GC-shaped session with v6 tunnel endpoints: the gNB access
    # tunnel (2001:db8:12::2, TEID 0x100) and the UPF's own uplink receive
    # F-TEID (2001:db8:12::1, TEID 0x500) — the UE stays IPv4.
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.0.2.2 --endpoint 2001:db8:12::2 --teid 0x100 --n3-endpoint 2001:db8:12::1 --n3-teid 0x500 --network-instance internet" in namespace "z1"
    And I wait 5 seconds
    Then show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "[ST1]"
    And show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "[ST2]"
    And show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "ep=2001:db8:12::1"
    And show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "teid=1280"

  Scenario: Round trip — UE pings the data network through the v6 GTP tunnel
    Given the test topology exists
    # Seed z1's v6 neighbor for the gNB (feeds the GTP6.E adjacency via the
    # tee) and the DN-side v4 neighbor for decapped egress.
    When I execute "ping -c 1 -W 1 2001:db8:12::2" in namespace "z1"
    And I execute "ping -c 1 -W 1 10.0.60.1" in namespace "dn"
    # ue -> gnb (GTP6.E, TEID 0x500, v6 outer) -> z1n3 XDP v6 decap into
    # VRF mobile -> dn6; reply: dn -> dn6 -> UE /32 -> GTP6.E (TEID 0x100)
    # -> gnb v6 decap -> ue.
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
