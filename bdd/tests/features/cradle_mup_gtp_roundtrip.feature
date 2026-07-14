@serial
@cradle_mup_gtp_roundtrip
Feature: BGP MUP dataplane gtp forwards a real round-trip ping
  The free5GC-shaped sibling of @cradle_mup_gtp_zebra: one PFCP session whose
  Network Instance ("internet") matches BOTH MUP VRFs, carrying the UPF's own
  uplink receive F-TEID in the Access PDR's PDI local F-TEID (TS 29.244 CH=0,
  exactly how free5GC programs a UPF) — pfcp-inject's `--n3-endpoint/--n3-teid`.
  That single session fans out to the Type-1 (downlink) and Type-2 (uplink)
  ST routes, and this time the two directions close into a real ICMP round
  trip: the data network hangs off z1 on TWO legs, one per VRF, with the
  downlink leg carrying the DN's return route toward the UE prefix.

    - VRF Ndl (route st1, table 1): UE prefix 10.0.2.2 -> GTP4.E encap toward
      the gNB (endpoint 10.0.12.2, TEID 256, outer source 10.0.12.1). The DN
      routes 10.0.2.0/24 back through this leg (dnd -> z1dl).
    - VRF Nul (route st2, table 2): H.M.GTP4.D decap PDR on the CP-allocated
      (10.0.12.1, TEID 1280); decapped packets egress the uplink leg
      (z1ul -> dnu) via the VRF's connected route.

  The connected routes of z1dl/z1ul exist only because cradle's address
  monitor re-derives port routes when zebra-rs assigns the addresses AFTER
  the ports were attached — a round-trip ping is the organic proof (the
  older feature's counters pass without post-decap egress working).

  Real gNBs never send the minimal 8-byte GTP header the static gnb mirror
  emits, so two crafted uplink G-PDUs also cover the decap of the optional
  fields (flags 0x32, free-ran-ue) and of a PDU Session Container
  (flags 0x34, UERANSIM / TS 38.415).

  Topology (kernel v4 forwarding off on z1/gnb; GTP runs in eBPF):
  ```
   ue 10.0.2.2 ── gnb [cradle static mirror] ──N3 10.0.12.0/24── z1 [zebra-rs + cradle]
                                                                  │ dataplane gtp
                                                    (VRF Ndl) z1dl┤10.0.61.1 ── dnd 10.0.61.2 ─┐
                                                    (VRF Nul) z1ul┤10.0.60.1 ── dnu 10.0.60.2 ─┤ dn
                                                                       10.0.2.0/24 via 10.0.61.1
  ```

  NOTE: needs `pfcp-inject` (with `--n3-endpoint/--n3-teid`) on the BDD host
  PATH and a zebra-rs binary whose mup-c honors the CP-allocated PDI local
  F-TEID (via $ZEBRA / $ZEBRA_YANG). Root netns.

  Scenario: Build the topology and originate both ST routes from one session
    Given a clean test environment
    When I create namespace "z1"
    And I create namespace "gnb"
    And I create namespace "ue"
    And I create namespace "dn"
    And I connect namespace "z1" interface "z1n3" to namespace "gnb" interface "gn3"
    And I connect namespace "gnb" interface "gue" to namespace "ue" interface "eth0"
    And I connect namespace "z1" interface "z1dl" to namespace "dn" interface "dnd"
    And I connect namespace "z1" interface "z1ul" to namespace "dn" interface "dnu"
    And I execute "ip link set dev z1n3 address 02:00:00:00:00:01" in namespace "z1"
    And I execute "ip link set dev eth0 address 02:00:00:00:00:04" in namespace "ue"
    And I add address "10.0.12.2/24" to interface "gn3" in namespace "gnb"
    And I add address "10.0.2.1/24" to interface "gue" in namespace "gnb"
    And I add address "10.0.2.2/24" to interface "eth0" in namespace "ue"
    And I add address "10.0.61.2/24" to interface "dnd" in namespace "dn"
    And I add address "10.0.60.2/24" to interface "dnu" in namespace "dn"
    And I add route "default" via "10.0.2.1" in namespace "ue"
    And I add route "10.0.2.0/24" via "10.0.61.1" in namespace "dn"
    And I disable IPv4 forwarding in namespace "z1"
    And I disable IPv4 forwarding in namespace "gnb"
    # cradle attaches z1's ports BEFORE zebra-rs assigns their addresses and
    # VRFs — the address monitor must re-derive the VRF connected routes.
    And I start cradle in namespace "z1" with config "z1-ports.json" serving gRPC as "ctl1"
    And I start cradle in namespace "gnb" with config "gnb.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "z1" with config "z1.yaml" teeing to cradle as "ctl1"
    And I wait 10 seconds
    # ONE session, free5GC-shaped: NI "internet" matches both VRFs; the gNB
    # tunnel rides the Access FAR OHC and the UPF's own uplink receive
    # F-TEID rides the PDI local F-TEID (CP-allocated, TS 29.244 CH=0).
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.0.2.2 --endpoint 10.0.12.2 --teid 0x100 --n3-endpoint 10.0.12.1 --n3-teid 0x500 --network-instance internet" in namespace "z1"
    And I wait 5 seconds
    Then show command "show bgp vrf Ndl mup" in namespace "z1" should eventually contain "[ST1]"
    And show command "show bgp vrf Nul mup" in namespace "z1" should eventually contain "[ST2]"
    # The ST2 carries the CP-allocated tunnel, not a self-allocated one.
    And show command "show bgp vrf Nul mup" in namespace "z1" should eventually contain "teid=1280"

  Scenario: Uplink decap accepts real-gNB GTP headers (optional fields, PSC)
    Given the test topology exists
    # Seed the DN-side neighbors so decapped packets can egress.
    When I execute "ping -c 1 -W 1 10.0.60.1" in namespace "dn"
    And I execute "ping -c 1 -W 1 10.0.61.1" in namespace "dn"
    # free-ran-ue's shape: S flag, 12-byte header, no extension.
    And I send a GTP-U G-PDU flags "0x32" teid "0x500" carrying ICMP from "10.0.2.2" to "10.0.60.2" toward "10.0.12.1" in namespace "gnb"
    Then the cradle stat "gtp_decap" in namespace "z1" via gRPC as "ctl1" should reach 1
    # UERANSIM's shape: E flag + one PDU Session Container (QFI), 16 bytes.
    When I send a GTP-U G-PDU flags "0x34" teid "0x500" carrying ICMP from "10.0.2.2" to "10.0.60.2" toward "10.0.12.1" in namespace "gnb"
    Then the cradle stat "gtp_decap" in namespace "z1" via gRPC as "ctl1" should reach 2

  Scenario: Round trip — UE pings the data network through the GTP tunnel
    Given the test topology exists
    # Seed z1's ARP for the gNB so the teed neighbor feeds the GTP egress.
    When I execute "ping -c 1 -W 1 10.0.12.2" in namespace "z1"
    # ue -> gnb (GTP4.E, TEID 0x500) -> z1 XDP decap into VRF Nul -> dnu;
    # reply: dn -> dnd -> VRF Ndl UE route -> GTP4.E (TEID 0x100) -> gnb
    # decap -> ue. Both directions must work for a single echo to return.
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
