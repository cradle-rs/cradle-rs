@serial
@cradle_mup_gtp_single_n6
Feature: BGP MUP dataplane gtp with a SINGLE N6 leg (one dual-direction VRF)
  The single-N6 sibling of @cradle_mup_gtp_roundtrip (zebra-rs issue #1947):
  ONE VRF binds BOTH `route st1` and `route st2` to the session's Network
  Instance, so the UPF needs only ONE N6-facing interface — the telco-normal
  shape (uplink and downlink are directions of the same N6 network, not two
  legs). The one cradle VRF table holds the H.M.GTP4.D decap PDR (from the
  ST2), the UE-prefix GTP4.E encap route (from the ST1), AND the N6
  connected route together:

    - Downlink: dn -> dn6 -> z1n6 (VRF mobile, table 1) -> UE /32 encap
      route -> GTP4.E toward the gNB (endpoint 10.0.12.2, TEID 256, outer
      source 10.0.12.1) out z1n3.
    - Uplink: gnb GTP4.E (TEID 1280) -> z1n3 XDP decap PDR (CP-allocated
      10.0.12.1/0x500) -> inner lookup in table 1 -> connected 10.0.60.0/24
      -> egress z1n6. N3 stays in the GLOBAL VRF so the PDR's vrf_id governs
      the post-decap lookup.

  The PFCP session is free5GC-shaped (Access PDI local F-TEID, TS 29.244
  CH=0 via pfcp-inject `--n3-endpoint/--n3-teid`), and the round trip plus
  an iperf3 TCP run (the exact ask on issue #1947) prove both directions
  through the single leg. The UE link runs at MTU 1400 (like free5GC's UE
  TUN) so TCP MSS leaves room for the 36-byte GTP overhead on N3.

  Topology (kernel v4 forwarding off on z1/gnb; GTP runs in eBPF):
  ```
   ue 10.0.2.2 ── gnb [cradle static mirror] ──N3 10.0.12.0/24── z1 [zebra-rs + cradle]
                                                                  │ dataplane gtp
                                              (VRF mobile) z1n6 ──┤10.0.60.1 ── dn6 10.0.60.2  dn
                                                                       10.0.2.0/24 via 10.0.60.1
  ```

  NOTE: needs `pfcp-inject` (with `--n3-endpoint/--n3-teid`) and `iperf3`
  on the BDD host PATH, and a zebra-rs binary that supports a
  dual-direction `afi-safi mup route` binding (zebra-rs PR #2038) via
  $ZEBRA / $ZEBRA_YANG. Root netns.

  Scenario: Build the topology and originate both ST routes from the one VRF
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
    # MTU 1400 on the UE link (the free5GC UE TUN default): TCP MSS then
    # fits the +36-byte GTP overhead within the 1500-byte N3 links.
    And I execute "ip link set dev eth0 mtu 1400" in namespace "ue"
    And I add route "default" via "10.0.2.1" in namespace "ue"
    And I add route "10.0.2.0/24" via "10.0.60.1" in namespace "dn"
    And I disable IPv4 forwarding in namespace "z1"
    And I disable IPv4 forwarding in namespace "gnb"
    # cradle attaches z1's ports BEFORE zebra-rs assigns their addresses and
    # VRF — the address monitor must re-derive the VRF connected route.
    And I start cradle in namespace "z1" with config "z1-ports.json" serving gRPC as "ctl1"
    And I start cradle in namespace "gnb" with config "gnb.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "z1" with config "z1.yaml" teeing to cradle as "ctl1"
    And I wait 10 seconds
    # ONE session, free5GC-shaped: NI "internet" matches BOTH bindings of
    # the ONE VRF; the gNB tunnel rides the Access FAR OHC and the UPF's
    # own uplink receive F-TEID rides the PDI local F-TEID (CH=0).
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.0.2.2 --endpoint 10.0.12.2 --teid 0x100 --n3-endpoint 10.0.12.1 --n3-teid 0x500 --network-instance internet" in namespace "z1"
    And I wait 5 seconds
    # BOTH STs originate from the single VRF, under the one RD.
    Then show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "[ST1]"
    And show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "[ST2]"
    # The ST2 carries the CP-allocated tunnel, not a self-allocated one.
    And show command "show bgp vrf mobile mup" in namespace "z1" should eventually contain "teid=1280"
    # The MUP VRFs block confirms the dual binding on one line.
    And show command "show bgp mup" in namespace "z1" should contain "mobile: rd=65000:1 encap/ST1 ni=internet decap/ST2 ni=internet dataplane=gtp"

  Scenario: Round trip — UE pings the data network through the single N6 leg
    Given the test topology exists
    # Seed z1's ARP for the gNB so the teed neighbor feeds the GTP egress,
    # and the DN-side neighbor so decapped packets can egress z1n6.
    When I execute "ping -c 1 -W 1 10.0.12.2" in namespace "z1"
    And I execute "ping -c 1 -W 1 10.0.60.1" in namespace "dn"
    # ue -> gnb (GTP4.E, TEID 0x500) -> z1 XDP decap into VRF mobile -> dn6;
    # reply: dn -> dn6 -> the SAME VRF's UE route -> GTP4.E (TEID 0x100) ->
    # gnb decap -> ue. One leg, both directions.
    Then ping from "ue" to "10.0.60.2" should eventually succeed
    And the cradle stat "gtp_encap" in namespace "z1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_decap" in namespace "z1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_encap" in namespace "gnb" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_decap" in namespace "gnb" via gRPC as "ctl2" should be nonzero

  Scenario: Throughput — iperf3 from the UE to a server on the N6 side
    Given the test topology exists
    # The one-shot daemonized server exits after serving the client — no
    # process leaks into teardown. The client step asserts its exit status:
    # a failed TCP connect or mid-test stall fails the scenario.
    When I execute "iperf3 -s -D -1" in namespace "dn"
    And I wait 2 seconds
    And I execute "iperf3 -c 10.0.60.2 -t 2 -f m" in namespace "ue"
    # A 2s TCP run pushes far more than 100 packets each way through the
    # tunnel: both the encap (downlink ACK/data toward the UE) and decap
    # (uplink data) counters must have moved well past the ping counts.
    Then the cradle stat "gtp_decap" in namespace "z1" via gRPC as "ctl1" should reach 100
    And the cradle stat "gtp_encap" in namespace "z1" via gRPC as "ctl1" should reach 100

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
