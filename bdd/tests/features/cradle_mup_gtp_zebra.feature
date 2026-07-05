@serial
@cradle_mup_gtp_zebra
Feature: BGP MUP dataplane gtp programs a real GTP-U tunnel into cradle
  A standalone zebra-rs MUP UPF anchor (z1) whose `afi-safi mup dataplane gtp`
  drives cradle over gRPC — no SRv6, no kernel GTP. Two PFCP sessions (one per
  Network Instance) make z1 originate its own Type-1 (downlink) and Type-2
  (uplink) Session-Transformed routes, which best-path locally and reconcile
  into cradle:
    - VRF Ndl (route st1): a UE-prefix (10.0.2.2) -> GTP4.E encap toward the
      gNB (endpoint 10.0.12.2, TEID 256, outer source = the UPF anchor
      10.0.12.1).
    - VRF Nul (route st2): an H.M.GTP4.D decap PDR on (10.0.12.1, TEID 512)
      that forwards the inner packet into VRF Nul.
  A static-config cradle node (gnb) mirrors the tunnel: it decaps z1's downlink
  (PDR 10.0.12.2/256) toward the UE and encaps the uplink (TEID 512) toward z1.

  Because a MUP VRF binds a single direction, the two directions use separate
  core hosts (cdl in VRF Ndl, cul in VRF Nul) and are verified one-way by the
  eBPF GTP counters on both ends of each tunnel — gtp_encap on the imposing
  node and gtp_decap on the terminating node, which together prove the full
  datapath end to end.

  Topology (kernel v4 forwarding off on z1/gnb; GTP runs in eBPF):
  ```
   cdl ─┐(VRF Ndl)                            ┌─ ue 10.0.2.2
   10.0.1.2   z1 [zebra-rs + cradle] ──N3──  gnb [cradle]
   cul ─┘(VRF Nul)   dataplane gtp   10.0.12.0/24   (static mirror)
   10.0.3.2
  ```

  NOTE: needs `pfcp-inject` on the BDD host PATH and a zebra-rs binary with the
  MUP `dataplane gtp` datapath (via $ZEBRA / $ZEBRA_YANG). Root netns.

  Scenario: Build the topology and originate the MUP GTP tunnels
    Given a clean test environment
    When I create namespace "cdl"
    And I create namespace "cul"
    And I create namespace "z1"
    And I create namespace "gnb"
    And I create namespace "ue"
    And I connect namespace "cdl" interface "eth0" to namespace "z1" interface "z1cdl"
    And I connect namespace "cul" interface "eth0" to namespace "z1" interface "z1cul"
    And I connect namespace "z1" interface "z1n3" to namespace "gnb" interface "gn3"
    And I connect namespace "gnb" interface "gue" to namespace "ue" interface "eth0"
    And I execute "ip link set dev z1n3 address 02:00:00:00:00:01" in namespace "z1"
    And I execute "ip link set dev eth0 address 02:00:00:00:00:04" in namespace "ue"
    And I add address "10.0.1.2/24" to interface "eth0" in namespace "cdl"
    And I add address "10.0.3.2/24" to interface "eth0" in namespace "cul"
    And I add address "10.0.12.2/24" to interface "gn3" in namespace "gnb"
    And I add address "10.0.2.1/24" to interface "gue" in namespace "gnb"
    And I add address "10.0.2.2/24" to interface "eth0" in namespace "ue"
    And I add route "default" via "10.0.1.1" in namespace "cdl"
    And I add route "default" via "10.0.3.1" in namespace "cul"
    And I add route "default" via "10.0.2.1" in namespace "ue"
    And I disable IPv4 forwarding in namespace "z1"
    And I disable IPv4 forwarding in namespace "gnb"
    And I start cradle in namespace "z1" with config "z1-ports.json" serving gRPC as "ctl1"
    And I start cradle in namespace "gnb" with config "gnb.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "z1" with config "z1.yaml" teeing to cradle as "ctl1"
    And I wait 10 seconds
    # Two PFCP sessions: NI `ndl` -> the st1 (downlink) VRF, NI `nul` -> the st2
    # (uplink) VRF. `--core-endpoint` carries the UPF anchor (10.0.12.1): the
    # ST1 outer source and the ST2 decap endpoint.
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.0.2.2 --endpoint 10.0.12.2 --teid 0x100 --core-endpoint 10.0.12.1 --core-teid 0x200 --network-instance ndl" in namespace "z1"
    And I execute "pfcp-inject --target 127.0.0.1 --port 8805 --ue-ipv4 10.0.2.2 --endpoint 10.0.12.2 --teid 0x100 --core-endpoint 10.0.12.1 --core-teid 0x200 --network-instance nul" in namespace "z1"
    And I wait 5 seconds
    Then show command "show bgp vrf Ndl mup" in namespace "z1" should eventually contain "[ST1]"
    And show command "show bgp vrf Nul mup" in namespace "z1" should eventually contain "[ST2]"

  Scenario: Downlink — z1 GTP4.E-encaps toward the gNB, which decaps to the UE
    Given the test topology exists
    # Seed z1's ARP for the gNB so the teed neighbor feeds the GTP egress.
    When I execute "ping -c 1 -W 1 10.0.12.2" in namespace "z1"
    # Drive customer -> UE traffic; the reply can't return (the UE's core host
    # is in the other VRF), so the ping "fails" one-way — the GTP counters on
    # both ends of the tunnel are the real proof.
    Then ping from "cdl" to "10.0.2.2" should fail
    And the cradle stat "gtp_encap" in namespace "z1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_decap" in namespace "gnb" via gRPC as "ctl2" should be nonzero

  Scenario: Uplink — the gNB GTP-encaps toward z1, whose PDR decaps into VRF Nul
    Given the test topology exists
    # Seed z1's ARP for the uplink core host so the decapped packet can egress.
    When I execute "ping -c 1 -W 1 10.0.3.1" in namespace "cul"
    # Drive UE -> core traffic; one-way, proven by the GTP counters.
    Then ping from "ue" to "10.0.3.2" should fail
    And the cradle stat "gtp_encap" in namespace "gnb" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_decap" in namespace "z1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "z1"
    And I stop cradle in namespace "z1"
    And I stop cradle in namespace "gnb"
    And I delete namespace "cdl"
    And I delete namespace "cul"
    And I delete namespace "z1"
    And I delete namespace "gnb"
    And I delete namespace "ue"
    Then the test environment should be clean
