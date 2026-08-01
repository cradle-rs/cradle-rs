@serial
@cradle_evpn_vxlan6_zebra
Feature: BGP EVPN over IPv6-underlay VXLAN programs the eBPF L2 data plane
  The full EVPN-over-VXLAN provider edge on an IPv6-only underlay, driven
  by zebra-rs and forwarded in eBPF — the v6 twin of
  cradle_evpn_vxlan_zebra: iBGP L2VPN-EVPN advertises each PE's IPv6 VTEP
  (the vxlan device's v6 local-address) as the nexthop on every Type-2 and
  the Type-3 IMET. The FibHandle tee installs it all into cradle — the VNI
  binding + local v6 VTEP source when the device appears
  (SetVni/SetVtepSource with the v6 slot), remote MACs as overlay FDB
  entries carrying the VTEP native (not v4-mapped), and each peer VTEP as
  a BUM replication slot. Encap resolves each VTEP by a FIB6 lookup on the
  teed static /128; the outer header is Ethernet + IPv6 + UDP 4789.

  Topology (kernel v4+v6 forwarding off on pe1/pe2; VTEPs are loopback v6
  addresses reached over the directly-connected underlay by a static /128):
  ```
   c1 ── pe1[cradle+zebra] ──2001:db8:12::/64── pe2[cradle+zebra] ── c2
    bd 100 / VNI 100    VTEP 2001:db8:ff::1 | ::2        bd 100 / VNI 100
   10.0.0.1                                              10.0.0.2
  ```
  Fully dynamic, exactly like the v4 twin: no static ARP, no static cradle
  state — c1's first ARP floods over the tee-installed replication slot,
  cradle streams the learned MACs up over WatchFdb, zebra originates the
  Type-2s with the v6 VTEP nexthop, and traffic flips to unicast FDB
  entries.

  Scenario: Bridge two CEs across a BGP-EVPN eBPF data plane on a v6 underlay
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:02" in namespace "c2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I wait 3 seconds
    # zebra's VNI declaration: enslave the zebra-created vxlan100 to a bridge
    # so the bridge↔VNI mapping exists. No FDB entries — local CE MACs are
    # learned by the cradle datapath and stream up over WatchFdb.
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8:ff::2" should be "Established"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "vxlan_flood" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The remote MAC's overlay slot carries the v6 VTEP native — the proof
    # this ran the IPv6 underlay, not a v4-mapped one.
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "2001:db8:ff::2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
