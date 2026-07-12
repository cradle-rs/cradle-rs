@serial
@cradle_evpn_vxlan_zebra
Feature: BGP EVPN over VXLAN programs the eBPF L2 data plane
  The full EVPN-over-VXLAN provider edge, driven by zebra-rs and forwarded in
  eBPF: iBGP L2VPN-EVPN (default VXLAN encapsulation) advertises each PE's
  VTEP as the nexthop on every Type-2 (MAC/IP) route and the Type-3 IMET.
  The FibHandle tee installs it all into cradle — the VNI binding + local
  VTEP source when the VXLAN device appears (SetVni/SetVtepSource), remote
  MACs as VXLAN overlay FDB entries (Type-2 → mac@remote-VTEP), and each
  peer VTEP as a BUM replication slot (Type-3 → remote VTEP). cradle owns
  the whole datapath; the kernel VXLAN device is only zebra's VNI
  declaration.

  Topology (kernel v4+v6 forwarding off on pe1/pe2; VTEPs are loopback
  addresses reached over the directly-connected underlay by a static /32
  route, so the cradle datapath resolves each remote VTEP to a real
  underlay nexthop):
  ```
   c1 ── pe1[cradle+zebra] ──10.0.12.0/24── pe2[cradle+zebra] ── c2
    bd 100 / VNI 100      VTEP 192.0.2.1 | 192.0.2.2       bd 100 / VNI 100
   10.0.0.1                                                10.0.0.2
  ```
  Local CE MACs flow UP from the datapath: cradle's XDP stage learns the CE
  source MAC and streams it to zebra over the WatchFdb gRPC channel; zebra
  originates the Type-2 with the local VTEP as nexthop. Fully dynamic — no
  static ARP, no static cradle FDB: c1's first ARP rides the tee-installed
  BUM replication slot (unknown unicast floods over the overlay too, so the
  exchange completes before BGP converges), the learned MACs become Type-2
  routes within a poll interval, and traffic flips to the tee-installed
  unicast VXLAN FDB entries. The remote VTEP resolves in the datapath by a
  FIB4 lookup on the VTEP (the static route, itself teed).

  Scenario: Bridge two CEs across a BGP-EVPN-over-VXLAN eBPF data plane
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
    Then BGP session in "pe1" to "192.0.2.2" should be "Established"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "vxlan_flood" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero

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
