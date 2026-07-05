@serial
@cradle_vpws_zebra
Feature: BGP EVPN VPWS over SRv6 programs the eBPF E-Line
  The full EVPN VPWS provider edge (RFC 8214), driven by zebra-rs and
  forwarded in eBPF: each PE's `vpws` service advertises an Ethernet A-D
  per-EVI route (Type-1) whose Ethernet Tag is its local service instance
  id, carrying an End.DX2 L2-Service Prefix-SID (RFC 9252 §6.3) carved
  from the BGP SRv6 locator. Importing the peer's Type-1 — matched by
  Ethernet Tag == remote-service-id within the shared EVI RT — drives one
  cradle AddXconnect that binds the E-Line both ways: the AC's ingress
  XCONNECT encap toward the remote SID, and the local End.DX2 decap that
  emits raw on the same AC. IS-IS SRv6 carries the locators; the underlay
  adjacency resolves in the datapath by a FIB6 lookup on the SID.

  No MAC learning, no FDB, no VNI: the E-Line is a transparent wire — the
  CEs share a subnet and ARP for each other straight through the service.

  Topology (kernel v4+v6 forwarding off on the PEs):
  ```
   c1 ── pe1[cradle+zebra] ──2001:db8:0:12::/64── pe2[cradle+zebra] ── c2
   10.0.0.1   LOC1 fcbb:bbbb:1::/48 | LOC2 fcbb:bbbb:2::/48    10.0.0.2
        vpws eline1: evi 100, pe1 svc-id 101 ⇄ pe2 svc-id 102
  ```

  Scenario: Cross-connect two CEs through a BGP-signalled SRv6 E-Line
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
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
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8::2" should be "Established"
    # The E-Line is transparent: ARP + ICMP ride the cross-connect, both
    # directions, with zero static state anywhere.
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "srv6_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_dx2" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_dx2" in namespace "pe2" via gRPC as "ctl2" should be nonzero

  Scenario: A VLAN-scoped E-Line multiplexes the same ACs by 802.1Q VID
    Given the test topology exists
    # eline2 (evi 200, VID 30) shares pe1c/pe2c with the untagged eline1:
    # the AC demuxes by tag — VID-30 frames ride the End.DX2V service (the
    # tag crossing transparently); untagged traffic still rides eline1.
    #
    # VLAN offloads must be OFF on the CE side of the AC: with them on,
    # the CE transmits the 802.1Q tag as skb *metadata* (never in the
    # packet bytes), and XDP — which sees only bytes — cannot demux the
    # VID. The standard operational requirement for any XDP VLAN path.
    When I execute "ethtool -K eth0 txvlan off rxvlan off" in namespace "c1"
    And I execute "ethtool -K eth0 txvlan off rxvlan off" in namespace "c2"
    And I execute "ip link add link eth0 name eth0.30 type vlan id 30" in namespace "c1"
    And I execute "ip addr add 10.0.30.1/24 dev eth0.30" in namespace "c1"
    And I execute "ip link set dev eth0.30 up" in namespace "c1"
    And I execute "ip link add link eth0 name eth0.30 type vlan id 30" in namespace "c2"
    And I execute "ip addr add 10.0.30.2/24 dev eth0.30" in namespace "c2"
    And I execute "ip link set dev eth0.30 up" in namespace "c2"
    Then ping from "c1" to "10.0.30.2" should eventually succeed
    And ping from "c2" to "10.0.30.1" should eventually succeed
    # The untagged E-Line still works alongside its VLAN-scoped twin.
    And ping from "c1" to "10.0.0.2" should eventually succeed

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
