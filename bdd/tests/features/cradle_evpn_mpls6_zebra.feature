@serial
@cradle_evpn_mpls6_zebra
Feature: BGP EVPN over MPLS between IPv6 PEs programs the eBPF L2 data plane
  The EVPN-over-MPLS provider edge on an IPv6-numbered core, driven by
  zebra-rs and forwarded in eBPF — the v6 twin of cradle_evpn_mpls_zebra.
  RFC 7432's encapsulation imposes no outer IP header, so the PEs'
  address family lives only in the control plane and the adjacency: the
  Type-2/Type-3 next hops are the PEs' v6 loopbacks (named by the new
  `vtep-source` leaf — the router-id fallback can only express IPv4),
  the tee installs remote MACs against the far PE natively in the
  16-byte slot, and the datapath resolves the service-label imposition
  by a FIB6 /128 lookup on the PE. Direct PE-PE link: the service label
  rides alone (a labeled v6 transport hop is cradle_evpn_mpls6's, the
  static engine twin).

  Topology (kernel v4+v6 forwarding off and kernel MPLS untouched on the
  PEs, so a successful ping proves the eBPF stage did the label work):
  ```
   c1 ── pe1[zebra+cradle] ──2001:db8:12::/64── pe2[zebra+cradle] ── c2
    bd 100 / evi 100   lo 2001:db8:255::1 | ::2    bd 100 / evi 100
   10.0.0.1                                        10.0.0.2
  ```
  Fully dynamic: no static ARP, no static cradle state, no static labels
  — the per-EVI service labels come from the dynamic block, c1's first
  ARP floods over the tee-installed replication slot, cradle streams the
  learned MACs up over WatchFdb and they become Type-2s with v6 next
  hops.

  Scenario: Bridge two CEs across a BGP-EVPN-over-MPLS core with v6 PEs
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
    # The EVI names a bridge; create it so the EVI-to-bridge-domain pin has
    # something to bind. The CE ports are cradle's, not the bridge's.
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
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
    Then BGP session in "pe1" to "2001:db8:255::2" should be "Established"
    # The EVI took a service label and programmed its bridge-domain decap.
    And show command "show mpls ilm" in namespace "pe1" should eventually contain "EVPN Decap (bd 100"
    And show command "show mpls ilm" in namespace "pe2" should eventually contain "EVPN Decap (bd 100"
    # Each PE learned the other's IMET: a label (not a VNI), rooted at the
    # far PE's v6 loopback.
    And show command "show bgp evpn" in namespace "pe1" should eventually contain "ingress-replication endpoint:2001:db8:255::2 label:"
    And show command "show bgp evpn" in namespace "pe2" should eventually contain "ingress-replication endpoint:2001:db8:255::1 label:"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    # BUM proves the Type-3 became a replication slot; encap/decap prove the
    # Type-2 loop closed (XDP learn -> WatchFdb -> Type-2 -> remote tee).
    And the cradle stat "mpls_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The remote MAC's overlay slot carries the PE's v6 address native.
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "2001:db8:255::2"

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
