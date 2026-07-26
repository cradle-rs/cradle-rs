@serial
@cradle_evpn_mpls_zebra
Feature: BGP EVPN over MPLS programs the eBPF L2 data plane
  The full EVPN-over-MPLS provider edge, driven by zebra-rs and forwarded in
  eBPF — RFC 7432's original encapsulation, and the one the Linux kernel
  cannot forward at all: no kernel action pops an MPLS label and hands the
  exposed Ethernet frame to a bridge. cradle is the only data plane for it,
  which makes this feature the whole thesis of the integration in one test.

  Three layers have to compose, each from a different protocol:
    - IS-IS SR-MPLS distributes the transport labels to the PE loopbacks;
    - iBGP L2VPN-EVPN (`encapsulation mpls`) advertises each PE's per-EVI
      service label on its Type-3 IMET, and its local MACs as Type-2;
    - the zebra-rs FibHandle tee carries all of it into cradle — the decap
      ILM at the local service label (bridge domain 100), remote MACs as
      overlay FDB entries imposing the far PE's label, and the remote BUM
      tunnel as a replication slot.

  Topology (kernel IPv4 forwarding off and kernel MPLS untouched on
  pe1/p/pe2, so a successful ping proves the eBPF stage did the label work):
  ```
   c1 ── pe1[zebra+cradle] ──10.250.0.0/30── p[zebra+cradle] ──10.250.0.4/30── pe2[zebra+cradle] ── c2
    bd 100 / evi 100          lo 1.1.1.1        lo 3.3.3.3          lo 2.2.2.2         bd 100 / evi 100
   10.0.0.1                                                                            10.0.0.2
  ```
  The P router carries no EVPN state whatsoever — no BGP, no EVI, no bridge.
  It only swaps the transport label, and being the penultimate hop for both
  loopbacks it pops it, exposing the service label to the egress PE. That is
  the layering this test exists to prove: BGP advertises a *PE*, IS-IS
  supplies the label to reach it, and the data plane composes the two.

  Fully dynamic — no static ARP, no static cradle FDB, no static kernel FDB,
  no static labels anywhere. c1's first ARP is flooded over the tee-installed
  replication slot; cradle's XDP stage learns the CE source MACs and streams
  them to zebra over WatchFdb; zebra originates a Type-2 carrying its EVI
  label; the far PE's tee installs the MAC against that label and unicast
  takes over.

  Scenario: Bridge two CEs across a BGP-EVPN-over-MPLS eBPF core
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "p"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "p" to namespace "p" interface "pe1"
    And I connect namespace "p" interface "pe2" to namespace "pe2" interface "p"
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
    And I disable IPv4 forwarding in namespace "p"
    And I disable IPv4 forwarding in namespace "pe2"
    # The PEs' own iBGP session is router-originated TCP entering an
    # XDP-forwarded core: it leaves the stack with deferred (partial)
    # checksums that an XDP redirect never resolves, so the far end drops the
    # segments while ICMP and transit traffic flow fine. Compute checksums in
    # software on the core-facing veths instead. See docs/design/mpls.md.
    And I execute "ethtool -K p tx off" in namespace "pe1"
    And I execute "ethtool -K p tx off" in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "ports-p.json" serving gRPC as "ctlp"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "p" with config "p.yaml" teeing to cradle as "ctlp"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2.2.2.2" should be "Established"
    # The EVI took a service label and programmed its bridge-domain decap.
    And show command "show mpls ilm" in namespace "pe1" should eventually contain "EVPN Decap (bd 100"
    And show command "show mpls ilm" in namespace "pe2" should eventually contain "EVPN Decap (bd 100"
    # Each PE learned the other's IMET, carrying a label rather than a VNI.
    And show command "show bgp evpn" in namespace "pe1" should eventually contain "ingress-replication endpoint:2.2.2.2 label:"
    And show command "show bgp evpn" in namespace "pe2" should eventually contain "ingress-replication endpoint:1.1.1.1 label:"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    # BUM proves the Type-3 became a replication slot; encap/decap prove the
    # Type-2 loop closed (XDP learn -> WatchFdb -> Type-2 -> remote tee).
    And the cradle stat "mpls_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The P router label-switched the overlay without any EVPN state.
    And the cradle stat "mpls_pop" in namespace "p" via gRPC as "ctlp" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "p"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "p"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "p"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
