@serial
@cradle_evpn_mpls6_zebra_transit
Feature: EVPN over MPLS crosses a pure-P IPv6 transit hop in eBPF
  The missing half of cradle_evpn_mpls6_zebra: a label-switched transit
  hop between the v6 PEs, with no IGP anywhere. The v4 twin
  (cradle_evpn_mpls_zebra) gets its transport LSP from IS-IS SR-MPLS,
  whose prefix-SIDs are IPv4-only — here the same three-layer
  composition is built statically: each PE's labeled static v6 route
  supplies the transport label toward the far PE's loopback, and the P
  router's static MPLS label bindings — their nexthops IPv6, the
  static-ILM v6 shape — pop it toward the egress PE (PHP), exposing the
  EVI service label BGP advertised. The P carries no EVPN state, no
  BGP: it label-switches between v6 adjacencies, entirely in eBPF.

  Topology (kernel v4+v6 forwarding off and kernel MPLS untouched on
  pe1/p/pe2):
  ```
   c1 ── pe1[zebra+cradle] ─2001:db8:12::/64─ p[zebra+cradle] ─2001:db8:23::/64─ pe2[zebra+cradle] ── c2
    bd 100 / evi 100   lo 2001:db8:255::1      pop 100 / 101      lo 2001:db8:255::2   bd 100 / evi 100
   10.0.0.1                                                                            10.0.0.2
  ```
  pe1: `route 2001:db8:255::2/128 via 2001:db8:12::2 label [100]`;
  p: `mpls label 100 nexthop 2001:db8:23::2` (pop toward pe2) and
  `mpls label 101 nexthop 2001:db8:12::1` (pop toward pe1);
  pe2 mirrors pe1 with label [101]. Even the PEs' own iBGP session rides
  the LSP: pe1's kernel imposes label 100 on the TCP toward pe2's
  loopback, p's eBPF stage pops it, pe2's stack receives it plain.

  Scenario: Bridge two CEs across a v6 label-switched core with a pure P
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "p"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "p" interface "pe1"
    And I connect namespace "p" interface "pe2" to namespace "pe2" interface "pe2u"
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
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "p"
    And I disable IPv6 forwarding in namespace "pe2"
    # The PEs' own iBGP session is router-originated TCP entering an
    # XDP-forwarded core: it leaves the stack with deferred (partial)
    # checksums that an XDP redirect never resolves, so the far end drops
    # the segments while transit traffic flows fine. Compute checksums in
    # software on the core-facing veths instead. See docs/design/mpls.md.
    And I execute "ethtool -K pe1u tx off" in namespace "pe1"
    And I execute "ethtool -K pe2u tx off" in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "ports-p.json" serving gRPC as "ctlp"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "p" with config "p.yaml" teeing to cradle as "ctlp"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    # The P's eBPF egress rewrite needs its neighbors' MACs: its own
    # kernel never originates toward the PEs, so one warm-up ping each
    # resolves ND and the netlink monitor tees the entries to cradle.
    And I wait 3 seconds
    And I execute "ping -c 1 -W 2 2001:db8:12::1" in namespace "p"
    And I execute "ping -c 1 -W 2 2001:db8:23::2" in namespace "p"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8:255::2" should be "Established"
    And show command "show mpls ilm" in namespace "pe1" should eventually contain "EVPN Decap (bd 100"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The P label-switched the overlay (and the PEs' BGP session) without
    # any EVPN state — the static-ILM v6 bindings did the work.
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
