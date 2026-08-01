@serial
@cradle_vpws_mpls_zebra
Feature: BGP EVPN VPWS over MPLS programs the eBPF E-Line
  The full EVPN VPWS provider edge (RFC 8214) over RFC 7432's original
  encapsulation, driven by zebra-rs and forwarded in eBPF — the one the
  Linux kernel cannot forward at all: no kernel action pops an MPLS
  label and emits the exposed Ethernet frame raw on a port.

  Three layers compose, each from a different protocol:
    - IS-IS SR-MPLS distributes the transport labels to the PE loopbacks;
    - iBGP L2VPN-EVPN (`encapsulation mpls`) advertises each PE's
      per-service label on its vpws Type-1 — drawn from the same dynamic
      block as EVI labels, with NO Encapsulation EC (RFC 8365 §5.1.3);
    - the zebra-rs FibHandle tee carries one AddXconnect per service into
      cradle: the AC's ingress XCONNECT encap toward the remote PE with
      the label the REMOTE advertised, and the local pop-to-AC ILM at the
      label we advertised.

  The P router carries no EVPN state whatsoever — no BGP, no vpws. It
  label-switches the transport label and, as penultimate hop for both
  loopbacks, pops it — exposing the service label to the egress PE. An
  E-Line has no MAC learning and no flooding: mpls_l2_bum stays ZERO,
  the sharpest possible contrast with the bridged EVI twin
  (cradle_evpn_mpls_zebra).

  Topology (kernel IPv4 forwarding off, kernel MPLS untouched):
  ```
   c1 ── pe1[zebra+cradle] ──10.250.0.0/30── p[zebra+cradle] ──10.250.0.4/30── pe2[zebra+cradle] ── c2
    vpws eline1            lo 1.1.1.1        lo 3.3.3.3          lo 2.2.2.2     vpws eline1
   10.0.0.1                                                                     10.0.0.2
  ```

  Scenario: Cross-connect two CEs through a BGP-signalled MPLS E-Line
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
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
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
    # Each side bound the other's PE + service label from its Type-1.
    And show command "show bgp evpn vpws" in namespace "pe1" should eventually contain "Remote PE: 2.2.2.2 (label "
    And show command "show bgp evpn vpws" in namespace "pe1" should contain "State: up"
    And show command "show bgp evpn vpws" in namespace "pe2" should eventually contain "Remote PE: 1.1.1.1 (label "
    # The E-Line is transparent: ARP + ICMP ride the cross-connect, both
    # directions, with zero static state anywhere.
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_dx2" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_dx2" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The P router label-switched the overlay without any EVPN state.
    And the cradle stat "mpls_pop" in namespace "p" via gRPC as "ctlp" should be nonzero
    # An E-Line never floods and never bridges — the sharpest contrast
    # with the EVI twin — and nothing fell back to another overlay.
    And the cradle stat "mpls_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be zero
    And the cradle stat "srv6_dx2" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "vxlan_dx2" in namespace "pe1" via gRPC as "ctl1" should be zero

  Scenario: A VLAN-scoped E-Line multiplexes the same ACs by 802.1Q VID
    Given the test topology exists
    # eline2 (evi 200, VID 30) shares pe1c/pe2c with the untagged eline1:
    # the AC demuxes by tag — VID-30 frames ride the VLAN-scoped service
    # (the tag crossing transparently, demuxed at the egress from the
    # DX2V table the pop-to-AC ILM names), untagged traffic still rides
    # eline1.
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
