@serial
@cradle_l3vpn_zebra
Feature: BGP/MPLS L3VPN over IS-IS SR programs the eBPF data plane
  The full provider stack, forwarded in eBPF: iBGP VPNv4 between the PEs
  distributes the per-VRF service label and customer routes; IS-IS SR-MPLS
  distributes the transport labels; per-VRF IS-IS exchanges routes with the
  CEs. The zebra-rs FibHandle tee carries all of it into cradle: labeled
  [transport, service] nexthops (imposition), the PHP ILM at P
  (pop-and-forward), the DecapVrf ILM (VPN label → per-VRF FIB), the
  VRF-scoped customer routes (the per-VRF route tee), and the resolved
  neighbors the MPLS egress rewrite needs.

  Topology (zebra's own l3vpn_isis_v4, with cradle on pe1/p/pe2 and kernel
  IP forwarding disabled there — the CEs and customer sites stay kernel):
  ```
   c1 ── ce1 ── pe1[zebra+cradle] ── p[zebra+cradle] ── pe2[zebra+cradle] ── ce2 ── c2
   10.0.1.1/32        vrf-cust ↑        IS-IS SR core       ↑ vrf-cust         10.0.2.1/32
  ```
  The PE CE-facing ports are cradle-VRF-bound to table 1 — the first (and
  only) VRF each zebra allocates, byte-identical to the table id the teed
  routes and the DecapVrf ILM carry. Warm-up pings seed the core ARP so the
  teed neighbors feed the label-switched egress.

  Scenario: Customer sites reach each other across an eBPF L3VPN core
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce1"
    And I create namespace "pe1"
    And I create namespace "p"
    And I create namespace "pe2"
    And I create namespace "ce2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "ce1" to namespace "ce1" interface "c1"
    And I connect namespace "ce1" interface "pe1" to namespace "pe1" interface "ce1"
    And I connect namespace "pe1" interface "p" to namespace "p" interface "pe1"
    And I connect namespace "p" interface "pe2" to namespace "pe2" interface "p"
    And I connect namespace "pe2" interface "ce2" to namespace "ce2" interface "pe2"
    And I connect namespace "ce2" interface "c2" to namespace "c2" interface "ce2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "p"
    And I disable IPv4 forwarding in namespace "pe2"
    # Locally-originated TCP (the iBGP session) leaves the PEs with deferred
    # (partial) checksums; the XDP pop-and-forward at P redirects frames
    # without resolving them, so the far PE drops the bad-checksum segments.
    # Compute checksums in software on the core-facing veths instead. ICMP
    # and transit traffic are unaffected — this is a veth+XDP peculiarity of
    # router-originated TCP entering an XDP-forwarded core.
    And I execute "ethtool -K p tx off" in namespace "pe1"
    And I execute "ethtool -K p tx off" in namespace "pe2"
    And I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "ports-p.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl3"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "p" with config "p.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl3"
    And I start zebra-rs in namespace "c1" with config "c1.yaml"
    And I start zebra-rs in namespace "ce1" with config "ce1.yaml"
    And I start zebra-rs in namespace "ce2" with config "ce2.yaml"
    And I start zebra-rs in namespace "c2" with config "c2.yaml"
    And I wait 60 seconds for BGP to operate
    And I execute "ping -c 1 -W 2 10.250.0.2" in namespace "pe1"
    And I execute "ping -c 1 -W 2 10.250.0.1" in namespace "p"
    And I execute "ping -c 1 -W 2 10.250.0.6" in namespace "p"
    And I execute "ping -c 1 -W 2 10.250.0.5" in namespace "pe2"
    Then BGP session in "pe1" to "1.1.1.3" should be "Established"
    And show command "show bgp vpnv4" in namespace "pe1" should eventually contain "10.0.2.1/32"
    And show command "show bgp vpnv4" in namespace "pe2" should eventually contain "10.0.1.1/32"
    And ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed
    And the cradle stat "mpls_push" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_pop" in namespace "p" via gRPC as "ctl2" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe2" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "p"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop zebra-rs in namespace "c1"
    And I stop zebra-rs in namespace "ce1"
    And I stop zebra-rs in namespace "ce2"
    And I stop zebra-rs in namespace "c2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "p"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "ce1"
    And I delete namespace "pe1"
    And I delete namespace "p"
    And I delete namespace "pe2"
    And I delete namespace "ce2"
    And I delete namespace "c2"
    Then the test environment should be clean
