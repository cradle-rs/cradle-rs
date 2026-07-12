@serial
@cradle_evpn_vxlan_irb_zebra
Feature: BGP EVPN Type-5 symmetric IRB programs the eBPF VXLAN data plane
  The full EVPN symmetric-IRB provider edge, driven by zebra-rs and forwarded
  in eBPF: iBGP L2VPN-EVPN advertises each PE's tenant CE subnet as a Type-5
  (IP Prefix) route carrying the tenant L3VNI in the NLRI label and this PE's
  router-MAC in the Router's-MAC extended community (RFC 9135). The ingress PE
  imports the remote Type-5 into the tenant VRF as an NH_F_VXLAN route (VTEP
  from the BGP nexthop, L3VNI from the label, remote router-MAC from the EC)
  and tees it — plus the L3VNI↔VRF binding (SetVni l3) and local VTEP source —
  into cradle. This drives the same cradle-native datapath that
  `cradle_evpn_vxlan_irb` proves under static config, but dynamically from BGP.

  Topology (kernel v4+v6 forwarding off on pe1/pe2; the L3VNI datapath runs
  entirely in eBPF; VTEPs are loopbacks reached over the directly-connected
  underlay by a static /32, so cradle resolves each remote VTEP to a real
  underlay nexthop):
  ```
   c1(10.1.1.100/24) ── pe1[cradle+zebra] ──10.0.12.0/24── pe2[cradle+zebra] ── c2(10.2.2.100/24)
     subnet A           vrf-cust, L3VNI 5000, VTEP 192.0.2.1|192.0.2.2          subnet B
  ```
  Each PE originates a Type-5 for its connected CE subnet with its own
  router-MAC; the peer routes toward it by rewriting the inner Ethernet
  destination to that router-MAC and VXLAN-wrapping with the L3VNI, and the
  originator decaps the L3VNI into vrf-cust and delivers to the local subnet.

  Scenario: Route between two tenant subnets over a BGP-driven eBPF L3VNI
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I add address "10.1.1.100/24" to interface "eth0" in namespace "c1"
    And I add address "10.2.2.100/24" to interface "eth0" in namespace "c2"
    # The PE customer-facing addresses must exist before cradle starts: cradle
    # derives a VRF's connected routes once, from the kernel, at set_port time
    # (it has no address monitor), and zebra never tees kernel-owned connected
    # routes. Seed them here so derive_port installs 10.x.x.0/24 into
    # FIB4_VRF[1]; zebra reconciles the same addresses idempotently and
    # enslaves the ports to vrf-cust.
    And I add address "10.1.1.1/24" to interface "pe1c" in namespace "pe1"
    And I add address "10.2.2.1/24" to interface "pe2c" in namespace "pe2"
    And I add route "default" via "10.1.1.1" in namespace "c1"
    And I add route "default" via "10.2.2.1" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.2.2.100" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "192.0.2.2" should be "Established"
    And ping from "c1" to "10.2.2.100" should eventually succeed
    And ping from "c2" to "10.1.1.100" should eventually succeed
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "vxlan_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe2" via gRPC as "ctl2" should be nonzero

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
