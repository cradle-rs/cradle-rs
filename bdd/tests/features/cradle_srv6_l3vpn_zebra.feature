@serial
@cradle_srv6_l3vpn_zebra
Feature: BGP L3VPN over SRv6 programs the eBPF data plane
  The full SRv6 provider edge, driven by zebra-rs and forwarded in eBPF:
  iBGP VPNv4+VPNv6 distributes a per-VRF End.DT46 service SID and the
  customer routes; IS-IS SRv6 advertises the locators; `encapsulation srv6`
  makes imported VPN routes H.Encaps toward the remote SID. The FibHandle
  SRv6 tee carries all of it into cradle — the local SID (route_sid_install),
  the H.Encap route nexthops (segs), and the resolved underlay neighbors.

  Topology (kernel v4+v6 forwarding and seg6 off on pe1/pe2; the whole SRv6
  data path runs in eBPF):
  ```
   c1 ── pe1[cradle+zebra] ──2001:db8:0:12::/64── pe2[cradle+zebra] ── c2
    vrf-cust 10.1.1/24 + 2001:db8:a::/64          vrf-cust 10.2.2/24 + 2001:db8:b::/64
  ```
  pe1 allocates an End.DT46 SID from LOC1 (fcbb:bbbb:1::/48), advertises
  c1's subnet as VPNv4/VPNv6 carrying it; pe2 does the mirror from LOC2.
  A customer packet is H.Encaps'd (outer DA = the remote End.DT46 SID, in
  the remote locator the IS-IS underlay routes directly), decapsulated at
  the egress PE into vrf-cust, and delivered. One SID serves both AFIs.

  Scenario: Customer v4 and v6 reach across an eBPF SRv6 L3VPN
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I add address "10.1.1.100/24" to interface "eth0" in namespace "c1"
    And I add address "2001:db8:a::100/64" to interface "eth0" in namespace "c1"
    And I add address "10.2.2.100/24" to interface "eth0" in namespace "c2"
    And I add address "2001:db8:b::100/64" to interface "eth0" in namespace "c2"
    # The PE customer-facing addresses must exist before cradle starts: cradle
    # derives a VRF's connected routes once, from the kernel, at set_port time
    # (it has no address monitor), and zebra never tees kernel-owned connected
    # routes. Seed them here so derive_port installs 10.x.x.0/24 into FIB<n>_VRF[1];
    # zebra reconciles the same addresses idempotently and enslaves the ports.
    And I add address "10.1.1.1/24" to interface "pe1c" in namespace "pe1"
    And I add address "2001:db8:a::1/64" to interface "pe1c" in namespace "pe1"
    And I add address "10.2.2.1/24" to interface "pe2c" in namespace "pe2"
    And I add address "2001:db8:b::1/64" to interface "pe2c" in namespace "pe2"
    And I add route "default" via "10.1.1.1" in namespace "c1"
    And I add route "::/0" via "2001:db8:a::1" in namespace "c1"
    And I add route "default" via "10.2.2.1" in namespace "c2"
    And I add route "::/0" via "2001:db8:b::1" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    And I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I wait 60 seconds for BGP to operate
    And I execute "ping -6 -c 1 -W 2 2001:db8:0:12::2" in namespace "pe1"
    And I execute "ping -6 -c 1 -W 2 2001:db8:0:12::1" in namespace "pe2"
    Then BGP session in "pe1" to "2001:db8::2" should be "Established"
    And show command "show bgp vpnv4" in namespace "pe1" should eventually contain "10.2.2.0/24"
    And show command "show bgp vpnv6" in namespace "pe1" should eventually contain "2001:db8:b::/64"
    And ping from "c1" to "10.2.2.100" should eventually succeed
    And ping from "c1" to "2001:db8:b::100" should eventually succeed
    And ping from "c2" to "10.1.1.100" should eventually succeed
    And the cradle stat "srv6_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "fib4_vrf_hit" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "fib6_vrf_hit" in namespace "pe2" via gRPC as "ctl2" should be nonzero

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
