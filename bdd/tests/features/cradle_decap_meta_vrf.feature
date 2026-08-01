@serial
@cradle_decap_meta_vrf
Feature: Decap metadata VRF wins over the ingress port's VRF binding
  As an operator terminating tunnels on VRF-bound underlay ports
  I want a decap stage's inner-table choice to survive the TC FIB stage
  So that a GTP-U or SRv6 tunnel may arrive in one VRF and its inner
  packet route in another (the MUP N3-in-a-VRF topology).

  The TC forward stage picks the lookup table as: decap metadata (set
  only by a decap stage that knows the *inner* table — GTP PDR, SRv6
  End.DT*, MPLS pop, VXLAN L3VNI) first, else the ingress port's VRF
  binding (the *outer* context). Previously the port binding won, so
  any decap arriving on a VRF-bound port was mis-routed in the port's
  table.

  Assertion teeth in both scenarios: the DUT's global table and the
  underlay port's VRF table hold no route for the inner destination,
  and kernel forwarding is off — the inner packet is delivered only if
  the lookup really ran in the decap's table. The reply leg doubles as
  the control: plain (non-decap) customer ingress on a VRF-bound port
  still uses the port VRF.

  Scenario: GTP-U decap on a VRF-bound N3 port routes the inner packet in the PDR's table
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1a"
    And I connect namespace "pe1" interface "pe1b" to namespace "pe2" interface "pe2a"
    And I connect namespace "pe2" interface "pe2b" to namespace "c2" interface "eth0"
    And I execute "ip link set dev pe1b address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2a address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev eth0 address 02:00:00:00:02:c2" in namespace "c2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.254/24" to interface "pe1a" in namespace "pe1"
    And I add address "10.0.12.1/24" to interface "pe1b" in namespace "pe1"
    And I add address "10.0.12.2/24" to interface "pe2a" in namespace "pe2"
    And I add address "10.0.2.254/24" to interface "pe2b" in namespace "pe2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.2.1" should fail
    When I start cradle in namespace "pe1" with config "gtp-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "gtp-pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed
    And the cradle stat "gtp_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "gtp_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_encap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "gtp_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown GTP topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean

  Scenario: SRv6 End.DT46 decap on a VRF-bound underlay port routes the inner packet in the SID's table
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1a"
    And I connect namespace "pe1" interface "pe1b" to namespace "pe2" interface "pe2a"
    And I connect namespace "pe2" interface "pe2b" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:01:c1" in namespace "c1"
    And I execute "ip link set dev pe1b address 02:00:00:00:12:01" in namespace "pe1"
    And I execute "ip link set dev pe2a address 02:00:00:00:12:02" in namespace "pe2"
    And I execute "ip link set dev eth0 address 02:00:00:00:02:c2" in namespace "c2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.254/24" to interface "pe1a" in namespace "pe1"
    And I add address "2001:db8:12::1/64" to interface "pe1b" in namespace "pe1"
    And I add address "2001:db8:12::2/64" to interface "pe2a" in namespace "pe2"
    And I add address "10.0.2.254/24" to interface "pe2b" in namespace "pe2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.2.1" should fail
    When I start cradle in namespace "pe1" with config "srv6-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "srv6-pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And ping from "c2" to "10.0.1.1" should eventually succeed
    And the cradle stat "srv6_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_encap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown SRv6 topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
