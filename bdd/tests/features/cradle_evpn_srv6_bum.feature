@serial
@cradle_evpn_srv6_bum
Feature: EVPN over SRv6 BUM (End.DT2M) floods L2 across the eBPF data plane
  As an operator running an L2VPN over an SRv6 fabric on cradle
  I want broadcast/unknown frames (ARP) carried to the remote PE's DT2M SID
  So that CEs resolve each other over the overlay with no static ARP, and the
  BUM flood + End.DT2M decap happen entirely in eBPF.

  Topology (kernel v4+v6 forwarding and seg6 off on pe1/pe2):
  ```
   c1 ── pe1[cradle] ──2001:db8::/64── pe2[cradle] ── c2
    bd 100    DT2U ::100 / DT2M ::200 per PE       bd 100
   10.0.0.1                                       10.0.0.2
  ```
  Unlike the unicast test there is NO static ARP: c1's ARP for c2 is broadcast,
  so pe1 tunnels it to the bridge domain's End.DT2M SID (fd00:2::200) — the
  all-ones-MAC FDB entry is the per-BD BUM sentinel. pe2 matches its End.DT2M
  SID, strips the outer header, and floods the inner (broadcast) frame into
  bd 100 out to c2. c2's unicast reply then rides End.DT2U (fd00:1::100), and
  once the CEs have learned each other the ping flows over End.DT2U both ways.
  A successful ping therefore proves the BUM path carried the ARP.

  Scenario: Resolve and bridge two CEs over EVPN-over-SRv6 BUM (End.DT2M)
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
    And I execute "ip link set dev pe1u address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "srv6_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
