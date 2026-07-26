@serial
@cradle_evpn_mpls_bum
Feature: EVPN over MPLS carries BUM traffic to a remote PE
  As an operator running an RFC 7432 MPLS-based EVPN on cradle
  I want broadcast, multicast and unknown-unicast frames tunneled to the remote PE
  So that a bridge domain works without any pre-seeded L2 or ARP state —
  the flood-and-learn behaviour a real L2VPN needs.

  Topology (identical to `cradle_evpn_mpls`, kernel MPLS untouched and kernel
  IPv4 forwarding off on both PEs):
  ```
   c1 ── pe1[cradle] ──10.0.1.0/24── pe2[cradle] ── c2
    bd 100    unicast 1100/2100, BUM 1200/2200      bd 100
   10.0.0.1                                        10.0.0.2
  ```
  Unlike `cradle_evpn_mpls` there is **no static ARP** on the CEs, so the very
  first frame is c1's broadcast ARP request. It has no unicast FDB match, so it
  takes the per-BD BUM sentinel — the all-ones-MAC FDB row — and is imposed
  with the remote PE's *BUM* service label (2200) rather than its unicast one
  (2100). pe2 pops it into bd 100 and floods it to c2; the ARP reply and the
  ping that follows are unicast and ride the 2100/1100 labels.

  A distinct BUM label per PE is what an ingress-replication PMSI advertises,
  and keeping it separate here proves the sentinel row — not the unicast row —
  carried the broadcast: `mpls_l2_bum` and `mpls_l2_encap` must both fire.

  Scenario: Flood an ARP over MPLS and converge on unicast
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
    And I add address "10.0.1.1/24" to interface "pe1u" in namespace "pe1"
    And I add address "10.0.1.2/24" to interface "pe2u" in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_bum" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
