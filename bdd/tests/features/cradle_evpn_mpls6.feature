@serial
@cradle_evpn_mpls6
Feature: EVPN over MPLS bridges L2 between IPv6 PEs in eBPF
  As an operator running an RFC 7432 MPLS-based EVPN on cradle
  I want the EVI service label imposed toward a remote PE named by an
  IPv6 address
  So that two CEs in one bridge domain reach each other across an
  IPv6-numbered MPLS core — the v6 twin of cradle_evpn_mpls. MPLS
  imposes no outer IP header, so the PE's address family only picks
  which FIB trie resolves the adjacency: the overlay FDB entry names the
  PE natively in its 16-byte slot, and the datapath's nexthop-0 fallback
  does a FIB6 /128 lookup that supplies the transport LSP stack.

  Topology (kernel v4+v6 forwarding off and kernel MPLS untouched —
  net.mpls.platform_labels stays 0 — on pe1/pe2, so a successful ping
  proves the eBPF stage switched the labels; the PE identities
  2001:db8:255::1/::2 live only in the eBPF maps):
  ```
   c1 ── pe1[cradle] ──2001:db8:12::/64── pe2[cradle] ── c2
    bd 100        EVI label 1100 / 2100          bd 100
   10.0.0.1                                     10.0.0.2
  ```
  A frame from c1 resolves to the remote FDB entry (c2 behind PE
  2001:db8:255::2, EVI service label 2100); pe1's FIB6 route to that
  /128 carries transport label 16, so the frame leaves as
  `[transport 16][service 2100]` under EtherType 0x8847 toward the v6
  adjacency. At pe2 the transport label pops locally (the oif-less UHP
  swap shape) and the service label's `pop-l2` ILM bridges the inner
  frame into bd 100. Static ARP on the CEs and a static overlay FDB on
  the PEs keep the path deterministic and BUM-free.

  Scenario: Bridge two CEs across an eBPF EVPN-over-MPLS domain with v6 PEs
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
    And I execute "ip neigh replace 10.0.0.2 lladdr 02:00:00:00:c2:02 dev eth0 nud permanent" in namespace "c1"
    And I execute "ip neigh replace 10.0.0.1 lladdr 02:00:00:00:c1:01 dev eth0 nud permanent" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_encap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "2001:db8:255::2"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
