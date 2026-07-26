@serial
@cradle_evpn_mpls
Feature: EVPN over MPLS bridges L2 across the eBPF data plane
  As an operator running an RFC 7432 MPLS-based EVPN on cradle
  I want a CE Ethernet frame carried under an EVI service label to the remote PE
  So that two CEs in one bridge domain reach each other over an MPLS underlay,
  with the imposition and the service-label disposition done entirely in eBPF —
  something the Linux kernel has no data path for at all.

  Topology (kernel IPv4 forwarding off and kernel MPLS untouched —
  net.mpls.platform_labels stays 0 — on pe1/pe2, so a successful ping proves
  the eBPF stage switched the labels):
  ```
   c1 ── pe1[cradle] ──10.0.1.0/24── pe2[cradle] ── c2
    bd 100      EVI label 1100 / 2100        bd 100
   10.0.0.1                                 10.0.0.2
  ```
  c1 and c2 share bridge domain 100 (one L2 subnet). A frame from c1 to c2
  arrives on pe1's L2 port; its destination MAC resolves to a remote FDB entry
  (c2 is behind pe2, EVI service label 2100), so pe1 imposes
  `[transport 16][service 2100]` and forwards it as EtherType 0x8847. The
  transport label is NOT pre-resolved on the FDB row: the entry names only the
  remote PE (10.255.0.2) and the datapath resolves the adjacency by a FIB
  lookup on it, picking up the LSP stack the PE's /32 route carries — the shape
  an SR-MPLS or LDP underlay produces.

  At pe2 the two labels are disposed of in one XDP pass: the transport label
  pops locally (an oif-less "swap with no out-labels", the UHP shape), exposing
  the service label, whose `pop-l2` ILM strips it and bridges the inner frame
  into bd 100 out to c2. Static ARP on the CEs and a static overlay FDB on the
  PEs keep the path deterministic and BUM-free (flooding is a later slice).

  Scenario: Bridge two CEs across an eBPF EVPN-over-MPLS domain
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
    And I execute "ip neigh replace 10.0.0.2 lladdr 02:00:00:00:c2:02 dev eth0 nud permanent" in namespace "c1"
    And I execute "ip neigh replace 10.0.0.1 lladdr 02:00:00:00:c1:01 dev eth0 nud permanent" in namespace "c2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_encap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
