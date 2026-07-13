@serial
@cradle_srv6_replicate
Feature: SRv6 End.Replicate (RFC 9524) fans EVPN BUM out an SR P2MP tree
  As an operator running EVPN BUM over an SRv6 SR-P2MP tree
  I want a bud node to replicate one received copy to every downstream branch
  So that the root sends a single copy into the tree instead of one per leaf,
  and a bud that is also a leaf delivers a copy into its own bridge domain —
  all in the eBPF data plane (RFC 9524 End.Replicate).

  This is the SR-P2MP tree the head-end ingress-replication slots never built:
  the root encapsulates a BUM frame once toward the bud's End.Replicate SID;
  the bud clones it to each downstream branch — rewriting the outer IPv6 DA to
  that branch's downstream Replication-SID (a leaf's End.DT2M SID) and
  decrementing the Hop Limit — and, being a Bud, also delivers one copy into
  its own bridge domain. Cloning is a TC-only primitive (bpf_clone_redirect),
  so the XDP stage matches the End.Replicate SID and hands the still-encapped
  frame to the TC stage, which fans it out.

  Topology (kernel v4+v6 forwarding off on all PEs; one bd 10 / VNI 10 subnet
  10.0.0.0/24 spanning four CEs; the bud is the SR-P2MP replication node):
  ```
    cr ── root ══(fd00:b::5)══> bud ══> leaf1 ── c1
   .0.1   (head)      End.Replicate  │    (End.DT2M fd00:1::100)  .0.2
                                     ├══> leaf2 ── c2
                                     │    (End.DT2M fd00:2::100)  .0.3
                                     └──> (local End.DT2M fd00:b::100) ── cb
                                          Bud local delivery         .0.4
  ```
  The root floods cr's BUM into a replication slot encapsulating toward the
  bud's End.Replicate SID (fd00:b::5). The bud's REPL_SEG fans each copy out to
  leaf1, leaf2, and a local leaf veth (its own End.DT2M SID). Reverse unicast
  rides static overlay FDB (the CE MACs → the root's End.DT2U SID), transiting
  the bud as plain IPv6 — so cr↔c1 (a remote branch) and cr↔cb (the Bud local
  branch) both reach, and leaf2's decap counter proves the third branch fired.

  Scenario: Replicate EVPN BUM across an SRv6 SR-P2MP tree (End.Replicate)
    Given a clean test environment
    When I create namespace "cr"
    And I create namespace "c1"
    And I create namespace "c2"
    And I create namespace "cb"
    And I create namespace "root"
    And I create namespace "bud"
    And I create namespace "leaf1"
    And I create namespace "leaf2"
    And I connect namespace "cr" interface "eth0" to namespace "root" interface "rc"
    And I connect namespace "c1" interface "eth0" to namespace "leaf1" interface "l1c"
    And I connect namespace "c2" interface "eth0" to namespace "leaf2" interface "l2c"
    And I connect namespace "cb" interface "eth0" to namespace "bud" interface "bc"
    And I connect namespace "root" interface "ru" to namespace "bud" interface "bur"
    And I connect namespace "bud" interface "bul1" to namespace "leaf1" interface "l1u"
    And I connect namespace "bud" interface "bul2" to namespace "leaf2" interface "l2u"
    And I execute "ip link set dev eth0 address 02:00:00:00:00:01" in namespace "cr"
    And I execute "ip link set dev eth0 address 02:00:00:00:00:02" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:00:03" in namespace "c2"
    And I execute "ip link set dev eth0 address 02:00:00:00:00:04" in namespace "cb"
    And I execute "ip link set dev ru address 02:00:00:00:0a:0a" in namespace "root"
    And I execute "ip link set dev bur address 02:00:00:00:0b:0a" in namespace "bud"
    And I execute "ip link set dev bul1 address 02:00:00:00:0b:01" in namespace "bud"
    And I execute "ip link set dev bul2 address 02:00:00:00:0b:02" in namespace "bud"
    And I execute "ip link set dev l1u address 02:00:00:00:01:0a" in namespace "leaf1"
    And I execute "ip link set dev l2u address 02:00:00:00:02:0a" in namespace "leaf2"
    # The root's replication slot: an internal veth pair whose A end floods in
    # bd 10 and whose B end MAC-in-SRv6 encapsulates toward the bud's SID.
    And I execute "ip link add rra type veth peer name rrb" in namespace "root"
    And I execute "ip link set rra up" in namespace "root"
    And I execute "ip link set rrb up" in namespace "root"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "cr"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.3/24" to interface "eth0" in namespace "c2"
    And I add address "10.0.0.4/24" to interface "eth0" in namespace "cb"
    And I add address "2001:db8:0b::a/64" to interface "ru" in namespace "root"
    And I add address "2001:db8:0b::b/64" to interface "bur" in namespace "bud"
    And I add address "2001:db8:b1::b/64" to interface "bul1" in namespace "bud"
    And I add address "2001:db8:b2::b/64" to interface "bul2" in namespace "bud"
    And I add address "2001:db8:b1::1/64" to interface "l1u" in namespace "leaf1"
    And I add address "2001:db8:b2::2/64" to interface "l2u" in namespace "leaf2"
    And I disable IPv4 forwarding in namespace "root"
    And I disable IPv4 forwarding in namespace "bud"
    And I disable IPv4 forwarding in namespace "leaf1"
    And I disable IPv4 forwarding in namespace "leaf2"
    And I disable IPv6 forwarding in namespace "root"
    And I disable IPv6 forwarding in namespace "bud"
    And I disable IPv6 forwarding in namespace "leaf1"
    And I disable IPv6 forwarding in namespace "leaf2"
    Then ping from "cr" to "10.0.0.2" should fail
    When I start cradle in namespace "root" with config "root.json" serving gRPC as "ctlR"
    And I start cradle in namespace "bud" with config "bud.json" serving gRPC as "ctlB"
    And I start cradle in namespace "leaf1" with config "leaf1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "leaf2" with config "leaf2.json" serving gRPC as "ctl2"
    # cr reaches c1 via a remote branch (leaf1) and cb via the Bud local branch.
    Then ping from "cr" to "10.0.0.2" should eventually succeed
    And ping from "cr" to "10.0.0.4" should eventually succeed
    # The root encapsulated BUM once toward the bud's End.Replicate SID.
    And the cradle stat "srv6_l2_bum" in namespace "root" via gRPC as "ctlR" should be nonzero
    # The bud replicated it to the tree's branches (the feature under test).
    And the cradle stat "srv6_replicate" in namespace "bud" via gRPC as "ctlB" should be nonzero
    # Every branch received a copy: two remote leaves + the Bud's local delivery.
    And the cradle stat "srv6_l2_decap" in namespace "leaf1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "leaf2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "bud" via gRPC as "ctlB" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "root"
    And I stop cradle in namespace "bud"
    And I stop cradle in namespace "leaf1"
    And I stop cradle in namespace "leaf2"
    And I delete namespace "cr"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "cb"
    And I delete namespace "root"
    And I delete namespace "bud"
    And I delete namespace "leaf1"
    And I delete namespace "leaf2"
    Then the test environment should be clean
