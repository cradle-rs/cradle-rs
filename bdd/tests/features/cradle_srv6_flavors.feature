@serial
@cradle_srv6_flavors
Feature: SRv6 endpoint flavors PSP, USP and USD in the eBPF data plane
  As an operator terminating SRv6 paths on cradle
  I want the RFC 8986 §4.16 flavors executed in eBPF
  So that the last hops of an SR policy never have to parse an SRH:
  PSP pops it at the penultimate segment, USP pops it before local
  delivery at the ultimate segment, and USD decapsulates the outer
  IPv6 there and forwards the inner packet.

  Kernel v4+v6 forwarding is off and seg6 is NEVER enabled on s/p/d —
  that is the assertion teeth: the USD and USP pings only work if the
  eBPF flavor processing removed the SRH/outer header (the kernels
  would otherwise drop the packets), and the PSP pop is pinned by its
  stat. All static config, no control plane, no VRFs (decaps land in
  the main table).

  Topology:
  ```
   c1 ── s[cradle] ──2001:db8:1::/64── p[cradle] ──2001:db8:2::/64── d[cradle] ── c2
   fc00:1::/64                                                        fc00:2::/64
  ```
  p holds two End SIDs: fd00:2::e1 (flavor PSP) and fd00:2::e2 (plain).
  d holds End.DT46 fd00:3::d46, End+USD fd00:3::ud, and End+USP
  fd00:3::aa (also a local address on d's lo, so the popped ping is
  answered by d itself). Three flows from c1:
    * PSP:  H.Encaps [e1(PSP), d46] — p's walk exhausts the SRH and
      pops it; d decaps the clean IPv6-in-IPv6 with End.DT46.
    * USD:  H.Encaps [e2, ud] to c2's loopback fc00:9::1 — at d the
      exhausted SRH plus outer header are decapsulated in one pass and
      the inner packet forwards in the main table.
    * USP:  ping d's fd00:3::aa itself; s H.Inserts [e2], p's walk
      restores the SID as destination, d pops the exhausted SRH and
      the kernel answers the then-ordinary echo request.

  Scenario: PSP pops at the penultimate hop, USD and USP serve the ultimate hop
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "p"
    And I create namespace "d"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "p" interface "ps"
    And I connect namespace "p" interface "pd" to namespace "d" interface "dp"
    And I connect namespace "d" interface "dc" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev ps address 02:00:00:00:0a:01" in namespace "p"
    And I execute "ip link set dev pd address 02:00:00:00:0b:01" in namespace "p"
    And I execute "ip link set dev dp address 02:00:00:00:0b:02" in namespace "d"
    And I execute "ip link set dev dc address 02:00:00:00:c2:ff" in namespace "d"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "2001:db8:1::2/64" to interface "ps" in namespace "p"
    And I add address "2001:db8:2::1/64" to interface "pd" in namespace "p"
    And I add address "2001:db8:2::2/64" to interface "dp" in namespace "d"
    And I add address "fc00:2::ff/64" to interface "dc" in namespace "d"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    # The USP SID is a local address on d — after the eBPF pop the kernel
    # answers the echo itself. Its reply (and nothing else on d's kernel)
    # needs a route back toward c1; the plain reply is forwarded by p's
    # and s's cradle FIBs.
    And I add address "fd00:3::aa/128" to interface "lo" in namespace "d"
    And I add route "fc00:1::/64" via "2001:db8:2::1" in namespace "d"
    # c2's loopback is the USD flow's inner destination.
    And I make namespace "c2" interface "lo" up
    And I add address "fc00:9::1/128" to interface "lo" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "p"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "p"
    And I disable IPv6 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "p" with config "p.json" serving gRPC as "ctl2"
    And I start cradle in namespace "d" with config "d.json" serving gRPC as "ctl3"
    # PSP: the ping works with or without the pop (End.DT46 also skips an
    # exhausted SRH), so the stat pins that the pop actually executed; the
    # wire-format proof is the zebra-driven cradle_tilfa_psp feature, where
    # the receiving kernel refuses un-popped packets.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_psp" in namespace "p" via gRPC as "ctl2" should be nonzero
    # USD: d's kernel never sees the SRv6 encapsulation — without the eBPF
    # decap the End SID's exhausted-SRH packet would punt to a
    # forwarding-disabled kernel and drop.
    Then ping from "c1" to "fc00:9::1" should eventually succeed
    And the cradle stat "srv6_usd" in namespace "d" via gRPC as "ctl3" should be nonzero
    # USP: without the pop, local delivery of an SL=0 SRH needs
    # seg6_enabled, which stays off — the ping only works popped.
    Then ping from "c1" to "fd00:3::aa" should eventually succeed
    And the cradle stat "srv6_usp" in namespace "d" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "s"
    And I stop cradle in namespace "p"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "p"
    And I delete namespace "d"
    And I delete namespace "c2"
    Then the test environment should be clean
