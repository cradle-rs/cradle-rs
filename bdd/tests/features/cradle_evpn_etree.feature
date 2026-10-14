@serial
@cradle_evpn_etree
Feature: EVPN E-Tree leaf isolation in eBPF
  As an operator running a rooted-multipoint (E-Tree) service over EVPN
  I want a leaf attachment circuit never to reach another leaf
  So that leaves talk only to roots, on this PE and across the core.

  RFC 8317: every AC is a root or a leaf, and a leaf never reaches another
  leaf. cradle keeps a port's role in `PORT_ETREE` (`SetEtreeRole`; here
  `ports[].etree_leaf`), and a remote MAC behind a leaf AC carries
  `FDB_F_ETREE_LEAF` (`FdbRemote.etree_leaf`; here `fdb[].etree_leaf`), as
  its Type-2's E-Tree EC said. Three checks, each counted:
  - known unicast between two local leaves is not redirected
    (`l2_drop_etree_local`);
  - a flood from a local leaf skips the other local leaves (also
    `l2_drop_etree_local`; the copies toward roots and the overlay go);
  - known unicast from a local leaf to a remote leaf MAC is dropped in XDP
    before it is encapsulated (`l2_drop_etree_uc`, RFC 8317 §4.1 ingress
    filtering), so it never crosses the core.

  BUM between leaves on different PEs is not filtered yet (the leaf label /
  IMET colouring of later phases), so nothing here floods across the core.

  Topology (one bridge domain, bd 100 ↔ VNI 10100, over a single IPv4 hop):
  ```
     l1 (leaf)  ─┐                                  ┌─ l2 (leaf)
     l1b (leaf) ─┼─ pe1[cradle] ──10.100.0.0/24── pe2[cradle] ─┤
     r1 (root)  ─┘   VTEP 10.100.0.1   VTEP 10.100.0.2          └─ r2 (root)
  ```
  Hosts 10.0.0.11 (l1), .12 (l1b), .13 (r1), .21 (l2), .22 (r2), with
  fixed MACs. The remote MACs are static FDB entries on the PEs, and the
  hosts use static ARP for each other, except l1 for r1: that one ARP is
  the broadcast the flood check watches. A tc counter on l1b counts the
  ARP frames from l1 that reach it. IPv6 is off everywhere, so no
  multicast chatter is flooded alongside.

  The first scenario is the control: without the leaf roles every path
  works and both counters stay zero. pe2 starts with l2 already a leaf
  (the role from the startup config, ahead of the port), which changes
  nothing yet: no MAC is flagged leaf on pe2. The second scenario adds the
  roles and flags over gRPC; each path that a role cuts is shown cut, and
  the counter that cut it shown moving.

  Scenario: Without leaf roles every attachment circuit reaches every other
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "l1b"
    And I create namespace "r1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "l1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "l1b"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "r1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "l2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "r2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l1"
    And I connect namespace "l1b" interface "eth0" to namespace "pe1" interface "pe1lb"
    And I connect namespace "r1" interface "eth0" to namespace "pe1" interface "pe1r1"
    And I connect namespace "l2" interface "eth0" to namespace "pe2" interface "pe2l2"
    And I connect namespace "r2" interface "eth0" to namespace "pe2" interface "pe2r2"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:01" in namespace "l1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:02" in namespace "l1b"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:03" in namespace "r1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:02" in namespace "r2"
    And I execute "ip link set dev pe1u address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.12/24" to interface "eth0" in namespace "l1b"
    And I add address "10.0.0.13/24" to interface "eth0" in namespace "r1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    # Static ARP for every pair a ping below uses, except l1 → r1.
    And I execute "ip neigh replace 10.0.0.12 lladdr 02:00:00:00:e1:02 dev eth0 nud permanent" in namespace "l1"
    And I execute "ip neigh replace 10.0.0.21 lladdr 02:00:00:00:e2:01 dev eth0 nud permanent" in namespace "l1"
    And I execute "ip neigh replace 10.0.0.22 lladdr 02:00:00:00:e2:02 dev eth0 nud permanent" in namespace "l1"
    And I execute "ip neigh replace 10.0.0.11 lladdr 02:00:00:00:e1:01 dev eth0 nud permanent" in namespace "l1b"
    And I execute "ip neigh replace 10.0.0.13 lladdr 02:00:00:00:e1:03 dev eth0 nud permanent" in namespace "l1b"
    And I execute "ip neigh replace 10.0.0.11 lladdr 02:00:00:00:e1:01 dev eth0 nud permanent" in namespace "r1"
    And I execute "ip neigh replace 10.0.0.12 lladdr 02:00:00:00:e1:02 dev eth0 nud permanent" in namespace "r1"
    And I execute "ip neigh replace 10.0.0.21 lladdr 02:00:00:00:e2:01 dev eth0 nud permanent" in namespace "r1"
    And I execute "ip neigh replace 10.0.0.11 lladdr 02:00:00:00:e1:01 dev eth0 nud permanent" in namespace "l2"
    And I execute "ip neigh replace 10.0.0.13 lladdr 02:00:00:00:e1:03 dev eth0 nud permanent" in namespace "l2"
    And I execute "ip neigh replace 10.0.0.11 lladdr 02:00:00:00:e1:01 dev eth0 nud permanent" in namespace "r2"
    # l1b counts the ARP frames from l1 that reach it (the flood check).
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l1b"
    And I execute "tc filter add dev eth0 ingress protocol arp flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l1b"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    Then ping from "l1" to "10.0.0.12" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    # Local: l1 reaches l1b by known unicast, and r1 after an ARP broadcast,
    # which the flood also delivers to l1b.
    Then ping from "l1" to "10.0.0.12" should eventually succeed
    And ping from "l1" to "10.0.0.13" should eventually succeed
    And command "tc -s filter show dev eth0 ingress" in namespace "l1b" should eventually not contain "Sent 0 bytes 0 pkt"
    # Across the core, both ways. l2 is a leaf on pe2 already, but nothing
    # on pe2 is flagged leaf, so it reaches l1 as well as r1.
    And ping from "l1" to "10.0.0.21" should eventually succeed
    And ping from "l1" to "10.0.0.22" should eventually succeed
    And ping from "l2" to "10.0.0.11" should eventually succeed
    And ping from "l2" to "10.0.0.13" should eventually succeed
    And the cradle stat "vxlan_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "l2_drop_etree_local" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "l2_drop_etree_uc" in namespace "pe2" via gRPC as "ctl2" should be zero

  Scenario: A leaf reaches roots only, locally and across the core
    Given the test topology exists
    When I apply cradle config "pe1-etree.json" to namespace "pe1" via gRPC as "ctl1"
    And I apply cradle config "pe2-etree.json" to namespace "pe2" via gRPC as "ctl2"
    Then the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "etree-leaf"
    And the cradle dump "l2" in namespace "pe2" via gRPC as "ctl2" should contain "etree-leaf"
    # Flood: l1 ARPs for r1 again (its dynamic entry flushed, the counter on
    # l1b reset). r1, a root, answers; l1b, a leaf, never sees the request.
    When I execute "ip neigh flush dev eth0" in namespace "l1"
    And I execute "tc filter del dev eth0 ingress" in namespace "l1b"
    And I execute "tc filter add dev eth0 ingress protocol arp flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l1b"
    Then ping from "l1" to "10.0.0.13" should eventually succeed
    And command "tc -s filter show dev eth0 ingress" in namespace "l1b" should eventually contain "Sent 0 bytes 0 pkt"
    # Local known unicast: l1b's MAC is in pe1's table (it just reached r1),
    # so l1 → l1b is a redirect that the roles refuse, not a flood.
    And ping from "l1b" to "10.0.0.13" should eventually succeed
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "02:00:00:00:e1:02"
    When I record the cradle stat "l2_drop_etree_local" in namespace "pe1" via gRPC as "ctl1"
    Then ping from "l1" to "10.0.0.12" should fail
    And the cradle stat "l2_drop_etree_local" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value
    # A root still reaches the leaf.
    And ping from "r1" to "10.0.0.12" should eventually succeed
    # Across the core: l1 → l2 (flagged leaf on pe1) is dropped at pe1
    # before encapsulation; l1 → r2 still goes.
    When I record the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1"
    Then ping from "l1" to "10.0.0.21" should fail
    And the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value
    And ping from "l1" to "10.0.0.22" should eventually succeed
    # The other way, from pe2's startup-config leaf: l2 → l1 (flagged leaf
    # on pe2) is dropped at pe2; l2 → r1 still goes. The ping alone cannot
    # tell: l1's reply would be leaf → leaf too, and pe1 drops that. It is
    # pe2's counter that proves l2's role took effect from the startup
    # config (shown by leaving that role out: the ping still fails, the
    # counter does not move).
    When I record the cradle stat "l2_drop_etree_uc" in namespace "pe2" via gRPC as "ctl2"
    Then ping from "l2" to "10.0.0.11" should fail
    And the cradle stat "l2_drop_etree_uc" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And ping from "l2" to "10.0.0.13" should eventually succeed

  Scenario: A leaf keeps its role when its port comes back with a new ifindex
    Given the test topology exists
    # l1b's link is deleted and re-created: the same name, a new ifindex.
    When I execute "ip link del pe1lb" in namespace "pe1"
    And I connect namespace "l1b" interface "eth0" to namespace "pe1" interface "pe1lb"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:02" in namespace "l1b"
    And I add address "10.0.0.12/24" to interface "eth0" in namespace "l1b"
    And I execute "ip neigh replace 10.0.0.11 lladdr 02:00:00:00:e1:01 dev eth0 nud permanent" in namespace "l1b"
    And I execute "ip neigh replace 10.0.0.13 lladdr 02:00:00:00:e1:03 dev eth0 nud permanent" in namespace "l1b"
    # The ports re-applied with no role in them: SetPort alone, as a control
    # plane re-sends it for a re-created device. The role l1b was given by
    # name must land on the new ifindex.
    And I apply cradle config "pe1-ports.json" to namespace "pe1" via gRPC as "ctl1"
    # l1b re-learns on its new port by reaching r1, and r1 reaches it...
    Then ping from "l1b" to "10.0.0.13" should eventually succeed
    And ping from "r1" to "10.0.0.12" should eventually succeed
    # ...but l1 still does not.
    When I record the cradle stat "l2_drop_etree_local" in namespace "pe1" via gRPC as "ctl1"
    Then ping from "l1" to "10.0.0.12" should fail
    And the cradle stat "l2_drop_etree_local" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value

  Scenario: A deleted leaf port stays isolated while it is still in its bridge domain
    Given the test topology exists
    # DelPort detaches pe1lb, but its device stays up and the port stays in
    # bd 100's flood list until a SetL2Domain without it, which is the
    # caller's to send and is not sent here. Its leaf role must hold until
    # then: l1's ARP broadcast for r1 still must not reach l1b.
    When I delete cradle port "pe1lb" in namespace "pe1" via gRPC as "ctl1"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    # l1b's eth0 was re-created above: a fresh counter on it.
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l1b"
    And I execute "tc filter add dev eth0 ingress protocol arp flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l1b"
    Then ping from "l1" to "10.0.0.13" should eventually succeed
    And command "tc -s filter show dev eth0 ingress" in namespace "l1b" should eventually contain "Sent 0 bytes 0 pkt"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "l1"
    And I delete namespace "l1b"
    And I delete namespace "r1"
    And I delete namespace "l2"
    And I delete namespace "r2"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
