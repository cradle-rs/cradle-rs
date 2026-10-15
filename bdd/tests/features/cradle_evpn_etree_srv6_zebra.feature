@serial
@cradle_evpn_etree_srv6_zebra
Feature: EVPN E-Tree over SRv6 driven by zebra-rs — leaf arguments from BGP
  As an operator running an EVPN E-Tree over an SRv6 core with zebra-rs
  I want each PE's leaf argument advertised and imported through BGP
  So that a leaf's broadcast reaches the roots on the other PE but never its
  leaves, with no static arguments, SIDs or slots anywhere.

  `cradle_evpn_etree_srv6` proves the datapath with static configuration.
  Here zebra-rs drives it (E-Tree plan phase 5b, decision D6). With a leaf
  AC under `encapsulation srv6`, zebra-rs:
  - gives this PE leaf argument 1 and tees it to cradle for decap
    (`SetEtreeLeafArg`);
  - installs the leaf VNI's End.DT2M at LOC:FUNC with a 16-bit argument
    (`LocalSid.arg_bits`) and advertises the argument length on its IMET;
  - advertises the argument in an ESI-0 Ethernet A-D route (the E-Tree EC,
    and an End.DT2M SID with the argument after the function, RFC 9819);
  - turns the other PE's argument and End.DT2M SID into a leaf slot toward
    it (`AddReplSlot.etree_leaf_sid`).

  Topology: `cradle_evpn_srv6_zebra` (IS-IS SRv6, iBGP over loopbacks,
  locators fcbb:bbbb:N::/48 in uSID form) with a leaf and a root host on
  each PE. The access ports are in br100 with vxlan100, which is how
  zebra-rs knows their VNI. IPv6 is off everywhere but the underlay port
  and the loopback: MLD and neighbour discovery are BUM too.
  ```
   l1 (leaf) ─ pe1l ┐                                           ┌ pe2l ─ l2 (leaf)
   r1 (root) ─ pe1r ┴ pe1 ──2001:db8:0:12::/64── pe2 ┴ pe2r ─ r2 (root)
                    lo 2001:db8::1        lo 2001:db8::2
   hosts 10.0.0.0/24, bd 100 / VNI 100
  ```
  tc counters on l2's eth0 count what l2 receives from l1 (pref 1) and from
  r1 (pref 2).

  Scenario: Each PE advertises a leaf argument and builds a leaf slot from the other's
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "r1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1" in namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l"
    And I connect namespace "r1" interface "eth0" to namespace "pe1" interface "pe1r"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2l" to namespace "l2" interface "eth0"
    And I connect namespace "pe2" interface "pe2r" to namespace "r2" interface "eth0"
    And I execute "sysctl -q -w net.ipv6.conf.pe1u.disable_ipv6=0" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.pe2u.disable_ipv6=0" in namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l2"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:01" in namespace "l1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:02" in namespace "r1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:02" in namespace "r2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.12/24" to interface "eth0" in namespace "r1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 2 flower src_mac 02:00:00:00:e1:02 action pass" in namespace "l2"
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1" with feature "etree"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2" with feature "etree"
    And I wait 3 seconds
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set pe1l master br100" in namespace "pe1"
    And I execute "ip link set pe1r master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set pe2l master br100" in namespace "pe2"
    And I execute "ip link set pe2r master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8::2" should be "Established"
    # Each PE's leaf argument crossed in BGP.
    And show command "show bgp evpn etree" in namespace "pe1" should eventually contain "Leaf argument:   1"
    And show command "show bgp evpn etree" in namespace "pe1" should eventually contain "2001:db8::2      1 (16 bits)"
    And show command "show bgp evpn etree" in namespace "pe2" should eventually contain "2001:db8::1      1 (16 bits)"
    # Roots reach each other, and each leaf the root on the other PE: the
    # leaves' ARP broadcasts cross through the leaf slots.
    And ping from "r1" to "10.0.0.22" should eventually succeed
    And ping from "l1" to "10.0.0.22" should eventually succeed
    And ping from "l2" to "10.0.0.12" should eventually succeed
    And the cradle stat "srv6_l2_leaf_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_l2_leaf_decap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_drop_arg" in namespace "pe1" via gRPC as "ctl1" should be zero

  Scenario: A leaf's broadcast reaches the remote root but not the remote leaf; a root's reaches both
    Given the test topology exists
    When I record the cradle stat "srv6_l2_leaf_decap" in namespace "pe2" via gRPC as "ctl2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "srv6_l2_leaf_decap" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"
    When I execute "tc filter del dev eth0 ingress pref 2" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 2 flower src_mac 02:00:00:00:e1:02 action pass" in namespace "l2"
    And I execute "ip neigh flush dev eth0" in namespace "r1"
    Then ping from "r1" to "10.0.0.21" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 2" in namespace "l2" should eventually not contain "Sent 0 bytes 0 pkt"

  Scenario: A leaf's known unicast to the remote leaf is dropped at its own PE
    Given the test topology exists
    # l2's MAC is advertised as a leaf (zebra-rs colours the Type-2), so pe1
    # drops l1's unicast to it before encapsulation.
    When I execute "ip neigh replace 10.0.0.21 lladdr 02:00:00:00:e2:01 dev eth0 nud permanent" in namespace "l1"
    And I record the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1"
    Then the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "etree-leaf"
    And ping from "l1" to "10.0.0.21" should fail
    And the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "l1"
    And I delete namespace "r1"
    And I delete namespace "l2"
    And I delete namespace "r2"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
