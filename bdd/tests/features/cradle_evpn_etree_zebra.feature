@serial
@cradle_evpn_etree_zebra
Feature: EVPN E-Tree over a zebra-rs-driven VXLAN fabric (RFC 8317)
  As an operator running an EVPN E-Tree on cradle under zebra-rs
  I want the leaf roles and the remote MACs' leaf flags to come from BGP
  So that a leaf never sends known unicast to a leaf on another PE, a leaf
  still reaches every root, and a host that moves from a leaf AC to a root
  AC becomes reachable from the leaves.

  `cradle_evpn_etree` proves the datapath with static configuration. Here
  zebra-rs drives it, with `etree leaf-interface` on each PE (which needs
  zebra-rs's `--feature etree`):
  - zebra-rs sends each leaf role to cradle (`SetEtreeRole`);
  - it advertises the Type-2 of every MAC cradle learns on a leaf AC with
    the E-Tree community's Leaf-Indication flag;
  - the receiving PE installs that MAC with `FdbRemote.etree_leaf`, and
    cradle drops a leaf's known unicast toward it before encapsulation.

  Known unicast is the half a leaf's flag gates on its own. A leaf's
  broadcast still reaches leaves on the other PE, so the leaf hosts get
  static ARP entries for each other: without them the ARP reply, which is
  leaf to leaf too, would be dropped and no unicast would ever be sent.

  ```
   l1 (leaf) ─ pe1l ┐                                    ┌ pe2l ─ l2 (leaf)
   r1 (root) ─ pe1r ┴ pe1 ──10.0.12.0/24── pe2 ┼ pe2r ─ r2 (root)
                VTEP 192.0.2.1      VTEP 192.0.2.2   └ pe2m ─ m (root; dark)
   hosts 10.0.0.0/24 in VNI 100
  ```

  Scenario: Setup — leaves reach the roots on the other PE
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "r1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "m"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l"
    And I connect namespace "r1" interface "eth0" to namespace "pe1" interface "pe1r"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2l" to namespace "l2" interface "eth0"
    And I connect namespace "pe2" interface "pe2r" to namespace "r2" interface "eth0"
    And I connect namespace "pe2" interface "pe2m" to namespace "m" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:01" in namespace "l1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:02" in namespace "r1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:02" in namespace "r2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.12/24" to interface "eth0" in namespace "r1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    # l2's host moves to m later; until then m is dark.
    And I execute "ip link set eth0 down" in namespace "m"
    And I execute "ip neigh replace 10.0.0.21 lladdr 02:00:00:00:e2:01 dev eth0 nud permanent" in namespace "l1"
    And I execute "ip neigh replace 10.0.0.11 lladdr 02:00:00:00:e1:01 dev eth0 nud permanent" in namespace "l2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1" with feature "etree"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2" with feature "etree"
    And I wait 3 seconds
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "192.0.2.2" should be "Established"
    # Root to root, and each leaf to the root on the other PE (both ways:
    # the reply is root to leaf). This also teaches both PEs every MAC.
    And ping from "r1" to "10.0.0.22" should eventually succeed
    And ping from "l1" to "10.0.0.22" should eventually succeed
    And ping from "l2" to "10.0.0.12" should eventually succeed
    And the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "l2_drop_etree_uc" in namespace "pe2" via gRPC as "ctl2" should be zero

  Scenario: Each PE installs the other's leaf MAC with the leaf flag
    Given the test topology exists
    # Only l2 is a leaf MAC behind pe2, and only l1 behind pe1.
    Then the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "02:00:00:00:e2:01"
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should contain "remote,vxlan,etree-leaf"
    And the cradle dump "l2" in namespace "pe2" via gRPC as "ctl2" should contain "remote,vxlan,etree-leaf"

  Scenario: A leaf's known unicast to a leaf on the other PE is dropped at its own PE
    Given the test topology exists
    When I record the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1"
    And I record the cradle stat "l2_drop_etree_uc" in namespace "pe2" via gRPC as "ctl2"
    Then ping from "l1" to "10.0.0.21" should fail
    And ping from "l2" to "10.0.0.11" should fail
    # Each PE dropped its own leaf's frames before encapsulating them.
    And the cradle stat "l2_drop_etree_uc" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value
    And the cradle stat "l2_drop_etree_uc" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value

  Scenario: A host moving from a leaf AC to a root AC becomes reachable from the leaves
    Given the test topology exists
    # l2's host (same MAC, same address) moves to pe2's root port pe2m. pe2
    # learns it there, re-advertises its Type-2 without the leaf flag, and
    # pe1 re-installs it as a root MAC.
    When I execute "ip link set eth0 down" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "m"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "m"
    And I execute "ip link set eth0 up" in namespace "m"
    Then ping from "m" to "10.0.0.22" should eventually succeed
    And the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should eventually not contain "etree-leaf"
    And ping from "l1" to "10.0.0.21" should eventually succeed

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
    And I delete namespace "m"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
