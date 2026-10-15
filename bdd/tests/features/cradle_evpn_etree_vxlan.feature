@serial
@cradle_evpn_etree_vxlan
Feature: EVPN E-Tree over VXLAN — leaf-only PEs keep a leaf's BUM from leaves
  As an operator running an EVPN E-Tree over a VXLAN fabric
  I want a broadcast, multicast or unknown-unicast frame from a leaf AC
  never to reach a leaf AC on another PE, where the PEs' roles make that
  decidable
  So that leaves stay apart across the core for BUM, not only unicast.

  VXLAN carries no label for a leaf mark, and there is no standard. This
  is the V1+ scheme of zebra-rs's E-Tree plan §8.5: a PE whose ACs in a
  bridge domain are all leaves says so on its IMET (the E-Tree EC), and
  cradle is told per (bridge domain, VTEP) by `SetEtreeRemote`.
  - **Egress.** VXLAN BUM from a leaf-only PE is leaf-originated, so decap
    marks it (`VTEP_ETREE`) and the flood keeps it off local leaf ports
    (`l2_drop_etree_bum`).
  - **Ingress.** A leaf-only PE has no root to deliver a leaf's BUM to, so
    the slot toward it serves roots only, and a local leaf's flood leaves
    it out.
  Between two PEs that both have roots and leaves (mixed), a leaf's BUM
  still reaches the other's leaves. V1+ cannot tell it apart from a root's.

  Topology: pe1 is leaf-only (one leaf host), pe2 is mixed (a leaf and a
  root host). Static VXLAN, VNI 10100 = bd 100, loopback VTEPs.
  ```
   l1 (leaf) ─ pe1l ─ pe1 ──10.12.0.0/24── pe2 ┬ pe2l ─ l2 (leaf)
                     192.0.2.1          192.0.2.2 └ pe2r ─ r2 (root)
   hosts 10.0.0.0/24
  ```
  pe2's slot toward pe1 is marked root-only in its startup config (it only
  matters once there are leaves). tc counters on l1 and l2 count what each
  receives from the other leaf.

  Scenario: Without leaf roles each leaf's broadcast reaches the other
    Given a clean test environment
    When I create namespace "l1"
    And I create namespace "l2"
    And I create namespace "r2"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I connect namespace "l1" interface "eth0" to namespace "pe1" interface "pe1l"
    And I connect namespace "l2" interface "eth0" to namespace "pe2" interface "pe2l"
    And I connect namespace "r2" interface "eth0" to namespace "pe2" interface "pe2r"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "l2"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "r2"
    And I execute "ip link set dev pe1u address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e1:01" in namespace "l1"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:01" in namespace "l2"
    And I execute "ip link set dev eth0 address 02:00:00:00:e2:02" in namespace "r2"
    And I execute "ip link add r12a type veth peer name r12b" in namespace "pe1"
    And I execute "ip link set r12a up" in namespace "pe1"
    And I execute "ip link set r12b up" in namespace "pe1"
    And I execute "ip link add r21a type veth peer name r21b" in namespace "pe2"
    And I execute "ip link set r21a up" in namespace "pe2"
    And I execute "ip link set r21b up" in namespace "pe2"
    And I add address "10.0.0.11/24" to interface "eth0" in namespace "l1"
    And I add address "10.0.0.21/24" to interface "eth0" in namespace "l2"
    And I add address "10.0.0.22/24" to interface "eth0" in namespace "r2"
    And I add address "10.12.0.1/24" to interface "pe1u" in namespace "pe1"
    And I add address "10.12.0.2/24" to interface "pe2u" in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l1"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e2:01 action pass" in namespace "l1"
    And I execute "tc qdisc add dev eth0 clsact" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And ping from "l2" to "10.0.0.11" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should eventually not contain "Sent 0 bytes 0 pkt"
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l1" should eventually not contain "Sent 0 bytes 0 pkt"
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should be zero

  Scenario: A leaf-only PE's broadcast is kept off the remote leaf at the egress PE
    Given the test topology exists
    When I apply cradle config "pe1-etree.json" to namespace "pe1" via gRPC as "ctl1"
    And I apply cradle config "pe2-etree.json" to namespace "pe2" via gRPC as "ctl2"
    And I record the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2"
    And I execute "tc filter del dev eth0 ingress pref 1" in namespace "l2"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e1:01 action pass" in namespace "l2"
    And I execute "ip neigh flush dev eth0" in namespace "l1"
    # l1's ARP for r2 crosses to pe2, which floods it to r2 but not to l2.
    Then ping from "l1" to "10.0.0.22" should eventually succeed
    And the cradle stat "l2_drop_etree_bum" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l2" should contain "Sent 0 bytes 0 pkt"

  Scenario: A leaf's broadcast is not sent to a leaf-only PE at all
    Given the test topology exists
    When I execute "tc filter del dev eth0 ingress pref 1" in namespace "l1"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:e2:01 action pass" in namespace "l1"
    And I execute "ip neigh flush dev eth0" in namespace "l2"
    And I record the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2"
    # l2's ARP for l1 reaches r2 locally and nothing else: pe1 has no root.
    Then ping from "l2" to "10.0.0.11" should fail
    And the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2" should still equal its recorded value
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "l1" should contain "Sent 0 bytes 0 pkt"

  Scenario: A root's broadcast still reaches the leaf-only PE
    Given the test topology exists
    When I record the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev eth0" in namespace "r2"
    Then ping from "r2" to "10.0.0.11" should eventually succeed
    And the cradle stat "vxlan_flood" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "l1"
    And I delete namespace "l2"
    And I delete namespace "r2"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
