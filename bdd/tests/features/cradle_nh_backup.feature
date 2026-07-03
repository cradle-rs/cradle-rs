@serial
@cradle_nh_backup
Feature: Protected nexthops fail over on link-down in the eBPF data plane
  As an operator running fast-reroute on cradle
  I want a nexthop with a backup to switch over when its link dies
  So that traffic keeps flowing within the link monitor's event latency,
  before any control-plane reconvergence.

  s's route to c2's subnet uses nexthop 1 (via n) protected by nexthop 2
  (via r): `resolve_nh` swaps to the backup while `LINK_DOWN` holds the
  primary's ifindex — fed by the `ip monitor link` watcher. The return
  path is pinned via r throughout, so killing the s—n link breaks exactly
  the protected direction.

  Topology (kernel forwarding off everywhere; all-static config):
  ```
   c1 ── s ──10.0.12.0/24── n ──10.0.23.0/24── d ── c2
          └──10.0.14.0/24── r ──10.0.34.0/24──┘
  ```

  Scenario: Traffic survives the primary link dying
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "c2"
    And I create namespace "s"
    And I create namespace "n"
    And I create namespace "r"
    And I create namespace "d"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "c2" interface "eth0" to namespace "d" interface "dc"
    And I connect namespace "s" interface "sn" to namespace "n" interface "ns"
    And I connect namespace "s" interface "sr" to namespace "r" interface "rs"
    And I connect namespace "n" interface "nd" to namespace "d" interface "dn"
    And I connect namespace "r" interface "rd" to namespace "d" interface "dr"
    And I execute "ip link set dev ns address 02:00:00:00:0a:01" in namespace "n"
    And I execute "ip link set dev rs address 02:00:00:00:0b:01" in namespace "r"
    And I execute "ip link set dev dn address 02:00:00:00:0c:01" in namespace "d"
    And I execute "ip link set dev sn address 02:00:00:00:0d:01" in namespace "s"
    And I execute "ip link set dev dr address 02:00:00:00:0e:01" in namespace "d"
    And I execute "ip link set dev sr address 02:00:00:00:0f:01" in namespace "s"
    And I execute "ip link set dev rd address 02:00:00:00:10:01" in namespace "r"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add address "10.0.1.254/24" to interface "sc" in namespace "s"
    And I add address "10.0.12.1/24" to interface "sn" in namespace "s"
    And I add address "10.0.14.1/24" to interface "sr" in namespace "s"
    And I add address "10.0.12.2/24" to interface "ns" in namespace "n"
    And I add address "10.0.23.1/24" to interface "nd" in namespace "n"
    And I add address "10.0.14.2/24" to interface "rs" in namespace "r"
    And I add address "10.0.34.1/24" to interface "rd" in namespace "r"
    And I add address "10.0.23.2/24" to interface "dn" in namespace "d"
    And I add address "10.0.34.2/24" to interface "dr" in namespace "d"
    And I add address "10.0.2.254/24" to interface "dc" in namespace "d"
    And I add route "default" via "10.0.1.254" in namespace "c1"
    And I add route "default" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "n"
    And I disable IPv4 forwarding in namespace "r"
    And I disable IPv4 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "n" with config "n.json" serving gRPC as "ctl2"
    And I start cradle in namespace "r" with config "r.json" serving gRPC as "ctl3"
    And I start cradle in namespace "d" with config "d.json" serving gRPC as "ctl4"
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    # Kill the primary from the far side: s sees carrier loss
    # (LOWERLAYERDOWN), the monitor marks the link, resolve_nh swaps to the
    # backup via r.
    When I execute "ip link set ns down" in namespace "n"
    And I wait 2 seconds
    Then ping from "c1" to "10.0.2.1" should eventually succeed
    And the cradle stat "nh_backup" in namespace "s" via gRPC as "ctl1" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "s"
    And I stop cradle in namespace "n"
    And I stop cradle in namespace "r"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "s"
    And I delete namespace "n"
    And I delete namespace "r"
    And I delete namespace "d"
    Then the test environment should be clean
