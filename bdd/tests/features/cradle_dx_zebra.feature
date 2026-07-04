@serial
@cradle_dx_zebra
Feature: zebra static End.DX4/DX6 actions program eBPF cross-connects
  As an operator configuring per-CE SRv6 egress statically
  I want config-static `action End.DX6 nh6 …` / `action End.DX4 nh4 …`
  to become live eBPF state
  So that the whole chain holds: static seg6local action routes —
  which install as route-embedded encaps and never pass the SID
  registry — now tee to cradle as local SIDs with their cross-connect
  adjacency, and the eBPF datapath decapsulates + hands the inner
  packet straight to the CE.

  d has NO forward routes toward c2 in any table — only the DX SIDs'
  adjacencies — so the pings only work if the cross-connect ran.
  Kernel v4+v6 forwarding off on s/d, seg6 never enabled.

  Topology:
  ```
   c1 ── s[cradle] ─2001:db8:1::/64 + 10.0.12.0/24─ d[zebra+cradle] ── c2
   fc00:1::/64                                                  fc00:2::/64
   10.0.1.0/24                                                  10.0.2.0/24
  ```

  Scenario: Static DX actions cross-connect both families through the tee
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "d"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "d" interface "ds"
    And I connect namespace "d" interface "dc" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev ds address 02:00:00:00:0a:01" in namespace "d"
    And I execute "ip link set dev dc address 02:00:00:00:c2:ff" in namespace "d"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "10.0.1.254/24" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "10.0.12.1/24" to interface "sp" in namespace "s"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "0.0.0.0/0" via "10.0.1.254" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I add route "0.0.0.0/0" via "10.0.2.254" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "d" with config "ports-d.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "d" with config "d.yaml" teeing to cradle as "ctl2"
    # End.DX6 via the static tee: decap + v6 cross-connect to c2.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_dx" in namespace "d" via gRPC as "ctl2" should be nonzero
    # End.DX4 via the static tee: decap + v4 cross-connect.
    Then ping from "c1" to "10.0.2.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "d"
    And I stop cradle in namespace "s"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "d"
    And I delete namespace "c2"
    Then the test environment should be clean
