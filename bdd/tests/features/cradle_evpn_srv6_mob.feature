@serial
@cradle_evpn_srv6_mob
Feature: MAC mobility moves a station between PEs (RFC 7432 §7.7)
  As an operator running a dynamic EVPN-over-SRv6 L2VPN on cradle
  I want a station (VM) that moves between PEs to reconverge automatically
  So that its MAC is re-advertised with a higher Mobility sequence number,
  the previous owner withdraws, and traffic follows — same MAC, same IP,
  no manual state anywhere.

  The move machinery: at the NEW PE, the datapath learn overwrites the
  remote FDB entry with a local one → WatchFdb reports it → zebra
  originates the Type-2 with the MAC Mobility extended community
  (seq = max remote + 1), which every PE prefers over the stale route. At
  the OLD PE, installing the new remote entry flips its local entry →
  WatchFdb reports the disappearance → the old Type-2 is withdrawn. A
  remote withdraw never clobbers a fresh local learn (fdb_remote_del is
  local-guarded), so rapid moves don't churn.

  Topology: the 2-PE dynamic EVPN with a second CE port on pe2 hosting the
  mobile station's new location. Station M = 02:00:00:00:c1:01 / 10.0.0.1
  starts at c1 (behind pe1) and "migrates" to cm (behind pe2), then back.
  ```
   c1 ── pe1[cradle+zebra] ──2001:db8:0:12::/64── pe2[cradle+zebra] ──┬── c2
    M, 10.0.0.1     LOC1 fcbb:bbbb:1::/48      LOC2 fcbb:bbbb:2::/48  └── cm (M's new home)
  ```

  Scenario: A station migrates PE1 → PE2 → PE1 and traffic follows
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "c2"
    And I create namespace "cm"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I connect namespace "pe2" interface "pe2c2" to namespace "cm" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:02" in namespace "c2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
    # The station's future home is dark until the migration.
    And I execute "ip link set eth0 down" in namespace "cm"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I wait 3 seconds
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8::2" should be "Established"
    And ping from "c1" to "10.0.0.2" should eventually succeed
    # ── Migrate M to pe2 (VM move: same MAC, same IP, new port) ──
    When I execute "ip link set eth0 down" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "cm"
    And I execute "ip link set eth0 up" in namespace "cm"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "cm"
    # M's first frames make pe2 learn it locally, originate the Type-2 with
    # Mobility seq 1, and pe1 flips + withdraws.
    Then ping from "cm" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed
    # ── Migrate M back to pe1 (seq 2) ──
    When I execute "ip link set eth0 down" in namespace "cm"
    And I execute "ip link set eth0 up" in namespace "c1"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "c2"
    And I delete namespace "cm"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    Then the test environment should be clean
