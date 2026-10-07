@serial
@cradle_evpn_mh_sa_role_zebra
Feature: EVPN single-active — the DF moves because the ROLE moved
  As an operator dual-homing a CE to two zebra-rs PEs in single-active mode
  I want known unicast to follow the Designated Forwarder when the ELECTION
  changes — no link down, no route withdrawn, every MAC still where it was —
  so a planned change of forwarder costs one attribute update rather than a
  relearn.

  The difference from cradle_evpn_mh_sa_zebra, which is the same topology: that
  feature moves the traffic by failing the DF's port, so the mass withdraw
  (RFC 7432 §8.2) does the work — pe2's ES routes vanish and pe1 has no choice
  but to use pe3. Here nothing is withdrawn. pe3 is simply given the better
  preference, so the election moves and the two PEs re-advertise their roles in
  the Layer-2 Attributes extended community of their per-EVI A-D
  (draft-ietf-bess-rfc7432bis §7.11.1). pe2's Type-2 for the CE's MAC is still
  in pe1's table throughout, so the ONLY thing that can have re-pointed the
  traffic is the signal.

  That is the datapath half of what zebra-rs phases 3a/3b built: the signal is
  advertised and consumed, and here it is shown to actually move frames.

  ```
        c1 ── pe1[cradle+zebra] ──10.0.12.0/24── pe2[cradle+zebra] ──pe2c── eth0 ┐
                                                   pref 200 → non-DF            bond0 ── ce
                  └────10.0.13.0/24── pe3[cradle+zebra] ──pe3c── eth1 ┘   active-backup
                                        pref 100 → 300 → DF
  ```

  Scenario: The BGP-elected DF alone carries the CE; the standby blocks
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe3"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "ce" interface "eth0" to namespace "pe2" interface "pe2c"
    And I connect namespace "ce" interface "eth1" to namespace "pe3" interface "pe3c"
    And I connect namespace "pe1" interface "pe1u2" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe1" interface "pe1u3" to namespace "pe3" interface "pe3u"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "ce"
    And I execute "ip link add bond0 type bond mode active-backup all_slaves_active 1" in namespace "ce"
    And I execute "ip link set bond0 address 02:00:00:00:ce:02" in namespace "ce"
    And I execute "ip link set eth0 down" in namespace "ce"
    And I execute "ip link set eth1 down" in namespace "ce"
    And I execute "ip link set eth0 master bond0" in namespace "ce"
    And I execute "ip link set eth1 master bond0" in namespace "ce"
    And I execute "ip link set bond0 type bond primary eth0" in namespace "ce"
    And I execute "ip link set eth0 up" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "ip link set bond0 up" in namespace "ce"
    And I add address "10.0.0.2/24" to interface "bond0" in namespace "ce"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe3"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe3"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe3" with config "ports-pe3.json" serving gRPC as "ctl3"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "pe3" with config "pe3.yaml" teeing to cradle as "ctl3"
    And I wait 3 seconds
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set pe2c master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I execute "ip link add br100 type bridge" in namespace "pe3"
    And I execute "ip link set vxlan100 master br100" in namespace "pe3"
    And I execute "ip link set pe3c master br100" in namespace "pe3"
    And I execute "ip link set br100 up" in namespace "pe3"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "192.0.2.2" should be "Established"
    And BGP session in "pe1" to "192.0.2.3" should be "Established"
    And BGP session in "pe2" to "192.0.2.3" should be "Established"
    # The DF (pe2) carries the CE. pe1's group for the segment is
    # single-active — primary pe2, backup pe3 pre-installed — and known
    # unicast to the CE rides it (slot 0, never hashed).
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And show command "show bgp evpn ethernet-segment" in namespace "pe1" should eventually contain "00:00:00:00:00:00:00:00:00:01 bd 100: single-active primary 192.0.2.2, backup 192.0.2.3"
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "l2_drop_sa" in namespace "pe2" via gRPC as "ctl2" should be zero

  Scenario: Raising the standby's preference moves the forwarder, not the routes
    Given the test topology exists
    # Both PEs signal their role, so pe1 reads the forwarder rather than
    # inferring it from which PE advertised the MAC.
    Then show command "show bgp evpn ethernet-segment" in namespace "pe1" should contain "(signalled)"
    When I record the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1"
    And I record the cradle stat "l2_drop_sa" in namespace "pe2" via gRPC as "ctl2"
    # The only change: pe3 outranks pe2. No interface is touched and no route
    # is withdrawn anywhere.
    And I apply config "pe3-pref.yaml" to namespace "pe3"
    Then show command "show bgp evpn ethernet-segment" in namespace "pe1" should eventually contain "00:00:00:00:00:00:00:00:00:01 bd 100: single-active primary 192.0.2.3, backup 192.0.2.2"
    And show command "show bgp evpn ethernet-segment" in namespace "pe1" should contain "(signalled)"
    # The discriminator: pe2's Type-2 for the CE is still there, still valid.
    # In the port-down twin this route's PE had withdrawn its ES routes; here
    # nothing was withdrawn, so a group that re-pointed did so on the signal.
    And show command "show bgp evpn" in namespace "pe1" should contain "[2]:[0]:[48]:[02:00:00:00:ce:02]"
    # pe2 is now the standby and blocks both directions, so the CE's frames on
    # the leg toward it are dropped before anything is learned from them.
    When I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should fail
    And the cradle stat "l2_drop_sa" in namespace "pe2" via gRPC as "ctl2" should exceed its recorded value
    # Flip the CE onto the new forwarder's leg (active-backup, no link monitor)
    # and the segment carries traffic again — through pe3 this time.
    When I execute "ip link set bond0 type bond primary eth1" in namespace "ce"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "ce" to "10.0.0.1" should eventually succeed
    # ... and it rode the segment's nexthop group to get there.
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should exceed its recorded value

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop the zebra-rs tee in namespace "pe3"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I stop cradle in namespace "pe3"
    And I delete namespace "c1"
    And I delete namespace "ce"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "pe3"
    Then the test environment should be clean
