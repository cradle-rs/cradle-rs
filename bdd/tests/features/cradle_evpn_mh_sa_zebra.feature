@serial
@cradle_evpn_mh_sa_zebra
Feature: BGP EVPN single-active multihoming drives the standby port block
  As an operator dual-homing a CE to two zebra-rs PEs in single-active mode
  I want the PE that loses the DF election to block its segment port in
  both directions
  So that the CE's traffic rides the Designated Forwarder alone.

  The single-active twin of cradle_evpn_mh_df_zebra: pe2 and pe3 configure
  ES-1 with `redundancy-mode single-active`. The carving picks pe2 as DF
  for VNI 100; zebra tees `SetEsRole{df: false, single_active: true}` to
  pe3, whose segment port cradle then blocks both ways (`ES_DF_F_BLOCK`,
  `l2_drop_sa`). The per-ES A-D routes carry a single-active ESI-label EC,
  so pe1 forms no aliasing group for the segment and sends the CE's MAC
  to its advertiser — the DF — alone.
  ```
        c1 ── pe1[cradle+zebra] ──10.0.12.0/24── pe2[cradle+zebra] ──pe2c── eth0 ┐
   bd 100         │  VTEP 192.0.2.1              VTEP .2 (DF, active)          ce bond0
                  └────10.0.13.0/24── pe3[cradle+zebra] ──pe3c── eth1 ┘   active-backup
                                       VTEP .3 (standby)                (ES-1, single-active)
  ```
  The CE is an active-backup LAG on the DF's leg, receiving on both.

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
    # The DF (pe2) carries the CE; pe1 aliases nothing under single-active.
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be zero
    And the cradle stat "l2_drop_sa" in namespace "pe2" via gRPC as "ctl2" should be zero
    # The standby (pe3) blocks inward: flip the CE's active leg to it and
    # its frames are dropped before anything is learned from them.
    When I execute "ip link set bond0 type bond primary eth1" in namespace "ce"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should fail
    And the cradle stat "l2_drop_sa" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    When I execute "ip link set bond0 type bond primary eth0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    # Failover: take the DF away. pe3 re-elects itself DF, zebra clears the
    # block, the CE (now active on pe3's leg) is reachable again.
    When I stop the zebra-rs tee in namespace "pe2"
    And I wait 3 seconds
    And I execute "ip link set bond0 type bond primary eth1" in namespace "ce"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    Then ping from "ce" to "10.0.0.1" should eventually succeed

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
