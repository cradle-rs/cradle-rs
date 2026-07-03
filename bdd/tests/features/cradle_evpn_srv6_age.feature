@serial
@cradle_evpn_srv6_age
Feature: FDB aging expires idle MACs and withdraws their EVPN Type-2 routes
  As an operator running a dynamic EVPN-over-SRv6 L2VPN on cradle
  I want idle locally-learned MACs to age out of the eBPF FDB
  So that departed stations stop being advertised (Type-2 withdrawn via the
  WatchFdb age event) and returning traffic re-learns and re-converges.

  The datapath stamps every learn with ktime (`FdbEntry.last_seen`, refreshed
  per frame); a user-space sweep expires local entries idle past
  `fdb_age_secs` (5s here; 300s default) and bumps `fdb_aged`. WatchFdb
  subscribers see the disappearance and emit an age event; zebra re-emits it
  as an FdbDel, withdrawing the Type-2 — the remote PE's overlay FDB entry
  is removed by the existing MacDel tee. A later frame re-learns,
  re-advertises, and the L2VPN reconverges by itself.

  Topology: the 2-PE dynamic EVPN (same as cradle_evpn_srv6_zebra) with a 5s
  age. IPv6 is disabled on the CE NICs so the links are genuinely idle
  between pings (no ND/MLD chatter refreshing the entries).
  ```
   c1 ── pe1[cradle+zebra] ──2001:db8:0:12::/64── pe2[cradle+zebra] ── c2
    bd 100 / VNI 100, fdb_age_secs 5, encapsulation srv6      bd 100 / VNI 100
  ```

  Scenario: Idle MACs age out, Type-2s withdraw, traffic reconverges
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "pe1" interface "pe1u" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe2" interface "pe2c" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:02" in namespace "c2"
    And I execute "sysctl -w net.ipv6.conf.eth0.disable_ipv6=1" in namespace "c1"
    And I execute "sysctl -w net.ipv6.conf.eth0.disable_ipv6=1" in namespace "c2"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    And I add address "10.0.0.2/24" to interface "eth0" in namespace "c2"
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
    # Idle past the 5s age (plus sweep + watch latency): the learned CE MACs
    # expire, the sweep bumps fdb_aged, and the age events withdraw the
    # Type-2s on both PEs.
    When I wait 15 seconds
    Then the cradle stat "fdb_aged" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "fdb_aged" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # Fresh traffic re-learns, re-advertises, and reconverges on its own.
    And ping from "c1" to "10.0.0.2" should eventually succeed
    And ping from "c2" to "10.0.0.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "c1"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "c2"
    Then the test environment should be clean
