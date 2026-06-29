@serial
@cradle_bgp
Feature: BGP-learned route programs the eBPF FIB
  An eBGP peer advertises a prefix; the forwarder's zebra-rs learns it via BGP
  and tees the install to cradle, so a BGP-learned route forwards in eBPF.

  Topology:
  ```
   cl(10.0.1.1) ─ fwd1 [ cradle + zebra-rs AS65001 ] fwd2 ─ peer(10.0.2.2, AS65002)
                                                            originates 10.9.9.0/24, hosts 10.9.9.1
  ```

  Scenario: A BGP-learned route forwards via the eBPF data plane
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "peer"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "peer" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.2.2/24" to interface "eth0" in namespace "peer"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add address "10.9.9.1/24" to interface "lo" in namespace "peer"
    And I add route "default" via "10.0.1.254" in namespace "cl"
    And I add route "default" via "10.0.2.254" in namespace "peer"
    And I disable IPv4 forwarding in namespace "fwd"
    And I start cradle in namespace "fwd" with config "ports.json" serving gRPC as "ctl"
    Then ping from "cl" to "10.9.9.1" should fail
    When I start zebra-rs in namespace "peer" with config "peer.yaml"
    And I start zebra-rs in namespace "fwd" with config "fwd.yaml" teeing to cradle as "ctl"
    Then ping from "cl" to "10.9.9.1" should eventually succeed

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "fwd"
    And I stop zebra-rs in namespace "peer"
    And I stop cradle in namespace "fwd"
    And I delete namespace "cl"
    And I delete namespace "peer"
    And I delete namespace "fwd"
    Then the test environment should be clean
