@serial
@cradle_color_bsid_zebra
Feature: BGP color steering to a BSID programs the cradle eBPF data plane
  As an operator running SR Policy color steering (RFC 9256 §8.5)
  I want a colored service route steered onto its policy's Binding SID
  So that the chain holds end to end in the data plane: controller candidate
  path -> iBGP sr-policy-v4 -> headend policy selection + `steering-mode
  binding-sid` -> the colored service route's nexthop imposes the SR-MPLS BSID
  label -> FIB tee -> cradle eBPF (the BSID ILM and the steered service route
  both land in cradle's maps).

  Topology (iBGP AS 65000 over one link):
  ```
   ctrl[zebra]  ── 192.168.12.0/24 ──  h[zebra + cradle]
   originates SR Policy DETOUR             consumes it (RT=10.0.0.1), owns the
   (color 100, endpoint 192.168.12.2,      BSID ILM 16100->{16002}, and steers
   binding-sid 16100, seg {16002})         the colored 10.99.0.0/24 onto it
   + originates 10.99.0.0/24
  ```

  Scenario: A colored route is steered onto its Binding SID in the eBPF FIB
    Given a clean test environment
    When I create namespace "ctrl"
    And I create namespace "h"
    And I connect namespace "h" interface "bc" to namespace "ctrl" interface "cb"
    And I execute "ip link set dev bc address 02:00:00:00:0b:01" in namespace "h"
    And I execute "ip link set dev cb address 02:00:00:00:0c:01" in namespace "ctrl"
    And I disable IPv4 forwarding in namespace "h"
    When I start cradle in namespace "h" with config "ports-h.json" serving gRPC as "ctl1"
    And I start zebra-rs in namespace "h" with config "h.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "ctrl" with config "ctrl.yaml"
    # The policy must arrive over SAFI 73 and be selected in binding-sid mode.
    Then show command "show bgp sr-policy" in namespace "h" should eventually contain "endpoint 192.168.12.2"
    And show command "show bgp sr-policy" in namespace "h" should contain "binding-sid: MPLS 16100"
    # COLOR100 is attached inbound from startup, so 10.99.0.0/24 arrives
    # already coloured. If it arrived before the SAFI-73 policy it installed
    # plain; when the Binding SID activates the headend re-installs the
    # colour-matched winner, steering it onto the BSID label 16100 in
    # binding-sid mode (RFC 9256 §8.5) — no manual re-evaluation needed.
    Then show command "show ip route 10.99.0.0/24" in namespace "h" should eventually contain "label 16100"
    # Datapath proof: the steered service route's nexthop imposes the BSID label
    # 16100 in cradle's eBPF FIB. `[16100]` on a nexthop appears only when a
    # route is steered onto the BSID — the BSID's own ILM nexthop imposes its
    # swap target [16002], not [16100]. This is the color-steer reaching the
    # data plane, not just zebra's RIB.
    And the cradle dump "nexthop" in namespace "h" via gRPC as "ctl1" should contain "[16100]"
    And the cradle dump "ipv4" in namespace "h" via gRPC as "ctl1" should contain "10.99.0.0/24"
    # The BSID's own ILM (16100 -> swap {16002}) is teed into cradle's eBPF LFIB.
    And the cradle dump "mpls" in namespace "h" via gRPC as "ctl1" should contain "16100"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "h"
    And I stop zebra-rs in namespace "ctrl"
    And I stop cradle in namespace "h"
    And I delete namespace "ctrl"
    And I delete namespace "h"
    Then the test environment should be clean
