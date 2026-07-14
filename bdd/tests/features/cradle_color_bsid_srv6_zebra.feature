@serial
@cradle_color_bsid_srv6_zebra
Feature: BGP color steering to an SRv6 Binding SID programs the cradle eBPF data plane
  As an operator running SR Policy color steering (RFC 9256 §8.5)
  I want a colored service route steered onto its policy's SRv6 Binding SID
  So that the chain holds end to end in the data plane: controller candidate
  path -> iBGP sr-policy-v6 -> headend policy selection + `steering-mode
  binding-sid` -> the colored service route H.Encaps toward the End.B6.Encaps
  BSID -> FIB tee -> cradle eBPF (the BSID local SID and the steered service
  route both land in cradle's maps).

  Topology (iBGP AS 65000 over one link):
  ```
   ctrl[zebra]  ── 2001:db8:9::/64 ──  h[zebra + cradle]
   originates SR Policy DETOUR              consumes it (RT=10.0.0.1), owns the
   (color 100, endpoint 2001:db8:9::2,     End.B6.Encaps BSID fd00:b::b6, and
   binding-sid fd00:b::b6, seg{fd00:e::e1})  steers the colored fc00:99::/64 onto it
   + originates fc00:99::/64
  ```

  Scenario: A colored route is steered onto its SRv6 Binding SID in the eBPF FIB
    Given a clean test environment
    When I create namespace "ctrl"
    And I create namespace "h"
    And I connect namespace "h" interface "bc" to namespace "ctrl" interface "cb"
    And I execute "ip link set dev bc address 02:00:00:00:0b:01" in namespace "h"
    And I execute "ip link set dev cb address 02:00:00:00:0c:01" in namespace "ctrl"
    And I disable IPv6 forwarding in namespace "h"
    When I start cradle in namespace "h" with config "ports-h.json" serving gRPC as "ctl1"
    And I start zebra-rs in namespace "h" with config "h.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "ctrl" with config "ctrl.yaml"
    # The colored service route arrives first and installs PLAIN — the SR
    # Policy is not advertised yet, so there is no Binding SID to steer onto
    # (`via 2001:db8:9::2` is the plain iBGP next-hop, no seg6 encap).
    Then show command "show ipv6 route fc00:99::/64" in namespace "h" should eventually contain "via 2001:db8:9::2"
    # Now advertise the SR Policy from the controller. When it reaches h and
    # its End.B6.Encaps Binding SID activates, the headend re-installs the
    # already-received colored winner so it steers (H.Encap) onto the fresh
    # BSID fd00:b::b6 (the SRv6 BSID-activation resync). Without that resync
    # the route would sit plain until an unrelated re-evaluation.
    When I apply config "ctrl-with-policy.yaml" to namespace "ctrl"
    Then show command "show bgp sr-policy ipv6" in namespace "h" should eventually contain "fd00:b::b6"
    And show command "show ipv6 route fc00:99::/64" in namespace "h" should eventually contain "seg6 [fd00:b::b6]"
    # Datapath proof: the steered service route H.Encaps toward the BSID
    # fd00:b::b6 in cradle's eBPF FIB (`segs=[fd00:b::b6]` on the encap
    # nexthop appears only when a route is steered onto the BSID).
    And the cradle dump "srv6" in namespace "h" via gRPC as "ctl1" should contain "segs=[fd00:b::b6]"
    And the cradle dump "ipv6" in namespace "h" via gRPC as "ctl1" should contain "fc00:99::/64"
    # The BSID's own End.B6.Encaps local SID is teed into cradle's eBPF.
    And the cradle dump "srv6" in namespace "h" via gRPC as "ctl1" should contain "localsid fd00:b::b6"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "h"
    And I stop zebra-rs in namespace "ctrl"
    And I stop cradle in namespace "h"
    And I delete namespace "ctrl"
    And I delete namespace "h"
    Then the test environment should be clean
