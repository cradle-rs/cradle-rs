@serial
@cradle_b6_zebra
Feature: BGP SR Policy programs an eBPF Binding SID through the tee
  As an operator distributing SR Policies with BGP (SAFI 73, RFC 9830)
  I want a received policy's SRv6 Binding SID installed into cradle
  So that the whole chain holds: controller-originated candidate path →
  iBGP sr-policy-v6 → headend policy selection → FIB tee (Binding SID
  local SID + policy segment list as a cradle SRv6 nexthop) → eBPF
  End.B6.Encaps push.

  The controller originates policy DETOUR (color 100) with Binding SID
  fd00:b::b6 and a one-SID segment list [fd00:e::e1], route-target
  10.0.0.1 — the headend's BGP Identifier, which is what makes the
  policy usable at b (RFC 9830 §4.2). b installs the BSID via the tee;
  the ingress s steers c1's traffic onto it with H.Encaps.Red
  [BSID, d-DT46]. At b the End walk advances the steering list and the
  policy encap (single SID → outer only) detours via e, whose End+USD
  exposes the steered packet again. Kernel forwarding off on s/b/e/d,
  seg6 never enabled.

  Topology:
  ```
                 ctrl[zebra]
                  │ 2001:db8:9::/64 (iBGP SAFI 73)
   c1 ── s[cradle] ── b[zebra+cradle] ── e[cradle] ── d[cradle] ── c2
   fc00:1::/64  db8:1::/64      db8:2::/64     db8:3::/64   fc00:2::/64
  ```

  Scenario: A BGP-learned Binding SID binds traffic onto its policy
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "s"
    And I create namespace "b"
    And I create namespace "ctrl"
    And I create namespace "e"
    And I create namespace "d"
    And I create namespace "c2"
    And I connect namespace "c1" interface "eth0" to namespace "s" interface "sc"
    And I connect namespace "s" interface "sp" to namespace "b" interface "bs"
    And I connect namespace "b" interface "bc" to namespace "ctrl" interface "cb"
    And I connect namespace "b" interface "be" to namespace "e" interface "eb"
    And I connect namespace "e" interface "ed" to namespace "d" interface "de"
    And I connect namespace "d" interface "dc" to namespace "c2" interface "eth0"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I execute "ip link set dev sc address 02:00:00:00:c1:ff" in namespace "s"
    And I execute "ip link set dev sp address 02:00:00:00:0a:00" in namespace "s"
    And I execute "ip link set dev bs address 02:00:00:00:0a:01" in namespace "b"
    And I execute "ip link set dev be address 02:00:00:00:0b:01" in namespace "b"
    And I execute "ip link set dev eb address 02:00:00:00:0b:02" in namespace "e"
    And I execute "ip link set dev ed address 02:00:00:00:0d:01" in namespace "e"
    And I execute "ip link set dev de address 02:00:00:00:0d:02" in namespace "d"
    And I execute "ip link set dev dc address 02:00:00:00:c2:ff" in namespace "d"
    And I execute "ip link set dev eth0 address 02:00:00:00:c2:01" in namespace "c2"
    And I add address "fc00:1::1/64" to interface "eth0" in namespace "c1"
    And I add address "fc00:1::ff/64" to interface "sc" in namespace "s"
    And I add address "2001:db8:1::1/64" to interface "sp" in namespace "s"
    And I add address "2001:db8:2::2/64" to interface "eb" in namespace "e"
    And I add address "2001:db8:3::1/64" to interface "ed" in namespace "e"
    And I add address "2001:db8:3::2/64" to interface "de" in namespace "d"
    And I add address "fc00:2::ff/64" to interface "dc" in namespace "d"
    And I add address "fc00:2::1/64" to interface "eth0" in namespace "c2"
    And I add route "::/0" via "fc00:1::ff" in namespace "c1"
    And I add route "::/0" via "fc00:2::ff" in namespace "c2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "b"
    And I disable IPv4 forwarding in namespace "e"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "b"
    And I disable IPv6 forwarding in namespace "e"
    And I disable IPv6 forwarding in namespace "d"
    When I start cradle in namespace "s" with config "s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "b" with config "ports-b.json" serving gRPC as "ctl2"
    And I start cradle in namespace "e" with config "e.json" serving gRPC as "ctl3"
    And I start cradle in namespace "d" with config "d.json" serving gRPC as "ctl4"
    And I start zebra-rs in namespace "b" with config "b.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "ctrl" with config "ctrl.yaml"
    # The policy must arrive over SAFI 73 and be selected before the
    # data-plane assertions mean anything.
    Then show command "show bgp sr-policy ipv6" in namespace "b" should eventually contain "fd00:b::b6"
    # The binding itself: c1's ping only reaches c2 if b's eBPF pushed
    # the policy encap (e's kernel would drop an unbound SRv6 packet —
    # forwarding off, no seg6) and e's USD exposed the steered packet.
    Then ping from "c1" to "fc00:2::1" should eventually succeed
    And the cradle stat "srv6_b6" in namespace "b" via gRPC as "ctl2" should be nonzero
    And the cradle stat "srv6_usd" in namespace "e" via gRPC as "ctl3" should be nonzero
    And the cradle stat "srv6_decap" in namespace "d" via gRPC as "ctl4" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "b"
    And I stop zebra-rs in namespace "ctrl"
    And I stop cradle in namespace "s"
    And I stop cradle in namespace "b"
    And I stop cradle in namespace "e"
    And I stop cradle in namespace "d"
    And I delete namespace "c1"
    And I delete namespace "s"
    And I delete namespace "b"
    And I delete namespace "ctrl"
    And I delete namespace "e"
    And I delete namespace "d"
    And I delete namespace "c2"
    Then the test environment should be clean
