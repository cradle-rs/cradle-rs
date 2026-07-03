@serial
@cradle_endm
Feature: SRv6 End.M egress protection survives an egress PE node death in eBPF
  A BGP L3VPN-over-SRv6 service keeps forwarding when its egress PE node
  dies, with every hop of the repair executed in the eBPF data plane. The
  protector peb advertises a Mirror SID (End.M) covering the egress pea's
  locator; pe1's `pic-retention` keeps pea's VPN route stale across the
  session drop, and IS-IS Mirror SID retention keeps pea's locator alive
  as a seg6 H.Encaps toward the Mirror SID.

  In cradle the repair is two eBPF pieces, both teed by zebra-rs:
    * pe1 (PLR): `srv6_encap` re-looks the freshly-imposed outer DA up in
      the FIB (the kernel's `seg6_lookup_nexthop` recursion) — the retained
      locator route answers with its own H.Encaps, stacking the repair
      layer: v6(Mirror SID) / v6(pea's service SID) / customer packet.
    * peb (protector): `srv6_endm` strips the repair layer, looks the
      exposed destination (pea's End.DT46 SID) up in the mirror context —
      populated by the mirror-route tee — and runs the dead PE's service
      decap into the local vrf-cust. Two decaps in one XDP pass.

  Topology (loopback 2001:db8::X, locator fcbb:bbbb:X::/48; kernel v4+v6
  forwarding off on pe1/pea/peb — the SRv6 data path runs in eBPF):
  ```
    ce1 ── pe1 ──── pea (stub) ── ce2     pea: protected egress (LOC3)
   (c1::2) (::1) │  (::3)          │ \    peb: protector (LOC4),
                 │                 │  \        Mirror SID fcbb:bbbb:4:1::
                 └──── peb ────────┘   ce2 dual-homed (lo c2::1/128)
                      (::4)
  ```
  ce2 returns to ce1 via peb in both states, so only the forward path
  changes when pea dies.

  Scenario: The VPN service forwards via pea, then survives pea's node death via End.M
    Given a clean test environment
    When I create namespace "ce1"
    And I create namespace "ce2"
    And I create namespace "pe1"
    And I create namespace "pea"
    And I create namespace "peb"
    And I connect namespace "pe1" interface "pe1-pea" to namespace "pea" interface "pea-pe1"
    And I connect namespace "pe1" interface "pe1-peb" to namespace "peb" interface "peb-pe1"
    And I connect namespace "pe1" interface "ce1" to namespace "ce1" interface "eth0"
    And I connect namespace "pea" interface "pea-ce2" to namespace "ce2" interface "eth-a"
    And I connect namespace "peb" interface "peb-ce2" to namespace "ce2" interface "eth-b"
    And I add address "2001:db8:c1::2/64" to interface "eth0" in namespace "ce1"
    And I add route "::/0" via "2001:db8:c1::1" in namespace "ce1"
    And I make namespace "ce2" interface "lo" up
    And I add address "2001:db8:c2::1/128" to interface "lo" in namespace "ce2"
    And I add address "2001:db8:ac::2/64" to interface "eth-a" in namespace "ce2"
    And I add address "2001:db8:bc::2/64" to interface "eth-b" in namespace "ce2"
    And I add route "2001:db8:c1::/64" via "2001:db8:bc::1" in namespace "ce2"
    # PE customer-facing addresses must exist before cradle starts: cradle
    # derives a VRF's connected routes once, from the kernel, at set_port
    # time. zebra reconciles the same addresses idempotently.
    And I add address "2001:db8:c1::1/64" to interface "ce1" in namespace "pe1"
    And I add address "2001:db8:ac::1/64" to interface "pea-ce2" in namespace "pea"
    And I add address "2001:db8:bc::1/64" to interface "peb-ce2" in namespace "peb"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pea"
    And I disable IPv4 forwarding in namespace "peb"
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pea"
    And I disable IPv6 forwarding in namespace "peb"
    And I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pea" with config "ports-pea.json" serving gRPC as "ctl2"
    And I start cradle in namespace "peb" with config "ports-peb.json" serving gRPC as "ctl3"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pea" with config "pea.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "peb" with config "peb.yaml" teeing to cradle as "ctl3"
    And I wait 45 seconds for BGP to operate
    # Warm-up: seed underlay ND on the core links.
    And I execute "ping -6 -c 1 -W 2 2001:db8:0:13::3" in namespace "pe1"
    And I execute "ping -6 -c 1 -W 2 2001:db8:0:14::4" in namespace "pe1"
    Then BGP session in "pe1" to "2001:db8::3" should be "Established"
    And BGP session in "pe1" to "2001:db8::4" should be "Established"
    And show command "show bgp vpnv6" in namespace "pe1" should eventually contain "2001:db8:c2::1/128"
    # Baseline: the service forwards via pea's End.DT46, all in eBPF.
    And ping from "ce1" to "2001:db8:c2::1" should eventually succeed
    And the cradle stat "srv6_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_decap" in namespace "pea" via gRPC as "ctl2" should be nonzero
    # Egress node death: stop pea's daemons. cradle's detach leaves pea's
    # kernel (forwarding off) as the namespace's only data plane — dark.
    # pe1's pea session drops (pic-retention holds the VPN route stale);
    # fast hellos time out in ~3 s and the retained locator route promotes.
    When I stop cradle in namespace "pea"
    And I stop the zebra-rs tee in namespace "pea"
    And I wait 20 seconds
    # pe1 has NOT withdrawn pea's VPN route — pic-retention held it.
    Then show command "show bgp vpnv6" in namespace "pe1" should contain "2001:db8:c2::1/128"
    # And the ping still reaches ce2 — now double-encapped by pe1's
    # post-encap re-lookup and double-decapped by peb's End.M.
    And ping from "ce1" to "2001:db8:c2::1" should eventually succeed
    And the cradle stat "srv6_endm" in namespace "peb" via gRPC as "ctl3" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "peb"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "peb"
    And I delete namespace "ce1"
    And I delete namespace "ce2"
    And I delete namespace "pe1"
    And I delete namespace "pea"
    And I delete namespace "peb"
    Then the test environment should be clean
