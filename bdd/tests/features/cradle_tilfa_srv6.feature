@serial
@cradle_tilfa_srv6
Feature: IS-IS TI-LFA uSID repair carriers forward in the eBPF data plane
  As an operator running SRv6 TI-LFA fast-reroute on cradle
  I want the IGP's packed NEXT-C-SID repair carriers executed in eBPF
  So that the whole repair chain — H.Insert at the PLR, the uN shift, the
  same-node uA(LIB) adjacency hop, the end-of-carrier walk restoring the
  original destination — runs in the data plane, driven end-to-end by the
  control plane's own carrier packing (`pack_carriers`).

  s protects link s—n with TI-LFA. The repair for r2's loopback goes
  P-node r1 then the r1→r2 adjacency (Q); both micro-SIDs share r1's
  locator block, so zebra packs them into ONE carrier
  (`fcbb:bbbb:5:<uA-fn>::`) and installs the repair as an H.Insert
  backup. `backup-as-primary` makes the repair carry steady-state
  traffic, so the test is deterministic — no failure timing. The
  FibHandle tee sends the protected pair to cradle (repair leaf = packed
  carrier + insert mode).

  Datapath walk asserted by the stats: e1's ping to r2's loopback
  ingresses s → H.Insert (SRH = [r2-lo, carrier], DA = carrier) → r1:
  uN shift exposes r1's OWN uA(LIB) → same-node re-dispatch →
  end-of-carrier → SRH walk restores r2's address → out the r1→r2
  adjacency, pinned loop-free → r2 delivers locally (seg6 enabled on r2
  so its kernel accepts the exhausted SL=0 SRH) and replies natively.

  Topology (kernel v4+v6 forwarding off on all routers):
  ```
   e1 ── s ──(1)── n ──(1)── d
          \\               /
          (10)── r1 ──(10)── r2 ──(10)
   locators: s=fcbb:bbbb:1::/48  n=2  d=4  r1=5  r2=6
  ```

  Scenario: A packed uSID carrier repairs traffic through the eBPF fabric
    Given a clean test environment
    When I create namespace "e1"
    And I create namespace "s"
    And I create namespace "n"
    And I create namespace "d"
    And I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "e1" interface "eth0" to namespace "s" interface "lan0"
    And I connect namespace "s" interface "s-n" to namespace "n" interface "n-s"
    And I connect namespace "n" interface "n-d" to namespace "d" interface "d-n"
    And I connect namespace "s" interface "s-r1" to namespace "r1" interface "r1-s"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I connect namespace "r2" interface "r2-d" to namespace "d" interface "d-r2"
    And I add address "2001:db8:100::2/64" to interface "eth0" in namespace "e1"
    And I add route "::/0" via "2001:db8:100::1" in namespace "e1"
    # The repaired packet reaches r2 still carrying the exhausted SRH (no
    # PSP); r2's kernel accepts it for local delivery with seg6 enabled.
    And I execute "sysctl -w net.ipv6.conf.all.seg6_enabled=1" in namespace "r2"
    And I execute "sysctl -w net.ipv6.conf.r2-r1.seg6_enabled=1" in namespace "r2"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "n"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv4 forwarding in namespace "r1"
    And I disable IPv4 forwarding in namespace "r2"
    And I disable IPv6 forwarding in namespace "s"
    And I disable IPv6 forwarding in namespace "n"
    And I disable IPv6 forwarding in namespace "d"
    And I disable IPv6 forwarding in namespace "r1"
    And I disable IPv6 forwarding in namespace "r2"
    When I start cradle in namespace "s" with config "ports-s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "n" with config "ports-n.json" serving gRPC as "ctl2"
    And I start cradle in namespace "d" with config "ports-d.json" serving gRPC as "ctl3"
    And I start cradle in namespace "r1" with config "ports-r1.json" serving gRPC as "ctl4"
    And I start cradle in namespace "r2" with config "ports-r2.json" serving gRPC as "ctl5"
    And I start zebra-rs in namespace "s" with config "s.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "n" with config "n.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "d" with config "d.yaml" teeing to cradle as "ctl3"
    And I start zebra-rs in namespace "r1" with config "r1.yaml" teeing to cradle as "ctl4"
    And I start zebra-rs in namespace "r2" with config "r2.yaml" teeing to cradle as "ctl5"
    And I wait 30 seconds
    Then ping from "e1" to "2001:db8::12" should eventually succeed
    And the cradle stat "srv6_hinsert" in namespace "s" via gRPC as "ctl1" should be nonzero
    # The end-of-carrier walk fires for both repair shapes zebra computes
    # (node-only `[uN(r1)]`, or `[uN(r1)+uA]` where the uA(LIB) hop ends the
    # carrier instead) — srv6_end counts the SRH walk restoring the
    # destination either way.
    And the cradle stat "srv6_end" in namespace "r1" via gRPC as "ctl4" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "s"
    And I stop the zebra-rs tee in namespace "n"
    And I stop the zebra-rs tee in namespace "d"
    And I stop the zebra-rs tee in namespace "r1"
    And I stop the zebra-rs tee in namespace "r2"
    And I stop cradle in namespace "s"
    And I stop cradle in namespace "n"
    And I stop cradle in namespace "d"
    And I stop cradle in namespace "r1"
    And I stop cradle in namespace "r2"
    And I delete namespace "e1"
    And I delete namespace "s"
    And I delete namespace "n"
    And I delete namespace "d"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
