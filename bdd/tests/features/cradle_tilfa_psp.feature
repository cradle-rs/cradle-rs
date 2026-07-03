@serial
@cradle_tilfa_psp
Feature: PSP pops the TI-LFA repair SRH so an SRv6-unaware node takes the handoff
  As an operator running SRv6 TI-LFA fast-reroute on cradle
  I want the repair point's locator flavored with PSP
  So that when the end-of-carrier walk restores the original destination
  (SL 1 → 0), the exhausted repair SRH is removed in eBPF and the final
  node receives a clean native packet — no `seg6_enabled` anywhere.

  The `cradle_tilfa_srv6` twin of this feature keeps the SRH on the wire
  and must enable seg6 on r2's kernel to accept the SL=0 SRH ("no PSP").
  Here r1's locator carries `flavor: [psp]`: zebra advertises the uN SID
  as `uN (PSP)` (IANA 44) and the uA-LIB twin as `uA (PSP)`, the tee
  programs the flavor bit into the eBPF LocalSid, and `srv6_end`'s walk
  pops the SRH the moment its decrement exhausts it — for both repair
  shapes zebra computes (node-only `[uN(r1)]` and `[uN+uA(LIB)]`).
  r2's kernels stay stock: the ping only survives because the pop ran.

  Topology (kernel v4+v6 forwarding off on all routers; seg6 off
  EVERYWHERE — that is the difference from `cradle_tilfa_srv6`):
  ```
   e1 ── s ──(1)── n ──(1)── d
          \\               /
          (10)── r1 ──(10)── r2 ──(10)
   locators: s=fcbb:bbbb:1::/48  n=2  d=4  r1=5 (PSP)  r2=6
  ```

  Scenario: The repair carrier is popped at r1 and r2 replies natively
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
    And the cradle stat "srv6_end" in namespace "r1" via gRPC as "ctl4" should be nonzero
    # The pop itself: the repair SRH never reaches r2.
    And the cradle stat "srv6_psp" in namespace "r1" via gRPC as "ctl4" should be nonzero

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
