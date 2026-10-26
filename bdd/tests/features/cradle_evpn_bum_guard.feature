@serial
@cradle_evpn_bum_guard
Feature: A bridge domain serves BUM through the sentinel or through slots, never both
  As an operator composing a bridge domain's BUM forwarding
  I want the control plane to refuse the one combination the datapath cannot serve
  So that half a flood set can never disappear while the counters look healthy.

  A bridge domain reaches its remote PEs for BUM one of two ways:

  * the **all-ones-MAC sentinel** — one FDB entry naming the domain's single
    overlay BUM tunnel, matched in `l2_evpn_xdp` and encapsulated there; or
  * **replication slots** — a veth pair per remote PE whose A end joins the
    flood list, so the TC flood clones one copy per PE and each B end
    encapsulates toward its own target.

  They do not compose. The sentinel path terminates in XDP with a redirect, so
  the TC flood never runs and EVERY slot is skipped — BUM reaches one PE and
  silently misses the rest, while `STAT_SRV6_L2_BUM` keeps incrementing. No
  counter separates the broken case from the healthy one, which is why
  `proto/cradle.proto` makes it a contract ("a bridge domain using slots must
  not also program the all-ones-MAC sentinel") and why that contract is now
  enforced at the write sites rather than trusted.

  This is a control-plane guard, so no traffic is passed: the three namespaces
  are independent and never connected to each other, and every link is a local
  veth pair that exists only so cradle has ports to attach.

  ```
   pe1: slots, then the sentinel added over gRPC → refused (fdb_overlay_add)
   pe2: sentinel alone                           → accepted (positive control)
   pe3: both in ONE bootstrap config             → refused (repl_target_add)
  ```

  The two guards are reached by different paths, which is why both appear here:
  a slot's bridge domain is resolved from its flood membership, so the
  statically-configured slot checks in `repl_target_add`, while the cradle-owned
  Type-3 slot joins the domain only after the target is programmed and checks in
  `add_repl_slot_auto_keyed` instead. pe3 covers the former; the latter is
  exercised wherever zebra-rs drives Type-3 (`cradle_evpn_srv6_zebra_multi`).

  NOTE pe3 drives `serve --config`, not `ctl apply`: `ctl apply` does not replay
  the `repl_slots` section at all, so a slot can only be added by bootstrap.

  Scenario: Build three independent single-PE topologies
    Given a clean test environment
    When I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    # pe1 — the slots side.
    And I execute "ip link add pe1c type veth peer name pe1cx" in namespace "pe1"
    And I execute "ip link add pe1u type veth peer name pe1ux" in namespace "pe1"
    And I execute "ip link add r12a type veth peer name r12b" in namespace "pe1"
    And I execute "ip link set pe1c up" in namespace "pe1"
    And I execute "ip link set pe1cx up" in namespace "pe1"
    And I execute "ip link set pe1u up" in namespace "pe1"
    And I execute "ip link set pe1ux up" in namespace "pe1"
    And I execute "ip link set r12a up" in namespace "pe1"
    And I execute "ip link set r12b up" in namespace "pe1"
    And I add address "2001:db8:12::1/64" to interface "pe1u" in namespace "pe1"
    # pe2 — the sentinel side.
    And I execute "ip link add pe2c type veth peer name pe2cx" in namespace "pe2"
    And I execute "ip link add pe2u type veth peer name pe2ux" in namespace "pe2"
    And I execute "ip link add r21a type veth peer name r21b" in namespace "pe2"
    And I execute "ip link set pe2c up" in namespace "pe2"
    And I execute "ip link set pe2cx up" in namespace "pe2"
    And I execute "ip link set pe2u up" in namespace "pe2"
    And I execute "ip link set pe2ux up" in namespace "pe2"
    And I execute "ip link set r21a up" in namespace "pe2"
    And I execute "ip link set r21b up" in namespace "pe2"
    And I add address "2001:db8:12::2/64" to interface "pe2u" in namespace "pe2"
    # pe3 — where a config carrying BOTH is offered to the bootstrap.
    And I execute "ip link add pe3c type veth peer name pe3cx" in namespace "pe3"
    And I execute "ip link add pe3u type veth peer name pe3ux" in namespace "pe3"
    And I execute "ip link add r31a type veth peer name r31b" in namespace "pe3"
    And I execute "ip link set pe3c up" in namespace "pe3"
    And I execute "ip link set pe3cx up" in namespace "pe3"
    And I execute "ip link set pe3u up" in namespace "pe3"
    And I execute "ip link set pe3ux up" in namespace "pe3"
    And I execute "ip link set r31a up" in namespace "pe3"
    And I execute "ip link set r31b up" in namespace "pe3"
    And I add address "2001:db8:13::1/64" to interface "pe3u" in namespace "pe3"
    # Positive control: each mechanism ALONE is accepted. If the guard were
    # over-broad these two would fail to start and every assertion below would
    # be vacuous — this is what keeps it from passing by rejecting everything.
    And I start cradle in namespace "pe1" with config "slots.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "sentinel.json" serving gRPC as "ctl2"
    Then the cradle dump "l2" in namespace "pe2" via gRPC as "ctl2" should contain "ff:ff:ff:ff:ff:ff"

  Scenario: A bridge domain that floods through slots refuses the sentinel
    Given the test topology exists
    Then applying cradle config "add-sentinel.json" to namespace "pe1" via gRPC as "ctl1" should be rejected with "both the all-ones-MAC BUM sentinel and BUM replication slots"

  Scenario: The refused sentinel left nothing behind
    Given the test topology exists
    # The guard runs before the write, so pe1's flood path is untouched.
    # (`eventually not contain` is the only negative dump step; it passes on
    # its first poll here, which is what "was never written" looks like.)
    Then the cradle dump "l2" in namespace "pe1" via gRPC as "ctl1" should eventually not contain "ff:ff:ff:ff:ff:ff"

  Scenario: A bootstrap config carrying both is refused outright
    Given the test topology exists
    Then cradle in namespace "pe3" should refuse config "both.json" with "both the all-ones-MAC BUM sentinel and BUM replication slots"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "pe3"
    Then the test environment should be clean
