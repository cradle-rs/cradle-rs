@serial
@cradle_ctl_apply_guard
Feature: ctl apply replays every config section, or says why it cannot
  As an operator pushing configuration to a running cradle
  I want a section that cannot be applied at runtime to be refused, not dropped
  So that `applied` means what it says.

  `cradle ctl apply` replays a JSON config over gRPC — the same operations the
  in-process bootstrap performs. It used to walk only the sections it had been
  taught, printing `applied` and silently discarding the rest: `repl_slots`,
  `repl_segs`, `xconnects`, `dx2v`, `vtep_source6`, `fib4_mode` and
  `fdb_age_secs`. A section accepted and dropped is the same failure shape as
  the BUM sentinel composing with slots ([`bum-replication.md`]) — the operator
  is told it worked, and nothing says otherwise.

  Three of those sections have RPCs behind them and are now actually sent
  (`repl_segs`, `xconnects`, `vtep_source6`). The remaining four cannot be
  replayed at all, and are now refused up front, before any RPC is sent, so a
  doomed apply does not land half of itself:

  * `fib4_mode` sizes the FIB maps at load time;
  * `fdb_age_secs` starts the aging task at load time;
  * `repl_slots` names operator-created veth ports, while the gRPC
    `AddReplSlot` takes a bridge domain and creates its own pair — not the
    same operation;
  * `dx2v` has no RPC of its own.

  One namespace, no traffic: this is about what the client sends.

  [`bum-replication.md`]: ../../docs/design/bum-replication.md

  Scenario: Build a node to push configuration at
    Given a clean test environment
    When I create namespace "n1"
    And I execute "ip link add n1c type veth peer name n1cx" in namespace "n1"
    And I execute "ip link add n1u type veth peer name n1ux" in namespace "n1"
    And I execute "ip link add n1ac type veth peer name n1acx" in namespace "n1"
    And I execute "ip link set n1c up" in namespace "n1"
    And I execute "ip link set n1cx up" in namespace "n1"
    And I execute "ip link set n1u up" in namespace "n1"
    And I execute "ip link set n1ux up" in namespace "n1"
    And I execute "ip link set n1ac up" in namespace "n1"
    And I execute "ip link set n1acx up" in namespace "n1"
    And I add address "2001:db8::1/64" to interface "n1u" in namespace "n1"
    And I start cradle in namespace "n1" with config "base.json" serving gRPC as "ctl1"

  Scenario: The sections that have RPCs behind them are replayed
    Given the test topology exists
    # Positive control, and the regression that matters: these three used to be
    # dropped client-side, so a wrong field mapping was invisible. Sending them
    # for real means the server validates them — a bad mapping now fails here.
    When I apply cradle config "replayable.json" to namespace "n1" via gRPC as "ctl1"

  Scenario: A bootstrap-only section is refused rather than dropped
    Given the test topology exists
    Then applying cradle config "has-fib4-mode.json" to namespace "n1" via gRPC as "ctl1" should be rejected with "`fib4_mode` cannot be applied over gRPC"
    And applying cradle config "has-fdb-age.json" to namespace "n1" via gRPC as "ctl1" should be rejected with "`fdb_age_secs` cannot be applied over gRPC"

  Scenario: A section with no RPC behind it is refused rather than dropped
    Given the test topology exists
    Then applying cradle config "has-repl-slots.json" to namespace "n1" via gRPC as "ctl1" should be rejected with "`repl_slots` cannot be applied over gRPC"
    And applying cradle config "has-dx2v.json" to namespace "n1" via gRPC as "ctl1" should be rejected with "`dx2v` cannot be applied over gRPC"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "n1"
    And I delete namespace "n1"
    Then the test environment should be clean
