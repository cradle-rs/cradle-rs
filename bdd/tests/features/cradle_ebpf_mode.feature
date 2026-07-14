@serial
@cradle_ebpf_mode
Feature: system ebpf mode — single-hook (xdp-only) datapath
  The `--ebpf-mode {tc-only|xdp-only}` knob (driven by zebra-rs `system ebpf
  mode`, docs/design/ebpf-mode-benchmark.md) restricts the cradle datapath to
  plain IPv4 L3 forwarding through a SINGLE eBPF hook, for isolating each hook's
  cost. This validates the novel xdp-only path end to end: the mode surfaces in
  `show ebpf`, only the dedicated XDP forwarder (`cradle_xdp_l3`) is attached —
  no TC classifier — and plain IPv4 forwards entirely in XDP.

  Topology:
  ```
   cl(10.0.1.1) ─ fwd1 [ cradle xdp-only + zebra-rs ] fwd2 ─ srv(10.0.2.1, +10.9.9.1/32)
  ```
  The sink hosts (cl, srv) run a pass-through cradle so their veth XDP RX is
  enabled: a native XDP redirect is only delivered to a veth peer that itself
  has an XDP program (a veth property, absent on a physical NIC).

  Scenario: xdp-only attaches only cradle_xdp_l3 and forwards IPv4
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "fwd"
    And I create namespace "srv"
    And I connect namespace "cl" interface "eth0" to namespace "fwd" interface "fwd1"
    And I connect namespace "srv" interface "eth0" to namespace "fwd" interface "fwd2"
    And I add address "10.0.1.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "srv"
    And I add address "10.0.1.254/24" to interface "fwd1" in namespace "fwd"
    And I add address "10.0.2.254/24" to interface "fwd2" in namespace "fwd"
    And I add address "10.9.9.1/32" to interface "lo" in namespace "srv"
    And I add route "default" via "10.0.1.254" in namespace "cl"
    And I add route "default" via "10.0.2.254" in namespace "srv"
    And I disable IPv4 forwarding in namespace "fwd"
    # Pass-through cradle on the sinks enables their veth XDP RX (see note above).
    And I start cradle in namespace "cl" with config "sink.json" serving gRPC as "clc"
    And I start cradle in namespace "srv" with config "sink.json" serving gRPC as "srvc"
    # The router runs cradle in xdp-only mode; zebra-rs tees its static route.
    And I start cradle in namespace "fwd" with config "ports.json" ebpf-mode "xdp-only" serving gRPC as "ctl"
    And I start zebra-rs in namespace "fwd" with config "xdp.yaml" teeing to cradle as "ctl"
    # The mode is reported.
    Then show command "show ebpf" in namespace "fwd" should eventually contain "xdp-only"
    # Only the dedicated XDP forwarder is attached — no TC classifier.
    And command "ip -d link show fwd1" in namespace "fwd" should eventually contain "xdp"
    And command "tc filter show dev fwd1 ingress" in namespace "fwd" should not contain "cradle_tc"
    # Plain IPv4 forwards end to end through the single XDP hook, and the
    # xdp_l3_fwd counter confirms the XDP fast path (not XDP_PASS) was taken.
    Then ping from "cl" to "10.9.9.1" should eventually succeed
    And the cradle stat "xdp_l3_fwd" in namespace "fwd" via gRPC as "ctl" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "fwd"
    And I stop cradle in namespace "fwd"
    And I stop cradle in namespace "cl"
    And I stop cradle in namespace "srv"
    And I delete namespace "cl"
    And I delete namespace "srv"
    And I delete namespace "fwd"
    Then the test environment should be clean
