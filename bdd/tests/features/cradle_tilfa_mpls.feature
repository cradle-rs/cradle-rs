@serial
@cradle_tilfa_mpls
Feature: IS-IS SR-MPLS TI-LFA repair label stacks forward in the eBPF data plane
  As an operator running SR-MPLS TI-LFA fast-reroute on cradle
  I want the IGP's pre-computed repair label stack executed in eBPF
  So that traffic survives the primary link dying — repaired at the PLR
  within the link monitor's latency — the MPLS sibling of
  `cradle_tilfa_srv6`, riding the same protected-nexthop tee.

  s protects link s—n with TI-LFA. The repair for r2's loopback is the
  explicit stack `[16004 (node-SID r1), adj-SID r1→r2]` toward P-node r1
  (`repair_segments_to_mpls_labels` never elides a segment), and the
  FibHandle tee installs the pair ahead of the failure: primary via n
  (out-label 16005) with `backup_id` pointing at the repair leaf. r1's
  ILM pops the whole repair stack (own node-SID = pop, its adjacency
  SID = pop-and-forward), so `mpls_pop` fires at r1 for every repaired
  packet.

  The repair's forwarding is proven twice:

  1. Deterministically, by promoting it: `fast-reroute backup-as-primary`
     (applied at runtime + `clear isis spf`) reinstalls each protected
     destination with the repair as the active route, pinning steady-state
     traffic onto the label stack with every link up — no failure timing.

  2. Under a real failure with the PLR's control plane lagging: IS-IS
     deliberately bypasses the SPF throttle on a local link-down
     (`link.rs` sends `SpfCalc` directly), and in a 5-node lab that
     reconvergence beats the link monitor — so s's zebra-rs is paused
     (SIGSTOP: adjacencies survive on hold time, nothing tears down)
     while the link dies, modeling the interval a loaded IGP takes to
     recompute. A 20/s background ping is in flight across the kill; the
     `LINK_DOWN` mark (ms, from the `ip monitor link` watcher) makes
     `resolve_nh` swap every lookup onto the repair — `nh_backup` counts
     them — until zebra-rs is resumed and reconverges normally.

  Topology (kernel IPv4 forwarding off on all routers; SRGB default
  16000, loopback SID index = node number ⇒ r1 = 16004, r2 = 16005):
  ```
   cl ── s ──(1)── n ──(1)── d
          \\                 /
          (10)── r1 ──(10)── r2 ──(10)
   lo: s=1.1.1.1 n=2.2.2.2 d=3.3.3.3 r1=4.4.4.4 r2=5.5.5.5
  ```

  Scenario: The eBPF data plane forwards the repair stack and fails over onto it
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "s"
    And I create namespace "n"
    And I create namespace "d"
    And I create namespace "r1"
    And I create namespace "r2"
    And I connect namespace "cl" interface "eth0" to namespace "s" interface "lan0"
    And I connect namespace "s" interface "s-n" to namespace "n" interface "n-s"
    And I connect namespace "n" interface "n-d" to namespace "d" interface "d-n"
    And I connect namespace "s" interface "s-r1" to namespace "r1" interface "r1-s"
    And I connect namespace "r1" interface "r1-r2" to namespace "r2" interface "r2-r1"
    And I connect namespace "r2" interface "r2-d" to namespace "d" interface "d-r2"
    And I add address "10.0.100.2/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.100.1/24" to interface "lan0" in namespace "s"
    And I add address "10.0.1.1/30" to interface "s-n" in namespace "s"
    And I add address "10.0.1.2/30" to interface "n-s" in namespace "n"
    And I add address "10.0.2.1/30" to interface "n-d" in namespace "n"
    And I add address "10.0.2.2/30" to interface "d-n" in namespace "d"
    And I add address "10.0.3.1/30" to interface "s-r1" in namespace "s"
    And I add address "10.0.3.2/30" to interface "r1-s" in namespace "r1"
    And I add address "10.0.4.1/30" to interface "r1-r2" in namespace "r1"
    And I add address "10.0.4.2/30" to interface "r2-r1" in namespace "r2"
    And I add address "10.0.5.1/30" to interface "r2-d" in namespace "r2"
    And I add address "10.0.5.2/30" to interface "d-r2" in namespace "d"
    And I add address "1.1.1.1/32" to interface "lo" in namespace "s"
    And I add address "2.2.2.2/32" to interface "lo" in namespace "n"
    And I add address "3.3.3.3/32" to interface "lo" in namespace "d"
    And I add address "4.4.4.4/32" to interface "lo" in namespace "r1"
    And I add address "5.5.5.5/32" to interface "lo" in namespace "r2"
    And I add route "default" via "10.0.100.1" in namespace "cl"
    And I disable IPv4 forwarding in namespace "s"
    And I disable IPv4 forwarding in namespace "n"
    And I disable IPv4 forwarding in namespace "d"
    And I disable IPv4 forwarding in namespace "r1"
    And I disable IPv4 forwarding in namespace "r2"
    When I start cradle in namespace "s" with config "ports-s.json" serving gRPC as "ctl1"
    And I start cradle in namespace "n" with config "ports-n.json" serving gRPC as "ctl2"
    And I start cradle in namespace "d" with config "ports-d.json" serving gRPC as "ctl3"
    And I start cradle in namespace "r1" with config "ports-r1.json" serving gRPC as "ctl4"
    And I start cradle in namespace "r2" with config "ports-r2.json" serving gRPC as "ctl5"
    Then ping from "cl" to "5.5.5.5" should fail
    When I start zebra-rs in namespace "s" with config "s.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "n" with config "n.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "d" with config "d.yaml" teeing to cradle as "ctl3"
    And I start zebra-rs in namespace "r1" with config "r1.yaml" teeing to cradle as "ctl4"
    And I start zebra-rs in namespace "r2" with config "r2.yaml" teeing to cradle as "ctl5"
    And I wait 20 seconds
    # Warm-up pings seed kernel ARP on every p2p link (each ping seeds both
    # ends) so the teed neighbors feed the label-switched egress rewrites —
    # both the primary chain (s→n→d→r2) and the repair chain (s→r1→r2).
    And I execute "ping -c 1 -W 2 10.0.1.2" in namespace "s"
    And I execute "ping -c 1 -W 2 10.0.3.2" in namespace "s"
    And I execute "ping -c 1 -W 2 10.0.2.2" in namespace "n"
    And I execute "ping -c 1 -W 2 10.0.5.1" in namespace "d"
    And I execute "ping -c 1 -W 2 10.0.4.2" in namespace "r1"
    # Steady state: the prefix-SID LSP forwards via the primary (s pushes
    # 16005 toward n; n swaps; d is the penultimate hop and pops), and s has
    # pre-computed the TI-LFA repair for the protected s—n destinations.
    Then mpls ilm in namespace "n" should contain label 16005
    And ping from "cl" to "5.5.5.5" should eventually succeed
    And the cradle stat "mpls_push" in namespace "s" via gRPC as "ctl1" should be nonzero
    And show command "show isis route detail" in namespace "s" should contain "Backup path: TI-LFA"
    # Proof 1 — promote the repair: every protected destination reinstalls
    # with the label-stack repair as its active route (demoted primary at
    # metric+1 behind it), so steady-state traffic is pinned onto the repair
    # with every link up. r1 is not on the primary path, so a nonzero
    # mpls_pop there is the repair stack — and nothing else — executing.
    When I apply command "set router isis fast-reroute backup-as-primary" in namespace "s"
    And I run "clear isis spf" in namespace "s"
    And I wait 5 seconds
    Then ping from "cl" to "5.5.5.5" should eventually succeed
    And the cradle stat "mpls_pop" in namespace "r1" via gRPC as "ctl4" should be nonzero
    # Back to the plain protected pair: primary via n, backup_id → repair.
    When I apply command "delete router isis fast-reroute backup-as-primary" in namespace "s"
    And I run "clear isis spf" in namespace "s"
    And I wait 5 seconds
    Then ping from "cl" to "5.5.5.5" should eventually succeed
    # Proof 2 — real failure, PLR control plane lagging. Freeze s's zebra
    # (IS-IS reconverges in ~300 ms here and would race the monitor), keep
    # 20/s pings in flight, and kill the primary from the far side: s keeps
    # admin-up but sees carrier loss (LOWERLAYERDOWN); the cradle link
    # monitor marks the ifindex in LINK_DOWN and resolve_nh swaps every
    # lookup onto the repair while the control plane is still "computing".
    # The surviving routers reconverge the return path normally, so the
    # repaired traffic flows end-to-end before s's IGP knows anything.
    When I start a background ping from "cl" to "5.5.5.5"
    And I pause zebra-rs in namespace "s"
    And I execute "ip link set n-s down" in namespace "n"
    And I wait 3 seconds
    Then the cradle stat "nh_backup" in namespace "s" via gRPC as "ctl1" should be nonzero
    # Un-freeze: zebra-rs catches up on the queued link-down, reconverges,
    # and the post-convergence route takes over from the repair.
    When I resume zebra-rs in namespace "s"
    And I wait 5 seconds
    Then ping from "cl" to "5.5.5.5" should eventually succeed

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
    And I delete namespace "cl"
    And I delete namespace "s"
    And I delete namespace "n"
    And I delete namespace "d"
    And I delete namespace "r1"
    And I delete namespace "r2"
    Then the test environment should be clean
