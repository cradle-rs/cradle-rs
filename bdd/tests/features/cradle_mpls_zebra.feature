@serial
@cradle_mpls_zebra
Feature: zebra-rs MPLS state programs the eBPF label switch
  cradle runs the eBPF data plane; zebra-rs runs the control plane with its
  FibHandle teeing labeled nexthops, ILM entries, and resolved neighbors to
  cradle over gRPC. A zebra static labeled route (imposition) and a static
  MPLS label binding (disposition) therefore build an LSP that forwards
  entirely in eBPF.

  Topology (kernel IP forwarding and kernel MPLS are off on both routers):
  ```
   cl(10.0.0.1) ── ler[zebra+cradle: push 16] ── per[zebra+cradle: pop] ── srv(10.0.2.1)
  ```
  ler: static route 10.0.2.0/24 via 10.0.1.2 label [16]  → teed labeled nexthop
  per: static mpls label 16 nexthop 10.0.2.1 (no out-label) → teed ILM; the
       data plane pops by the packet's S bit and routes the exposed IP packet.
  The MPLS egress rewrite needs the next hop's MAC in cradle's neighbor map:
  one warm-up ping from ler's own stack makes the kernel resolve ARP, and the
  netlink monitor tees the learned neighbor to cradle.

  Scenario: A zebra-rs static LSP forwards via the eBPF data plane
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "ler"
    And I create namespace "per"
    And I create namespace "srv"
    And I connect namespace "cl" interface "eth0" to namespace "ler" interface "lera"
    And I connect namespace "ler" interface "lerb" to namespace "per" interface "pera"
    And I connect namespace "per" interface "perb" to namespace "srv" interface "eth0"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.0.254/24" to interface "lera" in namespace "ler"
    And I add address "10.0.1.1/24" to interface "lerb" in namespace "ler"
    And I add address "10.0.1.2/24" to interface "pera" in namespace "per"
    And I add address "10.0.2.254/24" to interface "perb" in namespace "per"
    And I add address "10.0.2.1/24" to interface "eth0" in namespace "srv"
    And I add route "default" via "10.0.0.254" in namespace "cl"
    And I add route "default" via "10.0.2.254" in namespace "srv"
    And I disable IPv4 forwarding in namespace "ler"
    And I disable IPv4 forwarding in namespace "per"
    And I start cradle in namespace "ler" with config "ports-ler.json" serving gRPC as "ctl1"
    And I start cradle in namespace "per" with config "ports-per.json" serving gRPC as "ctl2"
    Then ping from "cl" to "10.0.2.1" should fail
    When I start zebra-rs in namespace "ler" with config "ler.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "per" with config "per.yaml" teeing to cradle as "ctl2"
    And I execute "ping -c 1 -W 2 10.0.1.2" in namespace "ler"
    Then mpls ilm in namespace "per" should contain label 16
    And ping from "cl" to "10.0.2.1" should eventually succeed
    And the cradle stat "mpls_push" in namespace "ler" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_pop" in namespace "per" via gRPC as "ctl2" should be nonzero

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "ler"
    And I stop the zebra-rs tee in namespace "per"
    And I stop cradle in namespace "ler"
    And I stop cradle in namespace "per"
    And I delete namespace "cl"
    And I delete namespace "ler"
    And I delete namespace "per"
    And I delete namespace "srv"
    Then the test environment should be clean
