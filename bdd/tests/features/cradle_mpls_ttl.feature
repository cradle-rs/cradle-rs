@serial
@cradle_mpls_ttl
Feature: MPLS TTL propagation — pipe vs uniform (RFC 3443)
  As an operator running the cradle data plane
  I want to choose the RFC 3443 label TTL model per LSP
  So that I can hide the LSP core (pipe) or expose its hops (uniform).

  Same 4-node LSP as cradle_mpls, driving two single-label LSPs whose only
  difference is the TTL model. A client packet starts at TTL 64.
  ```
   cl ─10.0.0/24─ ler1[push] ─10.0.1/24─ lsr2[swap] ─10.0.2/24─ per3[pop] ─10.0.3/24─ srv
  ```
  - 10.0.3.1 — UNIFORM LSP: push [16] (label TTL seeded from the inner IP TTL
    = 64) → swap 16→[17] (label TTL 64→63) → pop-l3 with `ttl_uniform`: the
    popped label TTL 63 is written back into the inner IP header, then per3's
    IP forward to srv decrements once ⇒ srv sees the request at TTL 62.
  - 10.0.5.1 — PIPE LSP: push [46] with `mpls_pipe` (label TTL seeded 255,
    hiding the hop count) → swap 46→[47] (255→254) → pop-l3 (default pipe: the
    label TTL is discarded, the inner IP TTL 64 preserved), per3's IP forward
    decrements once ⇒ srv sees the request at TTL 63. On the ler1→lsr2 wire the
    label carries TTL 255 — the pipe imposition seed.

  Scenario: Pipe hides the LSP hops, uniform exposes them
    Given a clean test environment
    When I create namespace "cl"
    And I create namespace "ler1"
    And I create namespace "lsr2"
    And I create namespace "per3"
    And I create namespace "srv"
    And I connect namespace "cl" interface "eth0" to namespace "ler1" interface "ler1a"
    And I connect namespace "ler1" interface "ler1b" to namespace "lsr2" interface "lsr2a"
    And I connect namespace "lsr2" interface "lsr2b" to namespace "per3" interface "per3a"
    And I connect namespace "per3" interface "per3b" to namespace "srv" interface "eth0"
    And I execute "ip link set dev lsr2a address 02:00:00:00:02:0a" in namespace "lsr2"
    And I execute "ip link set dev per3a address 02:00:00:00:03:0a" in namespace "per3"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "cl"
    And I add address "10.0.0.254/24" to interface "ler1a" in namespace "ler1"
    And I add address "10.0.1.1/24" to interface "ler1b" in namespace "ler1"
    And I add address "10.0.1.2/24" to interface "lsr2a" in namespace "lsr2"
    And I add address "10.0.2.1/24" to interface "lsr2b" in namespace "lsr2"
    And I add address "10.0.2.2/24" to interface "per3a" in namespace "per3"
    And I add address "10.0.3.254/24" to interface "per3b" in namespace "per3"
    And I add address "10.0.3.1/24" to interface "eth0" in namespace "srv"
    And I add address "10.0.5.1/32" to interface "eth0" in namespace "srv"
    And I add route "default" via "10.0.0.254" in namespace "cl"
    And I add route "default" via "10.0.3.254" in namespace "srv"
    And I disable IPv4 forwarding in namespace "ler1"
    And I disable IPv4 forwarding in namespace "lsr2"
    And I disable IPv4 forwarding in namespace "per3"
    Then ping from "cl" to "10.0.3.1" should fail
    When I start cradle in namespace "ler1" with config "ler1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "lsr2" with config "lsr2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "per3" with config "per3.json" serving gRPC as "ctl3"
    Then ping from "cl" to "10.0.3.1" should eventually succeed
    And ping from "cl" to "10.0.5.1" should eventually succeed
    And the cradle stat "mpls_push" in namespace "ler1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_swap" in namespace "lsr2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "mpls_pop" in namespace "per3" via gRPC as "ctl3" should be nonzero
    # Uniform LSP: srv sees the request at TTL 62 (LSP hop counted).
    When I start a background ping from "cl" to "10.0.3.1"
    Then command "timeout 8 tcpdump -n -v -c 1 -i eth0 icmp and dst 10.0.3.1" in namespace "srv" should eventually contain "ttl 62"
    # Pipe imposition: the label on the ler1→lsr2 wire carries TTL 255.
    When I start a background ping from "cl" to "10.0.5.1"
    Then command "timeout 8 tcpdump -n -v -c 1 -i lsr2a mpls 46" in namespace "lsr2" should eventually contain "ttl 255"
    # Pipe disposition: srv sees the request at TTL 63 (LSP hidden).
    When I start a background ping from "cl" to "10.0.5.1"
    Then command "timeout 8 tcpdump -n -v -c 1 -i eth0 icmp and dst 10.0.5.1" in namespace "srv" should eventually contain "ttl 63"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "ler1"
    And I stop cradle in namespace "lsr2"
    And I stop cradle in namespace "per3"
    And I delete namespace "cl"
    And I delete namespace "ler1"
    And I delete namespace "lsr2"
    And I delete namespace "per3"
    And I delete namespace "srv"
    Then the test environment should be clean
