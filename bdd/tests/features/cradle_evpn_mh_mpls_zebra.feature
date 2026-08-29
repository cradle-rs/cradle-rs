@serial
@cradle_evpn_mh_mpls_zebra
Feature: BGP EVPN multihoming over MPLS drives the ESI label split horizon in eBPF
  As an operator dual-homing a CE to two zebra-rs PEs on an MPLS fabric
  I want the ESI labels BGP allocates and advertises to reach cradle on
  both sides — ours for decap, the peer's on the copies toward it
  So that EVPN multihoming over MPLS works end to end with no static
  datapath state, split horizon included.

  The BGP-driven twin of cradle_evpn_mh_mpls, and the MPLS twin of
  cradle_evpn_mh_srv6_zebra. Under `encapsulation mpls` zebra-rs draws an
  ESI label per segment from the dynamic label block, advertises it in the
  per-ES A-D's ESI Label EC (RFC 7432 §7.5) and tees it as
  `SetEthernetSegment.esi_label`; from each peer's per-ES A-D it learns
  the peer's label and, per bridge domain, tees an ESI-label replication
  slot toward the peer (`AddReplSlot {remote_pe, remote_label, esi,
  esi_label}`) beside the plain Type-3 slot. DF election, the aliasing
  group (MPLS members) and the rest are the existing tee.
  ```
        c1 ── pe1[cradle+zebra] ──10.0.12.0/24── pe2[cradle+zebra] ──pe2c── eth0 ┐
   bd 100 / evi 100  │  lo 1.1.1.1, SID 1        lo 2.2.2.2 (DF)                ce
                     └────10.0.13.0/24── pe3[cradle+zebra] ──pe3c── eth1 ┘
                                          lo 3.3.3.3 (non-DF)          ES-1
  ```
  pe1 is both a PE and the LSR between pe2 and pe3 (IS-IS SR-MPLS,
  prefix-SIDs 1/2/3). ce is a real multihomed station: one LAG
  (active-backup, transmitting on the pe3 leg, receiving on both) with one
  MAC and one address. Per-leg tc counters tell which PE delivered what.

  Scenario: The BGP-allocated ESI labels stop the echo; DF filter and aliasing hold over MPLS
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    # No IPv6 on the PEs: a PE's own MLD / DAD / router solicitations on its
    # CE-facing port would land on the CE and pollute the copy counters.
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.default.disable_ipv6=1 net.ipv6.conf.all.disable_ipv6=1" in namespace "pe3"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "ce" interface "eth0" to namespace "pe2" interface "pe2c"
    And I connect namespace "ce" interface "eth1" to namespace "pe3" interface "pe3c"
    And I connect namespace "pe1" interface "pe1u2" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe1" interface "pe1u3" to namespace "pe3" interface "pe3u"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    And I add address "10.0.0.1/24" to interface "eth0" in namespace "c1"
    # The dual-homed CE: an active-backup LAG over both legs — one MAC, one
    # address, transmitting on the pe3 leg (primary eth1) and accepting
    # frames on either (all_slaves_active: aliasing may deliver on eth0).
    And I execute "sysctl -q -w net.ipv6.conf.all.disable_ipv6=1" in namespace "ce"
    And I execute "ip link add bond0 type bond mode active-backup all_slaves_active 1" in namespace "ce"
    And I execute "ip link set bond0 address 02:00:00:00:ce:02" in namespace "ce"
    And I execute "ip link set eth0 down" in namespace "ce"
    And I execute "ip link set eth1 down" in namespace "ce"
    And I execute "ip link set eth0 master bond0" in namespace "ce"
    And I execute "ip link set eth1 master bond0" in namespace "ce"
    And I execute "ip link set bond0 type bond primary eth1" in namespace "ce"
    And I execute "ip link set eth0 up" in namespace "ce"
    And I execute "ip link set eth1 up" in namespace "ce"
    And I execute "ip link set bond0 up" in namespace "ce"
    And I add address "10.0.0.2/24" to interface "bond0" in namespace "ce"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe3"
    # Checksum offload off on the label-switched links (MPLS over veth).
    And I execute "ethtool -K pe1u2 tx off" in namespace "pe1"
    And I execute "ethtool -K pe1u3 tx off" in namespace "pe1"
    And I execute "ethtool -K pe2u tx off" in namespace "pe2"
    And I execute "ethtool -K pe3u tx off" in namespace "pe3"
    # zebra's EVI declaration: a kernel bridge per PE (`evi 100 bridge
    # br100`). The ES access ports join too — that membership is what the
    # RIB turns into the port's EVI set (bridge domain 100) for the DF tee.
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set pe2c master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I execute "ip link add br100 type bridge" in namespace "pe3"
    And I execute "ip link set pe3c master br100" in namespace "pe3"
    And I execute "ip link set br100 up" in namespace "pe3"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe3" with config "ports-pe3.json" serving gRPC as "ctl3"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "pe3" with config "pe3.yaml" teeing to cradle as "ctl3"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2.2.2.2" should be "Established"
    And BGP session in "pe1" to "3.3.3.3" should be "Established"
    And BGP session in "pe2" to "3.3.3.3" should be "Established"
    # Each segment PE drew an ESI label from the dynamic block and shows it.
    And show command "show bgp evpn ethernet-segment" in namespace "pe2" should eventually contain "ESI label:"
    And show command "show bgp evpn ethernet-segment" in namespace "pe3" should eventually contain "ESI label:"
    And show command "show bgp evpn ethernet-segment" in namespace "pe2" should eventually contain "Member VTEPs (2)"
    # Split horizon by ESI label, BGP-driven (RFC 7432 §8.3): the CE
    # transmits on its pe3 leg — a non-DF still accepts the CE's traffic
    # and floods it. Toward pe2 the copy goes through the ESI-label slot
    # zebra teed from pe2's per-ES A-D (pe2's label under pe2's EVI
    # label); pe2 pops the label — teed from its own allocation — into the
    # segment's bit and withholds the copy from pe2c. A flower counter on
    # eth0 keyed on the CE's own source MAC catches any echo. (Forget c1's
    # MAC first so the ping starts with a broadcast that crosses pe3.)
    When I execute "tc qdisc add dev eth0 clsact" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:ce:02 action drop" in namespace "ce"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_esi_push" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "mpls_l2_esi_pop" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "l2_drop_sph" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control, BGP-driven: delete the segment on pe3. Its ES
    # routes are withdrawn, its label handed back, cradle's segment state
    # and the ESI-label slots on both sides torn down — pe3c is a plain
    # port again, so the CE's frames leave through the plain slot with no
    # ESI label and pe2 floods them back onto eth0.
    When I apply command "delete router bgp afi-safi evpn ethernet-segment es1" in namespace "pe3"
    And I wait 3 seconds
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    # Put the segment back on pe3: a fresh label is drawn, advertised, and
    # teed on both PEs again.
    When I apply command "set router bgp afi-safi evpn ethernet-segment es1 esi 00:00:00:00:00:00:00:00:00:01" in namespace "pe3"
    And I apply command "set router bgp afi-safi evpn ethernet-segment es1 interface pe3c" in namespace "pe3"
    Then show command "show bgp evpn ethernet-segment" in namespace "pe3" should eventually contain "ESI label:"
    And show command "show bgp evpn ethernet-segment" in namespace "pe2" should eventually contain "Member VTEPs (2)"
    And show command "show bgp evpn ethernet-segment" in namespace "pe3" should eventually contain "Designated Forwarder (tag 0): 2.2.2.2"
    # The CE first transmitted a moment ago: pe3 learned its MAC then, and
    # its Type-2 (ESI on the path) reaches pe1 an advertisement interval
    # later. Wait for it, so c1's ICMP below is known unicast at pe1 — the
    # aliasing group — rather than an unknown-unicast flood.
    And show command "show bgp evpn" in namespace "pe1" should eventually contain "[2]:[0]:[48]:[02:00:00:00:ce:02]"
    # Now count the BUM copies pe3 delivers on the CE's second leg: an
    # ARP-only counter (pass action) — known unicast may legitimately land
    # here too, because c1's PE aliases the CE's MAC across both segment
    # PEs.
    When I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol arp flower src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    # Reachability: c1's ARP rides the DF (pe2) to eth0; its ICMP is known
    # unicast at pe1, sent through the {pe2, pe3} MPLS aliasing group BGP
    # built from their per-ES + per-EVI A-D routes (RFC 7432 §8.4).
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The non-DF (pe3) received the same overlay copies and withheld every
    # one of them from pe3c — the role BGP elected and zebra teed...
    And the cradle stat "mpls_l2_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe2" via gRPC as "ctl2" should be zero
    # ...so the CE's second leg saw no broadcast: no duplicate BUM.
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control, BGP-driven: take pe2 away. Its Type-4 and A-D
    # routes are withdrawn: pe3 becomes the segment's only candidate,
    # re-elects itself DF and zebra clears cradle's non-DF row, while the
    # per-ES A-D withdraw (the §8.2 mass withdraw) drops pe2 from pe1's
    # aliasing group. The CE stays reachable through pe3 alone, and c1's
    # next ARP — now delivered by pe3 — shows up on eth1.
    When I stop the zebra-rs tee in namespace "pe2"
    And I wait 3 seconds
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop the zebra-rs tee in namespace "pe1"
    And I stop the zebra-rs tee in namespace "pe2"
    And I stop the zebra-rs tee in namespace "pe3"
    And I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I stop cradle in namespace "pe3"
    And I delete namespace "c1"
    And I delete namespace "ce"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "pe3"
    Then the test environment should be clean
