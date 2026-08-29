@serial
@cradle_evpn_mh_srv6_zebra
Feature: BGP EVPN multihoming over SRv6 drives the eBPF dataplane
  As an operator dual-homing a CE to two zebra-rs PEs on an SRv6 fabric
  I want the DF election, split horizon and aliasing BGP derives to reach
  cradle exactly as they do over VXLAN
  So that EVPN multihoming over SRv6 works end to end with no static
  datapath state.

  The BGP-driven twin of cradle_evpn_mh_srv6, and the SRv6 twin of
  cradle_evpn_mh_df_zebra: pe2 and pe3 configure the same ESI on their
  CE-facing ports, exchange Type-4 ES routes and run RFC 7432 §8.5 service
  carving with the VNI as the Ethernet Tag — 100 mod 2 = 0 picks the lower
  address, pe2. zebra-rs tees the roles as `SetEthernetSegment` /
  `SetEsRole`, the segment's other PE as `SetEsPeers`, and the {pe2, pe3}
  aliasing group as `SetEsNhg` with End.DT2U members. Everything else —
  End.DT2M replication slots, End.DT2U unicast FDB — is the existing
  SRv6 Type-2/Type-3 tee (cradle_evpn_srv6_zebra_multi).

  What is SRv6-specific: the split horizon keys on the *outer IPv6 source*
  of the MAC-in-SRv6 packet. zebra tees each peer's Type-4 Originating IP
  (`vtep-source`, here the loopback) as the ES peer, so the outer source
  cradle stamps on its SRv6 encapsulation must be that same address — the
  PE's EVPN source — for the peer to recognise it.
  ```
        c1 ── pe1[cradle+zebra] ──2001:db8:0:12::/64── pe2[cradle+zebra] ──pe2c── eth0 ┐
   bd 100         │  LOC1 fcbb:bbbb:1::/48              LOC2, src 2001:db8::2 (DF)     ce
                  └────2001:db8:0:13::/64── pe3[cradle+zebra] ──pe3c── eth1 ┘
                                             LOC3, src 2001:db8::3 (non-DF)    ES-1
  ```
  ce is a real multihomed station: one LAG (active-backup, transmitting on
  the pe3 leg, receiving on both) with one MAC and one address. Per-leg tc
  counters tell which PE delivered what.

  Scenario: The BGP-elected DF, split horizon and aliasing hold over SRv6
    Given a clean test environment
    When I create namespace "c1"
    And I create namespace "ce"
    And I create namespace "pe1"
    And I create namespace "pe2"
    And I create namespace "pe3"
    And I connect namespace "c1" interface "eth0" to namespace "pe1" interface "pe1c"
    And I connect namespace "ce" interface "eth0" to namespace "pe2" interface "pe2c"
    And I connect namespace "ce" interface "eth1" to namespace "pe3" interface "pe3c"
    And I connect namespace "pe1" interface "pe1u2" to namespace "pe2" interface "pe2u"
    And I connect namespace "pe1" interface "pe1u3" to namespace "pe3" interface "pe3u"
    # No IPv6 on the CE-facing ports: a PE's own MLD / DAD / router
    # solicitations would land on the CE and pollute the copy counters.
    And I execute "sysctl -q -w net.ipv6.conf.pe1c.disable_ipv6=1" in namespace "pe1"
    And I execute "sysctl -q -w net.ipv6.conf.pe2c.disable_ipv6=1" in namespace "pe2"
    And I execute "sysctl -q -w net.ipv6.conf.pe3c.disable_ipv6=1" in namespace "pe3"
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
    And I disable IPv6 forwarding in namespace "pe1"
    And I disable IPv6 forwarding in namespace "pe2"
    And I disable IPv6 forwarding in namespace "pe3"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "ports-pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "ports-pe2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe3" with config "ports-pe3.json" serving gRPC as "ctl3"
    And I start zebra-rs in namespace "pe1" with config "pe1.yaml" teeing to cradle as "ctl1"
    And I start zebra-rs in namespace "pe2" with config "pe2.yaml" teeing to cradle as "ctl2"
    And I start zebra-rs in namespace "pe3" with config "pe3.yaml" teeing to cradle as "ctl3"
    And I wait 3 seconds
    # zebra's VNI declaration: a bridge per PE with the zebra-created
    # vxlan100. The ES access ports join too — that membership is what the
    # RIB turns into the port's EVI set (bridge domain 100) for the DF tee.
    And I execute "ip link add br100 type bridge" in namespace "pe1"
    And I execute "ip link set vxlan100 master br100" in namespace "pe1"
    And I execute "ip link set br100 up" in namespace "pe1"
    And I execute "ip link add br100 type bridge" in namespace "pe2"
    And I execute "ip link set vxlan100 master br100" in namespace "pe2"
    And I execute "ip link set pe2c master br100" in namespace "pe2"
    And I execute "ip link set br100 up" in namespace "pe2"
    And I execute "ip link add br100 type bridge" in namespace "pe3"
    And I execute "ip link set vxlan100 master br100" in namespace "pe3"
    And I execute "ip link set pe3c master br100" in namespace "pe3"
    And I execute "ip link set br100 up" in namespace "pe3"
    And I wait 60 seconds for BGP to operate
    Then BGP session in "pe1" to "2001:db8::2" should be "Established"
    And BGP session in "pe1" to "2001:db8::3" should be "Established"
    And BGP session in "pe2" to "2001:db8::3" should be "Established"
    # Split horizon, BGP-driven (RFC 8365 §8.3.1 over SRv6): the CE
    # transmits on its pe3 leg — a non-DF still accepts the CE's traffic
    # and floods it (End.DT2M) to pe1 and pe2. pe2 is the DF, so only the
    # split horizon stops that copy coming back to the CE on eth0: zebra
    # teed pe3's Type-4 Originating IP (`vtep-source`, 2001:db8::3) as
    # pe2's ES-1 peer, and cradle drops what arrives from that outer
    # source. A flower counter on eth0 keyed on the CE's own source MAC
    # catches any echo (deliveries to the CE carry c1's).
    When I execute "tc qdisc add dev eth0 clsact" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:ce:02 action drop" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "l2_drop_sph" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: clear pe2's peer list underneath zebra (static
    # override) and the same traffic echoes back onto eth0.
    When I apply cradle config "pe2-nosph.json" to namespace "pe2" via gRPC as "ctl2"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    # The CE first transmitted a moment ago: pe3 learned its MAC then, and
    # its Type-2 (ESI on the path) reaches pe1 an advertisement interval
    # later. Wait for it, so c1's ICMP below is known unicast at pe1 — the
    # aliasing group — rather than an unknown-unicast flood that would
    # reach the CE just the same.
    Then show command "show bgp evpn" in namespace "pe1" should eventually contain "[2]:[0]:[48]:[02:00:00:00:ce:02]"
    # Now count the BUM copies pe3 delivers on the CE's second leg: an
    # ARP-only counter (pass action) — known unicast may legitimately land
    # here too, because c1's PE aliases the CE's MAC across both segment
    # PEs. Installed only now so the one-off frame the kernel emits when
    # pe3c joins its bridge does not count.
    When I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol arp flower src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    # Reachability: c1's ARP rides the DF (pe2) to eth0; its ICMP is known
    # unicast at pe1, sent through the {pe2, pe3} End.DT2U aliasing group
    # BGP built from their per-ES + per-EVI A-D routes (RFC 7432 §8.4).
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "srv6_l2_decap" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    # The non-DF (pe3) received the same overlay copies and withheld every
    # one of them from pe3c — the role BGP elected and zebra teed...
    And the cradle stat "srv6_l2_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
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
