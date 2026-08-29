@serial
@cradle_evpn_mh_mpls
Feature: EVPN multihoming over MPLS — the ESI label split horizon, DF filter and aliasing in eBPF
  As an operator dual-homing a CE to two EVPN PEs on an MPLS fabric
  I want a BUM frame the CE sends into one PE never to come back to the CE
  through the other PE, with the non-DF filter and aliasing working as
  they do over VXLAN and SRv6
  So that an Ethernet Segment needs neither VXLAN nor SRv6 underneath it.

  RFC 7432 §8.3: over MPLS no source address identifies the ingress PE,
  so each PE advertises an **ESI label** for every segment it is attached
  to (in its per-ES A-D route), and a peer PE of the segment pushes that
  label under the EVI label on BUM that entered the segment through it.
  The receiving PE pops it (`ESI_LABEL` → `es_bits`, `mpls_l2_esi_pop`)
  and withholds the copy from the segment's ports (`l2_drop_sph`) — the
  same flood-loop check the VXLAN local bias and the SRv6 outer source
  feed. On the ingress side the label is pushed only toward peers of the
  segment: a replication slot per (peer, segment) carries it (`SLOT_ES`
  `only`, `mpls_l2_esi_push`) and the peer's plain slot skips that
  segment's frames (`SLOT_ES` `skip`).

  Topology: the cradle_evpn_mpls_multi hub-and-spoke with c2 and c3
  collapsed into ONE CE dual-homed to pe2 (DF) and pe3 (non-DF) on ES-1.
  PE loopbacks 10.255.0.N are eBPF-only; pe1 is the LSR between pe2 and
  pe3 (labels 12 → pe2, 13 → pe3); EVI labels 1200/2200/3200, ESI labels
  2900 (pe2) / 3900 (pe3):
  ```
        c1 ── pe1[cradle] ──10.0.12.0/24── pe2[cradle] ──pe2c── eth0 ┐
   bd 100        │  10.255.0.1  EVI 1200     10.255.0.2  DF, ESI 2900   ce
                 └────10.0.13.0/24── pe3[cradle] ──pe3c── eth1 ┘   bond0
                                      10.255.0.3 non-DF, ESI 3900   ES-1
  ```
  ce is a real multihomed station: one LAG (active-backup, transmitting on
  the pe3 leg, receiving on both) with one MAC and one address. Per-leg tc
  counters tell which PE delivered what: ARP from c1 on the pe3 leg is a
  BUM copy the non-DF let through; the CE's own MAC arriving on the pe2 leg
  is an echo the split horizon failed to stop. Neither PE lists ES peers —
  only the ESI label can stop the echo here.

  Scenario: The ESI label stops the echo, the non-DF filter the duplicate, and aliasing carries unicast
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
    And I execute "ip link set dev pe1u2 address 02:00:00:00:01:0a" in namespace "pe1"
    And I execute "ip link set dev pe1u3 address 02:00:00:00:01:0b" in namespace "pe1"
    And I execute "ip link set dev pe2u address 02:00:00:00:02:0a" in namespace "pe2"
    And I execute "ip link set dev pe3u address 02:00:00:00:03:0a" in namespace "pe3"
    And I execute "ip link set dev eth0 address 02:00:00:00:c1:01" in namespace "c1"
    # Replication slots: one veth pair per remote PE, per PE — plus, on the
    # two segment PEs, the ESI-label slot toward the segment's other PE.
    And I execute "ip link add r12a type veth peer name r12b" in namespace "pe1"
    And I execute "ip link add r13a type veth peer name r13b" in namespace "pe1"
    And I execute "ip link set r12a up" in namespace "pe1"
    And I execute "ip link set r12b up" in namespace "pe1"
    And I execute "ip link set r13a up" in namespace "pe1"
    And I execute "ip link set r13b up" in namespace "pe1"
    And I execute "ip link add r21a type veth peer name r21b" in namespace "pe2"
    And I execute "ip link add r23a type veth peer name r23b" in namespace "pe2"
    And I execute "ip link add r23ea type veth peer name r23eb" in namespace "pe2"
    And I execute "ip link set r21a up" in namespace "pe2"
    And I execute "ip link set r21b up" in namespace "pe2"
    And I execute "ip link set r23a up" in namespace "pe2"
    And I execute "ip link set r23b up" in namespace "pe2"
    And I execute "ip link set r23ea up" in namespace "pe2"
    And I execute "ip link set r23eb up" in namespace "pe2"
    And I execute "ip link add r31a type veth peer name r31b" in namespace "pe3"
    And I execute "ip link add r32a type veth peer name r32b" in namespace "pe3"
    And I execute "ip link add r32ea type veth peer name r32eb" in namespace "pe3"
    And I execute "ip link set r31a up" in namespace "pe3"
    And I execute "ip link set r31b up" in namespace "pe3"
    And I execute "ip link set r32a up" in namespace "pe3"
    And I execute "ip link set r32b up" in namespace "pe3"
    And I execute "ip link set r32ea up" in namespace "pe3"
    And I execute "ip link set r32eb up" in namespace "pe3"
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
    # Kernel addresses on the hub links so pe1's transit forwarding can
    # resolve neighbours; the 10.255.0.N loopbacks and every label stay
    # eBPF-only (kernel MPLS untouched).
    And I add address "10.0.12.1/24" to interface "pe1u2" in namespace "pe1"
    And I add address "10.0.13.1/24" to interface "pe1u3" in namespace "pe1"
    And I add address "10.0.12.2/24" to interface "pe2u" in namespace "pe2"
    And I add address "10.0.13.2/24" to interface "pe3u" in namespace "pe3"
    And I disable IPv4 forwarding in namespace "pe1"
    And I disable IPv4 forwarding in namespace "pe2"
    And I disable IPv4 forwarding in namespace "pe3"
    Then ping from "c1" to "10.0.0.2" should fail
    When I start cradle in namespace "pe1" with config "pe1.json" serving gRPC as "ctl1"
    And I start cradle in namespace "pe2" with config "pe2.json" serving gRPC as "ctl2"
    And I start cradle in namespace "pe3" with config "pe3.json" serving gRPC as "ctl3"
    # Split horizon by ESI label (RFC 7432 §8.3): the CE transmits on its
    # pe3 leg — a non-DF still accepts the CE's traffic and floods it. Its
    # copy toward pe2 goes through the ESI-label slot (pe2's label 2900
    # under pe2's EVI label 2200), not the plain one; pe2 pops the label
    # into the segment's bit and withholds the copy from pe2c. A flower
    # counter on eth0 keyed on the CE's own source MAC catches any echo
    # (deliveries to the CE carry c1's).
    When I execute "tc qdisc add dev eth0 clsact" in namespace "ce"
    And I execute "tc filter add dev eth0 ingress pref 1 flower src_mac 02:00:00:00:ce:02 action drop" in namespace "ce"
    # (Forget c1's MAC — the CE may have picked it up from c1's own ARP
    # retries as the PEs came up — so this ping starts with a broadcast
    # that must cross pe3's flood loop.)
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And the cradle stat "mpls_l2_esi_push" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "mpls_l2_esi_pop" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And the cradle stat "l2_drop_sph" in namespace "pe2" via gRPC as "ctl2" should be nonzero
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: take pe3c out of the segment on pe3. Its frames
    # are no longer segment ingress, so they leave through the plain slot
    # with no ESI label, and pe2 — its own segment membership untouched —
    # floods them back onto eth0. (Forget c1's MAC so the next ping starts
    # with an ARP broadcast again — a cached neighbour would make it known
    # unicast, which pe3 tunnels straight to pe1 without flooding.)
    When I apply cradle config "pe3-noes.json" to namespace "pe3" via gRPC as "ctl3"
    And I execute "ip neigh flush dev bond0" in namespace "ce"
    Then ping from "ce" to "10.0.0.1" should eventually succeed
    And command "tc -s filter show dev eth0 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"
    # Put pe3c back on the segment (non-DF) for the rest.
    When I apply cradle config "pe3-es.json" to namespace "pe3" via gRPC as "ctl3"
    # Non-DF filter (RFC 7432 §8.5): count the BUM copies pe3 delivers on
    # the CE's second leg with an ARP-only counter — known unicast may
    # legitimately land here too, because pe1 aliases the CE's MAC across
    # both segment PEs.
    And I execute "tc qdisc add dev eth1 clsact" in namespace "ce"
    And I execute "tc filter add dev eth1 ingress pref 1 protocol arp flower src_mac 02:00:00:00:c1:01 action pass" in namespace "ce"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    # Reachability: c1's ARP rides the DF (pe2) to eth0; its ICMP is known
    # unicast at pe1, sent through the {pe2, pe3} MPLS aliasing group.
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And the cradle stat "l2_es_nhg" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    And the cradle stat "mpls_l2_encap" in namespace "pe1" via gRPC as "ctl1" should be nonzero
    # The non-DF (pe3) received the same overlay copies and withheld every
    # one of them from pe3c...
    And the cradle stat "mpls_l2_decap" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe3" via gRPC as "ctl3" should be nonzero
    And the cradle stat "l2_drop_nondf" in namespace "pe2" via gRPC as "ctl2" should be zero
    # ...so the CE's second leg saw no broadcast: no duplicate BUM.
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually contain "Sent 0 bytes 0 pkt"
    # Negative control: make pe3 the DF too (as if the election flipped and
    # both PEs claimed it) and c1's next ARP shows up on eth1 as well.
    When I apply cradle config "pe3-df.json" to namespace "pe3" via gRPC as "ctl3"
    And I execute "ip neigh flush dev eth0" in namespace "c1"
    Then ping from "c1" to "10.0.0.2" should eventually succeed
    And command "tc -s filter show dev eth1 ingress pref 1" in namespace "ce" should eventually not contain "Sent 0 bytes 0 pkt"

  Scenario: Teardown topology
    Given the test topology exists
    When I stop cradle in namespace "pe1"
    And I stop cradle in namespace "pe2"
    And I stop cradle in namespace "pe3"
    And I delete namespace "c1"
    And I delete namespace "ce"
    And I delete namespace "pe1"
    And I delete namespace "pe2"
    And I delete namespace "pe3"
    Then the test environment should be clean
