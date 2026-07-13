#! /bin/bash

# Grant the cradle daemon what the eBPF datapath needs so a supervisor
# running without root (e.g. zebra-rs under file capabilities — its
# `system ebpf enabled` spawns /usr/bin/cradle, and file capabilities do
# not inherit across exec) can still run it:
#   cap_bpf       — the bpf() syscall: create/write maps, program loads
#                   (kernel >= 5.8; cradle targets >= 5.11 for memcg
#                   accounting anyway)
#   cap_perfmon   — required by BPF_PROG_LOAD for this datapath (the
#                   cap_bpf/cap_perfmon split gates the load path;
#                   verified empirically: without it the load fails
#                   EPERM at instruction 0)
#   cap_net_admin — XDP/TC attach, clsact qdisc setup, IP_TRANSPARENT
#                   for the L7 TPROXY listener
#
# Not covered: the code paths that shell out to ip(8) with mutations
# (EVPN replication-slot veth pairs, TPROXY local-route install) — a
# child ip(8) gets no capabilities from cradle's file caps either. Those
# paths still want cradle run as root; the routed/zebra-driven datapath
# (ports, FIB, ILM, SRv6, FDB) is fully covered.
# cap_net_raw is required for the absorbed BFD Echo originator: cradle transmits
# self-addressed Echo frames over an AF_PACKET socket (the datapath the retired
# xdp-bfd-echo helper used to carry). The rest — XDP/TC attach (cap_net_admin),
# BPF load (cap_bpf, cap_perfmon) — covers the routed/zebra-driven datapath.
if [ -x /usr/bin/cradle ]; then
    setcap 'cap_net_admin,cap_bpf,cap_perfmon,cap_net_raw=ep' /usr/bin/cradle
fi
