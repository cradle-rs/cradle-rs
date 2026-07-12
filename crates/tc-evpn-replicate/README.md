# evpn-replicate

eBPF **TC/clsact** dataplane for EVPN BUM replication over an **RFC 9524 SR
replication segment** (the SRv6 P2MP tree signalled by EVPN Type-3 IMET,
`draft-ietf-bess-mvpn-evpn-sr-p2mp`).

## Why TC, not XDP

The stock Linux kernel cannot forward RFC 9524 natively — there is no
`End.Replicate` seg6local action and no `End.DT2M` for the L2 leaf flood.
Replication means *one copy per downstream branch, each with a different
rewritten header*. The TC layer can express that with `bpf_clone_redirect` in a
loop (mutating the skb between clones); XDP cannot clone per-copy. So this is a
`#[classifier]` program on `clsact`, unlike the sibling
[`xdp-bfd-echo`](../xdp-bfd-echo) offload.

Roles:
- **root / bud** (clsact ingress) — **implemented**: match the local
  Replication-SID, then for each downstream leaf clone the packet and rewrite
  the outer DA to that leaf's SID (`End.Replicate`);
- **leaf** (clsact ingress) — **implemented**: match the local `End.DT2M` SID,
  strip the outer encap (link Ethernet + outer IPv6), and redirect the inner
  frame to a bridge port for native BUM flooding;
- **root ingress** (clsact egress on the overlay port) — **implemented**: wrap a
  *bare* BUM frame in a reduced SRv6 encap (root `H.Encaps`) and fan it out, one
  copy per leaf.

The ingress classifier (`tc_evpn_replicate`) dispatches `End.Replicate` vs
`End.DT2M` by which map the inbound outer IPv6 DA hits; the egress classifier
(`tc_evpn_encap`) handles the bare-frame `H.Encaps`. The leaf set is a BPF map
the loader fills from the BGP control plane (`ReplSeg`, fed by
`EvpnFloodState::replication_leaves`).

## Status

**`End.Replicate`, leaf `End.DT2M`, and root `H.Encaps` all work.** The loader
fills these maps:

- `REPL_SEG` — per-VNI replication segment (tree + leaf SIDs);
- `REPL_LOCAL_SID` — local replication SID → VNI, for demuxing an inbound packet
  to its segment by outer IPv6 DA (derived from each segment's root SID);
- `DT2M_SID` — local `End.DT2M` SID → VNI for the leaf role;
- `CONFIG` — index 0 = `End.Replicate` clone egress ifindex; index 1 = the
  bridge port a leaf floods decapped frames into;
- `ENCAP_CFG` — root `H.Encaps` config: VNI, underlay ifindex, root SID, outer
  MAC header (`--encap` mode).

`End.Replicate`: on an inbound IPv6 frame whose DA is a known replication SID,
decrement the outer Hop Limit (drop anything ≤ 1) and emit one clone per leaf
with the outer DA rewritten, then drop the original.

`End.DT2M`: on an inbound IPv6 frame whose DA is a local `End.DT2M` SID (reduced
encap, Next Header = Ethernet), slide the inner Ethernet frame to the front of
the skb (`bpf_skb_adjust_room` can't strip a full outer L3), trim the tail with
`bpf_skb_change_tail`, and `bpf_redirect` it into a bridge port's ingress so the
bridge floods it to the local ACs.

`H.Encaps`: on a bare BUM frame egressing the overlay port, grow the buffer
(`bpf_skb_change_tail`) and slide the frame right to open headroom, write the
outer link Ethernet + IPv6 (Next Header = Ethernet, src = root SID), then
`clone_redirect` one copy per leaf with the outer DA set, out the underlay.

All three validated end-to-end on veth topologies:

```sh
sudo bash crates/tc-evpn-replicate/scripts/veth-replicate-test.sh   # End.Replicate
sudo bash crates/tc-evpn-replicate/scripts/veth-dt2m-test.sh        # leaf End.DT2M
sudo bash crates/tc-evpn-replicate/scripts/veth-encap-test.sh       # root H.Encaps
```

**SRH-present** (non-reduced) encap/decap is the remaining follow-up.

## Build / run

Like `xdp-bfd-echo` and `cradle-ebpf`, the eBPF crate builds only for
`bpfel-unknown-none` (via the loader's `build.rs`), so it is kept out of the
workspace `default-members` and excluded from the host CI gates. cradle-rs
already provides the nightly toolchain + `bpf-linker` its own eBPF needs; no
extra setup. It was imported from zebra-rs's `offload/` tree (see
`zebra-rs/docs/design/ebpf-offload-consolidation.md`).

```sh
# from the cradle-rs workspace root
cargo build --release -p tc-evpn-replicate      # builds loader; build.rs compiles the eBPF object
# XDP/TC attach needs CAP_NET_ADMIN, so run the built binary under sudo:
sudo ./target/release/tc-evpn-replicate --iface eth0 --direction ingress
```
