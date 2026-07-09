# cradle-rs SRv6 support — design

> Segment Routing over IPv6 in the eBPF data plane, driven by the zebra-rs SRv6
> control plane (locators, End/End.DT behaviors, H.Encaps, L3VPN/EVPN over SRv6).

Status: **Phases 1–4 (uSID) implemented.** Phase 1: single-SID `H.Encaps.Red`
imposition and `End.DT46/DT4/DT6` decap, **including the per-VRF binding**
(the MVP absorbed the old "Phase 3" VRF item: MPLS Phase 3 already built the
per-VRF FIB and the XDP→TC VRF-metadata channel, so `End.DT46` binds VRFs
from day one — Phase 1 only added the `FIB6_VRF` v6 mirror). Phase 2: **SRH
transit** — multi-SID `H.Encaps.Red` that writes a real SRH, and the `End` /
`End.X` endpoint behaviors that walk `Segments Left` (SR-TE waypoints).
Phase 3: **the zebra-rs tee** — `FibHandle::route_sid_install` tees the local
SID (`AddLocalSid`), H.Encap route nexthops carry `segs`/`encap_mode`, and the
encap source is derived from the first local SID's locator, so **BGP L3VPN over
SRv6 programs cradle end to end** (the direct analog of the MPLS
`cradle_l3vpn_zebra`). Phase 4: **uSID (NEXT-C-SID) transit** — the
micro-SID node/adjacency behaviors that carry the whole path in the IPv6
destination (no SRH, no per-hop table): `uN` (a block+node prefix match, e.g.
/48, that shifts the uSID container left by one micro-SID and forwards by the
new DA) and `uA`/`uALib` (the adjacency form — `uA` is classic `End.X` at /128;
`uALib` shifts the container mid-carrier then forwards straight out the
cross-connect adjacency). Static gRPC/JSON config for `cradle_srv6`
(single-SID), `cradle_srv6_te` (2-SID SR-TE via End + End.X), `cradle_srv6_usid`
(uN container transit), and `cradle_srv6_ualib` (uALib adjacency transit, no
FIB); zebra-driven `cradle_srv6_l3vpn_zebra` (iBGP VPNv4+VPNv6 over IS-IS SRv6)
proves the tee. BDDs cover both inner families across a v6 underlay. **EVPN over
SRv6** is complete for a 2-PE domain: `End.DT2U` unicast, `End.DT2M` BUM, and
the **BGP EVPN control-plane tee** — zebra advertises per-VNI DT2U/DT2M SIDs
(RFC 9252, `encapsulation srv6`) and the tee installs remote MACs, the BUM
sentinel, and the local L2 SIDs, so BGP EVPN over SRv6 programs the L2 data
plane end to end — `cradle_evpn_srv6` + `cradle_evpn_srv6_bum` +
`cradle_evpn_srv6_zebra` BDDs; see [evpn-srv6.md](evpn-srv6.md). The remainder —
multi-PE ingress replication and overlay MAC learning — remains design. It
builds on the
[L2–L7 datapath](architecture.md) and reuses mechanisms from the
[MPLS design](mpls.md) (packet geometry, the shared `cradle_xdp` stage, the
VRF model, the zebra tee pattern).

**SRH wire format** (RFC 8986/8754), the detail the transit path hinges on:
segments are stored **reversed** — `segment_list[0]` is the *last* SID. For
`H.Encaps.Red` of `[S1..Sn]`: outer DA = `S1`, the SRH carries `[S2..Sn]`
reversed (`segment_list[i] = segs[n-1-i]`, `n-1` entries), `Segments Left =
n-1`, `Last Entry = n-2`, `Hdr Ext Len = 2*(n-1)`. `End` does
**decrement-then-index** (`SL -= 1; DA = segment_list[SL]`), so `SL` is
always in range at the read. A single SID needs no SRH (the DA is the SID) —
that is the Phase 1 reduced form.

**Two corrections to the original design, from implementation:**

- *`bpf_redirect_neigh` does **not** work for encap egress.* After the outer
  IPv6 header is imposed, `skb->protocol` still reports the *inner* family,
  and `bpf_redirect_neigh` builds the Ethernet header from it — wrong
  EtherType on the wire. Encap egress instead uses the **explicit L2
  rewrite** (`l2_xmit`, the MPLS path generalized to an EtherType), fed by
  the `NEIGH6`/`PORTS` maps — the same neighbor tee MPLS needs. (Plain
  transit `End` and post-decap forwarding are unaffected: those frames carry
  a correct `skb->protocol`.)
- *Decap runs in the shared XDP stage* (`cradle_xdp`, renamed from
  `cradle_mpls` now that it hosts two overlays), not a TC tail-call: the
  native-XDP receive path re-runs `eth_type_trans` after `adjust_head`, so
  the inner packet enters TC with the right `skb->protocol`, and the
  VRF-metadata channel is already there. A TC decap would hit the same
  stale-`skb->protocol` trap on the inner forward.

## Goal and scope

SRv6 encodes a source-routed path as a list of **SIDs** — 128-bit IPv6 addresses
— that the packet visits in turn. Each SID belongs to a node's **locator** (an
IPv6 prefix the IGP advertises) and names a **behavior** the owning node executes
when a packet's IPv6 destination equals that SID. cradle-rs already forwards IPv6
by LPM; SRv6 adds (a) a **local SID table** the datapath consults before normal
forwarding, and (b) **encapsulation** (impose an outer IPv6 header, optionally
with a Segment Routing Header) on the ingress node.

The behaviors that matter, by router role:

| Role | Behavior | Action |
|---|---|---|
| **Ingress PE / headend** | `H.Encaps.Red` | encapsulate the packet in outer IPv6 (+SRH), DA = first SID |
| **Transit / endpoint** | `End`, `End.X` | decrement Segments Left, update DA to the next SID, forward |
| **Egress PE (L3VPN)** | `End.DT4/DT6/DT46` | decapsulate, look up the inner packet in a VRF |
| **Egress PE (per-CE)** | `End.DX4/DX6` | decapsulate, cross-connect to a nexthop |

## The MVP: single-SID L3VPN, no segment walking

The dominant SRv6 deployment — BGP L3VPN with a single per-VRF service SID — is
the highest-value slice, and it needs no *multi-segment* processing. The ingress
PE encapsulates the packet in an outer IPv6 header whose DA is the egress PE's
**`End.DT46`** SID (the per-VRF, dual-family decap behavior BGP binds by default);
the egress PE matches that DA in its local SID table, strips the outer header, and
looks the inner packet up in the bound VRF.

zebra allocates one `End.DT46` SID per VRF and encapsulates with `H.Encap`
(RFC 8986). On the wire that is an outer IPv6 header plus at most a **single,
already-exhausted** SRH (`Segments Left = 0`), so the egress never *walks* a
segment list — it skips at most one Routing extension header to reach the inner
packet. cradle's own ingress can go further and emit the **reduced** form (outer
IPv6, DA = SID, no SRH at all). Either way, Phase 1 avoids the one genuinely hard
part: an `End` behavior that decrements `Segments Left` and rewrites the DA from a
live SRH.

That gives a tractable **Phase 1**:

- **ingress**: `H.Encaps.Red` with a single SID (outer IPv6, DA = SID, no SRH);
- **egress**: `End.DT46` (and single-family `End.DT4` / `End.DT6`) — match the
  local SID, skip an exhausted SRH if present, decap, VRF (or global) lookup.

Multi-segment SR-TE policies (a live SRH with `End` / `End.X` transit hops and
`Segments Left` walking, plus `End.B6.Encaps` binding SIDs) are **Phase 2**.
Keeping segment walking out of Phase 1 is what makes the first slice fit the
verifier comfortably.

## Why `bpf_redirect_neigh` works here (unlike MPLS)

MPLS egress could not use `bpf_redirect_neigh` because the frame leaves as MPLS
(no MPLS `nh_family`). SRv6 is the opposite: after `H.Encaps` the packet **is a
valid IPv6 packet** destined to the first SID. So the encap path reuses the
existing IPv6 forwarding tail — push the outer header, then
`bpf_redirect_neigh(oif, AF_INET6, gateway)` toward the *resolved underlay
nexthop* (the SR policy's gateway/oif, not the SID itself; the kernel resolves
that neighbor). No explicit L2 rewrite, no new neighbor map. Likewise `End` and
the decap behaviors end in an ordinary IPv6/IPv4 forward. SRv6 therefore needs
**none** of the MPLS neighbor-map machinery.

## Packet format recap

An SRv6 SID is a 128-bit IPv6 address, structured as `LOC:FUNCT:ARG` — a locator
block/node prefix plus a function (behavior) and optional argument. When a
segment list must travel on the wire, it rides in an IPv6 **Segment Routing
Header** (SRH, a Routing extension header, type 4):

```
 Next Header | Hdr Ext Len | Routing Type=4 | Segments Left
 Last Entry  | Flags       | Tag
 Segment[0]  (128 bits)   ← the LAST segment (SRH stores the list in reverse)
 Segment[1]  ...
 ...
 (optional TLVs)
```

`Segments Left` (SL) indexes the active segment; `End` decrements SL and copies
`Segment[SL]` into the IPv6 DA. **Reduced** encap (`H.Encaps.Red`) omits the
first SID from the SRH (it is already the DA) and needs ≥2 SIDs. A single-SID
L3VPN encap therefore uses `H.Encap` (a one-entry, already-exhausted SRH) — or,
in cradle's own imposition, no SRH at all.

## Map contract additions (`cradle-common`)

### 1. `SRV6_LOCALSID` — the local SID table

Matched against the IPv6 destination *before* the normal FIB, by longest prefix
(a locator can be one entry covering many function SIDs, or a SID can be an exact
`/128`):

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LocalSid {
    /// SRV6_BH_* behavior.
    pub behavior: u8,
    pub _pad: [u8; 3],
    /// VRF/table id for End.DT4/DT6/DT46 (0 = global).
    pub vrf_id: u32,
    /// Nexthop id for End.X / uA (adjacency cross-connect); 0 otherwise.
    pub nexthop_id: u32,
    /// uSID (uN/uA) locator-block / node bit lengths, from the SID structure,
    /// so the NEXT-C-SID shift finds the next micro-SID. Phase 4.
    pub block_bits: u8,
    pub node_bits: u8,
    pub _pad2: [u8; 2],
}

// Behaviors mirror zebra-rs's *live* `SidBehavior` set (RFC 8986 + NEXT-C-SID);
// zebra emits no End.DX4/DX6 (those exist only in dead-code placeholders).
pub const SRV6_BH_END:      u8 = 0; // endpoint: decrement SL, next SID, forward
pub const SRV6_BH_END_X:    u8 = 1; // + cross-connect to a specific adjacency
pub const SRV6_BH_END_DT4:  u8 = 2; // decap, IPv4 table lookup
pub const SRV6_BH_END_DT6:  u8 = 3; // decap, IPv6 table lookup
pub const SRV6_BH_END_DT46: u8 = 4; // decap, dual-family VRF lookup (BGP L3VPN)
pub const SRV6_BH_END_B6:   u8 = 5; // binding SID: encap onto a stored SID list
pub const SRV6_BH_UN:       u8 = 6; // uSID (NEXT-C-SID) flavor of End
pub const SRV6_BH_UA:       u8 = 7; // uSID flavor of End.X
pub const SRV6_BH_END_M:    u8 = 11; // egress-protection mirror: repair decap
                                     // + mirror-context lookup + service decap
```

```rust
#[map]
static SRV6_LOCALSID: LpmTrie<[u8; 16], LocalSid> = LpmTrie::with_max_entries(4096, 0);
```

### 2. Segment list for encap (`SRV6_ENCAP`)

Unlike MPLS labels (4 bytes, inlined on `NextHop`), SIDs are 16 bytes each, so
the segment list lives in a side map keyed by the nexthop id, and `NextHop` only
gains a flag:

```rust
pub const NH_F_SRV6: u32 = 1 << 3;   // this nexthop imposes an SRv6 encap
pub const MAX_SEGS: usize = 6;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Srv6Encap {
    pub num_segs: u8,        // 1 = reduced single-SID (no SRH); >1 = SRH
    pub _pad: [u8; 3],
    pub segs: [[u8; 16]; MAX_SEGS],  // [0] = first SID = outer DA
}

#[map]
static SRV6_ENCAP: HashMap<u32 /* nexthop_id */, Srv6Encap> = HashMap::with_max_entries(4096, 0);
```

The IPv6 (or IPv4) `FibEntry` for a VPN prefix points at a `NextHop` flagged
`NH_F_SRV6`; the nexthop's `gateway_v6`/`oif` give the underlay next hop, and
`SRV6_ENCAP[nexthop_id]` gives the segment list to impose. This keeps `NextHop`
lean and reuses its existing forwarding fields — the same separation the MPLS
design used, adapted to 16-byte SIDs.

### The encap source address

`H.Encaps` needs an outer IPv6 **source** address (the node's SRv6 encap source).
It is one global value (config `srv6 encapsulation source-address`), held in a
one-entry array map `SRV6_ENCAP_SRC` (or a `PortConfig`-style global).

### New maps summary

| Map | Key | Value | Populated by |
|---|---|---|---|
| `SRV6_LOCALSID` | `[u8;16]` SID (LPM) | `LocalSid` | control plane (`route_sid_install`) |
| `SRV6_ENCAP` | `u32` nexthop id | `Srv6Encap` | control plane (segs on nexthop) |
| `SRV6_ENCAP_SRC` | `0` | `[u8;16]` | config |

## Data-plane logic (`cradle-ebpf`)

SRv6 is more header manipulation than MPLS; it is a strong candidate for a
**tail-call program** (`cradle_srv6`) from the start (see Verifier). The logic:

### Ingress classification

In `l3_forward_v6`, probe the local SID table **first** (a local SID is not a
normal local address and must pre-empt the FIB):

```rust
let dst: [u8;16] = ctx.load(IP6_DST_OFF)?;
if let Some(sid) = SRV6_LOCALSID.get(Key::new(128, dst)) {  // LPM
    return srv6_localsid(ctx, sid);       // End / End.X / End.DT* / End.DX*
}
// ... normal FIB6 lookup ...
```

For the **imposition** side, after the FIB6/FIB4 lookup resolves a nexthop with
`NH_F_SRV6`, branch to `srv6_encap` instead of the plain forward.

### `srv6_encap` (H.Encaps.Red)

1. Fetch `SRV6_ENCAP[nexthop_id]`. Compute `hdr_len = 40 + srh_len`, where
   `srh_len = 0` when `num_segs == 1` (reduced single-SID), else
   `8 + 16*(num_segs-1)` (SRH carrying all but the first SID).
2. Grow room by `hdr_len` after the MAC header (`adjust_room`,
   `BPF_ADJ_ROOM_MAC`); re-load pointers.
3. Write the outer IPv6 header: SA = `SRV6_ENCAP_SRC`, DA = `segs[0]`,
   `payload_len`, `hop_limit`, and `next_header` = `43` (Routing/SRH) when an SRH
   follows, else the inner L3 proto (`41` IPv6, `4` IPv4).
4. If `num_segs > 1`, write the SRH (segments in reverse, `segments_left =
   num_segs-1`, `next_header` = inner proto).
5. Set EtherType `0x86dd` (the outer header is IPv6 regardless of inner).
6. Forward: `bpf_redirect_neigh(oif, AF_INET6, gateway_v6)` — the underlay
   resolves the neighbor. `stat_inc(STAT_SRV6_ENCAP)`.

### `srv6_localsid`

Dispatch on `sid.behavior`:

- **End / End.X** *(Phase 2)* — parse the SRH, require `SL > 0`, decrement `SL`,
  copy `Segment[SL]` into the IPv6 DA, decrement hop limit, forward (End: normal
  FIB; End.X: to `nexthop_id`'s adjacency). If `SL == 0` the SID is the last
  segment — proceed to upper-layer / decap per the flavor.
- **uN** *(Phase 4, uSID / NEXT-C-SID)* — the DA matched this node's uN prefix
  (`block_bits + node_bits`, e.g. /48). Shift the uSID container left by one
  micro-SID: slide the address bytes after the block up by `node_bits`, exposing
  the next micro-SID right after the locator block and zero-filling the vacated
  tail; then forward by the new DA (`XDP_PASS` → the TC FIB stage decrements the
  hop limit, as with `End`). No SRH — the path rides in the DA carrier. Only
  byte-aligned geometry is handled (16-bit micro-SIDs; block 16/32/48 — usid
  locators cap the block at 32, so /48 → block 32, node 16); other geometry
  passes through. `stat_inc(STAT_SRV6_USID)`.
- **uA / uALib** *(Phase 4, uSID adjacency)* — the adjacency micro-SID. `uA` is
  classic `End.X` at /128 (no shift, SRH walk → adjacency), so it dispatches to
  the `End`/`End.X` handler. `uALib` is the compressed-carrier form (matched at
  a block+function prefix mid-carrier): shift the container (shared with `uN`),
  then forward straight out the SID's cross-connect adjacency (`nexthop_id`, hop
  limit decremented here) rather than by the FIB. `stat_inc(STAT_SRV6_USID)`.
- **End(REP) / End.X(REP)** *(REPLACE-C-SID, RFC 9800 §4.2)* — the other RFC
  9800 compression. The DA is `Block | C-SID | Argument`; SRH entries are
  *packed containers* of `node_bits + fun_bits`-wide C-SIDs (32- or 16-bit —
  K = 4 or 8 positions, position K-1 = least significant consumed first) and
  the argument's last 2/3 bits index the active position. Matched at
  /(block+C-SID) so the argument stays wild. Non-zero index: decrement and
  rewrite **only the C-SID bits** of the DA from `SegList[SL][idx]` (R20); a
  zero position means the container ended early — the next list entry is a
  full 128-bit SID loaded as the whole DA (R06). Index zero: `SL -= 1`,
  index := K-1 (R12–R17). The R06 load can land on a SID of this same node
  (the final destination's ultimate-segment flavors must still run), so the
  handler re-dispatches once — the `srv6_un` same-node pattern. PSP composes
  at both rewrite points with the §4.2.8 condition (position 0 consumed *or*
  zero padding next); USP/USD run at the S02 terminal (`SL == 0 &&
  (idx == 0 || SegList[0][idx-1] == 0)`), End only. Kernel 6.8 has no
  REPLACE flavor op, so zebra skips the seg6local install — cradle is the
  only data plane; zebra's TI-LFA also refuses REPLACE SIDs as plain repair
  segments (RFC 9800 §6.4 — they are only valid inside packed containers).
  Source-side compression is not implemented: static configs express packed
  containers as IPv6 literals in `segs`. Bounds violations PASS (no ICMP).
  `stat_inc(STAT_SRV6_REPLACE)`.
- **End.B6.Encaps** *(Binding SID, RFC 8986 §4.13)* — the SID is bound to an
  SR Policy: run the End steps on the received SRH (hop-limit check +
  decrement, `SL--`, inner DA from `Segment List[new SL]` — S12–S14, so the
  steering list advances past the BSID before the detour), then push a new
  outer IPv6 (+SRH) carrying the policy's segment list. The policy rides as
  an ordinary `SRV6_ENCAP` entry referenced by `LocalSid.nexthop_id` — the
  same shape the TC H.Encaps path consumes; zebra's tee synthesizes that
  nexthop from `Sid.segs` (BGP SAFI 73's candidate-path list). The push is
  the **Reduced** form (§4.14): the first policy SID rides only in the outer
  DA, and a single-SID policy omits the SRH entirely — matching
  `apply_hencap`. Grow happens in XDP (`bpf_xdp_adjust_head` negative
  delta), then `XDP_PASS` — the TC FIB forwards by the new outer DA (S19's
  egress FIB lookup). Deviations: the outer source is the global
  `SRV6_ENCAP_SRC`, not a per-SID source A; SL == 0 / no-SRH arrivals PASS
  to the stack (§4.1.1 upper-layer — the kernel silently drops them); no
  flavors (none are registered for B6). `stat_inc(STAT_SRV6_B6)`.
- **End.T / uT** *(RFC 8986 §4.3)* — the End walk with S15.1's "set the
  packet's associated FIB table to T": after the DA rewrite the handler
  attaches the SID's `vrf_id` on the XDP→TC metadata channel (the same one
  the DT decap path uses), so the TC forward looks up in that table. A `uN`
  with a non-zero `vrf_id` is zebra's uT — End.T semantics at
  end-of-carrier. Composes with PSP (pop, then table-scoped forward) and
  USD (decap, then the *inner* forwards in table T); USP is local delivery,
  no table. zebra side: the locator `vrf` leaf resolves to the VRF's table
  in the RIB (re-resolved when the VRF appears/disappears), advertises
  End.T / uT codepoints, installs the kernel's native End.T action
  (+`SEG6_LOCAL_TABLE`; uT is cradle-only — no NEXT-CSID composition
  exists), and tees behavior 14 / UN + `vrf_table_id`.
  `stat_inc(STAT_SRV6_ENDT)`.

  The metadata channel itself is guarded by `META_COOKIE`: skb metadata
  SURVIVES a veth hop into the neighbouring node's TC stage (invisible to
  its XDP program), so a constant magic would let one node's table id steer
  the next node's lookup — each instance seeds a random cookie at startup
  and XORs it into the magic, making inherited metadata fail the check.
- **End.DX4 / End.DX6** *(RFC 8986 §4.5 / §4.4)* — the per-CE VPN egress:
  reach the inner packet (direct proto or one exhausted SRH), check the
  family against the behavior, decapsulate, and hand the exposed packet
  straight to the SID's adjacency (`nexthop_id`) — no FIB lookup and no
  TTL/hop-limit decrement (the tunnel ingress charged the inner already).
  The cross-connect finishes at the TC stage via DX-typed metadata
  (`XDP_META_MAGIC_DX`, cookie-guarded like the rest of the channel): an
  XDP `bpf_redirect` toward a CE veth silently drops when the host-side
  peer runs no NAPI, while the skb-path TC redirect always delivers. The
  uDX4/uDX6 forms are the same SIDs matched at the carrier's last
  micro-SID. `stat_inc(STAT_SRV6_DX)`.
- **End.DX2 / End.DX2V** *(RFC 8986 §4.9 / §4.10)* — the EVPN VPWS
  (E-Line, RFC 8214) egress: gate on outer next-header 143
  (IPPROTO_ETHERNET, the reduced MAC-in-SRv6 form), strip the 54 outer
  bytes, and emit the inner Ethernet frame **raw** on the attachment
  circuit — no FDB, no learning, no MAC rewrite. DX2's AC rides in the
  SID's `vrf_id` slot (an ifindex); DX2V instead reads the inner frame's
  802.1Q TCI and picks the AC from the `DX2V` map keyed by
  `(vrf_id = table, VID)` — the tag stays on the frame. Like DX4/DX6 the
  emit finishes at the TC stage, via `XDP_META_MAGIC_DX2` metadata. The
  ingress side is the `XCONNECT` map: an AC ifindex bound there
  MAC-in-SRv6-encapsulates **every** arriving frame (any EtherType — ARP
  rides the wire transparently) toward the remote service SID, checked
  before the L2 bridge dispatch so a VPWS AC never learns or floods.
  Caveat: the AC must carry its 802.1Q tags **in-band** for DX2V — veth
  TX VLAN acceleration keeps the tag in `skb->vlan_tci` where XDP can't
  see it (`ethtool -K <ac> txvlan off`). In the EVPN control plane (RFC
  9252 §6.3) each `vpws` service advertises a per-EVI Ethernet A-D
  (Type-1) route carrying an End.DX2 L2-Service Prefix-SID whose
  Ethernet Tag is the service instance id; importing the peer's Type-1
  drives one cradle `AddXconnect` that binds the AC both ways (ingress
  XCONNECT entry + local End.DX2 decap). `stat_inc(STAT_SRV6_DX2)`.
- **End.DT46 / End.DT4 / End.DT6** — the L3VPN common case: strip the outer IPv6
  (and an exhausted SRH, if present) and forward the **inner** packet in a table.
  Steps: walk the outer next-header chain — the inner proto directly, or `43`
  (Routing) → skip the SRH via its `hdr_ext_len` → inner proto; shrink room by
  `outer_len` (`adjust_room` negative, `BPF_ADJ_ROOM_MAC`); set EtherType to the
  inner family (`0x0800`/`0x86dd`); then IP-forward. `End.DT46` is dual-family
  (inner may be v4 or v6) and uses the SID's VRF table; `End.DT4`/`End.DT6` are
  single-family. If `vrf_id == 0`, fall into the existing `l3_forward_v4/v6`;
  otherwise a per-VRF lookup (Phase 3). `stat_inc(STAT_SRV6_DECAP)`.

### Packet geometry

Same mechanism as MPLS: `TcContext::adjust_room(len_diff, BPF_ADJ_ROOM_MAC, 0)`
inserts/removes bytes right after the Ethernet header — here a whole outer IPv6
header (+SRH) rather than a 4-byte label. The same rules apply: call
`adjust_room` before writing, re-load cached pointers afterward, keep every write
inside re-validated bounds. (For a future `End` that *inserts* an SRH into an
existing IPv6 packet, `BPF_ADJ_ROOM_NET` grows room after the L3 header instead.)

### Verifier budget

SRv6 does materially more than the IP fast path: outer-header construction,
optional SRH write, inner-header discovery, and (Phase 2) SRH parsing with a
bounded `Segments Left` walk. This is likely to exceed the single-classifier
budget, so the design **tail-calls** a dedicated `cradle_srv6` program on the two
SRv6 triggers — a local-SID DA hit, and an `NH_F_SRV6` nexthop — keeping the IP
fast path lean. `MAX_SEGS` bounds the encap write loop and the SRH parse loop.

## Observability

```
STAT_SRV6_ENCAP   // H.Encaps imposed (ingress PE)
STAT_SRV6_END     // End / End.X transit (Phase 2)
STAT_SRV6_DECAP   // End.DT*/DX* decapsulation (egress PE)
STAT_SRV6_USID    // uN NEXT-C-SID container shift (Phase 4)
STAT_SRV6_REPLACE // REPLACE-C-SID rewrite / container advance (RFC 9800 §4.2)
STAT_SRV6_B6      // End.B6.Encaps binds (End walk + policy push, RFC 8986 §4.13)
STAT_SRV6_ENDT    // End.T table-scoped forwards (RFC 8986 §4.3)
STAT_SRV6_DX      // End.DX4/DX6 decap + cross-connect (RFC 8986 §4.4/§4.5)
STAT_SRV6_DX2     // End.DX2/DX2V decap + raw AC emit (EVPN VPWS, RFC 8986 §4.9/§4.10)
```

Surfaced through the existing `GetStats` RPC and `cradle stats`, and used by
the BDD suite to assert which SRv6 behavior handled a packet.

## Control-plane API (gRPC)

The seam is the same `cradle.v1.Cradle` service. zebra-rs installs SRv6 through
two distinct paths (both encoded in `zebra-rs/src/fib/netlink/srv6.rs`), which
cradle mirrors:

1. **H.Encaps on a route nexthop.** There is no dedicated FibHandle method — the
   segment list rides on the ordinary nexthop/route install (`NexthopUni.segs` +
   `encap_type`, emitted as a SEG6 lwtunnel on `nexthop_add`). cradle extends
   `Nexthop`:

   ```proto
   message Nexthop {
     // ... existing fields ...
     repeated string segs = 7;   // SRv6 SID list, forwarding order ([0] first)
     uint32 encap_mode    = 8;   // H.Encap | H.Encap.Red | H.Insert
   }
   ```

   A nexthop with `segs` set is flagged `NH_F_SRV6`; the IP route that references
   it (by `nexthop_id`) imposes the encap. `H.Encap.Red` drops `segs[0]` from the
   SRH (it is the outer DA) and requires ≥2 SIDs; single-SID L3VPN uses `H.Encap`
   (or cradle's reduced no-SRH form).

2. **Local SID install** — `FibHandle::route_sid_install(sid, gid, ifindex)` /
   `route_sid_uninstall(sid)` (the seg6local routes). Everything rides on the
   `Sid` struct, so the mirror carries its fields:

   ```proto
   message LocalSid {
     string sid          = 1;   // SID address (or locator prefix for uN/uA)
     uint32 prefix_len   = 2;   // /128 for End/End.X/End.DT*; masked for uSID
     uint32 behavior     = 3;   // SRV6_BH_END | END_X | END_DT4/6/46 | UN | UA | B6
     uint32 vrf_table_id = 4;   // End.DT46 → VRFTABLE; End.DT4/DT6 → TABLE
     uint32 oif          = 5;   // seg6 device (End/uN) or egress link (End.X)
     string nh6          = 6;   // adjacency IPv6 for End.X / uA
     // uSID (uN/uA) SID structure — locator-block / -node / function / arg bits
     uint32 lb_bits = 7; uint32 ln_bits = 8; uint32 fun_bits = 9; uint32 arg_bits = 10;
   }
   message LocalSidDel { string sid = 1; uint32 prefix_len = 2; }

   rpc AddLocalSid(LocalSid)    returns (Empty);
   rpc DelLocalSid(LocalSidDel) returns (Empty);
   ```

3. **Encap source**: `SetSrv6EncapSource(Srv6EncapSource { addr })` — the outer
   IPv6 SA for imposition.

`cradle`'s `Control`/`Dataplane` gain `localsid_add/del`, `srv6_encap_set` (segs
on a nexthop), and `srv6_encap_source_set`. The JSON bootstrap / `ctl apply`
config gains optional `segs`/`encap_mode` on nexthops, a `localsids` array, and an
`srv6_encap_source` field, so the data plane is provable standalone before the
zebra tee. Phase 1 implements the `End.DT46/DT4/DT6` behaviors; `End.X`, `uN`/`uA`,
and `End.B6.Encaps` arrive with later phases (the message already carries their
fields, so no ABI break is needed).

> The behavior codes and `Sid` fields match zebra-rs's *live* `SidBehavior` model
> (`src/rib/segment_routing/sid.rs`) — note zebra also has a dead-code
> `src/rib/srv6/` placeholder with richer names (End.T, End.DX*); cradle mirrors
> the live set that actually reaches the FIB. (Reconciled against the source.)

## Control-plane integration (zebra-rs)

zebra-rs tees IP FIB operations to cradle through `CradleFib`
(`zebra-rs/src/fib/cradle.rs`), gated by `system cradle-grpc`. **Phase 3 wired
the SRv6 tee** (`zebra-rs` `feat/cradle-srv6-tee`): `proto/cradle.proto` gains
`LocalSid` / `DelLocalSid` / `SetSrv6EncapSource` and `segs` + `encap_mode` on
`Nexthop`, and the tee fires at these hooks:

- **service SIDs / L3VPN egress** — `FibHandle::route_sid_install` /
  `route_sid_uninstall` tee to `AddLocalSid` / `DelLocalSid` (`local_sid_install`
  maps `SidBehavior` → `SRV6_BH_*`, carries `vrf_table_id` and, for `End.X`,
  resolves `(nh6, oif)` to a cradle nexthop id). BGP binds one `End.DT46` per VRF
  (`src/bgp/vrf/spawn.rs`) with the VRF's `table_id`; IS-IS / OSPF locators
  originate `End` / `End.X`;
- **transit encap / SR policy** — a route nexthop carrying `segs`
  (`encap_type = HEncap`/`HEncapRed`) tees as `Nexthop { segs, encap_mode }`; the
  member extractor (`cradle_members`) now carries `u.segs` + `srv6_encap_mode`,
  and `member_nexthop_id` dispatches SRv6 (v6-underlay) nexthops even for v4-inner
  routes. BGP L3VPN-over-SRv6 imports (`build_srv6_vpn_fib_entry`) are the
  producer;
- **encap source** — derived once from the first local SID's locator and pushed
  via `SetSrv6EncapSource` (zebra has no explicit encap-source config; a `::`
  source still decap-and-forwards correctly, so this is off the critical path).

**Connected VRF routes** are the one thing the tee does *not* carry: they are
kernel-owned (created when the interface address is added), so zebra never
`route_ipv4_add`s them. cradle instead derives them at `set_port` time from the
kernel (`derive_port`, `getifaddrs`) into `FIB{4,6}_VRF[vrf]` — which means the
PE customer-facing address must exist *before* cradle attaches. The
`cradle_srv6_l3vpn_zebra` BDD seeds those addresses ahead of cradle for exactly
this reason.

The locator model is derived, not spelled out: `config.yang`'s
`segment-routing { locator { prefix; behavior; } }` yields the SID structure from
the prefix length and behavior (there are no separate block/node/function-length
leaves). Static SRv6 for standalone testing lives in `config-static.yang` —
route-level `segments` + `encap-type`, and a local `action`
(`End`/`End.X`/`uN`/`uA`/`End.DT4`/`End.DT6`/`End.DT46`) + `vrf`. The SID/locator
allocation, behavior selection, and SR-policy computation stay in zebra-rs; cradle
executes the resulting encap and local-SID actions in eBPF — the same thesis as
IP and MPLS, applied to SRv6.

## VRF / L3VPN (Phase 3)

`End.DT46/DT4/DT6` decapsulate then look up the inner packet in a table. As with
MPLS this needs per-VRF FIB tables (a `table_id`-keyed FIB); the `LocalSid`
already carries `vrf_id` so Phase 1/2 need no ABI break to reach Phase 3.
`End.DT46` binds a VRF via the kernel `SEG6_LOCAL_VRFTABLE` (BGP's per-VRF SID);
`End.DT4`/`End.DT6` use `SEG6_LOCAL_TABLE`, and `table_id == 0` means the global
table — so single-table L3VPN (or plain SRv6 transport into the global RIB, which
BGP installs as a global `End.DT6`) works in Phase 1 before per-VRF tables land.

## Testing (BDD)

A `cradle_srv6` feature, mirroring `cradle_zebra` / the planned `cradle_mpls`: an
ingress PE, a transit node, and an egress PE over an IPv6 underlay —

```
 ce1 ── ingress-PE [cradle] ──(IPv6 underlay)── egress-PE [cradle] ── ce2
          H.Encaps.Red                            End.DT4 (decap + VRF)
          DA = egress End.DT4 SID
```

Kernel SRv6 processing (`net.ipv6.conf.all.seg6_enabled`, the kernel seg6local
routes) stays **off** on the nodes, so a ping/HTTP that crosses proves the *eBPF*
data plane did the encap and decap — the same "kernel forwarding off" trick the
IP features use. Assert `srv6_encap` nonzero at the ingress PE and `srv6_decap`
nonzero at the egress PE. Driven two ways: static JSON config (nexthop `segs`
+ a `localsids` array) proves the datapath — `cradle_srv6` (single-SID),
`cradle_srv6_te` (2-SID SR-TE End + End.X), `cradle_srv6_usid` (a uN uSID
container `fcbb:bbbb:10:20::` shifted at the transit node — asserts `srv6_usid`
nonzero there), and `cradle_srv6_ualib` (a uALib adjacency uSID
`fcbb:bbbb:e002:20::` where the transit node carries **no** IPv6 routes, so only
the adjacency cross-connect — not the FIB — can deliver, proving the uALib
behavior specifically); `cradle_srv6_l3vpn_zebra` proves the Phase 3 integration —
`c1 ── pe1[cradle+zebra] ── pe2[cradle+zebra] ── c2`, iBGP VPNv4+VPNv6 over
IS-IS SRv6 with `encapsulation srv6`, kernel v4+v6 forwarding off on the PEs.
It asserts the BGP session, the imported VPN prefixes, c1↔c2 v4 and v6 reach,
and `srv6_encap` @pe1 / `srv6_decap` + `fib4_vrf_hit` + `fib6_vrf_hit` @pe2.
Each scenario ends with the mandatory `Scenario: Teardown topology`.

## Phasing

1. **Phase 1 — L3VPN core (single-SID)** *(done)*. `SRV6_LOCALSID`,
   `SRV6_ENCAP`, `SRV6_ENCAP_SRC`, `FIB6_VRF`; `H.Encaps.Red` single-SID
   encap (TC, explicit L2 rewrite); `End.DT46`/`End.DT4`/`End.DT6` decap in
   the `cradle_xdp` stage (per-VRF lookup, exhausted-SRH skip); counters;
   gRPC `AddLocalSid` + `segs`-on-`Nexthop` + encap source; static config +
   `cradle_srv6` BDD. **VRF binding included** (absorbed from Phase 3).
2. **Phase 2 — SRH transit** *(done)*. Multi-SID `H.Encaps.Red` (writes the
   SRH, reversed list, `SL = n-1`) at TC; `End` (SL walk → XDP_PASS → TC
   FIB forward) and `End.X` (SL walk → adjacency redirect from XDP, own hop
   decrement) in `cradle_xdp`; `cradle_srv6_te` BDD. The DT decap now
   exercises Phase 1's exhausted-SRH-skip for real. `End.B6.Encaps` binding
   SIDs deferred; `End.X` adjacency SIDs get their IGP-originated exercise
   with the Phase 3 tee.
3. **Phase 3 — zebra tee** *(done)*. The `CradleFib` SRv6 tee
   (`route_sid_install` → `AddLocalSid`, `segs`-on-nexthop → the encap path,
   encap source derived from the local SID's locator) so BGP L3VPN over SRv6
   drives cradle end to end; `cradle_srv6_l3vpn_zebra` BDD (iBGP VPNv4+VPNv6
   over IS-IS SRv6). (The per-VRF FIB the old Phase 3 also listed already
   landed in Phase 1; connected VRF routes come from `derive_port`, not the
   tee.) IS-IS/OSPF `End.X` adjacency SIDs and BGP color / SR-policy steering
   are producers the tee already supports but no BDD wires yet.
4. **Phase 4 — uSID & EVPN** *(uSID done)*. NEXT-C-SID micro-SID transit.
   `uN` — a prefix match (`block_bits + node_bits`) that shifts the uSID
   container left by one micro-SID (`STAT_SRV6_USID`) and forwards by the new DA;
   `cradle_srv6_usid` BDD. `uA`/`uALib` — the adjacency form: `uA` (`SRV6_BH_UA`)
   is classic `End.X` at /128; `uALib` (`SRV6_BH_UALIB`) shifts the container
   mid-carrier then forwards out the cross-connect adjacency; `cradle_srv6_ualib`
   BDD proves it with a transit node that has **no** FIB routes (only the
   adjacency delivers). `LocalSid.block_bits`/`node_bits` carry the shift geometry,
   set by the static `localsids` config and by the tee (from the SID structure's
   `lb_bits`/`ln_bits`; the tee maps `UN`→`SRV6_BH_UN`, `UA`→`SRV6_BH_UA`,
   `UALib`→`SRV6_BH_UALIB`). **EVPN over SRv6** has `End.DT2U` unicast and
   `End.DT2M` BUM (2-PE): MAC-in-SRv6 encap in the XDP stage, `End.DT2U`/`DT2M`
   decap + L2 bridge/flood via an XDP→TC bridge-domain meta, BUM tunneling via
   an all-ones-MAC FDB sentinel; `FdbEntry` gains `remote_sid`/`FDB_F_REMOTE`;
   static FDB config; `cradle_evpn_srv6` + `cradle_evpn_srv6_bum` BDDs — detailed
   in [evpn-srv6.md](evpn-srv6.md), including the **BGP EVPN control-plane
   tee** (`encapsulation srv6`: per-VNI DT2U/DT2M SIDs on Type-2/Type-3, the
   `MacAdd`/`AddFdbRemote` pathway, local L2 SIDs via the SID registry —
   `cradle_evpn_srv6_zebra` BDD). **TI-LFA uSID carriers** are also done: the
   `Nexthop::Protect` tee sends the primary paired with its repair leaf
   (packed carriers + H.Insert, `srv6_encap_mode` 2); cradle programs
   `NextHop.backup_id`, a user-space link monitor feeds `LINK_DOWN`, and
   `resolve_nh` fails over at forward time. The datapath grew **H.Insert**
   (TC, `BPF_ADJ_ROOM_NET` — original DA as the SRH's final segment), the
   **uN/uA end-of-carrier End fallback** (exhausted container → SRH walk
   restores the carried destination), and **same-node re-dispatch** (a uN
   shift exposing the node's own uA-LIB). `cradle_tilfa_srv6` proves the
   IGP-packed carrier end to end (`backup-as-primary` pins traffic onto the
   repair deterministically); `cradle_nh_backup` proves the link-down
   switchover. **End.M egress protection** is done end
   to end: `SRV6_BH_END_M` (11) runs the double decap in XDP — strip the
   repair encap, look the exposed destination (the dead PE's service SID) up
   in the `MIRROR` LPM trie (keyed by mirror-context id + prefix, fed by the
   `AddMirrorRoute`/`DelMirrorRoute` tee from zebra's
   `route_mirror_context_install`), then run the End.DT* service decap into
   the local VRF. On the PLR side `srv6_encap` re-looks the freshly-imposed
   outer DA up in the main FIB (the kernel's `seg6_lookup_nexthop`
   recursion): when the answer is itself an H.Encaps route — the Mirror SID
   retention static holding a dead egress's locator — the second layer
   stacks and the packet leaves via that route's nexthop. `cradle_endm`
   proves the whole arc (BGP VPNv6 + `pic-retention` + IS-IS Mirror SID
   node-protection retention; kill the egress node, ping survives via the
   protector's End.M). **Flavors (RFC 8986 §4.16)** are done: `LocalSid`
   carries a `flavors` bitmask (`SRV6_FLAVOR_PSP/USP/USD`, proto field 12) —
   `srv6_end` pops the SRH when its own decrement exhausts it (PSP, also on
   End.X/uA), pops an already-exhausted SRH before local delivery (USP), or
   decapsulates the outer IPv6+SRH and forwards the inner packet by the main
   table (USD, tried before USP per the RFC's composite). Conformance
   choices: USP/USD apply to End/uN only — the End.X variants would forward
   the result via the adjacency (incl. an IPv4 adjacency forward) and are
   neither executed nor advertised (End.X folds only PSP); USP's local
   delivery additionally needs the SID as a kernel-local address, which
   zebra does not install — BDD-provable, production-limited; the SRH must
   be the first extension header (the existing `srv6_end` gate). zebra: the
   locator's `flavor` leaf-list folds into the advertised IANA codepoints
   (IS-IS + OSPFv3, `Behavior::with_flavors`; the classic USD block in
   `isis-packet` was off by one vs IANA and is now pinned by test) and into
   the kernel install's single `SEG6_LOCAL_FLV_OPERATION` bitmask NLA.
   `cradle_srv6_flavors` proves all three statically; `cradle_tilfa_psp`
   proves PSP end-to-end (the TI-LFA repair pop lets r2 take the handoff
   with `seg6_enabled` off everywhere).
