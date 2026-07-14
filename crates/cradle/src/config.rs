//! Static JSON configuration.
//!
//! Used both as a server-side bootstrap (applied in-process via [`Control`]) and
//! as the payload of `cradle ctl apply` (replayed over gRPC). The shape maps
//! directly to the control-plane operations.

use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

use anyhow::{Context as _, Result};
use serde::Deserialize;
use tracing::info;

use crate::{control::Control, util};

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    /// IPv4 FIB engine, "lpm" (default) or "dir24". Load-time only — it sizes
    /// the eBPF maps, so it is consumed by `serve` before the object loads
    /// and is NOT replayable over `ctl apply`.
    #[serde(default)]
    pub fib4_mode: Option<String>,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub nexthops: Vec<Nexthop>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
    #[serde(default)]
    pub ilm: Vec<Ilm>,
    #[serde(default)]
    pub routes6: Vec<Route6>,
    #[serde(default)]
    pub localsids: Vec<LocalSidCfg>,
    /// GTP-U decap PDRs (`H.M.GTP4.D`): a G-PDU on `(dst, teid)` is stripped
    /// and its inner packet forwarded in `vrf`.
    #[serde(default)]
    pub gtp_pdrs: Vec<GtpPdrCfg>,
    /// SRv6 H.Encaps outer source address.
    #[serde(default)]
    pub srv6_source: Option<String>,
    /// Local VTEP source IPv4 (EVPN/VXLAN outer source + decap match).
    #[serde(default)]
    pub vtep_source: Option<String>,
    /// EVPN/VXLAN L2VNI bindings: VNI ↔ bridge domain.
    #[serde(default)]
    pub vnis: Vec<VniCfg>,
    /// Static overlay FDB entries (EVPN over SRv6 or VXLAN).
    #[serde(default)]
    pub fdb: Vec<FdbCfg>,
    /// BUM ingress-replication slots (EVPN over SRv6, multi-PE).
    #[serde(default)]
    pub repl_slots: Vec<ReplSlotCfg>,
    /// RFC 9524 Replication segments (`End.Replicate` SR-P2MP tree nodes).
    #[serde(default)]
    pub repl_segs: Vec<ReplSegCfg>,
    /// VPWS cross-connects: every frame from `port` is MAC-in-SRv6
    /// encapsulated toward the remote End.DX2/DX2V SID (no FDB).
    #[serde(default)]
    pub xconnects: Vec<XconnectCfg>,
    /// End.DX2V VLAN-table entries: (table, vid) → AC port.
    #[serde(default)]
    pub dx2v: Vec<Dx2vCfg>,
    /// Idle timeout (seconds) for locally-learned FDB entries; 0 disables
    /// aging. Default 300 (the kernel bridge default).
    #[serde(default = "default_fdb_age_secs")]
    pub fdb_age_secs: u64,
    #[serde(default)]
    pub services: Vec<Service>,
    /// Egress masquerade: SNAT pod→outside-the-cluster to this node IP.
    #[serde(default)]
    pub masq_node: Option<String>,
    /// CIDRs never masqueraded (pod CIDR, service CIDR, fabric subnets).
    #[serde(default)]
    pub non_masq: Vec<String>,
    /// Policy identities: pod/node IP → identity (docs/design/policy.md).
    #[serde(default)]
    pub identities: Vec<IdentityCfg>,
    /// Peer-CIDR → identity bindings (ipBlock peers).
    #[serde(default)]
    pub cidr_identities: Vec<CidrIdentityCfg>,
    /// Endpoint policies (replace semantics per endpoint).
    #[serde(default)]
    pub policies: Vec<PolicyCfg>,
    #[serde(default)]
    pub l7_services: Vec<L7ServiceCfg>,
}

fn default_fdb_age_secs() -> u64 {
    300
}

/// A BUM ingress-replication slot: one remote PE in a bridge domain's flood
/// set. `flood_port` is the slot veth's A end (declare it as an L2 port in
/// the BD so the flood reaches it); `encap_port` is the B end (declare it as
/// an L3 port so the XDP stage attaches), where each flooded copy is
/// encapsulated toward the remote PE — MAC-in-SRv6 toward `remote_sid` (its
/// End.DT2M), or VXLAN toward `remote_vtep` carrying `vni` (exactly one of
/// sid/vtep; `vni` is required with `remote_vtep` — static slots name ports,
/// not a bridge domain, so there is no binding to resolve it from).
#[derive(Debug, Deserialize)]
pub struct ReplSlotCfg {
    pub flood_port: String,
    pub encap_port: String,
    #[serde(default)]
    pub remote_sid: Option<String>,
    #[serde(default)]
    pub remote_vtep: Option<String>,
    #[serde(default)]
    pub vni: Option<u32>,
}

/// An RFC 9524 Replication segment: the local `End.Replicate` SID `sid` (also
/// register it as a `localsids` entry with `behavior: end.replicate`) fans a
/// received copy out to each `branches` entry.
#[derive(Debug, Deserialize)]
pub struct ReplSegCfg {
    pub sid: String,
    #[serde(default)]
    pub branches: Vec<ReplSegBranchCfg>,
    /// RFC 9524 Hop-Limit Threshold (0 = disabled).
    #[serde(default)]
    pub hop_limit_threshold: u8,
}

/// One downstream branch of a [`ReplSegCfg`]: a copy is steered to `sid` — a
/// remote leaf's `End.DT2M` SID or the next tier's `End.Replicate` SID
/// (`nexthop` 0 = FIB6 lookup on the SID) — or, when `local`, delivered into
/// the bridge domain via a cradle-owned leaf veth (`sid` is this node's own
/// `End.DT2M` SID).
#[derive(Debug, Deserialize)]
pub struct ReplSegBranchCfg {
    pub sid: String,
    #[serde(default)]
    pub nexthop: u32,
    #[serde(default)]
    pub local: bool,
}

/// A static overlay FDB entry: the MAC `mac` in bridge domain `bd` is behind
/// a remote PE — over SRv6 (`remote_sid`, the PE's `End.DT2U`/`DT2M` SID) or
/// over VXLAN (`remote_vtep`, the PE's VTEP IPv4; the VNI comes from the BD's
/// `vnis` binding). Exactly one of the two. Reached via underlay nexthop
/// `nexthop` (0 = FIB lookup on the SID/VTEP).
#[derive(Debug, Deserialize)]
pub struct FdbCfg {
    pub mac: String,
    pub bd: u16,
    #[serde(default)]
    pub remote_sid: Option<String>,
    #[serde(default)]
    pub remote_vtep: Option<String>,
    #[serde(default)]
    pub nexthop: u32,
}

/// An EVPN/VXLAN VNI binding. An **L2VNI** (default): frames in bridge domain
/// `vlan` tunnel with `vni`, received frames bridge in `vlan`. An **L3VNI**
/// (`l3: true`, symmetric IRB): received frames route their inner IP in `vrf`,
/// with this PE's router MAC `rmac` — `vlan` is unused.
#[derive(Debug, Deserialize)]
pub struct VniCfg {
    pub vni: u32,
    #[serde(default)]
    pub vlan: u16,
    /// L3VNI (symmetric IRB) instead of an L2VNI.
    #[serde(default)]
    pub l3: bool,
    /// VRF the inner IP is routed in (L3VNI).
    #[serde(default)]
    pub vrf: u32,
    /// This PE's router MAC for the L3VNI.
    #[serde(default)]
    pub rmac: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Route6 {
    pub prefix: String,
    pub nexthop: u32,
    #[serde(default)]
    pub vrf: u32,
}

/// A local SID: `behavior` is
/// `end|end.x|end.dt4|end.dt6|end.dt46|end.b6|un|ua|ualib|end.replace|
/// end.x.replace`.
/// uSID (`un`/`ua`) SIDs match at `prefix_len` (block+node, e.g. 48) and carry
/// the `block_bits`/`node_bits` NEXT-C-SID shift geometry; classic SIDs match
/// at the default /128. REPLACE-C-SID SIDs match at block+C-SID (e.g. 80) and
/// carry `block_bits` plus the C-SID width as `node_bits + fun_bits` (16/32).
#[derive(Debug, Deserialize)]
pub struct LocalSidCfg {
    pub sid: String,
    pub behavior: String,
    #[serde(default)]
    pub vrf: u32,
    #[serde(default)]
    pub nexthop: u32,
    /// LPM prefix length the SID matches at (default 128; uSID SIDs use e.g. 48).
    #[serde(default)]
    pub prefix_len: u8,
    /// uSID locator-block bit length (0 = not a uSID).
    #[serde(default)]
    pub block_bits: u8,
    /// uSID node (micro-SID) bit length (0 = not a uSID).
    #[serde(default)]
    pub node_bits: u8,
    /// Function bit length (REPLACE-C-SID: C-SID width = node + fun bits).
    #[serde(default)]
    pub fun_bits: u8,
    /// Attachment-circuit port for `end.dx2` (resolved to an ifindex and
    /// carried in the SID's `vrf` slot). For `end.dx2v` use `vrf` as the
    /// VLAN-table id and populate `dx2v` entries instead.
    #[serde(default)]
    pub port: String,
    /// Endpoint flavors (RFC 8986 §4.16): any of `psp`, `usp`, `usd`.
    #[serde(default)]
    pub flavors: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct XconnectCfg {
    pub port: String,
    pub remote_sid: String,
    /// Non-zero = VLAN-scoped E-Line: only 802.1Q frames with this VID on
    /// `port` enter the cross-connect (tag kept). The return direction is
    /// a separate `locals` End.DX2V + `dx2v` entry as usual.
    #[serde(default)]
    pub vid: u16,
}

#[derive(Debug, Deserialize)]
pub struct Dx2vCfg {
    pub table: u32,
    pub vid: u16,
    pub port: String,
}

#[derive(Debug, Deserialize)]
pub struct L7ServiceCfg {
    pub vip: String,
    pub port: u16,
    pub routes: Vec<L7RouteCfg>,
}

#[derive(Debug, Deserialize)]
pub struct L7RouteCfg {
    #[serde(default = "default_prefix")]
    pub prefix: String,
    pub backend: String, // "ip:port"
}

fn default_prefix() -> String {
    "/".to_string()
}

#[derive(Debug, Deserialize)]
pub struct Port {
    pub name: String,
    #[serde(default)]
    pub l3: bool,
    #[serde(default)]
    pub vlan: u16,
    /// VRF table an L3 port belongs to (0 = global).
    #[serde(default)]
    pub vrf: u32,
}

#[derive(Debug, Deserialize)]
pub struct Nexthop {
    pub id: u32,
    /// Output interface. Absent = an oif-less nexthop (e.g. an ILM
    /// decap/local-chain target that never egresses through it).
    #[serde(default)]
    pub oif: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    /// MPLS out-label stack, `[0]` = outermost (swap value / imposition).
    #[serde(default)]
    pub labels: Vec<u32>,
    /// SRv6 SID list (H.Encaps). A non-empty list makes this an SRv6 nexthop
    /// (`gateway`/`oif` are the underlay next hop).
    #[serde(default)]
    pub segs: Vec<String>,
    /// SRv6 imposition mode: 0 = H.Encaps(.Red), 2 = H.Insert (TI-LFA).
    #[serde(default)]
    pub encap_mode: u8,
    /// Fast-reroute: nexthop id to fail over to when this one's link is down.
    #[serde(default)]
    pub backup: u32,
    /// GTP-U encap (`GTP4.E`): a present `gtp_dst` makes this a GTP nexthop that
    /// wraps the packet in outer IPv4 + UDP(2152) + GTP-U(`gtp_teid`) toward
    /// `gtp_dst`, sourced from `gtp_src`, over the v4 underlay `gateway`/`oif`.
    #[serde(default)]
    pub gtp_src: Option<String>,
    #[serde(default)]
    pub gtp_dst: Option<String>,
    #[serde(default)]
    pub gtp_teid: u32,
    /// EVPN symmetric-IRB VXLAN L3 encap: a present `vxlan_vtep` makes this an
    /// `NH_F_VXLAN` nexthop that VXLAN-wraps the routed packet with
    /// `vxlan_l3vni` toward `vxlan_vtep` (inner dst MAC = `vxlan_rmac`, the
    /// remote PE's router MAC), over the v4 underlay `gateway`/`oif`.
    #[serde(default)]
    pub vxlan_vtep: Option<String>,
    #[serde(default)]
    pub vxlan_l3vni: u32,
    #[serde(default)]
    pub vxlan_rmac: Option<String>,
    /// MPLS TTL model at imposition (RFC 3443). `false` (default) = uniform
    /// (seed the label TTL from the inner IP TTL); `true` = pipe (seed 255,
    /// hiding the LSP hop count). Only meaningful with a non-empty `labels`.
    #[serde(default)]
    pub mpls_pipe: bool,
}

/// A GTP-U decap PDR (`H.M.GTP4.D`).
#[derive(Debug, Deserialize)]
pub struct GtpPdrCfg {
    /// Local outer IPv4 destination a received G-PDU arrives on.
    pub dst: String,
    /// GTP-U TEID.
    pub teid: u32,
    /// Inner VRF table id (0 = global).
    #[serde(default)]
    pub vrf: u32,
}

/// An incoming-label map entry: `action` is `"swap"`, `"pop"` or `"pop-l3"`.
#[derive(Debug, Deserialize)]
pub struct Ilm {
    pub in_label: u32,
    pub nexthop: u32,
    pub action: String,
    #[serde(default)]
    pub vrf: u32,
    /// MPLS TTL model at disposition (RFC 3443). `false` (default) = pipe
    /// (discard the label TTL, preserve the inner IP TTL); `true` = uniform
    /// (copy the popped label TTL into the inner IP header on pop-to-IP).
    #[serde(default)]
    pub ttl_uniform: bool,
}

#[derive(Debug, Deserialize)]
pub struct Route {
    pub prefix: String,
    pub nexthop: u32,
    /// VRF table (0 = global).
    #[serde(default)]
    pub vrf: u32,
}

#[derive(Debug, Deserialize)]
pub struct Neighbor {
    pub oif: String,
    pub ip: String,
    pub mac: String,
}

#[derive(Debug, Deserialize)]
pub struct IdentityCfg {
    pub ip: String,
    pub id: u32,
    /// Identity scope (0 = global).
    #[serde(default)]
    pub vrf: u32,
}

/// An endpoint policy: target by `host_if` or `namespace`/`pod`. `enforce`
/// gates the ingress `rules`, `enforce_egress` the `egress_rules`.
#[derive(Debug, Deserialize)]
pub struct PolicyCfg {
    #[serde(default)]
    pub host_if: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub pod: String,
    #[serde(default = "default_true")]
    pub enforce: bool,
    #[serde(default)]
    pub rules: Vec<PolicyRuleCfg>,
    #[serde(default)]
    pub enforce_egress: bool,
    #[serde(default)]
    pub egress_rules: Vec<PolicyRuleCfg>,
    /// Audit mode: report denied verdicts, forward the packets.
    #[serde(default)]
    pub audit: bool,
    /// Ingress L7 (HTTP) policy per port.
    #[serde(default)]
    pub l7: Vec<L7PortCfg>,
}

#[derive(Debug, Deserialize)]
pub struct L7PortCfg {
    pub port: u16,
    #[serde(default)]
    pub rules: Vec<L7RuleCfg>,
}

/// Empty method/path = any.
#[derive(Debug, Deserialize)]
pub struct L7RuleCfg {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub path: String,
}

fn default_true() -> bool {
    true
}

/// A peer-CIDR → identity binding (ipBlock peers; v4 or v6).
#[derive(Debug, Deserialize)]
pub struct CidrIdentityCfg {
    pub cidr: String,
    pub id: u32,
    /// Identity scope (0 = global).
    #[serde(default)]
    pub vrf: u32,
}

/// An allow rule: 0 / empty = wildcard.
#[derive(Debug, Deserialize)]
pub struct PolicyRuleCfg {
    #[serde(default)]
    pub identity: u32,
    /// "tcp", "udp", or empty = any.
    #[serde(default)]
    pub proto: String,
    #[serde(default)]
    pub port: u16,
    /// Deny rule: wins over allow at any specificity.
    #[serde(default)]
    pub deny: bool,
}

/// Parse a policy-rule proto ("" = any).
pub fn rule_proto(s: &str) -> Result<u8> {
    match s {
        "" | "any" => Ok(0),
        other => proto_num(other),
    }
}

#[derive(Debug, Deserialize)]
pub struct Service {
    pub vip: String,
    pub port: u16,
    #[serde(default = "default_proto")]
    pub proto: String,
    #[serde(default)]
    pub affinity: bool,
    pub backends: Vec<BackendCfg>,
}

#[derive(Debug, Deserialize)]
pub struct BackendCfg {
    pub ip: String,
    pub port: u16,
}

fn default_proto() -> String {
    "tcp".to_string()
}

/// Group non-L3 ports into `(vlan -> member interface names)` L2 domains.
pub fn l2_domains(ports: &[Port]) -> BTreeMap<u16, Vec<String>> {
    let mut domains: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    for p in ports {
        if !p.l3 {
            domains.entry(p.vlan).or_default().push(p.name.clone());
        }
    }
    domains
}

/// Parse a service proto string to its IP protocol number.
pub fn proto_num(proto: &str) -> Result<u8> {
    match proto {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        other => anyhow::bail!("unknown service proto {other:?} (want tcp|udp)"),
    }
}

/// Parse an SRv6 behavior string to its `SRV6_BH_*` value.
pub fn srv6_behavior(s: &str) -> Result<u8> {
    use cradle_common::*;
    Ok(match s {
        "end" => SRV6_BH_END,
        "end.x" => SRV6_BH_END_X,
        "end.dt4" => SRV6_BH_END_DT4,
        "end.dt6" => SRV6_BH_END_DT6,
        "end.dt46" => SRV6_BH_END_DT46,
        "end.b6" => SRV6_BH_END_B6,
        "un" => SRV6_BH_UN,
        "ua" => SRV6_BH_UA,
        "ualib" => SRV6_BH_UALIB,
        "end.t" => SRV6_BH_END_T,
        "end.dx4" => SRV6_BH_END_DX4,
        "end.dx6" => SRV6_BH_END_DX6,
        "end.dx2" => SRV6_BH_END_DX2,
        "end.dx2v" => SRV6_BH_END_DX2V,
        "end.dt2u" => SRV6_BH_END_DT2U,
        "end.dt2m" => SRV6_BH_END_DT2M,
        "end.replace" => SRV6_BH_END_REP,
        "end.x.replace" => SRV6_BH_END_X_REP,
        "end.replicate" => SRV6_BH_END_REPLICATE,
        other => anyhow::bail!("unknown SRv6 behavior {other:?}"),
    })
}

/// Parse a flavor list (`psp`/`usp`/`usd`) to its `SRV6_FLAVOR_*` bitmask.
pub fn srv6_flavors(list: &[String]) -> Result<u8> {
    use cradle_common::*;
    let mut mask = 0u8;
    for f in list {
        mask |= match f.as_str() {
            "psp" => SRV6_FLAVOR_PSP,
            "usp" => SRV6_FLAVOR_USP,
            "usd" => SRV6_FLAVOR_USD,
            other => anyhow::bail!("unknown SRv6 flavor {other:?}"),
        };
    }
    Ok(mask)
}

/// Parse an ILM action string to its `MPLS_OP_*` value.
pub fn ilm_action(action: &str) -> Result<u8> {
    match action {
        "swap" => Ok(cradle_common::MPLS_OP_SWAP),
        "pop" => Ok(cradle_common::MPLS_OP_POP),
        "pop-l3" => Ok(cradle_common::MPLS_OP_POP_L3),
        other => anyhow::bail!("unknown ILM action {other:?} (want swap|pop|pop-l3)"),
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parsing config {}", path.display()))
    }

    /// Apply this configuration in-process via the control plane.
    pub async fn apply_control(&self, ctl: &Control) -> Result<()> {
        for p in &self.ports {
            ctl.set_port(&p.name, None, p.l3, p.vlan, p.vrf).await?;
        }
        for (vlan, members) in l2_domains(&self.ports) {
            ctl.set_l2_domain(vlan, &members).await?;
        }
        if let Some(src) = &self.srv6_source {
            let addr = src
                .parse()
                .with_context(|| format!("bad srv6_source {src:?}"))?;
            ctl.set_srv6_encap_source(addr).await?;
        }
        if let Some(src) = &self.vtep_source {
            let addr = src
                .parse()
                .with_context(|| format!("bad vtep_source {src:?}"))?;
            ctl.set_vtep_source(addr).await?;
        }
        for v in &self.vnis {
            if v.l3 {
                let rmac = util::parse_mac(
                    v.rmac
                        .as_deref()
                        .with_context(|| format!("L3VNI {} needs an rmac", v.vni))?,
                )?;
                ctl.set_vni_l3(v.vni, v.vrf, rmac).await?;
            } else {
                ctl.set_vni(v.vni, v.vlan).await?;
            }
        }
        for nh in &self.nexthops {
            if let Some(vtep) = &nh.vxlan_vtep {
                let gw = match &nh.gateway {
                    Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                    None => None,
                };
                let oif = match &nh.oif {
                    Some(o) => util::ifindex_of(o)?,
                    None => anyhow::bail!("VXLAN nexthop {} needs an oif", nh.id),
                };
                let vtep = vtep
                    .parse()
                    .with_context(|| format!("bad vxlan_vtep {vtep:?}"))?;
                let rmac = util::parse_mac(
                    nh.vxlan_rmac
                        .as_deref()
                        .with_context(|| format!("VXLAN nexthop {} needs a vxlan_rmac", nh.id))?,
                )?;
                ctl.set_nexthop_vxlan(nh.id, gw, oif, vtep, nh.vxlan_l3vni, rmac)
                    .await?;
                continue;
            }
            if let Some(dst) = &nh.gtp_dst {
                let gw = match &nh.gateway {
                    Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                    None => None,
                };
                let oif = match &nh.oif {
                    Some(o) => util::ifindex_of(o)?,
                    None => anyhow::bail!("GTP nexthop {} needs an oif", nh.id),
                };
                let src = nh
                    .gtp_src
                    .as_deref()
                    .unwrap_or("0.0.0.0")
                    .parse()
                    .context("bad gtp_src")?;
                let dst = dst
                    .parse()
                    .with_context(|| format!("bad gtp_dst {dst:?}"))?;
                ctl.set_nexthop_gtp(nh.id, gw, oif, src, dst, nh.gtp_teid)
                    .await?;
                continue;
            }
            if !nh.segs.is_empty() {
                let gw = match &nh.gateway {
                    Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                    None => None,
                };
                let oif = match &nh.oif {
                    Some(o) => util::ifindex_of(o)?,
                    None => anyhow::bail!("SRv6 nexthop {} needs an oif", nh.id),
                };
                let segs = nh
                    .segs
                    .iter()
                    .map(|s| s.parse().with_context(|| format!("bad SID {s:?}")))
                    .collect::<Result<Vec<_>>>()?;
                ctl.set_nexthop_srv6(nh.id, gw, oif, &segs, nh.encap_mode)
                    .await?;
                continue;
            }
            // Family inferred from the gateway (a v6 gateway ⇒ v6 nexthop).
            let is_v6 = nh
                .gateway
                .as_deref()
                .map(|g| g.contains(':'))
                .unwrap_or(false);
            let oif = match &nh.oif {
                Some(o) => util::ifindex_of(o)?,
                None => 0,
            };
            if is_v6 {
                let gw = match &nh.gateway {
                    Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                    None => None,
                };
                ctl.set_nexthop_idx_v6(nh.id, gw, oif, &nh.labels, nh.backup, nh.mpls_pipe)
                    .await?;
            } else {
                let gw = match &nh.gateway {
                    Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                    None => None,
                };
                ctl.set_nexthop_idx(nh.id, gw, oif, &nh.labels, nh.backup, nh.mpls_pipe)
                    .await?;
            }
        }
        for ls in &self.localsids {
            let sid = ls
                .sid
                .parse()
                .with_context(|| format!("bad SID {:?}", ls.sid))?;
            let behavior = srv6_behavior(&ls.behavior)?;
            let prefix_len = if ls.prefix_len == 0 {
                128
            } else {
                ls.prefix_len
            };
            // end.dx2: the AC port rides in the vrf slot as an ifindex.
            let vrf = if ls.port.is_empty() {
                ls.vrf
            } else {
                util::ifindex_of(&ls.port)?
            };
            ctl.add_localsid(
                sid,
                prefix_len,
                behavior,
                vrf,
                ls.nexthop,
                ls.block_bits,
                ls.node_bits,
                ls.fun_bits,
                srv6_flavors(&ls.flavors)?,
            )
            .await?;
        }
        for pdr in &self.gtp_pdrs {
            let dst = pdr
                .dst
                .parse()
                .with_context(|| format!("bad gtp pdr dst {:?}", pdr.dst))?;
            ctl.gtp_pdr_add(dst, pdr.teid, pdr.vrf).await?;
        }
        for f in &self.fdb {
            let mac = util::parse_mac(&f.mac)?;
            match (&f.remote_sid, &f.remote_vtep) {
                (Some(sid), None) => {
                    let remote_sid = sid
                        .parse()
                        .with_context(|| format!("bad remote SID {sid:?}"))?;
                    ctl.add_fdb_remote(mac, f.bd, remote_sid, f.nexthop).await?;
                }
                (None, Some(vtep)) => {
                    let vtep = vtep
                        .parse()
                        .with_context(|| format!("bad remote VTEP {vtep:?}"))?;
                    ctl.add_fdb_remote_vxlan(mac, f.bd, vtep, f.nexthop).await?;
                }
                _ => anyhow::bail!(
                    "fdb entry {}: exactly one of remote_sid / remote_vtep",
                    f.mac
                ),
            }
        }
        for r in &self.repl_slots {
            match (&r.remote_sid, &r.remote_vtep) {
                (Some(sid), None) => {
                    let remote_sid = sid
                        .parse()
                        .with_context(|| format!("bad remote SID {sid:?}"))?;
                    ctl.add_repl_slot(&r.flood_port, &r.encap_port, remote_sid)
                        .await?;
                }
                (None, Some(vtep)) => {
                    let vtep = vtep
                        .parse()
                        .with_context(|| format!("bad remote VTEP {vtep:?}"))?;
                    let vni = r.vni.with_context(|| {
                        format!("repl slot {}: remote_vtep needs a vni", r.flood_port)
                    })?;
                    ctl.add_repl_slot_vxlan(&r.flood_port, &r.encap_port, vtep, vni)
                        .await?;
                }
                _ => anyhow::bail!(
                    "repl slot {}: exactly one of remote_sid / remote_vtep",
                    r.flood_port
                ),
            }
        }
        for rs in &self.repl_segs {
            let sid = rs
                .sid
                .parse()
                .with_context(|| format!("bad End.Replicate SID {:?}", rs.sid))?;
            let mut branches = Vec::with_capacity(rs.branches.len());
            for b in &rs.branches {
                let bsid = b
                    .sid
                    .parse()
                    .with_context(|| format!("bad branch SID {:?}", b.sid))?;
                branches.push((bsid, b.nexthop, b.local));
            }
            ctl.set_repl_seg(sid, rs.hop_limit_threshold, branches)
                .await?;
        }
        for x in &self.xconnects {
            let remote_sid = x
                .remote_sid
                .parse()
                .with_context(|| format!("bad remote SID {:?}", x.remote_sid))?;
            ctl.add_xconnect(&x.port, remote_sid, None, x.vid, 0)
                .await?;
        }
        for d in &self.dx2v {
            ctl.add_dx2v(d.table, d.vid, &d.port).await?;
        }
        for n in &self.neighbors {
            let ip: IpAddr =
                n.ip.parse()
                    .with_context(|| format!("bad neighbor ip {:?}", n.ip))?;
            let mac = util::parse_mac(&n.mac)?;
            match ip {
                IpAddr::V4(v4) => ctl.set_neighbor4(&n.oif, v4, mac).await?,
                IpAddr::V6(v6) => ctl.set_neighbor6(&n.oif, v6, mac).await?,
            }
        }
        for i in &self.ilm {
            let op = ilm_action(&i.action)?;
            let flags = if i.ttl_uniform {
                cradle_common::MPLS_E_TTL_UNIFORM
            } else {
                0
            };
            ctl.add_ilm(i.in_label, i.nexthop, op, i.vrf, flags).await?;
        }
        // Bulk-install: the bootstrap config is an initial load, so all
        // routes go down in one plan (one block sync per affected /24).
        let routes = self
            .routes
            .iter()
            .map(|r| {
                let (addr, len) = util::parse_ipv4_prefix(&r.prefix)?;
                Ok((r.vrf, addr, len, r.nexthop, 0u32))
            })
            .collect::<Result<Vec<_>>>()?;
        if !routes.is_empty() {
            ctl.add_routes4(&routes).await?;
        }
        for r in &self.routes6 {
            let (addr, len) = util::parse_ipv6_prefix(&r.prefix)?;
            ctl.add_route6(r.vrf, addr, len, r.nexthop, 0).await?;
        }
        for (i, svc) in self.services.iter().enumerate() {
            let proto = proto_num(&svc.proto)?;
            let svc_id = i as u32 + 1;
            let vip: IpAddr = svc
                .vip
                .parse()
                .with_context(|| format!("bad VIP {:?}", svc.vip))?;
            match vip {
                IpAddr::V4(v4) => {
                    let backends = svc
                        .backends
                        .iter()
                        .map(|b| {
                            let ip =
                                b.ip.parse::<Ipv4Addr>()
                                    .with_context(|| format!("bad backend ip {:?}", b.ip))?;
                            Ok((ip, b.port))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    ctl.add_service(svc_id, v4, svc.port, proto, &backends, svc.affinity)
                        .await?;
                }
                IpAddr::V6(v6) => {
                    let backends = svc
                        .backends
                        .iter()
                        .map(|b| {
                            let ip =
                                b.ip.parse::<Ipv6Addr>()
                                    .with_context(|| format!("bad backend ip {:?}", b.ip))?;
                            Ok((ip, b.port))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    ctl.add_service6(svc_id, v6, svc.port, proto, &backends, svc.affinity)
                        .await?;
                }
            }
        }

        if let Some(node) = &self.masq_node {
            let ip = node
                .parse()
                .with_context(|| format!("bad masq_node {node:?}"))?;
            ctl.set_masq_node(Some(ip)).await?;
        }
        for cidr in &self.non_masq {
            let (net, len) = util::parse_ipv4_prefix(cidr)?;
            ctl.add_non_masq(net, len).await?;
        }
        for i in &self.identities {
            match i
                .ip
                .parse::<IpAddr>()
                .with_context(|| format!("bad identity ip {:?}", i.ip))?
            {
                IpAddr::V4(ip) => ctl.set_identity(i.vrf, ip, i.id).await?,
                IpAddr::V6(ip) => ctl.set_identity6(i.vrf, ip, i.id, false).await?,
            }
        }
        for c in &self.cidr_identities {
            if c.cidr.contains(':') {
                let (net, len) = util::parse_ipv6_prefix(&c.cidr)?;
                ctl.set_cidr6_identity(c.vrf, net, len, c.id, false).await?;
            } else {
                let (net, len) = util::parse_ipv4_prefix(&c.cidr)?;
                ctl.set_cidr_identity(c.vrf, net, len, c.id, false).await?;
            }
        }
        for pol in &self.policies {
            let ep = ctl
                .resolve_endpoint(&pol.host_if, &pol.namespace, &pol.pod)
                .await?;
            let as_tuples = |rs: &[PolicyRuleCfg]| -> Result<Vec<(u32, u8, u16, bool)>> {
                rs.iter()
                    .map(|r| Ok((r.identity, rule_proto(&r.proto)?, r.port, r.deny)))
                    .collect()
            };
            let rules = as_tuples(&pol.rules)?;
            let egress_rules = as_tuples(&pol.egress_rules)?;
            let l7: Vec<(u16, Vec<crate::l7::L7PolicyRule>)> = pol
                .l7
                .iter()
                .map(|pp| {
                    (
                        pp.port,
                        pp.rules
                            .iter()
                            .map(|r| crate::l7::L7PolicyRule {
                                method: r.method.clone(),
                                path: r.path.clone(),
                            })
                            .collect(),
                    )
                })
                .collect();
            ctl.set_endpoint_policy(
                ep,
                pol.enforce,
                pol.enforce_egress,
                pol.audit,
                &rules,
                &egress_rules,
                &l7,
            )
            .await?;
        }

        for svc in &self.l7_services {
            let vip: Ipv4Addr = svc
                .vip
                .parse()
                .with_context(|| format!("bad L7 VIP {:?}", svc.vip))?;
            let routes = svc
                .routes
                .iter()
                .map(|r| {
                    let backend = r
                        .backend
                        .parse()
                        .with_context(|| format!("bad L7 backend {:?}", r.backend))?;
                    Ok(crate::l7::L7Route {
                        prefix: r.prefix.clone(),
                        backend,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            ctl.add_l7_service(vip, svc.port, routes).await?;
        }

        info!(
            "applied config: {} ports, {} nexthops, {} neighbors, {} ilm, {} routes, {} services, {} l7-services",
            self.ports.len(),
            self.nexthops.len(),
            self.neighbors.len(),
            self.ilm.len(),
            self.routes.len(),
            self.services.len(),
            self.l7_services.len(),
        );
        Ok(())
    }
}
