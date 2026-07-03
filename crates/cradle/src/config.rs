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
    /// SRv6 H.Encaps outer source address.
    #[serde(default)]
    pub srv6_source: Option<String>,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub l7_services: Vec<L7ServiceCfg>,
}

#[derive(Debug, Deserialize)]
pub struct Route6 {
    pub prefix: String,
    pub nexthop: u32,
    #[serde(default)]
    pub vrf: u32,
}

/// A local SID: `behavior` is `end|end.x|end.dt4|end.dt6|end.dt46|end.b6|un|ua`.
#[derive(Debug, Deserialize)]
pub struct LocalSidCfg {
    pub sid: String,
    pub behavior: String,
    #[serde(default)]
    pub vrf: u32,
    #[serde(default)]
    pub nexthop: u32,
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
}

/// An incoming-label map entry: `action` is `"swap"`, `"pop"` or `"pop-l3"`.
#[derive(Debug, Deserialize)]
pub struct Ilm {
    pub in_label: u32,
    pub nexthop: u32,
    pub action: String,
    #[serde(default)]
    pub vrf: u32,
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
pub struct Service {
    pub vip: String,
    pub port: u16,
    #[serde(default = "default_proto")]
    pub proto: String,
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
        other => anyhow::bail!("unknown SRv6 behavior {other:?}"),
    })
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
            let addr = src.parse().with_context(|| format!("bad srv6_source {src:?}"))?;
            ctl.set_srv6_encap_source(addr).await?;
        }
        for nh in &self.nexthops {
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
                ctl.set_nexthop_srv6(nh.id, gw, oif, &segs).await?;
                continue;
            }
            // Family inferred from the gateway (a v6 gateway ⇒ v6 nexthop).
            let is_v6 = nh.gateway.as_deref().map(|g| g.contains(':')).unwrap_or(false);
            let oif = match &nh.oif {
                Some(o) => util::ifindex_of(o)?,
                None => 0,
            };
            if is_v6 {
                let gw = match &nh.gateway {
                    Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                    None => None,
                };
                ctl.set_nexthop_idx_v6(nh.id, gw, oif, &nh.labels).await?;
            } else {
                let gw = match &nh.gateway {
                    Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                    None => None,
                };
                ctl.set_nexthop_idx(nh.id, gw, oif, &nh.labels).await?;
            }
        }
        for ls in &self.localsids {
            let sid = ls.sid.parse().with_context(|| format!("bad SID {:?}", ls.sid))?;
            let behavior = srv6_behavior(&ls.behavior)?;
            ctl.add_localsid(sid, 128, behavior, ls.vrf, ls.nexthop).await?;
        }
        for n in &self.neighbors {
            let ip: IpAddr = n.ip.parse().with_context(|| format!("bad neighbor ip {:?}", n.ip))?;
            let mac = util::parse_mac(&n.mac)?;
            match ip {
                IpAddr::V4(v4) => ctl.set_neighbor4(&n.oif, v4, mac).await?,
                IpAddr::V6(v6) => ctl.set_neighbor6(&n.oif, v6, mac).await?,
            }
        }
        for i in &self.ilm {
            let op = ilm_action(&i.action)?;
            ctl.add_ilm(i.in_label, i.nexthop, op, i.vrf).await?;
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
            let vip: IpAddr = svc.vip.parse().with_context(|| format!("bad VIP {:?}", svc.vip))?;
            match vip {
                IpAddr::V4(v4) => {
                    let backends = svc
                        .backends
                        .iter()
                        .map(|b| {
                            let ip = b
                                .ip
                                .parse::<Ipv4Addr>()
                                .with_context(|| format!("bad backend ip {:?}", b.ip))?;
                            Ok((ip, b.port))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    ctl.add_service(svc_id, v4, svc.port, proto, &backends).await?;
                }
                IpAddr::V6(v6) => {
                    let backends = svc
                        .backends
                        .iter()
                        .map(|b| {
                            let ip = b
                                .ip
                                .parse::<Ipv6Addr>()
                                .with_context(|| format!("bad backend ip {:?}", b.ip))?;
                            Ok((ip, b.port))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    ctl.add_service6(svc_id, v6, svc.port, proto, &backends).await?;
                }
            }
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
