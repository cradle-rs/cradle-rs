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
    pub services: Vec<Service>,
    #[serde(default)]
    pub l7_services: Vec<L7ServiceCfg>,
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
}

#[derive(Debug, Deserialize)]
pub struct Nexthop {
    pub id: u32,
    pub oif: String,
    #[serde(default)]
    pub gateway: Option<String>,
    /// MPLS out-label stack, `[0]` = outermost (swap value / imposition).
    #[serde(default)]
    pub labels: Vec<u32>,
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
            ctl.set_port(&p.name, None, p.l3, p.vlan).await?;
        }
        for (vlan, members) in l2_domains(&self.ports) {
            ctl.set_l2_domain(vlan, &members).await?;
        }
        for nh in &self.nexthops {
            let gw = match &nh.gateway {
                Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                None => None,
            };
            ctl.set_nexthop(nh.id, gw, &nh.oif, &nh.labels).await?;
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
        for r in &self.routes {
            let (addr, len) = util::parse_ipv4_prefix(&r.prefix)?;
            ctl.add_route4(addr, len, r.nexthop, 0).await?;
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
