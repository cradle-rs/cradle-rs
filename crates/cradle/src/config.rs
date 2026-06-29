//! Static JSON configuration.
//!
//! Used both as a server-side bootstrap (applied in-process via [`Control`]) and
//! as the payload of `cradle ctl apply` (replayed over gRPC). The shape maps
//! directly to the control-plane operations.

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::{Context as _, Result};
use serde::Deserialize;
use tracing::info;

use crate::{control::Control, util};

#[derive(Debug, Default, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub nexthops: Vec<Nexthop>,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
    #[serde(default)]
    pub services: Vec<Service>,
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
            ctl.set_nexthop(nh.id, gw, &nh.oif).await?;
        }
        for n in &self.neighbors {
            let ip = n.ip.parse().with_context(|| format!("bad neighbor ip {:?}", n.ip))?;
            let mac = util::parse_mac(&n.mac)?;
            ctl.set_neighbor4(&n.oif, ip, mac).await?;
        }
        for r in &self.routes {
            let (addr, len) = util::parse_ipv4_prefix(&r.prefix)?;
            ctl.add_route4(addr, len, r.nexthop, 0).await?;
        }
        for (i, svc) in self.services.iter().enumerate() {
            let vip = svc.vip.parse().with_context(|| format!("bad VIP {:?}", svc.vip))?;
            let proto = proto_num(&svc.proto)?;
            let backends = svc
                .backends
                .iter()
                .map(|b| {
                    let ip = b.ip.parse().with_context(|| format!("bad backend ip {:?}", b.ip))?;
                    Ok((ip, b.port))
                })
                .collect::<Result<Vec<_>>>()?;
            ctl.add_service(i as u32 + 1, vip, svc.port, proto, &backends).await?;
        }

        info!(
            "applied config: {} ports, {} nexthops, {} neighbors, {} routes, {} services",
            self.ports.len(),
            self.nexthops.len(),
            self.neighbors.len(),
            self.routes.len(),
            self.services.len(),
        );
        Ok(())
    }
}
