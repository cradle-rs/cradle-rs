//! Static JSON configuration — the Phase-1 route-injection mechanism.
//!
//! This is deliberately simple; it will be superseded by the gRPC/unix-socket
//! API and ultimately by the zebra-rs control plane. The shape maps directly to
//! [`Dataplane`] operations.

use std::{fs, path::Path};

use anyhow::{Context as _, Result};
use serde::Deserialize;
use tracing::info;

use crate::{dataplane::Dataplane, util};
use cradle_common::{PORT_F_L2, PORT_F_L3};

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
}

#[derive(Debug, Deserialize)]
pub struct Port {
    pub name: String,
    /// Routed (L3) port — the datapath classifier is attached to its ingress.
    #[serde(default)]
    pub l3: bool,
}

#[derive(Debug, Deserialize)]
pub struct Nexthop {
    pub id: u32,
    /// Output interface name.
    pub oif: String,
    /// Gateway address; omit for an on-link/connected nexthop.
    #[serde(default)]
    pub gateway: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Route {
    /// `a.b.c.d/len`.
    pub prefix: String,
    /// Nexthop id.
    pub nexthop: u32,
}

#[derive(Debug, Deserialize)]
pub struct Neighbor {
    /// Interface the neighbor is reachable on.
    pub oif: String,
    pub ip: String,
    pub mac: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let s = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        serde_json::from_str(&s).with_context(|| format!("parsing config {}", path.display()))
    }

    /// L3 ports the datapath classifier should be attached to.
    pub fn l3_ports(&self) -> impl Iterator<Item = &str> {
        self.ports.iter().filter(|p| p.l3).map(|p| p.name.as_str())
    }

    /// Program the data plane from this configuration.
    pub fn apply(&self, dp: &mut Dataplane) -> Result<()> {
        for p in &self.ports {
            let ifindex = util::ifindex_of(&p.name)?;
            let mac = util::mac_of(&p.name)?;
            let flags = if p.l3 { PORT_F_L3 } else { PORT_F_L2 };
            dp.port_set(ifindex, mac, flags)?;
        }
        for nh in &self.nexthops {
            let oif = util::ifindex_of(&nh.oif)?;
            let gateway = match &nh.gateway {
                Some(g) => Some(g.parse().with_context(|| format!("bad gateway {g:?}"))?),
                None => None,
            };
            dp.nexthop_set(nh.id, gateway, oif)?;
        }
        for n in &self.neighbors {
            let oif = util::ifindex_of(&n.oif)?;
            let ip = n
                .ip
                .parse()
                .with_context(|| format!("bad neighbor ip {:?}", n.ip))?;
            let mac = util::parse_mac(&n.mac)?;
            dp.neigh4_set(oif, ip, mac)?;
        }
        for r in &self.routes {
            let (addr, len) = util::parse_ipv4_prefix(&r.prefix)?;
            dp.route4_add(addr, len, r.nexthop, 0)?;
        }
        info!(
            "programmed dataplane: {} ports, {} nexthops, {} neighbors, {} routes",
            self.ports.len(),
            self.nexthops.len(),
            self.neighbors.len(),
            self.routes.len()
        );
        Ok(())
    }
}
