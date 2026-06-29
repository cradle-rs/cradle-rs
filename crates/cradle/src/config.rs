//! Static JSON configuration — the Phase-1/2 injection mechanism.
//!
//! This is deliberately simple; it will be superseded by the gRPC/unix-socket
//! API and ultimately by the zebra-rs control plane. The shape maps directly to
//! [`Dataplane`] operations.

use std::{collections::BTreeMap, fs, path::Path};

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
    /// Routed (L3) port. If false, the port is an L2 bridge member in `vlan`.
    #[serde(default)]
    pub l3: bool,
    /// L2 bridge/VLAN domain id (for non-L3 ports).
    #[serde(default)]
    pub vlan: u16,
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

    /// Every managed port — the datapath classifier is attached to each one's
    /// ingress (both L2 and L3 ports need it).
    pub fn port_names(&self) -> impl Iterator<Item = &str> {
        self.ports.iter().map(|p| p.name.as_str())
    }

    /// Program the data plane from this configuration.
    pub fn apply(&self, dp: &mut Dataplane) -> Result<()> {
        // Ports.
        for p in &self.ports {
            let ifindex = util::ifindex_of(&p.name)?;
            let mac = util::mac_of(&p.name)?;
            let flags = if p.l3 { PORT_F_L3 } else { PORT_F_L2 };
            dp.port_set(ifindex, mac, flags, p.vlan)?;
        }

        // L2 domains: group non-L3 ports by VLAN and register the member sets.
        let mut domains: BTreeMap<u16, Vec<u32>> = BTreeMap::new();
        for p in &self.ports {
            if !p.l3 {
                domains
                    .entry(p.vlan)
                    .or_default()
                    .push(util::ifindex_of(&p.name)?);
            }
        }
        for (vlan, members) in &domains {
            dp.l2_domain_set(*vlan, members)?;
        }

        // L3: nexthops, neighbors, routes.
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
            "programmed dataplane: {} ports, {} L2 domains, {} nexthops, {} neighbors, {} routes",
            self.ports.len(),
            domains.len(),
            self.nexthops.len(),
            self.neighbors.len(),
            self.routes.len()
        );
        Ok(())
    }
}
