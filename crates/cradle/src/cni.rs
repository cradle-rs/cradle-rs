//! Kubernetes CNI support: the node-local IPAM allocator and the per-pod
//! endpoint store.
//!
//! Both live in the daemon (not the plugin) so state survives across
//! short-lived `cradle-cni` invocations and daemon restarts. Everything is
//! plain read-modify-write JSON under the `--state-dir` (default
//! `/run/cradle`): pod churn is orders of magnitude slower than the datapath,
//! so file-per-op I/O buys restart consistency for free. Callers serialize
//! access through `Control`'s mutex.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::util;

/// The IPAM owner key for a CNI attachment: `<container_id>/<ifname>`.
pub fn owner_key(container_id: &str, ifname: &str) -> String {
    format!("{container_id}/{ifname}")
}

/// FNV-1a 64-bit — stable filename hash for endpoint records (container IDs
/// can exceed filename comfort and `/` is not filename-safe).
fn fnv1a64(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// A pod endpoint programmed into the datapath (one per CNI ADD).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub container_id: String,
    pub ifname: String,
    pub netns: String,
    pub host_if: String,
    pub host_ifindex: u32,
    pub ip: Ipv4Addr,
    /// Pod IPv6 address (dual-stack); absent when the pool is v4-only.
    #[serde(default)]
    pub ip6: Option<Ipv6Addr>,
    pub vrf_id: u32,
    /// Kubernetes pod identity (empty outside Kubernetes) — feeds the
    /// CiliumEndpoint CRD publication. Defaults keep pre-M6 records readable.
    #[serde(default)]
    pub pod_name: String,
    #[serde(default)]
    pub pod_namespace: String,
    /// CNI-chained endpoint: cradle's datapath is not attached to the veth
    /// (the chained plugin — e.g. Cilium generic-veth — owns that hook).
    #[serde(default)]
    pub chained: bool,
}

/// One pod-IP allocation: address → owner (per family).
#[derive(Debug, Default, Serialize, Deserialize)]
struct IpamFile {
    #[serde(default)]
    allocations: std::collections::BTreeMap<Ipv4Addr, String>,
    #[serde(default)]
    allocations6: std::collections::BTreeMap<Ipv6Addr, String>,
}

/// File-backed CNI state under the daemon's state dir.
pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn ipam_path(&self) -> PathBuf {
        self.dir.join("ipam.json")
    }

    fn endpoints_dir(&self) -> PathBuf {
        self.dir.join("endpoints")
    }

    fn endpoint_path(&self, container_id: &str, ifname: &str) -> PathBuf {
        self.endpoints_dir().join(format!(
            "{:016x}.json",
            fnv1a64(&owner_key(container_id, ifname))
        ))
    }

    fn read_json<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    /// Write JSON atomically (tmp + rename) so a crash mid-write never leaves
    /// a truncated state file.
    fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(value)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, path).with_context(|| format!("renaming to {}", path.display()))?;
        Ok(())
    }

    /// Allocate a pod address from `pool`, idempotent per `owner` (a retried
    /// CNI ADD gets its previous address back). The network address, the first
    /// host address (reserved as a virtual gateway), and the broadcast address
    /// are never handed out.
    pub fn alloc_ip(&self, pool: &str, owner: &str) -> Result<(Ipv4Addr, u8)> {
        let (net, plen) = util::parse_ipv4_prefix(pool)?;
        if plen > 30 {
            anyhow::bail!("pod CIDR {pool} too small (need at least a /30)");
        }
        let mask = if plen == 0 {
            0
        } else {
            u32::MAX << (32 - plen as u32)
        };
        let base = u32::from(net) & mask;

        let path = self.ipam_path();
        let mut ipam: IpamFile = Self::read_json(&path)?;
        if let Some((&ip, _)) = ipam.allocations.iter().find(|(_, o)| o.as_str() == owner) {
            return Ok((ip, plen));
        }
        // Hosts from base+2 (skip network + gateway) to broadcast-1.
        let first = base + 2;
        let last = base | !mask;
        for candidate in first..last {
            let ip = Ipv4Addr::from(candidate);
            if let std::collections::btree_map::Entry::Vacant(slot) = ipam.allocations.entry(ip) {
                slot.insert(owner.to_string());
                Self::write_json(&path, &ipam)?;
                return Ok((ip, plen));
            }
        }
        anyhow::bail!("pod CIDR {pool} exhausted");
    }

    /// Allocate a pod IPv6 address from `pool6`, idempotent per `owner`. The
    /// network address and the first host address (the ptp gateway) are
    /// reserved; there is no v6 broadcast.
    pub fn alloc_ip6(&self, pool6: &str, owner: &str) -> Result<(Ipv6Addr, u8)> {
        let (net, plen) = util::parse_ipv6_prefix(pool6)?;
        if plen > 126 {
            anyhow::bail!("pod CIDR6 {pool6} too small (need at least a /126)");
        }
        let mask = if plen == 0 {
            0
        } else {
            u128::MAX << (128 - plen as u32)
        };
        let base = u128::from(net) & mask;

        let path = self.ipam_path();
        let mut ipam: IpamFile = Self::read_json(&path)?;
        if let Some((&ip, _)) = ipam.allocations6.iter().find(|(_, o)| o.as_str() == owner) {
            return Ok((ip, plen));
        }
        // From base+2 (skip the subnet-router anycast + the ptp gateway).
        let first = base + 2;
        let last = base | !mask;
        let mut candidate = first;
        while candidate < last {
            let ip = Ipv6Addr::from(candidate);
            if let std::collections::btree_map::Entry::Vacant(slot) = ipam.allocations6.entry(ip) {
                slot.insert(owner.to_string());
                Self::write_json(&path, &ipam)?;
                return Ok((ip, plen));
            }
            candidate += 1;
        }
        anyhow::bail!("pod CIDR6 {pool6} exhausted");
    }

    /// Release both-family allocations by owner and/or a specific v4/v6
    /// address. Missing entries are not an error (CNI DEL is idempotent).
    pub fn release_ip(
        &self,
        owner: &str,
        ip: Option<Ipv4Addr>,
        ip6: Option<Ipv6Addr>,
    ) -> Result<()> {
        let path = self.ipam_path();
        let mut ipam: IpamFile = Self::read_json(&path)?;
        let before = (ipam.allocations.len(), ipam.allocations6.len());
        let owns = |o: &str| !owner.is_empty() && o == owner;
        ipam.allocations.retain(|a, o| !(Some(*a) == ip || owns(o)));
        ipam.allocations6
            .retain(|a, o| !(Some(*a) == ip6 || owns(o)));
        if (ipam.allocations.len(), ipam.allocations6.len()) != before {
            Self::write_json(&path, &ipam)?;
        }
        Ok(())
    }

    pub fn put_endpoint(&self, ep: &Endpoint) -> Result<()> {
        Self::write_json(&self.endpoint_path(&ep.container_id, &ep.ifname), ep)
    }

    pub fn get_endpoint(&self, container_id: &str, ifname: &str) -> Result<Option<Endpoint>> {
        let path = self.endpoint_path(container_id, ifname);
        match std::fs::read_to_string(&path) {
            Ok(s) => Ok(Some(
                serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn remove_endpoint(&self, container_id: &str, ifname: &str) -> Result<()> {
        match std::fs::remove_file(self.endpoint_path(container_id, ifname)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn list_endpoints(&self) -> Result<Vec<Endpoint>> {
        let dir = self.endpoints_dir();
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let s = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            out.push(
                serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?,
            );
        }
        out.sort_by(|a: &Endpoint, b: &Endpoint| {
            (a.container_id.as_str(), a.ifname.as_str())
                .cmp(&(b.container_id.as_str(), b.ifname.as_str()))
        });
        Ok(out)
    }
}
