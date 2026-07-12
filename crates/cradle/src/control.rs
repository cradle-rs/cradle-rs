//! Control plane — the single implementation behind both the gRPC service and
//! the in-process bootstrap config. It resolves interface names, attaches the
//! datapath to ports on demand, and programs the BPF maps.
//!
//! This is the seam zebra-rs's FibHandle backend will drive: the method surface
//! mirrors `route_*_add/del`, nexthop and neighbor updates, plus L2/L4 setup.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context as _, Result};
use aya::{
    Ebpf,
    programs::{
        SchedClassifier, TcAttachType, Xdp, XdpMode,
        tc::{self, SchedClassifierLink},
        xdp::XdpLink,
    },
};
use tokio::sync::Mutex;
use tonic::{Request, Response, Status, transport::Server};
use tracing::{info, warn};

use crate::{
    dataplane::{Dataplane, DumpRow, DumpTable},
    grpc::GrpcEndpoint,
    pb::{
        self,
        cradle_server::{Cradle, CradleServer},
    },
    util,
};
use cradle_common::{
    MPLS_OP_POP, MPLS_OP_POP_L3, MPLS_OP_SWAP, NH_F_V6, NextHop, PORT_F_L2, PORT_F_L3, SRV6_BH_END,
    SRV6_BH_END_B6, SRV6_BH_END_DT2M, SRV6_BH_END_DT2U, SRV6_BH_END_DT4, SRV6_BH_END_DT6,
    SRV6_BH_END_DT46, SRV6_BH_END_DX2, SRV6_BH_END_DX2V, SRV6_BH_END_DX4, SRV6_BH_END_DX6,
    SRV6_BH_END_M, SRV6_BH_END_REP, SRV6_BH_END_T, SRV6_BH_END_X, SRV6_BH_END_X_REP, SRV6_BH_UA,
    SRV6_BH_UALIB, SRV6_BH_UN, SRV6_ENCAP_MODE_INSERT, STAT_MAX,
};

/// Validate a wire `behavior` code against the known `SRV6_BH_*` set.
fn srv6_behavior(code: u32) -> Result<u8> {
    match code as u8 {
        b @ (SRV6_BH_END | SRV6_BH_END_X | SRV6_BH_END_DT4 | SRV6_BH_END_DT6 | SRV6_BH_END_DT46
        | SRV6_BH_END_B6 | SRV6_BH_UN | SRV6_BH_UA | SRV6_BH_UALIB | SRV6_BH_END_DT2U
        | SRV6_BH_END_DT2M | SRV6_BH_END_M | SRV6_BH_END_REP | SRV6_BH_END_X_REP
        | SRV6_BH_END_T | SRV6_BH_END_DX4 | SRV6_BH_END_DX6) => Ok(b),
        other => anyhow::bail!("unknown SRv6 behavior code {other}"),
    }
}

/// Display names for the datapath stat counters, indexed by `STAT_*` (must match
/// the indices defined in `cradle_common`).
const STAT_NAMES: [&str; STAT_MAX as usize] = [
    "l2_forward",
    "l2_flood",
    "l3v4_forward",
    "l3v6_forward",
    "l3_local",
    "l4_dnat",
    "l4_snat",
    "drop",
    "l7_redirect",
    "mpls_swap",
    "mpls_pop",
    "mpls_push",
    "fib4_tbl24_hit",
    "fib4_tbl8_hit",
    "fib4_default",
    "fib4_vrf_hit",
    "srv6_encap",
    "srv6_decap",
    "fib6_vrf_hit",
    "srv6_end",
    "srv6_usid",
    "srv6_l2_encap",
    "srv6_l2_decap",
    "srv6_l2_bum",
    "fdb_aged",
    "srv6_hinsert",
    "nh_backup",
    "srv6_endm",
    "srv6_psp",
    "srv6_usp",
    "srv6_usd",
    "srv6_replace",
    "srv6_b6",
    "srv6_endt",
    "srv6_dx",
    "gtp_encap",
    "gtp_decap",
    "srv6_dx2",
    "policy_drop",
    "masq",
    "policy_audit",
    "vxlan_encap",
    "vxlan_decap",
    "vxlan_flood",
];

/// A BUM replication slot's veth pair: (A-end name, A ifindex, B ifindex).
type ReplSlot = (String, u32, u32);

/// What user space knows about a pod/node IP, for Hubble flow enrichment
/// (empty strings / zero identity when unknown).
#[derive(Clone, Debug, Default)]
pub struct EpInfo {
    pub namespace: String,
    pub pod_name: String,
    pub identity: u32,
}

/// Shared, cheaply-cloneable handle to the data plane.
/// Per-endpoint (pod-ip, port)s currently steered through the L7 proxy.
type L7Programmed = HashMap<u32, Vec<(Ipv4Addr, u16)>>;

/// One attached port, keyed by ifindex in `Control::attached`: the owned aya
/// links (dropping them detaches the TC/XDP programs — the mechanism behind
/// `del_port`), the attach-time name (so `del_port` can find the entry after
/// the device itself is gone), and the FIB artifacts the port derived while
/// L3 (so a role/VRF/address change or a `del_port` removes exactly them).
struct PortAttachment {
    name: String,
    _tc_ingress: SchedClassifierLink,
    _tc_egress: SchedClassifierLink,
    _xdp: XdpLink,
    derived: crate::kernel::DerivedPort,
}

#[derive(Clone)]
pub struct Control {
    bpf: Arc<Mutex<Ebpf>>,
    dp: Arc<Mutex<Dataplane>>,
    attached: Arc<Mutex<HashMap<u32, PortAttachment>>>,
    /// L7 path-routing table, shared with the transparent proxy task.
    routes: Arc<Mutex<crate::l7::RouteTable>>,
    /// Dynamic BUM replication slots (EVPN Type-3 tee): `(bd, remote DT2M
    /// SID)` → the slot's veth (A-end name, A ifindex, B ifindex). cradle
    /// creates/destroys the pair itself.
    repl_slots: Arc<Mutex<std::collections::HashMap<(u16, Ipv6Addr), ReplSlot>>>,
    /// Monotonic name counter for slot veth pairs (`crs<N>a`/`crs<N>b`).
    repl_next: Arc<std::sync::atomic::AtomicU32>,
    /// CNI state (IPAM allocations + endpoint records) under the state dir.
    cni: Arc<Mutex<crate::cni::Store>>,
    /// User-space mirror of the datapath `IDENTITY` map (pod/node IP → policy
    /// identity), for Hubble flow enrichment. Kept in step with `set_identity`
    /// / `del_identity`.
    identities: Arc<Mutex<HashMap<Ipv4Addr, u32>>>,
    /// Per-endpoint policy revision: bumped on every SetEndpointPolicy
    /// (0 = never programmed). Published via ListEndpoints → CiliumEndpoint.
    policy_revisions: Arc<Mutex<HashMap<u32, u64>>>,
    /// L7-steered (ip, port)s programmed per endpoint — replace semantics.
    l7_policies: Arc<Mutex<L7Programmed>>,
    /// MAC-move-away hints: `(mac, bd)` published when a remote install
    /// displaces a locally-learned entry. `WatchFdb` subscribers consume
    /// these to emit an age event *synchronously*, instead of waiting for the
    /// next poll to notice the (often sub-second, racy) local→remote flip —
    /// the RFC 7432 §7.7 move-away that must reach BGP so the previous owner
    /// withdraws before the station reappears elsewhere.
    fdb_hint_tx: tokio::sync::broadcast::Sender<([u8; 6], u16)>,
}

impl Control {
    pub fn new(bpf: Ebpf, dp: Dataplane, state_dir: std::path::PathBuf) -> Self {
        Self {
            bpf: Arc::new(Mutex::new(bpf)),
            dp: Arc::new(Mutex::new(dp)),
            attached: Arc::new(Mutex::new(HashMap::new())),
            routes: Arc::new(Mutex::new(crate::l7::RouteTable::default())),
            repl_slots: Arc::new(Mutex::new(std::collections::HashMap::new())),
            repl_next: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            cni: Arc::new(Mutex::new(crate::cni::Store::new(state_dir))),
            identities: Arc::new(Mutex::new(HashMap::new())),
            policy_revisions: Arc::new(Mutex::new(HashMap::new())),
            l7_policies: Arc::new(Mutex::new(HashMap::new())),
            fdb_hint_tx: tokio::sync::broadcast::channel(256).0,
        }
    }

    /// Subscribe to MAC-move-away hints (see `fdb_hint_tx`).
    pub fn subscribe_fdb_hints(&self) -> tokio::sync::broadcast::Receiver<([u8; 6], u16)> {
        self.fdb_hint_tx.subscribe()
    }

    /// Start the user-space L7 transparent proxy (best-effort; logs and
    /// continues if the transparent bind is unavailable).
    /// Register the Hubble L7 flow sink so the transparent proxy reports the
    /// HTTP requests it handles as L7 (HTTP) flow records.
    pub async fn set_l7_hubble_sink(&self, sink: crate::l7::L7Sink) {
        self.routes.lock().await.set_hubble_sink(sink);
    }

    pub async fn start_l7_proxy(&self) {
        if let Err(e) = crate::l7::spawn_proxy(self.routes.clone()).await {
            warn!("L7 proxy disabled: {e:#}");
        }
    }

    /// Start the FDB aging sweep: every few seconds, expire locally-learned
    /// MACs idle longer than `age_secs` (0 = aging disabled). `WatchFdb`
    /// subscribers report the removals upstream as age events.
    pub fn start_fdb_aging(&self, age_secs: u64) {
        if age_secs == 0 {
            return;
        }
        let dp = self.dp.clone();
        let age = std::time::Duration::from_secs(age_secs);
        // Sweep at a fraction of the age (5s cap) so expiry lag stays small.
        let interval = std::time::Duration::from_secs((age_secs / 3).clamp(1, 5));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                match dp.lock().await.fdb_age_sweep(age) {
                    Ok(0) => {}
                    Ok(n) => info!("fdb aging: expired {n} idle entries"),
                    Err(e) => warn!("fdb aging sweep failed: {e:#}"),
                }
            }
        });
        info!("fdb aging enabled: {age_secs}s idle timeout");
    }

    /// Mark an L7 service (VIP:port → path-prefix routes). The datapath steers
    /// matching TCP flows to the proxy; the proxy routes by path.
    pub async fn add_l7_service(
        &self,
        vip: Ipv4Addr,
        port: u16,
        routes: Vec<crate::l7::L7Route>,
    ) -> Result<()> {
        self.dp.lock().await.l7_service_add(vip, port)?;
        // TPROXY (bpf_sk_assign) needs the VIP to route locally; otherwise the
        // kernel forwards the non-local destination and drops it. Install the
        // `local <vip>/32 dev lo` route ourselves so operators and tests don't
        // have to. Best-effort: warn (rather than fail service config) if the
        // route can't be installed, since L7 will simply not deliver until it is.
        if let Err(e) = crate::kernel::add_local_route_v4(vip) {
            warn!("L7 {vip}:{port}: could not install local route: {e:#} (TPROXY may not deliver)");
        }
        self.routes.lock().await.add(IpAddr::V4(vip), port, routes);
        Ok(())
    }

    /// Attach the datapath classifier to a port's clsact ingress (idempotent),
    /// plus the XDP stage — L3 ports use it for MPLS pops / SRv6 `End.DT*`
    /// decap, L2 ports for EVPN-over-SRv6 MAC-in-SRv6 encap (`bpf_skb_adjust_room`
    /// can't resize non-IP or MPLS skbs at TC, so the grow/shrink runs in XDP).
    /// The attach links are taken out of the programs and stored per ifindex,
    /// so `del_port` can detach by dropping them. A failed attach rolls back
    /// (links taken so far drop → detach) and leaves the port unattached, so
    /// a retry re-runs the full sequence.
    async fn attach(&self, name: &str, ifindex: u32, _l3: bool) -> Result<()> {
        let mut attached = self.attached.lock().await;
        if attached.contains_key(&ifindex) {
            return Ok(());
        }
        let mut bpf = self.bpf.lock().await;
        if let Err(e) = tc::qdisc_add_clsact(name) {
            warn!("qdisc_add_clsact({name}): {e} (continuing; may already exist)");
        }
        // Predecessor cleanup. On TCX-capable kernels (≥6.6) aya attaches via
        // a bpf_link, which dies with the owning process — a killed daemon
        // leaves nothing behind. On older kernels the fallback is a netlink
        // cls_bpf filter, which DOES outlive the process and would keep
        // forwarding with the dead instance's maps, ahead of ours. Detach any
        // stale cradle_tc by program name so only this instance's datapath
        // runs. NotFound (the common case) is not an error.
        if let Err(e) = tc::qdisc_detach_program(name, TcAttachType::Ingress, "cradle_tc") {
            let benign = matches!(&e, tc::TcError::IoError(io)
                if io.kind() == std::io::ErrorKind::NotFound);
            if !benign {
                warn!("detaching stale cradle_tc from {name}: {e} (continuing)");
            }
        } else {
            info!("detached a stale cradle_tc filter from {name} (predecessor cleanup)");
        }
        let tc_ingress = {
            let prog: &mut SchedClassifier = bpf
                .program_mut("cradle_tc")
                .context("program cradle_tc not found")?
                .try_into()?;
            let id = prog
                .attach(name, TcAttachType::Ingress)
                .with_context(|| format!("attaching to {name}"))?;
            info!("attached cradle datapath to {name} (clsact ingress)");
            prog.take_link(id)?
        };
        // Egress reverse-NAT: rewrite a host-network/node-local service
        // reply's source back to the VIP as it leaves toward the client
        // (its 5-tuple hits a reverse CT entry; a pod-backed reply already
        // un-NATed at ingress won't match — no double-NAT).
        let tc_egress = {
            let eg: &mut SchedClassifier = bpf
                .program_mut("cradle_egress")
                .context("program cradle_egress not found")?
                .try_into()?;
            let id = eg
                .attach(name, TcAttachType::Egress)
                .with_context(|| format!("attaching egress reverse-NAT to {name}"))?;
            eg.take_link(id)?
        };
        let xdp_link = {
            let xdp: &mut Xdp = bpf
                .program_mut("cradle_xdp")
                .context("program cradle_xdp not found")?
                .try_into()?;
            // Native mode: generic XDP is skipped for TC-redirected skbs
            // (netif_receive_generic_xdp bails on skb_is_redirected), so a
            // frame forwarded by the previous hop's TC stage would bypass a
            // generic-mode pop. veth supports native XDP; fall back to
            // generic (with that caveat) on drivers that don't.
            let id = match xdp.attach(name, XdpMode::Driver) {
                Ok(id) => {
                    info!("attached cradle XDP stage to {name} (XDP native)");
                    id
                }
                Err(e) => {
                    warn!(
                        "native XDP attach on {name} failed ({e}); falling back to generic \
                         (frames redirected by an upstream TC hop bypass the pop stage)"
                    );
                    let id = xdp
                        .attach(name, XdpMode::Skb)
                        .with_context(|| format!("attaching XDP MPLS pop to {name}"))?;
                    info!("attached cradle XDP stage to {name} (XDP generic)");
                    id
                }
            };
            xdp.take_link(id)?
        };
        attached.insert(
            ifindex,
            PortAttachment {
                name: name.to_string(),
                _tc_ingress: tc_ingress,
                _tc_egress: tc_egress,
                _xdp: xdp_link,
                derived: Default::default(),
            },
        );
        Ok(())
    }

    pub async fn set_port(
        &self,
        name: &str,
        mac: Option<&str>,
        l3: bool,
        vlan: u16,
        vrf_id: u32,
    ) -> Result<()> {
        let ifindex = util::ifindex_of(name)?;
        let mac = match mac {
            Some(m) if !m.is_empty() => util::parse_mac(m)?,
            _ => util::mac_of(name)?,
        };
        let flags = if l3 { PORT_F_L3 } else { PORT_F_L2 };
        self.attach(name, ifindex, l3).await?;
        // Lock order (attach releases its locks first): attached → dp, the
        // same order `del_port` uses.
        let mut attached = self.attached.lock().await;
        let mut dp = self.dp.lock().await;
        dp.port_set(ifindex, mac, flags, vlan, vrf_id)?;
        // Routed ports auto-derive their local + connected routes from the
        // kernel (into the port's VRF table when bound), so no manual
        // route/neighbor config is needed.
        let new_derived = if l3 {
            crate::kernel::derive_port(&mut dp, name, ifindex, vrf_id)?
        } else {
            Default::default()
        };
        // Reconcile against what an earlier set_port derived (different VRF,
        // addresses, or an L3→L2 role change): the new set was just
        // (re-)inserted above, so remove only the leftovers.
        if let Some(att) = attached.get_mut(&ifindex) {
            for r in att
                .derived
                .v4
                .iter()
                .filter(|r| !new_derived.v4.contains(r))
            {
                let _ = dp.route4_del(r.0, r.1, r.2);
            }
            for r in att
                .derived
                .v6
                .iter()
                .filter(|r| !new_derived.v6.contains(r))
            {
                let _ = dp.route6_del(r.0, r.1, r.2);
            }
            if let Some(nh) = att.derived.nh4.filter(|_| new_derived.nh4.is_none()) {
                let _ = dp.nexthop_del(nh);
            }
            if let Some(nh) = att.derived.nh6.filter(|_| new_derived.nh6.is_none()) {
                let _ = dp.nexthop_del(nh);
            }
            att.derived = new_derived;
        }
        Ok(())
    }

    /// Inverse of `set_port`: detach the TC/XDP programs (by dropping their
    /// links), drop the `PORTS` entry and the routes the port derived, and
    /// flush the MACs learned on it. Resolves by current ifindex, falling
    /// back to the attach-time name when the device is already gone.
    /// Idempotent: unknown ports are a logged no-op. L2 domain membership is
    /// the caller's to update (`set_l2_domain` replaces the full list).
    pub async fn del_port(&self, name: &str) -> Result<()> {
        let mut attached = self.attached.lock().await;
        let key = match util::ifindex_of(name) {
            Ok(ix) if attached.contains_key(&ix) => Some(ix),
            _ => attached
                .iter()
                .find(|(_, a)| a.name == name)
                .map(|(ix, _)| *ix),
        };
        let Some(ifindex) = key else {
            info!("del_port {name}: not attached (no-op)");
            return Ok(());
        };
        let att = attached.remove(&ifindex).expect("looked up above");
        let mut dp = self.dp.lock().await;
        drop(attached);
        dp.port_del(ifindex)?;
        for (vrf, prefix, plen) in &att.derived.v4 {
            let _ = dp.route4_del(*vrf, *prefix, *plen);
        }
        for (vrf, prefix, plen) in &att.derived.v6 {
            let _ = dp.route6_del(*vrf, *prefix, *plen);
        }
        if let Some(nh) = att.derived.nh4 {
            let _ = dp.nexthop_del(nh);
        }
        if let Some(nh) = att.derived.nh6 {
            let _ = dp.nexthop_del(nh);
        }
        let flushed = dp.fdb_flush(Some(ifindex), None)?;
        drop(dp);
        // Dropping the attachment drops its links → the programs detach
        // (a no-op if the device is already gone).
        drop(att);
        info!("deleted port {name} (ifindex {ifindex}; flushed {flushed} learned FDB entries)");
        Ok(())
    }

    /// Flush locally-learned FDB entries, optionally scoped to a port and/or
    /// a bridge domain (control-plane-installed remote entries are never
    /// touched). `WatchFdb` subscribers report the removals as age events.
    pub async fn flush_fdb(&self, port: Option<&str>, vlan: Option<u16>) -> Result<usize> {
        let ifindex = match port {
            Some(name) => Some(match util::ifindex_of(name) {
                Ok(ix) => ix,
                // Device gone — fall back to the attach-time name so learned
                // entries of a just-removed interface can still be flushed.
                Err(e) => self
                    .attached
                    .lock()
                    .await
                    .iter()
                    .find(|(_, a)| a.name == name)
                    .map(|(ix, _)| *ix)
                    .ok_or(e)?,
            }),
            None => None,
        };
        let flushed = self.dp.lock().await.fdb_flush(ifindex, vlan)?;
        info!(
            "flushed {flushed} learned FDB entries (port {}, vlan {})",
            port.unwrap_or("any"),
            vlan.map_or("any".to_string(), |v| v.to_string()),
        );
        Ok(flushed)
    }

    pub async fn set_l2_domain(&self, vlan: u16, members: &[String]) -> Result<()> {
        let idxs = members
            .iter()
            .map(|m| util::ifindex_of(m))
            .collect::<Result<Vec<_>>>()?;
        self.dp.lock().await.l2_domain_set(vlan, &idxs)?;
        Ok(())
    }

    /// Program an overlay FDB entry: `mac` in bridge domain `bd` is behind
    /// the remote `End.DT2U`/`DT2M` `remote_sid`, reached via underlay
    /// `nexthop_id` — 0 = the datapath resolves it with a FIB6 lookup on the
    /// SID (EVPN over SRv6).
    pub async fn add_fdb_remote(
        &self,
        mac: [u8; 6],
        bd: u16,
        remote_sid: Ipv6Addr,
        nexthop_id: u32,
    ) -> Result<()> {
        let displaced_local = self
            .dp
            .lock()
            .await
            .fdb_remote_add(mac, bd, remote_sid, nexthop_id)?;
        // A remote install over a locally-learned MAC = the station moved away.
        // Signal WatchFdb so it ages the MAC out immediately (RFC 7432 §7.7),
        // rather than relying on the next poll catching the racy flip.
        if displaced_local {
            let _ = self.fdb_hint_tx.send((mac, bd));
        }
        Ok(())
    }

    /// The VXLAN flavor of [`Self::add_fdb_remote`]: `mac` is behind the
    /// remote VTEP `vtep`, tunneled with the bridge domain's VNI (`SetVni`).
    /// Same MAC-move-away hint semantics.
    pub async fn add_fdb_remote_vxlan(
        &self,
        mac: [u8; 6],
        bd: u16,
        vtep: Ipv4Addr,
        nexthop_id: u32,
    ) -> Result<()> {
        let displaced_local = self
            .dp
            .lock()
            .await
            .fdb_remote_add_vxlan(mac, bd, vtep, nexthop_id)?;
        if displaced_local {
            let _ = self.fdb_hint_tx.send((mac, bd));
        }
        Ok(())
    }

    /// Remove an overlay FDB entry.
    pub async fn del_fdb_remote(&self, mac: [u8; 6], bd: u16) -> Result<()> {
        self.dp.lock().await.fdb_remote_del(mac, bd)?;
        Ok(())
    }

    /// Bind a VPWS attachment circuit to its remote End.DX2/DX2V SID.
    /// `local_sid`, when given, also installs the matching End.DX2
    /// LocalSid on the same AC (decap + raw emit) — one call binds the
    /// E-Line in both directions. A non-zero `vid` makes the service
    /// VLAN-scoped (RFC 8214 VLAN-based E-Line): only 802.1Q frames with
    /// that VID enter the cross-connect, `local_sid` installs an
    /// End.DX2V over VLAN table `table`, and the `(table, vid)` entry
    /// emits decapped frames back on the same AC.
    pub async fn add_xconnect(
        &self,
        port: &str,
        remote_sid: Ipv6Addr,
        local_sid: Option<Ipv6Addr>,
        vid: u16,
        table: u32,
    ) -> Result<()> {
        let ifindex = util::ifindex_of(port)?;
        self.add_xconnect_idx(ifindex, remote_sid, local_sid, vid, table)
            .await
    }

    pub async fn add_xconnect_idx(
        &self,
        ifindex: u32,
        remote_sid: Ipv6Addr,
        local_sid: Option<Ipv6Addr>,
        vid: u16,
        table: u32,
    ) -> Result<()> {
        let mut dp = self.dp.lock().await;
        if vid == 0 {
            dp.xconnect_add(ifindex, remote_sid)?;
            if let Some(sid) = local_sid {
                dp.localsid_add(sid, 128, SRV6_BH_END_DX2, ifindex, 0, 0, 0, 0, 0)?;
            }
        } else {
            dp.xconnect_vlan_add(ifindex, vid, remote_sid)?;
            if let Some(sid) = local_sid {
                dp.localsid_add(sid, 128, SRV6_BH_END_DX2V, table, 0, 0, 0, 0, 0)?;
                dp.dx2v_add(table, vid, ifindex)?;
            }
        }
        Ok(())
    }

    pub async fn del_xconnect_idx(
        &self,
        ifindex: u32,
        local_sid: Option<Ipv6Addr>,
        vid: u16,
        table: u32,
    ) -> Result<()> {
        let mut dp = self.dp.lock().await;
        if vid == 0 {
            dp.xconnect_del(ifindex)?;
        } else {
            dp.xconnect_vlan_del(ifindex, vid)?;
            if local_sid.is_some() {
                dp.dx2v_del(table, vid)?;
            }
        }
        if let Some(sid) = local_sid {
            dp.localsid_del(sid, 128)?;
        }
        Ok(())
    }

    pub async fn del_xconnect(
        &self,
        port: &str,
        local_sid: Option<Ipv6Addr>,
        vid: u16,
        table: u32,
    ) -> Result<()> {
        let ifindex = util::ifindex_of(port)?;
        self.del_xconnect_idx(ifindex, local_sid, vid, table).await
    }

    /// End.DX2V VLAN-table entry: (table, vid) → AC port.
    pub async fn add_dx2v(&self, table: u32, vid: u16, port: &str) -> Result<()> {
        let oif = util::ifindex_of(port)?;
        self.dp.lock().await.dx2v_add(table, vid, oif)?;
        Ok(())
    }

    /// Register a BUM replication slot by interface names (see
    /// `Dataplane::repl_slot_add`).
    pub async fn add_repl_slot(
        &self,
        flood_port: &str,
        encap_port: &str,
        remote_sid: Ipv6Addr,
    ) -> Result<()> {
        let flood = util::ifindex_of(flood_port)?;
        let encap = util::ifindex_of(encap_port)?;
        self.dp
            .lock()
            .await
            .repl_slot_add(flood, encap, remote_sid)?;
        Ok(())
    }

    /// The VXLAN flavor of [`Self::add_repl_slot`]: flooded copies are
    /// VXLAN-encapsulated toward `vtep` with `vni` (static config carries
    /// the VNI explicitly — no bridge domain is in scope here).
    pub async fn add_repl_slot_vxlan(
        &self,
        flood_port: &str,
        encap_port: &str,
        vtep: Ipv4Addr,
        vni: u32,
    ) -> Result<()> {
        let flood = util::ifindex_of(flood_port)?;
        let encap = util::ifindex_of(encap_port)?;
        self.dp
            .lock()
            .await
            .repl_slot_add_vxlan(flood, encap, vtep, vni)?;
        Ok(())
    }

    /// Create a BUM replication slot for `(bd, remote_sid)` with cradle-owned
    /// plumbing (the EVPN Type-3 tee): a fresh veth pair `crs<N>a`/`crs<N>b`,
    /// the A end joined to `bd`'s flood list, the B end XDP-attached, and
    /// `REPL_SID` keyed by both ends. Idempotent per `(bd, remote_sid)`.
    pub async fn add_repl_slot_auto(&self, bd: u16, remote_sid: Ipv6Addr) -> Result<()> {
        self.add_repl_slot_auto_keyed(bd, remote_sid, |dp, a_idx, b_idx| {
            dp.repl_slot_add(a_idx, b_idx, remote_sid)
        })
        .await
    }

    /// The VXLAN flavor of [`Self::add_repl_slot_auto`]: the VNI comes from
    /// the bridge domain's `SetVni` binding (the single source of truth), so
    /// the binding must exist first. Keyed by the VTEP v4-mapped — colliding
    /// with no real SRv6 SID — so one slot registry and
    /// [`Self::del_repl_slot_auto`] serve both overlays.
    pub async fn add_repl_slot_auto_vxlan(&self, bd: u16, vtep: Ipv4Addr) -> Result<()> {
        let vni =
            self.dp.lock().await.vni_of(bd).with_context(|| {
                format!("bd {bd} has no VNI binding (SetVni before AddReplSlot)")
            })?;
        self.add_repl_slot_auto_keyed(bd, vtep.to_ipv6_mapped(), |dp, a_idx, b_idx| {
            dp.repl_slot_add_vxlan(a_idx, b_idx, vtep, vni)
        })
        .await
    }

    /// Shared cradle-owned slot plumbing: veth pair, XDP attach on the B end,
    /// slot programming via `program`, flood membership for the A end.
    async fn add_repl_slot_auto_keyed(
        &self,
        bd: u16,
        key: Ipv6Addr,
        program: impl FnOnce(&mut Dataplane, u32, u32) -> Result<()>,
    ) -> Result<()> {
        let mut slots = self.repl_slots.lock().await;
        if slots.contains_key(&(bd, key)) {
            return Ok(());
        }
        let n = self
            .repl_next
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let a = format!("crs{n}a");
        let b = format!("crs{n}b");
        crate::kernel::add_veth_pair(&a, &b)?;
        let a_idx = util::ifindex_of(&a)?;
        let b_idx = util::ifindex_of(&b)?;
        // The B end runs the per-copy encap in the XDP stage.
        self.attach(&b, b_idx, true).await?;
        {
            let mut dp = self.dp.lock().await;
            program(&mut dp, a_idx, b_idx)?;
            dp.l2_member_add(bd, a_idx)?;
        }
        info!("repl slot {a}/{b}: bd {bd} -> {key}");
        slots.insert((bd, key), (a, a_idx, b_idx));
        Ok(())
    }

    /// Tear down a `(bd, remote_sid)` replication slot: flood membership,
    /// SID bindings, and the veth pair. No-op if absent.
    pub async fn del_repl_slot_auto(&self, bd: u16, remote_sid: Ipv6Addr) -> Result<()> {
        let Some((a, a_idx, b_idx)) = self.repl_slots.lock().await.remove(&(bd, remote_sid)) else {
            return Ok(());
        };
        {
            let mut dp = self.dp.lock().await;
            dp.l2_member_remove(bd, a_idx)?;
            let _ = dp.repl_sid_del(a_idx);
            let _ = dp.repl_sid_del(b_idx);
        }
        // Deleting one end removes the pair; forget the attach so a reused
        // ifindex re-attaches cleanly.
        self.attached.lock().await.remove(&b_idx);
        crate::kernel::del_link(&a)?;
        info!("repl slot {a} removed: bd {bd} -> {remote_sid}");
        Ok(())
    }

    /// Install / remove an egress-protection mirror route (End.M context).
    pub async fn add_mirror_route(
        &self,
        ctx: u32,
        prefix: Ipv6Addr,
        prefix_len: u8,
        behavior: u8,
        vrf_id: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .mirror_route_add(ctx, prefix, prefix_len, behavior, vrf_id)?;
        Ok(())
    }

    pub async fn del_mirror_route(&self, ctx: u32, prefix: Ipv6Addr, prefix_len: u8) -> Result<()> {
        self.dp
            .lock()
            .await
            .mirror_route_del(ctx, prefix, prefix_len)?;
        Ok(())
    }

    /// Snapshot the locally-learned FDB (see `Dataplane::fdb_local_entries`).
    pub async fn fdb_local_entries(&self) -> Vec<([u8; 6], u16)> {
        self.dp.lock().await.fdb_local_entries()
    }

    /// Snapshot a forwarding table for `cradle dump` (see `Dataplane::dump`).
    pub async fn dump(&self, table: DumpTable, vrf: u32, resolve: bool) -> Result<Vec<DumpRow>> {
        self.dp.lock().await.dump(table, vrf, resolve)
    }

    pub async fn set_nexthop(
        &self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: &str,
        labels: &[u32],
        backup_id: u32,
    ) -> Result<()> {
        let oif = util::ifindex_of(oif)?;
        self.set_nexthop_idx(id, gateway, oif, labels, backup_id)
            .await
    }

    /// Set a nexthop by output ifindex directly (used by control planes such as
    /// zebra-rs that already work in ifindex space).
    pub async fn set_nexthop_idx(
        &self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: u32,
        labels: &[u32],
        backup_id: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .nexthop_set(id, gateway, oif, labels, backup_id)?;
        Ok(())
    }

    pub async fn add_route4(
        &self,
        vrf: u32,
        addr: Ipv4Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .route4_add(vrf, addr, prefix_len, nexthop_id, flags)?;
        Ok(())
    }

    pub async fn del_route4(&self, vrf: u32, addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
        self.dp.lock().await.route4_del(vrf, addr, prefix_len)?;
        Ok(())
    }

    /// Bulk-install IPv4 routes (`(vrf, addr, len, nexthop_id, flags)` each).
    pub async fn add_routes4(&self, routes: &[(u32, Ipv4Addr, u8, u32, u32)]) -> Result<()> {
        self.dp.lock().await.route4_add_bulk(routes)?;
        Ok(())
    }

    /// IPv4 FIB engine state: `(mode, routes, tbl8_used, tbl8_free)`.
    pub async fn fib_summary(&self) -> (&'static str, u64, u32, u32) {
        self.dp.lock().await.fib_summary()
    }

    pub async fn set_nexthop_idx_v6(
        &self,
        id: u32,
        gateway: Option<Ipv6Addr>,
        oif: u32,
        labels: &[u32],
        backup_id: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .nexthop_set_v6(id, gateway, oif, labels, backup_id)?;
        Ok(())
    }

    pub async fn set_nexthop_group(&self, group_id: u32, members: &[u32]) -> Result<()> {
        self.dp.lock().await.nexthop_group_set(group_id, members)?;
        Ok(())
    }

    pub async fn add_route6(
        &self,
        vrf: u32,
        addr: Ipv6Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .route6_add(vrf, addr, prefix_len, nexthop_id, flags)?;
        Ok(())
    }

    pub async fn del_route6(&self, vrf: u32, addr: Ipv6Addr, prefix_len: u8) -> Result<()> {
        self.dp.lock().await.route6_del(vrf, addr, prefix_len)?;
        Ok(())
    }

    /// Set an SRv6-encap nexthop by ifindex (segment list = `segs`; `mode`
    /// = `SRV6_ENCAP_MODE_*` — H.Encaps forms or H.Insert).
    pub async fn set_nexthop_srv6(
        &self,
        id: u32,
        gateway: Option<Ipv6Addr>,
        oif: u32,
        segs: &[Ipv6Addr],
        mode: u8,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .nexthop_set_srv6(id, gateway, oif, segs, mode)?;
        Ok(())
    }

    /// Set a GTP-U-encap nexthop (`GTP4.E`) by ifindex: a v4 underlay
    /// (`gateway`/`oif`) that imposes an outer IPv4 + UDP(2152) + GTP-U(`teid`)
    /// header with tunnel endpoints `src`/`dst`.
    pub async fn set_nexthop_gtp(
        &self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: u32,
        src: Ipv4Addr,
        dst: Ipv4Addr,
        teid: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .nexthop_set_gtp(id, gateway, oif, src, dst, teid)?;
        Ok(())
    }

    /// Install a GTP-U decap PDR: `(dst, teid)` → strip + forward inner in `vrf`.
    pub async fn gtp_pdr_add(&self, dst: Ipv4Addr, teid: u32, vrf: u32) -> Result<()> {
        self.dp.lock().await.gtp_pdr_add(dst, teid, vrf)?;
        Ok(())
    }

    /// Remove a GTP-U decap PDR.
    pub async fn gtp_pdr_del(&self, dst: Ipv4Addr, teid: u32) -> Result<()> {
        self.dp.lock().await.gtp_pdr_del(dst, teid)?;
        Ok(())
    }

    /// Start the link monitor: an `ip -o monitor link` subprocess feeds
    /// carrier/admin transitions into the `LINK_DOWN` map, arming the
    /// datapath's protected-nexthop failover within event latency.
    pub fn start_link_monitor(&self) {
        let dp = self.dp.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let child = tokio::process::Command::new("ip")
                .args(["-o", "monitor", "link"])
                .stdout(std::process::Stdio::piped())
                .spawn();
            let mut child = match child {
                Ok(c) => c,
                Err(e) => {
                    warn!("link monitor disabled: spawning `ip monitor link`: {e}");
                    return;
                }
            };
            let Some(stdout) = child.stdout.take() else {
                return;
            };
            let mut lines = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                // `ip -o monitor link` lines start "IDX: name: <FLAGS> ...
                // state STATE ...". Deleted links report "Deleted IDX: ...".
                let rest = line.strip_prefix("Deleted ").unwrap_or(&line);
                let Some((idx_str, _)) = rest.split_once(':') else {
                    continue;
                };
                let Ok(ifindex) = idx_str.trim().parse::<u32>() else {
                    continue;
                };
                let down = line.starts_with("Deleted ")
                    || rest.contains("state DOWN")
                    || rest.contains("state LOWERLAYERDOWN");
                let up = rest.contains("state UP");
                if !down && !up {
                    continue;
                }
                if let Err(e) = dp.lock().await.link_state_set(ifindex, down) {
                    warn!("link monitor: LINK_DOWN update for {ifindex}: {e:#}");
                } else if down {
                    info!("link {ifindex} down — protected nexthops fail over");
                }
            }
        });
        info!("link monitor started (protected-nexthop failover)");
    }

    pub async fn set_srv6_encap_source(&self, addr: Ipv6Addr) -> Result<()> {
        self.dp.lock().await.srv6_encap_source_set(addr)?;
        Ok(())
    }

    /// Bind an L2VNI to its bridge domain (both datapath directions).
    pub async fn set_vni(&self, vni: u32, vlan: u16) -> Result<()> {
        self.dp.lock().await.vni_set(vni, vlan)?;
        Ok(())
    }

    /// Remove an L2VNI binding.
    pub async fn del_vni(&self, vni: u32) -> Result<()> {
        self.dp.lock().await.vni_del(vni)?;
        Ok(())
    }

    /// Set the local VTEP source IPv4 (VXLAN outer source + decap match).
    pub async fn set_vtep_source(&self, addr: Ipv4Addr) -> Result<()> {
        self.dp.lock().await.vxlan_source_set(addr)?;
        Ok(())
    }

    /// Install a local SID. `oif`/`nh6` are resolved by the caller into a
    /// `nexthop_id` for End.X (Phase 2); Phase 1's DT behaviors use `vrf`.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_localsid(
        &self,
        sid: Ipv6Addr,
        prefix_len: u8,
        behavior: u8,
        vrf: u32,
        nexthop_id: u32,
        block_bits: u8,
        node_bits: u8,
        fun_bits: u8,
        flavors: u8,
    ) -> Result<()> {
        self.dp.lock().await.localsid_add(
            sid, prefix_len, behavior, vrf, nexthop_id, block_bits, node_bits, fun_bits, flavors,
        )?;
        Ok(())
    }

    pub async fn del_localsid(&self, sid: Ipv6Addr, prefix_len: u8) -> Result<()> {
        self.dp.lock().await.localsid_del(sid, prefix_len)?;
        Ok(())
    }

    pub async fn set_neighbor4(&self, oif: &str, ip: Ipv4Addr, mac: [u8; 6]) -> Result<()> {
        let oif = util::ifindex_of(oif)?;
        self.set_neighbor4_idx(oif, ip, mac).await
    }

    /// Set a v4 neighbor by ifindex directly (control planes such as
    /// zebra-rs work in ifindex space).
    pub async fn set_neighbor4_idx(&self, oif: u32, ip: Ipv4Addr, mac: [u8; 6]) -> Result<()> {
        self.dp.lock().await.neigh4_set(oif, ip, mac)?;
        Ok(())
    }

    pub async fn set_neighbor6(&self, oif: &str, ip: Ipv6Addr, mac: [u8; 6]) -> Result<()> {
        let oif = util::ifindex_of(oif)?;
        self.set_neighbor6_idx(oif, ip, mac).await
    }

    /// Set a v6 neighbor by ifindex directly.
    pub async fn set_neighbor6_idx(&self, oif: u32, ip: Ipv6Addr, mac: [u8; 6]) -> Result<()> {
        self.dp.lock().await.neigh6_set(oif, ip, mac)?;
        Ok(())
    }

    /// Install an ILM (incoming-label map) entry.
    pub async fn add_ilm(&self, in_label: u32, nexthop_id: u32, op: u8, vrf_id: u32) -> Result<()> {
        self.dp
            .lock()
            .await
            .ilm_add(in_label, nexthop_id, op, vrf_id)?;
        Ok(())
    }

    /// Remove an ILM entry.
    pub async fn del_ilm(&self, in_label: u32) -> Result<()> {
        self.dp.lock().await.ilm_del(in_label)?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_service(
        &self,
        svc_id: u32,
        vip: Ipv4Addr,
        port: u16,
        proto: u8,
        backends: &[(Ipv4Addr, u16)],
        affinity: bool,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .service_add(svc_id, vip, port, proto, backends, affinity)?;
        Ok(())
    }

    /// Remove a service by its (vip, port, proto) key — either family.
    pub async fn del_service(&self, vip: IpAddr, port: u16, proto: u8) -> Result<()> {
        let mut dp = self.dp.lock().await;
        match vip {
            IpAddr::V4(v4) => dp.service_del(v4, port, proto)?,
            IpAddr::V6(v6) => dp.service6_del(v6, port, proto)?,
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn add_service6(
        &self,
        svc_id: u32,
        vip: Ipv6Addr,
        port: u16,
        proto: u8,
        backends: &[(Ipv6Addr, u16)],
        affinity: bool,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .service6_add(svc_id, vip, port, proto, backends, affinity)?;
        Ok(())
    }

    /// Allocate a pod address from `pool` (idempotent per `owner`).
    pub async fn cni_alloc_ip(&self, pool: &str, owner: &str) -> Result<(Ipv4Addr, u8)> {
        self.cni.lock().await.alloc_ip(pool, owner)
    }

    /// Allocate a pod IPv6 address from `pool6` (idempotent per `owner`).
    pub async fn cni_alloc_ip6(&self, pool6: &str, owner: &str) -> Result<(Ipv6Addr, u8)> {
        self.cni.lock().await.alloc_ip6(pool6, owner)
    }

    /// Release a pod's addresses by owner and/or specific v4/v6 address
    /// (idempotent).
    pub async fn cni_release_ip(
        &self,
        owner: &str,
        ip: Option<Ipv4Addr>,
        ip6: Option<Ipv6Addr>,
    ) -> Result<()> {
        self.cni.lock().await.release_ip(owner, ip, ip6)
    }

    /// Program the datapath for a pod endpoint whose veth the CNI plugin has
    /// already plumbed: register the host-side veth as a routed port (attaches
    /// TC+XDP; the veth carries no address, so nothing derives from it), point
    /// the pod /32 at a connected nexthop on that veth, install the kernel
    /// twin route `bpf_redirect_neigh` resolves the pod's neighbor through,
    /// and persist the endpoint record. Idempotent per (container, ifname).
    #[allow(clippy::too_many_arguments)]
    pub async fn cni_create_endpoint(
        &self,
        container_id: &str,
        ifname: &str,
        netns: &str,
        host_if: &str,
        ip: Ipv4Addr,
        ip6: Option<Ipv6Addr>,
        vrf: u32,
        pod_name: &str,
        pod_namespace: &str,
        chained: bool,
    ) -> Result<()> {
        let ifindex = util::ifindex_of(host_if)?;
        // Chained deployments (Cilium generic-veth on top): the chained
        // plugin owns the veth TC hook — attaching cradle_tc there would
        // forward pod egress before the policy program runs. The pod /32
        // stays in the eBPF FIB either way, so fabric-ingress traffic still
        // forwards in eBPF (the chained plugin's ingress policy applies at
        // the veth egress hook, which redirects traverse).
        if !chained {
            self.set_port(host_if, None, true, 0, vrf).await?;
            // Flag the veth as an endpoint port so the datapath tracks pod
            // egress (PCT) for stateful ingress policy. set_port left it
            // PORT_F_L3; re-set with the endpoint bit added.
            let mac = util::mac_of(host_if)?;
            self.dp.lock().await.port_set(
                ifindex,
                mac,
                cradle_common::PORT_F_L3 | cradle_common::PORT_F_ENDPOINT,
                0,
                vrf,
            )?;
        }
        {
            let mut dp = self.dp.lock().await;
            let nh = crate::kernel::CONNECTED_NH_BASE_V4 + ifindex;
            dp.nexthop_set(nh, None, ifindex, &[], 0)?;
            dp.route4_add(vrf, ip, 32, nh, 0)?;
            // Dual-stack: point the pod /128 at a v6 connected nexthop on
            // the same veth (FIB6), mirroring the v4 path.
            if let Some(ip6) = ip6 {
                let nh6 = crate::kernel::CONNECTED_NH_BASE_V6 + ifindex;
                dp.nexthop_set_v6(nh6, None, ifindex, &[], 0)?;
                dp.route6_add(vrf, ip6, 128, nh6, 0)?;
            }
        }
        crate::kernel::replace_dev_route_v4(ip, host_if)?;
        if let Some(ip6) = ip6 {
            crate::kernel::replace_dev_route_v6(ip6, host_if)?;
        }
        self.cni.lock().await.put_endpoint(&crate::cni::Endpoint {
            container_id: container_id.to_string(),
            ifname: ifname.to_string(),
            netns: netns.to_string(),
            host_if: host_if.to_string(),
            host_ifindex: ifindex,
            ip,
            ip6,
            vrf_id: vrf,
            pod_name: pod_name.to_string(),
            pod_namespace: pod_namespace.to_string(),
            chained,
        })?;
        info!(
            "cni endpoint {container_id}/{ifname}: {ip}{} via {host_if} (vrf {vrf}{})",
            ip6.map(|v| format!(" + {v}")).unwrap_or_default(),
            if chained { ", chained" } else { "" }
        );
        Ok(())
    }

    /// Tear down a pod endpoint: FIB route, kernel twin route, IP allocation,
    /// and the record. Idempotent — an unknown endpoint is a no-op (CNI DEL
    /// may be repeated). The veth itself is the plugin's to delete.
    pub async fn cni_delete_endpoint(&self, container_id: &str, ifname: &str) -> Result<()> {
        let cni = self.cni.lock().await;
        let Some(ep) = cni.get_endpoint(container_id, ifname)? else {
            return Ok(());
        };
        {
            let mut dp = self.dp.lock().await;
            let _ = dp.route4_del(ep.vrf_id, ep.ip, 32);
            if let Some(ip6) = ep.ip6 {
                let _ = dp.route6_del(ep.vrf_id, ip6, 128);
            }
        }
        crate::kernel::del_dev_route_v4(ep.ip, &ep.host_if);
        if let Some(ip6) = ep.ip6 {
            crate::kernel::del_dev_route_v6(ip6, &ep.host_if);
        }
        // Forget the attach so a reused ifindex re-attaches cleanly once the
        // plugin deletes the veth pair.
        self.attached.lock().await.remove(&ep.host_ifindex);
        cni.release_ip(
            &crate::cni::owner_key(container_id, ifname),
            Some(ep.ip),
            ep.ip6,
        )?;
        cni.remove_endpoint(container_id, ifname)?;
        info!("cni endpoint {container_id}/{ifname} removed ({})", ep.ip);
        Ok(())
    }

    /// Snapshot of pod/node IPv4 → enrichment ([`EpInfo`]) for Hubble flows.
    /// Rebuilt from the endpoint store + identity mirror per drain wake (pod
    /// churn is far slower than the flow rate). Identity-only IPs (e.g. a
    /// node/world address bound via config but not a CNI pod) still surface so
    /// both ends of a flow can carry an identity.
    pub async fn cni_ip_index(&self) -> HashMap<Ipv4Addr, EpInfo> {
        let ids = self.identities.lock().await.clone();
        let cni = self.cni.lock().await;
        let mut idx: HashMap<Ipv4Addr, EpInfo> = HashMap::new();
        if let Ok(eps) = cni.list_endpoints() {
            for ep in eps {
                idx.insert(
                    ep.ip,
                    EpInfo {
                        namespace: ep.pod_namespace.clone(),
                        pod_name: ep.pod_name.clone(),
                        identity: ids.get(&ep.ip).copied().unwrap_or(0),
                    },
                );
            }
        }
        for (ip, id) in ids {
            idx.entry(ip).or_insert(EpInfo {
                namespace: String::new(),
                pod_name: String::new(),
                identity: id,
            });
        }
        idx
    }

    /// Set the node's uplink IPv4 for egress masquerade (None = disable).
    pub async fn set_masq_node(&self, node: Option<Ipv4Addr>) -> Result<()> {
        self.dp.lock().await.masq_node_set(node)?;
        Ok(())
    }

    /// Add / remove a non-masquerade CIDR.
    pub async fn add_non_masq(&self, net: Ipv4Addr, prefix_len: u8) -> Result<()> {
        self.dp.lock().await.non_masq_add(net, prefix_len)?;
        Ok(())
    }

    pub async fn del_non_masq(&self, net: Ipv4Addr, prefix_len: u8) -> Result<()> {
        self.dp.lock().await.non_masq_del(net, prefix_len)?;
        Ok(())
    }

    /// Bind a pod/node address to a policy identity (`vrf` 0 = global; the
    /// Hubble enrichment mirror tracks the global scope only).
    pub async fn set_identity(&self, vrf: u32, ip: Ipv4Addr, identity: u32) -> Result<()> {
        self.dp.lock().await.identity_set(vrf, ip, identity)?;
        if vrf == 0 {
            self.identities.lock().await.insert(ip, identity);
        }
        Ok(())
    }

    /// Remove an identity binding (idempotent).
    pub async fn del_identity(&self, vrf: u32, ip: Ipv4Addr) -> Result<()> {
        self.dp.lock().await.identity_del(vrf, ip)?;
        if vrf == 0 {
            self.identities.lock().await.remove(&ip);
        }
        Ok(())
    }

    /// v6 sibling of `set_identity` / `del_identity`. (No Hubble identity
    /// mirror: flow export is v4-only.)
    pub async fn set_identity6(
        &self,
        vrf: u32,
        ip: Ipv6Addr,
        identity: u32,
        del: bool,
    ) -> Result<()> {
        self.dp.lock().await.identity6_set(vrf, ip, identity, del)?;
        Ok(())
    }

    /// Bind (or remove, `del`) a peer-CIDR identity (ipBlock peers).
    pub async fn set_cidr_identity(
        &self,
        vrf: u32,
        net: Ipv4Addr,
        prefix_len: u8,
        identity: u32,
        del: bool,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .cidr_identity_set(vrf, net, prefix_len, identity, del)?;
        Ok(())
    }

    /// v6 sibling of `set_cidr_identity`.
    pub async fn set_cidr6_identity(
        &self,
        vrf: u32,
        net: Ipv6Addr,
        prefix_len: u8,
        identity: u32,
        del: bool,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .cidr6_identity_set(vrf, net, prefix_len, identity, del)?;
        Ok(())
    }

    /// Resolve a policy target to its endpoint ifindex: by host veth name,
    /// or by pod identity through the endpoint store.
    pub async fn resolve_endpoint(
        &self,
        host_if: &str,
        pod_namespace: &str,
        pod_name: &str,
    ) -> Result<u32> {
        if !host_if.is_empty() {
            return util::ifindex_of(host_if);
        }
        let eps = self.cni.lock().await.list_endpoints()?;
        eps.iter()
            .find(|ep| ep.pod_name == pod_name && ep.pod_namespace == pod_namespace)
            .map(|ep| ep.host_ifindex)
            .with_context(|| format!("no endpoint for pod {pod_namespace}/{pod_name}"))
    }

    /// Replace an endpoint's policy (see `Dataplane::endpoint_policy_set`).
    #[allow(clippy::too_many_arguments)]
    pub async fn set_endpoint_policy(
        &self,
        ep: u32,
        enforce: bool,
        enforce_egress: bool,
        audit: bool,
        rules: &[(u32, u8, u16, bool)],
        egress_rules: &[(u32, u8, u16, bool)],
        l7: &[(u16, Vec<crate::l7::L7PolicyRule>)],
    ) -> Result<u64> {
        self.set_endpoint_l7(ep, l7).await?;
        self.dp.lock().await.endpoint_policy_set(
            ep,
            enforce,
            enforce_egress,
            audit,
            rules,
            egress_rules,
        )?;
        let rev = {
            let mut revs = self.policy_revisions.lock().await;
            let rev = revs.entry(ep).or_insert(0);
            *rev += 1;
            *rev
        };
        info!(
            "endpoint policy ifindex {ep} rev {rev}: ingress={enforce} ({} rule(s)), \
             egress={enforce_egress} ({} rule(s)), audit={audit}",
            rules.len(),
            egress_rules.len()
        );
        Ok(rev)
    }

    /// Program the endpoint's ingress L7 policy: steer each (pod-ip, port)
    /// through the proxy (`L7_SERVICES`) and install the allow-list in the
    /// route table. Replace semantics per endpoint; endpoints without a
    /// CNI-recorded IPv4 (plain `host_if` ports) log and skip.
    async fn set_endpoint_l7(
        &self,
        ep: u32,
        l7: &[(u16, Vec<crate::l7::L7PolicyRule>)],
    ) -> Result<()> {
        let ip = self
            .cni
            .lock()
            .await
            .list_endpoints()?
            .iter()
            .find(|e| e.host_ifindex == ep)
            .map(|e| e.ip);
        let mut programmed = self.l7_policies.lock().await;
        let old = programmed.remove(&ep).unwrap_or_default();
        let mut new_set = Vec::new();
        if let Some(ip) = ip {
            for (port, rules) in l7 {
                info!(
                    "endpoint {ep}: L7 policy steer {ip}:{port} ({} rule(s))",
                    rules.len()
                );
                self.dp.lock().await.l7_service_add(ip, *port)?;
                self.routes
                    .lock()
                    .await
                    .set_policy(std::net::SocketAddr::from((ip, *port)), rules.clone());
                new_set.push((ip, *port));
            }
        } else if !l7.is_empty() {
            warn!("endpoint {ep}: L7 policy needs a CNI-recorded pod IPv4 — skipped");
        }
        for (ip, port) in old {
            if !new_set.contains(&(ip, port)) {
                let _ = self.dp.lock().await.l7_service_del(ip, port);
                self.routes
                    .lock()
                    .await
                    .del_policy(&std::net::SocketAddr::from((ip, port)));
            }
        }
        if !new_set.is_empty() {
            programmed.insert(ep, new_set);
        }
        Ok(())
    }

    /// Resolve a hypothetical flow against the live policy maps — the
    /// operator's "why" tool (`cradle ctl policy-trace`). Mirrors the
    /// datapath's resolution order exactly: endpoint lookup, L7 steering,
    /// PCT statefulness aside (not simulated — flows are), identity
    /// (exact → CIDR LPM → world), then the six wildcard probes with
    /// deny-over-allow.
    pub async fn policy_trace(
        &self,
        src: IpAddr,
        dst: IpAddr,
        vrf: u32,
        proto: u8,
        port: u16,
    ) -> Result<(Vec<String>, String)> {
        use cradle_common::{
            EP_F_AUDIT, EP_F_EGRESS, EP_F_GEN, EP_F_INGRESS, IDENTITY_WORLD, POLICY_DENY,
            POLICY_DIR_INGRESS, POLICY_KEY_GEN,
        };
        let mut lines = Vec::new();
        // The enforced endpoint: dst resolved through the CNI store.
        let ep = self
            .cni
            .lock()
            .await
            .list_endpoints()?
            .iter()
            .find(|e| IpAddr::V4(e.ip) == dst || e.ip6.map(IpAddr::V6) == Some(dst))
            .map(|e| e.host_ifindex);
        let Some(ep) = ep else {
            lines.push(format!("dst {dst}: no policy endpoint (not a CNI pod)"));
            return Ok((lines, "DEFAULT-ALLOW".into()));
        };
        lines.push(format!("dst {dst}: endpoint ifindex {ep}"));
        let dp = self.dp.lock().await;
        let Some(flags) = dp.ep_policy_get(ep) else {
            lines.push("EP_POLICY: no entry — endpoint not enforced".into());
            return Ok((lines, "DEFAULT-ALLOW".into()));
        };
        let gen_bit = if flags & EP_F_GEN != 0 {
            POLICY_KEY_GEN
        } else {
            0
        };
        lines.push(format!(
            "EP_POLICY: ingress={} egress={} audit={} generation={}",
            flags & EP_F_INGRESS != 0,
            flags & EP_F_EGRESS != 0,
            flags & EP_F_AUDIT != 0,
            (flags & EP_F_GEN != 0) as u8,
        ));
        if flags & EP_F_INGRESS == 0 {
            lines.push("ingress not enforced".into());
            return Ok((lines, "DEFAULT-ALLOW".into()));
        }
        // L7 steering pre-empts the L4 verdict for its ports.
        if let (IpAddr::V4(d), true) = (dst, port != 0)
            && self
                .l7_policies
                .lock()
                .await
                .values()
                .any(|v| v.contains(&(d, port)))
        {
            lines.push(format!(
                "L7_SERVICES: {d}:{port} steered to the transparent proxy \
                     (HTTP allow-list enforced there)"
            ));
            return Ok((lines, "L7".into()));
        }
        // Peer identity, exactly as the datapath resolves it.
        let identity = match src {
            IpAddr::V4(s) => dp
                .identity_get(vrf, s)
                .inspect(|id| lines.push(format!("IDENTITY: (vrf {vrf}, {s}) = {id}")))
                .or_else(|| {
                    dp.cidr_identity_get(vrf, s)
                        .inspect(|id| lines.push(format!("CIDR_ID: (vrf {vrf}, {s}) = {id}")))
                }),
            IpAddr::V6(s) => dp
                .identity6_get(vrf, s)
                .inspect(|id| lines.push(format!("IDENTITY6: (vrf {vrf}, {s}) = {id}")))
                .or_else(|| {
                    dp.cidr6_identity_get(vrf, s)
                        .inspect(|id| lines.push(format!("CIDR_ID6: (vrf {vrf}, {s}) = {id}")))
                }),
        }
        .unwrap_or_else(|| {
            lines.push(format!("identity: (vrf {vrf}, {src}) unbound = world (2)"));
            IDENTITY_WORLD
        });
        // The six wildcard probes, most specific first; deny wins anywhere.
        let dport = u16::to_be(port);
        let mut allowed = false;
        let mut denied = false;
        for pat in [0u8, 4, 6, 1, 5, 7] {
            let key = cradle_common::PolicyKey {
                ep,
                identity: if pat & 1 != 0 { 0 } else { identity },
                port: if pat & 4 != 0 { 0 } else { dport },
                proto: if pat & 2 != 0 { 0 } else { proto },
                dir: POLICY_DIR_INGRESS | gen_bit,
            };
            if let Some(v) = dp.policy_get(&key) {
                let what = if v == POLICY_DENY { "DENY" } else { "allow" };
                lines.push(format!(
                    "POLICY: (identity {}, proto {}, port {}) = {what}",
                    key.identity,
                    key.proto,
                    u16::from_be(key.port),
                ));
                if v == POLICY_DENY {
                    denied = true;
                    break;
                }
                allowed = true;
            }
        }
        let verdict = if denied || !allowed {
            if !denied && !allowed {
                lines.push("POLICY: no probe matched — default deny".into());
            }
            if flags & EP_F_AUDIT != 0 {
                "AUDIT".into()
            } else {
                "DENY".into()
            }
        } else {
            "ALLOW".into()
        };
        Ok((lines, verdict))
    }

    /// Live policy-map entry counts (`cradle ctl policy-summary`).
    pub async fn policy_summary(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        self.dp.lock().await.policy_counts()
    }

    /// Snapshot of all per-endpoint policy revisions.
    pub async fn policy_revisions_snapshot(&self) -> HashMap<u32, u64> {
        self.policy_revisions.lock().await.clone()
    }

    /// Snapshot the persisted pod endpoints (CHECK/GC).
    pub async fn cni_list_endpoints(&self) -> Result<Vec<crate::cni::Endpoint>> {
        self.cni.lock().await.list_endpoints()
    }

    /// Startup reconcile: re-program every persisted endpoint into the fresh
    /// eBPF maps (a restarted daemon starts empty — the predecessor's maps
    /// died with it). An endpoint whose host veth is gone (the pod was torn
    /// down while we were dead, so the plugin's DEL never reached us) is
    /// completed instead: its address and record are released. Per-endpoint
    /// failures are logged, never fatal — one bad record must not take the
    /// daemon down.
    pub async fn cni_reconcile(&self) {
        let endpoints = match self.cni.lock().await.list_endpoints() {
            Ok(eps) => eps,
            Err(e) => {
                warn!("cni reconcile: listing endpoints: {e:#}");
                return;
            }
        };
        for ep in endpoints {
            if util::ifindex_of(&ep.host_if).is_ok() {
                if let Err(e) = self
                    .cni_create_endpoint(
                        &ep.container_id,
                        &ep.ifname,
                        &ep.netns,
                        &ep.host_if,
                        ep.ip,
                        ep.ip6,
                        ep.vrf_id,
                        &ep.pod_name,
                        &ep.pod_namespace,
                        ep.chained,
                    )
                    .await
                {
                    warn!("cni reconcile {}/{}: {e:#}", ep.container_id, ep.ifname);
                }
            } else {
                info!(
                    "cni reconcile: {}/{} host veth {} gone — completing the delete",
                    ep.container_id, ep.ifname, ep.host_if
                );
                let cni = self.cni.lock().await;
                let _ = cni.release_ip(
                    &crate::cni::owner_key(&ep.container_id, &ep.ifname),
                    Some(ep.ip),
                    ep.ip6,
                );
                let _ = cni.remove_endpoint(&ep.container_id, &ep.ifname);
            }
        }
    }

    /// Snapshot the datapath packet counters as `(name, packets)` pairs.
    pub async fn stats(&self) -> Result<Vec<(String, u64)>> {
        let vals = self.dp.lock().await.stats()?;
        Ok(STAT_NAMES
            .iter()
            .zip(vals)
            .map(|(name, packets)| (name.to_string(), packets))
            .collect())
    }

    /// Serve the gRPC control API (TCP or unix socket) until Ctrl-C (SIGINT)
    /// or SIGTERM.
    pub async fn serve(self, endpoint: GrpcEndpoint) -> Result<()> {
        let svc = CradleServer::new(GrpcService { control: self });
        // A termination signal races the server future directly instead of
        // driving tonic's graceful shutdown. A subscriber holding an open
        // server-streaming RPC (zebra-rs on `WatchFdb`, or a live `Dump`) never
        // lets a graceful drain finish, so the daemon would hang. Dropping the
        // server future exits immediately; the eBPF programs are held by
        // bpf_links that die with the process, so there is nothing to flush.
        // We watch both Ctrl-C (SIGINT) and SIGTERM (systemd/`kill`/container
        // stop) so the daemon stops promptly under either.
        let shutdown = async {
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("register SIGTERM handler");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => info!("shutdown signal received (SIGINT)"),
                _ = sigterm.recv() => info!("shutdown signal received (SIGTERM)"),
            }
        };
        match endpoint {
            GrpcEndpoint::Tcp(addr) => {
                info!("serving gRPC control API on tcp {addr}");
                let srv = Server::builder().add_service(svc).serve(addr);
                tokio::select! {
                    r = srv => r?,
                    _ = shutdown => {}
                }
            }
            GrpcEndpoint::Uds(path) => {
                let _ = std::fs::remove_file(&path); // clear a stale socket
                info!("serving gRPC control API on unix {}", path.display());
                let uds = tokio::net::UnixListener::bind(&path)
                    .with_context(|| format!("binding {}", path.display()))?;
                let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);
                let srv = Server::builder()
                    .add_service(svc)
                    .serve_with_incoming(incoming);
                tokio::select! {
                    r = srv => r?,
                    _ = shutdown => {}
                }
            }
            GrpcEndpoint::AbstractUds(name) => {
                info!("serving gRPC control API on abstract unix @{name}");
                let incoming = bind_abstract_uds(&name)?;
                let srv = Server::builder()
                    .add_service(svc)
                    .serve_with_incoming(incoming);
                tokio::select! {
                    r = srv => r?,
                    _ = shutdown => {}
                }
            }
        }
        Ok(())
    }
}

/// Bind a Linux abstract Unix socket by name (no filesystem entry). The name
/// is scoped to the process network namespace, so per-netns cradle instances
/// don't collide — this backs the default `unix:cradle/grpc` endpoint.
fn bind_abstract_uds(name: &str) -> Result<tokio_stream::wrappers::UnixListenerStream> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::SocketAddr as StdSockAddr;
    use std::os::unix::net::UnixListener as StdUnixListener;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;

    let addr = StdSockAddr::from_abstract_name(name.as_bytes())
        .with_context(|| format!("invalid abstract socket name '@{name}' (contains NUL?)"))?;
    let std_listener = StdUnixListener::bind_addr(&addr).map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse => anyhow::anyhow!(
            "abstract gRPC socket '@{name}' is already in use \
             (another cradle running in this network namespace?)"
        ),
        _ => anyhow::anyhow!("failed to bind abstract gRPC socket '@{name}': {e}"),
    })?;
    std_listener
        .set_nonblocking(true)
        .with_context(|| format!("set_nonblocking on abstract gRPC socket '@{name}'"))?;
    let listener = UnixListener::from_std(std_listener)
        .with_context(|| format!("register abstract gRPC socket '@{name}' with tokio"))?;
    Ok(UnixListenerStream::new(listener))
}

struct GrpcService {
    control: Control,
}

fn st<E: std::fmt::Display>(e: E) -> Status {
    Status::internal(e.to_string())
}

/// Display name of an MPLS ILM op for `cradle dump mpls`.
fn mpls_op_name(op: u8) -> &'static str {
    match op {
        MPLS_OP_SWAP => "swap",
        MPLS_OP_POP_L3 => "pop_l3",
        MPLS_OP_POP => "pop",
        _ => "unknown",
    }
}

/// Display name of an SRv6 behavior code for `cradle dump srv6`.
fn srv6_behavior_name(b: u8) -> &'static str {
    match b {
        SRV6_BH_END => "End",
        SRV6_BH_END_X => "End.X",
        SRV6_BH_END_DT4 => "End.DT4",
        SRV6_BH_END_DT6 => "End.DT6",
        SRV6_BH_END_DT46 => "End.DT46",
        SRV6_BH_END_B6 => "End.B6.Encaps",
        SRV6_BH_UN => "uN",
        SRV6_BH_UA => "uA",
        SRV6_BH_UALIB => "uA.lib",
        SRV6_BH_END_DT2U => "End.DT2U",
        SRV6_BH_END_DT2M => "End.DT2M",
        SRV6_BH_END_M => "End.M",
        SRV6_BH_END_REP => "End.Replace",
        SRV6_BH_END_X_REP => "End.X.Replace",
        SRV6_BH_END_T => "End.T",
        SRV6_BH_END_DX4 => "End.DX4",
        SRV6_BH_END_DX6 => "End.DX6",
        SRV6_BH_END_DX2 => "End.DX2",
        SRV6_BH_END_DX2V => "End.DX2V",
        _ => "unknown",
    }
}

fn fmt_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Render a resolved nexthop into the wire `NexthopInfo`.
fn nh_to_pb(id: u32, nh: &NextHop) -> pb::NexthopInfo {
    let gateway = if nh.flags & NH_F_V6 != 0 {
        let a = Ipv6Addr::from(nh.gateway_v6);
        if a.is_unspecified() {
            String::new()
        } else {
            a.to_string()
        }
    } else if nh.gateway_v4 != 0 {
        Ipv4Addr::from(nh.gateway_v4.to_be_bytes()).to_string()
    } else {
        String::new()
    };
    pb::NexthopInfo {
        id,
        gateway,
        oif: nh.oif,
        labels: nh.labels[..nh.num_labels as usize].to_vec(),
        flags: nh.flags,
    }
}

/// Convert one domain `DumpRow` into the wire `pb::DumpEntry`.
fn row_to_pb(row: DumpRow) -> pb::DumpEntry {
    use pb::dump_entry::Entry;
    let entry = match row {
        DumpRow::Fdb {
            mac,
            vlan,
            oif,
            flags,
            remote_sid,
            age_ms,
        } => {
            let sid = Ipv6Addr::from(remote_sid);
            Entry::Fdb(pb::FdbDumpEntry {
                mac: fmt_mac(mac),
                vlan: vlan as u32,
                oif,
                flags,
                remote_sid: if sid.is_unspecified() {
                    String::new()
                } else {
                    sid.to_string()
                },
                age_ms,
            })
        }
        DumpRow::Fib {
            addr,
            prefix_len,
            vrf,
            nexthop_id,
            flags,
            nh,
        } => Entry::Fib(pb::FibDumpEntry {
            prefix: format!("{addr}/{prefix_len}"),
            vrf,
            nexthop_id,
            flags,
            nh: nh.map(|n| nh_to_pb(nexthop_id, &n)),
        }),
        DumpRow::Mpls {
            label,
            op,
            nexthop_id,
            vrf,
            nh,
        } => Entry::Mpls(pb::MplsDumpEntry {
            label,
            op: mpls_op_name(op).to_string(),
            nexthop_id,
            vrf,
            nh: nh.map(|n| nh_to_pb(nexthop_id, &n)),
        }),
        DumpRow::Srv6LocalSid {
            sid,
            prefix_len,
            behavior,
            flavors,
            vrf,
            nexthop_id,
            nh,
        } => Entry::Srv6Localsid(pb::Srv6LocalSidEntry {
            sid: sid.to_string(),
            prefix_len: prefix_len as u32,
            behavior: srv6_behavior_name(behavior).to_string(),
            flavors: flavors as u32,
            vrf,
            nexthop_id,
            nh: nh.map(|n| nh_to_pb(nexthop_id, &n)),
        }),
        DumpRow::Srv6Encap { nexthop_id, encap } => {
            let segs = encap.segs[..encap.num_segs as usize]
                .iter()
                .map(|s| Ipv6Addr::from(*s).to_string())
                .collect();
            Entry::Srv6Encap(pb::Srv6EncapEntry {
                nexthop_id,
                mode: if encap.mode == SRV6_ENCAP_MODE_INSERT {
                    "insert"
                } else {
                    "encaps"
                }
                .to_string(),
                segs,
            })
        }
        DumpRow::Nexthop { id, nh } => {
            let info = nh_to_pb(id, &nh);
            Entry::Nexthop(pb::NexthopDumpEntry {
                id,
                gateway: info.gateway,
                oif: info.oif,
                flags: info.flags,
                labels: info.labels,
                backup_id: nh.backup_id,
                group: Vec::new(),
            })
        }
        DumpRow::NexthopGroup { id, members } => Entry::Nexthop(pb::NexthopDumpEntry {
            id,
            gateway: String::new(),
            oif: 0,
            flags: 0,
            labels: Vec::new(),
            backup_id: 0,
            group: members,
        }),
    };
    pb::DumpEntry { entry: Some(entry) }
}

#[tonic::async_trait]
impl Cradle for GrpcService {
    async fn set_port(&self, req: Request<pb::Port>) -> Result<Response<pb::Empty>, Status> {
        let p = req.into_inner();
        self.control
            .set_port(&p.name, Some(&p.mac), p.l3, p.vlan as u16, p.vrf_id)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_port(&self, req: Request<pb::PortDel>) -> Result<Response<pb::Empty>, Status> {
        let p = req.into_inner();
        self.control.del_port(&p.name).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_l2_domain(
        &self,
        req: Request<pb::L2Domain>,
    ) -> Result<Response<pb::Empty>, Status> {
        let d = req.into_inner();
        self.control
            .set_l2_domain(d.vlan as u16, &d.members)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn flush_fdb(&self, req: Request<pb::FdbFlush>) -> Result<Response<pb::Empty>, Status> {
        let f = req.into_inner();
        let port = Some(f.port.as_str()).filter(|p| !p.is_empty());
        let vlan = (f.vlan != 0).then_some(f.vlan as u16);
        self.control.flush_fdb(port, vlan).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_nexthop(&self, req: Request<pb::Nexthop>) -> Result<Response<pb::Empty>, Status> {
        let n = req.into_inner();
        // Nudge the kernel into resolving the gateway's neighbor: cradle
        // owns the forwarding path, so nothing else would ever trigger
        // ND/ARP for it — and the L2-rewrite egress paths need the entry,
        // which the control plane tees back once the kernel learns it. A
        // 0-byte UDP datagram to the discard port is enough; best-effort.
        if !n.gateway.is_empty()
            && let Ok(gw) = n.gateway.parse::<std::net::IpAddr>()
        {
            tokio::spawn(async move {
                let bind = if gw.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                if let Ok(sock) = tokio::net::UdpSocket::bind(bind).await {
                    let _ = sock.send_to(&[], (gw, 9)).await;
                }
            });
        }
        // A GTP-U nexthop (non-empty `gtp_dst`) imposes a GTP4.E encap: outer
        // IPv4 + UDP(2152) + GTP-U(gtp_teid) over the v4 underlay `gateway`.
        if !n.gtp_dst.is_empty() {
            let gw = if n.gateway.is_empty() {
                None
            } else {
                Some(n.gateway.parse::<Ipv4Addr>().map_err(st)?)
            };
            let oif = if n.oif_index != 0 {
                n.oif_index
            } else {
                util::ifindex_of(&n.oif).map_err(st)?
            };
            let src = n.gtp_src.parse::<Ipv4Addr>().map_err(st)?;
            let dst = n.gtp_dst.parse::<Ipv4Addr>().map_err(st)?;
            self.control
                .set_nexthop_gtp(n.id, gw, oif, src, dst, n.gtp_teid)
                .await
                .map_err(st)?;
        // A nexthop carrying SRv6 segments imposes an H.Encaps (always v6
        // underlay), regardless of the `v6` flag.
        } else if !n.segs.is_empty() {
            let gw = if n.gateway.is_empty() {
                None
            } else {
                Some(n.gateway.parse::<Ipv6Addr>().map_err(st)?)
            };
            let oif = if n.oif_index != 0 {
                n.oif_index
            } else {
                util::ifindex_of(&n.oif).map_err(st)?
            };
            let segs = n
                .segs
                .iter()
                .map(|s| s.parse::<Ipv6Addr>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(st)?;
            self.control
                .set_nexthop_srv6(n.id, gw, oif, &segs, n.encap_mode as u8)
                .await
                .map_err(st)?;
        } else if n.v6 {
            let gw = if n.gateway.is_empty() {
                None
            } else {
                Some(n.gateway.parse::<Ipv6Addr>().map_err(st)?)
            };
            let oif = if n.oif_index != 0 {
                n.oif_index
            } else {
                util::ifindex_of(&n.oif).map_err(st)?
            };
            self.control
                .set_nexthop_idx_v6(n.id, gw, oif, &n.labels, n.backup_id)
                .await
                .map_err(st)?;
        } else {
            let gw = if n.gateway.is_empty() {
                None
            } else {
                Some(n.gateway.parse::<Ipv4Addr>().map_err(st)?)
            };
            if n.oif_index != 0 || n.oif.is_empty() {
                // oif_index 0 with no name: an oif-less nexthop (e.g. an ILM
                // decap target that never egresses through it) — store as-is.
                self.control
                    .set_nexthop_idx(n.id, gw, n.oif_index, &n.labels, n.backup_id)
                    .await
                    .map_err(st)?;
            } else {
                self.control
                    .set_nexthop(n.id, gw, &n.oif, &n.labels, n.backup_id)
                    .await
                    .map_err(st)?;
            }
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_nexthop_group(
        &self,
        req: Request<pb::NexthopGroup>,
    ) -> Result<Response<pb::Empty>, Status> {
        let g = req.into_inner();
        self.control
            .set_nexthop_group(g.id, &g.members)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_route4(&self, req: Request<pb::Route4>) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let (addr, len) = util::parse_ipv4_prefix(&r.prefix).map_err(st)?;
        self.control
            .add_route4(r.vrf_table_id, addr, len, r.nexthop_id, r.flags)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_route4(&self, req: Request<pb::Route4Del>) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let (addr, len) = util::parse_ipv4_prefix(&r.prefix).map_err(st)?;
        self.control
            .del_route4(r.vrf_table_id, addr, len)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_route4_batch(
        &self,
        req: Request<pb::Route4Batch>,
    ) -> Result<Response<pb::Empty>, Status> {
        let b = req.into_inner();
        let mut routes = Vec::with_capacity(b.routes.len());
        for r in &b.routes {
            let (addr, len) = util::parse_ipv4_prefix(&r.prefix).map_err(st)?;
            routes.push((r.vrf_table_id, addr, len, r.nexthop_id, r.flags));
        }
        self.control.add_routes4(&routes).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn get_fib_summary(
        &self,
        _req: Request<pb::FibSummaryRequest>,
    ) -> Result<Response<pb::FibSummary>, Status> {
        let (mode, routes4, tbl8_used, tbl8_free) = self.control.fib_summary().await;
        Ok(Response::new(pb::FibSummary {
            fib4_mode: mode.to_string(),
            routes4,
            tbl8_used,
            tbl8_free,
        }))
    }

    async fn add_route6(&self, req: Request<pb::Route6>) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let (addr, len) = util::parse_ipv6_prefix(&r.prefix).map_err(st)?;
        self.control
            .add_route6(r.vrf_table_id, addr, len, r.nexthop_id, r.flags)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_route6(&self, req: Request<pb::Route6Del>) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let (addr, len) = util::parse_ipv6_prefix(&r.prefix).map_err(st)?;
        self.control
            .del_route6(r.vrf_table_id, addr, len)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_local_sid(
        &self,
        req: Request<pb::LocalSid>,
    ) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let sid: Ipv6Addr = s.sid.parse().map_err(st)?;
        let prefix_len = if s.prefix_len == 0 {
            128
        } else {
            s.prefix_len as u8
        };
        let behavior = srv6_behavior(s.behavior).map_err(st)?;
        // uSID (uN/uA) NEXT-C-SID shift geometry: the locator block / node
        // (micro-SID) bit lengths from the SID structure (`lb_bits`/`ln_bits`).
        if s.flavors > 7 {
            return Err(Status::invalid_argument(format!(
                "unknown SRv6 flavor bits {:#x}",
                s.flavors
            )));
        }
        self.control
            .add_localsid(
                sid,
                prefix_len,
                behavior,
                s.vrf_table_id,
                s.nexthop_id,
                s.lb_bits as u8,
                s.ln_bits as u8,
                s.fun_bits as u8,
                s.flavors as u8,
            )
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_gtp_pdr(&self, req: Request<pb::GtpPdr>) -> Result<Response<pb::Empty>, Status> {
        let p = req.into_inner();
        let dst = p.dst.parse::<Ipv4Addr>().map_err(st)?;
        self.control
            .gtp_pdr_add(dst, p.teid, p.vrf)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_gtp_pdr(
        &self,
        req: Request<pb::GtpPdrDel>,
    ) -> Result<Response<pb::Empty>, Status> {
        let p = req.into_inner();
        let dst = p.dst.parse::<Ipv4Addr>().map_err(st)?;
        self.control.gtp_pdr_del(dst, p.teid).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_local_sid(
        &self,
        req: Request<pb::LocalSidDel>,
    ) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let sid: Ipv6Addr = s.sid.parse().map_err(st)?;
        let prefix_len = if s.prefix_len == 0 {
            128
        } else {
            s.prefix_len as u8
        };
        self.control
            .del_localsid(sid, prefix_len)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_srv6_encap_source(
        &self,
        req: Request<pb::Srv6EncapSource>,
    ) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let addr: Ipv6Addr = s.addr.parse().map_err(st)?;
        self.control.set_srv6_encap_source(addr).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_vni(&self, req: Request<pb::Vni>) -> Result<Response<pb::Empty>, Status> {
        let v = req.into_inner();
        self.control
            .set_vni(v.vni, v.vlan as u16)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_vni(&self, req: Request<pb::VniDel>) -> Result<Response<pb::Empty>, Status> {
        let v = req.into_inner();
        self.control.del_vni(v.vni).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_vtep_source(
        &self,
        req: Request<pb::VtepSource>,
    ) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let addr: Ipv4Addr = s.addr.parse().map_err(st)?;
        self.control.set_vtep_source(addr).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_fdb_remote(
        &self,
        req: Request<pb::FdbRemote>,
    ) -> Result<Response<pb::Empty>, Status> {
        let f = req.into_inner();
        let mac = util::parse_mac(&f.mac).map_err(st)?;
        match (f.remote_sid.is_empty(), f.remote_vtep.is_empty()) {
            (false, true) => {
                let remote_sid: Ipv6Addr = f.remote_sid.parse().map_err(st)?;
                self.control
                    .add_fdb_remote(mac, f.bd as u16, remote_sid, f.nexthop_id)
                    .await
                    .map_err(st)?;
            }
            (true, false) => {
                let vtep: Ipv4Addr = f.remote_vtep.parse().map_err(st)?;
                self.control
                    .add_fdb_remote_vxlan(mac, f.bd as u16, vtep, f.nexthop_id)
                    .await
                    .map_err(st)?;
            }
            _ => {
                return Err(Status::invalid_argument(
                    "exactly one of remote_sid / remote_vtep",
                ));
            }
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_fdb_remote(
        &self,
        req: Request<pb::FdbRemoteDel>,
    ) -> Result<Response<pb::Empty>, Status> {
        let f = req.into_inner();
        let mac = util::parse_mac(&f.mac).map_err(st)?;
        self.control
            .del_fdb_remote(mac, f.bd as u16)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_xconnect(
        &self,
        req: Request<pb::Xconnect>,
    ) -> Result<Response<pb::Empty>, Status> {
        let x = req.into_inner();
        let sid: Ipv6Addr = x.remote_sid.parse().map_err(st)?;
        let local_sid = if x.local_sid.is_empty() {
            None
        } else {
            Some(x.local_sid.parse().map_err(st)?)
        };
        let vid = x.vid as u16;
        if x.port_index != 0 {
            self.control
                .add_xconnect_idx(x.port_index, sid, local_sid, vid, x.dx2v_table)
                .await
                .map_err(st)?;
        } else {
            self.control
                .add_xconnect(&x.port, sid, local_sid, vid, x.dx2v_table)
                .await
                .map_err(st)?;
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_xconnect(
        &self,
        req: Request<pb::XconnectDel>,
    ) -> Result<Response<pb::Empty>, Status> {
        let x = req.into_inner();
        let local_sid = if x.local_sid.is_empty() {
            None
        } else {
            Some(x.local_sid.parse().map_err(st)?)
        };
        let vid = x.vid as u16;
        if x.port_index != 0 {
            self.control
                .del_xconnect_idx(x.port_index, local_sid, vid, x.dx2v_table)
                .await
                .map_err(st)?;
        } else {
            self.control
                .del_xconnect(&x.port, local_sid, vid, x.dx2v_table)
                .await
                .map_err(st)?;
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_repl_slot(
        &self,
        req: Request<pb::ReplSlot>,
    ) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        match (r.remote_sid.is_empty(), r.remote_vtep.is_empty()) {
            (false, true) => {
                let sid: Ipv6Addr = r.remote_sid.parse().map_err(st)?;
                self.control
                    .add_repl_slot_auto(r.bd as u16, sid)
                    .await
                    .map_err(st)?;
            }
            (true, false) => {
                let vtep: Ipv4Addr = r.remote_vtep.parse().map_err(st)?;
                self.control
                    .add_repl_slot_auto_vxlan(r.bd as u16, vtep)
                    .await
                    .map_err(st)?;
            }
            _ => {
                return Err(Status::invalid_argument(
                    "exactly one of remote_sid / remote_vtep",
                ));
            }
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_repl_slot(
        &self,
        req: Request<pb::ReplSlot>,
    ) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        // One slot registry serves both overlays: a VXLAN slot is keyed by
        // its VTEP v4-mapped, so the delete resolves to the same key.
        let key: Ipv6Addr = if r.remote_vtep.is_empty() {
            r.remote_sid.parse().map_err(st)?
        } else {
            r.remote_vtep
                .parse::<Ipv4Addr>()
                .map_err(st)?
                .to_ipv6_mapped()
        };
        self.control
            .del_repl_slot_auto(r.bd as u16, key)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_mirror_route(
        &self,
        req: Request<pb::MirrorRoute>,
    ) -> Result<Response<pb::Empty>, Status> {
        let m = req.into_inner();
        let prefix: Ipv6Addr = m.prefix.parse().map_err(st)?;
        let behavior = srv6_behavior(m.behavior).map_err(st)?;
        self.control
            .add_mirror_route(m.ctx, prefix, m.prefix_len as u8, behavior, m.vrf_table_id)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_mirror_route(
        &self,
        req: Request<pb::MirrorRouteDel>,
    ) -> Result<Response<pb::Empty>, Status> {
        let m = req.into_inner();
        let prefix: Ipv6Addr = m.prefix.parse().map_err(st)?;
        self.control
            .del_mirror_route(m.ctx, prefix, m.prefix_len as u8)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    type WatchFdbStream = tokio_stream::wrappers::ReceiverStream<Result<pb::FdbEvent, Status>>;

    /// Stream datapath MAC learning to the control plane: a 1s poll of the
    /// FDB map, diffed against the entries already reported on this stream.
    /// New entries emit `event: 0` (learned); entries that disappear —
    /// expired by the aging sweep, or removed any other way — emit
    /// `event: 1` (aged) so the subscriber withdraws its Type-2. A fresh
    /// subscription replays the full current set first.
    async fn watch_fdb(
        &self,
        _req: Request<pb::WatchFdbRequest>,
    ) -> Result<Response<Self::WatchFdbStream>, Status> {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let control = self.control.clone();
        let mut hints = self.control.subscribe_fdb_hints();
        tokio::spawn(async move {
            let fmt_mac = |mac: [u8; 6]| {
                format!(
                    "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                )
            };
            let mut seen: std::collections::HashSet<([u8; 6], u16)> =
                std::collections::HashSet::new();
            loop {
                let current: std::collections::HashSet<([u8; 6], u16)> =
                    control.fdb_local_entries().await.into_iter().collect();
                for &(mac, bd) in current.difference(&seen) {
                    let ev = pb::FdbEvent {
                        mac: fmt_mac(mac),
                        bd: bd as u32,
                        event: 0, // learned
                    };
                    if tx.send(Ok(ev)).await.is_err() {
                        return; // subscriber went away
                    }
                }
                for &(mac, bd) in seen.difference(&current) {
                    let ev = pb::FdbEvent {
                        mac: fmt_mac(mac),
                        bd: bd as u32,
                        event: 1, // aged / removed
                    };
                    if tx.send(Ok(ev)).await.is_err() {
                        return;
                    }
                }
                seen = current;
                // Wake either on the periodic poll or immediately on a
                // move-away hint. A hint fires an age event synchronously for a
                // MAC that a remote install just displaced from local — closing
                // the race where the local→remote flip is reverted by a fresh
                // learn before the next poll observes it (MAC mobility).
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                    hint = hints.recv() => {
                        match hint {
                            Ok((mac, bd)) => {
                                if seen.remove(&(mac, bd)) {
                                    let ev = pb::FdbEvent {
                                        mac: fmt_mac(mac),
                                        bd: bd as u32,
                                        event: 1, // aged / removed (moved away)
                                    };
                                    if tx.send(Ok(ev)).await.is_err() {
                                        return;
                                    }
                                }
                            }
                            // Lagged/closed: fall through and re-poll.
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        }
                    }
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn set_neighbor4(
        &self,
        req: Request<pb::Neighbor4>,
    ) -> Result<Response<pb::Empty>, Status> {
        let n = req.into_inner();
        let ip = n.ip.parse().map_err(st)?;
        let mac = util::parse_mac(&n.mac).map_err(st)?;
        if n.oif_index != 0 {
            self.control
                .set_neighbor4_idx(n.oif_index, ip, mac)
                .await
                .map_err(st)?;
        } else {
            self.control
                .set_neighbor4(&n.oif, ip, mac)
                .await
                .map_err(st)?;
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_neighbor6(
        &self,
        req: Request<pb::Neighbor6>,
    ) -> Result<Response<pb::Empty>, Status> {
        let n = req.into_inner();
        let ip = n.ip.parse().map_err(st)?;
        let mac = util::parse_mac(&n.mac).map_err(st)?;
        if n.oif_index != 0 {
            self.control
                .set_neighbor6_idx(n.oif_index, ip, mac)
                .await
                .map_err(st)?;
        } else {
            self.control
                .set_neighbor6(&n.oif, ip, mac)
                .await
                .map_err(st)?;
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_ilm(&self, req: Request<pb::Ilm>) -> Result<Response<pb::Empty>, Status> {
        let i = req.into_inner();
        if i.in_label >= 1 << 20 {
            return Err(Status::invalid_argument(format!(
                "MPLS label {} exceeds 20 bits",
                i.in_label
            )));
        }
        let op = match i.action {
            a if a == MPLS_OP_SWAP as u32 => MPLS_OP_SWAP,
            a if a == MPLS_OP_POP_L3 as u32 => MPLS_OP_POP_L3,
            a if a == MPLS_OP_POP as u32 => MPLS_OP_POP,
            other => {
                return Err(Status::invalid_argument(format!("bad ILM action {other}")));
            }
        };
        self.control
            .add_ilm(i.in_label, i.nexthop_id, op, i.vrf_table_id)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_ilm(&self, req: Request<pb::IlmDel>) -> Result<Response<pb::Empty>, Status> {
        let i = req.into_inner();
        self.control.del_ilm(i.in_label).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_service(&self, req: Request<pb::Service>) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let proto = match s.proto.as_str() {
            "tcp" => 6u8,
            "udp" => 17u8,
            other => return Err(Status::invalid_argument(format!("bad proto {other:?}"))),
        };
        let vip: IpAddr = s.vip.parse().map_err(st)?;
        match vip {
            IpAddr::V4(v4) => {
                let backends = s
                    .backends
                    .iter()
                    .map(|b| Ok((b.ip.parse::<Ipv4Addr>().map_err(st)?, b.port as u16)))
                    .collect::<Result<Vec<_>, Status>>()?;
                self.control
                    .add_service(s.svc_id, v4, s.port as u16, proto, &backends, s.affinity)
                    .await
                    .map_err(st)?;
            }
            IpAddr::V6(v6) => {
                let backends = s
                    .backends
                    .iter()
                    .map(|b| Ok((b.ip.parse::<Ipv6Addr>().map_err(st)?, b.port as u16)))
                    .collect::<Result<Vec<_>, Status>>()?;
                self.control
                    .add_service6(s.svc_id, v6, s.port as u16, proto, &backends, s.affinity)
                    .await
                    .map_err(st)?;
            }
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_service(
        &self,
        req: Request<pb::ServiceDel>,
    ) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let proto = match s.proto.as_str() {
            "tcp" => 6u8,
            "udp" => 17u8,
            other => return Err(Status::invalid_argument(format!("bad proto {other:?}"))),
        };
        let vip: IpAddr = s.vip.parse().map_err(st)?;
        self.control
            .del_service(vip, s.port as u16, proto)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn get_stats(
        &self,
        _req: Request<pb::StatsRequest>,
    ) -> Result<Response<pb::StatsReply>, Status> {
        let entries = self
            .control
            .stats()
            .await
            .map_err(st)?
            .into_iter()
            .map(|(name, packets)| pb::StatEntry { name, packets })
            .collect();
        Ok(Response::new(pb::StatsReply { entries }))
    }

    type DumpStream = tokio_stream::wrappers::ReceiverStream<Result<pb::DumpEntry, Status>>;

    /// Stream a forwarding table's contents (`cradle dump`). The snapshot is
    /// taken under the data-plane lock up front, then streamed so an arbitrarily
    /// large FIB never has to fit in one gRPC message.
    async fn dump(
        &self,
        req: Request<pb::DumpRequest>,
    ) -> Result<Response<Self::DumpStream>, Status> {
        let r = req.into_inner();
        let table = match pb::DumpTable::try_from(r.table).unwrap_or(pb::DumpTable::DumpL2) {
            pb::DumpTable::DumpL2 => DumpTable::L2,
            pb::DumpTable::DumpIpv4 => DumpTable::Ipv4,
            pb::DumpTable::DumpIpv6 => DumpTable::Ipv6,
            pb::DumpTable::DumpMpls => DumpTable::Mpls,
            pb::DumpTable::DumpSrv6 => DumpTable::Srv6,
            pb::DumpTable::DumpNexthop => DumpTable::Nexthop,
        };
        let rows = self
            .control
            .dump(table, r.vrf, r.resolve)
            .await
            .map_err(st)?;
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            for row in rows {
                if tx.send(Ok(row_to_pb(row))).await.is_err() {
                    return; // client hung up
                }
            }
        });
        Ok(Response::new(tokio_stream::wrappers::ReceiverStream::new(
            rx,
        )))
    }

    async fn set_masq_node(
        &self,
        req: Request<pb::MasqNode>,
    ) -> Result<Response<pb::Empty>, Status> {
        let m = req.into_inner();
        let node = if m.node.is_empty() {
            None
        } else {
            Some(m.node.parse::<Ipv4Addr>().map_err(st)?)
        };
        self.control.set_masq_node(node).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_non_masq(&self, req: Request<pb::NonMasq>) -> Result<Response<pb::Empty>, Status> {
        let n = req.into_inner();
        let (net, len) = util::parse_ipv4_prefix(&n.cidr).map_err(st)?;
        if n.del {
            self.control.del_non_masq(net, len).await.map_err(st)?;
        } else {
            self.control.add_non_masq(net, len).await.map_err(st)?;
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_identity(
        &self,
        req: Request<pb::Identity>,
    ) -> Result<Response<pb::Empty>, Status> {
        let i = req.into_inner();
        match i.ip.parse::<IpAddr>().map_err(st)? {
            IpAddr::V4(ip) => self.control.set_identity(i.vrf_id, ip, i.identity).await,
            IpAddr::V6(ip) => {
                self.control
                    .set_identity6(i.vrf_id, ip, i.identity, false)
                    .await
            }
        }
        .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_identity(
        &self,
        req: Request<pb::IdentityDel>,
    ) -> Result<Response<pb::Empty>, Status> {
        let i = req.into_inner();
        match i.ip.parse::<IpAddr>().map_err(st)? {
            IpAddr::V4(ip) => self.control.del_identity(i.vrf_id, ip).await,
            IpAddr::V6(ip) => self.control.set_identity6(i.vrf_id, ip, 0, true).await,
        }
        .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_cidr_identity(
        &self,
        req: Request<pb::CidrIdentity>,
    ) -> Result<Response<pb::Empty>, Status> {
        let c = req.into_inner();
        if c.cidr.contains(':') {
            let (net, len) = util::parse_ipv6_prefix(&c.cidr).map_err(st)?;
            self.control
                .set_cidr6_identity(c.vrf_id, net, len, c.identity, c.del)
                .await
                .map_err(st)?;
        } else {
            let (net, len) = util::parse_ipv4_prefix(&c.cidr).map_err(st)?;
            self.control
                .set_cidr_identity(c.vrf_id, net, len, c.identity, c.del)
                .await
                .map_err(st)?;
        }
        Ok(Response::new(pb::Empty {}))
    }

    async fn policy_trace(
        &self,
        req: Request<pb::PolicyTraceRequest>,
    ) -> Result<Response<pb::PolicyTraceReply>, Status> {
        let r = req.into_inner();
        let src = r.src.parse::<IpAddr>().map_err(st)?;
        let dst = r.dst.parse::<IpAddr>().map_err(st)?;
        let proto = match r.proto.as_str() {
            "udp" => 17,
            "" | "any" => 0,
            _ => 6,
        };
        let (lines, verdict) = self
            .control
            .policy_trace(src, dst, r.vrf_id, proto, r.port as u16)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::PolicyTraceReply { lines, verdict }))
    }

    async fn get_policy_summary(
        &self,
        _req: Request<pb::PolicySummaryRequest>,
    ) -> Result<Response<pb::PolicySummary>, Status> {
        let (identities, identities6, cidrs, cidrs6, endpoints, rules, pct, pct6) =
            self.control.policy_summary().await;
        Ok(Response::new(pb::PolicySummary {
            identities,
            identities6,
            cidrs,
            cidrs6,
            endpoints,
            rules,
            pct,
            pct6,
        }))
    }

    async fn set_endpoint_policy(
        &self,
        req: Request<pb::EndpointPolicy>,
    ) -> Result<Response<pb::Empty>, Status> {
        let p = req.into_inner();
        let ep = self
            .control
            .resolve_endpoint(&p.host_if, &p.pod_namespace, &p.pod_name)
            .await
            .map_err(st)?;
        let as_tuples = |rs: &[pb::PolicyRule]| -> Vec<(u32, u8, u16, bool)> {
            rs.iter()
                .map(|r| (r.identity, r.proto as u8, r.port as u16, r.deny))
                .collect()
        };
        let rules = as_tuples(&p.rules);
        let egress_rules = as_tuples(&p.egress_rules);
        let l7: Vec<(u16, Vec<crate::l7::L7PolicyRule>)> =
            p.l7.iter()
                .map(|pp| {
                    (
                        pp.port as u16,
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
        self.control
            .set_endpoint_policy(
                ep,
                p.enforce,
                p.enforce_egress,
                p.audit,
                &rules,
                &egress_rules,
                &l7,
            )
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn alloc_ip(
        &self,
        req: Request<pb::AllocIpRequest>,
    ) -> Result<Response<pb::AllocIpReply>, Status> {
        let r = req.into_inner();
        let (ip, prefix_len) = self
            .control
            .cni_alloc_ip(&r.pool, &r.owner)
            .await
            .map_err(st)?;
        // Dual-stack: allocate a v6 too when the request carries a v6 pool.
        let (ip6, prefix_len6) = if r.pool6.is_empty() {
            (String::new(), 0)
        } else {
            let (a, p) = self
                .control
                .cni_alloc_ip6(&r.pool6, &r.owner)
                .await
                .map_err(st)?;
            (a.to_string(), p as u32)
        };
        Ok(Response::new(pb::AllocIpReply {
            ip: ip.to_string(),
            prefix_len: prefix_len as u32,
            ip6,
            prefix_len6,
        }))
    }

    async fn release_ip(
        &self,
        req: Request<pb::ReleaseIpRequest>,
    ) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let ip = if r.ip.is_empty() {
            None
        } else {
            Some(r.ip.parse::<Ipv4Addr>().map_err(st)?)
        };
        self.control
            .cni_release_ip(&r.owner, ip, None)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn create_endpoint(
        &self,
        req: Request<pb::CniEndpoint>,
    ) -> Result<Response<pb::Empty>, Status> {
        let e = req.into_inner();
        let ip = e.ip.parse::<Ipv4Addr>().map_err(st)?;
        let ip6 = if e.ip6.is_empty() {
            None
        } else {
            Some(e.ip6.parse::<Ipv6Addr>().map_err(st)?)
        };
        self.control
            .cni_create_endpoint(
                &e.container_id,
                &e.ifname,
                &e.netns,
                &e.host_if,
                ip,
                ip6,
                e.vrf_id,
                &e.pod_name,
                &e.pod_namespace,
                e.chained,
            )
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn delete_endpoint(
        &self,
        req: Request<pb::CniEndpointKey>,
    ) -> Result<Response<pb::Empty>, Status> {
        let k = req.into_inner();
        self.control
            .cni_delete_endpoint(&k.container_id, &k.ifname)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn list_endpoints(
        &self,
        _req: Request<pb::Empty>,
    ) -> Result<Response<pb::CniEndpointList>, Status> {
        let revs = self.control.policy_revisions_snapshot().await;
        let endpoints = self
            .control
            .cni_list_endpoints()
            .await
            .map_err(st)?
            .into_iter()
            .map(|ep| pb::CniEndpoint {
                policy_revision: revs.get(&ep.host_ifindex).copied().unwrap_or(0),
                container_id: ep.container_id,
                ifname: ep.ifname,
                netns: ep.netns,
                host_if: ep.host_if,
                pod_name: ep.pod_name,
                pod_namespace: ep.pod_namespace,
                chained: ep.chained,
                host_ifindex: ep.host_ifindex,
                ip: ep.ip.to_string(),
                ip6: ep.ip6.map(|v| v.to_string()).unwrap_or_default(),
                vrf_id: ep.vrf_id,
            })
            .collect();
        Ok(Response::new(pb::CniEndpointList { endpoints }))
    }

    async fn add_l7_service(
        &self,
        req: Request<pb::L7Service>,
    ) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let vip: Ipv4Addr = s.vip.parse().map_err(st)?;
        let routes = s
            .routes
            .iter()
            .map(|r| {
                let backend: SocketAddr = format!("{}:{}", r.backend_ip, r.backend_port)
                    .parse()
                    .map_err(st)?;
                Ok(crate::l7::L7Route {
                    prefix: r.path_prefix.clone(),
                    backend,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;
        self.control
            .add_l7_service(vip, s.port as u16, routes)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }
}
