//! Control plane — the single implementation behind both the gRPC service and
//! the in-process bootstrap config. It resolves interface names, attaches the
//! datapath to ports on demand, and programs the BPF maps.
//!
//! This is the seam zebra-rs's FibHandle backend will drive: the method surface
//! mirrors `route_*_add/del`, nexthop and neighbor updates, plus L2/L4 setup.

use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context as _, Result};
use aya::{
    programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpMode},
    Ebpf,
};
use tokio::sync::Mutex;
use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

use crate::{
    dataplane::Dataplane,
    grpc::GrpcEndpoint,
    pb::{
        self,
        cradle_server::{Cradle, CradleServer},
    },
    util,
};
use cradle_common::{
    MPLS_OP_POP, MPLS_OP_POP_L3, MPLS_OP_SWAP, PORT_F_L2, PORT_F_L3, SRV6_BH_END, SRV6_BH_END_B6,
    SRV6_BH_END_DT2M, SRV6_BH_END_DT2U, SRV6_BH_END_DT4, SRV6_BH_END_DT46, SRV6_BH_END_DT6,
    SRV6_BH_END_DX2, SRV6_BH_END_DX2V, SRV6_BH_END_DX4, SRV6_BH_END_DX6, SRV6_BH_END_M,
    SRV6_BH_END_REP, SRV6_BH_END_T, SRV6_BH_END_X, SRV6_BH_END_X_REP, SRV6_BH_UA, SRV6_BH_UALIB,
    SRV6_BH_UN, STAT_MAX,
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
];

/// A BUM replication slot's veth pair: (A-end name, A ifindex, B ifindex).
type ReplSlot = (String, u32, u32);

/// Shared, cheaply-cloneable handle to the data plane.
#[derive(Clone)]
pub struct Control {
    bpf: Arc<Mutex<Ebpf>>,
    dp: Arc<Mutex<Dataplane>>,
    attached: Arc<Mutex<HashSet<u32>>>,
    /// L7 path-routing table, shared with the transparent proxy task.
    routes: Arc<Mutex<crate::l7::RouteTable>>,
    /// Dynamic BUM replication slots (EVPN Type-3 tee): `(bd, remote DT2M
    /// SID)` → the slot's veth (A-end name, A ifindex, B ifindex). cradle
    /// creates/destroys the pair itself.
    repl_slots: Arc<Mutex<std::collections::HashMap<(u16, Ipv6Addr), ReplSlot>>>,
    /// Monotonic name counter for slot veth pairs (`crs<N>a`/`crs<N>b`).
    repl_next: Arc<std::sync::atomic::AtomicU32>,
}

impl Control {
    pub fn new(bpf: Ebpf, dp: Dataplane) -> Self {
        Self {
            bpf: Arc::new(Mutex::new(bpf)),
            dp: Arc::new(Mutex::new(dp)),
            attached: Arc::new(Mutex::new(HashSet::new())),
            routes: Arc::new(Mutex::new(crate::l7::RouteTable::default())),
            repl_slots: Arc::new(Mutex::new(std::collections::HashMap::new())),
            repl_next: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }
    }

    /// Start the user-space L7 transparent proxy (best-effort; logs and
    /// continues if the transparent bind is unavailable).
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
    async fn attach(&self, name: &str, ifindex: u32, _l3: bool) -> Result<()> {
        let mut attached = self.attached.lock().await;
        if !attached.insert(ifindex) {
            return Ok(());
        }
        let mut bpf = self.bpf.lock().await;
        if let Err(e) = tc::qdisc_add_clsact(name) {
            warn!("qdisc_add_clsact({name}): {e} (continuing; may already exist)");
        }
        let prog: &mut SchedClassifier = bpf
            .program_mut("cradle_tc")
            .context("program cradle_tc not found")?
            .try_into()?;
        prog.attach(name, TcAttachType::Ingress)
            .with_context(|| format!("attaching to {name}"))?;
        info!("attached cradle datapath to {name} (clsact ingress)");
        {
            let xdp: &mut Xdp = bpf
                .program_mut("cradle_xdp")
                .context("program cradle_xdp not found")?
                .try_into()?;
            // Native mode: generic XDP is skipped for TC-redirected skbs
            // (netif_receive_generic_xdp bails on skb_is_redirected), so a
            // frame forwarded by the previous hop's TC stage would bypass a
            // generic-mode pop. veth supports native XDP; fall back to
            // generic (with that caveat) on drivers that don't.
            match xdp.attach(name, XdpMode::Driver) {
                Ok(_) => info!("attached cradle XDP stage to {name} (XDP native)"),
                Err(e) => {
                    warn!(
                        "native XDP attach on {name} failed ({e}); falling back to generic \
                         (frames redirected by an upstream TC hop bypass the pop stage)"
                    );
                    xdp.attach(name, XdpMode::Skb)
                        .with_context(|| format!("attaching XDP MPLS pop to {name}"))?;
                    info!("attached cradle XDP stage to {name} (XDP generic)");
                }
            }
        }
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
        let mut dp = self.dp.lock().await;
        dp.port_set(ifindex, mac, flags, vlan, vrf_id)?;
        // Routed ports auto-derive their local + connected routes from the
        // kernel (into the port's VRF table when bound), so no manual
        // route/neighbor config is needed.
        if l3 {
            crate::kernel::derive_port(&mut dp, name, ifindex, vrf_id)?;
        }
        Ok(())
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
        self.dp
            .lock()
            .await
            .fdb_remote_add(mac, bd, remote_sid, nexthop_id)?;
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

    /// Create a BUM replication slot for `(bd, remote_sid)` with cradle-owned
    /// plumbing (the EVPN Type-3 tee): a fresh veth pair `crs<N>a`/`crs<N>b`,
    /// the A end joined to `bd`'s flood list, the B end XDP-attached, and
    /// `REPL_SID` keyed by both ends. Idempotent per `(bd, remote_sid)`.
    pub async fn add_repl_slot_auto(&self, bd: u16, remote_sid: Ipv6Addr) -> Result<()> {
        let mut slots = self.repl_slots.lock().await;
        if slots.contains_key(&(bd, remote_sid)) {
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
            dp.repl_slot_add(a_idx, b_idx, remote_sid)?;
            dp.l2_member_add(bd, a_idx)?;
        }
        info!("repl slot {a}/{b}: bd {bd} -> {remote_sid}");
        slots.insert((bd, remote_sid), (a, a_idx, b_idx));
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

    pub async fn add_service(
        &self,
        svc_id: u32,
        vip: Ipv4Addr,
        port: u16,
        proto: u8,
        backends: &[(Ipv4Addr, u16)],
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .service_add(svc_id, vip, port, proto, backends)?;
        Ok(())
    }

    pub async fn add_service6(
        &self,
        svc_id: u32,
        vip: Ipv6Addr,
        port: u16,
        proto: u8,
        backends: &[(Ipv6Addr, u16)],
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .service6_add(svc_id, vip, port, proto, backends)?;
        Ok(())
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

    /// Serve the gRPC control API (TCP or unix socket) until Ctrl-C.
    pub async fn serve(self, endpoint: GrpcEndpoint) -> Result<()> {
        let svc = CradleServer::new(GrpcService { control: self });
        let shutdown = async {
            let _ = tokio::signal::ctrl_c().await;
            info!("shutdown signal received");
        };
        match endpoint {
            GrpcEndpoint::Tcp(addr) => {
                info!("serving gRPC control API on tcp {addr}");
                Server::builder()
                    .add_service(svc)
                    .serve_with_shutdown(addr, shutdown)
                    .await?;
            }
            GrpcEndpoint::Uds(path) => {
                let _ = std::fs::remove_file(&path); // clear a stale socket
                info!("serving gRPC control API on unix {}", path.display());
                let uds = tokio::net::UnixListener::bind(&path)
                    .with_context(|| format!("binding {}", path.display()))?;
                let incoming = tokio_stream::wrappers::UnixListenerStream::new(uds);
                Server::builder()
                    .add_service(svc)
                    .serve_with_incoming_shutdown(incoming, shutdown)
                    .await?;
            }
        }
        Ok(())
    }
}

struct GrpcService {
    control: Control,
}

fn st<E: std::fmt::Display>(e: E) -> Status {
    Status::internal(e.to_string())
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

    async fn set_nexthop(&self, req: Request<pb::Nexthop>) -> Result<Response<pb::Empty>, Status> {
        let n = req.into_inner();
        // Nudge the kernel into resolving the gateway's neighbor: cradle
        // owns the forwarding path, so nothing else would ever trigger
        // ND/ARP for it — and the L2-rewrite egress paths need the entry,
        // which the control plane tees back once the kernel learns it. A
        // 0-byte UDP datagram to the discard port is enough; best-effort.
        if !n.gateway.is_empty() {
            if let Ok(gw) = n.gateway.parse::<std::net::IpAddr>() {
                tokio::spawn(async move {
                    let bind = if gw.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                    if let Ok(sock) = tokio::net::UdpSocket::bind(bind).await {
                        let _ = sock.send_to(&[], (gw, 9)).await;
                    }
                });
            }
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

    async fn add_fdb_remote(
        &self,
        req: Request<pb::FdbRemote>,
    ) -> Result<Response<pb::Empty>, Status> {
        let f = req.into_inner();
        let mac = util::parse_mac(&f.mac).map_err(st)?;
        let remote_sid: Ipv6Addr = f.remote_sid.parse().map_err(st)?;
        self.control
            .add_fdb_remote(mac, f.bd as u16, remote_sid, f.nexthop_id)
            .await
            .map_err(st)?;
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
        let sid: Ipv6Addr = r.remote_sid.parse().map_err(st)?;
        self.control
            .add_repl_slot_auto(r.bd as u16, sid)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_repl_slot(
        &self,
        req: Request<pb::ReplSlot>,
    ) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let sid: Ipv6Addr = r.remote_sid.parse().map_err(st)?;
        self.control
            .del_repl_slot_auto(r.bd as u16, sid)
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
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
                    .add_service(s.svc_id, v4, s.port as u16, proto, &backends)
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
                    .add_service6(s.svc_id, v6, s.port as u16, proto, &backends)
                    .await
                    .map_err(st)?;
            }
        }
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
