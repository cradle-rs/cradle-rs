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
    SRV6_BH_END_X, SRV6_BH_UA, SRV6_BH_UALIB, SRV6_BH_UN, STAT_MAX,
};

/// Validate a wire `behavior` code against the known `SRV6_BH_*` set.
fn srv6_behavior(code: u32) -> Result<u8> {
    match code as u8 {
        b @ (SRV6_BH_END | SRV6_BH_END_X | SRV6_BH_END_DT4 | SRV6_BH_END_DT6 | SRV6_BH_END_DT46
        | SRV6_BH_END_B6 | SRV6_BH_UN | SRV6_BH_UA | SRV6_BH_UALIB | SRV6_BH_END_DT2U
        | SRV6_BH_END_DT2M) => Ok(b),
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
];

/// Shared, cheaply-cloneable handle to the data plane.
#[derive(Clone)]
pub struct Control {
    bpf: Arc<Mutex<Ebpf>>,
    dp: Arc<Mutex<Dataplane>>,
    attached: Arc<Mutex<HashSet<u32>>>,
    /// L7 path-routing table, shared with the transparent proxy task.
    routes: Arc<Mutex<crate::l7::RouteTable>>,
}

impl Control {
    pub fn new(bpf: Ebpf, dp: Dataplane) -> Self {
        Self {
            bpf: Arc::new(Mutex::new(bpf)),
            dp: Arc::new(Mutex::new(dp)),
            attached: Arc::new(Mutex::new(HashSet::new())),
            routes: Arc::new(Mutex::new(crate::l7::RouteTable::default())),
        }
    }

    /// Start the user-space L7 transparent proxy (best-effort; logs and
    /// continues if the transparent bind is unavailable).
    pub async fn start_l7_proxy(&self) {
        if let Err(e) = crate::l7::spawn_proxy(self.routes.clone()).await {
            warn!("L7 proxy disabled: {e:#}");
        }
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

    pub async fn set_nexthop(
        &self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: &str,
        labels: &[u32],
    ) -> Result<()> {
        let oif = util::ifindex_of(oif)?;
        self.set_nexthop_idx(id, gateway, oif, labels).await
    }

    /// Set a nexthop by output ifindex directly (used by control planes such as
    /// zebra-rs that already work in ifindex space).
    pub async fn set_nexthop_idx(
        &self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: u32,
        labels: &[u32],
    ) -> Result<()> {
        self.dp.lock().await.nexthop_set(id, gateway, oif, labels)?;
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
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .nexthop_set_v6(id, gateway, oif, labels)?;
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

    /// Set an SRv6-encap nexthop by ifindex (segment list = `segs`).
    pub async fn set_nexthop_srv6(
        &self,
        id: u32,
        gateway: Option<Ipv6Addr>,
        oif: u32,
        segs: &[Ipv6Addr],
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .nexthop_set_srv6(id, gateway, oif, segs)?;
        Ok(())
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
    ) -> Result<()> {
        self.dp.lock().await.localsid_add(
            sid, prefix_len, behavior, vrf, nexthop_id, block_bits, node_bits,
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
        // A nexthop carrying SRv6 segments imposes an H.Encaps (always v6
        // underlay), regardless of the `v6` flag.
        if !n.segs.is_empty() {
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
                .set_nexthop_srv6(n.id, gw, oif, &segs)
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
                .set_nexthop_idx_v6(n.id, gw, oif, &n.labels)
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
                    .set_nexthop_idx(n.id, gw, n.oif_index, &n.labels)
                    .await
                    .map_err(st)?;
            } else {
                self.control
                    .set_nexthop(n.id, gw, &n.oif, &n.labels)
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
        self.control
            .add_localsid(
                sid,
                prefix_len,
                behavior,
                s.vrf_table_id,
                s.nexthop_id,
                s.lb_bits as u8,
                s.ln_bits as u8,
            )
            .await
            .map_err(st)?;
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
