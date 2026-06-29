//! Control plane — the single implementation behind both the gRPC service and
//! the in-process bootstrap config. It resolves interface names, attaches the
//! datapath to ports on demand, and programs the BPF maps.
//!
//! This is the seam zebra-rs's FibHandle backend will drive: the method surface
//! mirrors `route_*_add/del`, nexthop and neighbor updates, plus L2/L4 setup.

use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::{Context as _, Result};
use aya::{
    programs::{tc, SchedClassifier, TcAttachType},
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
use cradle_common::{PORT_F_L2, PORT_F_L3};

/// Shared, cheaply-cloneable handle to the data plane.
#[derive(Clone)]
pub struct Control {
    bpf: Arc<Mutex<Ebpf>>,
    dp: Arc<Mutex<Dataplane>>,
    attached: Arc<Mutex<HashSet<u32>>>,
}

impl Control {
    pub fn new(bpf: Ebpf, dp: Dataplane) -> Self {
        Self {
            bpf: Arc::new(Mutex::new(bpf)),
            dp: Arc::new(Mutex::new(dp)),
            attached: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    /// Attach the datapath classifier to a port's clsact ingress (idempotent).
    async fn attach(&self, name: &str, ifindex: u32) -> Result<()> {
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
        Ok(())
    }

    pub async fn set_port(&self, name: &str, mac: Option<&str>, l3: bool, vlan: u16) -> Result<()> {
        let ifindex = util::ifindex_of(name)?;
        let mac = match mac {
            Some(m) if !m.is_empty() => util::parse_mac(m)?,
            _ => util::mac_of(name)?,
        };
        let flags = if l3 { PORT_F_L3 } else { PORT_F_L2 };
        self.attach(name, ifindex).await?;
        let mut dp = self.dp.lock().await;
        dp.port_set(ifindex, mac, flags, vlan)?;
        // Routed ports auto-derive their local + connected routes from the
        // kernel, so no manual route/neighbor config is needed.
        if l3 {
            crate::kernel::derive_port(&mut dp, name, ifindex)?;
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

    pub async fn set_nexthop(&self, id: u32, gateway: Option<Ipv4Addr>, oif: &str) -> Result<()> {
        let oif = util::ifindex_of(oif)?;
        self.set_nexthop_idx(id, gateway, oif).await
    }

    /// Set a nexthop by output ifindex directly (used by control planes such as
    /// zebra-rs that already work in ifindex space).
    pub async fn set_nexthop_idx(
        &self,
        id: u32,
        gateway: Option<Ipv4Addr>,
        oif: u32,
    ) -> Result<()> {
        self.dp.lock().await.nexthop_set(id, gateway, oif)?;
        Ok(())
    }

    pub async fn add_route4(
        &self,
        addr: Ipv4Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .route4_add(addr, prefix_len, nexthop_id, flags)?;
        Ok(())
    }

    pub async fn del_route4(&self, addr: Ipv4Addr, prefix_len: u8) -> Result<()> {
        self.dp.lock().await.route4_del(addr, prefix_len)?;
        Ok(())
    }

    pub async fn set_nexthop_idx_v6(
        &self,
        id: u32,
        gateway: Option<Ipv6Addr>,
        oif: u32,
    ) -> Result<()> {
        self.dp.lock().await.nexthop_set_v6(id, gateway, oif)?;
        Ok(())
    }

    pub async fn set_nexthop_group(&self, group_id: u32, members: &[u32]) -> Result<()> {
        self.dp.lock().await.nexthop_group_set(group_id, members)?;
        Ok(())
    }

    pub async fn add_route6(
        &self,
        addr: Ipv6Addr,
        prefix_len: u8,
        nexthop_id: u32,
        flags: u32,
    ) -> Result<()> {
        self.dp
            .lock()
            .await
            .route6_add(addr, prefix_len, nexthop_id, flags)?;
        Ok(())
    }

    pub async fn del_route6(&self, addr: Ipv6Addr, prefix_len: u8) -> Result<()> {
        self.dp.lock().await.route6_del(addr, prefix_len)?;
        Ok(())
    }

    pub async fn set_neighbor4(&self, oif: &str, ip: Ipv4Addr, mac: [u8; 6]) -> Result<()> {
        let oif = util::ifindex_of(oif)?;
        self.dp.lock().await.neigh4_set(oif, ip, mac)?;
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
            .set_port(&p.name, Some(&p.mac), p.l3, p.vlan as u16)
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
        if n.v6 {
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
                .set_nexthop_idx_v6(n.id, gw, oif)
                .await
                .map_err(st)?;
        } else {
            let gw = if n.gateway.is_empty() {
                None
            } else {
                Some(n.gateway.parse::<Ipv4Addr>().map_err(st)?)
            };
            if n.oif_index != 0 {
                self.control
                    .set_nexthop_idx(n.id, gw, n.oif_index)
                    .await
                    .map_err(st)?;
            } else {
                self.control.set_nexthop(n.id, gw, &n.oif).await.map_err(st)?;
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
            .add_route4(addr, len, r.nexthop_id, r.flags)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_route4(&self, req: Request<pb::Route4Del>) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let (addr, len) = util::parse_ipv4_prefix(&r.prefix).map_err(st)?;
        self.control.del_route4(addr, len).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_route6(&self, req: Request<pb::Route6>) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let (addr, len) = util::parse_ipv6_prefix(&r.prefix).map_err(st)?;
        self.control
            .add_route6(addr, len, r.nexthop_id, r.flags)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn del_route6(&self, req: Request<pb::Route6Del>) -> Result<Response<pb::Empty>, Status> {
        let r = req.into_inner();
        let (addr, len) = util::parse_ipv6_prefix(&r.prefix).map_err(st)?;
        self.control.del_route6(addr, len).await.map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn set_neighbor4(
        &self,
        req: Request<pb::Neighbor4>,
    ) -> Result<Response<pb::Empty>, Status> {
        let n = req.into_inner();
        let ip = n.ip.parse().map_err(st)?;
        let mac = util::parse_mac(&n.mac).map_err(st)?;
        self.control
            .set_neighbor4(&n.oif, ip, mac)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }

    async fn add_service(&self, req: Request<pb::Service>) -> Result<Response<pb::Empty>, Status> {
        let s = req.into_inner();
        let vip = s.vip.parse().map_err(st)?;
        let proto = match s.proto.as_str() {
            "tcp" => 6u8,
            "udp" => 17u8,
            other => return Err(Status::invalid_argument(format!("bad proto {other:?}"))),
        };
        let backends = s
            .backends
            .iter()
            .map(|b| Ok((b.ip.parse().map_err(st)?, b.port as u16)))
            .collect::<Result<Vec<_>, Status>>()?;
        self.control
            .add_service(s.svc_id, vip, s.port as u16, proto, &backends)
            .await
            .map_err(st)?;
        Ok(Response::new(pb::Empty {}))
    }
}
