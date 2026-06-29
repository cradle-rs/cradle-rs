//! `cradle ctl` — control-plane client. Replays a JSON config to a running
//! cradle over the gRPC control API (the same operations the in-process
//! bootstrap performs, exercised across the wire).

use std::net::SocketAddr;

use anyhow::{Context as _, Result};

use crate::{
    config::{self, Config},
    pb::{self, cradle_client::CradleClient},
    CtlOp,
};

pub async fn run(addr: SocketAddr, op: CtlOp) -> Result<()> {
    let endpoint = format!("http://{addr}");
    let mut client = CradleClient::connect(endpoint)
        .await
        .with_context(|| format!("connecting to {addr}"))?;

    match op {
        CtlOp::Apply { config } => {
            let cfg = Config::load(&config)?;

            for p in &cfg.ports {
                client
                    .set_port(pb::Port {
                        name: p.name.clone(),
                        mac: String::new(),
                        l3: p.l3,
                        vlan: p.vlan as u32,
                    })
                    .await?;
            }
            for (vlan, members) in config::l2_domains(&cfg.ports) {
                client
                    .set_l2_domain(pb::L2Domain {
                        vlan: vlan as u32,
                        members,
                    })
                    .await?;
            }
            for nh in &cfg.nexthops {
                client
                    .set_nexthop(pb::Nexthop {
                        id: nh.id,
                        gateway: nh.gateway.clone().unwrap_or_default(),
                        oif: nh.oif.clone(),
                        oif_index: 0,
                        v6: false,
                    })
                    .await?;
            }
            for n in &cfg.neighbors {
                client
                    .set_neighbor4(pb::Neighbor4 {
                        oif: n.oif.clone(),
                        ip: n.ip.clone(),
                        mac: n.mac.clone(),
                    })
                    .await?;
            }
            for r in &cfg.routes {
                client
                    .add_route4(pb::Route4 {
                        prefix: r.prefix.clone(),
                        nexthop_id: r.nexthop,
                        flags: 0,
                    })
                    .await?;
            }
            for (i, s) in cfg.services.iter().enumerate() {
                client
                    .add_service(pb::Service {
                        svc_id: i as u32 + 1,
                        vip: s.vip.clone(),
                        port: s.port as u32,
                        proto: s.proto.clone(),
                        backends: s
                            .backends
                            .iter()
                            .map(|b| pb::Backend {
                                ip: b.ip.clone(),
                                port: b.port as u32,
                            })
                            .collect(),
                    })
                    .await?;
            }
            println!("applied {} to {addr} via gRPC", config.display());
        }
    }
    Ok(())
}
