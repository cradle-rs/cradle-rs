//! `cradle ctl` — control-plane client. Replays a JSON config to a running
//! cradle over the gRPC control API (the same operations the in-process
//! bootstrap performs, exercised across the wire).

use anyhow::{Context as _, Result};

use crate::{
    config::{self, Config},
    grpc::GrpcEndpoint,
    pb::{self, cradle_client::CradleClient},
    CtlOp,
};

pub async fn run(endpoint: GrpcEndpoint, op: CtlOp) -> Result<()> {
    let uri = endpoint.connect_uri();
    let mut client = CradleClient::connect(uri.clone())
        .await
        .with_context(|| format!("connecting to {uri}"))?;

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
                        labels: nh.labels.clone(),
                    })
                    .await?;
            }
            for n in &cfg.neighbors {
                let is_v6 = n.ip.parse::<std::net::IpAddr>().map(|ip| ip.is_ipv6()).unwrap_or(false);
                if is_v6 {
                    client
                        .set_neighbor6(pb::Neighbor6 {
                            oif: n.oif.clone(),
                            ip: n.ip.clone(),
                            mac: n.mac.clone(),
                        })
                        .await?;
                } else {
                    client
                        .set_neighbor4(pb::Neighbor4 {
                            oif: n.oif.clone(),
                            ip: n.ip.clone(),
                            mac: n.mac.clone(),
                        })
                        .await?;
                }
            }
            for i in &cfg.ilm {
                let op = config::ilm_action(&i.action)?;
                client
                    .add_ilm(pb::Ilm {
                        in_label: i.in_label,
                        nexthop_id: i.nexthop,
                        action: op as u32,
                        vrf_table_id: i.vrf,
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
            for s in &cfg.l7_services {
                let routes = s
                    .routes
                    .iter()
                    .map(|r| {
                        let sa: std::net::SocketAddr = r
                            .backend
                            .parse()
                            .with_context(|| format!("bad L7 backend {:?}", r.backend))?;
                        Ok(pb::L7Route {
                            path_prefix: r.prefix.clone(),
                            backend_ip: sa.ip().to_string(),
                            backend_port: sa.port() as u32,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                client
                    .add_l7_service(pb::L7Service {
                        vip: s.vip.clone(),
                        port: s.port as u32,
                        routes,
                    })
                    .await?;
            }
            println!("applied {} to {uri} via gRPC", config.display());
        }
        CtlOp::Stats => {
            let reply = client.get_stats(pb::StatsRequest {}).await?.into_inner();
            for e in reply.entries {
                println!("{:<14} {}", e.name, e.packets);
            }
        }
    }
    Ok(())
}
