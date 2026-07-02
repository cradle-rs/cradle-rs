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
            if !cfg.routes.is_empty() {
                client
                    .add_route4_batch(pb::Route4Batch {
                        routes: cfg
                            .routes
                            .iter()
                            .map(|r| pb::Route4 {
                                prefix: r.prefix.clone(),
                                nexthop_id: r.nexthop,
                                flags: 0,
                            })
                            .collect(),
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
        CtlOp::Fib => {
            let s = client
                .get_fib_summary(pb::FibSummaryRequest {})
                .await?
                .into_inner();
            println!("{:<14} {}", "fib4_mode", s.fib4_mode);
            println!("{:<14} {}", "routes4", s.routes4);
            println!("{:<14} {}", "tbl8_used", s.tbl8_used);
            println!("{:<14} {}", "tbl8_free", s.tbl8_free);
        }
        CtlOp::DelRoute { prefix } => {
            client.del_route4(pb::Route4Del { prefix: prefix.clone() }).await?;
            println!("deleted {prefix}");
        }
        CtlOp::GenRoutes {
            count,
            seed,
            nexthop_id,
            chunk,
        } => {
            gen_routes(&mut client, count, seed, nexthop_id, chunk).await?;
        }
    }
    Ok(())
}

/// Generate and bulk-install a synthetic route table with a DFZ-like
/// prefix-length distribution (deterministic per seed). Addresses are spread
/// over 20.0.0.0–89.255.255.255 — away from the RFC1918 space the tests use
/// and from 99.0.0.0/8, which the BDD reserves for its DEFAULT4 probe; only
/// lengths /16../24 are emitted (a real DFZ propagates almost nothing longer
/// than /24, and shorter-than-/16 expansion is a Phase 3 churn topic).
async fn gen_routes(
    client: &mut CradleClient<tonic::transport::Channel>,
    count: u64,
    seed: u64,
    nexthop_id: u32,
    chunk: usize,
) -> Result<()> {
    // Cumulative per-mille weights, roughly the public-DFZ histogram.
    const LENS: [(u8, u32); 9] = [
        (24, 620),
        (23, 740),
        (22, 860),
        (21, 920),
        (20, 960),
        (19, 985),
        (18, 995),
        (17, 998),
        (16, 1000),
    ];
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    let mut rng = seed;
    let mut seen: std::collections::HashSet<(u32, u8)> = std::collections::HashSet::new();
    let start = std::time::Instant::now();
    let mut batch: Vec<pb::Route4> = Vec::with_capacity(chunk);
    while (seen.len() as u64) < count {
        batch.clear();
        while batch.len() < chunk && (seen.len() as u64) < count {
            let r = splitmix64(&mut rng);
            let dice = (r % 1000) as u32;
            let len = LENS.iter().find(|&&(_, cum)| dice < cum).unwrap().0;
            let mask = u32::MAX << (32 - len as u32);
            let addr = (((20 + (r >> 10) % 70) as u32) << 24 | (r >> 17) as u32 & 0x00ff_ffff)
                & mask;
            if !seen.insert((addr, len)) {
                continue;
            }
            batch.push(pb::Route4 {
                prefix: format!("{}/{}", std::net::Ipv4Addr::from(addr), len),
                nexthop_id,
                flags: 0,
            });
        }
        client
            .add_route4_batch(pb::Route4Batch {
                routes: batch.clone(),
            })
            .await?;
    }
    let elapsed = start.elapsed();
    println!(
        "installed {} routes in {:.2?} ({:.0} routes/s)",
        seen.len(),
        elapsed,
        seen.len() as f64 / elapsed.as_secs_f64()
    );
    Ok(())
}
