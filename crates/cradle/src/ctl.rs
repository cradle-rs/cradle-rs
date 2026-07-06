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
                        vrf_id: p.vrf,
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
            if let Some(src) = &cfg.srv6_source {
                client
                    .set_srv6_encap_source(pb::Srv6EncapSource { addr: src.clone() })
                    .await?;
            }
            for nh in &cfg.nexthops {
                client
                    .set_nexthop(pb::Nexthop {
                        id: nh.id,
                        gateway: nh.gateway.clone().unwrap_or_default(),
                        oif: nh.oif.clone().unwrap_or_default(),
                        oif_index: 0,
                        v6: nh
                            .gateway
                            .as_deref()
                            .map(|g| g.contains(':'))
                            .unwrap_or(false),
                        labels: nh.labels.clone(),
                        segs: nh.segs.clone(),
                        encap_mode: nh.encap_mode as u32,
                        backup_id: nh.backup,
                        gtp_src: nh.gtp_src.clone().unwrap_or_default(),
                        gtp_dst: nh.gtp_dst.clone().unwrap_or_default(),
                        gtp_teid: nh.gtp_teid,
                    })
                    .await?;
            }
            for ls in &cfg.localsids {
                client
                    .add_local_sid(pb::LocalSid {
                        sid: ls.sid.clone(),
                        prefix_len: if ls.prefix_len == 0 {
                            128
                        } else {
                            ls.prefix_len as u32
                        },
                        behavior: config::srv6_behavior(&ls.behavior)? as u32,
                        vrf_table_id: ls.vrf,
                        oif: 0,
                        nh6: String::new(),
                        lb_bits: ls.block_bits as u32,
                        ln_bits: ls.node_bits as u32,
                        fun_bits: ls.fun_bits as u32,
                        arg_bits: 0,
                        nexthop_id: ls.nexthop,
                        flavors: config::srv6_flavors(&ls.flavors)? as u32,
                    })
                    .await?;
            }
            for pdr in &cfg.gtp_pdrs {
                client
                    .add_gtp_pdr(pb::GtpPdr {
                        dst: pdr.dst.clone(),
                        teid: pdr.teid,
                        vrf: pdr.vrf,
                    })
                    .await?;
            }
            for n in &cfg.neighbors {
                let is_v6 =
                    n.ip.parse::<std::net::IpAddr>()
                        .map(|ip| ip.is_ipv6())
                        .unwrap_or(false);
                if is_v6 {
                    client
                        .set_neighbor6(pb::Neighbor6 {
                            oif: n.oif.clone(),
                            ip: n.ip.clone(),
                            mac: n.mac.clone(),
                            oif_index: 0,
                        })
                        .await?;
                } else {
                    client
                        .set_neighbor4(pb::Neighbor4 {
                            oif: n.oif.clone(),
                            ip: n.ip.clone(),
                            mac: n.mac.clone(),
                            oif_index: 0,
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
                                vrf_table_id: r.vrf,
                            })
                            .collect(),
                    })
                    .await?;
            }
            for r in &cfg.routes6 {
                client
                    .add_route6(pb::Route6 {
                        prefix: r.prefix.clone(),
                        nexthop_id: r.nexthop,
                        flags: 0,
                        vrf_table_id: r.vrf,
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
                        affinity: s.affinity,
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
            if let Some(node) = &cfg.masq_node {
                client
                    .set_masq_node(pb::MasqNode { node: node.clone() })
                    .await?;
            }
            for cidr in &cfg.non_masq {
                client
                    .set_non_masq(pb::NonMasq {
                        cidr: cidr.clone(),
                        del: false,
                    })
                    .await?;
            }
            for i in &cfg.identities {
                client
                    .set_identity(pb::Identity {
                        ip: i.ip.clone(),
                        identity: i.id,
                        vrf_id: i.vrf,
                    })
                    .await?;
            }
            for c in &cfg.cidr_identities {
                client
                    .set_cidr_identity(pb::CidrIdentity {
                        cidr: c.cidr.clone(),
                        identity: c.id,
                        del: false,
                        vrf_id: c.vrf,
                    })
                    .await?;
            }
            for pol in &cfg.policies {
                let as_rules = |rs: &[config::PolicyRuleCfg]| -> Result<Vec<pb::PolicyRule>> {
                    rs.iter()
                        .map(|r| {
                            Ok(pb::PolicyRule {
                                identity: r.identity,
                                proto: config::rule_proto(&r.proto)? as u32,
                                port: r.port as u32,
                                deny: r.deny,
                            })
                        })
                        .collect()
                };
                client
                    .set_endpoint_policy(pb::EndpointPolicy {
                        host_if: pol.host_if.clone(),
                        pod_namespace: pol.namespace.clone(),
                        pod_name: pol.pod.clone(),
                        enforce: pol.enforce,
                        rules: as_rules(&pol.rules)?,
                        enforce_egress: pol.enforce_egress,
                        egress_rules: as_rules(&pol.egress_rules)?,
                        audit: pol.audit,
                        l7: pol
                            .l7
                            .iter()
                            .map(|pp| pb::L7PortPolicy {
                                port: pp.port as u32,
                                rules: pp
                                    .rules
                                    .iter()
                                    .map(|r| pb::L7Rule {
                                        method: r.method.clone(),
                                        path_prefix: r.path.clone(),
                                    })
                                    .collect(),
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
            client
                .del_route4(pb::Route4Del {
                    prefix: prefix.clone(),
                    vrf_table_id: 0,
                })
                .await?;
            println!("deleted {prefix}");
        }
        CtlOp::DelService { vip, port, proto } => {
            client
                .del_service(pb::ServiceDel {
                    vip: vip.clone(),
                    port: port as u32,
                    proto,
                })
                .await?;
            println!("deleted service {vip}:{port}");
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

/// Generate and bulk-install a synthetic DFZ-shaped route table (see
/// `util::gen_dfz_prefixes` for the distribution), pushed as
/// `AddRoute4Batch` chunks.
async fn gen_routes(
    client: &mut CradleClient<tonic::transport::Channel>,
    count: u64,
    seed: u64,
    nexthop_id: u32,
    chunk: usize,
) -> Result<()> {
    let start = std::time::Instant::now();
    let prefixes = crate::util::gen_dfz_prefixes(count, seed);
    for slice in prefixes.chunks(chunk) {
        client
            .add_route4_batch(pb::Route4Batch {
                routes: slice
                    .iter()
                    .map(|&(addr, len)| pb::Route4 {
                        prefix: format!("{}/{}", std::net::Ipv4Addr::from(addr), len),
                        nexthop_id,
                        flags: 0,
                        vrf_table_id: 0,
                    })
                    .collect(),
            })
            .await?;
    }
    let elapsed = start.elapsed();
    println!(
        "installed {} routes in {:.2?} ({:.0} routes/s)",
        prefixes.len(),
        elapsed,
        prefixes.len() as f64 / elapsed.as_secs_f64()
    );
    Ok(())
}
