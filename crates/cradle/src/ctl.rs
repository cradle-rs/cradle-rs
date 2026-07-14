//! `cradle ctl` — control-plane client. Replays a JSON config to a running
//! cradle over the gRPC control API (the same operations the in-process
//! bootstrap performs, exercised across the wire).

use anyhow::{Context as _, Result};

use cradle_common::{
    FDB_F_LOCAL, FDB_F_REMOTE, FDB_F_VXLAN, FIB_F_BLACKHOLE, FIB_F_CONNECTED, FIB_F_ECMP,
    FIB_F_LOCAL, NH_F_GTP, NH_F_MPLS, NH_F_ONLINK, NH_F_SRV6, NH_F_V6, NH_F_VXLAN,
};

use crate::{
    CtlOp, DumpTable,
    config::{self, Config},
    grpc::GrpcEndpoint,
    pb::{self, cradle_client::CradleClient},
};

pub async fn run(endpoint: GrpcEndpoint, op: CtlOp) -> Result<()> {
    let uri = endpoint.uri();
    let channel = endpoint.connect().await?;
    let mut client = CradleClient::new(channel);

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
            if let Some(src) = &cfg.vtep_source {
                client
                    .set_vtep_source(pb::VtepSource { addr: src.clone() })
                    .await?;
            }
            for v in &cfg.vnis {
                client
                    .set_vni(pb::Vni {
                        vni: v.vni,
                        vlan: v.vlan as u32,
                        l3: v.l3,
                        vrf: v.vrf,
                        rmac: v.rmac.clone().unwrap_or_default(),
                    })
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
                        vxlan_vtep: nh.vxlan_vtep.clone().unwrap_or_default(),
                        vxlan_l3vni: nh.vxlan_l3vni,
                        vxlan_rmac: nh.vxlan_rmac.clone().unwrap_or_default(),
                        mpls_pipe_ttl: nh.mpls_pipe,
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
                        ttl_uniform: i.ttl_uniform,
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
                                        path: r.path.clone(),
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
        CtlOp::PolicyTrace {
            from,
            to,
            port,
            proto,
            vrf,
        } => {
            let reply = client
                .policy_trace(pb::PolicyTraceRequest {
                    src: from,
                    dst: to,
                    port: port as u32,
                    proto,
                    vrf_id: vrf,
                })
                .await?
                .into_inner();
            for line in reply.lines {
                println!("{line}");
            }
            println!("verdict: {}", reply.verdict);
        }
        CtlOp::PolicySummary => {
            let s = client
                .get_policy_summary(pb::PolicySummaryRequest {})
                .await?
                .into_inner();
            for (name, v) in [
                ("identities", s.identities),
                ("identities6", s.identities6),
                ("cidrs", s.cidrs),
                ("cidrs6", s.cidrs6),
                ("endpoints", s.endpoints),
                ("rules", s.rules),
                ("pct", s.pct),
                ("pct6", s.pct6),
            ] {
                println!("{name:<14} {v}");
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
        CtlOp::DelPort { name } => {
            client.del_port(pb::PortDel { name: name.clone() }).await?;
            println!("deleted port {name}");
        }
        CtlOp::FlushFdb { port, vlan } => {
            client
                .flush_fdb(pb::FdbFlush {
                    port: port.clone(),
                    vlan: vlan as u32,
                })
                .await?;
            println!(
                "flushed learned fdb (port {}, vlan {})",
                if port.is_empty() { "any" } else { &port },
                if vlan == 0 {
                    "any".to_string()
                } else {
                    vlan.to_string()
                },
            );
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
        // Dispatched in main() before the gRPC connect.
        CtlOp::GenRoutesKernel { .. } => unreachable!("handled without a daemon"),
    }
    Ok(())
}

/// `ctl gen-routes-kernel` — write the `gen-routes` table as `ip -batch`
/// lines on stdout (`route add <prefix> via <gw> dev <oif>`), so kernel-mode
/// benchmark baselines carry exactly the prefixes the eBPF FIB does.
pub fn gen_routes_kernel(count: u64, seed: u64, via: std::net::Ipv4Addr, dev: &str) -> Result<()> {
    use std::io::Write as _;
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    for (addr, len) in crate::util::gen_dfz_prefixes(count, seed) {
        writeln!(
            out,
            "route add {}/{} via {} dev {}",
            std::net::Ipv4Addr::from(addr),
            len,
            via,
            dev
        )?;
    }
    out.flush()?;
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

/// `cradle stats` — dump the data-plane packet counters over the gRPC control
/// API, one `name value` per line.
pub async fn run_stats(endpoint: GrpcEndpoint) -> Result<()> {
    let channel = endpoint.connect().await?;
    let mut client = CradleClient::new(channel);
    let reply = client.get_stats(pb::StatsRequest {}).await?.into_inner();
    for e in reply.entries {
        println!("{:<14} {}", e.name, e.packets);
    }
    Ok(())
}

/// `cradle dump <table>` — stream a forwarding table's contents over the gRPC
/// control API and print them in aligned columns.
pub async fn run_dump(
    endpoint: GrpcEndpoint,
    table: DumpTable,
    vrf: u32,
    resolve: bool,
) -> Result<()> {
    let channel = endpoint.connect().await?;
    let mut client = CradleClient::new(channel);
    let pb_table = match table {
        DumpTable::L2 => pb::DumpTable::DumpL2,
        DumpTable::Ipv4 => pb::DumpTable::DumpIpv4,
        DumpTable::Ipv6 => pb::DumpTable::DumpIpv6,
        DumpTable::Mpls => pb::DumpTable::DumpMpls,
        DumpTable::Srv6 => pb::DumpTable::DumpSrv6,
        DumpTable::Nexthop => pb::DumpTable::DumpNexthop,
    };
    let mut stream = client
        .dump(pb::DumpRequest {
            table: pb_table as i32,
            vrf,
            resolve,
        })
        .await?
        .into_inner();

    let mut header = false;
    let mut count = 0u64;
    while let Some(entry) = stream.message().await? {
        let Some(e) = entry.entry else { continue };
        match e {
            pb::dump_entry::Entry::Fdb(f) => {
                if !header {
                    println!(
                        "{:<18} {:>5} {:>8} {:<8} {:>9} remote_sid",
                        "mac", "vlan", "oif", "flags", "age_ms"
                    );
                    header = true;
                }
                println!(
                    "{:<18} {:>5} {:>8} {:<8} {:>9} {}",
                    f.mac,
                    f.vlan,
                    f.oif,
                    fdb_flags(f.flags),
                    f.age_ms,
                    f.remote_sid
                );
            }
            pb::dump_entry::Entry::Fib(r) => {
                if !header {
                    println!(
                        "{:<20} {:>4} {:>7} {:<10} nexthop",
                        "prefix", "vrf", "nh_id", "flags"
                    );
                    header = true;
                }
                println!(
                    "{:<20} {:>4} {:>7} {:<10} {}",
                    r.prefix,
                    r.vrf,
                    r.nexthop_id,
                    fib_flags(r.flags),
                    nh_str(&r.nh)
                );
            }
            pb::dump_entry::Entry::Mpls(m) => {
                if !header {
                    println!(
                        "{:>8} {:<7} {:>7} {:>4} nexthop",
                        "label", "op", "nh_id", "vrf"
                    );
                    header = true;
                }
                println!(
                    "{:>8} {:<7} {:>7} {:>4} {}",
                    m.label,
                    m.op,
                    m.nexthop_id,
                    m.vrf,
                    nh_str(&m.nh)
                );
            }
            pb::dump_entry::Entry::Srv6Localsid(s) => {
                println!(
                    "localsid {}/{:<3} {:<14} flavors={} vrf={} nh_id={} {}",
                    s.sid,
                    s.prefix_len,
                    s.behavior,
                    s.flavors,
                    s.vrf,
                    s.nexthop_id,
                    nh_str(&s.nh)
                );
            }
            pb::dump_entry::Entry::Srv6Encap(en) => {
                println!(
                    "encap    nh_id={} mode={} segs=[{}]",
                    en.nexthop_id,
                    en.mode,
                    en.segs.join(", ")
                );
            }
            pb::dump_entry::Entry::Nexthop(n) => {
                if !header {
                    println!(
                        "{:>7} {:<26} {:>5} {:<14} {:>7} labels",
                        "nh_id", "gateway", "oif", "flags", "backup"
                    );
                    header = true;
                }
                if !n.group.is_empty() {
                    println!("{:>7} group members {:?}", n.id, n.group);
                } else {
                    println!(
                        "{:>7} {:<26} {:>5} {:<14} {:>7} {}",
                        n.id,
                        if n.gateway.is_empty() {
                            "-"
                        } else {
                            n.gateway.as_str()
                        },
                        n.oif,
                        nh_flags(n.flags),
                        n.backup_id,
                        if n.labels.is_empty() {
                            String::new()
                        } else {
                            format!("{:?}", n.labels)
                        },
                    );
                }
            }
        }
        count += 1;
    }
    if count == 0 {
        println!("(empty)");
    }
    Ok(())
}

/// Human-readable `FDB_F_*` flag summary.
fn fdb_flags(flags: u32) -> String {
    let mut v = Vec::new();
    if flags & FDB_F_LOCAL != 0 {
        v.push("local");
    }
    if flags & FDB_F_REMOTE != 0 {
        v.push("remote");
    }
    if flags & FDB_F_VXLAN != 0 {
        v.push("vxlan");
    }
    if v.is_empty() {
        "learned".to_string()
    } else {
        v.join(",")
    }
}

/// Human-readable `FIB_F_*` flag summary.
fn fib_flags(flags: u32) -> String {
    let mut v = Vec::new();
    if flags & FIB_F_BLACKHOLE != 0 {
        v.push("blackhole");
    }
    if flags & FIB_F_LOCAL != 0 {
        v.push("local");
    }
    if flags & FIB_F_CONNECTED != 0 {
        v.push("connected");
    }
    if flags & FIB_F_ECMP != 0 {
        v.push("ecmp");
    }
    if v.is_empty() {
        "-".to_string()
    } else {
        v.join(",")
    }
}

/// Human-readable `NH_F_*` flag summary.
fn nh_flags(flags: u32) -> String {
    let mut v = Vec::new();
    if flags & NH_F_V6 != 0 {
        v.push("v6");
    }
    if flags & NH_F_ONLINK != 0 {
        v.push("onlink");
    }
    if flags & NH_F_MPLS != 0 {
        v.push("mpls");
    }
    if flags & NH_F_SRV6 != 0 {
        v.push("srv6");
    }
    if flags & NH_F_GTP != 0 {
        v.push("gtp");
    }
    if flags & NH_F_VXLAN != 0 {
        v.push("vxlan");
    }
    if v.is_empty() {
        "-".to_string()
    } else {
        v.join(",")
    }
}

/// Format a resolved nexthop (`--resolve`) as `via <gw> dev if<oif> [labels …]`.
fn nh_str(nh: &Option<pb::NexthopInfo>) -> String {
    let Some(n) = nh else {
        return String::new();
    };
    let mut s = String::new();
    if !n.gateway.is_empty() {
        s.push_str(&format!("via {} ", n.gateway));
    }
    s.push_str(&format!("dev if{}", n.oif));
    if !n.labels.is_empty() {
        s.push_str(&format!(" labels {:?}", n.labels));
    }
    s
}
