//! cradle-cni — Kubernetes CNI plugin (spec 1.1) for the cradle eBPF data
//! plane.
//!
//! The runtime (kubelet via containerd/CRI-O) execs this binary with the
//! operation in `CNI_COMMAND` and the network configuration on stdin. The
//! plugin does the pod-side plumbing itself (it runs in the node's privileged
//! context and receives `CNI_NETNS`): it allocates the pod address over the
//! cradle daemon's gRPC API (`AllocIp`), creates the veth pair, moves and
//! configures the pod end (address, ptp default route via 169.254.1.1 with a
//! permanent neighbor entry for the host veth MAC), then hands the host end
//! to the daemon (`CreateEndpoint`) which registers it as a routed port and
//! programs the pod /32 into the eBPF FIB.
//!
//! Results and errors go to stdout as JSON per the spec; supported verbs are
//! ADD, DEL, CHECK, STATUS, GC, and VERSION.

mod pb;

use std::fmt;
use std::io::Read as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;

use anyhow::{Context as _, Result};
use serde::Deserialize;
use serde_json::{json, Value};

use pb::cradle_client::CradleClient;

/// The pods' virtual point-to-point gateway: link-scoped on every pod's
/// interface, resolved by a permanent neighbor entry to the host veth MAC —
/// no shared L2, no real address consumed (the Cilium/Calico ptp trick).
const POD_GW: &str = "169.254.1.1";

/// The pods' IPv6 ptp gateway: a link-local address on the host veth,
/// resolved by a permanent ND entry — the v6 analogue of `POD_GW`.
const POD_GW6: &str = "fe80::1";

/// CNI error result codes (spec-reserved values).
const ERR_UNSUPPORTED_FIELD: u32 = 2;
const ERR_BAD_ENV: u32 = 4;
const ERR_DECODE: u32 = 6;
const ERR_BAD_CONFIG: u32 = 7;
const ERR_TRANSIENT: u32 = 11;
const ERR_PLUGIN_NOT_AVAILABLE: u32 = 50;
const ERR_INTERNAL: u32 = 100;

/// An error carrying a CNI result code; anything else surfaces as code 100.
#[derive(Debug)]
struct Coded {
    code: u32,
    msg: String,
}

impl fmt::Display for Coded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl std::error::Error for Coded {}

fn coded(code: u32, msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Coded {
        code,
        msg: msg.into(),
    })
}

/// Network configuration from stdin. Beyond the standard keys, cradle-cni
/// takes `grpcEndpoint` (the daemon's control socket) and reads the pod CIDR
/// from `ipam.subnet` (IPAM itself lives in the daemon, not a delegated
/// plugin binary).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetConf {
    #[serde(default = "default_cni_version")]
    cni_version: String,
    #[serde(default)]
    #[allow(dead_code)]
    name: String,
    #[serde(default = "default_grpc_endpoint")]
    grpc_endpoint: String,
    #[serde(default)]
    ipam: IpamConf,
    /// VRF table pod endpoints join (0 = global).
    #[serde(default)]
    vrf: u32,
    /// Chained deployment (e.g. Cilium generic-veth after cradle-cni in the
    /// conflist): cradle does IPAM/veth/routes but leaves the veth TC hook
    /// to the chained plugin.
    #[serde(default)]
    chained: bool,
    /// GC input: attachments the runtime still considers valid.
    #[serde(rename = "cni.dev/valid-attachments", default)]
    valid_attachments: Vec<Attachment>,
}

fn default_cni_version() -> String {
    "1.1.0".to_string()
}

fn default_grpc_endpoint() -> String {
    "unix:/run/cradle/cradle.sock".to_string()
}

#[derive(Debug, Default, Deserialize)]
struct IpamConf {
    #[serde(rename = "type", default)]
    #[allow(dead_code)]
    plugin_type: String,
    #[serde(default)]
    subnet: String,
    /// Optional pod IPv6 CIDR — set for a dual-stack pod.
    #[serde(default)]
    subnet6: String,
}

#[derive(Debug, Deserialize)]
struct Attachment {
    #[serde(rename = "containerID")]
    container_id: String,
    #[serde(default)]
    ifname: String,
}

/// The CNI_* environment for attachment operations.
struct CniEnv {
    container_id: String,
    netns: String,
    ifname: String,
    /// Kubernetes pod identity from CNI_ARGS (`K8S_POD_NAME` /
    /// `K8S_POD_NAMESPACE`, set by kubelet); empty outside Kubernetes.
    pod_name: String,
    pod_namespace: String,
}

/// Extract one `KEY=VAL` from the `;`-separated CNI_ARGS.
fn cni_arg(args: &str, key: &str) -> String {
    args.split(';')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
        .unwrap_or_default()
}

fn require_env(name: &str) -> Result<String> {
    match std::env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(coded(ERR_BAD_ENV, format!("required env {name} missing"))),
    }
}

impl CniEnv {
    fn load(netns_required: bool) -> Result<Self> {
        let args = std::env::var("CNI_ARGS").unwrap_or_default();
        Ok(Self {
            container_id: require_env("CNI_CONTAINERID")?,
            netns: if netns_required {
                require_env("CNI_NETNS")?
            } else {
                std::env::var("CNI_NETNS").unwrap_or_default()
            },
            ifname: require_env("CNI_IFNAME")?,
            pod_name: cni_arg(&args, "K8S_POD_NAME"),
            pod_namespace: cni_arg(&args, "K8S_POD_NAMESPACE"),
        })
    }
}

/// FNV-1a 64-bit, for deriving deterministic interface names.
fn fnv1a64(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        hash ^= *b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Deterministic host-side veth name for an attachment: `crdl` + 10 hex chars
/// (14 chars, under IFNAMSIZ). Recomputable on DEL, so the plugin needs no
/// local state.
fn host_ifname(container_id: &str, ifname: &str) -> String {
    format!(
        "crdl{:010x}",
        fnv1a64(&format!("{container_id}/{ifname}")) & 0xff_ffff_ffff
    )
}

/// Resolve a CNI_NETNS path to an iproute2 netns name. Container runtimes
/// (and `ip netns add`) mount named namespaces under /run/netns.
fn netns_name(path: &str) -> Result<String> {
    for prefix in ["/var/run/netns/", "/run/netns/"] {
        if let Some(name) = path.strip_prefix(prefix) {
            if !name.is_empty() && !name.contains('/') {
                return Ok(name.to_string());
            }
        }
    }
    Err(coded(
        ERR_UNSUPPORTED_FIELD,
        format!("unsupported CNI_NETNS path {path:?} (need a named netns under /run/netns)"),
    ))
}

/// Run `ip` with `args`, failing with its stderr.
fn ip(args: &[&str]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("running `ip {}`", args.join(" ")))?;
    if !out.status.success() {
        anyhow::bail!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Read an interface's MAC address inside a netns via `ip -n <ns> link show`.
fn mac_in_ns(ns: &str, ifname: &str) -> Result<String> {
    let out = Command::new("ip")
        .args(["-n", ns, "-o", "link", "show", ifname])
        .output()
        .with_context(|| format!("running `ip -n {ns} link show {ifname}`"))?;
    if !out.status.success() {
        anyhow::bail!(
            "`ip -n {ns} link show {ifname}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut tokens = text.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "link/ether" {
            if let Some(mac) = tokens.next() {
                return Ok(mac.to_string());
            }
        }
    }
    anyhow::bail!("no link/ether in `ip -n {ns} link show {ifname}` output")
}

fn host_mac(ifname: &str) -> Result<String> {
    let s = std::fs::read_to_string(format!("/sys/class/net/{ifname}/address"))
        .with_context(|| format!("reading /sys/class/net/{ifname}/address"))?;
    Ok(s.trim().to_string())
}

/// Connect to the cradle daemon. `unix:/path` or `tcp:host:port` / bare
/// `host:port` (mirrors the daemon's `GrpcEndpoint`).
async fn client(conf: &NetConf) -> Result<CradleClient<tonic::transport::Channel>> {
    let ep = &conf.grpc_endpoint;
    let uri = if ep.starts_with("unix:") {
        ep.clone()
    } else {
        format!("http://{}", ep.strip_prefix("tcp:").unwrap_or(ep))
    };
    CradleClient::connect(uri).await.map_err(|e| {
        coded(
            ERR_TRANSIENT,
            format!("cradle daemon unreachable at {ep}: {e}"),
        )
    })
}

fn read_stdin() -> String {
    let mut buf = String::new();
    let _ = std::io::stdin().read_to_string(&mut buf);
    buf
}

fn parse_conf(stdin: &str) -> Result<NetConf> {
    serde_json::from_str(stdin)
        .map_err(|e| coded(ERR_DECODE, format!("bad network configuration: {e}")))
}

async fn cmd_add(env: &CniEnv, conf: &NetConf) -> Result<Value> {
    if conf.ipam.subnet.is_empty() {
        return Err(coded(ERR_BAD_CONFIG, "ipam.subnet missing (pod CIDR)"));
    }
    let ns = netns_name(&env.netns)?;
    let owner = format!("{}/{}", env.container_id, env.ifname);
    let mut cl = client(conf).await?;
    let reply = cl
        .alloc_ip(pb::AllocIpRequest {
            pool: conf.ipam.subnet.clone(),
            owner: owner.clone(),
            pool6: conf.ipam.subnet6.clone(),
        })
        .await
        .map_err(|e| coded(ERR_INTERNAL, format!("AllocIp failed: {}", e.message())))?
        .into_inner();
    let pod_ip: Ipv4Addr = reply.ip.parse().map_err(|e| {
        coded(
            ERR_INTERNAL,
            format!("bad allocated ip {:?}: {e}", reply.ip),
        )
    })?;
    let pod_ip6: Option<Ipv6Addr> = if reply.ip6.is_empty() {
        None
    } else {
        Some(reply.ip6.parse().map_err(|e| {
            coded(
                ERR_INTERNAL,
                format!("bad allocated ip6 {:?}: {e}", reply.ip6),
            )
        })?)
    };

    match plumb(env, conf, &ns, pod_ip, pod_ip6, &mut cl).await {
        Ok(result) => Ok(result),
        Err(e) => {
            // Roll back so a failed ADD leaves nothing behind: the runtime is
            // not obliged to DEL an attachment whose ADD errored.
            let _ = Command::new("ip")
                .args(["link", "del", &host_ifname(&env.container_id, &env.ifname)])
                .output();
            let _ = cl
                .release_ip(pb::ReleaseIpRequest {
                    owner,
                    ip: pod_ip.to_string(),
                })
                .await;
            Err(e)
        }
    }
}

/// Create + configure the veth pair, then register the endpoint with the
/// daemon. Split from `cmd_add` so failures roll the allocation back.
async fn plumb(
    env: &CniEnv,
    conf: &NetConf,
    ns: &str,
    pod_ip: Ipv4Addr,
    pod_ip6: Option<Ipv6Addr>,
    cl: &mut CradleClient<tonic::transport::Channel>,
) -> Result<Value> {
    let host_if = host_ifname(&env.container_id, &env.ifname);
    let tmp = format!("tmp{:010x}", fnv1a64(&host_if) & 0xff_ffff_ffff);

    // A retried ADD after a crash may find the stale pair; recreate it.
    let _ = Command::new("ip").args(["link", "del", &host_if]).output();
    ip(&[
        "link", "add", &host_if, "type", "veth", "peer", "name", &tmp,
    ])?;
    // Move + rename in one step; fails (correctly) if CNI_IFNAME already
    // exists in the pod.
    ip(&["link", "set", &tmp, "netns", ns, "name", &env.ifname])?;
    ip(&["link", "set", &host_if, "up"])?;

    let pod_addr = format!("{pod_ip}/32");
    ip(&["-n", ns, "link", "set", "lo", "up"])?;
    ip(&["-n", ns, "addr", "add", &pod_addr, "dev", &env.ifname])?;
    ip(&["-n", ns, "link", "set", &env.ifname, "up"])?;
    let gw_route = format!("{POD_GW}/32");
    ip(&[
        "-n",
        ns,
        "route",
        "add",
        &gw_route,
        "dev",
        &env.ifname,
        "scope",
        "link",
    ])?;
    ip(&[
        "-n",
        ns,
        "route",
        "add",
        "default",
        "via",
        POD_GW,
        "dev",
        &env.ifname,
    ])?;
    let hmac = host_mac(&host_if)?;
    ip(&[
        "-n",
        ns,
        "neigh",
        "replace",
        POD_GW,
        "lladdr",
        &hmac,
        "dev",
        &env.ifname,
        "nud",
        "permanent",
    ])?;

    // Dual-stack: mirror the ptp setup for v6. `fe80::1` is link-local, so
    // the pod's default v6 route is via the gateway on-link, resolved by a
    // permanent ND entry to the host veth MAC.
    let pod_addr6 = pod_ip6.map(|ip6| format!("{ip6}/128"));
    if let Some(addr6) = &pod_addr6 {
        // `nodad` avoids DAD delay on the /128; the host veth needs a
        // link-local so the pod can resolve the gateway.
        ip(&["-n", ns, "addr", "add", addr6, "dev", &env.ifname, "nodad"])?;
        ip(&["-n", ns, "route", "add", POD_GW6, "dev", &env.ifname])?;
        ip(&[
            "-n",
            ns,
            "route",
            "add",
            "default",
            "via",
            POD_GW6,
            "dev",
            &env.ifname,
        ])?;
        ip(&[
            "-n",
            ns,
            "neigh",
            "replace",
            POD_GW6,
            "lladdr",
            &hmac,
            "dev",
            &env.ifname,
            "nud",
            "permanent",
        ])?;
    }

    cl.create_endpoint(pb::CniEndpoint {
        container_id: env.container_id.clone(),
        ifname: env.ifname.clone(),
        netns: env.netns.clone(),
        host_if: host_if.clone(),
        host_ifindex: 0,
        ip: pod_ip.to_string(),
        ip6: pod_ip6.map(|v| v.to_string()).unwrap_or_default(),
        vrf_id: conf.vrf,
        pod_name: env.pod_name.clone(),
        pod_namespace: env.pod_namespace.clone(),
        chained: conf.chained,
    })
    .await
    .map_err(|e| {
        coded(
            ERR_INTERNAL,
            format!("CreateEndpoint failed: {}", e.message()),
        )
    })?;

    let pod_mac = mac_in_ns(ns, &env.ifname)?;
    let mut ips = vec![json!({ "address": pod_addr, "gateway": POD_GW, "interface": 1 })];
    let mut routes = vec![json!({ "dst": "0.0.0.0/0", "gw": POD_GW })];
    if let Some(addr6) = pod_addr6 {
        ips.push(json!({ "address": addr6, "gateway": POD_GW6, "interface": 1 }));
        routes.push(json!({ "dst": "::/0", "gw": POD_GW6 }));
    }
    Ok(json!({
        "cniVersion": conf.cni_version,
        "interfaces": [
            { "name": host_if, "mac": hmac },
            { "name": env.ifname, "mac": pod_mac, "sandbox": env.netns },
        ],
        "ips": ips,
        "routes": routes,
        "dns": {},
    }))
}

async fn cmd_del(env: &CniEnv, conf: &NetConf) -> Result<()> {
    // Unprogram the datapath first (the daemon is normally still up during
    // pod teardown); an unreachable daemon must not fail the DEL — the veth
    // still comes down, and GC reconciles the rest later.
    if let Ok(mut cl) = client(conf).await {
        let _ = cl
            .delete_endpoint(pb::CniEndpointKey {
                container_id: env.container_id.clone(),
                ifname: env.ifname.clone(),
            })
            .await;
    }
    // Deleting the host end removes the pair wherever the peer lives.
    let _ = Command::new("ip")
        .args(["link", "del", &host_ifname(&env.container_id, &env.ifname)])
        .output();
    Ok(())
}

async fn cmd_check(env: &CniEnv, conf: &NetConf) -> Result<()> {
    let mut cl = client(conf).await?;
    let endpoints = cl
        .list_endpoints(pb::Empty {})
        .await
        .map_err(|e| {
            coded(
                ERR_INTERNAL,
                format!("ListEndpoints failed: {}", e.message()),
            )
        })?
        .into_inner()
        .endpoints;
    let Some(ep) = endpoints
        .iter()
        .find(|e| e.container_id == env.container_id && e.ifname == env.ifname)
    else {
        return Err(coded(
            ERR_INTERNAL,
            format!("no endpoint for {}/{}", env.container_id, env.ifname),
        ));
    };
    if !std::path::Path::new(&format!("/sys/class/net/{}", ep.host_if)).exists() {
        return Err(coded(
            ERR_INTERNAL,
            format!("host interface {} missing", ep.host_if),
        ));
    }
    Ok(())
}

async fn cmd_status(conf: &NetConf) -> Result<()> {
    let mut cl = client(conf)
        .await
        .map_err(|_| coded(ERR_PLUGIN_NOT_AVAILABLE, "cradle daemon unreachable"))?;
    cl.get_stats(pb::StatsRequest {}).await.map_err(|e| {
        coded(
            ERR_PLUGIN_NOT_AVAILABLE,
            format!("cradle daemon unhealthy: {e}"),
        )
    })?;
    Ok(())
}

async fn cmd_gc(conf: &NetConf) -> Result<()> {
    let mut cl = client(conf).await?;
    let endpoints = cl
        .list_endpoints(pb::Empty {})
        .await
        .map_err(|e| {
            coded(
                ERR_INTERNAL,
                format!("ListEndpoints failed: {}", e.message()),
            )
        })?
        .into_inner()
        .endpoints;
    for ep in endpoints {
        let valid = conf.valid_attachments.iter().any(|a| {
            a.container_id == ep.container_id && (a.ifname.is_empty() || a.ifname == ep.ifname)
        });
        if valid {
            continue;
        }
        let _ = cl
            .delete_endpoint(pb::CniEndpointKey {
                container_id: ep.container_id.clone(),
                ifname: ep.ifname.clone(),
            })
            .await;
        let _ = Command::new("ip")
            .args(["link", "del", &ep.host_if])
            .output();
    }
    Ok(())
}

async fn run(command: &str, stdin: &str) -> Result<Option<Value>> {
    match command {
        "VERSION" => {
            // Echo the input's cniVersion when parseable, per the spec.
            let v = serde_json::from_str::<Value>(stdin)
                .ok()
                .and_then(|c| {
                    c.get("cniVersion")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .unwrap_or_else(default_cni_version);
            Ok(Some(json!({
                "cniVersion": v,
                "supportedVersions": ["1.0.0", "1.1.0"],
            })))
        }
        "ADD" => {
            let conf = parse_conf(stdin)?;
            let env = CniEnv::load(true)?;
            cmd_add(&env, &conf).await.map(Some)
        }
        "DEL" => {
            let conf = parse_conf(stdin)?;
            let env = CniEnv::load(false)?;
            cmd_del(&env, &conf).await.map(|_| None)
        }
        "CHECK" => {
            let conf = parse_conf(stdin)?;
            let env = CniEnv::load(true)?;
            cmd_check(&env, &conf).await.map(|_| None)
        }
        "STATUS" => {
            let conf = parse_conf(stdin)?;
            cmd_status(&conf).await.map(|_| None)
        }
        "GC" => {
            let conf = parse_conf(stdin)?;
            cmd_gc(&conf).await.map(|_| None)
        }
        other => Err(coded(ERR_BAD_ENV, format!("unknown CNI_COMMAND {other:?}"))),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let command = std::env::var("CNI_COMMAND").unwrap_or_default();
    let stdin = read_stdin();
    match run(&command, &stdin).await {
        Ok(Some(result)) => println!("{result}"),
        Ok(None) => {}
        Err(e) => {
            let (code, msg) = match e.downcast_ref::<Coded>() {
                Some(c) => (c.code, c.msg.clone()),
                None => (ERR_INTERNAL, "internal error".to_string()),
            };
            let version = serde_json::from_str::<Value>(&stdin)
                .ok()
                .and_then(|c| {
                    c.get("cniVersion")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .unwrap_or_else(default_cni_version);
            println!(
                "{}",
                json!({
                    "cniVersion": version,
                    "code": code,
                    "msg": msg,
                    "details": format!("{e:#}"),
                })
            );
            std::process::exit(1);
        }
    }
}
