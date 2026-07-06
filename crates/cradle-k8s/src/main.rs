//! cradle-k8s — the Kubernetes controller for the cradle data plane.
//!
//! Two jobs, both node-local (it runs in the cradle DaemonSet pod):
//!
//! 1. **Service sync**: watch `Service` + `EndpointSlice` and program every
//!    IPv4 ClusterIP with Pod-backed endpoints into the eBPF L4 load balancer
//!    over the cradle gRPC API (`AddService` replaces in place, `DelService`
//!    removes). A periodic full resync re-pushes everything, so a restarted
//!    cradle daemon converges without coordination.
//! 2. **CNI config render**: wait for this Node's `spec.podCIDR` and write
//!    the kubelet CNI conflist (`--write-cni-conf`), after which the node
//!    becomes schedulable for pods — the Cilium-style "agent writes the CNI
//!    config when ready" flow.

mod cep;
mod cnp;
mod identity;
mod netpol;
mod pb;
mod sync;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use clap::Parser;
use futures::StreamExt as _;
use k8s_openapi::api::core::v1::{Node, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use kube::runtime::watcher;
use kube::{Api, Client};
use tokio::sync::Notify;
use tracing::{info, warn};

use pb::cradle_client::CradleClient;
use sync::Desired;

#[derive(Debug, Parser)]
#[command(
    name = "cradle-k8s",
    version,
    about = "Kubernetes Service/CNI controller for cradle"
)]
struct Args {
    /// cradle daemon gRPC endpoint: `unix:/path` or `tcp:host:port`.
    #[arg(long, default_value = "unix:/run/cradle/cradle.sock")]
    grpc: String,
    /// Write the kubelet CNI conflist here once the Node's podCIDR is known.
    #[arg(long)]
    write_cni_conf: Option<PathBuf>,
    /// This node's name (Downward-API `NODE_NAME` in the DaemonSet).
    #[arg(long, env = "NODE_NAME")]
    node_name: Option<String>,
    /// gRPC endpoint to embed in the rendered CNI conf — the path as the
    /// CNI plugin sees it on the host (defaults to --grpc).
    #[arg(long)]
    cni_grpc: Option<String>,
    /// Full-resync period: re-push all services (covers a restarted daemon).
    #[arg(long, default_value_t = 30)]
    resync_secs: u64,
    /// Publish CiliumEndpoint/CiliumNode CRDs for this node's cradle
    /// endpoints (needs the cilium.io/v2 CRDs installed — see deploy/crds/).
    #[arg(long)]
    publish_crds: bool,
    /// Garbage-collect CiliumIdentity CRDs no CiliumEndpoint references
    /// (mark-and-sweep with a grace period). Requires `--publish-crds` for
    /// the cluster-wide CEP in-use set; runs inside that loop.
    #[arg(long)]
    gc_identities: bool,
    /// Translate Kubernetes NetworkPolicies into cradle ingress policy for
    /// this node's endpoints (docs/design/policy.md).
    #[arg(long)]
    enforce_policy: bool,
    /// Policy enforcement mode: `default` = Kubernetes semantics (enforce
    /// only endpoints a policy selects), `always` = default-deny every
    /// endpoint (host allow only when nothing selects it), `never` =
    /// enforcement off (policies still translated but not applied).
    #[arg(long, default_value = "default")]
    policy_enforcement: String,
}

fn connect_uri(ep: &str) -> String {
    if ep.starts_with("unix:") {
        ep.to_string()
    } else {
        format!("http://{}", ep.strip_prefix("tcp:").unwrap_or(ep))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // kube's rustls-tls needs a process-level crypto provider selected.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();

    let client = Client::try_default()
        .await
        .context("connecting to the Kubernetes API (in-cluster config or KUBECONFIG)")?;

    if let Some(path) = args.write_cni_conf.clone() {
        let node = args
            .node_name
            .clone()
            .context("--write-cni-conf needs --node-name (or env NODE_NAME)")?;
        let cni_grpc = args.cni_grpc.clone().unwrap_or_else(|| args.grpc.clone());
        tokio::spawn(render_cni_conf(client.clone(), node, path, cni_grpc));
    }

    if args.publish_crds {
        let node = args
            .node_name
            .clone()
            .context("--publish-crds needs --node-name (or env NODE_NAME)")?;
        tokio::spawn(publish_crds_task(
            client.clone(),
            node,
            args.grpc.clone(),
            args.gc_identities,
        ));
    }

    if args.enforce_policy {
        tokio::spawn(policy_task(
            client.clone(),
            args.grpc.clone(),
            args.policy_enforcement.clone(),
        ));
    }

    service_sync(client, &args.grpc, args.resync_secs, args.node_name.clone()).await
}

/// This node's InternalIP (for NodePort frontends), or None if unknown.
async fn node_internal_ip(client: &Client, node: &Option<String>) -> Option<std::net::Ipv4Addr> {
    let name = node.as_ref()?;
    let nodes: Api<Node> = Api::all(client.clone());
    let n = nodes.get(name).await.ok()?;
    n.status?
        .addresses?
        .iter()
        .find(|a| a.type_ == "InternalIP")
        .and_then(|a| a.address.parse().ok())
}

/// NetworkPolicy enforcement loop: watch Pods/Namespaces/NetworkPolicies and,
/// on any change (plus a periodic tick), push identities + per-endpoint
/// ingress policy for this node's endpoints to the daemon.
async fn policy_task(client: Client, grpc: String, mode: String) {
    use k8s_openapi::api::core::v1::{Namespace, Pod};
    use k8s_openapi::api::networking::v1::NetworkPolicy;

    let pods: Api<Pod> = Api::all(client.clone());
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let policies: Api<NetworkPolicy> = Api::all(client.clone());

    let cid_api = identity::cilium_identity_api(&client);
    let cnp_api = cnp::cnp_api(&client);
    let notify = Arc::new(Notify::new());
    tokio::spawn(watch_notify(pods.clone(), notify.clone()));
    tokio::spawn(watch_notify(policies.clone(), notify.clone()));
    tokio::spawn(watch_notify(namespaces.clone(), notify.clone()));
    notify.notify_one();

    let mut cradle: Option<CradleClient<tonic::transport::Channel>> = None;
    // CIDR bindings pushed last reconcile — removed ones are deleted.
    let mut last_cidrs: Vec<(String, u32)> = Vec::new();
    let mut resync = tokio::time::interval(Duration::from_secs(30));
    resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    resync.tick().await;
    info!("NetworkPolicy enforcement started (cradle at {grpc})");

    loop {
        tokio::select! {
            _ = notify.notified() => {}
            _ = resync.tick() => {}
        }
        tokio::time::sleep(Duration::from_millis(200)).await;

        let lp = kube::api::ListParams::default();
        let (pl, nl, npl) = tokio::join!(pods.list(&lp), namespaces.list(&lp), policies.list(&lp));
        let (pl, nl, npl) = match (pl, nl, npl) {
            (Ok(a), Ok(b), Ok(c)) => (a.items, b.items, c.items),
            _ => {
                warn!("enforce-policy: listing Pods/Namespaces/NetworkPolicies failed");
                continue;
            }
        };
        if cradle.is_none() {
            match CradleClient::connect(connect_uri(&grpc)).await {
                Ok(c) => cradle = Some(c),
                Err(e) => {
                    warn!("enforce-policy: connecting to cradle at {grpc}: {e}");
                    continue;
                }
            }
        }
        // Allocated identities + CNPs — both degrade gracefully when the
        // cilium.io CRDs aren't installed (FNV fallback / no CNP rules).
        let alloc = match identity::ensure_identities(&cid_api, &pl).await {
            Ok(a) => a,
            Err(e) => {
                warn!("identity allocator: {e:#} — FNV fallback");
                identity::Alloc::default()
            }
        };
        let cnps = match cnp_api.list(&lp).await {
            Ok(l) => cnp::parse(&l.items),
            Err(e) => {
                warn!("cnp list: {e} — CiliumNetworkPolicies skipped");
                Vec::new()
            }
        };
        let cl = cradle.as_mut().unwrap();
        // This node's endpoints from the daemon's store.
        let endpoints = match cl.list_endpoints(pb::Empty {}).await {
            Ok(r) => r.into_inner().endpoints,
            Err(e) => {
                warn!("enforce-policy: ListEndpoints: {e}");
                cradle = None;
                continue;
            }
        };
        if let Err(e) = push_policy(
            cl,
            &pl,
            &nl,
            &npl,
            &endpoints,
            &mut last_cidrs,
            &mode,
            &alloc,
            &cnps,
        )
        .await
        {
            warn!("enforce-policy: {e:#}");
            cradle = None;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn push_policy(
    cl: &mut CradleClient<tonic::transport::Channel>,
    pods: &[k8s_openapi::api::core::v1::Pod],
    namespaces: &[k8s_openapi::api::core::v1::Namespace],
    policies: &[k8s_openapi::api::networking::v1::NetworkPolicy],
    endpoints: &[pb::CniEndpoint],
    last_cidrs: &mut Vec<(String, u32)>,
    mode: &str,
    alloc: &identity::Alloc,
    cnps: &[cnp::Cnp],
) -> Result<()> {
    for (ip, id) in netpol::identities(pods, alloc) {
        cl.set_identity(pb::Identity {
            ip,
            identity: id,
            vrf_id: 0,
        })
        .await?;
    }
    // ipBlock CIDR bindings: set the current ones, delete the vanished ones.
    let cidrs = netpol::cidr_bindings(policies);
    for (cidr, id) in &cidrs {
        cl.set_cidr_identity(pb::CidrIdentity {
            cidr: cidr.clone(),
            identity: *id,
            del: false,
            vrf_id: 0,
        })
        .await?;
    }
    for (cidr, id) in last_cidrs.iter() {
        if !cidrs.iter().any(|(c, _)| c == cidr) {
            cl.set_cidr_identity(pb::CidrIdentity {
                cidr: cidr.clone(),
                identity: *id,
                del: true,
                vrf_id: 0,
            })
            .await?;
        }
    }
    *last_cidrs = cidrs;
    for ep in endpoints {
        if ep.pod_name.is_empty() {
            continue;
        }
        let mut policy = netpol::endpoint_policy(ep, policies, pods, namespaces, alloc);
        // CiliumNetworkPolicy rules (incl. deny + entities) merge on top of
        // the NetworkPolicy translation; a CNP-only direction gets the same
        // implicit host allow (kubelet probes).
        let pod_labels = pods
            .iter()
            .find(|p| {
                kube::ResourceExt::namespace(*p).as_deref() == Some(ep.pod_namespace.as_str())
                    && kube::ResourceExt::name_any(*p) == ep.pod_name
            })
            .and_then(|p| p.metadata.labels.clone())
            .unwrap_or_default();
        let (cnp_in, cnp_eg, cnp_any_in, cnp_any_eg, cnp_l7) =
            cnp::endpoint_rules(cnps, &ep.pod_namespace, &pod_labels, pods, alloc);
        policy.l7.extend(cnp_l7);
        let host = pb::PolicyRule {
            identity: netpol::IDENTITY_HOST,
            proto: 0,
            port: 0,
            deny: false,
        };
        if cnp_any_in {
            if !policy.enforce {
                policy.enforce = true;
                policy.rules.push(host);
            }
            policy.rules.extend(cnp_in);
        }
        if cnp_any_eg {
            if !policy.enforce_egress {
                policy.enforce_egress = true;
                policy.egress_rules.push(host);
            }
            policy.egress_rules.extend(cnp_eg);
        }
        match mode {
            // Enforcement off: translated but not applied.
            "never" => {
                policy.enforce = false;
                policy.enforce_egress = false;
                policy.rules.clear();
                policy.egress_rules.clear();
            }
            // Default-deny endpoints nothing selects (host allow only, so
            // kubelet probes keep working).
            "always" if !policy.enforce && !policy.enforce_egress => {
                let host = pb::PolicyRule {
                    identity: netpol::IDENTITY_HOST,
                    proto: 0,
                    port: 0,
                    deny: false,
                };
                policy.enforce = true;
                policy.enforce_egress = true;
                policy.rules = vec![host];
                policy.egress_rules = vec![host];
            }
            _ => {}
        }
        cl.set_endpoint_policy(policy).await?;
    }
    Ok(())
}

/// CRD publication loop: every few seconds, mirror the daemon's endpoint
/// store into CiliumEndpoint objects and keep this node's CiliumNode fresh.
/// Missing CRDs (or an unreachable daemon) warn and retry — publication
/// starts working as soon as both are available.
async fn publish_crds_task(client: Client, node: String, grpc: String, gc_identities: bool) {
    use k8s_openapi::api::core::v1::Pod;
    let nodes: Api<Node> = Api::all(client.clone());
    let pods: Api<Pod> = Api::all(client.clone());
    let cid_api = identity::cilium_identity_api(&client);
    // Consecutive rounds each unreferenced CID has been seen (GC grace).
    let mut gc_strikes: std::collections::HashMap<u32, u32> = Default::default();
    // Grace = 3 rounds (~15s at the 5s tick): a fresh CID survives the lag
    // until its pod's CEP is published.
    const GC_GRACE: u32 = 3;
    let mut cradle: Option<CradleClient<tonic::transport::Channel>> = None;
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    info!("CRD publication started (CiliumEndpoint/CiliumNode for node {node})");
    loop {
        interval.tick().await;
        let (node_ip, pod_cidr) = match nodes.get(&node).await {
            Ok(n) => {
                let ip = n
                    .status
                    .as_ref()
                    .and_then(|s| s.addresses.as_ref())
                    .and_then(|a| a.iter().find(|x| x.type_ == "InternalIP"))
                    .map(|x| x.address.clone())
                    .unwrap_or_default();
                let spec = n.spec.unwrap_or_default();
                let cidr = spec
                    .pod_cidrs
                    .unwrap_or_default()
                    .into_iter()
                    .find(|c| c.contains('.'))
                    .or(spec.pod_cidr.filter(|c| c.contains('.')))
                    .unwrap_or_default();
                (ip, cidr)
            }
            Err(e) => {
                warn!("publish-crds: getting node {node}: {e}");
                continue;
            }
        };
        if cradle.is_none() {
            match CradleClient::connect(connect_uri(&grpc)).await {
                Ok(c) => cradle = Some(c),
                Err(e) => {
                    warn!("publish-crds: connecting to cradle at {grpc}: {e}");
                    continue;
                }
            }
        }
        let endpoints = match cradle.as_mut().unwrap().list_endpoints(pb::Empty {}).await {
            Ok(r) => r.into_inner().endpoints,
            Err(e) => {
                warn!("publish-crds: ListEndpoints: {e}");
                cradle = None;
                continue;
            }
        };
        // Resolve each endpoint's security identity for status.identity —
        // adopt existing CiliumIdentities read-only (the enforce-policy loop
        // owns creation), FNV fallback otherwise. Best-effort: a listing
        // failure just publishes CEPs without the identity field.
        let identities = build_cep_identities(&pods, &cid_api, &endpoints).await;
        if let Err(e) =
            cep::publish(&client, &node, &node_ip, &pod_cidr, &endpoints, &identities).await
        {
            warn!("publish-crds: {e:#} (are the cilium.io CRDs installed?)");
        }

        // Identity GC: sweep CiliumIdentities no CEP references, cluster-wide.
        if gc_identities {
            match (
                identity::all_cid_ids(&cid_api).await,
                cep::in_use_identities(&client).await,
            ) {
                (Ok(cids), Ok(in_use)) => {
                    let (strikes, del) = identity::gc_plan(&cids, &in_use, &gc_strikes, GC_GRACE);
                    gc_strikes = strikes;
                    for id in del {
                        identity::delete_cid(&cid_api, id).await;
                        info!("identity GC: removed unreferenced CiliumIdentity {id}");
                    }
                }
                (a, b) => {
                    if let Err(e) = a {
                        warn!("identity GC: listing CiliumIdentities: {e}");
                    }
                    if let Err(e) = b {
                        warn!("identity GC: listing CiliumEndpoints: {e}");
                    }
                }
            }
        }
    }
}

/// Resolve each Kubernetes endpoint's security identity (id + label list)
/// for `CiliumEndpoint.status.identity`. Read-only against the pods and the
/// CiliumIdentity CRDs; any listing failure yields an empty map (CEPs
/// publish without the identity field rather than failing).
async fn build_cep_identities(
    pods: &Api<k8s_openapi::api::core::v1::Pod>,
    cid_api: &Api<kube::core::DynamicObject>,
    endpoints: &[pb::CniEndpoint],
) -> std::collections::BTreeMap<(String, String), cep::CepIdentity> {
    use kube::ResourceExt as _;
    let Ok(pod_list) = pods.list(&kube::api::ListParams::default()).await else {
        return Default::default();
    };
    let pod_list = pod_list.items;
    let alloc = identity::resolve_only(cid_api, &pod_list)
        .await
        .unwrap_or_default();
    endpoints
        .iter()
        .filter(|ep| !ep.pod_name.is_empty() && !ep.pod_namespace.is_empty())
        .filter_map(|ep| {
            let pod = pod_list.iter().find(|p| {
                p.namespace().as_deref() == Some(ep.pod_namespace.as_str())
                    && p.name_any() == ep.pod_name
            })?;
            let labels = pod.metadata.labels.clone().unwrap_or_default();
            Some((
                (ep.pod_namespace.clone(), ep.pod_name.clone()),
                cep::CepIdentity {
                    id: alloc.resolve(&ep.pod_namespace, &labels),
                    labels: identity::label_list(&ep.pod_namespace, &labels),
                },
            ))
        })
        .collect()
}

/// Watch a resource kind purely as a change signal.
async fn watch_notify<K>(api: Api<K>, notify: Arc<Notify>)
where
    K: kube::Resource + Clone + serde::de::DeserializeOwned + std::fmt::Debug + Send + 'static,
{
    let mut stream = std::pin::pin!(watcher(api, watcher::Config::default()));
    while let Some(ev) = stream.next().await {
        match ev {
            Ok(_) => notify.notify_one(),
            Err(e) => {
                warn!("watch error: {e}");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn service_sync(
    client: Client,
    grpc: &str,
    resync_secs: u64,
    node_name: Option<String>,
) -> Result<()> {
    let services: Api<Service> = Api::all(client.clone());
    let slices: Api<EndpointSlice> = Api::all(client.clone());

    let notify = Arc::new(Notify::new());
    tokio::spawn(watch_notify(services.clone(), notify.clone()));
    tokio::spawn(watch_notify(slices.clone(), notify.clone()));
    notify.notify_one(); // initial reconcile

    let mut programmed = Desired::new();
    let mut cradle: Option<CradleClient<tonic::transport::Channel>> = None;
    let mut resync = tokio::time::interval(Duration::from_secs(resync_secs.max(5)));
    resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    resync.tick().await; // arm (first tick completes immediately)

    info!("service sync started (cradle at {grpc})");
    loop {
        tokio::select! {
            _ = notify.notified() => {}
            _ = resync.tick() => {
                // Forget what we programmed: everything re-pushes, converging
                // a cradle daemon that restarted with empty maps.
                programmed.clear();
            }
        }
        // Coalesce event bursts (a rollout flaps many EndpointSlices).
        tokio::time::sleep(Duration::from_millis(200)).await;

        let lp = kube::api::ListParams::default();
        let (svcs, sls) = tokio::join!(services.list(&lp), slices.list(&lp));
        let (svcs, sls) = match (svcs, sls) {
            (Ok(s), Ok(e)) => (s.items, e.items),
            (s, e) => {
                if let Err(err) = s {
                    warn!("listing services: {err}");
                }
                if let Err(err) = e {
                    warn!("listing endpointslices: {err}");
                }
                continue;
            }
        };
        let node_ip = node_internal_ip(&client, &node_name).await;
        let desired = sync::build_desired(&svcs, &sls, node_ip);
        if let Err(e) = apply(grpc, &mut cradle, &mut programmed, desired).await {
            warn!("programming cradle: {e:#} (will retry on next event/resync)");
            cradle = None; // reconnect next round
        }
    }
}

/// Push the diff between `programmed` and `desired` to the cradle daemon.
async fn apply(
    grpc: &str,
    cradle: &mut Option<CradleClient<tonic::transport::Channel>>,
    programmed: &mut Desired,
    desired: Desired,
) -> Result<()> {
    if cradle.is_none() {
        *cradle = Some(
            CradleClient::connect(connect_uri(grpc))
                .await
                .with_context(|| format!("connecting to cradle at {grpc}"))?,
        );
    }
    let cl = cradle.as_mut().unwrap();

    for (key, svc) in &desired {
        if programmed.get(key) == Some(svc) {
            continue;
        }
        cl.add_service(pb::Service {
            svc_id: sync::svc_id(key),
            vip: key.0.to_string(),
            port: key.1 as u32,
            proto: sync::proto_str(key.2).to_string(),
            affinity: svc.affinity,
            backends: svc
                .backends
                .iter()
                .map(|(ip, port)| pb::Backend {
                    ip: ip.to_string(),
                    port: *port as u32,
                })
                .collect(),
        })
        .await
        .with_context(|| format!("AddService {key:?}"))?;
        info!(
            "service {}:{}/{} -> {} backend(s){}",
            key.0,
            key.1,
            sync::proto_str(key.2),
            svc.backends.len(),
            if svc.affinity { " (ClientIP)" } else { "" }
        );
        programmed.insert(*key, svc.clone());
    }

    let stale: Vec<sync::Key> = programmed
        .keys()
        .filter(|k| !desired.contains_key(*k))
        .copied()
        .collect();
    for key in stale {
        cl.del_service(pb::ServiceDel {
            vip: key.0.to_string(),
            port: key.1 as u32,
            proto: sync::proto_str(key.2).to_string(),
        })
        .await
        .with_context(|| format!("DelService {key:?}"))?;
        info!(
            "service {}:{}/{} removed",
            key.0,
            key.1,
            sync::proto_str(key.2)
        );
        programmed.remove(&key);
    }
    Ok(())
}

/// Wait for the Node's podCIDR and render the kubelet CNI conflist (written
/// atomically; kubelet watches the directory). One-shot: podCIDR is stable
/// for the node's lifetime.
async fn render_cni_conf(client: Client, node: String, path: PathBuf, grpc: String) {
    let nodes: Api<Node> = Api::all(client);
    loop {
        match nodes.get(&node).await {
            Ok(n) => {
                let spec = n.spec.unwrap_or_default();
                let cidrs = spec.pod_cidrs.unwrap_or_default();
                // IPv4 podCIDR (required) + optional IPv6 podCIDR (dual-stack).
                let cidr = cidrs
                    .iter()
                    .find(|c| c.contains('.'))
                    .cloned()
                    .or(spec.pod_cidr.clone().filter(|c| c.contains('.')));
                let cidr6 = cidrs.iter().find(|c| c.contains(':')).cloned();
                // The node InternalIP is the hostPort frontend address.
                let node_ip = n
                    .status
                    .as_ref()
                    .and_then(|s| s.addresses.as_ref())
                    .and_then(|a| a.iter().find(|x| x.type_ == "InternalIP"))
                    .map(|x| x.address.clone())
                    .unwrap_or_default();
                if let Some(cidr) = cidr {
                    let mut ipam = serde_json::json!({ "type": "cradle", "subnet": cidr });
                    if let Some(c6) = &cidr6 {
                        ipam["subnet6"] = serde_json::json!(c6);
                    }
                    let conf = serde_json::json!({
                        "cniVersion": "1.0.0",
                        "name": "cradle",
                        "plugins": [{
                            "type": "cradle-cni",
                            "grpcEndpoint": grpc,
                            "nodeIP": node_ip,
                            "capabilities": { "portMappings": true },
                            "ipam": ipam
                        }]
                    });
                    let tmp = path.with_extension("tmp");
                    let write = std::fs::write(&tmp, format!("{conf:#}"))
                        .and_then(|()| std::fs::rename(&tmp, &path));
                    match write {
                        Ok(()) => {
                            info!(
                                "wrote {} (podCIDR {cidr}{})",
                                path.display(),
                                cidr6.map(|c| format!(" + {c}")).unwrap_or_default()
                            );
                            return;
                        }
                        Err(e) => warn!("writing {}: {e}", path.display()),
                    }
                } else {
                    info!("node {node}: podCIDR not assigned yet");
                }
            }
            Err(e) => warn!("getting node {node}: {e}"),
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
