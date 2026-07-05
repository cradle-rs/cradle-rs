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

    service_sync(client, &args.grpc, args.resync_secs).await
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

async fn service_sync(client: Client, grpc: &str, resync_secs: u64) -> Result<()> {
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
        let desired = sync::build_desired(&svcs, &sls);
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

    for (key, backends) in &desired {
        if programmed.get(key) == Some(backends) {
            continue;
        }
        cl.add_service(pb::Service {
            svc_id: sync::svc_id(key),
            vip: key.0.to_string(),
            port: key.1 as u32,
            proto: sync::proto_str(key.2).to_string(),
            backends: backends
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
            "service {}:{}/{} -> {} backend(s)",
            key.0,
            key.1,
            sync::proto_str(key.2),
            backends.len()
        );
        programmed.insert(*key, backends.clone());
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
                // Prefer the IPv4 entry of podCIDRs (dual-stack nodes).
                let cidr = spec
                    .pod_cidrs
                    .unwrap_or_default()
                    .into_iter()
                    .find(|c| c.contains('.'))
                    .or(spec.pod_cidr.filter(|c| c.contains('.')));
                if let Some(cidr) = cidr {
                    let conf = serde_json::json!({
                        "cniVersion": "1.0.0",
                        "name": "cradle",
                        "plugins": [{
                            "type": "cradle-cni",
                            "grpcEndpoint": grpc,
                            "ipam": { "type": "cradle", "subnet": cidr }
                        }]
                    });
                    let tmp = path.with_extension("tmp");
                    let write = std::fs::write(&tmp, format!("{conf:#}"))
                        .and_then(|()| std::fs::rename(&tmp, &path));
                    match write {
                        Ok(()) => {
                            info!("wrote {} (podCIDR {cidr})", path.display());
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
