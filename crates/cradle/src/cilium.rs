//! Cilium-agent API compatibility shim (story 2 / M5 of
//! `docs/design/cni-cilium.md`).
//!
//! Serves the subset of the cilium-agent REST API that the stock
//! `cilium-cni` plugin drives, over a unix socket (`--cilium-sock`), so the
//! unmodified Cilium CNI binary can front a cradle node: `GET /healthz`,
//! `GET /config`, `POST /ipam` + `DELETE /ipam/{ip}`, `PUT /endpoint/{id}`,
//! `DELETE /endpoint` (batch, by container-id), and
//! `GET /endpoint/{id}/healthz`. Field names and call flow are pinned to
//! Cilium v1.19.5 (`plugins/cilium-cni/cmd/cmd.go`); the API is stable for
//! all of Cilium 1.x, and unknown request fields are ignored.
//!
//! Datapath mapping: the config advertises `datapathMode: veth` with the
//! node addressing IP set to the ptp gateway 169.254.1.1, so the plugin
//! installs exactly the pod routes cradle-cni would (`gw/32 scope link` +
//! `default via gw`). cilium-cni does the veth plumbing itself and hands us
//! the host interface in `PUT /endpoint`, which maps onto
//! [`Control::cni_create_endpoint`]. One gap needs filling server-side:
//! v1.19.5 installs no ARP entry for the gateway (the real cilium datapath
//! answers ARP in eBPF), so the shim writes the permanent neighbor entry
//! into the pod netns (named via the request's `container-netns-path`).

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use http_body_util::{BodyExt as _, Full};
use hyper::body::{Bytes, Incoming};
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use crate::control::Control;

/// The pods' ptp gateway (must match cradle-cni's convention).
const POD_GW: &str = "169.254.1.1";

struct Api {
    control: Control,
    /// The node pod CIDR the compat IPAM allocates from (cilium-cni sends no
    /// pool of its own).
    pod_cidr: String,
}

/// Serve the compat API until the process exits.
pub async fn serve(control: Control, path: PathBuf, pod_cidr: String) -> Result<()> {
    let _ = std::fs::remove_file(&path); // clear a stale socket
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("binding {}", path.display()))?;
    info!(
        "serving Cilium-compat agent API on unix {} (pod CIDR {pod_cidr})",
        path.display()
    );
    let api = Arc::new(Api { control, pod_cidr });
    loop {
        let (stream, _) = listener.accept().await?;
        let api = api.clone();
        tokio::spawn(async move {
            let io = hyper_util::rt::TokioIo::new(stream);
            let svc = hyper::service::service_fn(move |req| {
                let api = api.clone();
                async move { Ok::<_, std::convert::Infallible>(api.handle(req).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                debug!("cilium API connection: {e}");
            }
        });
    }
}

fn respond(status: StatusCode, body: Value) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static response")
}

/// Minimal percent-decoding (the go-openapi client escapes `:` and `/` in
/// path segments and query values).
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len() + 1
            && i + 2 <= bytes.len() - 1 + 1
            && let (Some(h), Some(l)) = (
                bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16)),
                bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16)),
            )
        {
            out.push((h * 16 + l) as u8);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Extract a query parameter (percent-decoded).
fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    for pair in query.unwrap_or_default().split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            return Some(pct_decode(v));
        }
    }
    None
}

/// `NodeAddressing` advertising the ptp gateway as the node IP — the plugin
/// derives the pod's `gw/32 scope link` + `default via gw` routes from it.
fn host_addressing(pod_cidr: &str) -> Value {
    json!({
        "ipv4": { "enabled": true, "ip": POD_GW, "alloc-range": pod_cidr },
        "ipv6": { "enabled": false },
    })
}

/// Subset of `EndpointChangeRequest` the shim consumes (unknown fields are
/// ignored on purpose — the model is wide and version-dependent).
#[derive(Debug, Deserialize)]
struct EndpointChangeRequest {
    #[serde(rename = "container-id", default)]
    container_id: String,
    #[serde(rename = "container-interface-name", default)]
    container_ifname: String,
    #[serde(rename = "interface-name", default)]
    interface_name: String,
    #[serde(rename = "container-netns-path", default)]
    netns_path: String,
    #[serde(rename = "host-mac", default)]
    host_mac: String,
    #[serde(default)]
    addressing: Option<AddressPair>,
    #[serde(rename = "k8s-namespace", default)]
    k8s_namespace: String,
    #[serde(rename = "k8s-pod-name", default)]
    k8s_pod_name: String,
}

#[derive(Debug, Default, Deserialize)]
struct AddressPair {
    #[serde(default)]
    ipv4: String,
}

#[derive(Debug, Deserialize)]
struct EndpointBatchDeleteRequest {
    #[serde(rename = "container-id", default)]
    container_id: String,
}

impl Api {
    async fn handle(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        let method = req.method().clone();
        let path = pct_decode(req.uri().path());
        let query = req.uri().query().map(String::from);
        let body = match req.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => {
                return respond(
                    StatusCode::BAD_REQUEST,
                    json!(format!("reading request body: {e}")),
                );
            }
        };
        debug!("cilium API {method} {path}");
        let result = match (method.clone(), path.as_str()) {
            (Method::GET, "/healthz") | (Method::GET, "/v1/healthz") => self.healthz(),
            (Method::GET, "/config") | (Method::GET, "/v1/config") => self.config(),
            (Method::POST, "/ipam") | (Method::POST, "/v1/ipam") => {
                self.ipam_allocate(query.as_deref()).await
            }
            (Method::PUT, p) if p.starts_with("/endpoint/") || p.starts_with("/v1/endpoint/") => {
                self.endpoint_create(&body).await
            }
            (Method::DELETE, "/endpoint") | (Method::DELETE, "/v1/endpoint") => {
                self.endpoint_delete_batch(&body).await
            }
            (Method::GET, p) if p.ends_with("/healthz") && p.contains("/endpoint/") => {
                self.endpoint_healthz(p).await
            }
            (Method::DELETE, p) if p.starts_with("/ipam/") || p.starts_with("/v1/ipam/") => {
                let ip = p.rsplit('/').next().unwrap_or_default().to_string();
                self.ipam_release(&ip).await
            }
            _ => {
                warn!("cilium API: unhandled {method} {path}");
                Ok(respond(StatusCode::NOT_FOUND, json!("not found")))
            }
        };
        result.unwrap_or_else(|e| {
            warn!("cilium API {method} {path}: {e:#}");
            respond(StatusCode::INTERNAL_SERVER_ERROR, json!(format!("{e:#}")))
        })
    }

    fn healthz(&self) -> Result<Response<Full<Bytes>>> {
        // models.StatusResponse — every field optional; the plugin only
        // checks the call succeeded.
        Ok(respond(StatusCode::OK, json!({})))
    }

    fn config(&self) -> Result<Response<Full<Bytes>>> {
        // models.DaemonConfiguration. The plugin dereferences Status:
        // ipam-mode (must not be a delegated/cloud mode), datapathMode
        // ("veth" → connector.SetupVeth), addressing (gateway + routes), and
        // deviceMTU (LinkSetMTU runs unconditionally, so it must be sane).
        // GRO/GSO sizes are omitted — zero skips those setters.
        Ok(respond(
            StatusCode::OK,
            json!({
                "spec": {},
                "status": {
                    "datapathMode": "veth",
                    "ipam-mode": "cluster-pool",
                    "deviceMTU": 1500,
                    "routeMTU": 1500,
                    "addressing": host_addressing(&self.pod_cidr),
                    "realized": {},
                },
            }),
        ))
    }

    async fn ipam_allocate(&self, query: Option<&str>) -> Result<Response<Full<Bytes>>> {
        let owner = query_param(query, "owner").unwrap_or_else(|| "cilium".to_string());
        if query_param(query, "family").as_deref() == Some("ipv6") {
            return Ok(respond(
                StatusCode::BAD_GATEWAY, // 502 = allocation failure in the API
                json!("IPv6 allocation not supported"),
            ));
        }
        let (ip, _plen) = self.control.cni_alloc_ip(&self.pod_cidr, &owner).await?;
        info!("cilium API: allocated {ip} for {owner}");
        // models.IPAMResponse — address + host-addressing are required.
        Ok(respond(
            StatusCode::CREATED,
            json!({
                "address": { "ipv4": ip.to_string() },
                "host-addressing": host_addressing(&self.pod_cidr),
                "ipv4": {
                    "ip": ip.to_string(),
                    "cidrs": [self.pod_cidr],
                    "gateway": POD_GW,
                },
            }),
        ))
    }

    async fn ipam_release(&self, ip: &str) -> Result<Response<Full<Bytes>>> {
        let ip: Ipv4Addr = ip.parse().with_context(|| format!("bad ip {ip:?}"))?;
        self.control.cni_release_ip("", Some(ip), None).await?;
        info!("cilium API: released {ip}");
        Ok(respond(StatusCode::OK, json!({})))
    }

    async fn endpoint_create(&self, body: &Bytes) -> Result<Response<Full<Bytes>>> {
        let ecr: EndpointChangeRequest =
            serde_json::from_slice(body).context("parsing EndpointChangeRequest")?;
        let ip: Ipv4Addr = ecr
            .addressing
            .as_ref()
            .map(|a| a.ipv4.as_str())
            .unwrap_or_default()
            .parse()
            .context("EndpointChangeRequest.addressing.ipv4 missing or invalid")?;
        if ecr.container_id.is_empty() || ecr.interface_name.is_empty() {
            anyhow::bail!("EndpointChangeRequest needs container-id and interface-name");
        }
        let ifname = if ecr.container_ifname.is_empty() {
            "eth0"
        } else {
            &ecr.container_ifname
        };
        self.control
            .cni_create_endpoint(
                &ecr.container_id,
                ifname,
                &ecr.netns_path,
                &ecr.interface_name,
                ip,
                None, // the v1.19.5 shim path is v4-only (dual-stack: K-arc follow-on)
                0,
                &ecr.k8s_pod_name,
                &ecr.k8s_namespace,
                false,
            )
            .await?;
        // v1.19.5's cilium-cni installs no ARP entry for the gateway (the
        // real cilium datapath answers ARP in eBPF; kernel proxy_arp would
        // need forwarding enabled) — write the permanent neighbor entry into
        // the pod netns ourselves. Roll the endpoint back on failure so the
        // plugin's error path leaves nothing behind.
        if let Err(e) = self.pod_gateway_neigh(&ecr, ifname).await {
            let _ = self
                .control
                .cni_delete_endpoint(&ecr.container_id, ifname)
                .await;
            return Err(e);
        }
        info!(
            "cilium API: endpoint {}/{} = {ip} via {} (pod {}/{})",
            ecr.container_id, ifname, ecr.interface_name, ecr.k8s_namespace, ecr.k8s_pod_name
        );
        // 201 payload is models.Endpoint; `{}` decodes to an empty object and
        // the plugin nil-checks Status before use.
        Ok(respond(StatusCode::CREATED, json!({})))
    }

    /// Install the pod-side permanent neighbor entry for the ptp gateway.
    /// The pod netns is addressed by the basename of `container-netns-path`
    /// (named netns, which is what container runtimes create).
    async fn pod_gateway_neigh(&self, ecr: &EndpointChangeRequest, ifname: &str) -> Result<()> {
        let ns = ecr
            .netns_path
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty())
            .context("container-netns-path missing (needed for the gateway neighbor entry)")?;
        let mac = if ecr.host_mac.is_empty() {
            std::fs::read_to_string(format!("/sys/class/net/{}/address", ecr.interface_name))
                .with_context(|| format!("reading host MAC of {}", ecr.interface_name))?
                .trim()
                .to_string()
        } else {
            ecr.host_mac.clone()
        };
        let out = tokio::process::Command::new("ip")
            .args([
                "-n",
                ns,
                "neigh",
                "replace",
                POD_GW,
                "lladdr",
                &mac,
                "dev",
                ifname,
                "nud",
                "permanent",
            ])
            .output()
            .await
            .context("running ip -n <ns> neigh replace")?;
        if !out.status.success() {
            anyhow::bail!(
                "installing gateway neighbor in netns {ns}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    async fn endpoint_delete_batch(&self, body: &Bytes) -> Result<Response<Full<Bytes>>> {
        let req: EndpointBatchDeleteRequest =
            serde_json::from_slice(body).context("parsing EndpointBatchDeleteRequest")?;
        let endpoints = self.control.cni_list_endpoints().await?;
        for ep in endpoints
            .into_iter()
            .filter(|ep| ep.container_id == req.container_id)
        {
            self.control
                .cni_delete_endpoint(&ep.container_id, &ep.ifname)
                .await?;
            // The real cilium-agent owns the host veth's lifetime; the plugin
            // only removes the pod end. Mirror that (best-effort — the pair
            // may already be gone with the netns).
            let _ = crate::kernel::del_link(&ep.host_if);
            info!(
                "cilium API: endpoint {}/{} deleted",
                ep.container_id, ep.ifname
            );
        }
        Ok(respond(StatusCode::OK, json!({})))
    }

    /// `GET /endpoint/{id}/healthz` with id `cni-attachment-id:<cid>:<ifname>`.
    async fn endpoint_healthz(&self, path: &str) -> Result<Response<Full<Bytes>>> {
        let id = path
            .trim_start_matches("/v1")
            .trim_start_matches("/endpoint/")
            .trim_end_matches("/healthz");
        let Some(rest) = id.strip_prefix("cni-attachment-id:") else {
            return Ok(respond(StatusCode::NOT_FOUND, json!("unknown endpoint id")));
        };
        let (cid, ifname) = rest.rsplit_once(':').unwrap_or((rest, "eth0"));
        let found = self
            .control
            .cni_list_endpoints()
            .await?
            .iter()
            .any(|ep| ep.container_id == cid && ep.ifname == ifname);
        if found {
            Ok(respond(
                StatusCode::OK,
                json!({ "overallHealth": "OK", "bpf": "OK", "policy": "OK", "connected": true }),
            ))
        } else {
            Ok(respond(StatusCode::NOT_FOUND, json!("endpoint not found")))
        }
    }
}
