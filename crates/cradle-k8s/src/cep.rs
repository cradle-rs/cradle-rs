//! CiliumEndpoint / CiliumNode CRD publication (story 2 / M6 of
//! `docs/design/cni-cilium.md`).
//!
//! Publishes one `CiliumEndpoint` (cilium.io/v2) per cradle-managed pod —
//! sourced from the daemon's endpoint store over gRPC, so the CRD reflects
//! what the datapath actually carries — and a `CiliumNode` for this node.
//! `kubectl get ciliumendpoints` then shows cradle pods exactly as it would
//! Cilium's. Objects are written with server-side apply and labeled
//! `cradle.io/node=<node>`, which scopes the stale-object sweep; the CRDs
//! themselves are vendored under `deploy/crds/` (pinned Cilium v2 schemas,
//! no status subresource — full-object writes are the cilium-agent's own
//! convention). A missing CRD is a warning, not an error: publication
//! starts working the moment the CRDs are applied.

use std::collections::BTreeMap;

use anyhow::{Context as _, Result};
use kube::api::{Api, DeleteParams, ListParams, Patch, PatchParams};
use kube::core::{ApiResource, DynamicObject, GroupVersionKind};
use kube::{Client, ResourceExt as _};
use serde_json::{json, Value};

use crate::pb;

/// Label scoping the objects this node's publisher owns.
pub const NODE_LABEL: &str = "cradle.io/node";

pub fn cep_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk("cilium.io", "v2", "CiliumEndpoint"))
}

pub fn cilium_node_resource() -> ApiResource {
    ApiResource::from_gvk(&GroupVersionKind::gvk("cilium.io", "v2", "CiliumNode"))
}

/// Build the CiliumEndpoint object for a cradle endpoint. Only the fields
/// tooling reads are filled: `status.state`, `status.networking.addressing`
/// (the `kubectl get cep` IPv4 column), `status.networking.node`, and the
/// endpoint id (the host ifindex — stable while the veth lives).
pub fn cep_object(node: &str, node_ip: &str, ep: &pb::CniEndpoint) -> Value {
    let mut networking = json!({
        "addressing": [ { "ipv4": ep.ip } ],
    });
    if !node_ip.is_empty() {
        networking["node"] = json!(node_ip);
    }
    json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumEndpoint",
        "metadata": {
            "name": ep.pod_name,
            "namespace": ep.pod_namespace,
            "labels": { NODE_LABEL: node },
        },
        "status": {
            "id": ep.host_ifindex,
            "state": "ready",
            "networking": networking,
        },
    })
}

/// Build this node's CiliumNode object.
pub fn cilium_node_object(node: &str, node_ip: &str, pod_cidr: &str) -> Value {
    let mut addresses = Vec::new();
    if !node_ip.is_empty() {
        addresses.push(json!({ "type": "InternalIP", "ip": node_ip }));
    }
    json!({
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNode",
        "metadata": {
            "name": node,
            "labels": { NODE_LABEL: node },
        },
        "spec": {
            "addresses": addresses,
            "ipam": { "podCIDRs": if pod_cidr.is_empty() { json!([]) } else { json!([pod_cidr]) } },
        },
    })
}

/// The desired CEP set for this node: `(namespace, name) → object`. Only
/// endpoints with a Kubernetes pod identity are published.
pub fn desired_ceps(
    node: &str,
    node_ip: &str,
    endpoints: &[pb::CniEndpoint],
) -> BTreeMap<(String, String), Value> {
    endpoints
        .iter()
        .filter(|ep| !ep.pod_name.is_empty() && !ep.pod_namespace.is_empty())
        .map(|ep| {
            (
                (ep.pod_namespace.clone(), ep.pod_name.clone()),
                cep_object(node, node_ip, ep),
            )
        })
        .collect()
}

/// One publication round: upsert the desired CEPs + this node's CiliumNode
/// (server-side apply), then sweep CEPs labeled for this node that no longer
/// have a backing endpoint.
pub async fn publish(
    client: &Client,
    node: &str,
    node_ip: &str,
    pod_cidr: &str,
    endpoints: &[pb::CniEndpoint],
) -> Result<()> {
    let ssapply = PatchParams::apply("cradle").force();
    let cep_ar = cep_resource();

    let desired = desired_ceps(node, node_ip, endpoints);
    for ((ns, name), obj) in &desired {
        let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), ns, &cep_ar);
        api.patch(name, &ssapply, &Patch::Apply(obj))
            .await
            .with_context(|| format!("applying CiliumEndpoint {ns}/{name}"))?;
    }

    // Sweep this node's stale CEPs (pods gone from the endpoint store).
    let all: Api<DynamicObject> = Api::all_with(client.clone(), &cep_ar);
    let lp = ListParams::default().labels(&format!("{NODE_LABEL}={node}"));
    for item in all.list(&lp).await.context("listing CiliumEndpoints")? {
        let key = (item.namespace().unwrap_or_default(), item.name_any());
        if !desired.contains_key(&key) {
            let api: Api<DynamicObject> = Api::namespaced_with(client.clone(), &key.0, &cep_ar);
            let _ = api.delete(&key.1, &DeleteParams::default()).await;
            tracing::info!("CiliumEndpoint {}/{} removed", key.0, key.1);
        }
    }

    let node_api: Api<DynamicObject> = Api::all_with(client.clone(), &cilium_node_resource());
    node_api
        .patch(
            node,
            &ssapply,
            &Patch::Apply(&cilium_node_object(node, node_ip, pod_cidr)),
        )
        .await
        .with_context(|| format!("applying CiliumNode {node}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(pod: &str, ns: &str, ip: &str, ifindex: u32) -> pb::CniEndpoint {
        pb::CniEndpoint {
            container_id: format!("{pod}-cid"),
            ifname: "eth0".into(),
            netns: String::new(),
            host_if: "lxc1".into(),
            host_ifindex: ifindex,
            ip: ip.into(),
            vrf_id: 0,
            pod_name: pod.into(),
            pod_namespace: ns.into(),
        }
    }

    #[test]
    fn cep_carries_printer_columns() {
        let obj = cep_object(
            "node1",
            "10.1.1.1",
            &ep("web-abc", "default", "10.244.0.2", 42),
        );
        assert_eq!(obj["status"]["state"], "ready");
        assert_eq!(
            obj["status"]["networking"]["addressing"][0]["ipv4"],
            "10.244.0.2"
        );
        assert_eq!(obj["status"]["networking"]["node"], "10.1.1.1");
        assert_eq!(obj["status"]["id"], 42);
        assert_eq!(obj["metadata"]["namespace"], "default");
        assert_eq!(obj["metadata"]["labels"][NODE_LABEL], "node1");
    }

    #[test]
    fn desired_skips_non_kubernetes_endpoints() {
        let eps = vec![
            ep("web-abc", "default", "10.244.0.2", 40),
            ep("", "", "10.244.0.3", 41), // no pod identity: BDD/manual attach
        ];
        let desired = desired_ceps("node1", "", &eps);
        assert_eq!(desired.len(), 1);
        assert!(desired.contains_key(&("default".to_string(), "web-abc".to_string())));
    }

    #[test]
    fn cilium_node_shape() {
        let obj = cilium_node_object("node1", "10.1.1.1", "10.244.0.0/24");
        assert_eq!(obj["spec"]["ipam"]["podCIDRs"][0], "10.244.0.0/24");
        assert_eq!(obj["spec"]["addresses"][0]["type"], "InternalIP");
    }
}
