//! CiliumIdentity-backed identity allocation (phase 3b,
//! docs/design/policy-multitenant.md).
//!
//! Replaces the FNV label-hash with *allocated* numeric identities recorded
//! as cluster-scoped `CiliumIdentity` CRDs — collision-free (a hash
//! collision would merge two label sets, unacceptable once deny rules
//! exist) and visible to Cilium tooling (`kubectl get ciliumidentities`).
//! The CRD name is the numeric identity; `security-labels` carries the
//! label set in Cilium's `k8s:` form. Allocation is
//! find-existing-else-create with sequential ids from 256 (below 256 is
//! Cilium's reserved range). The FNV hash remains the fallback when the
//! allocator is disabled or a set isn't (yet) allocated, so non-Kubernetes
//! deployments and the BDD gRPC path are unchanged.

use std::collections::{BTreeMap, HashMap};

use anyhow::Result;
use kube::api::{Api, DynamicObject, ListParams, PostParams};
use kube::core::{ApiResource, GroupVersionKind};
use kube::Client;
use serde_json::json;

/// First allocatable identity (256..: Cilium's cluster-scoped range).
pub const FIRST_ID: u32 = 256;

/// The canonical string for a label set — the allocation key.
pub fn labels_key(namespace: &str, labels: &BTreeMap<String, String>) -> String {
    let mut parts = vec![format!("k8s:io.kubernetes.pod.namespace={namespace}")];
    for (k, v) in labels {
        parts.push(format!("k8s:{k}={v}"));
    }
    parts.join(";")
}

/// The allocation table: canonical label-set string → allocated identity.
/// Empty when the allocator is off — resolution falls back to the FNV hash.
#[derive(Default, Clone)]
pub struct Alloc(pub HashMap<String, u32>);

impl Alloc {
    /// Resolve a pod's identity: allocated if present, FNV hash otherwise.
    pub fn resolve(&self, namespace: &str, labels: &BTreeMap<String, String>) -> u32 {
        self.0
            .get(&labels_key(namespace, labels))
            .copied()
            .unwrap_or_else(|| crate::netpol::identity(namespace, labels))
    }

    /// Every allocated identity (the `cluster` entity expansion).
    pub fn all_ids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.0.values().copied().collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

pub fn cilium_identity_api(client: &Client) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk("cilium.io", "v2", "CiliumIdentity");
    Api::all_with(client.clone(), &ApiResource::from_gvk(&gvk))
}

/// Reconcile the allocation table against the CiliumIdentity CRDs: adopt
/// every existing CID, then create one for each pod label set that has
/// none. Never deletes (GC is a follow-up; a stale CID only wastes a
/// number). Errors are per-item best-effort — a failed create just leaves
/// that set on the FNV fallback until the next reconcile.
pub async fn ensure_identities(
    api: &Api<DynamicObject>,
    pods: &[k8s_openapi::api::core::v1::Pod],
) -> Result<Alloc> {
    use kube::ResourceExt as _;

    let mut alloc = HashMap::new();
    let mut max_id = FIRST_ID - 1;
    for cid in api.list(&ListParams::default()).await?.items {
        let Ok(id) = cid.name_any().parse::<u32>() else {
            continue;
        };
        max_id = max_id.max(id);
        let labels: BTreeMap<String, String> = cid
            .data
            .get("security-labels")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();
        let key = labels
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";");
        alloc.insert(key, id);
    }

    for pod in pods {
        let ns = pod.namespace().unwrap_or_default();
        let labels = pod.metadata.labels.clone().unwrap_or_default();
        let key = security_labels(&ns, &labels)
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(";");
        if alloc.contains_key(&key) {
            continue;
        }
        max_id += 1;
        let id = max_id;
        let body = json!({
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumIdentity",
            "metadata": { "name": id.to_string() },
            "security-labels": security_labels(&ns, &labels),
        });
        match api
            .create(
                &PostParams::default(),
                &serde_json::from_value(body).expect("static shape"),
            )
            .await
        {
            Ok(_) => {
                alloc.insert(key, id);
            }
            Err(e) => {
                tracing::warn!("identity: creating CiliumIdentity {id}: {e}");
                max_id -= 1;
            }
        }
    }

    // Re-key by the canonical labels_key form used by resolve().
    let table = pods
        .iter()
        .filter_map(|pod| {
            let ns = pod.namespace().unwrap_or_default();
            let labels = pod.metadata.labels.clone().unwrap_or_default();
            let cid_key = security_labels(&ns, &labels)
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(";");
            alloc
                .get(&cid_key)
                .map(|id| (labels_key(&ns, &labels), *id))
        })
        .collect();
    Ok(Alloc(table))
}

/// The CRD's `security-labels` map for a pod label set (Cilium `k8s:` form).
fn security_labels(namespace: &str, labels: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    out.insert(
        "k8s:io.kubernetes.pod.namespace".to_string(),
        namespace.to_string(),
    );
    for (k, v) in labels {
        out.insert(format!("k8s:{k}"), v.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_prefers_allocation_over_hash() {
        let labels: BTreeMap<String, String> = [("app".to_string(), "web".to_string())]
            .into_iter()
            .collect();
        let empty = Alloc::default();
        let hash = empty.resolve("default", &labels);
        assert!(hash >= 3);
        let mut table = HashMap::new();
        table.insert(labels_key("default", &labels), 256);
        let alloc = Alloc(table);
        assert_eq!(alloc.resolve("default", &labels), 256);
        assert_eq!(alloc.all_ids(), vec![256]);
    }
}
