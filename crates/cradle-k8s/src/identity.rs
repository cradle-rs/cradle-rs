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

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Result;
use kube::api::{Api, DeleteParams, DynamicObject, ListParams, PostParams};
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

/// The CID `security-labels` join key for a label set (matches how existing
/// CiliumIdentities are keyed on read).
fn cid_key(namespace: &str, labels: &BTreeMap<String, String>) -> String {
    security_labels(namespace, labels)
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(";")
}

/// List every CiliumIdentity as `cid_key → id` (adoption table).
async fn list_cids(api: &Api<DynamicObject>) -> Result<HashMap<String, u32>> {
    use kube::ResourceExt as _;
    let mut out = HashMap::new();
    for cid in api.list(&ListParams::default()).await?.items {
        let Ok(id) = cid.name_any().parse::<u32>() else {
            continue;
        };
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
        out.insert(key, id);
    }
    Ok(out)
}

/// Re-key an adoption table by the canonical `labels_key` form `resolve`
/// uses, for the label sets the given pods carry.
fn rekey_for_pods(
    cids: &HashMap<String, u32>,
    pods: &[k8s_openapi::api::core::v1::Pod],
) -> HashMap<String, u32> {
    use kube::ResourceExt as _;
    pods.iter()
        .filter_map(|pod| {
            let ns = pod.namespace().unwrap_or_default();
            let labels = pod.metadata.labels.clone().unwrap_or_default();
            cids.get(&cid_key(&ns, &labels))
                .map(|id| (labels_key(&ns, &labels), *id))
        })
        .collect()
}

/// Read-only allocation table: adopt existing CiliumIdentities without
/// creating any (the enforce-policy loop owns creation). Pods whose set has
/// no CID fall back to the FNV hash via `Alloc::resolve`. Used by the CRD
/// publisher, which must not race the allocator on creation.
pub async fn resolve_only(
    api: &Api<DynamicObject>,
    pods: &[k8s_openapi::api::core::v1::Pod],
) -> Result<Alloc> {
    let cids = list_cids(api).await?;
    Ok(Alloc(rekey_for_pods(&cids, pods)))
}

/// Every allocated CiliumIdentity id (all label sets, not just current pods').
pub async fn all_cid_ids(api: &Api<DynamicObject>) -> Result<Vec<u32>> {
    Ok(list_cids(api).await?.into_values().collect())
}

/// Mark-and-sweep GC plan. Given every CID id, the cluster-wide in-use id
/// set, and prior consecutive-unreferenced strike counts, return the new
/// strike counts and the ids to delete. Reserved ids (`< FIRST_ID`) are
/// never touched; a referenced id clears its strikes; an id unreferenced
/// for `grace` consecutive rounds is deleted. The grace period absorbs the
/// lag between a CID's creation and its CEP appearing, and brief pod churn.
pub fn gc_plan(
    cids: &[u32],
    in_use: &HashSet<u32>,
    prev: &HashMap<u32, u32>,
    grace: u32,
) -> (HashMap<u32, u32>, Vec<u32>) {
    let mut counts = HashMap::new();
    let mut del = Vec::new();
    for &id in cids {
        if id < FIRST_ID || in_use.contains(&id) {
            continue; // reserved or live → no strike
        }
        let n = prev.get(&id).copied().unwrap_or(0) + 1;
        if n >= grace {
            del.push(id);
        } else {
            counts.insert(id, n);
        }
    }
    (counts, del)
}

/// Delete a CiliumIdentity by numeric id (idempotent; errors are logged).
pub async fn delete_cid(api: &Api<DynamicObject>, id: u32) {
    if let Err(e) = api.delete(&id.to_string(), &DeleteParams::default()).await {
        tracing::warn!("identity GC: deleting CiliumIdentity {id}: {e}");
    }
}

/// A label set in Cilium's `["k8s:key=value", ...]` list form — the shape
/// `CiliumEndpoint.status.identity.labels` uses.
pub fn label_list(namespace: &str, labels: &BTreeMap<String, String>) -> Vec<String> {
    security_labels(namespace, labels)
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect()
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

    let mut cids = list_cids(api).await?;
    let mut max_id = cids
        .values()
        .copied()
        .max()
        .unwrap_or(FIRST_ID - 1)
        .max(FIRST_ID - 1);

    for pod in pods {
        let ns = pod.namespace().unwrap_or_default();
        let labels = pod.metadata.labels.clone().unwrap_or_default();
        let key = cid_key(&ns, &labels);
        if cids.contains_key(&key) {
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
                cids.insert(key, id);
            }
            Err(e) => {
                tracing::warn!("identity: creating CiliumIdentity {id}: {e}");
                max_id -= 1;
            }
        }
    }

    Ok(Alloc(rekey_for_pods(&cids, pods)))
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
    fn gc_reserved_and_grace() {
        let cids = vec![1, 2, 256, 300, 301];
        let in_use: HashSet<u32> = [256].into_iter().collect();
        // Round 1: 300 and 301 unreferenced (1 strike); reserved (1,2) and
        // in-use (256) untouched; nothing deleted at grace 2.
        let (c1, d1) = gc_plan(&cids, &in_use, &HashMap::new(), 2);
        assert!(d1.is_empty());
        assert_eq!(c1.get(&300), Some(&1));
        assert_eq!(c1.get(&301), Some(&1));
        assert!(!c1.contains_key(&1) && !c1.contains_key(&256));
        // Round 2: 301 comes back into use → clears; 300 hits grace → deleted.
        let in_use2: HashSet<u32> = [256, 301].into_iter().collect();
        let (c2, d2) = gc_plan(&cids, &in_use2, &c1, 2);
        assert_eq!(d2, vec![300]);
        assert!(!c2.contains_key(&301));
    }

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
