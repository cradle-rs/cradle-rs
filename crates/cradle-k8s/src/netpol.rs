//! Kubernetes `NetworkPolicy` → cradle ingress policy (story 2 / M8,
//! docs/design/policy.md).
//!
//! Watches Pods, Namespaces, and NetworkPolicies and, every reconcile,
//! programs the cradle daemon over gRPC:
//!
//! - **Identities**: every pod IP → the FNV-1a/32 hash of its namespace + its
//!   sorted `matchLabels` set (`SetIdentity`). Pods with identical labels in
//!   a namespace share one identity; the hash is stable across restarts.
//! - **Endpoint policies**: for each of this node's endpoints (from the
//!   daemon's endpoint store), the NetworkPolicies whose `podSelector` matches
//!   the pod are unioned into `(source-identity, proto, port)` allow rules and
//!   pushed with `SetEndpointPolicy` (`enforce=true`). A pod that no policy
//!   selects is set `enforce=false` (Kubernetes default-allow). The node
//!   identity (kubelet health probes) is always allowed.
//!
//! Scope of this first cut (documented in the design): ingress only,
//! `matchLabels` selectors (not `matchExpressions`), pod/namespace-selector
//! and empty peers. `ipBlock` peers are skipped (logged) and egress policies
//! are ignored.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Namespace, Pod};
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyIngressRule, NetworkPolicyPeer,
};
use kube::ResourceExt as _;

use crate::pb;

pub const IDENTITY_HOST: u32 = 1;

/// Stable identity for a `(namespace, labels)` pair.
pub fn identity(namespace: &str, labels: &BTreeMap<String, String>) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    let mut feed = |b: &[u8]| {
        for &x in b {
            hash ^= x as u32;
            hash = hash.wrapping_mul(0x0100_0193);
        }
    };
    feed(namespace.as_bytes());
    feed(b"\0");
    // BTreeMap iterates sorted, so the identity is order-independent.
    for (k, v) in labels {
        feed(k.as_bytes());
        feed(b"=");
        feed(v.as_bytes());
        feed(b";");
    }
    // Never collide with the reserved identities (1 host, 2 world).
    hash.max(3)
}

fn labels_of(pod: &Pod) -> BTreeMap<String, String> {
    pod.metadata.labels.clone().unwrap_or_default()
}

/// Does `selector` (matchLabels only) match `labels`? An empty selector
/// matches everything.
fn selector_matches(
    selector: &Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector>,
    labels: &BTreeMap<String, String>,
) -> bool {
    let Some(sel) = selector else { return true };
    if sel
        .match_expressions
        .as_ref()
        .is_some_and(|e| !e.is_empty())
    {
        // Unsupported in this cut — treat as non-matching so we never
        // over-allow (documented scope).
        return false;
    }
    match &sel.match_labels {
        None => true,
        Some(ml) => ml.iter().all(|(k, v)| labels.get(k) == Some(v)),
    }
}

/// Resolve one ingress `from` peer to the set of source identities it admits.
/// Returns `Some(vec)` of identities, or `None` for "any source" (identity 0).
fn peer_identities(
    peer: &NetworkPolicyPeer,
    policy_ns: &str,
    pods: &[Pod],
    namespaces: &[Namespace],
) -> Option<Vec<u32>> {
    if peer.ip_block.is_some() {
        tracing::warn!("netpol: ipBlock peer not supported yet — skipped");
        return Some(vec![]);
    }
    // Which namespaces does this peer draw pods from?
    let ns_match: Vec<String> = if peer.namespace_selector.is_some() {
        namespaces
            .iter()
            .filter(|ns| {
                selector_matches(
                    &peer.namespace_selector,
                    &ns.metadata.labels.clone().unwrap_or_default(),
                )
            })
            .map(|ns| ns.name_any())
            .collect()
    } else {
        vec![policy_ns.to_string()]
    };
    let mut ids = Vec::new();
    for pod in pods {
        let ns = pod.namespace().unwrap_or_default();
        if !ns_match.contains(&ns) {
            continue;
        }
        if selector_matches(&peer.pod_selector, &labels_of(pod)) {
            ids.push(identity(&ns, &labels_of(pod)));
        }
    }
    Some(ids)
}

fn proto_num(p: &Option<String>) -> u8 {
    match p.as_deref() {
        Some("UDP") => 17,
        Some("SCTP") => 0, // unsupported → wildcard proto rather than drop
        _ => 6,            // TCP is the NetworkPolicy default
    }
}

/// Expand one ingress rule to `(identity, proto, port)` allow tuples.
fn rule_tuples(
    rule: &NetworkPolicyIngressRule,
    policy_ns: &str,
    pods: &[Pod],
    namespaces: &[Namespace],
) -> Vec<(u32, u8, u16)> {
    // Sources: empty `from` ⇒ any (identity 0); else the union of peers.
    let identities: Vec<u32> = match &rule.from {
        None => vec![0],
        Some(f) if f.is_empty() => vec![0],
        Some(f) => {
            let mut ids = Vec::new();
            for peer in f {
                if let Some(mut p) = peer_identities(peer, policy_ns, pods, namespaces) {
                    ids.append(&mut p);
                }
            }
            ids
        }
    };
    // Ports: empty ⇒ any (proto 0, port 0); else each listed port.
    let ports: Vec<(u8, u16)> = match &rule.ports {
        None => vec![(0, 0)],
        Some(p) if p.is_empty() => vec![(0, 0)],
        Some(p) => p
            .iter()
            .map(|np| {
                use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
                let port = match &np.port {
                    Some(IntOrString::Int(n)) => u16::try_from(*n).unwrap_or(0),
                    // Named ports would need the pod's containerPort map;
                    // unsupported in this cut → any port for the proto.
                    _ => 0,
                };
                (proto_num(&np.protocol), port)
            })
            .collect(),
    };
    let mut out = Vec::new();
    for &id in &identities {
        for &(proto, port) in &ports {
            out.push((id, proto, port));
        }
    }
    out
}

/// Compute the `SetEndpointPolicy` payload for one local endpoint.
pub fn endpoint_policy(
    ep: &pb::CniEndpoint,
    policies: &[NetworkPolicy],
    pods: &[Pod],
    namespaces: &[Namespace],
) -> pb::EndpointPolicy {
    let ns = &ep.pod_namespace;
    // This pod's labels (from the matching Pod object, if we can see it).
    let pod_labels = pods
        .iter()
        .find(|p| p.namespace().as_deref() == Some(ns) && p.name_any() == ep.pod_name)
        .map(labels_of)
        .unwrap_or_default();

    let selecting: Vec<&NetworkPolicy> = policies
        .iter()
        .filter(|np| np.namespace().as_deref() == Some(ns.as_str()))
        .filter(|np| {
            np.spec.as_ref().is_some_and(|s| {
                // A policy with Ingress in policyTypes (or none set) and a
                // podSelector that matches enforces ingress on this pod.
                let ingress = s
                    .policy_types
                    .as_ref()
                    .map(|t| t.iter().any(|x| x == "Ingress"))
                    .unwrap_or(true);
                ingress && selector_matches(&s.pod_selector, &pod_labels)
            })
        })
        .collect();

    if selecting.is_empty() {
        return pb::EndpointPolicy {
            host_if: String::new(),
            pod_namespace: ns.clone(),
            pod_name: ep.pod_name.clone(),
            enforce: false,
            rules: Vec::new(),
        };
    }

    // Kubelet probes come from the node — always allowed.
    let mut rules = vec![pb::PolicyRule {
        identity: IDENTITY_HOST,
        proto: 0,
        port: 0,
    }];
    for np in selecting {
        let Some(spec) = &np.spec else { continue };
        for rule in spec.ingress.iter().flatten() {
            for (identity, proto, port) in rule_tuples(rule, ns, pods, namespaces) {
                rules.push(pb::PolicyRule {
                    identity,
                    proto: proto as u32,
                    port: port as u32,
                });
            }
        }
    }
    pb::EndpointPolicy {
        host_if: String::new(),
        pod_namespace: ns.clone(),
        pod_name: ep.pod_name.clone(),
        enforce: true,
        rules,
    }
}

/// All pod-IP → identity bindings currently derivable.
pub fn identities(pods: &[Pod]) -> Vec<(String, u32)> {
    pods.iter()
        .filter_map(|p| {
            let ip = p.status.as_ref().and_then(|s| s.pod_ip.clone())?;
            let ns = p.namespace().unwrap_or_default();
            Some((ip, identity(&ns, &labels_of(p))))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn identity_stable_and_order_independent() {
        let a = identity("default", &labels(&[("app", "web"), ("tier", "fe")]));
        let b = identity("default", &labels(&[("tier", "fe"), ("app", "web")]));
        assert_eq!(a, b);
        assert_ne!(
            a,
            identity("other", &labels(&[("app", "web"), ("tier", "fe")]))
        );
        assert!(a >= 3);
    }

    #[test]
    fn selector_matchlabels() {
        let l = labels(&[("app", "web")]);
        assert!(selector_matches(&None, &l));
        assert!(selector_matches(
            &Some(LabelSelector {
                match_labels: Some(labels(&[("app", "web")])),
                ..Default::default()
            }),
            &l
        ));
        assert!(!selector_matches(
            &Some(LabelSelector {
                match_labels: Some(labels(&[("app", "db")])),
                ..Default::default()
            }),
            &l
        ));
    }
}
