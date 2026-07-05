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
//! Scope (documented in the design): ingress and egress rules,
//! `matchLabels` selectors (not `matchExpressions`), pod/namespace-selector
//! and empty peers. `ipBlock` peers are skipped (logged).

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{Namespace, Pod};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicyPeer, NetworkPolicyPort};
use kube::ResourceExt as _;

use crate::pb;

pub const IDENTITY_HOST: u32 = 1;
pub const IDENTITY_WORLD: u32 = 2;

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

/// Stable identity for an ipBlock CIDR. Same FNV space as label identities
/// (the "cidr:" prefix keeps the feeds distinct); collision-free allocation
/// is the phase-3 CiliumIdentity work (docs/design/policy-multitenant.md).
pub fn cidr_identity(cidr: &str) -> u32 {
    identity(
        "\0cidr",
        &BTreeMap::from([("cidr".to_string(), cidr.to_string())]),
    )
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

/// The pods one peer's selectors admit (empty for ipBlock peers).
fn peer_pods<'a>(
    peer: &NetworkPolicyPeer,
    policy_ns: &str,
    pods: &'a [Pod],
    namespaces: &[Namespace],
) -> Vec<&'a Pod> {
    if peer.ip_block.is_some() {
        return Vec::new();
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
    pods.iter()
        .filter(|pod| ns_match.contains(&pod.namespace().unwrap_or_default()))
        .filter(|pod| selector_matches(&peer.pod_selector, &labels_of(pod)))
        .collect()
}

/// Resolve one peer (`from`/`to`) to the set of identities it admits.
fn peer_identities(
    peer: &NetworkPolicyPeer,
    policy_ns: &str,
    pods: &[Pod],
    namespaces: &[Namespace],
) -> Option<Vec<u32>> {
    if let Some(b) = &peer.ip_block {
        // The CIDR's identity; the binding itself (CIDR → identity, plus
        // except-prefixes → world) is pushed separately via cidr_bindings().
        return Some(vec![cidr_identity(&b.cidr)]);
    }
    Some(
        peer_pods(peer, policy_ns, pods, namespaces)
            .iter()
            .map(|pod| identity(&pod.namespace().unwrap_or_default(), &labels_of(pod)))
            .collect(),
    )
}

/// A pod's numeric containerPort for a named port.
fn named_port(pod: &Pod, name: &str) -> Option<u16> {
    pod.spec
        .as_ref()?
        .containers
        .iter()
        .flat_map(|c| c.ports.iter().flatten())
        .find(|cp| cp.name.as_deref() == Some(name))
        .map(|cp| cp.container_port as u16)
}

fn proto_num(p: &Option<String>) -> u8 {
    match p.as_deref() {
        Some("UDP") => 17,
        Some("SCTP") => 0, // unsupported → wildcard proto rather than drop
        _ => 6,            // TCP is the NetworkPolicy default
    }
}

/// Expand one rule's peers (`from`/`to`) and ports to `(identity, proto,
/// port)` allow tuples. Named ports resolve against `port_pods`: the
/// enforced pod itself for ingress rules (its containerPorts), the peer
/// pods for egress rules (theirs). An unresolvable named port yields no
/// tuple — fail closed, never wildcard.
fn rule_tuples(
    peers: &Option<Vec<NetworkPolicyPeer>>,
    rule_ports: &Option<Vec<NetworkPolicyPort>>,
    policy_ns: &str,
    pods: &[Pod],
    namespaces: &[Namespace],
    port_pods: &[&Pod],
) -> Vec<(u32, u8, u16)> {
    // Peers: empty ⇒ any (identity 0); else the union of peers.
    let identities: Vec<u32> = match peers {
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
    let ports: Vec<(u8, u16)> = match rule_ports {
        None => vec![(0, 0)],
        Some(p) if p.is_empty() => vec![(0, 0)],
        Some(p) => p
            .iter()
            .flat_map(|np| {
                use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
                let proto = proto_num(&np.protocol);
                match &np.port {
                    Some(IntOrString::Int(n)) => {
                        vec![(proto, u16::try_from(*n).unwrap_or(0))]
                    }
                    Some(IntOrString::String(name)) => {
                        let mut nums: Vec<(u8, u16)> = port_pods
                            .iter()
                            .filter_map(|pod| named_port(pod, name))
                            .map(|port| (proto, port))
                            .collect();
                        nums.sort_unstable();
                        nums.dedup();
                        if nums.is_empty() {
                            tracing::warn!("netpol: named port {name:?} unresolved — no rule");
                        }
                        nums
                    }
                    None => vec![(proto, 0)],
                }
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
    // This pod (for its labels and its containerPorts — ingress named ports).
    let this_pod = pods
        .iter()
        .find(|p| p.namespace().as_deref() == Some(ns) && p.name_any() == ep.pod_name);
    let pod_labels = this_pod.map(labels_of).unwrap_or_default();
    let target: Vec<&Pod> = this_pod.into_iter().collect();

    // Which of this namespace's policies select the pod, per direction?
    // policyTypes defaults (K8s): unset ⇒ Ingress always, Egress only if the
    // policy has egress rules.
    let selecting: Vec<&NetworkPolicy> = policies
        .iter()
        .filter(|np| np.namespace().as_deref() == Some(ns.as_str()))
        .filter(|np| {
            np.spec
                .as_ref()
                .is_some_and(|s| selector_matches(&s.pod_selector, &pod_labels))
        })
        .collect();
    let has_type = |np: &NetworkPolicy, dir: &str| -> bool {
        let Some(spec) = &np.spec else { return false };
        match &spec.policy_types {
            Some(t) => t.iter().any(|x| x == dir),
            None => dir == "Ingress" || spec.egress.as_ref().is_some_and(|e| !e.is_empty()),
        }
    };
    let enforce = selecting.iter().any(|np| has_type(np, "Ingress"));
    let enforce_egress = selecting.iter().any(|np| has_type(np, "Egress"));

    if !enforce && !enforce_egress {
        return pb::EndpointPolicy {
            host_if: String::new(),
            pod_namespace: ns.clone(),
            pod_name: ep.pod_name.clone(),
            enforce: false,
            rules: Vec::new(),
            enforce_egress: false,
            egress_rules: Vec::new(),
        };
    }

    let host_rule = pb::PolicyRule {
        identity: IDENTITY_HOST,
        proto: 0,
        port: 0,
    };
    // Kubelet probes come from the node — always allowed inbound.
    let mut rules = vec![host_rule.clone()];
    // Node-originated traffic never traverses the veth TC ingress hook, so an
    // admitted probe leaves no PCT entry — the pod's probe *replies* need an
    // explicit egress allow to the host (docs/design/policy.md).
    let mut egress_rules = vec![host_rule];
    for np in &selecting {
        let Some(spec) = &np.spec else { continue };
        if has_type(np, "Ingress") {
            for rule in spec.ingress.iter().flatten() {
                for (identity, proto, port) in
                    rule_tuples(&rule.from, &rule.ports, ns, pods, namespaces, &target)
                {
                    rules.push(pb::PolicyRule {
                        identity,
                        proto: proto as u32,
                        port: port as u32,
                    });
                }
            }
        }
        if has_type(np, "Egress") {
            for rule in spec.egress.iter().flatten() {
                // Egress named ports live on the peers' containers.
                let peers: Vec<&Pod> = rule
                    .to
                    .iter()
                    .flatten()
                    .flat_map(|peer| peer_pods(peer, ns, pods, namespaces))
                    .collect();
                for (identity, proto, port) in
                    rule_tuples(&rule.to, &rule.ports, ns, pods, namespaces, &peers)
                {
                    egress_rules.push(pb::PolicyRule {
                        identity,
                        proto: proto as u32,
                        port: port as u32,
                    });
                }
            }
        }
    }
    if !enforce {
        rules.clear();
    }
    if !enforce_egress {
        egress_rules.clear();
    }
    pb::EndpointPolicy {
        host_if: String::new(),
        pod_namespace: ns.clone(),
        pod_name: ep.pod_name.clone(),
        enforce,
        rules,
        enforce_egress,
        egress_rules,
    }
}

/// All CIDR → identity bindings the current policy set needs: every ipBlock
/// peer's CIDR bound to its `cidr_identity`, and every `except` prefix bound
/// back to world (a more-specific LPM entry, so excepted sources don't match
/// the block's allow rules). Sorted/deduped so reconcile diffs are stable.
pub fn cidr_bindings(policies: &[NetworkPolicy]) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut push_peers = |peers: &Option<Vec<NetworkPolicyPeer>>| {
        for peer in peers.iter().flatten() {
            let Some(b) = &peer.ip_block else { continue };
            out.push((b.cidr.clone(), cidr_identity(&b.cidr)));
            for e in b.except.iter().flatten() {
                out.push((e.clone(), IDENTITY_WORLD));
            }
        }
    };
    for np in policies {
        let Some(spec) = &np.spec else { continue };
        for rule in spec.ingress.iter().flatten() {
            push_peers(&rule.from);
        }
        for rule in spec.egress.iter().flatten() {
            push_peers(&rule.to);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// All pod-IP → identity bindings currently derivable (dual-stack: every
/// address in `podIPs`, plus `podIP` for older status shapes).
pub fn identities(pods: &[Pod]) -> Vec<(String, u32)> {
    pods.iter()
        .flat_map(|p| {
            let id = identity(&p.namespace().unwrap_or_default(), &labels_of(p));
            let status = p.status.as_ref();
            let mut ips: Vec<String> = status
                .and_then(|s| s.pod_ips.as_ref())
                .map(|v| v.iter().map(|pip| pip.ip.clone()).collect())
                .unwrap_or_default();
            if let Some(ip) = status.and_then(|s| s.pod_ip.clone()) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
            ips.into_iter().map(move |ip| (ip, id))
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

    fn pod(ns: &str, name: &str, lbls: &[(&str, &str)], ip: &str) -> Pod {
        let mut p = Pod::default();
        p.metadata.namespace = Some(ns.into());
        p.metadata.name = Some(name.into());
        p.metadata.labels = Some(labels(lbls));
        p.status = Some(k8s_openapi::api::core::v1::PodStatus {
            pod_ip: Some(ip.into()),
            ..Default::default()
        });
        p
    }

    fn netpol_with(
        ns: &str,
        pod_sel: &[(&str, &str)],
        policy_types: Option<Vec<&str>>,
        egress_to: Option<&[(&str, &str)]>,
    ) -> NetworkPolicy {
        use k8s_openapi::api::networking::v1::{
            NetworkPolicyEgressRule, NetworkPolicyPeer, NetworkPolicySpec,
        };
        let mut np = NetworkPolicy::default();
        np.metadata.namespace = Some(ns.into());
        np.metadata.name = Some("t".into());
        np.spec = Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(labels(pod_sel)),
                ..Default::default()
            }),
            policy_types: policy_types.map(|t| t.iter().map(|s| s.to_string()).collect()),
            egress: egress_to.map(|sel| {
                vec![NetworkPolicyEgressRule {
                    to: Some(vec![NetworkPolicyPeer {
                        pod_selector: Some(LabelSelector {
                            match_labels: Some(labels(sel)),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ports: None,
                }]
            }),
            ..Default::default()
        });
        np
    }

    fn ep(ns: &str, name: &str) -> pb::CniEndpoint {
        pb::CniEndpoint {
            pod_namespace: ns.into(),
            pod_name: name.into(),
            ..Default::default()
        }
    }

    #[test]
    fn egress_policy_enforces_and_allows_host_and_peer() {
        let pods = vec![
            pod("default", "web", &[("app", "web")], "10.0.0.1"),
            pod("default", "db", &[("app", "db")], "10.0.0.2"),
        ];
        let np = netpol_with(
            "default",
            &[("app", "web")],
            Some(vec!["Egress"]),
            Some(&[("app", "db")]),
        );
        let p = endpoint_policy(&ep("default", "web"), &[np], &pods, &[]);
        assert!(!p.enforce, "ingress must stay default-allow");
        assert!(p.rules.is_empty());
        assert!(p.enforce_egress);
        // Implicit host allow (probe replies) + the db peer.
        assert_eq!(p.egress_rules[0].identity, IDENTITY_HOST);
        let db = identity("default", &labels(&[("app", "db")]));
        assert!(p.egress_rules.iter().any(|r| r.identity == db));
    }

    #[test]
    fn ingress_named_port_resolves_against_target_pod() {
        use k8s_openapi::api::core::v1::{Container, ContainerPort, PodSpec};
        use k8s_openapi::api::networking::v1::{
            NetworkPolicyIngressRule, NetworkPolicyPort, NetworkPolicySpec,
        };
        use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
        let mut web = pod("default", "web", &[("app", "web")], "10.0.0.1");
        web.spec = Some(PodSpec {
            containers: vec![Container {
                name: "c".into(),
                ports: Some(vec![ContainerPort {
                    name: Some("http".into()),
                    container_port: 8080,
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            ..Default::default()
        });
        let mut np = NetworkPolicy::default();
        np.metadata.namespace = Some("default".into());
        np.spec = Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(labels(&[("app", "web")])),
                ..Default::default()
            }),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: None,
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::String("http".into())),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
            }]),
            ..Default::default()
        });
        let pods = vec![web];
        let p = endpoint_policy(&ep("default", "web"), &[np], &pods, &[]);
        assert!(p.enforce);
        // host rule + (any, tcp, 8080)
        assert!(p
            .rules
            .iter()
            .any(|r| r.identity == 0 && r.proto == 6 && r.port == 8080));
    }

    #[test]
    fn cidr_bindings_include_except_as_world() {
        use k8s_openapi::api::networking::v1::{
            IPBlock, NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicySpec,
        };
        let mut np = NetworkPolicy::default();
        np.metadata.namespace = Some("default".into());
        np.spec = Some(NetworkPolicySpec {
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: Some(vec![NetworkPolicyPeer {
                    ip_block: Some(IPBlock {
                        cidr: "10.0.0.0/8".into(),
                        except: Some(vec!["10.1.0.0/16".into()]),
                    }),
                    ..Default::default()
                }]),
                ports: None,
            }]),
            ..Default::default()
        });
        let b = cidr_bindings(&[np]);
        assert_eq!(b.len(), 2);
        assert!(b.contains(&("10.0.0.0/8".to_string(), cidr_identity("10.0.0.0/8"))));
        assert!(b.contains(&("10.1.0.0/16".to_string(), IDENTITY_WORLD)));
        assert!(cidr_identity("10.0.0.0/8") >= 3);
    }

    #[test]
    fn policy_types_default_derives_egress_from_rules() {
        let pods = vec![pod("default", "web", &[("app", "web")], "10.0.0.1")];
        // No policyTypes, egress rules present ⇒ Ingress AND Egress enforced.
        let np = netpol_with("default", &[("app", "web")], None, Some(&[("app", "db")]));
        let p = endpoint_policy(&ep("default", "web"), &[np], &pods, &[]);
        assert!(p.enforce);
        assert!(p.enforce_egress);
        // No policyTypes, no egress rules ⇒ ingress only.
        let np = netpol_with("default", &[("app", "web")], None, None);
        let p = endpoint_policy(&ep("default", "web"), &[np], &pods, &[]);
        assert!(p.enforce);
        assert!(!p.enforce_egress);
        assert!(p.egress_rules.is_empty());
    }
}
