//! CiliumNetworkPolicy → cradle policy rules (phase 3b,
//! docs/design/policy-multitenant.md).
//!
//! The L3/L4 subset: `endpointSelector` (matchLabels), `ingress`/`egress`
//! with `fromEndpoints`/`toEndpoints` (matchLabels) + `toPorts[].ports`,
//! their `ingressDeny`/`egressDeny` siblings (deny wins over allow at any
//! specificity — POLICY_DENY in the datapath), and
//! `fromEntities`/`toEntities`: `all` → wildcard peer, `host` → reserved 1,
//! `world` → reserved 2, `cluster` → the host plus every *allocated*
//! identity (requires the CiliumIdentity allocator; without it the
//! expansion degrades to host-only with a warning). L7 rules and
//! `matchExpressions` are out of scope (phase 5 / follow-ups).

use std::collections::BTreeMap;

use kube::api::DynamicObject;
use kube::core::{ApiResource, GroupVersionKind};
use kube::{Api, Client};
use serde::Deserialize;

use crate::identity::Alloc;
use crate::netpol::{IDENTITY_HOST, IDENTITY_WORLD};
use crate::pb;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CnpSpec {
    #[serde(default)]
    pub endpoint_selector: Selector,
    #[serde(default)]
    pub ingress: Vec<Rule>,
    #[serde(default)]
    pub egress: Vec<Rule>,
    #[serde(default)]
    pub ingress_deny: Vec<Rule>,
    #[serde(default)]
    pub egress_deny: Vec<Rule>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Selector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(default)]
    pub from_endpoints: Vec<Selector>,
    #[serde(default)]
    pub to_endpoints: Vec<Selector>,
    #[serde(default)]
    pub from_entities: Vec<String>,
    #[serde(default)]
    pub to_entities: Vec<String>,
    #[serde(default)]
    pub to_ports: Vec<PortRule>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PortRule {
    #[serde(default)]
    pub ports: Vec<Port>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Port {
    #[serde(default)]
    pub port: String,
    #[serde(default)]
    pub protocol: String,
}

/// A parsed CNP: its namespace, endpoint selector, and rule sets.
pub struct Cnp {
    pub namespace: String,
    pub spec: CnpSpec,
}

pub fn cnp_api(client: &Client) -> Api<DynamicObject> {
    let gvk = GroupVersionKind::gvk("cilium.io", "v2", "CiliumNetworkPolicy");
    Api::all_with(client.clone(), &ApiResource::from_gvk(&gvk))
}

/// Parse the dynamic objects a CNP list call returns (unparseable specs are
/// skipped with a warning — never fail the whole reconcile).
pub fn parse(objs: &[DynamicObject]) -> Vec<Cnp> {
    use kube::ResourceExt as _;
    objs.iter()
        .filter_map(|o| {
            let spec = o.data.get("spec")?;
            match serde_json::from_value::<CnpSpec>(spec.clone()) {
                Ok(spec) => Some(Cnp {
                    namespace: o.namespace().unwrap_or_default(),
                    spec,
                }),
                Err(e) => {
                    tracing::warn!("cnp {}: unparseable spec: {e}", o.name_any());
                    None
                }
            }
        })
        .collect()
}

fn selector_matches(sel: &Selector, labels: &BTreeMap<String, String>) -> bool {
    sel.match_labels
        .iter()
        .all(|(k, v)| labels.get(k) == Some(v))
}

/// Peer identity sets for one rule: selector peers resolve through the
/// allocator over the known pods; entities expand per the module docs.
/// Empty peers (no fromEndpoints/entities) ⇒ wildcard.
fn peer_ids(
    peers: &[Selector],
    entities: &[String],
    policy_ns: &str,
    pods: &[k8s_openapi::api::core::v1::Pod],
    alloc: &Alloc,
) -> Vec<u32> {
    use kube::ResourceExt as _;
    let mut ids = Vec::new();
    for sel in peers {
        for pod in pods {
            let ns = pod.namespace().unwrap_or_default();
            if ns != policy_ns {
                continue; // namespace-scoped like fromEndpoints without a ns selector
            }
            let labels = pod.metadata.labels.clone().unwrap_or_default();
            if selector_matches(sel, &labels) {
                ids.push(alloc.resolve(&ns, &labels));
            }
        }
    }
    for e in entities {
        match e.as_str() {
            "all" => ids.push(0),
            "host" => ids.push(IDENTITY_HOST),
            "world" => ids.push(IDENTITY_WORLD),
            "cluster" => {
                ids.push(IDENTITY_HOST);
                let all = alloc.all_ids();
                if all.is_empty() {
                    tracing::warn!(
                        "cnp: `cluster` entity without the identity allocator \
                         degrades to host-only"
                    );
                }
                ids.extend(all);
            }
            other => tracing::warn!("cnp: entity {other:?} unsupported — skipped"),
        }
    }
    if peers.is_empty() && entities.is_empty() {
        ids.push(0);
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn from_peers(r: &Rule) -> (&[Selector], &[String]) {
    (&r.from_endpoints, &r.from_entities)
}

fn to_peers(r: &Rule) -> (&[Selector], &[String]) {
    (&r.to_endpoints, &r.to_entities)
}

fn rule_ports(rule: &Rule) -> Vec<(u8, u16)> {
    let mut out = Vec::new();
    for pr in &rule.to_ports {
        for p in &pr.ports {
            let proto = match p.protocol.as_str() {
                "UDP" => 17,
                "ANY" => 0,
                _ => 6,
            };
            out.push((proto, p.port.parse().unwrap_or(0)));
        }
    }
    if out.is_empty() {
        out.push((0, 0));
    }
    out
}

/// Expand the CNPs that select `pod_labels` in `ns` into cradle policy
/// rules. Returns (ingress, egress) rule lists — deny rules carry
/// `deny: true` — plus whether any CNP selected the pod per direction.
#[allow(clippy::type_complexity)]
pub fn endpoint_rules(
    cnps: &[Cnp],
    ns: &str,
    pod_labels: &BTreeMap<String, String>,
    pods: &[k8s_openapi::api::core::v1::Pod],
    alloc: &Alloc,
) -> (Vec<pb::PolicyRule>, Vec<pb::PolicyRule>, bool, bool) {
    let mut ingress = Vec::new();
    let mut egress = Vec::new();
    let (mut any_in, mut any_eg) = (false, false);
    for cnp in cnps {
        if cnp.namespace != ns || !selector_matches(&cnp.spec.endpoint_selector, pod_labels) {
            continue;
        }
        let expand = |rules: &[Rule],
                      peers_of: for<'r> fn(&'r Rule) -> (&'r [Selector], &'r [String]),
                      deny: bool| {
            let mut out = Vec::new();
            for rule in rules {
                let (peers, entities) = peers_of(rule);
                for id in peer_ids(peers, entities, ns, pods, alloc) {
                    for (proto, port) in rule_ports(rule) {
                        out.push(pb::PolicyRule {
                            identity: id,
                            proto: proto as u32,
                            port: port as u32,
                            deny,
                        });
                    }
                }
            }
            out
        };
        if !cnp.spec.ingress.is_empty() || !cnp.spec.ingress_deny.is_empty() {
            any_in = true;
            ingress.extend(expand(&cnp.spec.ingress, from_peers, false));
            ingress.extend(expand(&cnp.spec.ingress_deny, from_peers, true));
        }
        if !cnp.spec.egress.is_empty() || !cnp.spec.egress_deny.is_empty() {
            any_eg = true;
            egress.extend(expand(&cnp.spec.egress, to_peers, false));
            egress.extend(expand(&cnp.spec.egress_deny, to_peers, true));
        }
    }
    (ingress, egress, any_in, any_eg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn deny_and_entities_expand() {
        let spec: CnpSpec = serde_json::from_value(serde_json::json!({
            "endpointSelector": { "matchLabels": { "app": "web" } },
            "ingress": [ { "fromEntities": ["world"],
                           "toPorts": [ { "ports": [ { "port": "80", "protocol": "TCP" } ] } ] } ],
            "ingressDeny": [ { "fromEntities": ["host"] } ]
        }))
        .unwrap();
        let cnps = vec![Cnp {
            namespace: "default".into(),
            spec,
        }];
        let (ing, eg, any_in, any_eg) = endpoint_rules(
            &cnps,
            "default",
            &labels(&[("app", "web")]),
            &[],
            &Alloc::default(),
        );
        assert!(any_in && !any_eg && eg.is_empty());
        assert!(ing
            .iter()
            .any(|r| r.identity == IDENTITY_WORLD && r.proto == 6 && r.port == 80 && !r.deny));
        assert!(ing.iter().any(|r| r.identity == IDENTITY_HOST && r.deny));
    }

    #[test]
    fn non_matching_selector_is_skipped() {
        let spec: CnpSpec = serde_json::from_value(serde_json::json!({
            "endpointSelector": { "matchLabels": { "app": "db" } },
            "ingress": [ {} ]
        }))
        .unwrap();
        let cnps = vec![Cnp {
            namespace: "default".into(),
            spec,
        }];
        let (ing, _, any_in, _) = endpoint_rules(
            &cnps,
            "default",
            &labels(&[("app", "web")]),
            &[],
            &Alloc::default(),
        );
        assert!(!any_in && ing.is_empty());
    }
}
