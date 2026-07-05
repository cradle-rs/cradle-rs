//! Pure mapping from Kubernetes objects to the desired cradle service state.
//!
//! The desired state is `(vip, port, proto) → ordered backend set`. Rules:
//! a Service contributes one entry per TCP/UDP port when it has a parseable
//! IPv4 ClusterIP (headless and ExternalName services are skipped — nothing
//! to DNAT); backends come from the Service's IPv4 EndpointSlices, keeping
//! every ready endpoint. Both pod-backed and host-network / node-local
//! backends (e.g. the `default/kubernetes` API server) are programmed: the
//! clsact-egress reverse-NAT (K4) rewrites a node-local backend's reply back
//! to the VIP as it leaves toward the client, so those services no longer
//! need kube-proxy. Backend target ports resolve the EndpointSlice way: match
//! the slice port whose *name* equals the service port's name (Kubernetes has
//! already resolved named/int targetPorts into the slice's port numbers).

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use k8s_openapi::api::core::v1::Service;
use k8s_openapi::api::discovery::v1::EndpointSlice;

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

/// A cradle service key: (VIP, port, IP proto).
pub type Key = (Ipv4Addr, u16, u8);
/// A programmed service: its backend set + ClientIP session affinity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Svc {
    pub backends: BTreeSet<(Ipv4Addr, u16)>,
    pub affinity: bool,
}
/// Desired state: service key → service.
pub type Desired = BTreeMap<Key, Svc>;

pub fn proto_str(proto: u8) -> &'static str {
    if proto == UDP {
        "udp"
    } else {
        "tcp"
    }
}

/// Stable nonzero backend-slot namespace for a service key (FNV-1a/32 of the
/// canonical `vip:port/proto` string).
pub fn svc_id(key: &Key) -> u32 {
    let s = format!("{}:{}/{}", key.0, key.1, key.2);
    let mut hash: u32 = 0x811c_9dc5;
    for b in s.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash.max(1)
}

fn parse_proto(p: Option<&str>) -> Option<u8> {
    match p.unwrap_or("TCP") {
        "TCP" => Some(TCP),
        "UDP" => Some(UDP),
        _ => None, // SCTP etc. — not supported by the datapath
    }
}

/// Normalized port-name equality: `None` and `""` both mean "unnamed".
fn name_eq(a: Option<&str>, b: Option<&str>) -> bool {
    a.unwrap_or("") == b.unwrap_or("")
}

pub fn build_desired(
    services: &[Service],
    slices: &[EndpointSlice],
    node_ip: Option<Ipv4Addr>,
) -> Desired {
    let mut out = Desired::new();
    for svc in services {
        let Some(spec) = &svc.spec else { continue };
        if spec.type_.as_deref() == Some("ExternalName") {
            continue;
        }
        let Some(vip) = spec
            .cluster_ip
            .as_deref()
            .filter(|ip| *ip != "None" && !ip.is_empty())
            .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        else {
            continue;
        };
        let ns = svc.metadata.namespace.as_deref().unwrap_or("default");
        let name = svc.metadata.name.as_deref().unwrap_or_default();

        let svc_slices: Vec<&EndpointSlice> = slices
            .iter()
            .filter(|s| {
                s.metadata.namespace.as_deref() == Some(ns)
                    && s.address_type == "IPv4"
                    && s.metadata
                        .labels
                        .as_ref()
                        .and_then(|l| l.get("kubernetes.io/service-name"))
                        .map(|v| v == name)
                        .unwrap_or(false)
            })
            .collect();

        for sp in spec.ports.as_deref().unwrap_or_default() {
            let Some(proto) = parse_proto(sp.protocol.as_deref()) else {
                continue;
            };
            let port = match u16::try_from(sp.port) {
                Ok(p) if p != 0 => p,
                _ => continue,
            };
            let mut backends = BTreeSet::new();
            for slice in &svc_slices {
                // The slice port with the same *name* carries the resolved
                // target port number for this service port.
                let target = slice
                    .ports
                    .as_deref()
                    .unwrap_or_default()
                    .iter()
                    .find(|ep| {
                        name_eq(ep.name.as_deref(), sp.name.as_deref())
                            && parse_proto(ep.protocol.as_deref()) == Some(proto)
                    })
                    .and_then(|ep| ep.port)
                    .and_then(|p| u16::try_from(p).ok());
                let Some(target) = target else { continue };
                for ep in slice.endpoints.as_deref().unwrap_or_default() {
                    if ep.conditions.as_ref().and_then(|c| c.ready) == Some(false) {
                        continue;
                    }
                    // Both pod-backed and host-network / node-local backends
                    // are programmed: the latter's replies come from the
                    // node's own stack, and the clsact-egress reverse-NAT
                    // (K4) rewrites them back to the VIP as they leave toward
                    // the client. This is what lets `default/kubernetes` (the
                    // API server) be served with kube-proxy off.
                    for addr in &ep.addresses {
                        if let Ok(ip) = addr.parse::<Ipv4Addr>() {
                            backends.insert((ip, target));
                        }
                    }
                }
            }
            // No Pod-backed endpoints (host-network services, or a drained
            // rollout) ⇒ don't program the VIP at all: traffic falls through
            // the datapath untouched (kube-proxy can serve it), and a
            // previously-programmed service gets a DelService.
            if backends.is_empty() {
                continue;
            }
            let affinity = spec.session_affinity.as_deref() == Some("ClientIP");
            let svc = Svc { backends, affinity };
            // NodePort/LoadBalancer: also expose the service on the node's
            // own IP at `nodePort`. The node IP is a local address, but
            // l4_nat's SERVICES lookup runs before the local-punt, so the
            // same backend set is reachable at <nodeIP>:<nodePort> with no
            // datapath change (the reverse-SNAT rewrites replies back to
            // nodeIP:nodePort — externalTrafficPolicy Local / source-
            // preserving; cross-node Cluster policy is a follow-on).
            if let (Some(node), Ok(np)) = (node_ip, u16::try_from(sp.node_port.unwrap_or(0))) {
                if np != 0 {
                    out.insert((node, np, proto), svc.clone());
                }
            }
            out.insert((vip, port, proto), svc);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::{ObjectReference, ServicePort, ServiceSpec};
    use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

    fn service(
        ns: &str,
        name: &str,
        cluster_ip: &str,
        ports: Vec<ServicePort>,
        type_: Option<&str>,
    ) -> Service {
        Service {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(name.into()),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some(cluster_ip.into()),
                ports: Some(ports),
                type_: type_.map(String::from),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn sport(name: Option<&str>, port: i32, proto: &str) -> ServicePort {
        ServicePort {
            name: name.map(String::from),
            port,
            protocol: Some(proto.into()),
            ..Default::default()
        }
    }

    fn endpoint(addr: &str, ready: Option<bool>, kind: Option<&str>) -> Endpoint {
        Endpoint {
            addresses: vec![addr.into()],
            conditions: ready.map(|r| EndpointConditions {
                ready: Some(r),
                ..Default::default()
            }),
            target_ref: kind.map(|k| ObjectReference {
                kind: Some(k.into()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn slice(
        ns: &str,
        svc: &str,
        endpoints: Vec<Endpoint>,
        ports: Vec<(Option<&str>, i32)>,
    ) -> EndpointSlice {
        EndpointSlice {
            metadata: ObjectMeta {
                namespace: Some(ns.into()),
                name: Some(format!("{svc}-abc")),
                labels: Some(
                    [("kubernetes.io/service-name".to_string(), svc.to_string())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
            address_type: "IPv4".into(),
            endpoints: Some(endpoints),
            ports: Some(
                ports
                    .into_iter()
                    .map(|(name, port)| EndpointPort {
                        name: name.map(String::from),
                        port: Some(port),
                        protocol: Some("TCP".into()),
                        ..Default::default()
                    })
                    .collect(),
            ),
        }
    }

    #[test]
    fn maps_ready_pod_backends() {
        let svcs = vec![service(
            "default",
            "web",
            "10.96.0.10",
            vec![sport(None, 80, "TCP")],
            None,
        )];
        let slices = vec![slice(
            "default",
            "web",
            vec![
                endpoint("10.244.0.2", Some(true), Some("Pod")),
                endpoint("10.244.0.3", None, Some("Pod")), // ready unset counts as ready
            ],
            vec![(None, 8080)],
        )];
        let desired = build_desired(&svcs, &slices, None);
        let key = ("10.96.0.10".parse().unwrap(), 80u16, TCP);
        let backends = &desired.get(&key).unwrap().backends;
        assert_eq!(backends.len(), 2);
        assert!(backends.contains(&("10.244.0.2".parse().unwrap(), 8080)));
    }

    #[test]
    fn nodeport_adds_a_node_ip_frontend() {
        let mut sp = sport(None, 80, "TCP");
        sp.node_port = Some(31000);
        let svcs = vec![service(
            "default",
            "web",
            "10.96.0.10",
            vec![sp],
            Some("NodePort"),
        )];
        let slices = vec![slice(
            "default",
            "web",
            vec![endpoint("10.244.0.2", Some(true), Some("Pod"))],
            vec![(None, 8080)],
        )];
        let node: Ipv4Addr = "172.18.0.2".parse().unwrap();
        let desired = build_desired(&svcs, &slices, Some(node));
        // ClusterIP frontend + node-IP:nodePort frontend, same backend.
        let cluster = &desired
            .get(&("10.96.0.10".parse().unwrap(), 80, TCP))
            .unwrap()
            .backends;
        let np = &desired.get(&(node, 31000, TCP)).unwrap().backends;
        assert_eq!(cluster, np);
        // A ClientIP-affinity service carries the flag through both frontends.
        let mut sp2 = sport(None, 80, "TCP");
        sp2.node_port = Some(31001);
        let mut aff_svc = service("default", "web", "10.96.0.11", vec![sp2], Some("NodePort"));
        aff_svc.spec.as_mut().unwrap().session_affinity = Some("ClientIP".into());
        let aff = build_desired(&[aff_svc], &slices, Some(node));
        assert!(aff.values().all(|s| s.affinity));
        assert!(np.contains(&("10.244.0.2".parse().unwrap(), 8080)));
        // Without a known node IP, only the ClusterIP frontend is emitted.
        assert_eq!(build_desired(&svcs, &slices, None).len(), 1);
    }

    #[test]
    fn programs_host_network_backend_skips_not_ready() {
        let svcs = vec![service(
            "default",
            "kubernetes",
            "10.96.0.1",
            vec![sport(Some("https"), 443, "TCP")],
            None,
        )];
        let slices = vec![slice(
            "default",
            "kubernetes",
            vec![
                endpoint("172.18.0.2", Some(true), None), // API server: host-network, no Pod ref
                endpoint("172.18.0.3", Some(false), None), // not ready — dropped
            ],
            vec![(Some("https"), 6443)],
        )];
        let desired = build_desired(&svcs, &slices, None);
        // The host-network backend IS programmed now (K4: the egress
        // reverse-NAT makes its reply return through cradle).
        let key = ("10.96.0.1".parse().unwrap(), 443u16, TCP);
        let backends = &desired.get(&key).unwrap().backends;
        assert_eq!(backends.len(), 1);
        assert!(backends.contains(&("172.18.0.2".parse().unwrap(), 6443)));
    }

    #[test]
    fn resolves_named_ports_per_slice() {
        let svcs = vec![service(
            "prod",
            "api",
            "10.96.1.1",
            vec![
                sport(Some("http"), 80, "TCP"),
                sport(Some("metrics"), 9100, "TCP"),
            ],
            None,
        )];
        let slices = vec![slice(
            "prod",
            "api",
            vec![endpoint("10.244.1.5", Some(true), Some("Pod"))],
            vec![(Some("http"), 8080), (Some("metrics"), 19100)],
        )];
        let desired = build_desired(&svcs, &slices, None);
        let http = &desired
            .get(&("10.96.1.1".parse().unwrap(), 80, TCP))
            .unwrap()
            .backends;
        assert!(http.contains(&("10.244.1.5".parse().unwrap(), 8080)));
        let metrics = &desired
            .get(&("10.96.1.1".parse().unwrap(), 9100, TCP))
            .unwrap()
            .backends;
        assert!(metrics.contains(&("10.244.1.5".parse().unwrap(), 19100)));
    }

    #[test]
    fn skips_headless_and_external_name() {
        let svcs = vec![
            service("default", "hl", "None", vec![sport(None, 80, "TCP")], None),
            service(
                "default",
                "ext",
                "",
                vec![sport(None, 80, "TCP")],
                Some("ExternalName"),
            ),
        ];
        assert!(build_desired(&svcs, &[], None).is_empty());
    }

    #[test]
    fn svc_id_stable_and_nonzero() {
        let key = ("10.96.0.10".parse().unwrap(), 80u16, TCP);
        assert_eq!(svc_id(&key), svc_id(&key));
        assert_ne!(svc_id(&key), 0);
    }
}
