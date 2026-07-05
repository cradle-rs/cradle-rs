//! Hubble Observer API (H1 of `docs/design/hubble.md`).
//!
//! Drains the `FLOWS` eBPF ring buffer — one [`FlowRecord`] per forwarding
//! verdict the datapath reaches (FORWARDED / DROPPED) — enriches each record
//! into a Hubble [`flow::Flow`] (pod identity from the CNI endpoint store),
//! keeps the most recent ones in an in-memory ring, and serves the subset of
//! the `observer.Observer` gRPC service the stock `hubble` CLI drives over a
//! unix socket (`--hubble-sock`, typically `/var/run/cilium/hubble.sock`):
//! `GetFlows` (replay + `--follow`), `ServerStatus`, `GetNodes`,
//! `GetNamespaces`. `GetAgentEvents` / `GetDebugEvents` return empty streams
//! (cradle has no agent/debug event source yet). Field names and enum values
//! are pinned to Cilium v1.19.5 (`api/v1/observer`, `api/v1/flow`).

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result};
use aya::maps::{Map, MapData, RingBuf};
use tokio::io::unix::AsyncFd;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

use cradle_common::{
    FlowRecord, FLOW_DIR_EGRESS, FLOW_DIR_INGRESS, FLOW_DROPPED, FLOW_FORWARDED, FLOW_TRANSLATED,
};

use crate::control::Control;
use crate::hpb::observer::observer_server::{Observer, ObserverServer};
use crate::hpb::{flow, observer, relay};

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// How many recent flows the in-memory ring keeps (per node). `hubble observe`
/// replays from here; older flows age out.
const RING_CAP: usize = 8192;

/// Version string surfaced to the `hubble` CLI (`hubble status` / node list).
const HUBBLE_VERSION: &str = "1.19.5 (cradle)";

/// Shared observer state: the flow ring, a broadcast channel that fans new
/// flows out to `--follow` streams, and lifetime counters.
struct State {
    flows: Mutex<VecDeque<flow::Flow>>,
    tx: broadcast::Sender<flow::Flow>,
    seen: AtomicU64,
    start: SystemTime,
    node_name: String,
}

/// Serve the Hubble Observer API on `path` until the process exits, draining
/// `flows_map` (the `FLOWS` ring buffer taken from the loaded eBPF object) in
/// the background.
pub async fn serve(
    control: Control,
    path: PathBuf,
    flows_map: Map,
    node_name: String,
) -> Result<()> {
    let ring: RingBuf<MapData> =
        RingBuf::try_from(flows_map).context("FLOWS is not a ring buffer")?;
    let (tx, _rx) = broadcast::channel(1024);
    let state = Arc::new(State {
        flows: Mutex::new(VecDeque::with_capacity(RING_CAP)),
        tx,
        seen: AtomicU64::new(0),
        start: SystemTime::now(),
        node_name,
    });

    // Background: drain the ring buffer into the in-memory flow ring.
    {
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = drain_loop(ring, control, state).await {
                warn!("hubble flow drain stopped: {e:#}");
            }
        });
    }

    let _ = std::fs::remove_file(&path); // clear a stale socket
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let uds = tokio::net::UnixListener::bind(&path)
        .with_context(|| format!("binding {}", path.display()))?;
    let incoming = UnixListenerStream::new(uds);
    info!("serving Hubble Observer API on unix {}", path.display());
    Server::builder()
        .add_service(ObserverServer::new(ObserverSvc { state }))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

/// Poll the ring buffer for readability and drain every pending [`FlowRecord`]
/// each time it wakes. The CNI endpoint index is refreshed once per wake (pod
/// churn is far slower than the flow rate), then reused to enrich the batch.
async fn drain_loop(ring: RingBuf<MapData>, control: Control, state: Arc<State>) -> Result<()> {
    let mut afd = AsyncFd::new(ring)?;
    loop {
        let mut guard = afd.readable_mut().await?;
        let index = control.cni_ip_index().await;
        {
            let ring = guard.get_inner_mut();
            while let Some(item) = ring.next() {
                if item.len() < std::mem::size_of::<FlowRecord>() {
                    continue;
                }
                // The ring buffer holds `#[repr(C)]` `FlowRecord`s; the slot is
                // 8-byte aligned but read unaligned to be safe.
                let rec: FlowRecord =
                    unsafe { std::ptr::read_unaligned(item.as_ptr() as *const FlowRecord) };
                let f = build_flow(&rec, &index, &state.node_name);
                state.seen.fetch_add(1, Ordering::Relaxed);
                let _ = state.tx.send(f.clone()); // ok if no followers
                let mut q = state.flows.lock().await;
                if q.len() >= RING_CAP {
                    q.pop_front();
                }
                q.push_back(f);
            }
        }
        guard.clear_ready();
    }
}

/// Enrich one datapath record into a Hubble `Flow`.
fn build_flow(
    rec: &FlowRecord,
    index: &HashMap<Ipv4Addr, (String, String)>,
    node: &str,
) -> flow::Flow {
    let src = Ipv4Addr::from(rec.saddr);
    let dst = Ipv4Addr::from(rec.daddr);

    let verdict = match rec.verdict {
        FLOW_FORWARDED => flow::Verdict::Forwarded,
        FLOW_DROPPED => flow::Verdict::Dropped,
        FLOW_TRANSLATED => flow::Verdict::Translated,
        _ => flow::Verdict::Unknown,
    } as i32;
    let traffic_direction = match rec.dir {
        FLOW_DIR_INGRESS => flow::TrafficDirection::Ingress,
        FLOW_DIR_EGRESS => flow::TrafficDirection::Egress,
        _ => flow::TrafficDirection::Unknown,
    } as i32;

    let sport = u16::from_be(rec.sport) as u32;
    let dport = u16::from_be(rec.dport) as u32;
    let l4 = match rec.proto {
        IPPROTO_TCP => Some(flow::Layer4 {
            protocol: Some(flow::layer4::Protocol::Tcp(flow::Tcp {
                source_port: sport,
                destination_port: dport,
                flags: None,
            })),
        }),
        IPPROTO_UDP => Some(flow::Layer4 {
            protocol: Some(flow::layer4::Protocol::Udp(flow::Udp {
                source_port: sport,
                destination_port: dport,
            })),
        }),
        _ => None,
    };

    let endpoint = |ip: &Ipv4Addr| -> Option<flow::Endpoint> {
        index.get(ip).map(|(ns, pod)| flow::Endpoint {
            namespace: ns.clone(),
            pod_name: pod.clone(),
            ..Default::default()
        })
    };

    flow::Flow {
        time: Some(now_ts()),
        verdict,
        ip: Some(flow::Ip {
            source: src.to_string(),
            destination: dst.to_string(),
            ip_version: flow::IpVersion::IPv4 as i32,
            ..Default::default()
        }),
        l4,
        source: endpoint(&src),
        destination: endpoint(&dst),
        r#type: flow::FlowType::L3L4 as i32,
        node_name: node.to_string(),
        traffic_direction,
        ..Default::default()
    }
}

/// Wall-clock now as a protobuf timestamp. The record's `time_ns` is a
/// monotonic `ktime`, not wall time; flows are drained promptly, so stamping
/// at enrichment time is accurate to the millisecond for observability.
fn now_ts() -> ::prost_types::Timestamp {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    ::prost_types::Timestamp {
        seconds: d.as_secs() as i64,
        nanos: d.subsec_nanos() as i32,
    }
}

/// Wrap a `Flow` in the streaming response envelope.
fn wrap_flow(f: flow::Flow, node: &str) -> observer::GetFlowsResponse {
    observer::GetFlowsResponse {
        node_name: node.to_string(),
        time: f.time,
        response_types: Some(observer::get_flows_response::ResponseTypes::Flow(f)),
    }
}

struct ObserverSvc {
    state: Arc<State>,
}

impl ObserverSvc {
    fn uptime_ns(&self) -> u64 {
        SystemTime::now()
            .duration_since(self.state.start)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

type FlowStream =
    Pin<Box<dyn Stream<Item = Result<observer::GetFlowsResponse, Status>> + Send + 'static>>;
type AgentStream =
    Pin<Box<dyn Stream<Item = Result<observer::GetAgentEventsResponse, Status>> + Send + 'static>>;
type DebugStream =
    Pin<Box<dyn Stream<Item = Result<observer::GetDebugEventsResponse, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl Observer for ObserverSvc {
    type GetFlowsStream = FlowStream;
    type GetAgentEventsStream = AgentStream;
    type GetDebugEventsStream = DebugStream;

    async fn get_flows(
        &self,
        request: Request<observer::GetFlowsRequest>,
    ) -> Result<Response<Self::GetFlowsStream>, Status> {
        let req = request.into_inner();
        let follow = req.follow;
        let number = req.number as usize;
        let node = self.state.node_name.clone();

        // Subscribe before snapshotting the ring so no flow slips through the
        // gap between replay and follow (a rare duplicate is preferable).
        let mut sub = self.state.tx.subscribe();
        let replay: Vec<flow::Flow> = {
            let q = self.state.flows.lock().await;
            let n = if number == 0 || number > q.len() {
                q.len()
            } else {
                number
            };
            if req.first {
                q.iter().take(n).cloned().collect()
            } else {
                q.iter().skip(q.len() - n).cloned().collect()
            }
        };

        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            for f in replay {
                if tx.send(Ok(wrap_flow(f, &node))).await.is_err() {
                    return;
                }
            }
            if !follow {
                return;
            }
            loop {
                match sub.recv().await {
                    Ok(f) => {
                        if tx.send(Ok(wrap_flow(f, &node))).await.is_err() {
                            return;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }

    async fn server_status(
        &self,
        _request: Request<observer::ServerStatusRequest>,
    ) -> Result<Response<observer::ServerStatusResponse>, Status> {
        let num_flows = self.state.flows.lock().await.len() as u64;
        Ok(Response::new(observer::ServerStatusResponse {
            num_flows,
            max_flows: RING_CAP as u64,
            seen_flows: self.state.seen.load(Ordering::Relaxed),
            uptime_ns: self.uptime_ns(),
            num_connected_nodes: Some(1),
            num_unavailable_nodes: Some(0),
            unavailable_nodes: Vec::new(),
            version: HUBBLE_VERSION.to_string(),
            flows_rate: 0.0,
        }))
    }

    async fn get_nodes(
        &self,
        _request: Request<observer::GetNodesRequest>,
    ) -> Result<Response<observer::GetNodesResponse>, Status> {
        let num_flows = self.state.flows.lock().await.len() as u64;
        Ok(Response::new(observer::GetNodesResponse {
            nodes: vec![observer::Node {
                name: self.state.node_name.clone(),
                version: HUBBLE_VERSION.to_string(),
                address: String::new(),
                state: relay::NodeState::NodeConnected as i32,
                tls: None,
                uptime_ns: self.uptime_ns(),
                num_flows,
                max_flows: RING_CAP as u64,
                seen_flows: self.state.seen.load(Ordering::Relaxed),
            }],
        }))
    }

    async fn get_namespaces(
        &self,
        _request: Request<observer::GetNamespacesRequest>,
    ) -> Result<Response<observer::GetNamespacesResponse>, Status> {
        let mut set = BTreeSet::new();
        for f in self.state.flows.lock().await.iter() {
            for ep in [f.source.as_ref(), f.destination.as_ref()]
                .into_iter()
                .flatten()
            {
                if !ep.namespace.is_empty() {
                    set.insert(ep.namespace.clone());
                }
            }
        }
        let namespaces = set
            .into_iter()
            .map(|namespace| observer::Namespace {
                cluster: String::new(),
                namespace,
            })
            .collect();
        Ok(Response::new(observer::GetNamespacesResponse {
            namespaces,
        }))
    }

    async fn get_agent_events(
        &self,
        _request: Request<observer::GetAgentEventsRequest>,
    ) -> Result<Response<Self::GetAgentEventsStream>, Status> {
        debug!("hubble GetAgentEvents: no agent event source (returning empty)");
        Ok(Response::new(Box::pin(tokio_stream::empty())))
    }

    async fn get_debug_events(
        &self,
        _request: Request<observer::GetDebugEventsRequest>,
    ) -> Result<Response<Self::GetDebugEventsStream>, Status> {
        debug!("hubble GetDebugEvents: no debug event source (returning empty)");
        Ok(Response::new(Box::pin(tokio_stream::empty())))
    }
}
