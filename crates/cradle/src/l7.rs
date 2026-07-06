//! User-space L7 (HTTP) transparent proxy.
//!
//! The eBPF datapath steers TCP flows destined to an L7-marked VIP to this
//! proxy via `bpf_sk_assign` (see `l7_redirect` in cradle-ebpf). The proxy binds
//! `IP_TRANSPARENT`, so an accepted connection's *local* address is the original
//! VIP:port the client targeted — we read it with `local_addr()`, pick a backend
//! by HTTP path, and splice the two connections together.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use socket2::{Domain, Socket, Type};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, warn};

use cradle_common::L7_PROXY_PORT;

/// One L7 routing rule: an HTTP path prefix → backend.
#[derive(Clone, Debug)]
pub struct L7Route {
    pub prefix: String,
    pub backend: SocketAddr,
}

/// One allowed HTTP request shape (empty method/path = any). `path` is a
/// regex matched against the whole request path (Cilium semantics). This is
/// the wire/config form; the proxy precompiles it into a [`CompiledRule`].
#[derive(Clone, Debug)]
pub struct L7PolicyRule {
    pub method: String,
    pub path: String,
}

/// An HTTP request the proxy handled under an L7 policy — emitted to Hubble
/// as an L7 (HTTP) flow record. `allowed` is the policy verdict (false = the
/// empty-403).
#[derive(Clone, Debug)]
pub struct L7Event {
    pub client: SocketAddr,
    pub dst: SocketAddr,
    pub method: String,
    pub path: String,
    pub allowed: bool,
}

/// Sink the proxy pushes [`L7Event`]s into (Hubble registers the receiver).
pub type L7Sink = tokio::sync::mpsc::UnboundedSender<L7Event>;

/// A precompiled allow-rule: `path` full-matches the request path. A rule
/// whose regex failed to compile falls back to `exact` string equality
/// (fail closed toward the literal, never silently open).
struct CompiledRule {
    method: String,
    path: Option<regex::Regex>,
    exact: String,
}

impl CompiledRule {
    fn compile(r: &L7PolicyRule) -> Self {
        let path = if r.path.is_empty() {
            None
        } else {
            match regex::Regex::new(&format!("^(?:{})$", r.path)) {
                Ok(re) => Some(re),
                Err(e) => {
                    tracing::warn!("L7 policy: bad path regex {:?}: {e} (exact match)", r.path);
                    None
                }
            }
        };
        Self {
            method: r.method.clone(),
            path,
            exact: r.path.clone(),
        }
    }

    fn matches(&self, method: &str, path: &str) -> bool {
        let method_ok = self.method.is_empty() || self.method == method;
        let path_ok = match &self.path {
            _ if self.exact.is_empty() => true,
            Some(re) => re.is_match(path),
            None => path == self.exact, // regex failed to compile
        };
        method_ok && path_ok
    }
}

/// Maps an L7 VIP:port to its ordered path routes. Shared between the
/// control plane (which populates it) and the proxy (which reads it).
#[derive(Default)]
pub struct RouteTable {
    /// Ingress L7 policy allow-lists keyed by the *original* destination
    /// (the pod ip:port), precompiled. A steered flow matching no rule is
    /// answered with an empty 403 and closed; a match proxies to the
    /// original destination transparently (docs/design/policy.md phase 5).
    policies: std::collections::HashMap<SocketAddr, Vec<CompiledRule>>,
    services: HashMap<(IpAddr, u16), Vec<L7Route>>,
    /// Where the proxy reports handled requests for Hubble L7 flows; `None`
    /// until the Hubble server registers it.
    hubble_sink: Option<L7Sink>,
}

impl RouteTable {
    pub fn set_policy(&mut self, dst: SocketAddr, rules: Vec<L7PolicyRule>) {
        self.policies
            .insert(dst, rules.iter().map(CompiledRule::compile).collect());
    }

    /// Register the Hubble L7 flow sink (called once when the Hubble API
    /// starts).
    pub fn set_hubble_sink(&mut self, sink: L7Sink) {
        self.hubble_sink = Some(sink);
    }

    pub fn del_policy(&mut self, dst: &SocketAddr) {
        self.policies.remove(dst);
    }

    /// The policy verdict for a request to `dst`: None = no L7 policy
    /// (fall through to routing), Some(true) = allowed, Some(false) = 403.
    fn policy_verdict(&self, dst: &SocketAddr, method: &str, path: &str) -> Option<bool> {
        let rules = self.policies.get(dst)?;
        Some(rules.iter().any(|r| r.matches(method, path)))
    }

    pub fn add(&mut self, vip: IpAddr, port: u16, routes: Vec<L7Route>) {
        self.services.insert((vip, port), routes);
    }

    /// Longest path-prefix match for `dst`'s service; falls back to the first
    /// route. `None` if `dst` is not a configured L7 service.
    fn choose(&self, dst: SocketAddr, path: &str) -> Option<SocketAddr> {
        let routes = self.services.get(&(dst.ip(), dst.port()))?;
        let best = routes
            .iter()
            .filter(|r| path.starts_with(&r.prefix))
            .max_by_key(|r| r.prefix.len())
            .or_else(|| routes.first())?;
        Some(best.backend)
    }
}

pub type SharedRoutes = Arc<Mutex<RouteTable>>;

/// Bind a transparent TCP listener on `0.0.0.0:L7_PROXY_PORT` and spawn the
/// accept loop. Returns an error if the transparent bind fails (needs
/// CAP_NET_ADMIN); callers treat that as "L7 disabled" rather than fatal.
pub async fn spawn_proxy(routes: SharedRoutes) -> Result<()> {
    let sock = Socket::new(Domain::IPV4, Type::STREAM, None).context("socket")?;
    sock.set_reuse_address(true)?;
    sock.set_ip_transparent(true)
        .context("set IP_TRANSPARENT (needs CAP_NET_ADMIN)")?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = (Ipv4Addr::UNSPECIFIED, L7_PROXY_PORT).into();
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    let listener = TcpListener::from_std(sock.into())?;
    info!("L7 transparent proxy listening on {addr}");

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((client, _)) => {
                    let routes = routes.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle(client, routes).await {
                            warn!("L7 proxy connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    warn!("L7 proxy accept error: {e}");
                    break;
                }
            }
        }
    });
    Ok(())
}

async fn handle(mut client: TcpStream, routes: SharedRoutes) -> Result<()> {
    // Transparent accept: the socket's local address is the original VIP:port.
    let orig = client.local_addr().context("original destination")?;
    let peer = client.peer_addr().ok();

    // Read the request head (request line + headers) to route on path/host.
    let mut head = vec![0u8; 8192];
    let n = client.read(&mut head).await.context("read request")?;
    head.truncate(n);
    let (method, path, host) = parse_request(&head);
    // Ingress L7 policy: enforce the allow-list before any routing.
    let (verdict, sink) = {
        let rt = routes.lock().await;
        (
            rt.policy_verdict(&orig, &method, &path),
            rt.hubble_sink.clone(),
        )
    };
    // Report the HTTP request to Hubble as an L7 flow (policy-observed only).
    if let (Some(allowed), Some(sink), Some(peer)) = (verdict, &sink, peer) {
        let _ = sink.send(L7Event {
            client: peer,
            dst: orig,
            method: method.clone(),
            path: path.clone(),
            allowed,
        });
    }
    match verdict {
        Some(true) => {
            info!("L7 policy allow {method} {path} -> {orig}");
            return splice_to(client, orig, &head).await;
        }
        Some(false) => {
            info!("L7 policy deny {method} {path} -> {orig} (403)");
            let _ = client
                .write_all(
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        }
        None => {}
    }

    let backend = match routes.lock().await.choose(orig, &path) {
        Some(b) => b,
        None => return Ok(()), // unconfigured / no matching route
    };
    info!("L7 {method} {path} Host={host:?} {orig} -> {backend}");
    splice_to(client, backend, &head).await
}

/// Connect to `backend`, replay the buffered request head, splice the rest.
async fn splice_to(mut client: TcpStream, backend: SocketAddr, head: &[u8]) -> Result<()> {
    let mut upstream = TcpStream::connect(backend)
        .await
        .with_context(|| format!("connecting upstream {backend}"))?;
    upstream.write_all(head).await.context("forward head")?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream)
        .await
        .context("proxy copy")?;
    Ok(())
}

/// Best-effort parse of `METHOD PATH HTTP/x` plus the `Host:` header.
fn parse_request(head: &[u8]) -> (String, String, Option<String>) {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split_whitespace();
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("/").to_string();
    let host = lines
        .find(|l| l.len() >= 5 && l[..5].eq_ignore_ascii_case("host:"))
        .map(|l| l[5..].trim().to_string());
    (method, path, host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_verdict_matches_method_and_path_regex() {
        let mut rt = RouteTable::default();
        let dst: SocketAddr = "10.0.0.2:8080".parse().unwrap();
        rt.set_policy(
            dst,
            vec![L7PolicyRule {
                method: "GET".into(),
                // Full-match regex: exact `/allowed`, or anything under it.
                path: "/allowed(/.*)?".into(),
            }],
        );
        assert_eq!(rt.policy_verdict(&dst, "GET", "/allowed"), Some(true));
        assert_eq!(rt.policy_verdict(&dst, "GET", "/allowed/x"), Some(true));
        // Full match: `/allowedfoo` is NOT under `/allowed(/.*)?`.
        assert_eq!(rt.policy_verdict(&dst, "GET", "/allowedfoo"), Some(false));
        assert_eq!(rt.policy_verdict(&dst, "GET", "/secret"), Some(false));
        assert_eq!(rt.policy_verdict(&dst, "POST", "/allowed"), Some(false));
        let other: SocketAddr = "10.0.0.3:8080".parse().unwrap();
        assert_eq!(rt.policy_verdict(&other, "GET", "/allowed"), None);
        rt.del_policy(&dst);
        assert_eq!(rt.policy_verdict(&dst, "GET", "/allowed"), None);
    }

    #[test]
    fn bad_regex_falls_back_to_exact() {
        let mut rt = RouteTable::default();
        let dst: SocketAddr = "10.0.0.2:8080".parse().unwrap();
        rt.set_policy(
            dst,
            vec![L7PolicyRule {
                method: String::new(),
                path: "/a[".into(), // invalid regex
            }],
        );
        assert_eq!(rt.policy_verdict(&dst, "GET", "/a["), Some(true));
        assert_eq!(rt.policy_verdict(&dst, "GET", "/a"), Some(false));
    }
}
