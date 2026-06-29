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

/// Maps an L7 VIP:port to its ordered path-prefix routes. Shared between the
/// control plane (which populates it) and the proxy (which reads it).
#[derive(Default)]
pub struct RouteTable {
    services: HashMap<(IpAddr, u16), Vec<L7Route>>,
}

impl RouteTable {
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

    // Read the request head (request line + headers) to route on path/host.
    let mut head = vec![0u8; 8192];
    let n = client.read(&mut head).await.context("read request")?;
    head.truncate(n);
    let (method, path, host) = parse_request(&head);

    let backend = match routes.lock().await.choose(orig, &path) {
        Some(b) => b,
        None => return Ok(()), // unconfigured / no matching route
    };
    info!("L7 {method} {path} Host={host:?} {orig} -> {backend}");

    let mut upstream = TcpStream::connect(backend)
        .await
        .with_context(|| format!("connecting upstream {backend}"))?;
    upstream.write_all(&head).await.context("forward head")?;
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
