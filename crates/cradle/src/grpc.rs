//! gRPC endpoint addressing — TCP or unix-domain socket.
//!
//! Accepts `tcp:host:port`, a bare `host:port` (treated as TCP), or a `unix:`
//! form:
//! - `unix:/abs/path.sock` — a filesystem-path Unix socket.
//! - `unix:NAME` (no leading `/`) — a Linux abstract Unix socket, whose name is
//!   scoped to the process network namespace. This is the default endpoint,
//!   `unix:cradle/grpc`, and mirrors zebra-rs's `unix:zebra-rs/vty`: per-netns
//!   cradle instances get a working control socket with no shared filesystem
//!   path to coordinate or clean up.
//!
//! tonic serves/dials filesystem UDS natively; abstract sockets have no path,
//! so they need a custom listener (see `control::bind_abstract_uds`) and a
//! custom client connector (`connect_abstract` below).

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use tonic::transport::{Channel, Endpoint};

#[derive(Clone, Debug)]
pub enum GrpcEndpoint {
    Tcp(SocketAddr),
    Uds(PathBuf),
    /// Linux abstract Unix socket, addressed by name (no filesystem entry).
    AbstractUds(String),
}

impl GrpcEndpoint {
    pub fn parse(s: &str) -> Result<Self> {
        if let Some(rest) = s.strip_prefix("unix:") {
            // A leading '/' is a filesystem path; any other name is a Linux
            // abstract socket (mirrors zebra-rs's `unix:NAME`).
            if rest.starts_with('/') {
                Ok(Self::Uds(PathBuf::from(rest)))
            } else {
                let name = rest.trim_start_matches('@');
                if name.is_empty() {
                    anyhow::bail!("empty unix socket name in {s:?}");
                }
                Ok(Self::AbstractUds(name.to_string()))
            }
        } else {
            let addr = s.strip_prefix("tcp:").unwrap_or(s);
            Ok(Self::Tcp(addr.parse().with_context(|| {
                format!("bad gRPC TCP address {addr:?}")
            })?))
        }
    }

    /// Human-readable endpoint string, for logging.
    pub fn uri(&self) -> String {
        match self {
            Self::Tcp(a) => format!("http://{a}"),
            Self::Uds(p) => format!("unix:{}", p.display()),
            Self::AbstractUds(name) => format!("unix:{name}"),
        }
    }

    /// Connect a tonic client channel to this endpoint.
    pub async fn connect(&self) -> Result<Channel> {
        match self {
            Self::Tcp(a) => Endpoint::try_from(format!("http://{a}"))?
                .connect()
                .await
                .with_context(|| format!("connecting to tcp {a}")),
            Self::Uds(p) => {
                let uri = format!("unix:{}", p.display());
                Endpoint::try_from(uri.clone())?
                    .connect()
                    .await
                    .with_context(|| format!("connecting to {uri}"))
            }
            Self::AbstractUds(name) => connect_abstract(name)
                .await
                .with_context(|| format!("connecting to unix:{name}")),
        }
    }
}

/// Dial a Linux abstract Unix socket by name. tonic has no built-in support
/// (its UDS connector calls `UnixStream::connect(path)`, which is filesystem
/// only), so we hand it a connector that ignores the placeholder URI and dials
/// the abstract address each time.
async fn connect_abstract(name: &str) -> Result<Channel> {
    use hyper_util::rt::TokioIo;
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr as StdSockAddr, UnixStream as StdUnixStream};
    use tokio::net::UnixStream;
    use tower::service_fn;

    let name = name.to_string();
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: tonic::transport::Uri| {
            let name = name.clone();
            async move {
                let addr = StdSockAddr::from_abstract_name(name.as_bytes())
                    .map_err(std::io::Error::other)?;
                let std = StdUnixStream::connect_addr(&addr)?;
                std.set_nonblocking(true)?;
                let stream = UnixStream::from_std(std)?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_abstract_by_default() {
        // No leading '/': the default and zebra-rs-style names are abstract.
        assert!(matches!(
            GrpcEndpoint::parse("unix:cradle/grpc").unwrap(),
            GrpcEndpoint::AbstractUds(n) if n == "cradle/grpc"
        ));
        // A leading '@' is the conventional abstract-socket sigil; strip it.
        assert!(matches!(
            GrpcEndpoint::parse("unix:@cradle/grpc").unwrap(),
            GrpcEndpoint::AbstractUds(n) if n == "cradle/grpc"
        ));
    }

    #[test]
    fn unix_absolute_path_is_filesystem() {
        assert!(matches!(
            GrpcEndpoint::parse("unix:/run/cradle/cradle.sock").unwrap(),
            GrpcEndpoint::Uds(p) if p == PathBuf::from("/run/cradle/cradle.sock")
        ));
    }

    #[test]
    fn tcp_forms() {
        assert!(matches!(
            GrpcEndpoint::parse("tcp:127.0.0.1:50151").unwrap(),
            GrpcEndpoint::Tcp(_)
        ));
        // A bare host:port is treated as TCP.
        assert!(matches!(
            GrpcEndpoint::parse("127.0.0.1:50151").unwrap(),
            GrpcEndpoint::Tcp(_)
        ));
    }

    #[test]
    fn empty_abstract_name_is_rejected() {
        assert!(GrpcEndpoint::parse("unix:").is_err());
        assert!(GrpcEndpoint::parse("unix:@").is_err());
    }
}
