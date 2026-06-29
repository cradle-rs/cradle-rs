//! gRPC endpoint addressing — TCP or unix-domain socket.
//!
//! Accepts `unix:/path/to.sock`, `tcp:host:port`, or a bare `host:port`
//! (treated as TCP). tonic has built-in UDS support on both ends: the server
//! serves over a `UnixListener`, and the client connects with a `unix:` URI.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context as _, Result};

#[derive(Clone, Debug)]
pub enum GrpcEndpoint {
    Tcp(SocketAddr),
    Uds(PathBuf),
}

impl GrpcEndpoint {
    pub fn parse(s: &str) -> Result<Self> {
        if let Some(path) = s.strip_prefix("unix:") {
            Ok(Self::Uds(PathBuf::from(path)))
        } else {
            let addr = s.strip_prefix("tcp:").unwrap_or(s);
            Ok(Self::Tcp(
                addr.parse()
                    .with_context(|| format!("bad gRPC TCP address {addr:?}"))?,
            ))
        }
    }

    /// URI string for tonic's client `connect` (handles the `unix:` scheme).
    pub fn connect_uri(&self) -> String {
        match self {
            Self::Tcp(a) => format!("http://{a}"),
            Self::Uds(p) => format!("unix:{}", p.display()),
        }
    }
}
