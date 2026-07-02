//! cradle — user-space control plane for the cradle-rs eBPF data plane.
//!
//! `serve` loads the eBPF datapath and, optionally, applies a bootstrap JSON
//! config and/or serves the gRPC control API. `ctl` is the client that pushes
//! configuration to a running instance. The gRPC API is the seam the zebra-rs
//! routing control plane will eventually drive.

mod config;
mod control;
mod ctl;
mod dataplane;
mod grpc;
mod kernel;
mod l7;
mod pb;
mod util;

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aya::programs::SchedClassifier;
use clap::{Parser, Subcommand};
use tracing::info;

use crate::{config::Config, control::Control, dataplane::Dataplane, grpc::GrpcEndpoint};

#[derive(Debug, Parser)]
#[command(name = "cradle", version, about = "cradle-rs eBPF L2/L3/L4 data plane")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Load the data plane; optionally apply a bootstrap config and/or serve the
    /// gRPC control API.
    Serve(ServeArgs),
    /// Control-plane client: push configuration to a running cradle.
    Ctl(CtlArgs),
}

#[derive(Debug, Parser)]
struct ServeArgs {
    /// Bootstrap JSON config applied at startup.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Serve the gRPC control API. `unix:/path/to.sock` or `tcp:127.0.0.1:50151`
    /// (a bare `host:port` is treated as TCP).
    #[arg(short, long)]
    grpc: Option<String>,
    /// Write this process's PID to this file at startup (for test harnesses).
    #[arg(long)]
    pid_file: Option<PathBuf>,
}

#[derive(Debug, Parser)]
struct CtlArgs {
    /// gRPC server endpoint: `unix:/path/to.sock` or `tcp:127.0.0.1:50151`.
    #[arg(short, long)]
    grpc: String,
    #[command(subcommand)]
    op: CtlOp,
}

#[derive(Debug, Subcommand)]
pub enum CtlOp {
    /// Apply a JSON config to the running data plane.
    Apply {
        /// Path to the JSON config.
        config: PathBuf,
    },
    /// Dump the data-plane packet counters.
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        Cmd::Serve(args) => serve(args).await,
        Cmd::Ctl(args) => ctl::run(GrpcEndpoint::parse(&args.grpc)?, args.op).await,
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    if let Some(p) = &args.pid_file {
        std::fs::write(p, std::process::id().to_string())
            .with_context(|| format!("writing pid file {}", p.display()))?;
    }

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cradle-ebpf"
    )))
    .context("failed to load embedded eBPF object")?;

    {
        let prog: &mut SchedClassifier = bpf
            .program_mut("cradle_tc")
            .context("program cradle_tc not found")?
            .try_into()?;
        prog.load().context("loading cradle_tc")?;
    }
    {
        // MPLS pop stage — XDP, because a TC program cannot shrink an MPLS
        // frame (bpf_skb_adjust_room is IP-only). Attached per L3 port.
        let prog: &mut aya::programs::Xdp = bpf
            .program_mut("cradle_mpls_pop")
            .context("program cradle_mpls_pop not found")?
            .try_into()?;
        prog.load().context("loading cradle_mpls_pop")?;
    }

    let dp = Dataplane::from_ebpf(&mut bpf)?;
    let control = Control::new(bpf, dp);

    if let Some(path) = &args.config {
        Config::load(path)?.apply_control(&control).await?;
    }

    // Start the L7 transparent proxy (no-op for traffic until an L7 service is
    // configured; best-effort if the transparent bind is unavailable).
    control.start_l7_proxy().await;

    match args.grpc {
        Some(s) => control.serve(GrpcEndpoint::parse(&s)?).await?, // runs until Ctrl-C
        None => {
            info!("cradle running — press Ctrl-C to exit");
            tokio::signal::ctrl_c().await?;
        }
    }

    info!("shutting down");
    Ok(())
}
