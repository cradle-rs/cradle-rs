//! cradle — user-space control plane for the cradle-rs eBPF data plane.
//!
//! Phase 1: load the L3 datapath, attach it to the configured L3 ports'
//! `clsact` ingress hooks, and program the FIB / nexthop / neighbor / port maps
//! from a static JSON config. Later phases replace the static config with a
//! gRPC/unix-socket route-injection API and the zebra-rs control plane.

mod config;
mod dataplane;
mod util;

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aya::programs::{tc, SchedClassifier, TcAttachType};
use clap::Parser;
use tracing::{info, warn};

use crate::{config::Config, dataplane::Dataplane};

#[derive(Debug, Parser)]
#[command(name = "cradle", version, about = "cradle-rs eBPF L2/L3/L4 data plane")]
struct Cli {
    /// JSON config: ports, nexthops, routes, neighbors.
    #[arg(short, long)]
    config: Option<PathBuf>,
    /// Extra interface(s) to attach to (clsact ingress), in addition to the
    /// config's L3 ports. Repeatable.
    #[arg(short, long)]
    iface: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let cfg = match &cli.config {
        Some(p) => Some(Config::load(p)?),
        None => None,
    };

    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cradle-ebpf"
    )))
    .context("failed to load embedded eBPF object")?;

    // Load the classifier once.
    {
        let prog: &mut SchedClassifier = bpf
            .program_mut("cradle_tc")
            .context("program `cradle_tc` not found")?
            .try_into()?;
        prog.load().context("loading cradle_tc")?;
    }

    // Attach to every L3 port from the config, plus any explicit --iface.
    let mut attach: Vec<String> = Vec::new();
    if let Some(cfg) = &cfg {
        attach.extend(cfg.port_names().map(str::to_owned));
    }
    attach.extend(cli.iface.iter().cloned());
    if attach.is_empty() {
        warn!("no interfaces to attach to (no --iface and no L3 ports in config)");
    }
    for name in &attach {
        if let Err(e) = tc::qdisc_add_clsact(name) {
            warn!("qdisc_add_clsact({name}): {e} (continuing; may already exist)");
        }
        let prog: &mut SchedClassifier = bpf
            .program_mut("cradle_tc")
            .context("program `cradle_tc` not found")?
            .try_into()?;
        prog.attach(name, TcAttachType::Ingress)
            .with_context(|| format!("attaching to {name}"))?;
        info!("attached cradle datapath to {name} (clsact ingress)");
    }

    // Program the maps (after attach, so relocations are resolved).
    let mut dp = Dataplane::from_ebpf(&mut bpf)?;
    if let Some(cfg) = &cfg {
        cfg.apply(&mut dp)?;
    }

    info!("cradle running — press Ctrl-C to exit");
    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
