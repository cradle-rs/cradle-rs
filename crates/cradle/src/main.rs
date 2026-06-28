//! cradle — user-space control plane for the cradle-rs eBPF data plane.
//!
//! Phase 0 responsibilities: load the eBPF object and, if an interface is
//! given, attach the datapath classifier to its `clsact` ingress hook. Later
//! phases add map programming and the route-injection API that wires the
//! data plane to the zebra-rs routing control plane.

use anyhow::Context as _;
use aya::programs::{tc, SchedClassifier, TcAttachType};
use clap::Parser;
use tracing::{info, warn};

/// cradle-rs eBPF L2/L3/L4 data plane.
#[derive(Debug, Parser)]
#[command(name = "cradle", version)]
struct Cli {
    /// Interface to attach the datapath to (clsact ingress). If omitted, the
    /// object is loaded but not attached.
    #[arg(short, long)]
    iface: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    // The eBPF object is compiled by build.rs and embedded here.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/cradle-ebpf"
    )))
    .context("failed to load embedded eBPF object")?;

    match cli.iface.as_deref() {
        Some(iface) => {
            // clsact qdisc is idempotent-ish; ignore "already exists".
            if let Err(e) = tc::qdisc_add_clsact(iface) {
                warn!("qdisc_add_clsact({iface}): {e} (continuing; may already exist)");
            }
            let prog: &mut SchedClassifier = bpf
                .program_mut("cradle_tc")
                .context("program `cradle_tc` not found in object")?
                .try_into()?;
            prog.load().context("failed to load cradle_tc into kernel")?;
            prog.attach(iface, TcAttachType::Ingress)
                .with_context(|| format!("failed to attach cradle_tc to {iface}"))?;
            info!("cradle datapath attached to {iface} (clsact ingress)");
        }
        None => {
            info!("eBPF object loaded; no --iface given, so nothing attached");
        }
    }

    info!("cradle running — press Ctrl-C to exit");
    tokio::signal::ctrl_c().await?;
    info!("shutting down");
    Ok(())
}
