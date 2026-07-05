//! cradle — user-space control plane for the cradle-rs eBPF data plane.
//!
//! `serve` loads the eBPF datapath and, optionally, applies a bootstrap JSON
//! config and/or serves the gRPC control API. `ctl` is the client that pushes
//! configuration to a running instance. The gRPC API is the seam the zebra-rs
//! routing control plane will eventually drive.

mod bench;
mod cilium;
mod cni;
mod config;
mod control;
mod ctl;
mod dataplane;
mod dir24;
mod grpc;
mod kernel;
mod l7;
mod pb;
mod util;

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aya::programs::SchedClassifier;
use clap::{Parser, Subcommand, ValueEnum};
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
    /// FIB lookup-latency harness (BPF_PROG_TEST_RUN; root, no attach) —
    /// large-fib.md's LPM vs DIR-24-8 numbers. Not CI-gating.
    FibBench(FibBenchArgs),
}

#[derive(Debug, Parser)]
struct FibBenchArgs {
    /// Routes to populate (DFZ-shaped distribution, deterministic per seed).
    #[arg(long, default_value_t = 1_000_000)]
    routes: u64,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Kernel-side iterations per probe address (the kernel reports avg ns).
    #[arg(long, default_value_t = 100_000)]
    repeat: u32,
    /// Engine to measure; omit to run both.
    #[arg(long, value_enum)]
    mode: Option<Fib4Mode>,
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
    /// Directory for persistent CNI state (IPAM allocations + endpoint
    /// records) — survives daemon restarts.
    #[arg(long, default_value = "/run/cradle")]
    state_dir: PathBuf,
    /// Serve the Cilium-agent-compatible REST API on this unix socket, so
    /// the stock cilium-cni plugin can drive this node (requires
    /// `--pod-cidr`). Typically /var/run/cilium/cilium.sock.
    #[arg(long)]
    cilium_sock: Option<PathBuf>,
    /// Pod CIDR the Cilium-compat IPAM allocates from.
    #[arg(long)]
    pod_cidr: Option<String>,
    /// IPv4 FIB engine: `lpm` (default) or `dir24` (DIR-24-8 direct-index —
    /// sizes TBL24/TBL8 at load; ~68 MiB, full-DFZ capacity). Load-time only;
    /// the JSON config's `fib4_mode` applies when this flag is not given.
    #[arg(long, value_enum)]
    fib4_mode: Option<Fib4Mode>,
}

/// IPv4 FIB engine selector (`docs/design/large-fib.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum Fib4Mode {
    Lpm,
    Dir24,
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
    /// Show the IPv4 FIB engine summary (mode, routes, TBL8 groups).
    Fib,
    /// Delete one IPv4 route.
    DelRoute {
        /// Prefix, e.g. "10.0.9.16/28".
        prefix: String,
    },
    /// Delete one L4 service by its (vip, port, proto) key.
    DelService {
        /// Service VIP, e.g. "10.96.0.10".
        vip: String,
        /// Service port.
        port: u16,
        /// Protocol: tcp or udp.
        #[arg(default_value = "tcp")]
        proto: String,
    },
    /// Generate and bulk-install a synthetic route table with a DFZ-like
    /// prefix-length distribution (deterministic per seed).
    GenRoutes {
        /// Number of routes to install.
        #[arg(long, default_value_t = 1_000_000)]
        count: u64,
        /// RNG seed (same seed => same table).
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Nexthop id every generated route points at (must exist).
        #[arg(long)]
        nexthop_id: u32,
        /// Routes per AddRoute4Batch RPC.
        #[arg(long, default_value_t = 8192)]
        chunk: usize,
    },
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
        Cmd::FibBench(args) => bench::run(args.mode, args.routes, args.seed, args.repeat),
    }
}

async fn serve(args: ServeArgs) -> Result<()> {
    if let Some(p) = &args.pid_file {
        std::fs::write(p, std::process::id().to_string())
            .with_context(|| format!("writing pid file {}", p.display()))?;
    }

    // Parse the bootstrap config *before* loading the eBPF object — the FIB
    // engine choice sizes maps at load time.
    let cfg = match &args.config {
        Some(path) => Some(Config::load(path)?),
        None => None,
    };
    let fib4_mode = match (
        args.fib4_mode,
        cfg.as_ref().and_then(|c| c.fib4_mode.as_deref()),
    ) {
        (Some(m), _) => m, // explicit flag wins
        (None, Some("dir24")) => Fib4Mode::Dir24,
        (None, Some("lpm")) | (None, None) => Fib4Mode::Lpm,
        (None, Some(other)) => anyhow::bail!("bad fib4_mode {other:?} (want lpm|dir24)"),
    };

    let mut loader = aya::EbpfLoader::new();
    if fib4_mode == Fib4Mode::Dir24 {
        // DIR-24-8: full-size direct-index tables (large-fib.md). In lpm
        // mode they stay at their declared 1 entry — no memory cost.
        loader
            .map_max_entries("TBL24", 1 << 24)
            .map_max_entries("TBL8", cradle_common::DIR24_TBL8_GROUPS * 256);
    }
    let mut bpf = loader
        .load(aya::include_bytes_aligned!(concat!(
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
        // Egress reverse-NAT stage (host-network service replies).
        let prog: &mut SchedClassifier = bpf
            .program_mut("cradle_egress")
            .context("program cradle_egress not found")?
            .try_into()?;
        prog.load().context("loading cradle_egress")?;
    }
    {
        // XDP stage — XDP, because a TC program cannot shrink an MPLS
        // frame (bpf_skb_adjust_room is IP-only). Attached per L3 port.
        let prog: &mut aya::programs::Xdp = bpf
            .program_mut("cradle_xdp")
            .context("program cradle_xdp not found")?
            .try_into()?;
        prog.load().context("loading cradle_xdp")?;
    }

    let mut dp = Dataplane::from_ebpf(&mut bpf)?;
    dp.meta_cookie_seed()?;
    if fib4_mode == Fib4Mode::Dir24 {
        dp.set_fib4_mode_dir24()?;
        info!("IPv4 FIB engine: dir24 (DIR-24-8 direct index)");
    }
    let control = Control::new(bpf, dp, args.state_dir.clone());

    if let Some(cfg) = &cfg {
        cfg.apply_control(&control).await?;
    }

    // Re-program persisted CNI endpoints into the fresh maps (restart
    // survival); completes deletes for pods torn down while we were dead.
    control.cni_reconcile().await;

    // Cilium-agent API compatibility shim: the stock cilium-cni plugin as a
    // drop-in front end for this node.
    if let Some(sock) = args.cilium_sock.clone() {
        let cidr = args
            .pod_cidr
            .clone()
            .context("--cilium-sock requires --pod-cidr")?;
        let c = control.clone();
        tokio::spawn(async move {
            if let Err(e) = cilium::serve(c, sock, cidr).await {
                tracing::warn!("cilium compat API stopped: {e:#}");
            }
        });
    }

    // Start the L7 transparent proxy (no-op for traffic until an L7 service is
    // configured; best-effort if the transparent bind is unavailable).
    control.start_l7_proxy().await;

    // Expire idle locally-learned MACs (default 300s; `fdb_age_secs: 0`
    // disables). WatchFdb subscribers see the removals as age events.
    control.start_fdb_aging(cfg.as_ref().map(|c| c.fdb_age_secs).unwrap_or(300));

    // Feed link carrier/admin transitions into the datapath so protected
    // nexthops fail over to their backups (TI-LFA fast-reroute).
    control.start_link_monitor();

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
