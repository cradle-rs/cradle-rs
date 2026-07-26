//! Build script: (1) compile the gRPC control API proto, and (2) compile the
//! `cradle-ebpf` crate to `bpfel-unknown-none` (embedded by `main.rs`).

use anyhow::Context as _;
use aya_build::{Package, Toolchain};

/// The workspace toolchain pin, and the only place the channel is named.
const TOOLCHAIN_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../rust-toolchain.toml");

/// Extract the `channel = "..."` value from `rust-toolchain.toml`.
///
/// `aya_build` shells out to `rustup run <toolchain> cargo build` for the eBPF
/// crate and does not consult `rust-toolchain.toml`, so the channel has to be
/// handed to it explicitly. Reading it back out of the pin file keeps one
/// source of truth: bumping the pin moves the host build and the eBPF build
/// together, instead of leaving a second copy of the date here to drift.
fn toolchain_channel() -> anyhow::Result<String> {
    let text = std::fs::read_to_string(TOOLCHAIN_FILE)
        .with_context(|| format!("failed to read {TOOLCHAIN_FILE}"))?;
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let value = line
                .strip_prefix("channel")?
                .trim_start()
                .strip_prefix('=')?;
            Some(value.trim().trim_matches('"').to_owned())
        })
        .with_context(|| format!("no `channel` key in {TOOLCHAIN_FILE}"))
}

fn main() -> anyhow::Result<()> {
    // gRPC control API. The build script runs in the crate dir, so reference
    // the workspace-root proto by absolute path. Emit rerun-if-changed
    // explicitly — the proto lives outside this crate's package dir, so cargo
    // wouldn't otherwise re-run this script (and regenerate the bindings) when
    // it changes.
    println!(
        "cargo:rerun-if-changed={}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto/cradle.proto")
    );
    tonic_prost_build::compile_protos(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../proto/cradle.proto"
    ))?;

    // Hubble Observer + Peer API (docs/design/hubble.md). `proto/hubble` is the
    // include root so `import "flow/flow.proto"` resolves; observer.proto
    // pulls in flow.proto + relay.proto. peer.proto (H3, Relay discovery) is
    // standalone.
    let hubble = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto/hubble");
    tonic_prost_build::configure().compile_protos(
        &[
            format!("{hubble}/observer/observer.proto"),
            format!("{hubble}/peer/peer.proto"),
        ],
        &[hubble.to_string()],
    )?;

    // eBPF data plane. Built with the pinned toolchain rather than
    // `Toolchain::default()`, which is the literal `nightly` channel: that
    // default ignores rust-toolchain.toml, so the data plane was compiled by
    // whatever floating nightly happened to be installed, and fails outright
    // where only the pinned toolchain exists (CI).
    println!("cargo:rerun-if-changed={TOOLCHAIN_FILE}");
    let channel = toolchain_channel()?;
    aya_build::build_ebpf(
        [Package {
            name: "cradle-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../cradle-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::Custom(&channel),
    )?;
    Ok(())
}
