//! Build script: (1) compile the gRPC control API proto, and (2) compile the
//! `cradle-ebpf` crate to `bpfel-unknown-none` (embedded by `main.rs`).

use aya_build::{Package, Toolchain};

fn main() -> anyhow::Result<()> {
    // gRPC control API. The build script runs in the crate dir, so reference
    // the workspace-root proto by absolute path.
    tonic_prost_build::compile_protos(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../proto/cradle.proto"
    ))?;

    // eBPF data plane.
    aya_build::build_ebpf(
        [Package {
            name: "cradle-ebpf",
            root_dir: concat!(env!("CARGO_MANIFEST_DIR"), "/../cradle-ebpf"),
            no_default_features: false,
            features: &[],
        }],
        Toolchain::default(),
    )?;
    Ok(())
}
